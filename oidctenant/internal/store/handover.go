package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/example/oidctenant/internal/models"
)

var (
	// ErrForbidden 表示成员/会话不属于交接申请所在租户或不是申请参与方。
	ErrForbidden = errors.New("store: handover actor is outside the tenant or not a participant")
	// ErrProofMismatch 表示新近 OIDC 证明与应证明的身份锚点不一致。
	ErrProofMismatch = errors.New("store: OIDC proof does not match the required identity")
	// ErrAuthSession 表示证明所绑定的会话不存在、已过期、已吊销或不属于正确成员。
	ErrAuthSession = errors.New("store: handover authentication session is invalid")
)

type HandoverProofInput struct {
	State     string
	IDPID     uuid.UUID
	Issuer    string
	Subject   string
	AuthTime  time.Time
	SessionID uuid.UUID
	MemberID  uuid.UUID
}

const activeHandoverStatuses = "('pending', 'source_confirmed', 'target_confirmed')"

// CreateIdentityHandover 在事务中创建一条待双方确认的交接申请。
// 创建时只读取当前归属；在完成前不修改 identities.member_id。
func (s *Store) CreateIdentityHandover(ctx context.Context, tenantID, identityID, sourceMemberID,
	targetMemberID, createdBySessionID uuid.UUID, ttl time.Duration) (*models.IdentityHandover, error) {

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 串行化同一身份上的并发申请；下面的部分唯一索引是第二道防线。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2)`,
		int64(0x48414e44), identityIDLeastSignificant(identityID)); err != nil {
		return nil, err
	}

	var (
		gotTenantID     uuid.UUID
		gotOwnerID      uuid.UUID
		identityIssuer  string
		identitySubject string
	)
	err = tx.QueryRow(ctx,
		`SELECT tenant_id, member_id, issuer, subject FROM identities WHERE id=$1 FOR UPDATE`,
		identityID,
	).Scan(&gotTenantID, &gotOwnerID, &identityIssuer, &identitySubject)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if gotTenantID != tenantID {
		return nil, ErrForbidden
	}
	if gotOwnerID != sourceMemberID {
		return nil, ErrConflict
	}
	var targetTenantID uuid.UUID
	if err := tx.QueryRow(ctx,
		`SELECT tenant_id FROM members WHERE id=$1 AND tenant_id=$2`,
		targetMemberID, tenantID).Scan(&targetTenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrForbidden
		}
		return nil, err
	}
	if sourceMemberID == targetMemberID {
		return nil, ErrConflict
	}

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM identity_handovers
		   WHERE tenant_id=$1 AND identity_id=$2
		     AND status IN ('pending','source_confirmed','target_confirmed')
		 )`, tenantID, identityID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrConflict
	}

	now := time.Now()
	h := &models.IdentityHandover{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		IdentityID:         identityID,
		IdentityIssuer:     identityIssuer,
		IdentitySubject:    identitySubject,
		SourceMemberID:     sourceMemberID,
		TargetMemberID:     targetMemberID,
		CreatedBySessionID: &createdBySessionID,
		Status:             "pending",
		CreatedAt:          now,
		ExpiresAt:          now.Add(ttl),
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO identity_handovers(
		    id, tenant_id, identity_id, identity_issuer, identity_subject,
		    source_member_id, target_member_id, created_by_session_id,
		    status, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10)`,
		h.ID, h.TenantID, h.IdentityID, h.IdentityIssuer, h.IdentitySubject,
		h.SourceMemberID, h.TargetMemberID, createdBySessionID, h.CreatedAt, h.ExpiresAt); err != nil {
		return nil, mapErr(err)
	}
	if err := insertHandoverEvent(ctx, tx, h.ID, h.TenantID, h.IdentityID,
		&h.TargetMemberID, &createdBySessionID, "created"); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return h, nil
}

// IdentityHandover 返回申请，并先把已到 TTL 的活跃申请原子标记为 expired。
func (s *Store) IdentityHandover(ctx context.Context, tenantID, id uuid.UUID) (*models.IdentityHandover, error) {
	if err := s.ExpireDueHandovers(ctx, time.Now()); err != nil {
		return nil, err
	}
	return s.identityHandoverNoExpiry(ctx, s.pool, tenantID, id)
}

func (s *Store) identityHandoverNoExpiry(ctx context.Context, q querier,
	tenantID, id uuid.UUID) (*models.IdentityHandover, error) {
	row := q.QueryRow(ctx, `SELECT
	    id, tenant_id, identity_id, identity_issuer, identity_subject,
	    source_member_id, target_member_id, created_by_session_id, status,
	    source_session_id, source_idp_id, source_issuer, source_subject,
	    source_auth_time, source_confirmed_at,
	    target_session_id, target_idp_id, target_issuer, target_subject,
	    target_auth_time, target_confirmed_at,
	    created_at, expires_at, completed_at, decided_at
	 FROM identity_handovers WHERE id=$1`, id)
	h, err := scanIdentityHandover(row)
	if err != nil {
		return nil, err
	}
	if h.TenantID != tenantID {
		return nil, ErrNotFound
	}
	switch h.Status {
	case "pending", "source_confirmed", "target_confirmed":
		if !h.ExpiresAt.After(time.Now()) {
			return nil, ErrExpired
		}
	}
	return h, nil
}

// ListIdentityHandovers 只返回当前成员作为原绑定成员或目标成员参与的申请。
func (s *Store) ListIdentityHandovers(ctx context.Context, tenantID, memberID uuid.UUID) ([]models.IdentityHandover, error) {
	if err := s.ExpireDueHandovers(ctx, time.Now()); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT
	    id, tenant_id, identity_id, identity_issuer, identity_subject,
	    source_member_id, target_member_id, created_by_session_id, status,
	    source_session_id, source_idp_id, source_issuer, source_subject,
	    source_auth_time, source_confirmed_at,
	    target_session_id, target_idp_id, target_issuer, target_subject,
	    target_auth_time, target_confirmed_at,
	    created_at, expires_at, completed_at, decided_at
	 FROM identity_handovers
	 WHERE tenant_id=$1 AND (source_member_id=$2 OR target_member_id=$2)
	 ORDER BY created_at DESC`, tenantID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.IdentityHandover
	for rows.Next() {
		h, err := scanIdentityHandover(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

func consumePendingHandoverAuthRequests(ctx context.Context, tx pgx.Tx, id uuid.UUID, kind string) error {
	_, err := tx.Exec(ctx,
		`UPDATE auth_requests SET consumed_at=now()
		 WHERE handover_id=$1 AND kind=$2 AND consumed_at IS NULL`, id, kind)
	return err
}

// CreateHandoverProofAuthRequest 在同一事务里把一次性 OIDC auth_request 绑定到
// 交接申请与发起它的当前应用会话；证明回调通过 auth_request 反查参与方和会话。
func (s *Store) CreateHandoverProofAuthRequest(ctx context.Context, id, actorMemberID, actorSessionID,
	idpID uuid.UUID, state, kind, nonce, pkceVerifier, role string, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := expireDueHandoversTx(ctx, tx, now); err != nil {
		return err
	}
	h, err := lockHandover(ctx, tx, id)
	if err != nil {
		return err
	}
	if isActiveHandover(h.Status) && !h.ExpiresAt.After(now) {
		if err := commitExpiredHandover(ctx, tx, h, now); err != nil {
			return err
		}
		return ErrExpired
	}
	switch role {
	case "source":
		if h.SourceMemberID != actorMemberID || h.Status != "pending" {
			return ErrConflict
		}
		if err := consumePendingHandoverAuthRequests(ctx, tx, id, "handover_source"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE identity_handovers SET source_idp_id=$1 WHERE id=$2`, idpID, id); err != nil {
			return err
		}
	case "target":
		if h.TargetMemberID != actorMemberID || h.Status != "source_confirmed" {
			return ErrConflict
		}
		if err := consumePendingHandoverAuthRequests(ctx, tx, id, "handover_target"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE identity_handovers SET target_idp_id=$1 WHERE id=$2`, idpID, id); err != nil {
			return err
		}
	default:
		return ErrProofMismatch
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth_requests
		 (state, kind, tenant_id, idp_id, nonce, pkce_verifier, return_to, session_id, handover_id)
		 VALUES ($1,$2,$3,$4,$5,$6,'/',$7,$8)`,
		state, kind, h.TenantID, idpID, nonce, pkceVerifier, actorSessionID, id); err != nil {
		return mapErr(err)
	}
	return tx.Commit(ctx)
}

// AttachHandoverProof 消费 OIDC 回调时记录一腿新近证明。它不移动身份归属；
// 目标腿写入后 CompleteIdentityHandover 在完成事务里复核全部条件才移动归属。
func (s *Store) AttachHandoverProof(ctx context.Context, id uuid.UUID, role string,
	in HandoverProofInput, maxAge time.Duration, now time.Time) (*models.IdentityHandover, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := expireDueHandoversTx(ctx, tx, now); err != nil {
		return nil, err
	}
	h, err := lockHandover(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if isActiveHandover(h.Status) && !h.ExpiresAt.After(now) {
		if err := commitExpiredHandover(ctx, tx, h, now); err != nil {
			return nil, err
		}
		return nil, ErrExpired
	}
	if in.AuthTime.IsZero() {
		return nil, reauthError("provider did not report auth_time; cannot prove recent authentication")
	}
	if now.Sub(in.AuthTime) > maxAge {
		return nil, reauthError("handover identity authentication is stale; re-authenticate")
	}
	if err := requireValidSession(ctx, tx, h.TenantID, in.MemberID, in.SessionID, now); err != nil {
		return nil, err
	}

	switch role {
	case "source":
		if h.SourceMemberID != in.MemberID || h.Status != "pending" {
			return nil, ErrConflict
		}
		if h.SourceSessionID != nil {
			return nil, ErrConflict
		}
		if in.Issuer != h.IdentityIssuer || in.Subject != h.IdentitySubject {
			return nil, ErrProofMismatch
		}
		if err := requireIdentityOwner(ctx, tx, h.TenantID, h.IdentityID, in.Issuer, in.Subject, h.SourceMemberID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE identity_handovers
			 SET source_session_id=$1, source_idp_id=$2, source_issuer=$3, source_subject=$4,
			     source_auth_time=$5, source_confirmed_at=$6,
			     status='source_confirmed'
			 WHERE id=$7`,
			in.SessionID, in.IDPID, in.Issuer, in.Subject, in.AuthTime, now, id); err != nil {
			return nil, err
		}
		if err := insertHandoverEvent(ctx, tx, id, h.TenantID, h.IdentityID,
			&in.MemberID, &in.SessionID, "source_confirmed"); err != nil {
			return nil, err
		}
	case "target":
		if h.TargetMemberID != in.MemberID || h.Status != "source_confirmed" {
			return nil, ErrConflict
		}
		if h.TargetSessionID != nil {
			return nil, ErrConflict
		}
		if err := requireIdentityOwner(ctx, tx, h.TenantID, h.IdentityID,
			h.IdentityIssuer, h.IdentitySubject, h.SourceMemberID); err != nil {
			return nil, err
		}
		if err := requireIdentityOwner(ctx, tx, h.TenantID, uuid.Nil,
			in.Issuer, in.Subject, h.TargetMemberID); err != nil {
			return nil, err
		}
		if in.Issuer == h.IdentityIssuer && in.Subject == h.IdentitySubject {
			return nil, ErrConflict
		}
		if _, err := tx.Exec(ctx,
			`UPDATE identity_handovers
			 SET target_session_id=$1, target_idp_id=$2, target_issuer=$3, target_subject=$4,
			     target_auth_time=$5, target_confirmed_at=$6,
			     status='target_confirmed'
			 WHERE id=$7`,
			in.SessionID, in.IDPID, in.Issuer, in.Subject, in.AuthTime, now, id); err != nil {
			return nil, err
		}
		if err := insertHandoverEvent(ctx, tx, id, h.TenantID, h.IdentityID,
			&in.MemberID, &in.SessionID, "target_confirmed"); err != nil {
			return nil, err
		}
	default:
		return nil, ErrProofMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return s.identityHandoverNoExpiry(ctx, s.pool, h.TenantID, id)
}

// CompleteIdentityHandover 在单事务中复核双方、租户、OIDC 锚点、当前所有者和状态，
// 然后才把 identities.member_id 从原成员移动到目标成员。
func (s *Store) CompleteIdentityHandover(ctx context.Context, id, actorMemberID, actorSessionID uuid.UUID,
	now time.Time) (*models.IdentityHandover, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := expireDueHandoversTx(ctx, tx, now); err != nil {
		return nil, err
	}
	h, err := lockHandover(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if isActiveHandover(h.Status) && !h.ExpiresAt.After(now) {
		if err := commitExpiredHandover(ctx, tx, h, now); err != nil {
			return nil, err
		}
		return nil, ErrExpired
	}
	if h.Status != "target_confirmed" {
		return nil, ErrConflict
	}
	if h.TargetMemberID != actorMemberID || h.TargetSessionID == nil || *h.TargetSessionID != actorSessionID {
		return nil, ErrForbidden
	}
	if !h.SourceAuthTime.Valid || !h.TargetAuthTime.Valid ||
		h.SourceIDPID == nil || h.TargetIDPID == nil {
		return nil, reauthError("both members must provide recent OIDC proof before completing handover")
	}
	if err := requireValidSession(ctx, tx, h.TenantID, h.SourceMemberID, *h.SourceSessionID, now); err != nil {
		return nil, err
	}
	if err := requireValidSession(ctx, tx, h.TenantID, h.TargetMemberID, actorSessionID, now); err != nil {
		return nil, err
	}

	sourceProv, err := providerByIDTx(ctx, tx, h.TenantID, *h.SourceIDPID)
	if err != nil {
		return nil, err
	}
	targetProv, err := providerByIDTx(ctx, tx, h.TenantID, *h.TargetIDPID)
	if err != nil {
		return nil, err
	}
	if !sourceProv.Enabled || !targetProv.Enabled {
		return nil, ErrForbidden
	}
	if now.Sub(h.SourceAuthTime.Time) > providerDuration(sourceProv) ||
		now.Sub(h.TargetAuthTime.Time) > providerDuration(targetProv) {
		return nil, reauthError("one or both handover proofs are no longer recent")
	}

	var identityTenantID, ownerID uuid.UUID
	var issuer, subject string
	if err := tx.QueryRow(ctx,
		`SELECT tenant_id, member_id, issuer, subject FROM identities WHERE id=$1 FOR UPDATE`,
		h.IdentityID,
	).Scan(&identityTenantID, &ownerID, &issuer, &subject); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if identityTenantID != h.TenantID || issuer != h.IdentityIssuer || subject != h.IdentitySubject {
		return nil, ErrProofMismatch
	}
	if ownerID != h.SourceMemberID {
		return nil, ErrConflict
	}
	if h.SourceIssuer != issuer || h.SourceSubject != subject {
		return nil, ErrProofMismatch
	}
	if err := requireIdentityOwner(ctx, tx, h.TenantID, uuid.Nil,
		h.TargetIssuer, h.TargetSubject, h.TargetMemberID); err != nil {
		return nil, err
	}
	if err := requireMemberTenant(ctx, tx, h.TenantID, h.SourceMemberID); err != nil {
		return nil, err
	}
	if err := requireMemberTenant(ctx, tx, h.TenantID, h.TargetMemberID); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE identities SET member_id=$1, updated_at=now() WHERE id=$2 AND member_id=$3`,
		h.TargetMemberID, h.IdentityID, h.SourceMemberID); err != nil {
		return nil, mapErr(err)
	}
	// 原成员已不再持有该身份；撤销其全部现存会话，确保旧浏览器不能以该身份继续使用。
	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET revoked_at=now()
		 WHERE tenant_id=$1 AND member_id=$2 AND revoked_at IS NULL`,
		h.TenantID, h.SourceMemberID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identity_handovers
		 SET status='completed', completed_at=$2, decided_at=$2
		 WHERE id=$1 AND status='target_confirmed'`, id, now); err != nil {
		return nil, err
	}
	if err := insertHandoverEvent(ctx, tx, id, h.TenantID, h.IdentityID,
		&actorMemberID, &actorSessionID, "completed"); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return s.identityHandoverNoExpiry(ctx, s.pool, h.TenantID, id)
}

// RejectIdentityHandover 允许原绑定成员在完成前拒绝申请。身份归属保持不变。
func (s *Store) RejectIdentityHandover(ctx context.Context, id, actorMemberID, actorSessionID uuid.UUID,
	now time.Time) (*models.IdentityHandover, error) {
	return s.decideIdentityHandover(ctx, id, actorMemberID, actorSessionID, "source", "rejected", now)
}

// CancelIdentityHandover 允许发起/目标成员在目标确认前取消申请。身份归属保持不变。
func (s *Store) CancelIdentityHandover(ctx context.Context, id, actorMemberID, actorSessionID uuid.UUID,
	now time.Time) (*models.IdentityHandover, error) {
	return s.decideIdentityHandover(ctx, id, actorMemberID, actorSessionID, "target", "cancelled", now)
}

func (s *Store) decideIdentityHandover(ctx context.Context, id, actorMemberID, actorSessionID uuid.UUID,
	actorRole, eventType string, now time.Time) (*models.IdentityHandover, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := expireDueHandoversTx(ctx, tx, now); err != nil {
		return nil, err
	}
	h, err := lockHandover(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if isActiveHandover(h.Status) && !h.ExpiresAt.After(now) {
		if err := commitExpiredHandover(ctx, tx, h, now); err != nil {
			return nil, err
		}
		return h, ErrExpired
	}
	var expectedActor uuid.UUID
	switch actorRole {
	case "source":
		expectedActor = h.SourceMemberID
		if h.Status != "pending" {
			return nil, ErrConflict
		}
	case "target":
		expectedActor = h.TargetMemberID
		// 目标确认后回调会立即进入完成路径，不允许取消已提交的最终确认。
		if h.Status != "pending" && h.Status != "source_confirmed" {
			return nil, ErrConflict
		}
	default:
		return nil, ErrProofMismatch
	}
	if actorMemberID != expectedActor {
		return nil, ErrForbidden
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth_requests SET consumed_at=now()
		 WHERE handover_id=$1 AND consumed_at IS NULL`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identity_handovers
		 SET status=$1, decided_at=$2
		 WHERE id=$3`, eventType, now, id); err != nil {
		return nil, err
	}
	if err := insertHandoverEvent(ctx, tx, id, h.TenantID, h.IdentityID,
		&actorMemberID, &actorSessionID, eventType); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return s.identityHandoverNoExpiry(ctx, s.pool, h.TenantID, id)
}

// ExpireDueHandovers 把所有到 TTL 仍未终结的申请标记为 expired。
func (s *Store) ExpireDueHandovers(ctx context.Context, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := expireDueHandoversTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func isActiveHandover(status string) bool {
	return status == "pending" || status == "source_confirmed" || status == "target_confirmed"
}

func expireLockedHandover(ctx context.Context, tx pgx.Tx, h *models.IdentityHandover, now time.Time) error {
	if _, err := tx.Exec(ctx,
		`UPDATE identity_handovers SET status='expired', decided_at=$2
		 WHERE id=$1 AND status IN `+activeHandoverStatuses, h.ID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth_requests SET consumed_at=now()
		 WHERE handover_id=$1 AND consumed_at IS NULL`, h.ID); err != nil {
		return err
	}
	return insertHandoverEvent(ctx, tx, h.ID, h.TenantID, h.IdentityID, nil, nil, "expired")
}

func commitExpiredHandover(ctx context.Context, tx pgx.Tx, h *models.IdentityHandover, now time.Time) error {
	if err := expireLockedHandover(ctx, tx, h, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func expireDueHandoversTx(ctx context.Context, tx pgx.Tx, now time.Time) error {
	rows, err := tx.Query(ctx,
		`SELECT id, tenant_id, identity_id FROM identity_handovers
		 WHERE status IN `+activeHandoverStatuses+` AND expires_at <= $1
		 FOR UPDATE SKIP LOCKED`, now)
	if err != nil {
		return err
	}
	var due []models.IdentityHandover
	for rows.Next() {
		var h models.IdentityHandover
		if err := rows.Scan(&h.ID, &h.TenantID, &h.IdentityID); err != nil {
			rows.Close()
			return err
		}
		due = append(due, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range due {
		if err := expireLockedHandover(ctx, tx, &due[i], now); err != nil {
			return err
		}
	}
	return nil
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func scanIdentityHandover(row pgx.Row) (*models.IdentityHandover, error) {
	var h models.IdentityHandover
	err := row.Scan(
		&h.ID, &h.TenantID, &h.IdentityID, &h.IdentityIssuer, &h.IdentitySubject,
		&h.SourceMemberID, &h.TargetMemberID, &h.CreatedBySessionID, &h.Status,
		&h.SourceSessionID, &h.SourceIDPID, &h.SourceIssuer, &h.SourceSubject,
		&h.SourceAuthTime, &h.SourceConfirmedAt,
		&h.TargetSessionID, &h.TargetIDPID, &h.TargetIssuer, &h.TargetSubject,
		&h.TargetAuthTime, &h.TargetConfirmedAt,
		&h.CreatedAt, &h.ExpiresAt, &h.CompletedAt, &h.DecidedAt,
	)
	if err != nil {
		return nil, mapErr(err)
	}
	return &h, nil
}

func lockHandover(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*models.IdentityHandover, error) {
	return scanIdentityHandover(tx.QueryRow(ctx,
		`SELECT
		    id, tenant_id, identity_id, identity_issuer, identity_subject,
		    source_member_id, target_member_id, created_by_session_id, status,
		    source_session_id, source_idp_id, source_issuer, source_subject,
		    source_auth_time, source_confirmed_at,
		    target_session_id, target_idp_id, target_issuer, target_subject,
		    target_auth_time, target_confirmed_at,
		    created_at, expires_at, completed_at, decided_at
		 FROM identity_handovers WHERE id=$1 FOR UPDATE`, id))
}

func providerByIDTx(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (*models.Provider, error) {
	var p models.Provider
	err := tx.QueryRow(ctx,
		`SELECT id, tenant_id, issuer, client_id, client_secret, redirect_uris,
		        auth_time_max_age, enabled, created_at, updated_at
		 FROM identity_providers WHERE tenant_id=$1 AND id=$2`,
		tenantID, id).Scan(
		&p.ID, &p.TenantID, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.RedirectURIs,
		&p.AuthTimeMaxAge, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func providerDuration(p *models.Provider) time.Duration {
	secs := p.AuthTimeMaxAge
	if secs <= 0 {
		secs = 300
	}
	return time.Duration(secs) * time.Second
}

func requireValidSession(ctx context.Context, tx pgx.Tx, tenantID, memberID, sessionID uuid.UUID, now time.Time) error {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM sessions
		   WHERE id=$1 AND tenant_id=$2 AND member_id=$3
		     AND revoked_at IS NULL AND expires_at > $4
		 )`, sessionID, tenantID, memberID, now).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return ErrAuthSession
	}
	return nil
}

func requireIdentityOwner(ctx context.Context, tx pgx.Tx, tenantID, identityID uuid.UUID,
	issuer, subject string, memberID uuid.UUID) error {
	var (
		gotTenantID uuid.UUID
		gotID       uuid.UUID
		ownerID     uuid.UUID
	)
	query := `SELECT id, tenant_id, member_id FROM identities
	          WHERE issuer=$1 AND subject=$2 AND member_id=$3`
	args := []any{issuer, subject, memberID}
	if tenantID != uuid.Nil {
		query += ` AND tenant_id=$4`
		args = append(args, tenantID)
	}
	err := tx.QueryRow(ctx, query, args...).Scan(&gotID, &gotTenantID, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrProofMismatch
	}
	if err != nil {
		return err
	}
	if identityID != uuid.Nil && gotID != identityID {
		return ErrProofMismatch
	}
	return nil
}

func requireMemberTenant(ctx context.Context, tx pgx.Tx, tenantID, memberID uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM members WHERE id=$1 AND tenant_id=$2)`,
		memberID, tenantID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrForbidden
	}
	return nil
}

func insertHandoverEvent(ctx context.Context, tx pgx.Tx, handoverID, tenantID, identityID uuid.UUID,
	actorMemberID, actorSessionID *uuid.UUID, eventType string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO identity_handover_events(
		    id, handover_id, tenant_id, identity_id,
		    actor_member_id, actor_session_id, event_type)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), handoverID, tenantID, identityID, actorMemberID, actorSessionID, eventType)
	return err
}

func identityIDLeastSignificant(id uuid.UUID) int64 {
	b := id[8:]
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}
	// 转为有符号 key space；仅用于将不同 UUID 分散到不同咨询锁。
	return int64(v)
}
