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
	// ErrExpired 表示交接申请已过 expires_at（会被翻转为终态 expired）。
	ErrExpired = errors.New("store: handoff request expired")
	// ErrNotBoundToCaller 表示要交接的身份当前不属于发起成员。
	ErrNotBoundToCaller = errors.New("store: identity is not bound to the requesting member")
	// ErrSameMember 表示目标成员与原绑定成员相同（不能自我交接）。
	ErrSameMember = errors.New("store: owner and target are the same member")
	// ErrAnchorMoved 表示申请中记录的身份锚点在完成时已不满足前提。
	ErrAnchorMoved = errors.New("store: identity anchor changed during handoff")
)

// handoffColumns 描述 handoff_requests 的全部列，供各处复用。
const handoffColumns = `
	id, tenant_id, identity_id, issuer, subject,
	owner_member_id, target_member_id,
	target_anchor_issuer, target_anchor_subject,
	owner_session_id, target_session_id,
	owner_confirm_state, target_confirm_state,
	owner_auth_issuer, owner_auth_subject, owner_auth_time,
	target_auth_issuer, target_auth_subject, target_auth_time,
	status, created_at, expires_at,
	owner_confirmed_at, target_confirmed_at, completed_at, decided_at`

func scanHandoff(row pgx.Row) (*models.HandoffRequest, error) {
	var h models.HandoffRequest
	err := row.Scan(
		&h.ID, &h.TenantID, &h.IdentityID, &h.Issuer, &h.Subject,
		&h.OwnerMemberID, &h.TargetMemberID,
		&h.TargetAnchorIssuer, &h.TargetAnchorSubject,
		&h.OwnerSessionID, &h.TargetSessionID,
		&h.OwnerConfirmState, &h.TargetConfirmState,
		&h.OwnerAuthIssuer, &h.OwnerAuthSubject, &h.OwnerAuthTime,
		&h.TargetAuthIssuer, &h.TargetAuthSubject, &h.TargetAuthTime,
		&h.Status, &h.CreatedAt, &h.ExpiresAt,
		&h.OwnerConfirmedAt, &h.TargetConfirmedAt, &h.CompletedAt, &h.DecidedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &h, nil
}

// CreateHandoffInput 是创建交接申请的输入：身份与目标成员都只用租户内已核实锚点表达。
type CreateHandoffInput struct {
	TenantID uuid.UUID

	// 要交接的身份锚点（必须当前属于 OwnerMemberID）。
	Issuer  string
	Subject string

	OwnerMemberID  uuid.UUID
	OwnerSessionID uuid.UUID

	// 目标成员当前持有的一条已核实身份锚点（绝不按邮箱找人）。
	TargetAnchorIssuer  string
	TargetAnchorSubject string
}

// CreateHandoff 在单事务内校验全部前提并创建申请（初始 owner_pending）。
//
// 事务内对两条身份锚点加咨询锁（按键值排序，杜绝双向死锁）+ 行锁：
//   - 待交接身份此刻必须属于发起成员，否则 ErrNotBoundToCaller；
//   - 目标锚点此刻必须属于本租户另一名成员，否则 ErrNotFound/ErrSameMember；
//   - 部分唯一索引保证同一身份并发申请只有一行成功，其余 ErrConflict。
//
// 身份归属在整个申请期间绝不被本函数或任何确认操作触碰。
func (s *Store) CreateHandoff(ctx context.Context, in CreateHandoffInput, ttl time.Duration) (*models.HandoffRequest, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 同一把咨询锁与 LoginOrRegisterMember 一致，串行化相同锚点上的并发归属操作。
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1 || '|' || $2, 0))`,
		in.Issuer, in.Subject); err != nil {
		return nil, err
	}

	var identityID, ownerID uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT id, member_id FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3 FOR UPDATE`,
		in.TenantID, in.Issuer, in.Subject,
	).Scan(&identityID, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if ownerID != in.OwnerMemberID {
		return nil, ErrNotBoundToCaller
	}

	var targetMemberID uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT member_id FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		in.TenantID, in.TargetAnchorIssuer, in.TargetAnchorSubject,
	).Scan(&targetMemberID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if targetMemberID == in.OwnerMemberID {
		return nil, ErrSameMember
	}

	h := &models.HandoffRequest{
		ID:                  uuid.New(),
		TenantID:            in.TenantID,
		IdentityID:          identityID,
		Issuer:              in.Issuer,
		Subject:             in.Subject,
		OwnerMemberID:       in.OwnerMemberID,
		TargetMemberID:      targetMemberID,
		TargetAnchorIssuer:  in.TargetAnchorIssuer,
		TargetAnchorSubject: in.TargetAnchorSubject,
		OwnerSessionID:      &in.OwnerSessionID,
		Status:              models.HandoffOwnerPending,
		ExpiresAt:           time.Now().Add(ttl),
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO handoff_requests
		(id, tenant_id, identity_id, issuer, subject,
		 owner_member_id, target_member_id,
		 target_anchor_issuer, target_anchor_subject,
		 owner_session_id, status, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'owner_pending',$11)`,
		h.ID, h.TenantID, h.IdentityID, h.Issuer, h.Subject,
		h.OwnerMemberID, h.TargetMemberID,
		h.TargetAnchorIssuer, h.TargetAnchorSubject,
		h.OwnerSessionID, h.ExpiresAt); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return h, nil
}

// HandoffRequest 按主键读取申请。
func (s *Store) HandoffRequest(ctx context.Context, id uuid.UUID) (*models.HandoffRequest, error) {
	return scanHandoff(s.pool.QueryRow(ctx,
		`SELECT `+handoffColumns+` FROM handoff_requests WHERE id=$1`, id))
}

// HandoffRequestsForMember 返回该成员作为原绑定方或目标方参与的全部申请（按时间倒序）。
func (s *Store) HandoffRequestsForMember(ctx context.Context, tenantID, memberID uuid.UUID) ([]models.HandoffRequest, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+handoffColumns+` FROM handoff_requests
		 WHERE tenant_id=$1 AND (owner_member_id=$2 OR target_member_id=$2)
		 ORDER BY created_at DESC`, tenantID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.HandoffRequest
	for rows.Next() {
		h, err := scanHandoff(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

// ExpireHandoffIfDue 惰性把已到期的活申请翻转为 expired 终态；返回是否发生了翻转。
func (s *Store) ExpireHandoffIfDue(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE handoff_requests
		SET status='expired', decided_at=now(),
		    owner_confirm_state='', target_confirm_state=''
		WHERE id=$1
		  AND status IN ('owner_pending','target_pending')
		  AND expires_at <= now()`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ExpireDueHandoffs 后台清扫：批量过期所有到期申请。
func (s *Store) ExpireDueHandoffs(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE handoff_requests
		SET status='expired', decided_at=now(),
		    owner_confirm_state='', target_confirm_state=''
		WHERE status IN ('owner_pending','target_pending') AND expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// BindHandoffConfirmSession 为一方登记“待消费的 state + 当前会话”。
// 允许覆盖上一个尚未消费的 state（用户放弃/重开登录）：旧 state 的回调会在
// AttachHandoffProof 的逐字节比对中失败，因此无法乱序复活任何证明。
//
//	role=owner : 活状态 owner_pending/target_pending（后者允许刷新过期的 owner 证明），
//	             只能由原绑定成员、在创建申请时绑定的同一会话内登记；
//	role=target: 活状态 target_pending，只能由目标成员、在其当前会话内登记。
//
// 目标方首次登记会把会话钉死；之后任何不同会话都无法再登记（ErrConflict）。
func (s *Store) BindHandoffConfirmSession(ctx context.Context, role string,
	handoffID uuid.UUID, tenantID, memberID, sessionID uuid.UUID, state string) error {

	var q string
	switch role {
	case "owner":
		q = `
		UPDATE handoff_requests SET owner_confirm_state=$1
		WHERE id=$2 AND tenant_id=$3
		  AND status IN ('owner_pending','target_pending')
		  AND expires_at > now()
		  AND owner_member_id=$5 AND owner_session_id=$4`
	case "target":
		q = `
		UPDATE handoff_requests SET target_confirm_state=$1,
		       target_session_id = COALESCE(target_session_id, $4)
		WHERE id=$2 AND tenant_id=$3
		  AND status='target_pending' AND expires_at > now()
		  AND target_member_id=$5
		  AND (target_session_id IS NULL OR target_session_id=$4)`
	default:
		return errors.New("unknown handoff role")
	}
	tag, err := s.pool.Exec(ctx, q, state, handoffID, tenantID, sessionID, memberID)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// AttachHandoffProof 在回调通过完整 OIDC 校验后，原子提交一方的新近证明。
// state 必须与 BindHandoffConfirmSession 登记的值一致（一次性），
// 会话、成员、租户、状态全部在 WHERE 中复核，任何乱序/重复/换人/换会话都无法写入。
// owner 首次提交把状态从 owner_pending 推进到 target_pending；
// owner 在 target_pending 刷新证明时状态不变。
func (s *Store) AttachHandoffProof(ctx context.Context, role string,
	handoffID uuid.UUID, tenantID, memberID, sessionID uuid.UUID,
	state, issuer, subject string, authTime time.Time) error {

	var q string
	switch role {
	case "owner":
		q = `
		UPDATE handoff_requests SET
		  owner_confirm_state='',
		  owner_auth_issuer=$1, owner_auth_subject=$2, owner_auth_time=$3,
		  owner_confirmed_at=now(),
		  status = CASE WHEN status='owner_pending' THEN 'target_pending' ELSE status END
		WHERE id=$4 AND tenant_id=$5 AND status IN ('owner_pending','target_pending')
		  AND expires_at > now()
		  AND owner_member_id=$6 AND owner_session_id=$7
		  AND owner_confirm_state=$8 AND owner_confirm_state <> ''`
	case "target":
		q = `
		UPDATE handoff_requests SET
		  target_confirm_state='',
		  target_auth_issuer=$1, target_auth_subject=$2, target_auth_time=$3,
		  target_confirmed_at=now()
		WHERE id=$4 AND tenant_id=$5 AND status='target_pending'
		  AND expires_at > now()
		  AND target_member_id=$6 AND target_session_id=$7
		  AND target_confirm_state=$8 AND target_confirm_state <> ''`
	default:
		return errors.New("unknown handoff role")
	}
	tag, err := s.pool.Exec(ctx, q,
		issuer, subject, authTime, handoffID, tenantID, memberID, sessionID, state)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// HandoffDecision 是 Reject/Cancel 的输入。
type HandoffDecision struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	MemberID uuid.UUID
}

// RejectHandoff 仅允许本人在自己的确认窗口拒绝：
// 原绑定成员在 owner_pending；目标成员在 target_pending。
func (s *Store) RejectHandoff(ctx context.Context, d HandoffDecision, asOwner bool) error {
	var q string
	if asOwner {
		q = `
		UPDATE handoff_requests SET status='rejected', decided_at=now(),
		       owner_confirm_state='', target_confirm_state=''
		WHERE id=$1 AND tenant_id=$2 AND owner_member_id=$3 AND status='owner_pending'`
	} else {
		q = `
		UPDATE handoff_requests SET status='rejected', decided_at=now(),
		       owner_confirm_state='', target_confirm_state=''
		WHERE id=$1 AND tenant_id=$2 AND target_member_id=$3 AND status='target_pending'`
	}
	return s.decide(ctx, q, d)
}

// CancelHandoff 允许任意参与方在申请仍存活时取消（双方在各自阶段都可撤申请）。
func (s *Store) CancelHandoff(ctx context.Context, d HandoffDecision) error {
	q := `
	UPDATE handoff_requests SET status='cancelled', decided_at=now(),
	       owner_confirm_state='', target_confirm_state=''
	WHERE id=$1 AND tenant_id=$2
	  AND status IN ('owner_pending','target_pending')
	  AND (owner_member_id=$3 OR target_member_id=$3)`
	return s.decide(ctx, q, d)
}

func (s *Store) decide(ctx context.Context, q string, d HandoffDecision) error {
	// 先惰性过期：到期申请不能再被拒绝/取消成别的终态。
	expired, err := s.ExpireHandoffIfDue(ctx, d.ID)
	if err != nil {
		return err
	}
	if expired {
		return ErrExpired
	}
	tag, err := s.pool.Exec(ctx, q, d.ID, d.TenantID, d.MemberID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// 0 行：可能申请在此刻已到期（过期已被前一个请求翻转）或处于其他终态。
	// 重读以区分“过期”与一般状态冲突，给调用方明确的错误类别。
	h, err := s.HandoffRequest(ctx, d.ID)
	if err != nil {
		return err
	}
	if h.Status == models.HandoffExpired {
		return ErrExpired
	}
	return ErrConflict
}

// CompleteHandoff 在单事务内完成交接。全部复核与归属移动原子发生：
//
//  1. 申请必须处于 target_pending（owner 已确认、target 证明已提交）且未过期；
//  2. 双方会话均已绑定且仍有效（未吊销、未过期）；
//  3. 双方 OIDC 证明锚点正确、齐全且各自在 provider 新鲜度窗口内；
//  4. 两条身份锚点行（按 id 排序加行锁）当前所有者仍是各自预期成员，
//     tenant/issuer/subject 与申请记录逐字段一致 —— 完成前身份从未离开原归属；
//  5. 移动 member_id（同一把咨询锁与登录路径共用，杜绝并发双归属），
//     写 handoff_records（无令牌、无邮箱），申请置 completed。
func (s *Store) CompleteHandoff(ctx context.Context, id uuid.UUID, now time.Time,
	ownerMaxAge, targetMaxAge time.Duration) (*models.HandoffRecord, error) {

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	h, err := scanHandoff(tx.QueryRow(ctx,
		`SELECT `+handoffColumns+` FROM handoff_requests WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return nil, err
	}
	if h.Status != models.HandoffTargetPending {
		if !h.ExpiresAt.After(now) {
			return nil, markExpiredTx(ctx, tx, id)
		}
		return nil, ErrConflict
	}
	if !h.ExpiresAt.After(now) {
		return nil, markExpiredTx(ctx, tx, id)
	}

	// 双方会话：必须都绑定过，且当前仍然有效。
	if h.OwnerSessionID == nil || h.TargetSessionID == nil {
		return nil, ErrConflict
	}
	for _, sid := range []uuid.UUID{*h.OwnerSessionID, *h.TargetSessionID} {
		var ok bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM sessions
			 WHERE id=$1 AND revoked_at IS NULL AND expires_at > now()`, sid,
		).Scan(&ok); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, reauthError("a confirming session is no longer valid; re-authenticate and retry")
			}
			return nil, err
		}
	}

	// 双方证明：齐全 + 锚点正确 + 新鲜度。
	if !h.OwnerAuthTime.Valid || !h.TargetAuthTime.Valid ||
		h.OwnerAuthIssuer == "" || h.OwnerAuthSubject == "" ||
		h.TargetAuthIssuer == "" || h.TargetAuthSubject == "" {
		return nil, ErrConflict
	}
	if h.OwnerAuthIssuer != h.Issuer || h.OwnerAuthSubject != h.Subject {
		return nil, ErrAnchorMoved
	}
	if h.TargetAuthIssuer != h.TargetAnchorIssuer || h.TargetAuthSubject != h.TargetAnchorSubject {
		return nil, ErrAnchorMoved
	}
	if now.Sub(h.OwnerAuthTime.Time) > ownerMaxAge {
		return nil, reauthError("original owner authentication is stale; owner must re-confirm")
	}
	if now.Sub(h.TargetAuthTime.Time) > targetMaxAge {
		return nil, reauthError("target authentication is stale; target must re-confirm")
	}

	// 双锚点咨询锁，按哈希键值排序获取，避免与其他交接/登录路径交叉死锁。
	var lockLo, lockHi int64
	if err := tx.QueryRow(ctx,
		`SELECT least(k1,k2), greatest(k1,k2) FROM
		 (SELECT hashtextextended($1 || '|' || $2, 0) AS k1,
		         hashtextextended($3 || '|' || $4, 0) AS k2) t`,
		h.Issuer, h.Subject, h.TargetAnchorIssuer, h.TargetAnchorSubject,
	).Scan(&lockLo, &lockHi); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1), pg_advisory_xact_lock($2)`,
		lockLo, lockHi); err != nil {
		return nil, err
	}

	// 两条身份行按 id 排序一次性加行锁，再逐行复核当前所有者与锚点。
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, member_id, issuer, subject FROM identities
		 WHERE (tenant_id=$1 AND issuer=$2 AND subject=$3)
		    OR (tenant_id=$1 AND issuer=$4 AND subject=$5)
		 ORDER BY id FOR UPDATE`,
		h.TenantID, h.Issuer, h.Subject, h.TargetAnchorIssuer, h.TargetAnchorSubject)
	if err != nil {
		return nil, err
	}
	type idRow struct {
		id, tenantID, memberID uuid.UUID
		issuer, subject        string
	}
	var locked []idRow
	for rows.Next() {
		var r idRow
		if err := rows.Scan(&r.id, &r.tenantID, &r.memberID, &r.issuer, &r.subject); err != nil {
			rows.Close()
			return nil, err
		}
		locked = append(locked, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(locked) != 2 {
		return nil, ErrAnchorMoved
	}
	for _, r := range locked {
		if r.tenantID != h.TenantID {
			return nil, ErrAnchorMoved
		}
		switch {
		case r.issuer == h.Issuer && r.subject == h.Subject:
			if r.memberID != h.OwnerMemberID || r.id != h.IdentityID {
				return nil, ErrAnchorMoved
			}
		case r.issuer == h.TargetAnchorIssuer && r.subject == h.TargetAnchorSubject:
			if r.memberID != h.TargetMemberID {
				return nil, ErrAnchorMoved
			}
		default:
			return nil, ErrAnchorMoved
		}
	}

	// 移动归属：WHERE 带上当前所有者做最终条件。UNIQUE(tenant_id,issuer,subject)
	// 始终保护锚点；本 UPDATE 只改 member_id，不可能产生双归属。
	tag, err := tx.Exec(ctx,
		`UPDATE identities SET member_id=$1, updated_at=now()
		 WHERE id=$2 AND tenant_id=$3 AND member_id=$4`,
		h.TargetMemberID, h.IdentityID, h.TenantID, h.OwnerMemberID)
	if err != nil {
		return nil, mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrConflict
	}

	rec := &models.HandoffRecord{
		ID:                uuid.New(),
		HandoffID:         h.ID,
		TenantID:          h.TenantID,
		IdentityID:        h.IdentityID,
		Issuer:            h.Issuer,
		Subject:           h.Subject,
		FromMemberID:      h.OwnerMemberID,
		ToMemberID:        h.TargetMemberID,
		OwnerSessionID:    *h.OwnerSessionID,
		TargetSessionID:   *h.TargetSessionID,
		OwnerAuthIssuer:   h.OwnerAuthIssuer,
		OwnerAuthSubject:  h.OwnerAuthSubject,
		OwnerAuthTime:     h.OwnerAuthTime,
		TargetAuthIssuer:  h.TargetAuthIssuer,
		TargetAuthSubject: h.TargetAuthSubject,
		TargetAuthTime:    h.TargetAuthTime,
		CompletedAt:       now,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO handoff_records
		(id, handoff_id, tenant_id, identity_id, issuer, subject,
		 from_member_id, to_member_id, owner_session_id, target_session_id,
		 owner_auth_issuer, owner_auth_subject, owner_auth_time,
		 target_auth_issuer, target_auth_subject, target_auth_time, completed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		rec.ID, rec.HandoffID, rec.TenantID, rec.IdentityID, rec.Issuer, rec.Subject,
		rec.FromMemberID, rec.ToMemberID, rec.OwnerSessionID, rec.TargetSessionID,
		rec.OwnerAuthIssuer, rec.OwnerAuthSubject, nullableTime(rec.OwnerAuthTime),
		rec.TargetAuthIssuer, rec.TargetAuthSubject, nullableTime(rec.TargetAuthTime),
		rec.CompletedAt); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE handoff_requests SET status='completed', completed_at=now() WHERE id=$1`,
		id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return rec, nil
}

func markExpiredTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	if _, err := tx.Exec(ctx,
		`UPDATE handoff_requests SET status='expired', decided_at=now(),
		        owner_confirm_state='', target_confirm_state='' WHERE id=$1`, id); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return ErrExpired
}
