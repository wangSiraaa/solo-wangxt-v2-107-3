package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

const (
	handoffRoleOwner  = "owner"
	handoffRoleTarget = "target"
)

// handoffCreateRequest 发起身份交接申请。
// identity 是要交接的身份（必须属于调用方）；target 是目标成员当前持有的
// 一条已核实身份锚点 —— 目标成员只能用锚点定位，绝不按邮箱定位。
type handoffCreateRequest struct {
	Identity struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	} `json:"identity"`
	Target struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	} `json:"target"`
}

// POST /t/{slug}/api/handoffs
func (s *Server) handoffCreate(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	var req handoffCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	if req.Identity.Issuer == "" || req.Identity.Subject == "" ||
		req.Target.Issuer == "" || req.Target.Subject == "" {
		writeAPIError(w, badRequest("identity.issuer/subject and target.issuer/subject are required"))
		return
	}

	h, err := s.store.CreateHandoff(r.Context(), store.CreateHandoffInput{
		TenantID:            ac.session.TenantID,
		Issuer:              req.Identity.Issuer,
		Subject:             req.Identity.Subject,
		OwnerMemberID:       ac.member.ID,
		OwnerSessionID:      ac.session.ID,
		TargetAnchorIssuer:  req.Target.Issuer,
		TargetAnchorSubject: req.Target.Subject,
	}, s.cfg.HandoffTTL)
	if err != nil {
		writeAPIError(w, s.mapHandoffWriteError(err, "create handoff failed"))
		return
	}
	writeJSON(w, http.StatusCreated, s.handoffView(h))
}

// GET /t/{slug}/api/handoffs —— 只返回本人参与的申请。
func (s *Server) handoffList(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	list, err := s.store.HandoffRequestsForMember(r.Context(), ac.session.TenantID, ac.member.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "list handoffs failed"))
		return
	}
	out := make([]map[string]any, 0, len(list))
	for i := range list {
		out = append(out, s.handoffView(&list[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"handoffs": out})
}

// GET /t/{slug}/api/handoffs/{id}
func (s *Server) handoffGet(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	id, ae := parseHandoffID(r.PathValue("id"))
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	h, ae := s.loadParticipantHandoff(r, id, ac)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	writeJSON(w, http.StatusOK, s.handoffView(h))
}

// POST /t/{slug}/api/handoffs/{id}/confirm
//
// 由当前会话的成员发起“自己这一方”的确认：
//   - 原绑定成员在 owner_pending 或 target_pending（后者用于刷新过期的证明）；
//   - 目标成员只在 target_pending。
//
// 返回 OIDC 授权地址（强制 prompt=login）。确认完成前身份归属不变。
func (s *Server) handoffConfirmStart(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	id, ae := parseHandoffID(r.PathValue("id"))
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	h, ae := s.loadParticipantHandoff(r, id, ac)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}

	role, roleErr := handoffRole(h, ac.member.ID)
	if roleErr != nil {
		writeAPIError(w, handoffNotFound("not a participant of this handoff"))
		return
	}
	switch role {
	case handoffRoleOwner:
		if h.Status != models.HandoffOwnerPending && h.Status != models.HandoffTargetPending {
			writeAPIError(w, s.stateConflict(h))
			return
		}
	case handoffRoleTarget:
		if h.Status != models.HandoffTargetPending {
			writeAPIError(w, s.stateConflict(h))
			return
		}
	}

	// 要新近认证的身份就是该方在本租户内的已核实身份锚点，provider 必须仍被租户授权。
	confirmIssuer := h.Issuer
	if role == handoffRoleTarget {
		confirmIssuer = h.TargetAnchorIssuer
	}
	slug := r.PathValue("slug")
	_, prov, ae2 := s.loadTenantProvider(r.Context(), slug, confirmIssuer)
	if ae2 != nil {
		writeAPIError(w, ae2)
		return
	}
	redirectURI := s.cfg.BaseURL + handoffCBPath
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("handoff callback url is not registered for this provider"))
		return
	}

	state, err := sec.State()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state failed"))
		return
	}
	nonce, err := sec.Nonce()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce failed"))
		return
	}
	verifier, err := sec.PKCEVerifier()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce failed"))
		return
	}
	kind := "handoff_owner"
	if role == handoffRoleTarget {
		kind = "handoff_target"
	}
	hID := h.ID
	sessID := ac.session.ID
	if err := s.store.CreateAuthRequest(r.Context(), &models.AuthRequest{
		State:        state,
		Kind:         kind,
		TenantID:     ac.session.TenantID,
		IDPID:        prov.ID,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     "/",
		HandoffID:    &hID,
		SessionID:    &sessID,
	}); err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist auth request failed"))
		return
	}
	// 原子把 state 绑定到申请+会话+角色；状态已变/换会话/到期都会在此被拒绝。
	if err := s.store.BindHandoffConfirmSession(r.Context(), role,
		h.ID, ac.session.TenantID, ac.member.ID, ac.session.ID, state); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAPIError(w, handoffConflict("handoff is not in a state that accepts this confirmation"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "bind confirmation failed"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	authURL := oidcx.AuthCodeURL(cfg, state, nonce, challenge, "S256", true, nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"handoff_id":    h.ID.String(),
		"role":          role,
		"confirm_url":   authURL,
		"current_state": h.Status,
	})
}

// GET /oauth/handoff/callback?state=...&code=...
//
// 任一方确认的统一回调：state 一次性消费、OIDC 全套校验、证明与申请中该方锚点逐字节一致、
// auth_time 必须新鲜；目标方证明提交后在同一请求内尝试完成交接。
// 回调乱序、重复、申请取消/拒绝/过期后迟到，都只会得到冲突/过期错误，绝不复活申请。
func (s *Server) handoffCallback(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}
	if ep := q.Get("error"); ep != "" {
		writeAPIError(w, authn("provider returned error: "+sanitizeErrParam(ep)))
		return
	}

	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("handoff authorization request is unknown or already used"))
		return
	}
	if (ar.Kind != "handoff_owner" && ar.Kind != "handoff_target") || ar.HandoffID == nil {
		writeAPIError(w, badRequest("state is not valid for a handoff confirmation"))
		return
	}
	// 必须用发起确认时的同一会话、同一租户。
	if ar.SessionID == nil || *ar.SessionID != ac.session.ID {
		writeAPIError(w, authn("handoff confirmation must use the same browser session that started it"))
		return
	}
	if ar.TenantID != ac.session.TenantID {
		writeAPIError(w, tenantForbidden("handoff crosses tenant boundary"))
		return
	}
	role := handoffRoleOwner
	if ar.Kind == "handoff_target" {
		role = handoffRoleTarget
	}

	h, err := s.store.HandoffRequest(r.Context(), *ar.HandoffID)
	if err != nil {
		writeAPIError(w, handoffNotFound("handoff not found"))
		return
	}
	if h.TenantID != ac.session.TenantID {
		writeAPIError(w, tenantForbidden("handoff crosses tenant boundary"))
		return
	}
	if !h.IsParticipant(ac.member.ID) {
		writeAPIError(w, handoffNotFound("not a participant of this handoff"))
		return
	}
	if role == handoffRoleOwner && h.OwnerMemberID != ac.member.ID {
		writeAPIError(w, handoffNotFound("state was issued for the other handoff party"))
		return
	}
	if role == handoffRoleTarget && h.TargetMemberID != ac.member.ID {
		writeAPIError(w, handoffNotFound("state was issued for the other handoff party"))
		return
	}
	if h.Status != models.HandoffOwnerPending && h.Status != models.HandoffTargetPending {
		writeAPIError(w, s.stateConflict(h))
		return
	}
	// 绑定到申请的待消费 state 必须就是这个 state（取消会清空绑定，迟到回调因此失败）。
	bound := h.OwnerConfirmState
	if role == handoffRoleTarget {
		bound = h.TargetConfirmState
	}
	if bound == "" || bound != state {
		writeAPIError(w, handoffConflict("confirmation state is stale or was superseded; start confirmation again"))
		return
	}

	// 回调必须在租户仍授权该 issuer 的前提下继续。
	prov, err := s.store.ProviderByID(r.Context(), ar.TenantID, ar.IDPID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, tenantForbidden("provider is no longer authorized for the tenant"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	redirectURI := s.cfg.BaseURL + handoffCBPath
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("handoff callback url is not registered for this provider"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	ver, err := s.oidc.Verifier(r.Context(), prov, ar.Nonce)
	if err != nil {
		writeAPIError(w, authn("failed to initialize token verifier"))
		return
	}
	claims, _, err := s.oidc.ExchangeAndVerify(r.Context(), prov, cfg, ver, code, ar.PKCEVerifier)
	if err != nil {
		s.logVerifyFailure(err)
		writeAPIError(w, authn("token exchange or id token verification failed"))
		return
	}

	// 新近证明必须就是该方应认证的那条身份锚点（issuer+subject 双重一致，邮箱从不参与）。
	wantIssuer := h.Issuer
	wantSubject := h.Subject
	if role == handoffRoleTarget {
		wantIssuer = h.TargetAnchorIssuer
		wantSubject = h.TargetAnchorSubject
	}
	if claims.Issuer != wantIssuer || claims.Subject != wantSubject {
		writeAPIError(w, authn("authenticated identity does not match the handoff party's anchor"))
		return
	}
	authTime := claims.AuthTime
	if authTime.IsZero() {
		writeAPIError(w, reauthRequired(
			"provider did not report auth_time; cannot prove recent re-authentication"))
		return
	}
	maxAge := providerAuthMaxAge(prov)
	if s.now().Sub(authTime) > maxAge {
		writeAPIError(w, reauthRequired("handoff confirmation authentication is stale; re-authenticate"))
		return
	}

	// 原子提交证明：state 逐字节比对、会话钉死、状态机校验全部在一条 UPDATE 内。
	if err := s.store.AttachHandoffProof(r.Context(), role,
		h.ID, ac.session.TenantID, ac.member.ID, ac.session.ID,
		state, claims.Issuer, claims.Subject, authTime); err != nil {
		if errors.Is(err, store.ErrExpired) {
			writeAPIError(w, handoffExpired("handoff request has expired"))
			return
		}
		writeAPIError(w, handoffConflict("handoff confirmation cannot be recorded in the current state"))
		return
	}

	resp := map[string]any{
		"handoff_id": h.ID.String(),
		"role":       role,
		"confirmed": map[string]string{
			"issuer":  claims.Issuer,
			"subject": claims.Subject,
		},
	}

	// owner 首次确认 -> target_pending，等待目标方确认；target 确认后直接尝试完成。
	if role == handoffRoleOwner {
		h2, err := s.store.HandoffRequest(r.Context(), h.ID)
		if err != nil {
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "reload handoff failed"))
			return
		}
		resp["status"] = h2.Status
		writeJSON(w, http.StatusOK, resp)
		return
	}

	rec, err := s.completeWithProviderWindows(r, h)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	resp["status"] = models.HandoffCompleted
	resp["record_id"] = rec.ID.String()
	writeJSON(w, http.StatusOK, resp)
}

// POST /t/{slug}/api/handoffs/{id}/reject
func (s *Server) handoffReject(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	id, ae := parseHandoffID(r.PathValue("id"))
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	h, ae := s.loadParticipantHandoff(r, id, ac)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	var asOwner bool
	switch {
	case h.OwnerMemberID == ac.member.ID:
		asOwner = true
	case h.TargetMemberID == ac.member.ID:
		asOwner = false
	default:
		writeAPIError(w, handoffNotFound("not a participant of this handoff"))
		return
	}
	if err := s.store.RejectHandoff(r.Context(),
		store.HandoffDecision{ID: id, TenantID: ac.session.TenantID, MemberID: ac.member.ID}, asOwner); err != nil {
		writeAPIError(w, s.mapHandoffWriteError(err, "reject handoff failed"))
		return
	}
	h2, _ := s.store.HandoffRequest(r.Context(), id)
	writeJSON(w, http.StatusOK, s.handoffView(h2))
}

// POST /t/{slug}/api/handoffs/{id}/cancel —— 任意参与方在申请存活时可取消。
func (s *Server) handoffCancel(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	id, ae := parseHandoffID(r.PathValue("id"))
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	if _, ae := s.loadParticipantHandoff(r, id, ac); ae != nil {
		writeAPIError(w, ae)
		return
	}
	if err := s.store.CancelHandoff(r.Context(),
		store.HandoffDecision{ID: id, TenantID: ac.session.TenantID, MemberID: ac.member.ID}); err != nil {
		writeAPIError(w, s.mapHandoffWriteError(err, "cancel handoff failed"))
		return
	}
	h2, _ := s.store.HandoffRequest(r.Context(), id)
	writeJSON(w, http.StatusOK, s.handoffView(h2))
}

// POST /t/{slug}/api/handoffs/{id}/complete
//
// 幂等的完成入口：双方确认都已新鲜提交后，任意一方可调用；
// 真正的复核与归属移动全部发生在 store.CompleteHandoff 的单事务里。
func (s *Server) handoffComplete(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	id, ae := parseHandoffID(r.PathValue("id"))
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	h, ae := s.loadParticipantHandoff(r, id, ac)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	if !h.IsParticipant(ac.member.ID) {
		writeAPIError(w, handoffNotFound("not a participant of this handoff"))
		return
	}
	if h.Status == models.HandoffCompleted {
		// 幂等：已完成的申请直接返回当前状态。
		writeJSON(w, http.StatusOK, s.handoffView(h))
		return
	}

	rec, err := s.completeWithProviderWindows(r, h)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	fresh, err := s.store.HandoffRequest(r.Context(), id)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "reload handoff failed"))
		return
	}
	view := s.handoffView(fresh)
	view["record_id"] = rec.ID.String()
	writeJSON(w, http.StatusOK, view)
}

// completeWithProviderWindows 以双方各自 provider 的新鲜度窗口调用单事务完成。
func (s *Server) completeWithProviderWindows(r *http.Request,
	h *models.HandoffRequest) (*models.HandoffRecord, error) {
	ownerProv, err := s.store.ProviderByIssuer(r.Context(), h.TenantID, h.Issuer)
	if err != nil {
		return nil, tenantForbidden("provider is no longer authorized for the tenant")
	}
	targetProv, err := s.store.ProviderByIssuer(r.Context(), h.TenantID, h.TargetAnchorIssuer)
	if err != nil {
		return nil, tenantForbidden("provider is no longer authorized for the tenant")
	}
	if !ownerProv.Enabled || !targetProv.Enabled {
		return nil, tenantForbidden("identity provider is disabled for the tenant")
	}
	rec, err := s.store.CompleteHandoff(r.Context(), h.ID, s.now(),
		providerAuthMaxAge(ownerProv), providerAuthMaxAge(targetProv))
	if err != nil {
		return nil, s.mapHandoffWriteError(err, "complete handoff failed")
	}
	return rec, nil
}

// ---------- helpers ----------

func parseHandoffID(raw string) (uuid.UUID, *APIError) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, handoffNotFound("handoff not found")
	}
	return id, nil
}

// loadParticipantHandoff 惰性过期后读取申请，并要求调用成员是参与方、租户一致。
func (s *Server) loadParticipantHandoff(r *http.Request, id uuid.UUID, ac *authedContext) (
	*models.HandoffRequest, *APIError) {
	if _, err := s.store.ExpireHandoffIfDue(r.Context(), id); err != nil {
		return nil, newAPIError(http.StatusInternalServerError, "internal_error", "expire handoff failed")
	}
	h, err := s.store.HandoffRequest(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, handoffNotFound("handoff not found")
		}
		return nil, newAPIError(http.StatusInternalServerError, "internal_error", "load handoff failed")
	}
	if h.TenantID != ac.session.TenantID {
		return nil, tenantForbidden("handoff belongs to another tenant")
	}
	if !h.IsParticipant(ac.member.ID) {
		// 不暴露申请存在性。
		return nil, handoffNotFound("handoff not found")
	}
	return h, nil
}

func handoffRole(h *models.HandoffRequest, memberID uuid.UUID) (string, error) {
	switch memberID {
	case h.OwnerMemberID:
		return handoffRoleOwner, nil
	case h.TargetMemberID:
		return handoffRoleTarget, nil
	default:
		return "", store.ErrNotFound
	}
}

// stateConflict 把终态映射为明确的错误类别（过期 410，其余 409 handoff_conflict）。
func (s *Server) stateConflict(h *models.HandoffRequest) *APIError {
	if h.Status == models.HandoffExpired {
		return handoffExpired("handoff request has expired")
	}
	return handoffConflict("handoff is " + h.Status + " and does not accept this action")
}

func (s *Server) mapHandoffWriteError(err error, internalMsg string) *APIError {
	switch {
	case errors.Is(err, store.ErrExpired):
		return handoffExpired("handoff request has expired")
	case errors.Is(err, store.ErrNotFound):
		return handoffNotFound("handoff or referenced identity not found")
	case errors.Is(err, store.ErrConflict):
		return handoffConflict("handoff state or identity ownership does not allow this action")
	case errors.Is(err, store.ErrNotBoundToCaller):
		return handoffConflict("the identity to hand off is not bound to the calling member")
	case errors.Is(err, store.ErrSameMember):
		return badRequest("target must be a different member")
	case errors.Is(err, store.ErrAnchorMoved):
		return handoffConflict("an identity anchor changed during the handoff; the binding was not moved")
	}
	if msg, ok := store.AsReauth(err); ok {
		return reauthRequired(msg)
	}
	s.logger.Printf("%s: %v", internalMsg, err)
	return newAPIError(http.StatusInternalServerError, "internal_error", internalMsg)
}

// handoffView 构造对外视图：刻意不含任何令牌与邮箱。
func (s *Server) handoffView(h *models.HandoffRequest) map[string]any {
	v := map[string]any{
		"id":     h.ID.String(),
		"status": h.Status,
		"identity": map[string]string{
			"issuer":  h.Issuer,
			"subject": h.Subject,
		},
		"target_anchor": map[string]string{
			"issuer":  h.TargetAnchorIssuer,
			"subject": h.TargetAnchorSubject,
		},
		"owner_member_id":  h.OwnerMemberID.String(),
		"target_member_id": h.TargetMemberID.String(),
		"created_at":       h.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":       h.ExpiresAt.UTC().Format(time.RFC3339),
		"owner_confirmed":  h.OwnerConfirmedAt.Valid,
		"target_confirmed": h.TargetConfirmedAt.Valid,
	}
	return v
}
