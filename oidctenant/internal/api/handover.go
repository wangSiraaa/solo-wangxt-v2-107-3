package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
	"github.com/google/uuid"
)

type createHandoverRequest struct {
	Issuer         string `json:"issuer"`
	Subject        string `json:"subject"`
	TargetMemberID string `json:"target_member_id"`
}

type targetProofRequest struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type handoverView struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	Status            string     `json:"status"`
	Role              string     `json:"role,omitempty"`
	IdentityID        string     `json:"identity_id"`
	IdentityIssuer    string     `json:"identity_issuer"`
	IdentitySubject   string     `json:"identity_subject"`
	SourceMemberID    string     `json:"source_member_id"`
	TargetMemberID    string     `json:"target_member_id"`
	SourceProof       *proofView `json:"source_proof,omitempty"`
	TargetProof       *proofView `json:"target_proof,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	ConfirmedAt       *time.Time `json:"source_confirmed_at,omitempty"`
	TargetConfirmedAt *time.Time `json:"target_confirmed_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	DecidedAt         *time.Time `json:"decided_at,omitempty"`
}

type proofView struct {
	Issuer      string     `json:"issuer"`
	Subject     string     `json:"subject"`
	AuthTime    *time.Time `json:"auth_time,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

// POST /t/{slug}/api/identity-handovers
//
// 由目标成员发起。申请创建后身份仍属于原成员；活跃申请由数据库部分唯一索引限制。
func (s *Server) createHandover(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	var req createHandoverRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	if req.Issuer == "" || req.Subject == "" || req.TargetMemberID == "" {
		writeAPIError(w, badRequest("issuer, subject and target_member_id are required"))
		return
	}
	targetID, err := uuid.Parse(req.TargetMemberID)
	if err != nil {
		writeAPIError(w, badRequest("target_member_id must be a UUID"))
		return
	}
	if targetID != ac.member.ID {
		writeAPIError(w, tenantForbidden("target_member_id must identify the authenticated member"))
		return
	}

	tenant, ae := s.tenantFromSlug(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	if _, err := s.store.Member(r.Context(), tenant.ID, targetID); err != nil {
		writeAPIError(w, mapHandoverError(err, "target member is not in this tenant"))
		return
	}
	identity, err := s.store.IdentityByAnchor(r.Context(), tenant.ID, req.Issuer, req.Subject)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "identity is not bound in this tenant"))
		return
	}
	if identity.MemberID == targetID {
		writeAPIError(w, conflict("identity already belongs to the target member"))
		return
	}
	prov, err := s.store.ProviderByIssuer(r.Context(), tenant.ID, req.Issuer)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "identity issuer is not authorized for the tenant"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}

	h, err := s.store.CreateIdentityHandover(r.Context(), tenant.ID, identity.ID,
		identity.MemberID, targetID, ac.session.ID, s.cfg.HandoverTTL)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "create identity handover failed"))
		return
	}
	writeJSON(w, http.StatusCreated, s.handoverView(h, ac.member.ID))
}

// GET /t/{slug}/api/identity-handovers
func (s *Server) listHandovers(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	tenant, ae := s.tenantFromSlug(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	hs, err := s.store.ListIdentityHandovers(r.Context(), tenant.ID, ac.member.ID)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "list identity handovers failed"))
		return
	}
	out := make([]handoverView, 0, len(hs))
	for i := range hs {
		out = append(out, s.handoverView(&hs[i], ac.member.ID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"handovers": out})
}

// GET /t/{slug}/api/identity-handovers/{id}
func (s *Server) getHandover(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	h, ae := s.loadParticipantHandover(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	writeJSON(w, http.StatusOK, s.handoverView(h, ac.member.ID))
}

// POST .../{id}/source-confirm
func (s *Server) startSourceHandoverConfirm(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	h, ae := s.loadParticipantHandover(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	if h.SourceMemberID != ac.member.ID {
		writeAPIError(w, tenantForbidden("only the current owner can confirm as source"))
		return
	}
	prov, err := s.store.ProviderByIssuer(r.Context(), h.TenantID, h.IdentityIssuer)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "identity provider is unavailable"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	s.startHandoverProof(w, r, h, ac, prov, "source")
}

// POST .../{id}/target-confirm body: {"issuer":"...", "subject":"..."}
func (s *Server) startTargetHandoverConfirm(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	h, ae := s.loadParticipantHandover(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	if h.TargetMemberID != ac.member.ID {
		writeAPIError(w, tenantForbidden("only the target member can provide target proof"))
		return
	}
	var req targetProofRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	if req.Issuer == "" || req.Subject == "" {
		writeAPIError(w, badRequest("issuer and subject are required"))
		return
	}
	ids, err := s.store.IdentitiesOfMember(r.Context(), h.TenantID, ac.member.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "load target identities failed"))
		return
	}
	var proofIdentity *models.Identity
	for i := range ids {
		if ids[i].Issuer == req.Issuer && ids[i].Subject == req.Subject {
			proofIdentity = &ids[i]
			break
		}
	}
	if proofIdentity == nil {
		writeAPIError(w, tenantForbidden("proof identity is not currently bound to the target member"))
		return
	}
	if proofIdentity.Issuer == h.IdentityIssuer && proofIdentity.Subject == h.IdentitySubject {
		writeAPIError(w, conflict("target proof must not be the identity being handed over"))
		return
	}
	prov, err := s.store.ProviderByIssuer(r.Context(), h.TenantID, proofIdentity.Issuer)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "proof issuer is not authorized for the tenant"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	s.startHandoverProof(w, r, h, ac, prov, "target")
}

func (s *Server) startHandoverProof(w http.ResponseWriter, r *http.Request, h *models.IdentityHandover,
	ac *authedContext, prov *models.Provider, role string) {
	redirectURI := s.redirectURLHandover()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("handover callback url is not registered for this provider"))
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
	kind := "handover_" + role
	if err := s.store.CreateHandoverProofAuthRequest(r.Context(), h.ID, ac.member.ID,
		ac.session.ID, prov.ID, state, kind, nonce, verifier, role, s.now()); err != nil {
		writeAPIError(w, mapHandoverError(err, "start handover confirmation failed"))
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
		"handover_id": h.ID.String(),
		"role":        role,
		"auth_url":    authURL,
	})
}

// GET /oauth/handover/callback?state=...&code=...
func (s *Server) handoverCallback(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}
	if ep := r.URL.Query().Get("error"); ep != "" {
		writeAPIError(w, authn("provider returned error: "+sanitizeErrParam(ep)))
		return
	}
	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("handover authorization request is unknown or already used"))
		return
	}
	var role string
	switch ar.Kind {
	case "handover_source":
		role = "source"
	case "handover_target":
		role = "target"
	default:
		writeAPIError(w, badRequest("state is not valid for identity handover"))
		return
	}
	if ar.HandoverID == nil {
		writeAPIError(w, badRequest("state is not bound to a handover"))
		return
	}
	if ar.SessionID == nil || *ar.SessionID != ac.session.ID || ar.TenantID != ac.session.TenantID {
		writeAPIError(w, authn("handover confirmation must use the same session that started it"))
		return
	}
	h, err := s.store.IdentityHandover(r.Context(), ar.TenantID, *ar.HandoverID)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "handover not found"))
		return
	}
	if role == "source" && h.SourceMemberID != ac.member.ID {
		writeAPIError(w, tenantForbidden("callback actor is not the current owner"))
		return
	}
	if role == "target" && h.TargetMemberID != ac.member.ID {
		writeAPIError(w, tenantForbidden("callback actor is not the target member"))
		return
	}
	if h.Status == "expired" {
		writeAPIError(w, expired("identity handover has expired"))
		return
	}

	prov, err := s.store.ProviderByID(r.Context(), ar.TenantID, ar.IDPID)
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "provider is no longer authorized for the tenant"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	redirectURI := s.redirectURLHandover()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("handover callback url is not registered for this provider"))
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
	if claims.Issuer != prov.Issuer {
		writeAPIError(w, authn("id token issuer does not match the configured provider"))
		return
	}
	maxAge := providerAuthMaxAge(prov)
	h, err = s.store.AttachHandoverProof(r.Context(), h.ID, role, store.HandoverProofInput{
		State:     state,
		IDPID:     prov.ID,
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		AuthTime:  claims.AuthTime,
		SessionID: ac.session.ID,
		MemberID:  ac.member.ID,
	}, maxAge, s.now())
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "record handover proof failed"))
		return
	}
	if role == "target" {
		h, err = s.store.CompleteIdentityHandover(r.Context(), h.ID, ac.member.ID, ac.session.ID, s.now())
		if err != nil {
			writeAPIError(w, mapHandoverError(err, "complete handover failed"))
			return
		}
	}
	writeJSON(w, http.StatusOK, s.handoverView(h, ac.member.ID))
}

// POST .../{id}/complete
func (s *Server) completeHandover(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	h, ae := s.loadParticipantHandover(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	h, err := s.store.CompleteIdentityHandover(r.Context(), h.ID, ac.member.ID, ac.session.ID, s.now())
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "complete handover failed"))
		return
	}
	writeJSON(w, http.StatusOK, s.handoverView(h, ac.member.ID))
}

// POST .../{id}/reject
func (s *Server) rejectHandover(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	h, ae := s.loadParticipantHandover(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	h, err := s.store.RejectIdentityHandover(r.Context(), h.ID, ac.member.ID, ac.session.ID, s.now())
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "reject handover failed"))
		return
	}
	writeJSON(w, http.StatusOK, s.handoverView(h, ac.member.ID))
}

// POST .../{id}/cancel
func (s *Server) cancelHandover(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	h, ae := s.loadParticipantHandover(r)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	h, err := s.store.CancelIdentityHandover(r.Context(), h.ID, ac.member.ID, ac.session.ID, s.now())
	if err != nil {
		writeAPIError(w, mapHandoverError(err, "cancel handover failed"))
		return
	}
	writeJSON(w, http.StatusOK, s.handoverView(h, ac.member.ID))
}

func (s *Server) tenantFromSlug(r *http.Request) (*models.Tenant, *APIError) {
	tenant, err := s.store.TenantBySlug(r.Context(), r.PathValue("slug"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, tenantForbidden("unknown tenant")
		}
		return nil, newAPIError(http.StatusInternalServerError, "internal_error", "lookup tenant failed")
	}
	return tenant, nil
}

func (s *Server) loadParticipantHandover(r *http.Request) (*models.IdentityHandover, *APIError) {
	ac := authed(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return nil, badRequest("handover id must be a UUID")
	}
	tenant, ae := s.tenantFromSlug(r)
	if ae != nil {
		return nil, ae
	}
	h, err := s.store.IdentityHandover(r.Context(), tenant.ID, id)
	if err != nil {
		return nil, mapHandoverError(err, "handover not found")
	}
	if ac.member.ID != h.SourceMemberID && ac.member.ID != h.TargetMemberID {
		return nil, tenantForbidden("handover belongs to another member")
	}
	return h, nil
}

func (s *Server) handoverView(h *models.IdentityHandover, actorID uuid.UUID) handoverView {
	role := ""
	if actorID == h.SourceMemberID {
		role = "source"
	} else if actorID == h.TargetMemberID {
		role = "target"
	}
	v := handoverView{
		ID:              h.ID.String(),
		TenantID:        h.TenantID.String(),
		Status:          h.Status,
		Role:            role,
		IdentityID:      h.IdentityID.String(),
		IdentityIssuer:  h.IdentityIssuer,
		IdentitySubject: h.IdentitySubject,
		SourceMemberID:  h.SourceMemberID.String(),
		TargetMemberID:  h.TargetMemberID.String(),
		CreatedAt:       h.CreatedAt,
		ExpiresAt:       h.ExpiresAt,
	}
	if h.SourceAuthTime.Valid || h.SourceConfirmedAt.Valid {
		v.SourceProof = &proofView{
			Issuer:  h.SourceIssuer,
			Subject: h.SourceSubject,
		}
		if h.SourceAuthTime.Valid {
			t := h.SourceAuthTime.Time
			v.SourceProof.AuthTime = &t
		}
		if h.SourceConfirmedAt.Valid {
			t := h.SourceConfirmedAt.Time
			v.SourceProof.ConfirmedAt = &t
			v.ConfirmedAt = &t
		}
	}
	if h.TargetAuthTime.Valid || h.TargetConfirmedAt.Valid {
		v.TargetProof = &proofView{
			Issuer:  h.TargetIssuer,
			Subject: h.TargetSubject,
		}
		if h.TargetAuthTime.Valid {
			t := h.TargetAuthTime.Time
			v.TargetProof.AuthTime = &t
		}
		if h.TargetConfirmedAt.Valid {
			t := h.TargetConfirmedAt.Time
			v.TargetProof.ConfirmedAt = &t
			v.TargetConfirmedAt = &t
		}
	}
	if h.CompletedAt.Valid {
		t := h.CompletedAt.Time
		v.CompletedAt = &t
	}
	if h.DecidedAt.Valid {
		t := h.DecidedAt.Time
		v.DecidedAt = &t
	}
	return v
}

func mapHandoverError(err error, fallback string) *APIError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return newAPIError(http.StatusNotFound, "not_found", fallback)
	case errors.Is(err, store.ErrExpired):
		return expired("identity handover has expired")
	case errors.Is(err, store.ErrConflict):
		return conflict("identity handover state conflicts with another request or operation")
	case errors.Is(err, store.ErrForbidden):
		return tenantForbidden(fallback)
	case errors.Is(err, store.ErrProofMismatch):
		return authn("OIDC proof does not match the required identity")
	case errors.Is(err, store.ErrAuthSession):
		return authn("handover session is invalid, expired or revoked")
	}
	if msg, ok := store.AsReauth(err); ok {
		return reauthRequired(msg)
	}
	return newAPIError(http.StatusInternalServerError, "internal_error", fallback)
}
