package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func loginMember(t *testing.T, tenantSlug string, user keycloakUser) *browserClient {
	t.Helper()
	b := newBrowserClient(t)
	resp := b.login(tenantSlug, user)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return b
}

// TestIdentityHandoverHappyPath 验证双方新近 OIDC 确认完成后，
// 身份在同一事务中从原成员移动到目标成员，且原成员会话立即失效。
func TestIdentityHandoverHappyPath(t *testing.T) {
	env := startEnv(t)

	source := loginMember(t, "acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	target := loginMember(t, "acme", keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	sourceID := source.memberID("acme")
	targetID := target.memberID("acme")
	if sourceID == targetID {
		t.Fatalf("source and target collapsed to one member")
	}

	identityIssuer := issuer("acme")
	identitySubject := subjectOf(t, env, "acme", "alice@example.com")
	before := identityOwner(t, env, tenantAcmeID, identityIssuer, identitySubject)
	if before != sourceID {
		t.Fatalf("initial owner=%s, want %s", before, sourceID)
	}

	h := target.createHandover("acme", identityIssuer, identitySubject, targetID, http.StatusCreated)
	id := h["id"].(string)
	if h["status"] != "pending" {
		t.Fatalf("created handover status=%v, want pending", h["status"])
	}

	sourceOut := source.confirmHandover("acme", id, "source",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}, "", "", http.StatusOK)
	if sourceOut["status"] != "source_confirmed" {
		t.Fatalf("after source confirmation status=%v, want source_confirmed", sourceOut["status"])
	}
	targetOut := target.confirmHandover("acme", id, "target",
		keycloakUser{realm: "acme", username: "carol", password: "carol-pass"},
		identityIssuer, subjectOf(t, env, "acme", "carol@example.com"), http.StatusOK)
	if targetOut["status"] != "completed" {
		t.Fatalf("after target confirmation status=%v, want completed", targetOut["status"])
	}

	after := identityOwner(t, env, tenantAcmeID, identityIssuer, identitySubject)
	if after != targetID {
		t.Fatalf("identity owner after handover=%s, want target %s", after, targetID)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, identityIssuer, identitySubject); n != 1 {
		t.Fatalf("handed identity rows=%d, want exactly 1", n)
	}

	// 完成时撤销原成员所有现存会话；原会话不能再调用受保护接口。
	stale := readBody(t, source.meResponse("acme"))
	if _, ok := stale["error"]; !ok || stale["error"] != "authentication_failed" {
		t.Fatalf("old source session after handover=%v, want authentication_failed", stale)
	}

	// 原成员再次 OIDC 登录时，锚点现在属于目标成员，因此进入目标成员，而不是恢复原归属。
	// 使用新浏览器，避免刚被撤销的应用 sid 跟随请求；Keycloak 侧仍强制重新登录。
	resource := newBrowserClient(t)
	cb := resource.login("acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusFound {
		t.Fatalf("login with transferred identity status=%d, want 302", cb.StatusCode)
	}
	_ = cb.Body.Close()
	if got := resource.memberID("acme"); got != targetID {
		t.Fatalf("login with transferred identity returned member=%s, want target %s", got, targetID)
	}

	// 审计记录不包含邮箱，也不包含 state/nonce/code/token。
	var eventCount int
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT count(*) FROM identity_handover_events
		 WHERE handover_id=$1 AND event_type IN
		       ('created','source_confirmed','target_confirmed','completed')`,
		id).Scan(&eventCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if eventCount != 4 {
		t.Fatalf("handover audit events=%d, want 4", eventCount)
	}
	var columns int
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_name='identity_handovers'
		   AND column_name IN ('email','token','state','nonce','pkce_verifier')`).Scan(&columns); err != nil {
		t.Fatalf("inspect sensitive columns: %v", err)
	}
	if columns != 0 {
		t.Fatalf("handover table contains sensitive columns count=%d, want 0", columns)
	}
}

// TestIdentityHandoverRejectKeepsBinding 验证原成员拒绝后身份归属不变。
func TestIdentityHandoverRejectKeepsBinding(t *testing.T) {
	env := startEnv(t)
	source := loginMember(t, "acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	target := loginMember(t, "acme", keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	sourceID, targetID := source.memberID("acme"), target.memberID("acme")
	sub := subjectOf(t, env, "acme", "alice@example.com")

	h := target.createHandover("acme", issuer("acme"), sub, targetID, http.StatusCreated)
	out := source.postHandover("acme", "/"+h["id"].(string)+"/reject", nil, http.StatusOK)
	if out["status"] != "rejected" {
		t.Fatalf("reject status=%v, want rejected", out["status"])
	}
	if owner := identityOwner(t, env, tenantAcmeID, issuer("acme"), sub); owner != sourceID {
		t.Fatalf("owner after reject=%s, want source %s", owner, sourceID)
	}

	// 终结后迟到的确认不能复活申请。
	status, body := source.postHandoverRaw("acme", "/"+h["id"].(string)+"/source-confirm", nil)
	if status != http.StatusConflict || body["error"] != "binding_conflict" {
		t.Fatalf("late source confirmation status=%d body=%v", status, body)
	}
}

// TestIdentityHandoverExpiredKeepsBinding 验证过期是明确状态，且原绑定保持不变。
func TestIdentityHandoverExpiredKeepsBinding(t *testing.T) {
	env := startEnv(t)
	source := loginMember(t, "acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	target := loginMember(t, "acme", keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	sourceID, targetID := source.memberID("acme"), target.memberID("acme")
	sub := subjectOf(t, "acme", "alice@example.com")

	h := target.createHandover("acme", issuer("acme"), sub, targetID, http.StatusCreated)
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE identity_handovers SET expires_at=$2 WHERE id=$1`,
		h["id"].(string), time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("age handover: %v", err)
	}
	out := target.getHandover("acme", h["id"].(string), http.StatusGone)
	if out["error"] != "expired" {
		t.Fatalf("expired query error=%v, want expired", out["error"])
	}
	if owner := identityOwner(t, env, tenantAcmeID, issuer("acme"), sub); owner != sourceID {
		t.Fatalf("owner after expiry=%s, want source %s", owner, sourceID)
	}
	var status string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT status FROM identity_handovers WHERE id=$1`, h["id"].(string)).Scan(&status); err != nil {
		t.Fatalf("read handover status: %v", err)
	}
	if status != "expired" {
		t.Fatalf("db status=%s, want expired", status)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identity_handover_events
		 WHERE handover_id=$1 AND event_type='expired'`, h["id"].(string)); n != 1 {
		t.Fatalf("expired audit events=%d, want 1", n)
	}
}

// TestIdentityHandoverConcurrentApplications 验证同一身份同时只能有一个活跃申请。
func TestIdentityHandoverConcurrentApplications(t *testing.T) {
	env := startEnv(t)
	source := loginMember(t, "acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	targetA := loginMember(t, "acme", keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	env.kc.CreateUser("acme", "dave", "dave@example.com", "dave-pass")
	targetB := loginMember(t, "acme", keycloakUser{realm: "acme", username: "dave", password: "dave-pass"})

	// 两个不同目标成员并发申请同一身份；部分唯一索引与行锁保证只有一个活跃申请。
	sourceID := source.memberID("acme")
	targetID := targetA.memberID("acme")
	otherTargetID := targetB.memberID("acme")
	sub := subjectOf(t, env, "acme", "alice@example.com")

	browsers := []*browserClient{targetA, targetB}
	targets := []string{targetID, otherTargetID}
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		i := i
		b := browsers[i]
		go func() {
			status, _ := b.postHandoverRaw("acme", "", map[string]string{
				"issuer":           issuer("acme"),
				"subject":          sub,
				"target_member_id": targets[i],
			})
			results <- status
		}()
	}
	created, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		switch <-results {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent create status")
		}
	}
	if created != 1 || conflicts != 1 {
		t.Fatalf("concurrent handovers created=%d conflicts=%d, want 1/1", created, conflicts)
	}
	if owner := identityOwner(t, env, tenantAcmeID, issuer("acme"), sub); owner != sourceID {
		t.Fatalf("owner after concurrent create=%s, want unchanged source", owner)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identity_handovers
		 WHERE tenant_id=$1 AND identity_issuer=$2 AND identity_subject=$3
		   AND status IN ('pending','source_confirmed','target_confirmed')`,
		tenantAcmeID, issuer("acme"), sub); n != 1 {
		t.Fatalf("active handovers=%d, want 1", n)
	}
}

// TestIdentityHandoverCancelRejectsLateProof 验证取消后迟到 OIDC 回调不能复活申请。
func TestIdentityHandoverCancelRejectsLateProof(t *testing.T) {
	env := startEnv(t)
	source := loginMember(t, "acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	target := loginMember(t, "acme", keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	targetID := target.memberID("acme")
	sub := subjectOf(t, env, "acme", "alice@example.com")
	h := target.createHandover("acme", issuer("acme"), sub, targetID, http.StatusCreated)

	start := source.postHandover("acme", "/"+h["id"].(string)+"/source-confirm", nil, http.StatusOK)
	callbackURL := source.kc.passwordLogin(start["auth_url"].(string),
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})

	cancelled := target.postHandover("acme", "/"+h["id"].(string)+"/cancel", nil, http.StatusOK)
	if cancelled["status"] != "cancelled" {
		t.Fatalf("cancel status=%v, want cancelled", cancelled["status"])
	}
	late := source.callAppCallback(callbackURL)
	body := readBody(t, late)
	if late.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("late callback after cancel status=%d body=%v, want 400 invalid_request",
			late.StatusCode, body)
	}
	again := target.getHandover("acme", h["id"].(string), http.StatusOK)
	if again["status"] != "cancelled" {
		t.Fatalf("handover after late callback status=%v, want cancelled", again["status"])
	}
}

// TestIdentityHandoverTenantAndSessionBoundaries 验证跨租户同邮箱、错误会话
// 和非参与成员均不能查询或操作交接。
func TestIdentityHandoverTenantAndSessionBoundaries(t *testing.T) {
	env := startEnv(t)
	source := loginMember(t, "acme", keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	target := loginMember(t, "acme", keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	otherTenant := loginMember(t, "globex",
		keycloakUser{realm: "globex", username: "alice.globex", password: "aliceg-pass"})

	targetID := target.memberID("acme")
	sub := subjectOf(t, env, "acme", "alice@example.com")
	h := target.createHandover("acme", issuer("acme"), sub, targetID, http.StatusCreated)

	cross := otherTenant.getHandover("acme", h["id"].(string), http.StatusForbidden)
	if cross["error"] != "tenant_unauthorized" {
		t.Fatalf("cross tenant handover access=%v, want tenant_unauthorized", cross)
	}
	// 同邮箱但 globex 租户身份不能作为 acme 租户目标。
	globexSub := subjectOf(t, env, "globex", "alice@example.com")
	status, body := otherTenant.postHandoverRaw("globex", "", map[string]string{
		"issuer":           issuer("globex"),
		"subject":          globexSub,
		"target_member_id": targetID,
	})
	if status != http.StatusNotFound || body["error"] != "not_found" {
		t.Fatalf("cross-tenant target member status=%d body=%v, want 404 not_found", status, body)
	}

	// 错误会话：目标浏览器持有的是目标 sid，不能发起原成员确认。
	wrong, wrongBody := target.postHandoverRaw("acme", "/"+h["id"].(string)+"/source-confirm", nil)
	if wrong != http.StatusForbidden || wrongBody["error"] != "tenant_unauthorized" {
		t.Fatalf("wrong actor source confirm status=%d body=%v, want 403", wrong, wrongBody)
	}

	// 原成员启动 OIDC 后，用目标成员的应用会话打回调也必须被拒绝；申请不会被推进。
	sourceStart := source.postHandover("acme", "/"+h["id"].(string)+"/source-confirm", nil, http.StatusOK)
	sourceCallbackURL := source.kc.passwordLogin(sourceStart["auth_url"].(string),
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	wrongSession := target.callAppCallback(sourceCallbackURL)
	wrongSessionBody := readBody(t, wrongSession)
	if wrongSession.StatusCode != http.StatusUnauthorized || wrongSessionBody["error"] != "authentication_failed" {
		t.Fatalf("wrong session handover callback status=%d body=%v, want 401 authentication_failed",
			wrongSession.StatusCode, wrongSessionBody)
	}
	stillPending := source.getHandover("acme", h["id"].(string), http.StatusOK)
	if stillPending["status"] != "pending" {
		t.Fatalf("handover after wrong-session callback status=%v, want pending", stillPending["status"])
	}

	// 非参与成员不能看到本人列表外的申请（直接 GET 也 403）。
	if hs := source.listHandovers("acme", http.StatusOK); len(hs) != 1 {
		t.Fatalf("source handovers=%d, want 1", len(hs))
	}
	if hs := otherTenant.listHandovers("globex", http.StatusOK); len(hs) != 0 {
		t.Fatalf("globex handovers=%d, want 0", len(hs))
	}
}
