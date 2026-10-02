package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/store"
)

func acmeUser(name string) keycloakUser {
	return keycloakUser{realm: "acme", username: name, password: name + "-pass"}
}

// handoffBody 构造发起交接的嵌套请求体（目标成员只用锚点表达，绝不用邮箱）。
func handoffBody(identity, target map[string]string) map[string]any {
	return map[string]any{"identity": identity, "target": target}
}

// TestHandoffHappyPath 验收主路径：
// 同租户两名成员完成双方确认后，身份只归目标成员；原成员的既有会话不再持有该身份，
// 原成员的身份重新登录会落到目标成员上；审计记录不含令牌与邮箱。
func TestHandoffHappyPath(t *testing.T) {
	env := startEnv(t)

	owner := newBrowserClient(t)
	if r := owner.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("owner login status=%d", r.StatusCode)
	}
	target := newBrowserClient(t)
	if r := target.login("acme", acmeUser("carol")); r.StatusCode != http.StatusFound {
		t.Fatalf("target login status=%d", r.StatusCode)
	}

	ownerMe := owner.me("acme")
	targetMe := target.me("acme")
	ownerID := ownerMe["member_id"].(string)
	targetID := targetMe["member_id"].(string)
	ownerAnchor := anchorFromMe(ownerMe, issuer("acme"))
	targetAnchor := anchorFromMe(targetMe, issuer("acme"))
	if ownerAnchor == nil || targetAnchor == nil || ownerID == targetID {
		t.Fatalf("bad anchors/owner ids: %v %v", ownerAnchor, targetAnchor)
	}

	created := owner.createHandoff("acme", handoffBody(ownerAnchor, targetAnchor))
	id := created["id"].(string)
	if created["status"] != "owner_pending" {
		t.Fatalf("new handoff status=%v, want owner_pending", created["status"])
	}
	if created["owner_confirmed"] != false {
		t.Fatalf("new handoff should not be confirmed: %v", created)
	}

	// 目标方不能抢在原绑定成员之前确认（乱序）。
	if status, body := target.handoffActionRaw("acme", id, "confirm"); status != http.StatusConflict ||
		body["error"] != "handoff_conflict" {
		t.Fatalf("target early confirm status=%d body=%v, want 409 handoff_conflict", status, body)
	}

	// 原绑定成员强制重认证确认。
	cb := owner.confirmHandoff("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	ownerCB := readBody(t, cb)
	if cb.StatusCode != http.StatusOK || ownerCB["status"] != "target_pending" {
		t.Fatalf("owner confirm status=%d body=%v, want 200 target_pending", cb.StatusCode, ownerCB)
	}

	// 目标成员强制重认证确认，回调内单事务完成。
	cb = target.confirmHandoff("acme", id, acmeUser("carol"))
	targetCB := readBody(t, cb)
	if cb.StatusCode != http.StatusOK || targetCB["status"] != "completed" {
		t.Fatalf("target confirm status=%d body=%v, want 200 completed", cb.StatusCode, targetCB)
	}
	if targetCB["record_id"] == nil || targetCB["record_id"] == "" {
		t.Fatalf("completed response should carry record_id: %v", targetCB)
	}

	// 身份只归目标成员：原成员 /me 已无任何身份。
	if ids := owner.identities("acme"); len(ids) != 0 {
		t.Fatalf("former owner still has identities after handoff: %v", ids)
	}
	if ids := target.identities("acme"); len(ids) != 2 {
		t.Fatalf("target identities=%v, want 2 (own anchor + received)", ids)
	}

	// DB：归属已移动，申请 completed，审计记录恰好一条。
	var newOwner string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT member_id::text FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, ownerAnchor["issuer"], ownerAnchor["subject"]).Scan(&newOwner); err != nil {
		t.Fatalf("identity owner after handoff: %v", err)
	}
	if newOwner != targetID {
		t.Fatalf("identity owner after handoff=%s, want target %s", newOwner, targetID)
	}
	var status string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT status FROM handoff_requests WHERE id=$1`,
		uuid.MustParse(id)).Scan(&status); err != nil {
		t.Fatalf("handoff status: %v", err)
	}
	if status != "completed" {
		t.Fatalf("handoff status=%s, want completed", status)
	}
	if n := countRows(t, env, `SELECT count(*) FROM handoff_records WHERE handoff_id=$1`,
		uuid.MustParse(id)); n != 1 {
		t.Fatalf("handoff_records=%d, want 1", n)
	}

	// 审计记录不含令牌、不含邮箱。
	var raw []byte
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT to_jsonb(r) FROM handoff_records r WHERE handoff_id=$1`,
		uuid.MustParse(id)).Scan(&raw); err != nil {
		t.Fatalf("load handoff record json: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	for k := range rec {
		if k == "email" || containsFold(k, "token") {
			t.Fatalf("audit record must not contain tokens/emails: key=%s", k)
		}
	}
	if rec["issuer"] != ownerAnchor["issuer"] || rec["subject"] != ownerAnchor["subject"] {
		t.Fatalf("audit record anchor wrong: %v", rec)
	}
	if rec["from_member_id"] != ownerID || rec["to_member_id"] != targetID {
		t.Fatalf("audit record parties wrong: %v", rec)
	}
	// 完成后响应视图同样不含邮箱/令牌。
	for k := range targetCB {
		if k == "email" || containsFold(k, "token") {
			t.Fatalf("handoff response must not expose %s", k)
		}
	}

	// 原成员不能再用该身份登录：全新浏览器以 alice 凭证登录后，落到目标成员。
	fresh := newBrowserClient(t)
	if r := fresh.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("re-login as former owner status=%d", r.StatusCode)
	}
	freshMe := fresh.me("acme")
	if freshMe["member_id"] != targetID {
		t.Fatalf("identity after re-login resolves to member %s, want target %s",
			freshMe["member_id"], targetID)
	}

	// 双方都能在“本人参与的申请”列表里看到它；非参与方看不到。
	for _, b := range []*browserClient{owner, target} {
		list := b.listHandoffs("acme", http.StatusOK)
		found := false
		for _, raw := range list["handoffs"].([]any) {
			if raw.(map[string]any)["id"] == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("participant list missing handoff %s: %v", id, list)
		}
	}
	env.kc.CreateUser("acme", "dave", "dave@example.com", "dave-pass")
	outsider := newBrowserClient(t)
	if r := outsider.login("acme", acmeUser("dave")); r.StatusCode != http.StatusFound {
		t.Fatalf("outsider login: %d", r.StatusCode)
	}
	if body := outsider.getHandoff("acme", id, http.StatusNotFound); body["error"] != "handoff_not_found" {
		t.Fatalf("outsider GET handoff body=%v, want 404 handoff_not_found", body)
	}
	if list := outsider.listHandoffs("acme", http.StatusOK); len(list["handoffs"].([]any)) != 0 {
		t.Fatalf("outsider list should be empty: %v", list)
	}

	// 跨租户会话不能查询（slug 匹配但申请属于另一租户 -> 403；slug 不匹配同样 403）。
	globex := newBrowserClient(t)
	if r := globex.login("globex",
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("globex login: %d", r.StatusCode)
	}
	if body := globex.getHandoff("globex", id, http.StatusForbidden); body["error"] != "tenant_unauthorized" {
		t.Fatalf("cross-tenant GET (matching slug) body=%v, want 403 tenant_unauthorized", body)
	}
	if body := globex.getHandoff("acme", id, http.StatusForbidden); body["error"] != "tenant_unauthorized" {
		t.Fatalf("cross-tenant GET (other slug) body=%v, want 403 tenant_unauthorized", body)
	}

	// 未认证请求被明确归类。
	anon := &http.Client{}
	resp, err := anon.Get(appBaseURL + "/t/acme/api/handoffs")
	if err != nil {
		t.Fatalf("anon list: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "authentication_failed" {
		t.Fatalf("anon list status=%d body=%v, want 401 authentication_failed", resp.StatusCode, body)
	}
}

// TestHandoffOwnerRejectKeepsBinding 原绑定成员拒绝后原绑定保持不变。
func TestHandoffOwnerRejectKeepsBinding(t *testing.T) {
	env := startEnv(t)
	owner, target, id, ownerAnchor := setupTwoMemberHandoff(t, env)

	rejected := owner.handoffAction("acme", id, "reject", http.StatusOK)
	if rejected["status"] != "rejected" {
		t.Fatalf("reject status=%v", rejected["status"])
	}

	// 目标方不能再确认，终态不可推进。
	if status, body := target.handoffActionRaw("acme", id, "confirm"); status != http.StatusConflict ||
		body["error"] != "handoff_conflict" {
		t.Fatalf("confirm after owner reject status=%d body=%v", status, body)
	}

	assertBindingUnchanged(t, env, ownerAnchor, owner.memberID("acme"))
	assertNoHandoffRecord(t, env, id)
}

// TestHandoffTargetRejectKeepsBinding 目标成员在其确认窗口拒绝，原绑定同样不变。
func TestHandoffTargetRejectKeepsBinding(t *testing.T) {
	env := startEnv(t)
	owner, target, id, ownerAnchor := setupTwoMemberHandoff(t, env)

	cb := owner.confirmHandoff("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("owner confirm: %d %v", cb.StatusCode, readBody(t, cb))
	}

	rejected := target.handoffAction("acme", id, "reject", http.StatusOK)
	if rejected["status"] != "rejected" {
		t.Fatalf("target reject status=%v", rejected["status"])
	}
	if status, body := owner.handoffActionRaw("acme", id, "confirm"); status != http.StatusConflict {
		t.Fatalf("owner confirm on rejected status=%d body=%v", status, body)
	}
	assertBindingUnchanged(t, env, ownerAnchor, owner.memberID("acme"))
	assertNoHandoffRecord(t, env, id)
}

// TestHandoffExpiryKeepsBinding 申请在任一活状态过期后原绑定不变，且操作返回明确过期错误。
func TestHandoffExpiryKeepsBinding(t *testing.T) {
	env := startEnv(t)
	owner, _, id, ownerAnchor := setupTwoMemberHandoff(t, env)

	expireHandoff(t, env, id)
	status, body := owner.handoffActionRaw("acme", id, "confirm")
	if status != http.StatusGone || body["error"] != "handoff_expired" {
		t.Fatalf("confirm expired (owner_pending) status=%d body=%v, want 410 handoff_expired", status, body)
	}
	assertBindingUnchanged(t, env, ownerAnchor, owner.memberID("acme"))
	if got := owner.getHandoff("acme", id, http.StatusOK)["status"]; got != "expired" {
		t.Fatalf("handoff status=%v, want expired", got)
	}

	// target_pending 阶段过期同样保持原绑定。
	owner2, target2, id2, ownerAnchor2 := setupTwoMemberHandoff(t, env)
	cb := owner2.confirmHandoff("acme", id2,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("owner confirm: %d", cb.StatusCode)
	}
	expireHandoff(t, env, id2)
	status, body = target2.handoffActionRaw("acme", id2, "confirm")
	if status != http.StatusGone || body["error"] != "handoff_expired" {
		t.Fatalf("confirm expired (target_pending) status=%d body=%v", status, body)
	}
	status, body = target2.handoffActionRaw("acme", id2, "reject")
	if status != http.StatusGone || body["error"] != "handoff_expired" {
		t.Fatalf("reject expired status=%d body=%v", status, body)
	}
	assertBindingUnchanged(t, env, ownerAnchor2, owner2.memberID("acme"))
}

// TestHandoffConcurrentRequestsOnlyOneActive 同一身份并发申请只有一个能进入完成路径。
func TestHandoffConcurrentRequestsOnlyOneActive(t *testing.T) {
	env := startEnv(t)

	owner := newBrowserClient(t)
	if r := owner.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("owner login: %d", r.StatusCode)
	}
	target := newBrowserClient(t)
	if r := target.login("acme", acmeUser("carol")); r.StatusCode != http.StatusFound {
		t.Fatalf("target login: %d", r.StatusCode)
	}
	ownerAnchor := anchorFromMe(owner.me("acme"), issuer("acme"))
	targetAnchor := anchorFromMe(target.me("acme"), issuer("acme"))
	body := handoffBody(ownerAnchor, targetAnchor)

	type result struct {
		status int
		id     string
	}
	res := make([]result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, out := owner.postHandoffRaw("acme", body)
			res[i] = result{status: st}
			if v, ok := out["id"].(string); ok {
				res[i].id = v
			}
		}(i)
	}
	wg.Wait()

	var activeID string
	created, conflicts := 0, 0
	for _, r := range res {
		switch r.status {
		case http.StatusCreated:
			created++
			activeID = r.id
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent create status=%d", r.status)
		}
	}
	if created != 1 || conflicts != 1 {
		t.Fatalf("concurrent creates: created=%d conflicts=%d, want 1/1", created, conflicts)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM handoff_requests WHERE identity_id=(SELECT id FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3)`,
		tenantAcmeID, ownerAnchor["issuer"], ownerAnchor["subject"]); n != 1 {
		t.Fatalf("handoff rows for identity=%d, want 1", n)
	}

	// 只有成功创建的那一个能走完完成路径。
	cb := owner.confirmHandoff("acme", activeID,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("owner confirm active: %d %v", cb.StatusCode, readBody(t, cb))
	}
	cb = target.confirmHandoff("acme", activeID, acmeUser("carol"))
	if cb.StatusCode != http.StatusOK || readBody(t, cb)["status"] != "completed" {
		t.Fatalf("target confirm active: %d %v", cb.StatusCode, readBody(t, cb))
	}

	// 上一轮结束后同一身份可以再次出现在新申请里（部分唯一索引只约束活申请）。
	// 身份现已归 carol：由 carol 作为原绑定方，向第三名成员 dave 再发一个申请。
	env.kc.CreateUser("acme", "dave", "dave@example.com", "dave-pass")
	dave := newBrowserClient(t)
	if r := dave.login("acme", keycloakUser{realm: "acme", username: "dave", password: "dave-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("dave login: %d", r.StatusCode)
	}
	receivedAnchor := anchorFromMe(target.me("acme"), issuer("acme"))
	daveAnchor := anchorFromMe(dave.me("acme"), issuer("acme"))
	if st, out := target.postHandoffRaw("acme", handoffBody(receivedAnchor, daveAnchor)); st != http.StatusCreated {
		t.Fatalf("new handoff after completion status=%d body=%v", st, out)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM handoff_requests WHERE identity_id=(SELECT id FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3)`,
		tenantAcmeID, ownerAnchor["issuer"], ownerAnchor["subject"]); n != 2 {
		t.Fatalf("handoff rows for identity=%d, want 2 (one completed + one active)", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM handoff_requests WHERE identity_id=(SELECT id FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3)
		 AND status IN ('owner_pending','target_pending')`,
		tenantAcmeID, ownerAnchor["issuer"], ownerAnchor["subject"]); n != 1 {
		t.Fatalf("active handoff rows=%d, want exactly 1", n)
	}
}

// TestHandoffCancelledLateCallbackCannotRevive 取消后迟到的确认与 OIDC 回调被拒绝，
// 申请保持终态、身份不移动；重复回调（state 重放）同样被拒。
func TestHandoffCancelledLateCallbackCannotRevive(t *testing.T) {
	env := startEnv(t)
	owner, target, id, ownerAnchor := setupTwoMemberHandoff(t, env)

	// owner 已完成 Keycloak 登录但应用回调尚未到达。
	callbackURL := owner.prepareConfirmCallback("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})

	cancelled := owner.handoffAction("acme", id, "cancel", http.StatusOK)
	if cancelled["status"] != "cancelled" {
		t.Fatalf("cancel status=%v", cancelled["status"])
	}

	// 迟到的 OIDC 回调：state 仍可消费，但申请已取消且绑定 state 已清空 -> 409，不复活。
	late := owner.callAppCallback(callbackURL)
	b := readBody(t, late.Response)
	if late.Response.StatusCode != http.StatusConflict || b["error"] != "handoff_conflict" {
		t.Fatalf("late callback status=%d body=%v, want 409 handoff_conflict",
			late.Response.StatusCode, b)
	}
	if got := owner.getHandoff("acme", id, http.StatusOK)["status"]; got != "cancelled" {
		t.Fatalf("handoff revived to %v, want cancelled", got)
	}

	// 重复回调：state 已消费 -> 400 invalid_request。
	replay := owner.replayCallback(callbackURL)
	rb := readBody(t, replay)
	if replay.StatusCode != http.StatusBadRequest || rb["error"] != "invalid_request" {
		t.Fatalf("replayed callback status=%d body=%v, want 400 invalid_request",
			replay.StatusCode, rb)
	}

	// 终态后任何一方的确认/拒绝/取消都不能推进。
	for _, c := range []struct {
		b      *browserClient
		action string
	}{{owner, "confirm"}, {target, "confirm"}, {target, "reject"}, {owner, "cancel"}} {
		if status, body := c.b.handoffActionRaw("acme", id, c.action); status != http.StatusConflict {
			t.Fatalf("%s on cancelled status=%d body=%v, want 409", c.action, status, body)
		}
	}
	assertBindingUnchanged(t, env, ownerAnchor, owner.memberID("acme"))
	assertNoHandoffRecord(t, env, id)
}

// TestHandoffWrongSessionAndTenantCannotParticipate 错误会话与跨租户锚点都不能参与。
func TestHandoffWrongSessionAndTenantCannotParticipate(t *testing.T) {
	env := startEnv(t)

	owner := newBrowserClient(t)
	if r := owner.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("owner login: %d", r.StatusCode)
	}
	target1 := newBrowserClient(t)
	if r := target1.login("acme", acmeUser("carol")); r.StatusCode != http.StatusFound {
		t.Fatalf("target1 login: %d", r.StatusCode)
	}
	target2 := newBrowserClient(t)
	if r := target2.login("acme", acmeUser("carol")); r.StatusCode != http.StatusFound {
		t.Fatalf("target2 login: %d", r.StatusCode)
	}
	// 两个 carol 浏览器是同一成员的两个不同会话。
	if target1.memberID("acme") != target2.memberID("acme") {
		t.Fatalf("carol sessions should resolve to the same member")
	}

	ownerAnchor := anchorFromMe(owner.me("acme"), issuer("acme"))
	targetAnchor := anchorFromMe(target1.me("acme"), issuer("acme"))
	h := owner.createHandoff("acme", handoffBody(ownerAnchor, targetAnchor))
	id := h["id"].(string)

	// 目标方在 owner_pending 阶段不能确认/拒绝。
	if status, _ := target1.handoffActionRaw("acme", id, "reject"); status != http.StatusConflict {
		t.Fatalf("target reject at owner_pending status=%d, want 409", status)
	}

	cb := owner.confirmHandoff("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("owner confirm: %d", cb.StatusCode)
	}

	// 目标成员的正确会话先发起确认（会话此刻被钉死），但暂不打应用回调。
	callbackURL := target1.prepareConfirmCallback("acme", id, acmeUser("carol"))

	// 目标成员的另一个会话不能替它确认：state 已绑定 target1 的会话。
	if status, body := target2.handoffActionRaw("acme", id, "confirm"); status != http.StatusConflict ||
		body["error"] != "handoff_conflict" {
		t.Fatalf("wrong-session target confirm status=%d body=%v, want 409", status, body)
	}

	// 正确会话的迟到回调仍然有效，交接正常完成。
	cb = target1.callAppCallback(callbackURL).Response
	if cb.StatusCode != http.StatusOK || readBody(t, cb)["status"] != "completed" {
		t.Fatalf("correct-session target callback: %d %v", cb.StatusCode, readBody(t, cb))
	}

	// 跨租户同邮箱：globex 的 alice.globex 与 acme 的 alice 邮箱相同，
	// 但 acme 租户内不存在 globex 锚点 -> 404 handoff_not_found，绝不按邮箱匹配。
	globexAlice := newBrowserClient(t)
	if r := globexAlice.login("globex",
		keycloakUser{realm: "globex", username: "alice.globex", password: "aliceg-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("globex alice login: %d", r.StatusCode)
	}
	gAnchor := anchorFromMe(globexAlice.me("globex"), issuer("globex"))

	env.kc.CreateUser("acme", "dave2", "dave2@example.com", "dave2-pass")
	dave := newBrowserClient(t)
	if r := dave.login("acme", keycloakUser{realm: "acme", username: "dave2", password: "dave2-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("dave login: %d", r.StatusCode)
	}
	daveAnchor := anchorFromMe(dave.me("acme"), issuer("acme"))
	status, body := dave.postHandoffRaw("acme", handoffBody(daveAnchor, gAnchor))
	if status != http.StatusNotFound || body["error"] != "handoff_not_found" {
		t.Fatalf("cross-tenant target anchor status=%d body=%v, want 404 handoff_not_found", status, body)
	}

	// 跨租户会话不能在 acme 上发起任何交接操作。
	status, body = globexAlice.postHandoffRaw("acme", handoffBody(gAnchor, gAnchor))
	if status != http.StatusForbidden || body["error"] != "tenant_unauthorized" {
		t.Fatalf("cross-tenant create status=%d body=%v, want 403 tenant_unauthorized", status, body)
	}
}

// TestHandoffOwnerStaleProofMustReconfirm owner 确认后搁置过久，目标完成时必须被要求重认证；
// owner 重新新近确认后交接方可完成（原归属在整个过程中不变）。
func TestHandoffOwnerStaleProofMustReconfirm(t *testing.T) {
	env := startEnv(t)
	owner, target, id, ownerAnchor := setupTwoMemberHandoff(t, env)

	cb := owner.confirmHandoff("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("owner confirm: %d", cb.StatusCode)
	}

	// 把 owner 证明调老（超过 provider 300s 窗口）。
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE handoff_requests SET owner_auth_time=$1 WHERE id=$2`,
		time.Now().Add(-time.Hour), uuid.MustParse(id)); err != nil {
		t.Fatalf("age owner proof: %v", err)
	}

	// 目标新近确认，但完成事务发现 owner 证明过期 -> 401，身份不动。
	cb = target.confirmHandoff("acme", id, acmeUser("carol"))
	b := readBody(t, cb)
	if cb.StatusCode != http.StatusUnauthorized || b["error"] != "reauthentication_required" {
		t.Fatalf("complete with stale owner proof status=%d body=%v, want 401 reauthentication_required",
			cb.StatusCode, b)
	}
	assertBindingUnchanged(t, env, ownerAnchor, owner.memberID("acme"))

	// owner 在 target_pending 阶段重新确认（刷新证明），随后目标再次确认 -> completed。
	cb = owner.confirmHandoff("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK || readBody(t, cb)["status"] != "target_pending" {
		t.Fatalf("owner re-confirm: %d %v", cb.StatusCode, readBody(t, cb))
	}
	cb = target.confirmHandoff("acme", id, acmeUser("carol"))
	if cb.StatusCode != http.StatusOK || readBody(t, cb)["status"] != "completed" {
		t.Fatalf("target re-confirm: %d %v", cb.StatusCode, readBody(t, cb))
	}
}

// TestHandoffCreateValidation 发起申请的边界校验。
func TestHandoffCreateValidation(t *testing.T) {
	startEnv(t)

	owner := newBrowserClient(t)
	if r := owner.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("owner login: %d", r.StatusCode)
	}
	target := newBrowserClient(t)
	if r := target.login("acme", acmeUser("carol")); r.StatusCode != http.StatusFound {
		t.Fatalf("target login: %d", r.StatusCode)
	}
	ownerAnchor := anchorFromMe(owner.me("acme"), issuer("acme"))
	targetAnchor := anchorFromMe(target.me("acme"), issuer("acme"))

	// 交接不属于自己的身份 -> 409 handoff_conflict。
	st, body := target.postHandoffRaw("acme", handoffBody(ownerAnchor, targetAnchor))
	if st != http.StatusConflict || body["error"] != "handoff_conflict" {
		t.Fatalf("hand off foreign identity status=%d body=%v", st, body)
	}
	// 自我交接 -> 400。
	st, body = owner.postHandoffRaw("acme", handoffBody(ownerAnchor, ownerAnchor))
	if st != http.StatusBadRequest {
		t.Fatalf("self handoff status=%d body=%v, want 400", st, body)
	}
	// 不存在的目标锚点 -> 404。
	st, body = owner.postHandoffRaw("acme", handoffBody(ownerAnchor, map[string]string{
		"issuer": issuer("acme"), "subject": "no-such-subject",
	}))
	if st != http.StatusNotFound || body["error"] != "handoff_not_found" {
		t.Fatalf("missing target anchor status=%d body=%v", st, body)
	}
	// 缺字段 -> 400。
	st, body = owner.postHandoffRaw("acme", map[string]any{"identity": map[string]string{"issuer": "x"}})
	if st != http.StatusBadRequest {
		t.Fatalf("malformed body status=%d body=%v, want 400", st, body)
	}
}

// TestHandoffConcurrentCompleteOnlyOneMoves 双方证明都提交后并发触发完成，
// 只有一个调用成功移动归属，另一个得到状态冲突；绝不产生双归属/双审计记录。
func TestHandoffConcurrentCompleteOnlyOneMoves(t *testing.T) {
	env := startEnv(t)
	owner, target, id, ownerAnchor := setupTwoMemberHandoff(t, env)

	cb := owner.confirmHandoff("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("owner confirm: %d", cb.StatusCode)
	}
	cb = target.confirmHandoff("acme", id, acmeUser("carol"))
	// 回调自身已完成；这里仅需把申请留在 completed —— 用它做并发幂等观察没有意义，
	// 改为直接在 DB 上把申请复位到 target_pending（双方证明保留），模拟最终化竞态。
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("target confirm: %d %v", cb.StatusCode, readBody(t, cb))
	}

	// 复位：归属拨回 owner、状态回到 target_pending，双方证明保留，模拟“完成前一刻”。
	hid := uuid.MustParse(id)
	ownerID := uuid.MustParse(owner.memberID("acme"))
	targetID := uuid.MustParse(target.memberID("acme"))
	identityID := identityIDByAnchor(t, env, ownerAnchor)
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE identities SET member_id=$1 WHERE id=$2`, ownerID, identityID); err != nil {
		t.Fatalf("reset identity owner: %v", err)
	}
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE handoff_requests SET status='target_pending', completed_at=NULL,
		        decided_at=NULL WHERE id=$1`, hid); err != nil {
		t.Fatalf("reset handoff status: %v", err)
	}
	if _, err := env.store.DB().Exec(context.Background(),
		`DELETE FROM handoff_records WHERE handoff_id=$1`, hid); err != nil {
		t.Fatalf("clear records: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = env.store.CompleteHandoff(context.Background(), hid,
				time.Now(), 10*time.Minute, 10*time.Minute)
		}(i)
	}
	wg.Wait()

	ok, conflict := 0, 0
	for _, e := range errs {
		switch {
		case e == nil:
			ok++
		case errors.Is(e, store.ErrConflict):
			conflict++
		default:
			t.Fatalf("unexpected complete error: %v", e)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("concurrent complete: ok=%d conflict=%d, want 1/1 (errs=%v)", ok, conflict, errs)
	}

	// 归属唯一、审计记录唯一。
	var got string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT member_id::text FROM identities WHERE id=$1`, identityID).Scan(&got); err != nil {
		t.Fatalf("identity owner: %v", err)
	}
	if got != targetID.String() {
		t.Fatalf("identity owner=%s, want target %s", got, targetID)
	}
	if n := countRows(t, env, `SELECT count(*) FROM handoff_records WHERE handoff_id=$1`, hid); n != 1 {
		t.Fatalf("handoff_records=%d, want 1", n)
	}
	if n := countRows(t, env, `SELECT count(*) FROM handoff_requests WHERE id=$1 AND status='completed'`, hid); n != 1 {
		t.Fatalf("handoff not completed")
	}
}

// TestHandoffProofAnchorMismatchRejected 任一方的新近 OIDC 证明不是申请锚点的身份时
// 必须被拒（401 authentication_failed），状态不推进、身份不移动。
func TestHandoffProofAnchorMismatchRejected(t *testing.T) {
	env := startEnv(t)
	owner, target, id, ownerAnchor := setupTwoMemberHandoff(t, env)

	// owner 用自己的身份确认，正常推进到 target_pending。
	cb := owner.confirmHandoff("acme", id,
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("owner confirm: %d %v", cb.StatusCode, readBody(t, cb))
	}

	// 目标方在确认登录时改用另一名 acme 用户 dave 的凭证：
	// OIDC 证明 subject 与目标锚点（carol）不一致 -> 拒绝，target 证明不得写入。
	// Keycloak 不允许在同一 SSO 会话用 prompt=login 切换用户，因此用
	// “target1 的应用 sid + 全新 KC SSO 上下文”的组合浏览器完成这次错误登录。
	env.kc.CreateUser("acme", "dave", "dave@example.com", "dave-pass")
	targetWrongKC := newBrowserClientWithJars(t, target.cloneAppJar(), nil)
	confirmURL := target.startConfirm("acme", id, http.StatusOK)
	cb = targetWrongKC.finishAuth(confirmURL,
		keycloakUser{realm: "acme", username: "dave", password: "dave-pass"})
	b := readBody(t, cb)
	if cb.StatusCode != http.StatusUnauthorized || b["error"] != "authentication_failed" {
		t.Fatalf("wrong-identity proof status=%d body=%v, want 401 authentication_failed",
			cb.StatusCode, b)
	}

	// 申请仍停在 target_pending（target 未确认），原绑定不变。
	if got := target.getHandoff("acme", id, http.StatusOK)["status"]; got != "target_pending" {
		t.Fatalf("handoff status=%v, want target_pending", got)
	}
	assertBindingUnchanged(t, env, ownerAnchor, owner.memberID("acme"))

	// 目标方用正确身份 carol 重新确认后正常完成（错误证明没有污染流程）。
	cb = target.confirmHandoff("acme", id, acmeUser("carol"))
	if cb.StatusCode != http.StatusOK || readBody(t, cb)["status"] != "completed" {
		t.Fatalf("correct target confirm: %d %v", cb.StatusCode, readBody(t, cb))
	}
}

// ---------- 共用准备/断言 ----------

func setupTwoMemberHandoff(t *testing.T, env *testEnv) (
	owner, target *browserClient, id string, ownerAnchor map[string]string) {
	t.Helper()
	owner = newBrowserClient(t)
	if r := owner.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}); r.StatusCode != http.StatusFound {
		t.Fatalf("owner login: %d", r.StatusCode)
	}
	target = newBrowserClient(t)
	if r := target.login("acme", acmeUser("carol")); r.StatusCode != http.StatusFound {
		t.Fatalf("target login: %d", r.StatusCode)
	}
	ownerAnchor = anchorFromMe(owner.me("acme"), issuer("acme"))
	targetAnchor := anchorFromMe(target.me("acme"), issuer("acme"))
	h := owner.createHandoff("acme", handoffBody(ownerAnchor, targetAnchor))
	return owner, target, h["id"].(string), ownerAnchor
}

func assertBindingUnchanged(t *testing.T, env *testEnv, anchor map[string]string, wantMemberID string) {
	t.Helper()
	var got string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT member_id::text FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, anchor["issuer"], anchor["subject"]).Scan(&got); err != nil {
		t.Fatalf("identity lookup: %v", err)
	}
	if got != wantMemberID {
		t.Fatalf("identity owner=%s, binding should remain %s", got, wantMemberID)
	}
	if n := countRows(t, env, `SELECT count(*) FROM handoff_records`); n != 0 {
		t.Fatalf("handoff_records=%d, want 0 (no move happened)", n)
	}
}

func assertNoHandoffRecord(t *testing.T, env *testEnv, id string) {
	t.Helper()
	if n := countRows(t, env, `SELECT count(*) FROM handoff_records WHERE handoff_id=$1`,
		uuid.MustParse(id)); n != 0 {
		t.Fatalf("handoff_records for rejected/cancelled=%d, want 0", n)
	}
}

func expireHandoff(t *testing.T, env *testEnv, id string) {
	t.Helper()
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE handoff_requests SET expires_at=$1 WHERE id=$2`,
		time.Now().Add(-time.Minute), uuid.MustParse(id)); err != nil {
		t.Fatalf("expire handoff: %v", err)
	}
}

func identityIDByAnchor(t *testing.T, env *testEnv, anchor map[string]string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT id FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, anchor["issuer"], anchor["subject"]).Scan(&id); err != nil {
		t.Fatalf("identity id by anchor: %v", err)
	}
	return id
}
