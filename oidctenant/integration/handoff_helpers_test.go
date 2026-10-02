package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// ---------- 身份交接的浏览器辅助 ----------

func handoffAPI(slug, suffix string) string {
	return appBaseURL + "/t/" + slug + "/api/handoffs" + suffix
}

// postHandoffRaw 发起交接申请，返回原始状态码与响应体。
func (b *browserClient) postHandoffRaw(slug string, body any) (int, map[string]any) {
	b.t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := b.app.Post(handoffAPI(slug, ""), "application/json", bytes.NewReader(buf))
	if err != nil {
		b.t.Fatalf("post handoff: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (b *browserClient) createHandoff(slug string, body any) map[string]any {
	b.t.Helper()
	status, out := b.postHandoffRaw(slug, body)
	if status != http.StatusCreated {
		b.t.Fatalf("create handoff status=%d body=%v, want 201", status, out)
	}
	return out
}

// handoffAction POST 交接动作（confirm/reject/cancel/complete），返回响应（不校验状态码）。
func (b *browserClient) handoffAction(slug, id, action string, wantStatus int) map[string]any {
	b.t.Helper()
	resp, err := b.app.Post(handoffAPI(slug, "/"+id+"/"+action), "application/json",
		bytes.NewReader(nil))
	if err != nil {
		b.t.Fatalf("post handoff %s: %v", action, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode != wantStatus {
		b.t.Fatalf("handoff %s status=%d body=%v, want %d", action, resp.StatusCode, out, wantStatus)
	}
	return out
}

// handoffActionRaw 同 handoffAction 但不校验状态码。
func (b *browserClient) handoffActionRaw(slug, id, action string) (int, map[string]any) {
	b.t.Helper()
	resp, err := b.app.Post(handoffAPI(slug, "/"+id+"/"+action), "application/json",
		bytes.NewReader(nil))
	if err != nil {
		b.t.Fatalf("post handoff %s: %v", action, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (b *browserClient) listHandoffs(slug string, wantStatus int) map[string]any {
	b.t.Helper()
	return getJSON(b.t, b.app, handoffAPI(slug, ""), wantStatus)
}

func (b *browserClient) getHandoff(slug, id string, wantStatus int) map[string]any {
	b.t.Helper()
	return getJSON(b.t, b.app, handoffAPI(slug, "/"+id), wantStatus)
}

// startConfirm 调用 confirm 端点，返回 Keycloak 强制重认证地址。
func (b *browserClient) startConfirm(slug, id string, wantStatus int) string {
	b.t.Helper()
	out := b.handoffAction(slug, id, "confirm", wantStatus)
	if u, ok := out["confirm_url"].(string); ok {
		return u
	}
	return ""
}

// confirmHandoff 走完整“发起确认 -> Keycloak 重认证 -> 应用回调”。
func (b *browserClient) confirmHandoff(slug, id string, user keycloakUser) *http.Response {
	b.t.Helper()
	u := b.startConfirm(slug, id, http.StatusOK)
	if u == "" {
		b.t.Fatalf("empty confirm url")
	}
	return b.finishAuth(u, user)
}

// prepareConfirmCallback 发起确认并在 Keycloak 完成登录，但不打应用回调
// （用于构造“取消后迟到的回调”）。
func (b *browserClient) prepareConfirmCallback(slug, id string, user keycloakUser) string {
	b.t.Helper()
	u := b.startConfirm(slug, id, http.StatusOK)
	return b.kc.passwordLogin(u, user)
}

// finishAuth 完成 Keycloak 登录并打应用回调（与 finishLink 同机制，语义通用）。
func (b *browserClient) finishAuth(authURL string, user keycloakUser) *http.Response {
	b.t.Helper()
	return b.runAuthorizationFlow(authURL, user).Response
}

// identityAnchor 从 /me 的身份里取指定 issuer 的锚点。
func anchorFromMe(me map[string]any, iss string) map[string]string {
	for _, raw := range me["identities"].([]any) {
		m := raw.(map[string]any)
		if m["issuer"].(string) == iss {
			return map[string]string{
				"issuer":  m["issuer"].(string),
				"subject": m["subject"].(string),
			}
		}
	}
	return nil
}
