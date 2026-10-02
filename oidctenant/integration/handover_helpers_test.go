package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func (b *browserClient) postHandover(tenantSlug string, path string, body any, wantStatus int) map[string]any {
	b.t.Helper()
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	resp, err := b.app.Post(appBaseURL+"/t/"+tenantSlug+"/api/identity-handovers"+path,
		"application/json", reader)
	if err != nil {
		b.t.Fatalf("POST identity handover %s: %v", path, err)
	}
	defer resp.Body.Close()
	return decodeExpect(b.t, resp, wantStatus)
}

func (b *browserClient) postHandoverRaw(tenantSlug string, path string, body any) (int, map[string]any) {
	b.t.Helper()
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	resp, err := b.app.Post(appBaseURL+"/t/"+tenantSlug+"/api/identity-handovers"+path,
		"application/json", reader)
	if err != nil {
		b.t.Fatalf("POST identity handover raw %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (b *browserClient) listHandovers(tenantSlug string, wantStatus int) []any {
	b.t.Helper()
	out := getJSON(b.t, b.app, appBaseURL+"/t/"+tenantSlug+"/api/identity-handovers", wantStatus)
	return out["handovers"].([]any)
}

func (b *browserClient) getHandover(tenantSlug, id string, wantStatus int) map[string]any {
	b.t.Helper()
	return getJSON(b.t, b.app, appBaseURL+"/t/"+tenantSlug+"/api/identity-handovers/"+id, wantStatus)
}

func (b *browserClient) createHandover(tenantSlug, issuer, subject, targetMemberID string, wantStatus int) map[string]any {
	return b.postHandover(tenantSlug, "", map[string]string{
		"issuer":           issuer,
		"subject":          subject,
		"target_member_id": targetMemberID,
	}, wantStatus)
}

func (b *browserClient) confirmHandover(tenantSlug, id, role string, user keycloakUser,
	proofIssuer, proofSubject string, wantStatus int) map[string]any {
	b.t.Helper()
	path := "/" + id + "/" + role + "-confirm"
	body := map[string]string{}
	if role == "target" {
		body = map[string]string{"issuer": proofIssuer, "subject": proofSubject}
	}
	out := b.postHandover(tenantSlug, path, body, http.StatusOK)
	cb := b.finishHandover(out["auth_url"].(string), user)
	defer cb.Body.Close()
	return decodeExpect(b.t, cb, wantStatus)
}

func (b *browserClient) finishHandover(authURL string, user keycloakUser) *http.Response {
	b.t.Helper()
	return b.finishLink(authURL, user)
}

func identityOwner(t *testing.T, env *testEnv, tenantID, issuer, subject string) string {
	t.Helper()
	var owner string
	err := env.store.DB().QueryRow(context.Background(),
		`SELECT member_id::text FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantID, issuer, subject).Scan(&owner)
	if err != nil {
		t.Fatalf("lookup identity owner: %v", err)
	}
	return owner
}
