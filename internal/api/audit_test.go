package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/testenv"
)

func TestAPIAudit(t *testing.T) {
	env := testenv.New(t)
	raw, acct := env.APIToken(t, "door", model.APITokenScopeAdmin)
	body, resp := env.API(t, raw, http.MethodPost, "/api/v1/users", map[string]any{"name": "Priya", "email": "priya@example.org"})
	if resp.StatusCode != 201 {
		t.Fatalf("create user: %d %v", resp.StatusCode, body)
	}

	now := time.Now().UTC()
	for i := range 3 {
		err := env.Store.InsertAuditEvent(context.Background(), &model.AuditEvent{
			At: now.Add(-time.Duration(i) * time.Minute), ActorType: model.ActorSystem, Action: audit.LoginFailure,
			TargetType: "user", TargetID: "u1", Summary: "Failed sign-in"})
		if err != nil {
			t.Fatal(err)
		}
	}

	body, resp = env.API(t, raw, http.MethodGet, "/api/v1/audit?action=user.", nil)
	if resp.StatusCode != 200 || body["total"] != float64(1) {
		t.Fatalf("user.: %d %v", resp.StatusCode, body)
	}
	ev := items(t, body)[0]
	if ev["action"] != "user.create" || ev["actor_type"] != "service_account" || ev["actor_id"] != acct.ID {
		t.Errorf("event %v", ev)
	}
	if d, _ := ev["detail"].(map[string]any); d["token_id"] == nil {
		t.Errorf("detail %v", ev["detail"])
	}
	if got := len(ev); got != 9 {
		t.Errorf("event keys %v", keys(ev))
	}

	body, _ = env.API(t, raw, http.MethodGet, "/api/v1/audit?action=login.failure", nil)
	if body["total"] != float64(3) || len(items(t, body)) != 3 {
		t.Errorf("login failures should not collapse: %v", body)
	}
	body, _ = env.API(t, raw, http.MethodGet, "/api/v1/audit?target=u1", nil)
	if body["total"] != float64(3) {
		t.Errorf("target: %v", body)
	}
	body, _ = env.API(t, raw, http.MethodGet, "/api/v1/audit?actor="+acct.ID, nil)
	if body["total"] != float64(1) {
		t.Errorf("actor: %v", body)
	}
	body, _ = env.API(t, raw, http.MethodGet, "/api/v1/audit?q=failed", nil)
	if body["total"] != float64(3) {
		t.Errorf("q: %v", body)
	}
	all, _ := env.API(t, raw, http.MethodGet, "/api/v1/audit", nil)
	rows := items(t, all)
	for i := 1; i < len(rows); i++ {
		if rows[i-1]["at"].(string) < rows[i]["at"].(string) {
			t.Errorf("not newest first: %v then %v", rows[i-1]["at"], rows[i]["at"])
		}
	}

	tomorrow := now.AddDate(0, 0, 1).Format("2006-01-02")
	body, resp = env.API(t, raw, http.MethodGet, "/api/v1/audit?since="+tomorrow, nil)
	if resp.StatusCode != 200 || body["total"] != float64(0) || len(items(t, body)) != 0 {
		t.Errorf("since tomorrow: %d %v", resp.StatusCode, body)
	}
	body, _ = env.API(t, raw, http.MethodGet, "/api/v1/audit?since="+now.Add(-time.Hour).Format(time.RFC3339)+"&until="+tomorrow, nil)
	if body["total"] == float64(0) {
		t.Errorf("rfc3339 since: %v", body)
	}
	body, resp = env.API(t, raw, http.MethodGet, "/api/v1/audit?since=yesterday&until=2026-13-45", nil)
	assertError(t, body, resp, 422, "invalid")
	f := fieldsOf(body)
	if f["since"] == nil || f["until"] == nil {
		t.Errorf("fields %v", f)
	}
}
