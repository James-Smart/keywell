package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latch/internal/model"
)

const fresh = `# HELP latch_build_info The running version of Latch.
# TYPE latch_build_info gauge
latch_build_info{version="v1"} 1
# HELP latch_http_requests_total Requests answered, by status class.
# TYPE latch_http_requests_total counter
latch_http_requests_total{code="1xx"} 0
latch_http_requests_total{code="2xx"} 0
latch_http_requests_total{code="3xx"} 0
latch_http_requests_total{code="4xx"} 0
latch_http_requests_total{code="5xx"} 0
# HELP latch_logins_total Sign-ins, by result.
# TYPE latch_logins_total counter
latch_logins_total{result="success"} 0
latch_logins_total{result="failure"} 0
latch_logins_total{result="second_step_failure"} 0
# HELP latch_tokens_issued_total Tokens issued to apps, by grant.
# TYPE latch_tokens_issued_total counter
latch_tokens_issued_total{grant="authorization_code"} 0
latch_tokens_issued_total{grant="refresh_token"} 0
latch_tokens_issued_total{grant="client_credentials"} 0
`

func scrape(t *testing.T, m *Registry) (string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String(), rec.Header().Get("Content-Type")
}

func TestMetricsText(t *testing.T) {
	body, ct := scrape(t, New("v1"))
	if ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if body != fresh {
		t.Errorf("body:\n%s\nwant:\n%s", body, fresh)
	}
}

func TestObserveAudit(t *testing.T) {
	m := New("v1")
	ev := func(action string, d map[string]any) model.AuditEvent {
		return model.AuditEvent{Action: action, Detail: d}
	}
	m.ObserveAudit(ev("login.success", nil))
	m.ObserveAudit(ev("login.success", map[string]any{"second_factor": "pending"}))
	m.ObserveAudit(ev("login.success", map[string]any{"second_factor": "totp"}))
	m.ObserveAudit(ev("login.failure", nil))
	m.ObserveAudit(ev("login.totp_failure", nil))
	m.ObserveAudit(ev("oidc.token.issued", map[string]any{"grant": "refresh_token"}))
	m.ObserveAudit(ev("oidc.token.issued", map[string]any{"grant": "implicit"}))
	m.ObserveAudit(ev("oidc.token.issued", nil))
	m.ObserveAudit(ev("logout", nil))
	m.CountRequest(302)
	m.CountRequest(0)
	m.CountRequest(503)
	body, _ := scrape(t, m)
	for _, want := range []string{
		`latch_http_requests_total{code="2xx"} 1`,
		`latch_http_requests_total{code="3xx"} 1`,
		`latch_http_requests_total{code="5xx"} 1`,
		`latch_logins_total{result="success"} 2`,
		`latch_logins_total{result="failure"} 1`,
		`latch_logins_total{result="second_step_failure"} 1`,
		`latch_tokens_issued_total{grant="refresh_token"} 1`,
		`latch_tokens_issued_total{grant="authorization_code"} 0`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	var nilm *Registry
	nilm.CountRequest(200) // must not panic
}
