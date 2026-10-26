// Package metrics keeps a few counters and serves them in the Prometheus
// text format. The text is written by hand; there is no client library.
package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/model"
)

// Registry holds the counters. Every series exists from the start at 0.
type Registry struct {
	version  string
	requests [5]atomic.Uint64 // 1xx..5xx
	logins   [3]atomic.Uint64 // success, failure, second_step_failure
	tokens   [3]atomic.Uint64 // authorization_code, refresh_token, client_credentials
}

var (
	loginResults = [...]string{"success", "failure", "second_step_failure"}
	grants       = [...]string{"authorization_code", "refresh_token", "client_credentials"}
)

// New returns a Registry reporting version in keywell_build_info.
func New(version string) *Registry { return &Registry{version: version} }

// CountRequest counts a response by status class. A status of 0 (nothing
// written) is a 200. A nil Registry counts nothing.
func (m *Registry) CountRequest(status int) {
	if m == nil {
		return
	}
	if status == 0 {
		status = http.StatusOK
	}
	if c := status / 100; c >= 1 && c <= 5 {
		m.requests[c-1].Add(1)
	}
}

// ObserveAudit counts the audit events that matter. It is meant for
// audit.Recorder.WithObserver.
func (m *Registry) ObserveAudit(e model.AuditEvent) {
	if m == nil {
		return
	}
	switch e.Action {
	case audit.LoginSuccess:
		if e.Detail["second_factor"] == "pending" {
			return // the password was right but sign-in is not finished
		}
		m.logins[0].Add(1)
	case audit.LoginFailure:
		m.logins[1].Add(1)
	case audit.LoginTOTPFailure:
		m.logins[2].Add(1)
	case audit.TokenIssued:
		g, _ := e.Detail["grant"].(string)
		for i, name := range grants {
			if g == name {
				m.tokens[i].Add(1)
			}
		}
	}
}

// Handler serves the metrics text.
func (m *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString("# HELP keywell_build_info The running version of Keywell.\n# TYPE keywell_build_info gauge\n")
		fmt.Fprintf(&b, "keywell_build_info{version=%q} 1\n", m.version)
		b.WriteString("# HELP keywell_http_requests_total Requests answered, by status class.\n# TYPE keywell_http_requests_total counter\n")
		for i := range m.requests {
			fmt.Fprintf(&b, "keywell_http_requests_total{code=\"%dxx\"} %d\n", i+1, m.requests[i].Load())
		}
		b.WriteString("# HELP keywell_logins_total Sign-ins, by result.\n# TYPE keywell_logins_total counter\n")
		for i, name := range loginResults {
			fmt.Fprintf(&b, "keywell_logins_total{result=%q} %d\n", name, m.logins[i].Load())
		}
		b.WriteString("# HELP keywell_tokens_issued_total Tokens issued to apps, by grant.\n# TYPE keywell_tokens_issued_total counter\n")
		for i, name := range grants {
			fmt.Fprintf(&b, "keywell_tokens_issued_total{grant=%q} %d\n", name, m.tokens[i].Load())
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, b.String())
	})
}
