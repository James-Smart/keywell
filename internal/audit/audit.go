// Package audit records security-relevant events to the audit log.
package audit

import (
	"context"
	"log/slog"

	"latch/internal/model"
	"latch/internal/store"
)

// ActorSystem is the actor type for events caused by Latch itself.
const ActorSystem = model.ActorType("system")

// Action names recorded in audit events.
const (
	LoginSuccess           = "login.success"
	LoginFailure           = "login.failure"
	LoginTOTPFailure       = "login.totp_failure"
	Logout                 = "logout"
	PasswordChanged        = "user.password.change"
	PasswordResetRequested = "user.password.reset_requested"
	PasswordResetCompleted = "user.password.reset_completed"
	TOTPEnrolled           = "user.totp.enrol"
	TOTPDisabled           = "user.totp.disable"
	TokenIssued            = "oidc.token.issued"
	KeyRotated             = "oidc.key.rotate"
)

// UserActor returns the actor type and ID for an event caused by a user.
func UserActor(userID string) (model.ActorType, string) { return model.ActorUser, userID }

// Recorder writes audit events to the store and mirrors them to the log.
type Recorder struct {
	store *store.Store
	log   *slog.Logger
}

// New returns a Recorder. A nil log uses slog.Default().
func New(s *store.Store, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{store: s, log: log}
}

// Record stores the event (filling ID and At) and logs it. Failures are
// logged, never returned: auditing must not break the action being audited.
// Only identifying fields are logged; Detail is never written to the log.
func (r *Recorder) Record(ctx context.Context, e model.AuditEvent) {
	if err := r.store.InsertAuditEvent(ctx, &e); err != nil {
		r.log.ErrorContext(ctx, "audit insert failed", "action", e.Action, "error", err)
		return
	}
	r.log.InfoContext(ctx, "audit",
		"action", e.Action,
		"actor_type", string(e.ActorType),
		"actor_id", e.ActorID,
		"target_type", e.TargetType,
		"target_id", e.TargetID)
}
