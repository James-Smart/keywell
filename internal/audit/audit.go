// Package audit records security-relevant events to the audit log.
package audit

import (
	"context"
	"log/slog"

	"keywell/internal/model"
	"keywell/internal/store"
)

// ActorSystem is the actor type for events caused by Keywell itself.
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
	AuthorizeDenied        = "oidc.authorize.denied"
	KeyRotated             = "oidc.key.rotate"
)

// Action names of changes made through the admin pages and API.
const (
	UserCreate         = "user.create"
	UserInvite         = "user.invite"
	UserUpdate         = "user.update"
	UserDisable        = "user.disable"
	UserEnable         = "user.enable"
	UserDelete         = "user.delete"
	UserPasswordSet    = "user.password.set"
	UserResetSent      = "user.password.reset_sent"
	UserTOTPClear      = "user.totp.clear"
	UserSessionsRevoke = "user.sessions.revoke"

	GroupCreate       = "group.create"
	GroupUpdate       = "group.update"
	GroupDelete       = "group.delete"
	GroupMemberAdd    = "group.member.add"
	GroupMemberRemove = "group.member.remove"

	AppCreate       = "app.create"
	AppUpdate       = "app.update"
	AppDelete       = "app.delete"
	AppSecretRotate = "app.secret.rotate"

	ServiceAccountCreate = "service_account.create"
	ServiceAccountUpdate = "service_account.update"
	ServiceAccountDelete = "service_account.delete"

	APITokenCreate = "api_token.create"
	APITokenRevoke = "api_token.revoke"

	SMTPTest = "settings.smtp_test"

	// ImportRun is one real run of the Authentik importer.
	ImportRun = "import.run"
)

// UserActor returns the actor type and ID for an event caused by a user.
func UserActor(userID string) (model.ActorType, string) { return model.ActorUser, userID }

// Recorder writes audit events to the store and mirrors them to the log.
type Recorder struct {
	store *store.Store
	log   *slog.Logger

	observe func(model.AuditEvent)
}

// New returns a Recorder. A nil log uses slog.Default().
func New(s *store.Store, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{store: s, log: log}
}

// WithObserver returns a Recorder that also calls f with every event it is
// given, after the attempt to store it, whether or not that succeeded.
func (r *Recorder) WithObserver(f func(model.AuditEvent)) *Recorder {
	c := *r
	c.observe = f
	return &c
}

// Record stores the event (filling ID and At) and logs it. Failures are
// logged, never returned: auditing must not break the action being audited.
// Only identifying fields are logged; Detail is never written to the log.
func (r *Recorder) Record(ctx context.Context, e model.AuditEvent) {
	err := r.store.InsertAuditEvent(ctx, &e)
	if r.observe != nil {
		defer r.observe(e)
	}
	if err != nil {
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
