// Package admin is where every change made from the admin pages or the
// admin API happens. It validates input, writes through the store, sends
// password emails through a Notifier, and records one audit event per
// change, naming the admin or service account that made it.
//
// Errors meant for the person making the change are typed:
// *ValidationError holds a message per form field, *RefusedError a change
// that cannot be made as asked, and *EmailError a change that was made but
// whose email was not sent. A missing record, or an ID of the wrong kind,
// is store.ErrNotFound.
package admin

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/mail"
	"latch/internal/model"
	"latch/internal/password"
	"latch/internal/store"
)

// Notifier emails a member a link to choose a password. *web.Server
// satisfies it; its SendReset records its own audit event for the member.
type Notifier interface {
	SendReset(ctx context.Context, user *model.User, purpose model.ResetPurpose) error
}

// Keys rotates and retires the token signing keys. *oidc.KeyManager
// satisfies it.
type Keys interface {
	RotateAs(ctx context.Context, actorType model.ActorType, actorID string) (newKID string, err error)
	RetireOlderThan(ctx context.Context, d time.Duration) (int, error)
	ActiveKID() string
}

// Deps is what a Service needs.
type Deps struct {
	Cfg          *config.Config
	Store        *store.Store
	Audit        *audit.Recorder
	Mailer       mail.Mailer
	Notifier     Notifier
	Keys         Keys
	HashPassword func(ctx context.Context, pw string) (string, error) // nil = password.HashCtx
	Now          func() time.Time                                     // nil = time.Now
}

// Service makes admin changes.
type Service struct{ d Deps }

// New returns a Service, filling HashPassword and Now when they are nil.
func New(d Deps) *Service {
	if d.HashPassword == nil {
		d.HashPassword = password.HashCtx
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{d: d}
}

// Actor is who makes a change: an admin in the admin pages, or a service
// account using an API token.
type Actor struct {
	Type    model.ActorType // model.ActorUser (an admin in the UI) or model.ActorServiceAccount (an API token)
	ID      string
	TokenID string // the API token used; recorded as detail["token_id"] when set
}

// isUser reports whether the actor is the user with this ID, so a change
// to that user is a change to their own account.
func (a Actor) isUser(userID string) bool { return a.Type == model.ActorUser && a.ID == userID }

// ValidationError reports input that cannot be saved. Fields maps each
// field's name (the form field and JSON key alike) to the message shown
// beside it.
type ValidationError struct{ Fields map[string]string }

func (e *ValidationError) Error() string {
	return "admin: invalid " + strings.Join(slices.Sorted(maps.Keys(e.Fields)), ", ")
}

// RefusedError reports a change that cannot be made as asked, such as an
// admin disabling their own account. Message is shown as is.
type RefusedError struct{ Message string }

func (e *RefusedError) Error() string { return e.Message }

// EmailError reports a change that was made but whose email was not sent.
// Err is the sender's error.
type EmailError struct{ Err error }

func (e *EmailError) Error() string {
	if e.Err == nil {
		return "admin: email not sent"
	}
	return "admin: email not sent: " + e.Err.Error()
}

func (e *EmailError) Unwrap() error { return e.Err }

// Field messages and refusals shared by more than one kind of record.
const (
	msgName           = "Enter a name."
	msgTooLongFormat  = "Use at most %d characters."
	msgEmail          = "Enter an email address, like alex@example.org."
	msgEmailTaken     = "Another member already uses that email address."
	msgUsernameSpaces = "Usernames can't contain spaces."
	msgUsernameTaken  = "That username is taken."
	msgTooShortFormat = "Use at least %d characters."
	msgTooCommon      = "That password is too common. Pick something less guessable."
	msgMetadataObject = `Metadata must be a JSON object, like {"member_number": 42}.`
	msgMetadataLong   = "Metadata is too long. Keep it under 8 KB."
	msgGroupGone      = "That group no longer exists."
	msgOwnAdmin       = "You can't remove your own admin access. Ask another admin to do it."
)

// Length limits, in characters except where noted.
const (
	maxNameLen     = 200
	maxEmailLen    = 254
	maxUsernameLen = 150
	maxMetadataLen = 8192 // bytes of the stored, compact JSON
)

// Audit target types.
const (
	targetUser           = "user"
	targetGroup          = "group"
	targetApp            = "application"
	targetServiceAccount = "service_account"
	targetAPIToken       = "api_token"
)

// problems collects the field messages of one request, keeping the first
// message for each field.
type problems map[string]string

func (p problems) add(field, msg string) {
	if _, ok := p[field]; !ok {
		p[field] = msg
	}
}

// err is the *ValidationError for the problems, or nil when there are none.
func (p problems) err() error {
	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Fields: p}
}

// text trims s and checks that it is at most max characters and, when
// emptyMsg is not "", that it is not empty (emptyMsg is then the message).
// It returns the trimmed text.
func (p problems) text(field, s string, max int, emptyMsg string) string {
	s = strings.TrimSpace(s)
	switch n := utf8.RuneCountInString(s); {
	case n == 0 && emptyMsg != "":
		p.add(field, emptyMsg)
	case n > max:
		p.add(field, fmt.Sprintf(msgTooLongFormat, max))
	}
	return s
}

// name applies the name rule of members and service accounts to the
// "name" field.
func (p problems) name(s string) string { return p.text("name", s, maxNameLen, msgName) }

// email applies the member email rule to the "email" field: at most 254
// characters, exactly one @ with text on both sides, and no spaces.
func (p problems) email(s string) string {
	s = strings.TrimSpace(s)
	local, domain, _ := strings.Cut(s, "@")
	if local == "" || domain == "" || strings.Contains(domain, "@") || strings.ContainsFunc(s, unicode.IsSpace) ||
		utf8.RuneCountInString(s) > maxEmailLen {
		p.add("email", msgEmail)
	}
	return s
}

// username applies the username rule to the "username" field. An empty
// username is allowed unless emptyMsg is set.
func (p problems) username(s, emptyMsg string) string {
	s = p.text("username", s, maxUsernameLen, emptyMsg)
	if strings.ContainsFunc(s, unicode.IsSpace) {
		p.add("username", msgUsernameSpaces)
	}
	return s
}

// password applies the password policy to the "password" field, with the
// member pages' copy.
func (p problems) password(pw string, minLen int) {
	err := password.CheckPolicy(pw, minLen)
	var short password.ErrTooShort
	switch {
	case errors.As(err, &short):
		p.add("password", fmt.Sprintf(msgTooShortFormat, short.Min))
	case err != nil: // password.ErrCommon, the only other refusal
		p.add("password", msgTooCommon)
	}
}

// metadata checks that m, stored as JSON, fits in maxMetadataLen bytes. It
// returns m, or {} for nil.
func (p problems) metadata(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(m)
	switch {
	case err != nil: // a value JSON cannot hold, such as NaN
		p.add("metadata", msgMetadataObject)
	case len(b) > maxMetadataLen:
		p.add("metadata", msgMetadataLong)
	}
	return m
}

// ParseMetadata reads metadata as typed into a form or sent to the API.
// Blank text is {}. Anything else must be a JSON object whose stored,
// compact form is at most 8192 bytes; otherwise the error has a message
// for the "metadata" field.
func ParseMetadata(raw string) (map[string]any, *ValidationError) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]any{}, nil
	}
	var m map[string]any
	// Unmarshal accepts null into a map, so the object is also checked for.
	if !strings.HasPrefix(raw, "{") || json.Unmarshal([]byte(raw), &m) != nil {
		return nil, &ValidationError{Fields: map[string]string{"metadata": msgMetadataObject}}
	}
	p := problems{}
	if m = p.metadata(m); len(p) > 0 {
		return nil, &ValidationError{Fields: p}
	}
	return m, nil
}

// checkFree adds msg under field when lookup finds a user other than
// selfID with value ("" for a new user). It does nothing when value is
// empty or the field already has a problem.
func checkFree(ctx context.Context, p problems, field, value, selfID, msg string,
	lookup func(context.Context, string) (*model.User, error)) error {
	if _, bad := p[field]; bad || value == "" {
		return nil
	}
	u, err := lookup(ctx, value)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return fmt.Errorf("admin: check %s is free: %w", field, err)
	case u.ID != selfID:
		p.add(field, msg)
	}
	return nil
}

// asType passes on the result of a user lookup when the user is of type
// typ, and turns a user of another type into store.ErrNotFound.
func asType(u *model.User, err error, typ model.UserType) (*model.User, error) {
	if err != nil {
		return nil, err
	}
	if u.Type != typ {
		return nil, store.ErrNotFound
	}
	return u, nil
}

// displayName is how summaries name a user: their name, else their email,
// username or ID.
func displayName(u *model.User) string { return cmp.Or(u.Name, u.Email, u.Username, u.ID) }

// record writes one audit event for a change a made. When a.TokenID is set
// it is added to the detail as token_id.
func (s *Service) record(ctx context.Context, a Actor, action, targetType, targetID, summary string, detail map[string]any) {
	if a.TokenID != "" {
		detail = maps.Clone(detail)
		if detail == nil {
			detail = map[string]any{}
		}
		detail["token_id"] = a.TokenID
	}
	s.d.Audit.Record(ctx, model.AuditEvent{ActorType: a.Type, ActorID: a.ID, Action: action,
		TargetType: targetType, TargetID: targetID, Summary: summary, Detail: detail})
}

// changeSet is the detail.changed of an update event: each changed field
// maps to {"from": old, "to": new}, except metadata, which maps to {} so
// that its values never reach the audit log.
type changeSet map[string]any

// noteChange records field in c when old and new differ.
func noteChange[T comparable](c changeSet, field string, old, new T) {
	if old != new {
		c[field] = map[string]any{"from": old, "to": new}
	}
}

// noteMetadata records metadata in c, without its values, when old and new
// differ as JSON.
func (c changeSet) noteMetadata(old, new map[string]any) {
	if !sameJSON(old, new) {
		c["metadata"] = map[string]any{}
	}
}

// detail is the event detail holding the changes.
func (c changeSet) detail() map[string]any { return map[string]any{"changed": map[string]any(c)} }

// sameJSON reports whether a and b encode to the same JSON, so a value
// loaded from the database (where numbers are float64) equals the same
// value given as an int, and nil equals {}.
func sameJSON(a, b map[string]any) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// groupsByID loads the groups with these IDs, in order and without
// repeats. An unknown ID adds "That group no longer exists." under
// "groups".
func (s *Service) groupsByID(ctx context.Context, ids []string, p problems) ([]model.Group, error) {
	var out []model.Group
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		g, err := s.d.Store.GetGroup(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			p.add("groups", msgGroupGone)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("admin: load group: %w", err)
		}
		out = append(out, *g)
	}
	return out, nil
}

// keepOwnAdmin refuses to leave the actor, changing their own groups, in
// no admin group.
func keepOwnAdmin(a Actor, userID string, groups []model.Group) error {
	if a.isUser(userID) && !slices.ContainsFunc(groups, func(g model.Group) bool { return g.IsAdmin }) {
		return &RefusedError{Message: msgOwnAdmin}
	}
	return nil
}

// setGroups makes next u's complete set of groups in place of current, and
// records a group.member.remove or group.member.add event for each group
// left or joined.
func (s *Service) setGroups(ctx context.Context, a Actor, u *model.User, current, next []model.Group) error {
	removed, added := minus(current, next), minus(next, current)
	if len(removed) == 0 && len(added) == 0 {
		return nil
	}
	if err := s.d.Store.ReplaceUserGroups(ctx, u.ID, groupIDs(next)); err != nil {
		return fmt.Errorf("admin: set groups: %w", err)
	}
	for _, g := range removed {
		s.recordMembership(ctx, a, audit.GroupMemberRemove, u, &g)
	}
	for _, g := range added {
		s.recordMembership(ctx, a, audit.GroupMemberAdd, u, &g)
	}
	return nil
}

// recordMembership records u joining or leaving g: action is
// audit.GroupMemberAdd or audit.GroupMemberRemove.
func (s *Service) recordMembership(ctx context.Context, a Actor, action string, u *model.User, g *model.Group) {
	summary := "Added " + displayName(u) + " to " + g.Name
	if action == audit.GroupMemberRemove {
		summary = "Removed " + displayName(u) + " from " + g.Name
	}
	s.record(ctx, a, action, targetUser, u.ID, summary, map[string]any{"group_id": g.ID, "group_name": g.Name})
}

// groupIDs returns the IDs of groups.
func groupIDs(groups []model.Group) []string {
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return ids
}

// groupNames returns the names of groups, for event details.
func groupNames(groups []model.Group) []string {
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = g.Name
	}
	return names
}

// minus returns the groups in a that are not in b.
func minus(a, b []model.Group) []model.Group {
	var out []model.Group
	for _, g := range a {
		if !slices.ContainsFunc(b, func(h model.Group) bool { return h.ID == g.ID }) {
			out = append(out, g)
		}
	}
	return out
}

// createUser stores u and puts it in groups. A taken email or username
// becomes a field message. When the groups cannot be set the user is
// deleted again. op names the operation in errors, such as "create member".
func (s *Service) createUser(ctx context.Context, u *model.User, groups []model.Group, op string) error {
	if err := s.d.Store.CreateUser(ctx, u); err != nil {
		return s.explainUserConflict(ctx, fmt.Errorf("admin: %s: %w", op, err), u.Email, u.Username, "")
	}
	if len(groups) == 0 {
		return nil
	}
	if err := s.d.Store.ReplaceUserGroups(ctx, u.ID, groupIDs(groups)); err != nil {
		// Leave no user behind without the groups asked for.
		if derr := s.d.Store.DeleteUser(ctx, u.ID); derr != nil {
			err = errors.Join(err, derr)
		}
		return fmt.Errorf("admin: %s: %w", op, err)
	}
	return nil
}
