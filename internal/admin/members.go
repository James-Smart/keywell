package admin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/store"
)

// Refusals of member changes.
const (
	msgOwnDisable = "You can't disable your own account."
	msgOwnDelete  = "You can't delete your own account."
	msgDisabled   = "This account is disabled. Enable it first."
)

// msgNoSuchGroupFormat is the "groups" message for a name ResolveGroups
// cannot find.
const msgNoSuchGroupFormat = `No group called "%s".`

// NewMember is a member to add.
type NewMember struct {
	Name, Email, Username string
	GroupIDs              []string
	Metadata              map[string]any // nil = {}
	Invite                bool           // email an invitation
	Password              string         // used when !Invite; "" leaves the member Needs password
}

// MemberPatch is a change to a member. Nil fields are left alone; a
// Username of "" removes the username.
type MemberPatch struct {
	Name, Email, Username *string
	GroupIDs              *[]string
	Metadata              *map[string]any
	IsActive              *bool
}

// member returns the member with this ID; store.ErrNotFound when there is
// none or the ID is a service account's.
func (s *Service) member(ctx context.Context, id string) (*model.User, error) {
	u, err := s.d.Store.GetUser(ctx, id)
	return asType(u, err, model.UserTypeMember)
}

// CreateMember adds an active member with a password, with an emailed
// invitation, or with neither (they then need a password). It records
// user.create and, for an invitation, user.invite. When the invitation
// cannot be sent the member is still added: CreateMember returns them
// together with an *EmailError.
func (s *Service) CreateMember(ctx context.Context, a Actor, in NewMember) (*model.User, error) {
	p := problems{}
	u := &model.User{
		Type:     model.UserTypeMember,
		IsActive: true,
		Name:     p.name(in.Name),
		Email:    p.email(in.Email),
		Username: p.username(in.Username, ""),
		Metadata: p.metadata(in.Metadata),
	}
	withPassword := !in.Invite && in.Password != ""
	if withPassword {
		p.password(in.Password, s.d.Cfg.Password.MinLength)
	}
	groups, err := s.groupsByID(ctx, in.GroupIDs, p)
	if err != nil {
		return nil, err
	}
	if err := s.checkUserFree(ctx, p, u.Email, u.Username, ""); err != nil {
		return nil, err
	}
	if err := p.err(); err != nil {
		return nil, err
	}

	if withPassword {
		if u.PasswordHash, err = s.d.HashPassword(ctx, in.Password); err != nil {
			return nil, fmt.Errorf("admin: hash password: %w", err)
		}
	}
	if err := s.createUser(ctx, u, groups, "create member"); err != nil {
		return nil, err
	}
	s.record(ctx, a, audit.UserCreate, targetUser, u.ID, "Added member "+displayName(u),
		map[string]any{"name": u.Name, "email": u.Email, "username": u.Username, "groups": groupNames(groups)})
	s.recordJoined(ctx, a, u, groups)
	if in.Invite {
		if err := s.emailPasswordLink(ctx, a, u, model.ResetPurposeInvite); err != nil {
			return u, err
		}
	}
	return u, nil
}

// UpdateMember makes the changes p asks for and returns the member as
// saved. It records user.update for changed fields, user.disable or
// user.enable, and a group.member.remove or group.member.add per group
// left or joined. Disabling also signs the member out everywhere. Admins
// cannot disable themselves, or leave themselves in no admin group
// (*RefusedError); then nothing is changed.
func (s *Service) UpdateMember(ctx context.Context, a Actor, id string, p MemberPatch) (*model.User, error) {
	old, err := s.member(ctx, id)
	if err != nil {
		return nil, err
	}
	next := *old
	probs := problems{}
	if p.Name != nil {
		next.Name = probs.name(*p.Name)
	}
	if p.Email != nil {
		next.Email = probs.email(*p.Email)
	}
	if p.Username != nil {
		next.Username = probs.username(*p.Username, "")
	}
	if p.Metadata != nil {
		next.Metadata = probs.metadata(*p.Metadata)
	}
	if p.IsActive != nil {
		next.IsActive = *p.IsActive
	}
	var groups []model.Group
	if p.GroupIDs != nil {
		if groups, err = s.groupsByID(ctx, *p.GroupIDs, probs); err != nil {
			return nil, err
		}
	}
	if err := s.checkUserFree(ctx, probs, next.Email, next.Username, id); err != nil {
		return nil, err
	}
	if err := probs.err(); err != nil {
		return nil, err
	}
	if p.IsActive != nil && !*p.IsActive && a.isUser(id) {
		return nil, &RefusedError{Message: msgOwnDisable}
	}
	var current []model.Group
	if p.GroupIDs != nil {
		if err := keepOwnAdmin(a, id, groups); err != nil {
			return nil, err
		}
		if current, err = s.d.Store.ListGroupsForUser(ctx, id); err != nil {
			return nil, fmt.Errorf("admin: update member: %w", err)
		}
	}

	changes := changeSet{}
	noteChange(changes, "name", old.Name, next.Name)
	noteChange(changes, "email", old.Email, next.Email)
	noteChange(changes, "username", old.Username, next.Username)
	changes.noteMetadata(old.Metadata, next.Metadata)
	if len(changes) > 0 || old.IsActive != next.IsActive {
		if err := s.d.Store.UpdateUser(ctx, &next); err != nil {
			return nil, s.explainUserConflict(ctx, fmt.Errorf("admin: update member: %w", err), next.Email, next.Username, id)
		}
	}
	name := displayName(&next)
	if len(changes) > 0 {
		s.record(ctx, a, audit.UserUpdate, targetUser, id, "Updated "+name, changes.detail())
	}
	switch {
	case old.IsActive && !next.IsActive:
		s.record(ctx, a, audit.UserDisable, targetUser, id, "Disabled "+name, nil)
	case !old.IsActive && next.IsActive:
		s.record(ctx, a, audit.UserEnable, targetUser, id, "Enabled "+name, nil)
	}
	if !next.IsActive && p.IsActive != nil {
		if err := s.endSessions(ctx, id); err != nil {
			return nil, err
		}
	}
	if p.GroupIDs != nil {
		if err := s.setGroups(ctx, a, &next, current, groups); err != nil {
			return nil, err
		}
	}
	return &next, nil
}

// DeleteMember deletes the member, with their memberships, sessions and
// tokens, and records user.delete with their email and name. Admins cannot
// delete themselves (*RefusedError).
func (s *Service) DeleteMember(ctx context.Context, a Actor, id string) error {
	u, err := s.member(ctx, id)
	if err != nil {
		return err
	}
	if a.isUser(id) {
		return &RefusedError{Message: msgOwnDelete}
	}
	if err := s.d.Store.DeleteUser(ctx, id); err != nil {
		return fmt.Errorf("admin: delete member: %w", err)
	}
	s.record(ctx, a, audit.UserDelete, targetUser, id, "Deleted "+displayName(u),
		map[string]any{"email": u.Email, "name": u.Name})
	return nil
}

// SendPasswordEmail emails the member a link to choose a password: an
// invitation when they have no password, otherwise a reset. It returns
// which it sent, also when the email failed (then with an *EmailError). A
// disabled account is refused.
func (s *Service) SendPasswordEmail(ctx context.Context, a Actor, id string) (model.ResetPurpose, error) {
	u, err := s.member(ctx, id)
	if err != nil {
		return "", err
	}
	if !u.IsActive {
		return "", &RefusedError{Message: msgDisabled}
	}
	purpose := model.ResetPurposeReset
	if !u.HasPassword() {
		purpose = model.ResetPurposeInvite
	}
	return purpose, s.emailPasswordLink(ctx, a, u, purpose)
}

// emailPasswordLink sends u an invitation or a reset link and records
// user.invite or user.password.reset_sent, with detail email_sent. A failed
// send is recorded too, with email_sent false and a summary saying it
// wasn't sent, and returns an *EmailError. (The Notifier removes the link
// it made for an email that failed, so the member doesn't show as
// invited.)
func (s *Service) emailPasswordLink(ctx context.Context, a Actor, u *model.User, purpose model.ResetPurpose) error {
	err := s.d.Notifier.SendReset(ctx, u, purpose)
	action, what := audit.UserResetSent, " a password reset link"
	if purpose == model.ResetPurposeInvite {
		action, what = audit.UserInvite, " an invitation"
	}
	summary := "Emailed " + displayName(u) + what
	if err != nil {
		summary = "Tried to email " + displayName(u) + what + ", but it wasn't sent"
	}
	s.record(ctx, a, action, targetUser, u.ID, summary, map[string]any{"email_sent": err == nil})
	if err != nil {
		return &EmailError{Err: err}
	}
	return nil
}

// SetMemberPassword sets the member's password and signs them out
// everywhere. A password the policy refuses is a *ValidationError for the
// "password" field.
func (s *Service) SetMemberPassword(ctx context.Context, a Actor, id, password string) error {
	u, err := s.member(ctx, id)
	if err != nil {
		return err
	}
	p := problems{}
	if p.password(password, s.d.Cfg.Password.MinLength); len(p) > 0 {
		return p.err()
	}
	hash, err := s.d.HashPassword(ctx, password)
	if err != nil {
		return fmt.Errorf("admin: hash password: %w", err)
	}
	if err := s.d.Store.SetPassword(ctx, id, hash); err != nil {
		return fmt.Errorf("admin: set password: %w", err)
	}
	s.record(ctx, a, audit.UserPasswordSet, targetUser, id, "Set a password for "+displayName(u), nil)
	return s.endSessions(ctx, id)
}

// ClearMemberTOTP removes the member's two-step sign in: the TOTP secret,
// their recovery codes and any enrolment in progress.
func (s *Service) ClearMemberTOTP(ctx context.Context, a Actor, id string) error {
	u, err := s.member(ctx, id)
	if err != nil {
		return err
	}
	if err := s.d.Store.ClearTOTP(ctx, id); err != nil {
		return fmt.Errorf("admin: clear two-step sign in: %w", err)
	}
	s.record(ctx, a, audit.UserTOTPClear, targetUser, id, "Cleared two-step sign in for "+displayName(u), nil)
	return nil
}

// SignOutEverywhere ends all the member's sessions and revokes their
// refresh tokens.
func (s *Service) SignOutEverywhere(ctx context.Context, a Actor, id string) error {
	u, err := s.member(ctx, id)
	if err != nil {
		return err
	}
	if err := s.endSessions(ctx, id); err != nil {
		return err
	}
	s.record(ctx, a, audit.UserSessionsRevoke, targetUser, id, "Signed "+displayName(u)+" out everywhere", nil)
	return nil
}

// endSessions deletes all the user's sessions and revokes their refresh
// tokens.
func (s *Service) endSessions(ctx context.Context, userID string) error {
	if err := s.d.Store.DeleteSessionsForUser(ctx, userID); err != nil {
		return fmt.Errorf("admin: sign out: %w", err)
	}
	if err := s.d.Store.RevokeRefreshTokensForUser(ctx, userID); err != nil {
		return fmt.Errorf("admin: sign out: %w", err)
	}
	return nil
}

// ResolveMember finds a member by ID or by "email:<address>", ignoring the
// address's case. Anything else, including a service account, is
// store.ErrNotFound.
func (s *Service) ResolveMember(ctx context.Context, ref string) (*model.User, error) {
	if email, ok := strings.CutPrefix(ref, "email:"); ok {
		u, err := s.d.Store.GetUserByEmail(ctx, email)
		return asType(u, err, model.UserTypeMember)
	}
	return s.member(ctx, ref)
}

// ResolveGroups turns group IDs or exact names into IDs, in order and
// without repeats. A reference to no group is a *ValidationError for the
// "groups" field.
func (s *Service) ResolveGroups(ctx context.Context, refs []string) ([]string, error) {
	ids := []string{}
	for _, ref := range refs {
		g, err := s.d.Store.GetGroup(ctx, ref)
		if errors.Is(err, store.ErrNotFound) {
			g, err = s.d.Store.GetGroupByName(ctx, ref)
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil, &ValidationError{Fields: map[string]string{"groups": fmt.Sprintf(msgNoSuchGroupFormat, ref)}}
		}
		if err != nil {
			return nil, fmt.Errorf("admin: resolve groups: %w", err)
		}
		if !slices.Contains(ids, g.ID) {
			ids = append(ids, g.ID)
		}
	}
	return ids, nil
}

// checkUserFree adds a field message when another user than selfID ("" for
// a new user) has the email, ignoring case, or the username. An empty email
// or username is not checked.
func (s *Service) checkUserFree(ctx context.Context, p problems, email, username, selfID string) error {
	if err := checkFree(ctx, p, "email", email, selfID, msgEmailTaken, s.d.Store.GetUserByEmail); err != nil {
		return err
	}
	return checkFree(ctx, p, "username", username, selfID, msgUsernameTaken, s.d.Store.GetUserByUsername)
}

// explainUserConflict turns a unique-constraint failure from saving a user,
// because another request took the email or username after it was
// checked, into the field message by checking again. Other errors pass
// through.
func (s *Service) explainUserConflict(ctx context.Context, err error, email, username, selfID string) error {
	if !errors.Is(err, store.ErrConflict) {
		return err
	}
	p := problems{}
	if cerr := s.checkUserFree(ctx, p, email, username, selfID); cerr != nil || len(p) == 0 {
		return err
	}
	return p.err()
}
