package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"keywell/internal/audit"
	"keywell/internal/model"
	"keywell/internal/secrets"
	"keywell/internal/store"
)

// Messages and limits for service accounts and API tokens.
const (
	msgServiceUsername = "Enter a username."
	msgTokenLabel      = "Enter a label so you can tell tokens apart."
	msgTokenScope      = "Choose full admin or read only."
	msgTokenExpiry     = "Choose a date in the future."

	maxDescriptionLen = 500
	maxTokenLabelLen  = 100

	tokenPrefix   = "keywell_"
	touchInterval = time.Minute // how often LastUsedAt is written
)

// ErrBadToken is returned by AuthenticateToken for a token that is
// unknown, expired or revoked, or whose service account is gone or
// disabled. It does not say which.
var ErrBadToken = errors.New("admin: unknown, expired or revoked API token")

// ServiceAccountInput is a service account to add.
type ServiceAccountInput struct {
	Name, Username, Description string
	GroupIDs                    []string
	Metadata                    map[string]any // nil = {}
}

// ServiceAccountPatch is a change to a service account. Nil fields are
// left alone.
type ServiceAccountPatch struct {
	Name, Username, Description *string
	GroupIDs                    *[]string
	Metadata                    *map[string]any
}

// NewToken is an API token to make. A nil ExpiresAt never expires.
type NewToken struct {
	Label     string
	Scope     model.APITokenScope
	ExpiresAt *time.Time
}

// Caller is who an API token stands for.
type Caller struct {
	Account *model.User
	Token   *model.APIToken
}

// Actor is the Caller as the actor of changes, naming the token used.
func (c *Caller) Actor() Actor {
	return Actor{Type: model.ActorServiceAccount, ID: c.Account.ID, TokenID: c.Token.ID}
}

// serviceAccount returns the service account with this ID; store.ErrNotFound
// when there is none or the ID is a member's.
func (s *Service) serviceAccount(ctx context.Context, id string) (*model.User, error) {
	u, err := s.d.Store.GetUser(ctx, id)
	return asType(u, err, model.UserTypeService)
}

// CreateServiceAccount adds an active service account, which has no
// password, and records service_account.create.
func (s *Service) CreateServiceAccount(ctx context.Context, a Actor, in ServiceAccountInput) (*model.User, error) {
	p := problems{}
	u := &model.User{
		Type:        model.UserTypeService,
		IsActive:    true,
		Name:        p.name(in.Name),
		Username:    p.username(in.Username, msgServiceUsername),
		Description: p.text("description", in.Description, maxDescriptionLen, ""),
		Metadata:    p.metadata(in.Metadata),
	}
	groups, err := s.groupsByID(ctx, in.GroupIDs, p)
	if err != nil {
		return nil, err
	}
	if err := s.checkUserFree(ctx, p, "", u.Username, ""); err != nil {
		return nil, err
	}
	if err := p.err(); err != nil {
		return nil, err
	}

	if err := s.createUser(ctx, u, groups, "create service account"); err != nil {
		return nil, err
	}
	s.record(ctx, a, audit.ServiceAccountCreate, targetServiceAccount, u.ID, "Added service account "+displayName(u),
		map[string]any{"name": u.Name, "username": u.Username, "groups": groupNames(groups)})
	s.recordJoined(ctx, a, u, groups)
	return u, nil
}

// UpdateServiceAccount makes the changes p asks for and returns the
// account as saved. It records service_account.update for changed fields
// and a group.member.remove or group.member.add per group left or joined.
func (s *Service) UpdateServiceAccount(ctx context.Context, a Actor, id string, patch ServiceAccountPatch) (*model.User, error) {
	old, err := s.serviceAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	next := *old
	p := problems{}
	if patch.Name != nil {
		next.Name = p.name(*patch.Name)
	}
	if patch.Username != nil {
		next.Username = p.username(*patch.Username, msgServiceUsername)
	}
	if patch.Description != nil {
		next.Description = p.text("description", *patch.Description, maxDescriptionLen, "")
	}
	if patch.Metadata != nil {
		next.Metadata = p.metadata(*patch.Metadata)
	}
	var groups, current []model.Group
	if patch.GroupIDs != nil {
		if groups, err = s.groupsByID(ctx, *patch.GroupIDs, p); err != nil {
			return nil, err
		}
	}
	if err := s.checkUserFree(ctx, p, "", next.Username, id); err != nil {
		return nil, err
	}
	if err := p.err(); err != nil {
		return nil, err
	}
	if patch.GroupIDs != nil {
		if current, err = s.d.Store.ListGroupsForUser(ctx, id); err != nil {
			return nil, fmt.Errorf("admin: update service account: %w", err)
		}
	}

	changes := changeSet{}
	noteChange(changes, "name", old.Name, next.Name)
	noteChange(changes, "username", old.Username, next.Username)
	noteChange(changes, "description", old.Description, next.Description)
	changes.noteMetadata(old.Metadata, next.Metadata)
	if len(changes) > 0 {
		if err := s.d.Store.UpdateUser(ctx, &next); err != nil {
			return nil, s.explainUserConflict(ctx, fmt.Errorf("admin: update service account: %w", err), "", next.Username, id)
		}
		s.record(ctx, a, audit.ServiceAccountUpdate, targetServiceAccount, id, "Updated "+displayName(&next), changes.detail())
	}
	if patch.GroupIDs != nil {
		if err := s.setGroups(ctx, a, &next, current, groups); err != nil {
			return nil, err
		}
	}
	return &next, nil
}

// DeleteServiceAccount deletes the service account, with its group
// memberships and API tokens, and records service_account.delete with its
// name and username.
func (s *Service) DeleteServiceAccount(ctx context.Context, a Actor, id string) error {
	u, err := s.serviceAccount(ctx, id)
	if err != nil {
		return err
	}
	if err := s.d.Store.DeleteUser(ctx, id); err != nil {
		return fmt.Errorf("admin: delete service account: %w", err)
	}
	s.record(ctx, a, audit.ServiceAccountDelete, targetServiceAccount, id, "Deleted service account "+displayName(u),
		map[string]any{"name": u.Name, "username": u.Username})
	return nil
}

// ResolveServiceAccount finds a service account by ID or by
// "username:<name>". Anything else, including a member, is
// store.ErrNotFound.
func (s *Service) ResolveServiceAccount(ctx context.Context, ref string) (*model.User, error) {
	if username, ok := strings.CutPrefix(ref, "username:"); ok {
		u, err := s.d.Store.GetUserByUsername(ctx, username)
		return asType(u, err, model.UserTypeService)
	}
	return s.serviceAccount(ctx, ref)
}

// CreateToken makes an API token for the service account and records
// api_token.create. It returns the token and the raw token, which is not
// kept and cannot be shown again.
func (s *Service) CreateToken(ctx context.Context, a Actor, serviceAccountID string, in NewToken) (*model.APIToken, string, error) {
	sa, err := s.serviceAccount(ctx, serviceAccountID)
	if err != nil {
		return nil, "", err
	}
	p := problems{}
	label := p.text("label", in.Label, maxTokenLabelLen, msgTokenLabel)
	if in.Scope != model.APITokenScopeAdmin && in.Scope != model.APITokenScopeRead {
		p.add("scope", msgTokenScope)
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.d.Now()) {
		p.add("expires_at", msgTokenExpiry)
	}
	if err := p.err(); err != nil {
		return nil, "", err
	}

	raw := tokenPrefix + secrets.RandomToken(32)
	t := &model.APIToken{
		ServiceAccountID: sa.ID,
		Label:            label,
		TokenHash:        secrets.HashToken(raw),
		Scope:            in.Scope,
		CreatedByUserID:  a.ID,
		ExpiresAt:        in.ExpiresAt,
	}
	if err := s.d.Store.CreateAPIToken(ctx, t); err != nil {
		return nil, "", fmt.Errorf("admin: create API token: %w", err)
	}
	kind := "read-only"
	if t.Scope == model.APITokenScopeAdmin {
		kind = "full admin"
	}
	s.record(ctx, a, audit.APITokenCreate, targetAPIToken, t.ID, "Made "+kind+" API token "+label+" for "+displayName(sa),
		map[string]any{"label": label, "scope": string(t.Scope), "service_account_id": sa.ID})
	return t, raw, nil
}

// RevokeToken deletes the service account's API token and records
// api_token.revoke. A token of another account is store.ErrNotFound.
func (s *Service) RevokeToken(ctx context.Context, a Actor, serviceAccountID, tokenID string) error {
	sa, err := s.serviceAccount(ctx, serviceAccountID)
	if err != nil {
		return err
	}
	tokens, err := s.d.Store.ListAPITokens(ctx, sa.ID)
	if err != nil {
		return fmt.Errorf("admin: revoke API token: %w", err)
	}
	var label string
	found := false
	for _, t := range tokens {
		if t.ID == tokenID {
			label, found = t.Label, true
		}
	}
	if !found {
		return store.ErrNotFound
	}
	if err := s.d.Store.DeleteAPIToken(ctx, sa.ID, tokenID); err != nil {
		return fmt.Errorf("admin: revoke API token: %w", err)
	}
	s.record(ctx, a, audit.APITokenRevoke, targetAPIToken, tokenID, "Revoked API token "+label+" of "+displayName(sa),
		map[string]any{"label": label, "service_account_id": sa.ID})
	return nil
}

// AuthenticateToken finds who a raw API token stands for. Every failure,
// whatever the reason, is ErrBadToken. It records when the token was last
// used, at most once a minute.
func (s *Service) AuthenticateToken(ctx context.Context, raw string) (*Caller, error) {
	t, err := s.d.Store.GetAPITokenByHash(ctx, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrBadToken
	}
	if err != nil {
		return nil, fmt.Errorf("admin: authenticate token: %w", err)
	}
	now := s.d.Now()
	if t.ExpiresAt != nil && !t.ExpiresAt.After(now) {
		return nil, ErrBadToken
	}
	u, err := s.serviceAccount(ctx, t.ServiceAccountID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrBadToken
	}
	if err != nil {
		return nil, fmt.Errorf("admin: authenticate token: %w", err)
	}
	if !u.IsActive {
		return nil, ErrBadToken
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= touchInterval {
		// A failed write must not turn away a valid token.
		if err := s.d.Store.TouchAPIToken(ctx, t.ID, now); err != nil {
			slog.WarnContext(ctx, "admin: record API token use", "token_id", t.ID, "error", err)
		} else {
			t.LastUsedAt = &now
		}
	}
	return &Caller{Account: u, Token: t}, nil
}
