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

// Messages and limits for groups.
const (
	msgGroupName      = "Enter a group name."
	msgGroupNameTaken = "There's already a group with that name."
	msgLastAdminGroup = "This is the only admin group. Make another group an admin group first."

	maxGroupNameLen        = 100
	maxGroupDescriptionLen = 500
)

// GroupInput is a group to add.
type GroupInput struct {
	Name, Description    string
	IsAdmin, RequireTOTP bool
	Metadata             map[string]any // nil = {}
}

// GroupPatch is a change to a group. Nil fields are left alone.
type GroupPatch struct {
	Name, Description    *string
	IsAdmin, RequireTOTP *bool
	Metadata             *map[string]any
}

// CreateGroup adds a group and records group.create.
func (s *Service) CreateGroup(ctx context.Context, a Actor, in GroupInput) (*model.Group, error) {
	p := problems{}
	g := &model.Group{
		Name:        p.text("name", in.Name, maxGroupNameLen, msgGroupName),
		Description: p.text("description", in.Description, maxGroupDescriptionLen, ""),
		IsAdmin:     in.IsAdmin,
		RequireTOTP: in.RequireTOTP,
		Metadata:    p.metadata(in.Metadata),
	}
	if err := s.checkGroupName(ctx, p, g.Name, ""); err != nil {
		return nil, err
	}
	if err := p.err(); err != nil {
		return nil, err
	}
	if err := s.d.Store.CreateGroup(ctx, g); err != nil {
		return nil, groupConflict(fmt.Errorf("admin: create group: %w", err))
	}
	s.record(ctx, a, audit.GroupCreate, targetGroup, g.ID, "Added group "+g.Name,
		map[string]any{"name": g.Name, "is_admin": g.IsAdmin, "require_totp": g.RequireTOTP})
	return g, nil
}

// UpdateGroup makes the changes p asks for and returns the group as saved.
// It records group.update when something changed. Removing admin access
// from the only admin group is a *RefusedError; then nothing is changed.
func (s *Service) UpdateGroup(ctx context.Context, a Actor, id string, patch GroupPatch) (*model.Group, error) {
	old, err := s.d.Store.GetGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	next := *old
	p := problems{}
	if patch.Name != nil {
		next.Name = p.text("name", *patch.Name, maxGroupNameLen, msgGroupName)
	}
	if patch.Description != nil {
		next.Description = p.text("description", *patch.Description, maxGroupDescriptionLen, "")
	}
	if patch.IsAdmin != nil {
		next.IsAdmin = *patch.IsAdmin
	}
	if patch.RequireTOTP != nil {
		next.RequireTOTP = *patch.RequireTOTP
	}
	if patch.Metadata != nil {
		next.Metadata = p.metadata(*patch.Metadata)
	}
	if err := s.checkGroupName(ctx, p, next.Name, id); err != nil {
		return nil, err
	}
	if err := p.err(); err != nil {
		return nil, err
	}

	changes := changeSet{}
	noteChange(changes, "name", old.Name, next.Name)
	noteChange(changes, "description", old.Description, next.Description)
	noteChange(changes, "is_admin", old.IsAdmin, next.IsAdmin)
	noteChange(changes, "require_totp", old.RequireTOTP, next.RequireTOTP)
	changes.noteMetadata(old.Metadata, next.Metadata)
	if len(changes) == 0 {
		return old, nil
	}
	if err := s.d.Store.UpdateGroup(ctx, &next); err != nil {
		return nil, groupConflict(fmt.Errorf("admin: update group: %w", err))
	}
	s.record(ctx, a, audit.GroupUpdate, targetGroup, id, "Updated group "+next.Name, changes.detail())
	return &next, nil
}

// DeleteGroup deletes the group, with its memberships and application
// access, and records group.delete with its name. Deleting the only admin
// group is a *RefusedError.
func (s *Service) DeleteGroup(ctx context.Context, a Actor, id string) error {
	g, err := s.d.Store.GetGroup(ctx, id)
	if err != nil {
		return err
	}
	if err := s.d.Store.DeleteGroup(ctx, id); err != nil {
		return groupConflict(fmt.Errorf("admin: delete group: %w", err))
	}
	s.record(ctx, a, audit.GroupDelete, targetGroup, id, "Deleted group "+g.Name, map[string]any{"name": g.Name})
	return nil
}

// AddToGroup adds a member or service account to the group and records
// group.member.add. Someone already in the group is left alone and nothing
// is recorded.
func (s *Service) AddToGroup(ctx context.Context, a Actor, userID, groupID string) error {
	u, g, in, err := s.membership(ctx, userID, groupID)
	if err != nil || in {
		return err
	}
	if err := s.d.Store.AddMember(ctx, u.ID, g.ID); err != nil {
		return fmt.Errorf("admin: add to group: %w", err)
	}
	s.recordMembership(ctx, a, audit.GroupMemberAdd, u, g)
	return nil
}

// RemoveFromGroup removes a member or service account from the group and
// records group.member.remove. Someone not in the group is left alone and
// nothing is recorded. Admins cannot leave themselves in no admin group
// (*RefusedError).
func (s *Service) RemoveFromGroup(ctx context.Context, a Actor, userID, groupID string) error {
	u, g, in, err := s.membership(ctx, userID, groupID)
	if err != nil || !in {
		return err
	}
	if a.isUser(userID) {
		current, err := s.d.Store.ListGroupsForUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("admin: remove from group: %w", err)
		}
		if err := keepOwnAdmin(a, userID, slices.DeleteFunc(current, func(h model.Group) bool { return h.ID == g.ID })); err != nil {
			return err
		}
	}
	if err := s.d.Store.RemoveMember(ctx, u.ID, g.ID); err != nil {
		return fmt.Errorf("admin: remove from group: %w", err)
	}
	s.recordMembership(ctx, a, audit.GroupMemberRemove, u, g)
	return nil
}

// membership loads the user (a member or a service account) and the group,
// and reports whether the user is in the group.
func (s *Service) membership(ctx context.Context, userID, groupID string) (*model.User, *model.Group, bool, error) {
	u, err := s.d.Store.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, false, err
	}
	g, err := s.d.Store.GetGroup(ctx, groupID)
	if err != nil {
		return nil, nil, false, err
	}
	current, err := s.d.Store.ListGroupsForUser(ctx, userID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("admin: list groups: %w", err)
	}
	return u, g, slices.ContainsFunc(current, func(h model.Group) bool { return h.ID == g.ID }), nil
}

// ResolveGroup finds a group by ID or by "name:<name>".
func (s *Service) ResolveGroup(ctx context.Context, ref string) (*model.Group, error) {
	if name, ok := strings.CutPrefix(ref, "name:"); ok {
		return s.d.Store.GetGroupByName(ctx, name)
	}
	return s.d.Store.GetGroup(ctx, ref)
}

// checkGroupName adds a message under "name" when a group other than
// selfID ("" for a new group) has the name.
func (s *Service) checkGroupName(ctx context.Context, p problems, name, selfID string) error {
	if _, bad := p["name"]; bad || name == "" {
		return nil
	}
	g, err := s.d.Store.GetGroupByName(ctx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return fmt.Errorf("admin: check group name is free: %w", err)
	case g.ID != selfID:
		p.add("name", msgGroupNameTaken)
	}
	return nil
}

// groupConflict turns the store's refusals of a group write into the typed
// errors: a name taken since it was checked, and the last admin group.
// Other errors pass through.
func groupConflict(err error) error {
	switch {
	case errors.Is(err, store.ErrConflict):
		return &ValidationError{Fields: map[string]string{"name": msgGroupNameTaken}}
	case errors.Is(err, store.ErrLastAdminGroup):
		return &RefusedError{Message: msgLastAdminGroup}
	}
	return err
}
