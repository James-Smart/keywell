package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
)

const groupCols = `id, name, description, is_admin, require_totp, metadata, COALESCE(authentik_uuid,''), created_at, updated_at`

func scanGroup(row interface{ Scan(...any) error }) (*model.Group, error) {
	var (
		g                    model.Group
		admin, req           int
		meta                 sql.NullString
		createdAt, updatedAt string
	)
	err := row.Scan(&g.ID, &g.Name, &g.Description, &admin, &req, &meta, &g.AuthentikUUID, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan group: %w", err)
	}
	g.IsAdmin, g.RequireTOTP = admin != 0, req != 0
	if g.Metadata, err = unmarshalMeta(meta); err != nil {
		return nil, err
	}
	if g.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if g.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &g, nil
}

// CreateGroup inserts g, filling ID and timestamps when empty.
func (s *Store) CreateGroup(ctx context.Context, g *model.Group) error {
	if g.ID == "" {
		g.ID = secrets.NewID()
	}
	now := time.Now().UTC()
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	if g.UpdatedAt.IsZero() {
		g.UpdatedAt = now
	}
	meta, err := marshalMeta(g.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO groups
		(id, name, description, is_admin, require_totp, metadata, authentik_uuid, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		g.ID, g.Name, g.Description, boolInt(g.IsAdmin), boolInt(g.RequireTOTP), meta,
		nullIfEmpty(g.AuthentikUUID), formatTime(g.CreatedAt), formatTime(g.UpdatedAt))
	return wrapWrite("store: create group", err)
}

// GetGroup returns the group with the given id.
func (s *Store) GetGroup(ctx context.Context, id string) (*model.Group, error) {
	return scanGroup(s.db.QueryRowContext(ctx, `SELECT `+groupCols+` FROM groups WHERE id = ?`, id))
}

// GetGroupByName returns the group with the given exact name.
func (s *Store) GetGroupByName(ctx context.Context, name string) (*model.Group, error) {
	return scanGroup(s.db.QueryRowContext(ctx, `SELECT `+groupCols+` FROM groups WHERE name = ?`, name))
}

func (s *Store) queryGroups(ctx context.Context, query string, args ...any) ([]model.Group, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list groups: %w", err)
	}
	defer rows.Close()
	var out []model.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list groups: %w", err)
	}
	return out, nil
}

// ListGroups returns all groups ordered by name.
func (s *Store) ListGroups(ctx context.Context) ([]model.Group, error) {
	return s.queryGroups(ctx, `SELECT `+groupCols+` FROM groups ORDER BY name`)
}

// ListGroupsForUser returns the groups the user belongs to, ordered by name.
func (s *Store) ListGroupsForUser(ctx context.Context, userID string) ([]model.Group, error) {
	return s.queryGroups(ctx, `SELECT `+groupCols+` FROM groups
		WHERE id IN (SELECT group_id FROM memberships WHERE user_id = ?) ORDER BY name`, userID)
}

// AddMember adds the user to the group; adding twice is a no-op.
func (s *Store) AddMember(ctx context.Context, userID, groupID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO memberships (user_id, group_id) VALUES (?,?)`, userID, groupID)
	if err != nil {
		return fmt.Errorf("store: add member: %w", err)
	}
	return nil
}

// RemoveMember removes the user from the group.
func (s *Store) RemoveMember(ctx context.Context, userID, groupID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM memberships WHERE user_id=? AND group_id=?`, userID, groupID)
	if err != nil {
		return fmt.Errorf("store: remove member: %w", err)
	}
	return nil
}
