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

// ErrLastAdminGroup is returned when a change would leave no group with is_admin.
var ErrLastAdminGroup = errors.New("store: last admin group")

// ErrSoleAppGroup is returned when deleting a group would leave an
// application that lets in only that group with no groups, which lets in
// every member.
var ErrSoleAppGroup = errors.New("store: the only group an application lets in")

// lastAdminOK is true when the group may stop being an admin group or be
// deleted: it is not one, or another admin group exists. It reads the row
// the enclosing statement targets, so the check and the write are one statement.
const lastAdminOK = `(is_admin = 0 OR (SELECT COUNT(*) FROM groups WHERE is_admin = 1) > 1)`

// GroupRow is a group with its member count.
type GroupRow struct {
	model.Group
	MemberCount int // members and service accounts
}

// ListGroupsWithCounts returns every group ordered by name with its member count.
func (s *Store) ListGroupsWithCounts(ctx context.Context) ([]GroupRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+groupCols+`,
		(SELECT COUNT(*) FROM memberships m WHERE m.group_id = groups.id)
		FROM groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list groups with counts: %w", err)
	}
	defer rows.Close()
	var out []GroupRow
	for rows.Next() {
		var n int
		g, err := scanGroup(extraScan{rows, []any{&n}})
		if err != nil {
			return nil, err
		}
		out = append(out, GroupRow{*g, n})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list groups with counts: %w", err)
	}
	return out, nil
}

// UpdateGroup writes the group's name, description, flags and metadata. It
// returns ErrNotFound if the group is gone, ErrConflict if the name is taken,
// and ErrLastAdminGroup if it would remove is_admin from the only admin group.
func (s *Store) UpdateGroup(ctx context.Context, g *model.Group) error {
	meta, err := marshalMeta(g.Metadata)
	if err != nil {
		return err
	}
	g.UpdatedAt = time.Now().UTC()
	q := `UPDATE groups SET name=?, description=?, is_admin=?, require_totp=?, metadata=?, updated_at=? WHERE id=?`
	if !g.IsAdmin {
		q += ` AND ` + lastAdminOK
	}
	res, err := s.db.ExecContext(ctx, q, g.Name, g.Description, boolInt(g.IsAdmin), boolInt(g.RequireTOTP),
		meta, formatTime(g.UpdatedAt), g.ID)
	return s.guardedResult(ctx, "store: update group", g.ID, res, err)
}

// soleAppGroup is true when the group the enclosing statement targets is the
// only group some application lets in. Deleting it would leave that
// application with no groups, which lets in every member.
const soleAppGroup = `EXISTS (SELECT 1 FROM application_groups ag WHERE ag.group_id = groups.id
	AND NOT EXISTS (SELECT 1 FROM application_groups other
	                WHERE other.application_id = ag.application_id AND other.group_id <> ag.group_id))`

// DeleteGroup removes the group; memberships and application grants go with
// it. It returns ErrNotFound if the group is gone, ErrLastAdminGroup if it
// is the only admin group, and ErrSoleAppGroup if it is the only group an
// application lets in. The checks and the delete are one statement.
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE id = ? AND `+lastAdminOK+` AND NOT `+soleAppGroup, id)
	err = s.guardedResult(ctx, "store: delete group", id, res, err)
	if !errors.Is(err, ErrLastAdminGroup) {
		return err
	}
	// One of two guards refused; say which.
	var sole bool
	if qerr := s.db.QueryRowContext(ctx, `SELECT `+soleAppGroup+` FROM groups WHERE id = ?`, id).Scan(&sole); qerr != nil {
		return fmt.Errorf("store: delete group: %w", qerr)
	}
	if sole {
		return ErrSoleAppGroup
	}
	return err
}

// guardedResult reports the outcome of a group write guarded by lastAdminOK.
// When no row changed, the row is read back: gone means ErrNotFound, still
// there means the guard refused.
func (s *Store) guardedResult(ctx context.Context, op, id string, res sql.Result, err error) error {
	err = oneRow(op, res, err)
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	if _, err := s.GetGroup(ctx, id); err != nil {
		return err
	}
	return ErrLastAdminGroup
}

// ReplaceUserGroups makes groupIDs the user's complete set of memberships in
// one transaction. An unknown group fails the foreign key and leaves the
// previous memberships in place.
func (s *Store) ReplaceUserGroups(ctx context.Context, userID string, groupIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: replace user groups: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM memberships WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: replace user groups: %w", err)
	}
	for _, g := range groupIDs {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO memberships (user_id, group_id) VALUES (?,?)`, userID, g); err != nil {
			return fmt.Errorf("store: replace user groups: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: replace user groups: %w", err)
	}
	return nil
}
