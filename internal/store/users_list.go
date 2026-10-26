package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"keywell/internal/model"
)

// UserFilter selects and pages the users ListUsers returns.
type UserFilter struct {
	Type    model.UserType // "" = members and service accounts
	Query   string         // case-insensitive substring of name, email or username
	Status  string         // "", "active", "invited", "needs_password", "disabled", "no_2fa", "admins"
	GroupID string         // only members of this group
	Page    int            // 1-based; < 1 means 1
	PerPage int            // 0 means 50; capped at 500
}

// UserRow is a user with the derived facts the admin lists show.
type UserRow struct {
	model.User
	Status        model.UserStatus
	Groups        []model.Group // ordered by name
	IsAdmin       bool          // in any group with IsAdmin
	TokenCount    int           // API tokens it holds (service accounts)
	TokenLastUsed *time.Time    // latest LastUsedAt among them
}

// UserPage is one page of ListUsers; Total counts every match.
type UserPage struct {
	Rows                 []UserRow
	Total, Page, PerPage int
}

// statusExpr is the one place a user's status is worked out, in order:
// disabled, then active for every service account, then for members with no
// password invited (an unused unexpired invite link exists) or needing a
// password, else active. It takes one argument, the current time, and reads
// the users row of the enclosing query.
const statusExpr = `CASE
	WHEN users.is_active = 0 THEN 'disabled'
	WHEN users.type <> 'member' THEN 'active'
	WHEN users.password_hash = '' AND users.legacy_password_hash = '' THEN
		CASE WHEN EXISTS (SELECT 1 FROM password_reset_tokens t
			WHERE t.user_id = users.id AND t.purpose = 'invite' AND t.used_at IS NULL AND t.expires_at > ?)
		THEN 'invited' ELSE 'needs_password' END
	ELSE 'active' END`

// likeEscaper makes a search string literal inside LIKE ... ESCAPE '\'.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// normPaging applies the paging defaults shared by the list filters: Page < 1
// means 1, perPage 0 (or less) means 50, and perPage is capped at 500.
func normPaging(page, perPage int) (int, int) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	return page, perPage
}

// ListUsers returns one page of users matching f, ordered by name, then
// email, then id, each with its status and groups.
func (s *Store) ListUsers(ctx context.Context, f UserFilter) (UserPage, error) {
	const op = "store: list users"
	page := UserPage{}
	page.Page, page.PerPage = normPaging(f.Page, f.PerPage)
	now := formatTime(time.Now())

	var conds []string
	var args []any
	if f.Type != "" {
		conds = append(conds, `users.type = ?`)
		args = append(args, string(f.Type))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + likeEscaper.Replace(q) + "%"
		conds = append(conds, `(users.name LIKE ? ESCAPE '\' OR COALESCE(users.email,'') LIKE ? ESCAPE '\'
			OR COALESCE(users.username,'') LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like)
	}
	switch f.Status {
	case "":
	case "no_2fa":
		conds = append(conds, `users.totp_confirmed_at IS NULL`)
	case "admins":
		conds = append(conds, `EXISTS (SELECT 1 FROM memberships m JOIN groups g ON g.id = m.group_id
			WHERE m.user_id = users.id AND g.is_admin = 1)`)
	default:
		conds = append(conds, `(`+statusExpr+`) = ?`)
		args = append(args, now, f.Status)
	}
	if f.GroupID != "" {
		conds = append(conds, `EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = users.id AND m.group_id = ?)`)
		args = append(args, f.GroupID)
	}
	where := ""
	if len(conds) > 0 {
		where = ` WHERE ` + strings.Join(conds, ` AND `)
	}

	if err := s.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`+where, args...).Scan(&page.Total); err != nil {
		return UserPage{}, fmt.Errorf("%s: %w", op, err)
	}

	query := `SELECT ` + userCols + `, ` + statusExpr + `,
		(SELECT COUNT(*) FROM api_tokens a WHERE a.service_account_id = users.id),
		(SELECT MAX(a.last_used_at) FROM api_tokens a WHERE a.service_account_id = users.id)
		FROM users` + where + `
		ORDER BY users.name COLLATE NOCASE, users.email COLLATE NOCASE, users.id
		LIMIT ? OFFSET ?`
	qargs := append([]any{now}, args...)
	qargs = append(qargs, page.PerPage, (page.Page-1)*page.PerPage)
	rows, err := s.q.QueryContext(ctx, query, qargs...)
	if err != nil {
		return UserPage{}, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()
	byID := map[string]int{}
	for rows.Next() {
		var (
			row      UserRow
			status   string
			lastUsed sql.NullString
		)
		u, err := scanUser(extraScan{rows, []any{&status, &row.TokenCount, &lastUsed}})
		if err != nil {
			return UserPage{}, err
		}
		row.User, row.Status = *u, model.UserStatus(status)
		if row.TokenLastUsed, err = parseNullTime(lastUsed); err != nil {
			return UserPage{}, err
		}
		byID[u.ID] = len(page.Rows)
		page.Rows = append(page.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return UserPage{}, fmt.Errorf("%s: %w", op, err)
	}
	rows.Close()

	if err := s.loadRowGroups(ctx, &page, byID); err != nil {
		return UserPage{}, err
	}
	return page, nil
}

// extraScan scans a row's user columns followed by extra destinations, so
// scanUser can be reused for queries that select more than userCols.
type extraScan struct {
	rows  *sql.Rows
	extra []any
}

func (e extraScan) Scan(dest ...any) error { return e.rows.Scan(append(dest, e.extra...)...) }

// groupScan scans a membership's user id followed by the group columns.
type groupScan struct {
	rows   *sql.Rows
	userID *string
}

func (g groupScan) Scan(dest ...any) error { return g.rows.Scan(append([]any{g.userID}, dest...)...) }

// loadRowGroups fills Groups and IsAdmin on the page's rows in one query.
func (s *Store) loadRowGroups(ctx context.Context, page *UserPage, byID map[string]int) error {
	if len(page.Rows) == 0 {
		return nil
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(page.Rows)), ",")
	args := make([]any, 0, len(page.Rows))
	for _, r := range page.Rows {
		args = append(args, r.ID)
	}
	rows, err := s.q.QueryContext(ctx, `SELECT m.user_id, `+groupCols+` FROM memberships m
		JOIN groups ON groups.id = m.group_id WHERE m.user_id IN (`+marks+`) ORDER BY groups.name`, args...)
	if err != nil {
		return fmt.Errorf("store: list user groups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var uid string
		g, err := scanGroup(groupScan{rows, &uid})
		if err != nil {
			return err
		}
		r := &page.Rows[byID[uid]]
		r.Groups = append(r.Groups, *g)
		r.IsAdmin = r.IsAdmin || g.IsAdmin
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: list user groups: %w", err)
	}
	return nil
}

// GetUserStatus returns u's derived status as ListUsers would, read fresh
// from the database; ErrNotFound if the user no longer exists.
func (s *Store) GetUserStatus(ctx context.Context, u *model.User) (model.UserStatus, error) {
	var status string
	err := s.q.QueryRowContext(ctx, `SELECT `+statusExpr+` FROM users WHERE users.id = ?`,
		formatTime(time.Now()), u.ID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: get user status: %w", err)
	}
	return model.UserStatus(status), nil
}
