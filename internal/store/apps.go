package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
)

const appCols = `id, name, slug, client_id, client_secret_hash, client_type, redirect_uris,
	post_logout_redirect_uris, subject_mode, access_token_ttl, refresh_token_ttl, id_token_ttl,
	launch_url, icon_url, description, show_tile, COALESCE(service_account_id,''),
	authentik_provider_pk, created_at, updated_at`

func marshalStrings(v []string) (string, error) {
	if v == nil {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("store: marshal list: %w", err)
	}
	return string(b), nil
}

func unmarshalStrings(s string) ([]string, error) {
	v := []string{}
	if s == "" {
		return v, nil
	}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("store: unmarshal list: %w", err)
	}
	if v == nil {
		v = []string{}
	}
	return v, nil
}

func ttlSeconds(d time.Duration) any {
	if d <= 0 {
		return nil
	}
	return int64(d / time.Second)
}

func durFromNull(n sql.NullInt64) time.Duration {
	if !n.Valid {
		return 0
	}
	return time.Duration(n.Int64) * time.Second
}

// scanApp reads one applications row; AllowedGroupIDs is filled by the caller.
func scanApp(row interface{ Scan(...any) error }) (*model.Application, error) {
	var (
		a                    model.Application
		redirects, postOut   string
		accessTTL, refreshTL sql.NullInt64
		idTTL, pk            sql.NullInt64
		tile                 int
		createdAt, updatedAt string
	)
	err := row.Scan(&a.ID, &a.Name, &a.Slug, &a.ClientID, &a.ClientSecretHash, &a.ClientType,
		&redirects, &postOut, &a.SubjectMode, &accessTTL, &refreshTL, &idTTL,
		&a.LaunchURL, &a.IconURL, &a.Description, &tile, &a.ServiceAccountID, &pk, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan application: %w", err)
	}
	if a.RedirectURIs, err = unmarshalStrings(redirects); err != nil {
		return nil, err
	}
	if a.PostLogoutRedirectURIs, err = unmarshalStrings(postOut); err != nil {
		return nil, err
	}
	a.AccessTokenTTL, a.RefreshTokenTTL, a.IDTokenTTL = durFromNull(accessTTL), durFromNull(refreshTL), durFromNull(idTTL)
	a.ShowTile = tile != 0
	if pk.Valid {
		v := pk.Int64
		a.AuthentikProviderPK = &v
	}
	if a.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if a.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	a.AllowedGroupIDs = []string{}
	return &a, nil
}

// loadAppGroups fills AllowedGroupIDs (sorted by group id) for every app in apps.
func (s *Store) loadAppGroups(ctx context.Context, apps []model.Application) error {
	if len(apps) == 0 {
		return nil
	}
	idx := make(map[string]int, len(apps))
	for i := range apps {
		idx[apps[i].ID] = i
	}
	rows, err := s.db.QueryContext(ctx, `SELECT application_id, group_id FROM application_groups ORDER BY group_id`)
	if err != nil {
		return fmt.Errorf("store: load application groups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var appID, groupID string
		if err := rows.Scan(&appID, &groupID); err != nil {
			return fmt.Errorf("store: scan application group: %w", err)
		}
		if i, ok := idx[appID]; ok {
			apps[i].AllowedGroupIDs = append(apps[i].AllowedGroupIDs, groupID)
		}
	}
	return rows.Err()
}

func (s *Store) queryApps(ctx context.Context, query string, args ...any) ([]model.Application, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query applications: %w", err)
	}
	apps := []model.Application{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		apps = append(apps, *a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store: query applications: %w", err)
	}
	rows.Close()
	if err := s.loadAppGroups(ctx, apps); err != nil {
		return nil, err
	}
	return apps, nil
}

func (s *Store) getAppWhere(ctx context.Context, where string, arg any) (*model.Application, error) {
	apps, err := s.queryApps(ctx, `SELECT `+appCols+` FROM applications WHERE `+where, arg)
	if err != nil {
		return nil, err
	}
	if len(apps) == 0 {
		return nil, ErrNotFound
	}
	return &apps[0], nil
}

// replaceAppGroups swaps the application's allowed group set inside tx.
func replaceAppGroups(ctx context.Context, tx *sql.Tx, appID string, groupIDs []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM application_groups WHERE application_id=?`, appID); err != nil {
		return fmt.Errorf("store: replace application groups: %w", err)
	}
	for _, g := range groupIDs {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO application_groups (application_id, group_id) VALUES (?,?)`, appID, g); err != nil {
			return wrapWrite("store: replace application groups", err)
		}
	}
	return nil
}

// CreateApplication inserts a, filling ID, timestamps, SubjectMode and ClientType when empty.
func (s *Store) CreateApplication(ctx context.Context, a *model.Application) error {
	if a.ID == "" {
		a.ID = secrets.NewID()
	}
	if a.SubjectMode == "" {
		a.SubjectMode = model.SubjectModeID
	}
	if a.ClientType == "" {
		a.ClientType = model.ClientTypeConfidential
	}
	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = now
	}
	redirects, err := marshalStrings(a.RedirectURIs)
	if err != nil {
		return err
	}
	postOut, err := marshalStrings(a.PostLogoutRedirectURIs)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: create application: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO applications
		(id, name, slug, client_id, client_secret_hash, client_type, redirect_uris, post_logout_redirect_uris,
		 subject_mode, access_token_ttl, refresh_token_ttl, id_token_ttl, launch_url, icon_url, description,
		 show_tile, service_account_id, authentik_provider_pk, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Slug, a.ClientID, a.ClientSecretHash, string(a.ClientType), redirects, postOut,
		string(a.SubjectMode), ttlSeconds(a.AccessTokenTTL), ttlSeconds(a.RefreshTokenTTL), ttlSeconds(a.IDTokenTTL),
		a.LaunchURL, a.IconURL, a.Description, boolInt(a.ShowTile), nullIfEmpty(a.ServiceAccountID),
		nullPK(a.AuthentikProviderPK), formatTime(a.CreatedAt), formatTime(a.UpdatedAt))
	if err != nil {
		return wrapWrite("store: create application", err)
	}
	if err := replaceAppGroups(ctx, tx, a.ID, a.AllowedGroupIDs); err != nil {
		return err
	}
	return tx.Commit()
}

// GetApplication returns the application with the given id.
func (s *Store) GetApplication(ctx context.Context, id string) (*model.Application, error) {
	return s.getAppWhere(ctx, `id = ?`, id)
}

// GetApplicationByClientID looks an application up by OAuth client id.
func (s *Store) GetApplicationByClientID(ctx context.Context, clientID string) (*model.Application, error) {
	return s.getAppWhere(ctx, `client_id = ?`, clientID)
}

// GetApplicationBySlug looks an application up by slug.
func (s *Store) GetApplicationBySlug(ctx context.Context, slug string) (*model.Application, error) {
	return s.getAppWhere(ctx, `slug = ?`, slug)
}

// ListApplications returns all applications ordered by name.
func (s *Store) ListApplications(ctx context.Context) ([]model.Application, error) {
	return s.queryApps(ctx, `SELECT `+appCols+` FROM applications ORDER BY name, id`)
}

// UpdateApplication writes every column and replaces the allowed group set.
func (s *Store) UpdateApplication(ctx context.Context, a *model.Application) error {
	redirects, err := marshalStrings(a.RedirectURIs)
	if err != nil {
		return err
	}
	postOut, err := marshalStrings(a.PostLogoutRedirectURIs)
	if err != nil {
		return err
	}
	a.UpdatedAt = time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: update application: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE applications SET name=?, slug=?, client_id=?, client_secret_hash=?,
		client_type=?, redirect_uris=?, post_logout_redirect_uris=?, subject_mode=?, access_token_ttl=?,
		refresh_token_ttl=?, id_token_ttl=?, launch_url=?, icon_url=?, description=?, show_tile=?,
		service_account_id=?, authentik_provider_pk=?, updated_at=? WHERE id=?`,
		a.Name, a.Slug, a.ClientID, a.ClientSecretHash, string(a.ClientType), redirects, postOut,
		string(a.SubjectMode), ttlSeconds(a.AccessTokenTTL), ttlSeconds(a.RefreshTokenTTL), ttlSeconds(a.IDTokenTTL),
		a.LaunchURL, a.IconURL, a.Description, boolInt(a.ShowTile), nullIfEmpty(a.ServiceAccountID),
		nullPK(a.AuthentikProviderPK), formatTime(a.UpdatedAt), a.ID)
	if err := oneRow("store: update application", res, err); err != nil {
		return err
	}
	if err := replaceAppGroups(ctx, tx, a.ID, a.AllowedGroupIDs); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteApplication removes the application; its authorization codes, refresh
// tokens and group grants go with it. ErrNotFound if it is already gone.
func (s *Store) DeleteApplication(ctx context.Context, id string) error {
	n, err := s.deleteRows(ctx, "store: delete application", `DELETE FROM applications WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListTileApplicationsForUser returns tiles the user may launch: ShowTile with a
// launch URL, and either no group restriction or membership of an allowed group.
func (s *Store) ListTileApplicationsForUser(ctx context.Context, userID string) ([]model.Application, error) {
	return s.queryApps(ctx, `SELECT `+appCols+` FROM applications a
		WHERE show_tile = 1 AND launch_url <> ''
		AND (NOT EXISTS (SELECT 1 FROM application_groups ag WHERE ag.application_id = a.id)
		     OR EXISTS (SELECT 1 FROM application_groups ag
		                JOIN memberships m ON m.group_id = ag.group_id
		                WHERE ag.application_id = a.id AND m.user_id = ?))
		ORDER BY name, id`, userID)
}
