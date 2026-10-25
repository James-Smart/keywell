package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// connect opens the one connection Read uses. The session is read-only, so a
// bug here cannot change Authentik. A failure never carries the password.
func connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	source := Source(dsn)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// The parse error can quote the DSN, so it is dropped.
		return nil, fmt.Errorf("authentik: connect to %s failed: the connection string is not valid", source)
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		out := fmt.Errorf("authentik: connect to %s: %w", source, err)
		if cfg.Password != "" && strings.Contains(out.Error(), cfg.Password) {
			return nil, fmt.Errorf("authentik: connect to %s failed", source)
		}
		return nil, out
	}
	return conn, nil
}

// Read copies an Authentik 2026.8 database into a Snapshot. It reads
// everything in one repeatable-read, read-only transaction. A failed query
// names the table it was reading.
func Read(ctx context.Context, dsn string) (*Snapshot, error) {
	conn, err := connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("authentik: begin read of %s: %w", Source(dsn), err)
	}
	// Nothing was written, so ending the transaction by rollback is fine.
	defer tx.Rollback(context.WithoutCancel(ctx))

	s := &Snapshot{}
	steps := []struct {
		table string
		read  func(context.Context, pgx.Tx, *Snapshot) error
	}{
		{"authentik_install_id", readInstallID},
		{"authentik_core_user", readUsers},
		{"authentik_core_group", readGroups},
		{"authentik_core_user_groups", readMemberships},
		{"authentik_core_groupparentage", readParents},
		{"authentik_stages_authenticator_totp_totpdevice", readTOTP},
		{"authentik_stages_authenticator_static_statictoken", readStaticTokens},
		{"authentik_core_application", readApplications},
		{"authentik_providers_oauth2_oauth2provider", readProviders},
		{"authentik_policies_policybinding", readBindings},
		{"authentik_core_provider_property_mappings", readMappings},
	}
	for _, step := range steps {
		if err := step.read(ctx, tx, s); err != nil {
			return nil, fmt.Errorf("authentik: read %s: %w", step.table, err)
		}
	}
	return s, nil
}

// attrs decodes a jsonb object. A null, empty or non-object value gives an
// empty map, never nil.
func attrs(raw []byte) (map[string]any, error) {
	m := map[string]any{}
	if len(raw) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("attributes: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func readInstallID(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	return tx.QueryRow(ctx, `SELECT id::text FROM authentik_install_id ORDER BY id LIMIT 1`).Scan(&s.InstallID)
}

func readUsers(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id, uuid::text, username, name, email, password, is_active,
		type, attributes, last_login, date_joined FROM authentik_core_user ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var u User
		var raw []byte
		if err := rows.Scan(&u.PK, &u.UUID, &u.Username, &u.Name, &u.Email, &u.Password, &u.IsActive,
			&u.Type, &raw, &u.LastLogin, &u.DateJoined); err != nil {
			return err
		}
		if u.Attributes, err = attrs(raw); err != nil {
			return fmt.Errorf("user %d: %w", u.PK, err)
		}
		s.Users = append(s.Users, u)
	}
	return rows.Err()
}

func readGroups(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT group_uuid::text, name, is_superuser, attributes
		FROM authentik_core_group ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var g Group
		var raw []byte
		if err := rows.Scan(&g.UUID, &g.Name, &g.IsSuperuser, &raw); err != nil {
			return err
		}
		if g.Attributes, err = attrs(raw); err != nil {
			return fmt.Errorf("group %s: %w", g.Name, err)
		}
		s.Groups = append(s.Groups, g)
	}
	return rows.Err()
}

func readMemberships(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT user_id, group_id::text FROM authentik_core_user_groups
		ORDER BY user_id, group_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.UserPK, &m.GroupUUID); err != nil {
			return err
		}
		s.Memberships = append(s.Memberships, m)
	}
	return rows.Err()
}

func readParents(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT child_id::text, parent_id::text FROM authentik_core_groupparentage
		ORDER BY child_id, parent_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p Parentage
		if err := rows.Scan(&p.ChildUUID, &p.ParentUUID); err != nil {
			return err
		}
		s.Parents = append(s.Parents, p)
	}
	return rows.Err()
}

func readTOTP(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT user_id, name, confirmed, key, step, t0, digits, last_t, created, last_used
		FROM authentik_stages_authenticator_totp_totpdevice ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d TOTPDevice
		var created time.Time
		if err := rows.Scan(&d.UserPK, &d.Name, &d.Confirmed, &d.KeyHex, &d.Step, &d.T0, &d.Digits,
			&d.LastT, &created, &d.LastUsed); err != nil {
			return err
		}
		d.Created = created
		s.TOTPDevices = append(s.TOTPDevices, d)
	}
	return rows.Err()
}

func readStaticTokens(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT d.user_id, t.token
		FROM authentik_stages_authenticator_static_statictoken t
		JOIN authentik_stages_authenticator_static_staticdevice d ON d.id = t.device_id
		WHERE d.confirmed ORDER BY d.user_id, t.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t StaticToken
		if err := rows.Scan(&t.UserPK, &t.Token); err != nil {
			return err
		}
		s.StaticTokens = append(s.StaticTokens, t)
	}
	return rows.Err()
}

func readApplications(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT a.policybindingmodel_ptr_id::text, a.name, a.slug,
		COALESCE(a.meta_launch_url, ''), COALESCE(a.meta_icon, ''), COALESCE(a.meta_description, ''),
		a.meta_hide, a.provider_id, m.policy_engine_mode
		FROM authentik_core_application a
		JOIN authentik_policies_policybindingmodel m ON m.pbm_uuid = a.policybindingmodel_ptr_id
		ORDER BY a.name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a Application
		if err := rows.Scan(&a.UUID, &a.Name, &a.Slug, &a.LaunchURL, &a.Icon, &a.Description,
			&a.Hide, &a.ProviderPK, &a.EngineMode); err != nil {
			return err
		}
		s.Applications = append(s.Applications, a)
	}
	return rows.Err()
}

func readProviders(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT p.id, p.name, o.client_type, o.client_id, o.client_secret, o.sub_mode,
		o.access_token_validity, o.refresh_token_validity, o._redirect_uris, o.grant_types
		FROM authentik_providers_oauth2_oauth2provider o
		JOIN authentik_core_provider p ON p.id = o.provider_ptr_id ORDER BY p.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p OAuth2Provider
		var raw []byte
		if err := rows.Scan(&p.PK, &p.Name, &p.ClientType, &p.ClientID, &p.ClientSecret, &p.SubMode,
			&p.AccessTokenValidity, &p.RefreshTokenValidity, &raw, &p.GrantTypes); err != nil {
			return err
		}
		// Each URI is {"url", "matching_mode", "redirect_uri_type"}.
		var uris []struct {
			URL  string `json:"url"`
			Mode string `json:"matching_mode"`
			Type string `json:"redirect_uri_type"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &uris); err != nil {
				return fmt.Errorf("provider %s: _redirect_uris: %w", p.Name, err)
			}
		}
		p.RedirectURIs = []RedirectURI{}
		for _, u := range uris {
			p.RedirectURIs = append(p.RedirectURIs, RedirectURI{URL: u.URL, MatchingMode: u.Mode, Type: u.Type})
		}
		s.Providers = append(s.Providers, p)
	}
	return rows.Err()
}

func readBindings(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT b.target_id::text, COALESCE(b.group_id::text, ''), b.user_id,
		COALESCE(b.policy_id::text, ''), b.enabled, b.negate
		FROM authentik_policies_policybinding b
		JOIN authentik_core_application a ON a.policybindingmodel_ptr_id = b.target_id
		ORDER BY b."order", b.policy_binding_uuid`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var b Binding
		if err := rows.Scan(&b.TargetUUID, &b.GroupUUID, &b.UserPK, &b.PolicyUUID, &b.Enabled, &b.Negate); err != nil {
			return err
		}
		s.Bindings = append(s.Bindings, b)
	}
	return rows.Err()
}

func readMappings(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT pm.provider_id, m.name, COALESCE(m.managed, '')
		FROM authentik_core_provider_property_mappings pm
		JOIN authentik_core_propertymapping m ON m.pm_uuid = pm.propertymapping_id
		JOIN authentik_providers_oauth2_oauth2provider o ON o.provider_ptr_id = pm.provider_id
		ORDER BY pm.provider_id, m.name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var m ProviderMapping
		if err := rows.Scan(&m.ProviderPK, &m.Name, &m.Managed); err != nil {
			return err
		}
		s.Mappings = append(s.Mappings, m)
	}
	return rows.Err()
}
