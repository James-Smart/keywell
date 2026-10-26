package importer

import (
	"errors"
	"fmt"
	"slices"

	"github.com/James-Smart/keywell/internal/authentik"
	"github.com/James-Smart/keywell/internal/password"
	"github.com/James-Smart/keywell/internal/secrets"
	"github.com/James-Smart/keywell/internal/totp"
)

// Report copy for credentials.
const (
	warnPasswordUnchecked = "Has a password Keywell can't check. They'll need a reset link."
	warnTOTPUnsupported   = "Used a kind of two-step code Keywell doesn't support. They'll set up two-step sign in again."
	warnSeveralDevices    = "Had %d authenticator apps in Authentik. Keywell kept the one used most recently (%q)."
)

// writeCredentials carries over each imported member's password, two-step
// device and recovery codes (Ruling 3). A member who already has a native
// password hash uses Keywell, so their credentials are left as they are; for
// everyone else all three mirror Authentik.
func (r *run) writeCredentials() error {
	devices := map[int64][]authentik.TOTPDevice{}
	for _, d := range r.snap.TOTPDevices {
		devices[d.UserPK] = append(devices[d.UserPK], d)
	}
	tokens := map[int64][]string{}
	for _, t := range r.snap.StaticTokens {
		tokens[t.UserPK] = append(tokens[t.UserPK], t.Token)
	}
	for _, m := range r.members {
		if !m.synced() {
			continue
		}
		if m.keywell.PasswordHash != "" {
			r.rep.KeptKeywellCredentials++
			continue
		}
		if err := r.importPassword(m); err != nil {
			return err
		}
		if err := r.importTOTP(m, devices[m.src.PK], tokens[m.src.PK]); err != nil {
			return err
		}
	}
	return nil
}

// importPassword stores Authentik's password hash as the member's legacy
// hash when Keywell can check it, and none otherwise.
func (r *run) importPassword(m *member) error {
	hash := m.src.Password
	if err := password.CheckStored(hash); err != nil {
		hash = ""
		// An account with no password at all is not worth a warning.
		if !errors.Is(err, password.ErrUnusable) {
			m.warn(warnPasswordUnchecked)
		}
		r.rep.NoPassword++
	}
	if hash == m.keywell.LegacyPasswordHash {
		return nil
	}
	if _, err := r.tx.SetLegacyPassword(r.ctx, m.keywell.ID, hash); err != nil {
		return fmt.Errorf("importer: set password of member %s: %w", m.email, err)
	}
	m.keywell.LegacyPasswordHash = hash
	return nil
}

// usableDevice reports whether Keywell can generate the same codes as d, and
// returns its base32 secret.
func usableDevice(d *authentik.TOTPDevice) (string, bool) {
	if d.Step != 30 || d.T0 != 0 || d.Digits != 6 {
		return "", false
	}
	secret, err := totp.SecretFromHex(d.KeyHex)
	if err != nil || secret == "" {
		return "", false
	}
	return secret, true
}

// importTOTP makes the member's two-step sign in match Authentik's: the
// confirmed device used most recently that Keywell supports, with the
// member's recovery codes; or none.
func (r *run) importTOTP(m *member, devices []authentik.TOTPDevice, tokens []string) error {
	var confirmed, usable []authentik.TOTPDevice
	for _, d := range devices {
		if !d.Confirmed {
			continue
		}
		confirmed = append(confirmed, d)
		if _, ok := usableDevice(&d); ok {
			usable = append(usable, d)
		}
	}
	if len(usable) == 0 {
		if len(confirmed) > 0 {
			m.warn(warnTOTPUnsupported)
		}
		if m.keywell.TOTPSecretEnc != nil {
			if err := r.tx.ClearTOTP(r.ctx, m.keywell.ID); err != nil {
				return fmt.Errorf("importer: clear two-step sign in of member %s: %w", m.email, err)
			}
			m.keywell.TOTPSecretEnc, m.keywell.TOTPConfirmedAt = nil, nil
		}
		return nil
	}

	// Latest LastUsed first, never used last, then the latest Created.
	slices.SortStableFunc(usable, func(a, b authentik.TOTPDevice) int {
		switch {
		case a.LastUsed != nil && b.LastUsed == nil:
			return -1
		case a.LastUsed == nil && b.LastUsed != nil:
			return 1
		case a.LastUsed != nil && b.LastUsed != nil:
			if c := b.LastUsed.Compare(*a.LastUsed); c != 0 {
				return c
			}
		}
		return b.Created.Compare(a.Created)
	})
	kept := usable[0]
	if len(confirmed) > 1 {
		m.warn(fmt.Sprintf(warnSeveralDevices, len(confirmed), kept.Name))
	}

	secret, _ := usableDevice(&kept)
	if r.enc == nil {
		return errors.New("importer: no encryptor to seal two-step keys with")
	}
	sealed, err := r.enc.Seal([]byte(secret))
	if err != nil {
		return fmt.Errorf("importer: seal two-step key of member %s: %w", m.email, err)
	}
	var codes []string
	for _, t := range tokens {
		if t == "" {
			continue
		}
		if h := secrets.HashToken(t); !slices.Contains(codes, h) {
			codes = append(codes, h)
		}
	}
	created := kept.Created.UTC()
	if err := r.tx.ImportTOTP(r.ctx, m.keywell.ID, sealed, created, kept.LastT, codes); err != nil {
		return fmt.Errorf("importer: import two-step sign in of member %s: %w", m.email, err)
	}
	m.keywell.TOTPSecretEnc, m.keywell.TOTPConfirmedAt = sealed, &created
	r.rep.TOTP++
	r.rep.RecoveryCodes += len(codes)
	return nil
}
