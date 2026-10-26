package importer

import (
	"context"
	"reflect"
	"testing"
	"time"

	"keywell/internal/authentik"
	"keywell/internal/secrets"
	"keywell/internal/totp"
)

// newCredEnv is newEnv with an encryptor, which TOTP needs.
func newCredEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	enc, err := secrets.NewEncryptor(secrets.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	e.d.Enc = enc
	return e
}

const (
	keyHex  = "3132333435363738393031323334353637383930" // "12345678901234567890"
	keyHex2 = "6162636465666768696a6b6c6d6e6f7071727374"

	pbkdf2Hash = UsableHash
	argonHash  = "argon2$argon2id$v=19$m=102400,t=2,p=8$dks5bVoycFF4TDNuQWJDZA$v8TF/ZYe14p3FcLHRA6jRYFGhPQeg4Ja6gSqYQa18o4"
	nativeHash = "$argon2id$native"
)

var t0 = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// device adds a TOTP device for the user: confirmed, 30 seconds, 6 digits.
func (s *Snap) device(pk int64, name, key string, mod ...func(*authentik.TOTPDevice)) {
	d := authentik.TOTPDevice{UserPK: pk, Name: name, KeyHex: key, Confirmed: true, Step: 30, Digits: 6,
		LastT: 1000, Created: t0}
	for _, f := range mod {
		f(&d)
	}
	s.TOTPDevices = append(s.TOTPDevices, d)
}

func (s *Snap) tokens(pk int64, toks ...string) {
	for _, t := range toks {
		s.StaticTokens = append(s.StaticTokens, authentik.StaticToken{UserPK: pk, Token: t})
	}
}

// itemsFor returns the reasons of the report items named name.
func itemsFor(rep *Report, name string) []string {
	var out []string
	for _, it := range rep.Items {
		if it.Name == name {
			out = append(out, it.Reason)
		}
	}
	return out
}

func TestImportPasswords(t *testing.T) {
	e := newCredEnv(t)
	ada := e.mkKeywellAdmin("ada@example.org")
	if err := e.st.SetPassword(context.Background(), ada.ID, nativeHash); err != nil {
		t.Fatal(err)
	}
	s := NewSnap()
	s.User("pb", "pb@example.org", WithPassword(pbkdf2Hash))
	s.User("ar", "ar@example.org", WithPassword(argonHash))
	s.User("bang", "bang@example.org", WithPassword("!x"))
	s.User("md5", "md5@example.org", WithPassword("md5$abc$0123456789abcdef0123456789abcdef"))
	s.User("ada", "ADA@example.org", WithPassword(pbkdf2Hash))

	rep := e.run(s)
	for email, want := range map[string]string{"pb@example.org": pbkdf2Hash, "ar@example.org": argonHash,
		"bang@example.org": "", "md5@example.org": ""} {
		if got := e.user(email).LegacyPasswordHash; got != want {
			t.Errorf("%s legacy hash = %q, want %q", email, got, want)
		}
	}
	a := e.user("ada@example.org")
	if a.PasswordHash != nativeHash || a.LegacyPasswordHash != "" {
		t.Errorf("ada: native %q, legacy %q; want native kept, no legacy", a.PasswordHash, a.LegacyPasswordHash)
	}
	if rep.NoPassword != 2 || rep.KeptKeywellCredentials != 1 {
		t.Errorf("NoPassword %d, KeptKeywellCredentials %d; want 2 and 1", rep.NoPassword, rep.KeptKeywellCredentials)
	}
	want := []string{"Has a password Keywell can't check. They'll need a reset link."}
	if got := itemsFor(rep, "md5@example.org"); !reflect.DeepEqual(got, want) {
		t.Errorf("md5 items = %q, want %q", got, want)
	}
	if got := itemsFor(rep, "bang@example.org"); len(got) != 0 {
		t.Errorf("unusable password was warned about: %q", got)
	}

	// A second run changes nothing and counts the same.
	before := e.rows()
	rep = e.run(s)
	if rep.NoPassword != 2 || rep.KeptKeywellCredentials != 1 || !reflect.DeepEqual(e.rows(), before) {
		t.Errorf("rerun: %+v", rep)
	}
}

func TestImportTOTP(t *testing.T) {
	e := newCredEnv(t)
	s := NewSnap()
	pk := s.User("alex", "alex@example.org")
	s.device(pk, "Tablet", keyHex2, func(d *authentik.TOTPDevice) { d.LastUsed = ptr(t0.Add(-time.Hour)) })
	s.device(pk, "Phone", keyHex, func(d *authentik.TOTPDevice) { d.LastUsed = ptr(t0); d.LastT = 5555 })
	s.device(pk, "Never", keyHex2)
	s.device(pk, "Pending", keyHex2, func(d *authentik.TOTPDevice) { d.Confirmed = false; d.LastUsed = ptr(t0.Add(time.Hour)) })
	s.tokens(pk, "AbCdEf12", "zzTOP99")
	// jo has two unused devices: the later Created wins.
	jo := s.User("jo", "jo@example.org")
	s.device(jo, "Old", keyHex2, func(d *authentik.TOTPDevice) { d.Created = t0.Add(-48 * time.Hour) })
	s.device(jo, "New", keyHex)
	// kim has one device only, so there is nothing to warn about.
	kim := s.User("kim", "kim@example.org")
	s.device(kim, "Solo", keyHex)

	rep := e.run(s)
	u := e.user("alex@example.org")
	plain, err := e.d.Enc.Open(u.TOTPSecretEnc)
	if err != nil {
		t.Fatal(err)
	}
	wantSecret, _ := totp.SecretFromHex(keyHex)
	if string(plain) != wantSecret {
		t.Errorf("secret = %q, want %q", plain, wantSecret)
	}
	if u.TOTPConfirmedAt == nil || !u.TOTPConfirmedAt.Equal(t0) {
		t.Errorf("TOTPConfirmedAt = %v, want %v", u.TOTPConfirmedAt, t0)
	}
	ctx := context.Background()
	if ok, err := e.st.ClaimTOTPStep(ctx, u.ID, 5555); ok || err != nil {
		t.Errorf("ClaimTOTPStep(LastT) = %v, %v; want false", ok, err)
	}
	if ok, err := e.st.ClaimTOTPStep(ctx, u.ID, 5556); !ok || err != nil {
		t.Errorf("ClaimTOTPStep(LastT+1) = %v, %v; want true", ok, err)
	}
	if n, _ := e.st.CountUnusedRecoveryCodes(ctx, u.ID); n != 2 {
		t.Errorf("recovery codes = %d, want 2", n)
	}
	if ok, _ := e.st.ConsumeRecoveryCode(ctx, u.ID, secrets.HashToken("abcdef12")); ok {
		t.Error("recovery code matched in the wrong case")
	}
	if ok, _ := e.st.ConsumeRecoveryCode(ctx, u.ID, secrets.HashToken("AbCdEf12")); !ok {
		t.Error("recovery code did not match as typed")
	}
	want := []string{`Had 3 authenticator apps in Authentik. Keywell kept the one used most recently ("Phone").`}
	if got := itemsFor(rep, "alex@example.org"); !reflect.DeepEqual(got, want) {
		t.Errorf("alex items = %q, want %q", got, want)
	}
	// Created breaks the tie among devices never used.
	jp, _ := e.d.Enc.Open(e.user("jo@example.org").TOTPSecretEnc)
	if string(jp) != wantSecret {
		t.Errorf("jo kept the wrong device")
	}
	want = []string{`Had 2 authenticator apps in Authentik. Keywell kept the one used most recently ("New").`}
	if got := itemsFor(rep, "jo@example.org"); !reflect.DeepEqual(got, want) {
		t.Errorf("jo items = %q, want %q", got, want)
	}
	if got := itemsFor(rep, "kim@example.org"); len(got) != 0 {
		t.Errorf("kim items = %q", got)
	}
	if rep.TOTP != 3 || rep.RecoveryCodes != 2 {
		t.Errorf("TOTP %d, RecoveryCodes %d; want 3 and 2", rep.TOTP, rep.RecoveryCodes)
	}
}

func TestImportTOTPUnsupported(t *testing.T) {
	const warn = "Used a kind of two-step code Keywell doesn't support. They'll set up two-step sign in again."
	e := newCredEnv(t)
	s := NewSnap()
	names := []string{"digits", "step", "t0", "hex"}
	mods := []func(*authentik.TOTPDevice){
		func(d *authentik.TOTPDevice) { d.Digits = 8 },
		func(d *authentik.TOTPDevice) { d.Step = 60 },
		func(d *authentik.TOTPDevice) { d.T0 = 5 },
		func(d *authentik.TOTPDevice) { d.KeyHex = "not hex" },
	}
	for i, name := range names {
		pk := s.User(name, name+"@example.org")
		s.device(pk, "Phone", keyHex, mods[i])
		s.tokens(pk, "code"+name)
	}
	rep := e.run(s)
	for _, name := range names {
		email := name + "@example.org"
		if got := itemsFor(rep, email); !reflect.DeepEqual(got, []string{warn}) {
			t.Errorf("%s items = %q", name, got)
		}
		u := e.user(email)
		if u.TOTPSecretEnc != nil {
			t.Errorf("%s has TOTP", name)
		}
		if n, _ := e.st.CountUnusedRecoveryCodes(context.Background(), u.ID); n != 0 {
			t.Errorf("%s kept %d recovery codes without TOTP", name, n)
		}
	}
	if rep.TOTP != 0 || rep.RecoveryCodes != 0 {
		t.Errorf("TOTP %d, RecoveryCodes %d", rep.TOTP, rep.RecoveryCodes)
	}
}

func TestImportTOTPMirrorsAuthentik(t *testing.T) {
	e := newCredEnv(t)
	s := NewSnap()
	pk := s.User("alex", "alex@example.org")
	s.device(pk, "Phone", keyHex)
	s.tokens(pk, "abc1234")
	e.run(s)
	if e.user("alex@example.org").TOTPSecretEnc == nil {
		t.Fatal("not imported")
	}

	// Authentik drops the device; Keywell drops it and its codes.
	s.TOTPDevices, s.StaticTokens = nil, nil
	rep := e.run(s)
	u := e.user("alex@example.org")
	if u.TOTPSecretEnc != nil || u.TOTPConfirmedAt != nil {
		t.Error("TOTP not cleared")
	}
	if n, _ := e.st.CountUnusedRecoveryCodes(context.Background(), u.ID); n != 0 {
		t.Errorf("%d recovery codes left", n)
	}
	if len(itemsFor(rep, "alex@example.org")) != 0 || rep.TOTP != 0 {
		t.Errorf("report: %+v", rep)
	}
}

// Ruling 3, Review Focus 2.
func TestImportKeepsKeywellCredentials(t *testing.T) {
	e := newCredEnv(t)
	ctx := context.Background()
	ada := e.mkKeywellAdmin("ada@example.org")
	if err := e.st.SetPassword(ctx, ada.ID, nativeHash); err != nil {
		t.Fatal(err)
	}
	sealed, _ := e.d.Enc.Seal([]byte("JBSWY3DPEHPK3PXP"))
	if err := e.st.ImportTOTP(ctx, ada.ID, sealed, t0, 77, []string{secrets.HashToken("keywell-code")}); err != nil {
		t.Fatal(err)
	}

	s := NewSnap()
	pk := s.User("ada", "ada@example.org", WithPassword(pbkdf2Hash))
	s.device(pk, "Phone", keyHex)
	s.tokens(pk, "ak-code")
	for i := 0; i < 2; i++ {
		rep := e.run(s)
		a := e.user("ada@example.org")
		if a.PasswordHash != nativeHash || a.LegacyPasswordHash != "" {
			t.Errorf("run %d password: %q / %q", i, a.PasswordHash, a.LegacyPasswordHash)
		}
		plain, err := e.d.Enc.Open(a.TOTPSecretEnc)
		if err != nil || string(plain) != "JBSWY3DPEHPK3PXP" {
			t.Errorf("run %d secret = %q, %v", i, plain, err)
		}
		if ok, _ := e.st.ClaimTOTPStep(ctx, a.ID, 77); ok {
			t.Errorf("run %d reset the last step", i)
		}
		if n, _ := e.st.CountUnusedRecoveryCodes(ctx, a.ID); n != 1 {
			t.Errorf("run %d: %d recovery codes, want her 1", i, n)
		}
		if rep.KeptKeywellCredentials != 1 || rep.TOTP != 0 || rep.RecoveryCodes != 0 || rep.NoPassword != 0 {
			t.Errorf("run %d report: %+v", i, rep)
		}
		if got := itemsFor(rep, "ada@example.org"); len(got) != 0 {
			t.Errorf("run %d items: %q", i, got)
		}
	}
	a := e.user("ada@example.org")
	if ok, _ := e.st.ConsumeRecoveryCode(ctx, a.ID, secrets.HashToken("ak-code")); ok {
		t.Error("Authentik's recovery code was imported")
	}
	if ok, _ := e.st.ConsumeRecoveryCode(ctx, a.ID, secrets.HashToken("keywell-code")); !ok {
		t.Error("Keywell recovery code is gone")
	}
}
