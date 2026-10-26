package authentik

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
)

// stackDSN returns the dev stack's DSN, or skips the test without one.
func stackDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYWELL_TEST_AUTHENTIK_DSN")
	if dsn == "" {
		t.Skip("set KEYWELL_TEST_AUTHENTIK_DSN (make authentik-up) to run")
	}
	return dsn
}

func TestReadAuthentikFixture(t *testing.T) {
	snap, err := Read(context.Background(), stackDSN(t))
	if err != nil {
		t.Fatal(err)
	}

	uuidRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRE.MatchString(snap.InstallID) {
		t.Errorf("InstallID = %q, want a UUID", snap.InstallID)
	}

	users := map[string]User{}
	for _, u := range snap.Users {
		users[u.Username] = u
		if u.Attributes == nil {
			t.Errorf("user %s: Attributes is nil", u.Username)
		}
	}
	alex, ok := users["alex"]
	if !ok {
		t.Fatal("no user alex")
	}
	if alex.Email != "Alex.Smith@Example.org" {
		t.Errorf("alex email = %q", alex.Email)
	}
	if !strings.HasPrefix(alex.Password, "pbkdf2_sha256$1000000$") {
		t.Errorf("alex password has an unexpected format")
	}
	if alex.Attributes["member_number"] != float64(42) {
		t.Errorf("alex member_number = %v (%T)", alex.Attributes["member_number"], alex.Attributes["member_number"])
	}
	if users["door-bot"].Type != "service_account" {
		t.Errorf("door-bot type = %q", users["door-bot"].Type)
	}

	groups := map[string]Group{}
	for _, g := range snap.Groups {
		groups[g.Name] = g
		if g.Attributes == nil {
			t.Errorf("group %s: Attributes is nil", g.Name)
		}
	}
	laser, members := groups["Laser"], groups["Members"]
	if laser.UUID == "" || members.UUID == "" {
		t.Fatal("Laser or Members group missing")
	}
	hasParent := false
	for _, p := range snap.Parents {
		if p.ChildUUID == laser.UUID && p.ParentUUID == members.UUID {
			hasParent = true
		}
	}
	if !hasParent {
		t.Error("Laser should have Members as a parent")
	}

	var alexDevices, alexConfirmed int
	var phone *TOTPDevice
	for i, d := range snap.TOTPDevices {
		if d.UserPK != alex.PK {
			continue
		}
		alexDevices++
		if d.Confirmed {
			alexConfirmed++
		}
		if d.Name == "Phone" {
			phone = &snap.TOTPDevices[i]
		}
	}
	if alexDevices != 3 || alexConfirmed != 2 {
		t.Errorf("alex has %d TOTP devices, %d confirmed; want 3 and 2", alexDevices, alexConfirmed)
	}
	if phone == nil {
		t.Fatal("alex has no Phone device")
	}
	if phone.KeyHex != "3132333435363738393031323334353637383930" || phone.LastT != 1000 || phone.LastUsed == nil {
		t.Errorf("Phone = %+v", *phone)
	}

	if len(snap.StaticTokens) != 3 {
		t.Errorf("StaticTokens = %d, want 3", len(snap.StaticTokens))
	}
	tokens := map[string]bool{}
	for _, st := range snap.StaticTokens {
		if st.UserPK != alex.PK {
			t.Errorf("static token belongs to user %d, want alex", st.UserPK)
		}
		tokens[st.Token] = true
	}
	for _, want := range []string{"RecoveryAAA1", "RecoveryBBB2", "RecoveryCCC3"} {
		if !tokens[want] {
			t.Errorf("missing a recovery token")
		}
	}

	apps := map[string]Application{}
	for _, a := range snap.Applications {
		apps[a.Name] = a
	}
	providers := map[int64]OAuth2Provider{}
	byName := map[string]OAuth2Provider{}
	for _, p := range snap.Providers {
		providers[p.PK] = p
		byName[p.Name] = p
	}

	wiki := apps["Wiki"]
	if wiki.ProviderPK == nil {
		t.Fatal("Wiki has no provider")
	}
	wp, ok := providers[*wiki.ProviderPK]
	if !ok {
		t.Fatal("Wiki's provider is not in Providers")
	}
	if len(wp.RedirectURIs) != 3 {
		t.Fatalf("Wiki RedirectURIs = %d, want 3", len(wp.RedirectURIs))
	}
	seen := map[RedirectURI]bool{}
	for _, r := range wp.RedirectURIs {
		seen[RedirectURI{MatchingMode: r.MatchingMode, Type: r.Type}] = true
	}
	for _, want := range []RedirectURI{
		{MatchingMode: "strict", Type: "authorization"},
		{MatchingMode: "regex", Type: "authorization"},
		{MatchingMode: "strict", Type: "logout"},
	} {
		if !seen[want] {
			t.Errorf("Wiki has no %s %s redirect", want.MatchingMode, want.Type)
		}
	}
	if wp.AccessTokenValidity != "hours=2" {
		t.Errorf("Wiki access validity = %q", wp.AccessTokenValidity)
	}

	var sawGroup, sawPolicy bool
	tools := apps["Tool Booking"]
	for _, b := range snap.Bindings {
		if b.TargetUUID != tools.UUID {
			continue
		}
		sawGroup = sawGroup || b.GroupUUID != ""
		sawPolicy = sawPolicy || b.PolicyUUID != ""
	}
	if !sawGroup || !sawPolicy {
		t.Errorf("Tool Booking bindings: group=%v policy=%v, want both", sawGroup, sawPolicy)
	}

	grafana := apps["Grafana"]
	if grafana.ProviderPK == nil {
		t.Error("Grafana should have a ProviderPK")
	} else if _, ok := providers[*grafana.ProviderPK]; ok {
		t.Error("Grafana's SAML provider should not be in Providers")
	}
	if apps["Printer"].ProviderPK != nil {
		t.Error("Printer should have no ProviderPK")
	}
	if _, ok := byName["orphan"]; !ok {
		t.Error("orphan provider should be in Providers")
	}

	var sawProfile, sawExtra bool
	for _, m := range snap.Mappings {
		if m.ProviderPK != wp.PK {
			continue
		}
		sawProfile = sawProfile || m.Managed == ManagedProfileScope
		sawExtra = sawExtra || (m.Managed == "" && m.Name == "Wiki extra claims")
	}
	if !sawProfile || !sawExtra {
		t.Errorf("Wiki mappings: profile=%v extra=%v, want both", sawProfile, sawExtra)
	}
}

func TestReadAuthentikIsReadOnly(t *testing.T) {
	ctx := context.Background()
	conn, err := connect(ctx, stackDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, `INSERT INTO authentik_core_group (group_uuid, name, is_superuser, attributes)
		VALUES (gen_random_uuid(), 'should-not-exist', false, '{}')`)
	if err == nil {
		t.Fatal("INSERT succeeded on the importer's connection; it must be read-only")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("INSERT failed, but not for being read-only: %v", err)
	}
}

func TestReadAuthentikErrorsHideThePassword(t *testing.T) {
	const secret = "hunter2-secret"
	_, err := Read(context.Background(), "postgres://authentik:"+secret+"@127.0.0.1:1/authentik")
	if err == nil {
		t.Fatal("Read succeeded against a closed port")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks the password: %v", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1/authentik") {
		t.Errorf("error should name the source: %v", err)
	}
}
