package importer

import (
	"encoding/json"
	"strings"
	"testing"
)

// fixedReport is the report the brief's expected text describes.
func fixedReport() *Report {
	return &Report{
		Source:        "db.internal:5432/authentik",
		DryRun:        true,
		Members:       Counts{Added: 6, Skipped: 1},
		Groups:        Counts{Added: 4, Skipped: 2},
		Apps:          Counts{Added: 3, Skipped: 3},
		LeftOut:       3,
		NoPassword:    1,
		TOTP:          1,
		RecoveryCodes: 3,
		MemberKeys:    []KeyCount{{"member_number", 1}},
		GroupKeys:     []KeyCount{{"door", 1}, {"induction", 1}},
		Items: []Item{
			{Kind: "member", Name: "nomail", Skipped: true, Reason: "Has no email address, which Latch needs to sign them in."},
			{Kind: "app", Name: "Wiki", Reason: `Return address https://.*\.example\.org/cb is a pattern. Add the real addresses on the app's page.`},
		},
	}
}

func text(t *testing.T, r *Report) string {
	t.Helper()
	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestReportText(t *testing.T) {
	want := `Dry run of an import from db.internal:5432/authentik. Nothing was saved.
Members: 6 added, 0 updated, 1 skipped
Groups: 4 added, 0 updated, 2 skipped
Apps: 3 added, 0 updated, 3 skipped
Left out 3 service accounts and Authentik's own accounts.
Two-step sign in carried over for 1 member, with 3 recovery codes.
1 member has no usable password and will need a reset link.

Metadata apps will see for members:
  member_number (1 member)
Metadata apps will see for groups:
  door (1 group)
  induction (1 group)

Skipped:
  member nomail: Has no email address, which Latch needs to sign them in.
Warnings:
  app Wiki: Return address https://.*\.example\.org/cb is a pattern. Add the real addresses on the app's page.
`
	r := fixedReport()
	if got := text(t, r); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if got, want := r.Summary(), "6 members added, 0 updated, 1 skipped; 4 groups added, 0 updated, 2 skipped; "+
		"3 apps added, 0 updated, 3 skipped"; got != want {
		t.Errorf("Summary = %q", got)
	}

	// A real run, plurals, and sentence lines with a count of 0 left out.
	r = &Report{
		Source:               "db.internal:5432/authentik",
		Members:              Counts{Added: 1, Updated: 2},
		Groups:               Counts{Updated: 1},
		LeftOut:              1,
		TOTP:                 2,
		RecoveryCodes:        1,
		KeptLatchCredentials: 2,
		NoPassword:           2,
		MemberKeys:           []KeyCount{{"member_number", 2}},
		Items:                []Item{{Kind: "group", Name: "Trustees", Reason: "A warning."}},
	}
	want = `Imported from db.internal:5432/authentik.
Members: 1 added, 2 updated, 0 skipped
Groups: 0 added, 1 updated, 0 skipped
Apps: 0 added, 0 updated, 0 skipped
Left out 1 service accounts and Authentik's own accounts.
Two-step sign in carried over for 2 members, with 1 recovery code.
2 members already use Latch and kept their Latch password and two-step sign in.
2 members have no usable password and will need a reset link.

Metadata apps will see for members:
  member_number (2 members)

Warnings:
  group Trustees: A warning.
`
	if got := text(t, r); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if got, want := r.Summary(), "1 member added, 2 updated, 0 skipped; 0 groups added, 1 updated, 0 skipped; "+
		"0 apps added, 0 updated, 0 skipped"; got != want {
		t.Errorf("Summary = %q", got)
	}

	r = &Report{Source: "db.internal:5432/authentik", KeptLatchCredentials: 1, GroupKeys: []KeyCount{{"door", 2}}}
	want = `Imported from db.internal:5432/authentik.
Members: 0 added, 0 updated, 0 skipped
Groups: 0 added, 0 updated, 0 skipped
Apps: 0 added, 0 updated, 0 skipped
1 member already uses Latch and kept their Latch password and two-step sign in.

Metadata apps will see for groups:
  door (2 groups)
`
	if got := text(t, r); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}

	// A blocked report prints its header and the blocking lines only.
	r = fixedReport()
	r.Blocking = []string{"First problem.", "Second problem."}
	want = `Nothing was imported from db.internal:5432/authentik. Fix these first:
  First problem.
  Second problem.
`
	if got := text(t, r); got != want {
		t.Errorf("blocked text:\n%s\nwant:\n%s", got, want)
	}
}

func TestReportJSON(t *testing.T) {
	b, err := json.Marshal(fixedReport())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"source":"db.internal:5432/authentik"`, `"dry_run":true`, `"left_out":3`, `"no_password":1`,
		`"kept_latch_credentials":0`, `"recovery_codes":3`, `"totp":1`,
		`"members":{"added":6,"updated":0,"skipped":1}`,
		`"member_keys":[{"key":"member_number","count":1}]`,
		`{"kind":"member","name":"nomail","skipped":true,"reason":"Has no email address`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON lacks %s:\n%s", want, b)
		}
	}
}
