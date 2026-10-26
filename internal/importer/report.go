package importer

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Report says what an import did, or would do in a dry run. It is stored as
// JSON with the import run and shown on the Settings page, so its text
// follows the admin pages' copy rules. It holds no secrets.
type Report struct {
	Source                 string     `json:"source"`
	DryRun                 bool       `json:"dry_run"`
	StartedAt              time.Time  `json:"started_at"`
	FinishedAt             time.Time  `json:"finished_at"`
	Members                Counts     `json:"members"`
	Groups                 Counts     `json:"groups"`
	Apps                   Counts     `json:"apps"`
	LeftOut                int        `json:"left_out"`                 // service accounts and Authentik's own accounts
	KeptKeywellCredentials int        `json:"kept_keywell_credentials"` // Ruling 3
	NoPassword             int        `json:"no_password"`
	TOTP                   int        `json:"totp"`
	RecoveryCodes          int        `json:"recovery_codes"`
	MemberKeys             []KeyCount `json:"member_keys"`
	GroupKeys              []KeyCount `json:"group_keys"`
	Items                  []Item     `json:"items"`
	Blocking               []string   `json:"blocking"`
}

// Counts is how many records of one kind were added, updated and skipped.
// A record that matched counts as updated even when nothing changed.
type Counts struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

// KeyCount is a metadata key and how many imported records have it.
type KeyCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Item is a record that was skipped, or imported with a warning.
type Item struct {
	Kind    string `json:"kind"`    // "member", "group" or "app"
	Name    string `json:"name"`    // email for members (username when there is none); name otherwise
	Skipped bool   `json:"skipped"` // false: imported, with a warning
	Reason  string `json:"reason"`  // a full sentence
}

// plural is one when n is 1 and many otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// WriteText writes the report as the CLI prints it and the Settings page
// shows it. A blocked report gives only what must be fixed.
func (r *Report) WriteText(w io.Writer) error {
	var b strings.Builder
	if len(r.Blocking) > 0 {
		fmt.Fprintf(&b, "Nothing was imported from %s. Fix these first:\n", r.Source)
		for _, line := range r.Blocking {
			fmt.Fprintf(&b, "  %s\n", line)
		}
		_, err := io.WriteString(w, b.String())
		return err
	}

	if r.DryRun {
		fmt.Fprintf(&b, "Dry run of an import from %s. Nothing was saved.\n", r.Source)
	} else {
		fmt.Fprintf(&b, "Imported from %s.\n", r.Source)
	}
	for _, line := range r.CountLines() {
		b.WriteString(line + "\n")
	}
	if r.LeftOut > 0 {
		fmt.Fprintf(&b, "Left out %d service accounts and Authentik's own accounts.\n", r.LeftOut)
	}
	if r.TOTP > 0 {
		fmt.Fprintf(&b, "Two-step sign in carried over for %d %s", r.TOTP, plural(r.TOTP, "member", "members"))
		if r.RecoveryCodes > 0 {
			fmt.Fprintf(&b, ", with %d %s", r.RecoveryCodes, plural(r.RecoveryCodes, "recovery code", "recovery codes"))
		}
		b.WriteString(".\n")
	}
	if n := r.KeptKeywellCredentials; n > 0 {
		fmt.Fprintf(&b, "%d %s Keywell and kept their Keywell password and two-step sign in.\n",
			n, plural(n, "member already uses", "members already use"))
	}
	if n := r.NoPassword; n > 0 {
		fmt.Fprintf(&b, "%d %s no usable password and will need a reset link.\n", n, plural(n, "member has", "members have"))
	}

	if len(r.MemberKeys) > 0 || len(r.GroupKeys) > 0 {
		b.WriteString("\n")
		writeKeys(&b, "members", "member", r.MemberKeys)
		writeKeys(&b, "groups", "group", r.GroupKeys)
	}

	var skipped, warnings []Item
	for _, it := range r.Items {
		if it.Skipped {
			skipped = append(skipped, it)
		} else {
			warnings = append(warnings, it)
		}
	}
	if len(r.Items) > 0 {
		b.WriteString("\n")
		writeItems(&b, "Skipped", skipped)
		writeItems(&b, "Warnings", warnings)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// CountLines is the "Members: …", "Groups: …" and "Apps: …" lines.
func (r *Report) CountLines() []string {
	var lines []string
	for _, c := range []struct {
		kind string
		n    Counts
	}{{"Members", r.Members}, {"Groups", r.Groups}, {"Apps", r.Apps}} {
		lines = append(lines, fmt.Sprintf("%s: %d added, %d updated, %d skipped", c.kind, c.n.Added, c.n.Updated, c.n.Skipped))
	}
	return lines
}

// writeKeys writes the metadata keys apps will see for one kind of record.
func writeKeys(b *strings.Builder, kinds, kind string, keys []KeyCount) {
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(b, "Metadata apps will see for %s:\n", kinds)
	for _, k := range keys {
		fmt.Fprintf(b, "  %s (%d %s)\n", k.Key, k.Count, plural(k.Count, kind, kinds))
	}
}

// writeItems writes a heading and one line per item.
func writeItems(b *strings.Builder, heading string, items []Item) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "%s:\n", heading)
	for _, it := range items {
		fmt.Fprintf(b, "  %s %s: %s\n", it.Kind, it.Name, it.Reason)
	}
}

// Summary is the counts on one line, such as "6 members added, 0 updated,
// 1 skipped; 4 groups added, 0 updated, 2 skipped; 3 apps added, 0
// updated, 3 skipped".
func (r *Report) Summary() string {
	part := func(c Counts, one, many string) string {
		return fmt.Sprintf("%d %s added, %d updated, %d skipped", c.Added, plural(c.Added, one, many), c.Updated, c.Skipped)
	}
	return part(r.Members, "member", "members") + "; " + part(r.Groups, "group", "groups") + "; " +
		part(r.Apps, "app", "apps")
}
