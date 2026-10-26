// Package importer copies an Authentik snapshot into Latch: members,
// groups and memberships, then credentials and applications.
//
// One Run is one SQLite transaction on the store's single connection. A
// dry run, an import with problems that block it, and a failure partway
// all roll back, so Latch is left exactly as it was; a dry run's report is
// the one the real run would give. Inside the transaction only the
// transaction's Store is used.
package importer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"latch/internal/audit"
	"latch/internal/authentik"
	"latch/internal/config"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
)

// Deps is what Run needs.
type Deps struct {
	Store *store.Store
	Enc   *secrets.Encryptor
	Cfg   *config.Config   // token lifetime caps
	Audit *audit.Recorder  // nil: no audit event
	Now   func() time.Time // nil: time.Now
}

// Options are the choices of one import.
type Options struct {
	DryRun   bool
	DropKeys []string // metadata keys to leave out besides "goauthentik.io/…"
	Source   string   // authentik.Source(dsn), for the report
}

// ErrBlocked is returned, with a report whose Blocking says why, when
// problems must be fixed before anything can be imported.
var ErrBlocked = errors.New("importer: problems must be fixed before importing")

// errDryRun rolls back a dry run's transaction; Run turns it into nil.
var errDryRun = errors.New("importer: dry run")

// testHookAfterMembers, when a test sets it, runs once members are
// written; an error from it fails the run there.
var testHookAfterMembers func() error

// Run imports snap into Latch in one transaction and reports what it did.
// With opts.DryRun it reports what it would do and saves nothing. When
// there are blocking problems it saves nothing and returns ErrBlocked with
// the report. Any other error means nothing was saved and there is no
// report.
func Run(ctx context.Context, d Deps, snap *authentik.Snapshot, opts Options) (*Report, error) {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	rep := &Report{Source: opts.Source, DryRun: opts.DryRun, StartedAt: now().UTC()}
	err := d.Store.InTx(ctx, func(tx *store.Store) error {
		r := &run{ctx: ctx, tx: tx, enc: d.Enc, cfg: d.Cfg, snap: snap, opts: opts, rep: rep}
		if err := r.load(); err != nil {
			return err
		}
		r.planMembers()
		r.planGroups()
		r.planApps()
		if len(r.blocking) > 0 {
			rep.Blocking = r.blocking
			return ErrBlocked
		}
		if err := r.writeGroups(); err != nil {
			return err
		}
		if err := r.writeMembers(); err != nil {
			return err
		}
		if testHookAfterMembers != nil {
			if err := testHookAfterMembers(); err != nil {
				return err
			}
		}
		if err := r.writeMemberships(); err != nil {
			return err
		}
		if err := r.writeCredentials(); err != nil {
			return err
		}
		if err := r.writeApps(); err != nil {
			return err
		}
		r.finish()
		rep.FinishedAt = now().UTC()
		if opts.DryRun {
			return errDryRun
		}
		return r.saveRun()
	})
	switch {
	case errors.Is(err, errDryRun):
	case errors.Is(err, ErrBlocked):
		return &Report{Source: opts.Source, DryRun: opts.DryRun, StartedAt: rep.StartedAt,
			FinishedAt: now().UTC(), Blocking: rep.Blocking}, ErrBlocked
	case err != nil:
		return nil, err
	}
	// The audit event is recorded after commit, through the outer store: the
	// transaction's store is closed by now. Per-record detail is in the
	// stored report.
	if !opts.DryRun && d.Audit != nil {
		d.Audit.Record(ctx, model.AuditEvent{
			ActorType: model.ActorImporter,
			Action:    audit.ImportRun,
			Summary:   "Imported from Authentik: " + rep.Summary(),
		})
	}
	return rep, nil
}

// run is one import in progress, bound to its transaction.
type run struct {
	ctx  context.Context
	tx   *store.Store
	enc  *secrets.Encryptor
	cfg  *config.Config
	snap *authentik.Snapshot
	opts Options
	rep  *Report

	// Latch as it was when the run started.
	latchUsers  []model.User
	latchGroups []model.Group
	latchApps   []model.Application

	members    []*member    // every snapshot user not left out, in snapshot order
	goneUsers  []Item       // Latch members whose Authentik account is gone
	groups     []*group     // every snapshot group, in snapshot order
	goneGroups []Item       // Latch groups whose Authentik group is gone
	apps       []*importApp // every snapshot application, in snapshot order
	// otherAppItems lists the providers no application uses, then the Latch
	// apps whose Authentik app is gone.
	otherAppItems []Item
	blocking      []string
}

// load reads Latch's users, groups and applications.
func (r *run) load() error {
	var err error
	if r.latchUsers, err = r.tx.AllUsers(r.ctx); err != nil {
		return fmt.Errorf("importer: load members: %w", err)
	}
	if r.latchGroups, err = r.tx.ListGroups(r.ctx); err != nil {
		return fmt.Errorf("importer: load groups: %w", err)
	}
	if r.latchApps, err = r.tx.ListApplications(r.ctx); err != nil {
		return fmt.Errorf("importer: load apps: %w", err)
	}
	return nil
}

// block records a problem that stops the import.
func (r *run) block(format string, args ...any) {
	r.blocking = append(r.blocking, fmt.Sprintf(format, args...))
}

// keep returns the attributes Latch keeps as metadata: all but the
// "goauthentik.io/…" keys and Options.DropKeys.
func (r *run) keep(attrs map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range attrs {
		if strings.HasPrefix(k, "goauthentik.io/") || slices.Contains(r.opts.DropKeys, k) {
			continue
		}
		out[k] = v
	}
	return out
}

// finish fills the report's items, in snapshot order within each kind
// (members, then groups, then apps), and its metadata key counts.
func (r *run) finish() {
	var memberMeta, groupMeta []map[string]any
	for _, m := range r.members {
		r.rep.Items = append(r.rep.Items, m.items...)
		if m.synced() {
			memberMeta = append(memberMeta, m.metadata)
		}
	}
	r.rep.Items = append(r.rep.Items, r.goneUsers...)
	for _, g := range r.groups {
		r.rep.Items = append(r.rep.Items, g.items...)
		if !g.skipped {
			groupMeta = append(groupMeta, g.metadata)
		}
	}
	r.rep.Items = append(r.rep.Items, r.goneGroups...)
	for _, a := range r.apps {
		r.rep.Items = append(r.rep.Items, a.items...)
	}
	r.rep.Items = append(r.rep.Items, r.otherAppItems...)
	r.rep.MemberKeys = countKeys(memberMeta)
	r.rep.GroupKeys = countKeys(groupMeta)
}

// countKeys counts, for each top-level key, how many of the metadata maps
// have it, sorted by key.
func countKeys(metas []map[string]any) []KeyCount {
	n := map[string]int{}
	for _, m := range metas {
		for k := range m {
			n[k]++
		}
	}
	var out []KeyCount
	for _, k := range slices.Sorted(maps.Keys(n)) {
		out = append(out, KeyCount{Key: k, Count: n[k]})
	}
	return out
}

// saveRun stores the run and its report.
func (r *run) saveRun() error {
	b, err := json.Marshal(r.rep)
	if err != nil {
		return fmt.Errorf("importer: encode report: %w", err)
	}
	if err := r.tx.InsertImportRun(r.ctx, &store.ImportRun{StartedAt: r.rep.StartedAt, FinishedAt: r.rep.FinishedAt,
		Source: r.rep.Source, Report: string(b)}); err != nil {
		return fmt.Errorf("importer: save import run: %w", err)
	}
	return nil
}

// sameJSON reports whether a and b encode to the same JSON, so metadata
// read back from the database (numbers as float64) equals the same
// metadata from Authentik, and nil equals {}.
func sameJSON(a, b map[string]any) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ja) == string(jb)
}
