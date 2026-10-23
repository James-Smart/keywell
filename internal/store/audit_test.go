package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"latch/internal/model"
)

func addAudit(t *testing.T, s *Store, at time.Time, actor, action, target, summary string) string {
	t.Helper()
	e := &model.AuditEvent{At: at, ActorType: model.ActorUser, ActorID: actor, Action: action,
		TargetType: "user", TargetID: target, Summary: summary}
	if err := s.InsertAuditEvent(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	return e.ID
}

func auditIDs(p AuditPage) []string {
	out := []string{}
	for _, r := range p.Rows {
		out = append(out, r.ID)
	}
	return out
}

func TestListAuditEvents(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	e1 := addAudit(t, s, base, "a1", "login.success", "u1", "Signed in")
	e2 := addAudit(t, s, base.Add(time.Hour), "a2", "user.create", "u2", "Created Alex")
	e3 := addAudit(t, s, base.Add(2*time.Hour), "a1", "logout", "u1", "Signed out")
	e4 := addAudit(t, s, base.Add(3*time.Hour), "a2", "group.member.add", "u2", "Added Alex to Laser")

	list := func(f AuditFilter) AuditPage {
		t.Helper()
		p, err := s.ListAuditEvents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	check := func(name string, f AuditFilter, want ...string) {
		t.Helper()
		p := list(f)
		if got := auditIDs(p); !reflect.DeepEqual(got, append([]string{}, want...)) || p.Total != len(want) {
			t.Fatalf("%s: got %v total %d, want %v", name, got, p.Total, want)
		}
	}
	check("all newest first", AuditFilter{}, e4, e3, e2, e1)
	check("since inclusive", AuditFilter{Since: base.Add(time.Hour)}, e4, e3, e2)
	check("until exclusive", AuditFilter{Until: base.Add(2 * time.Hour)}, e2, e1)
	check("window", AuditFilter{Since: base.Add(time.Hour), Until: base.Add(3 * time.Hour)}, e3, e2)
	check("actor", AuditFilter{ActorID: "a1"}, e3, e1)
	check("target", AuditFilter{TargetID: "u2"}, e4, e2)
	check("actions", AuditFilter{Actions: []string{"user.", "logout"}}, e3, e2)
	check("query", AuditFilter{Query: "laser"}, e4)
	check("query literal percent", AuditFilter{Query: "%"})

	p := list(AuditFilter{PerPage: 2})
	if p.Total != 4 || p.Page != 1 || p.PerPage != 2 || !reflect.DeepEqual(auditIDs(p), []string{e4, e3}) {
		t.Fatalf("page 1: %+v", p)
	}
	p = list(AuditFilter{PerPage: 2, Page: 2})
	if p.Total != 4 || !reflect.DeepEqual(auditIDs(p), []string{e2, e1}) {
		t.Fatalf("page 2: %+v", p)
	}
	for _, r := range p.Rows {
		if r.Count != 1 {
			t.Fatalf("count %d", r.Count)
		}
	}
}

func TestListAuditEventsCollapsesLoginFailures(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ten := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	var lastX string
	for _, m := range []int{5, 20, 40, 59} {
		lastX = addAudit(t, s, ten.Add(time.Duration(m)*time.Minute), "", "login.failure", "X", "Failed sign-in")
	}
	x11 := addAudit(t, s, ten.Add(65*time.Minute), "", "login.failure", "X", "Failed sign-in")
	var lastBlank string
	for _, m := range []int{1, 2, 3} {
		lastBlank = addAudit(t, s, ten.Add(time.Duration(m)*time.Minute), "", "login.failure", "", "Failed sign-in")
	}
	upd := addAudit(t, s, ten.Add(30*time.Minute), "adm", "user.update", "X", "Updated X")

	p, err := s.ListAuditEvents(ctx, AuditFilter{CollapseLoginFailures: true})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id    string
		count int
	}
	var got []row
	for _, r := range p.Rows {
		got = append(got, row{r.ID, r.Count})
	}
	want := []row{{x11, 1}, {lastX, 4}, {upd, 1}, {lastBlank, 3}}
	if p.Total != 4 || !reflect.DeepEqual(got, want) {
		t.Fatalf("collapsed: total %d got %v want %v", p.Total, got, want)
	}
	if p.Rows[1].At.Minute() != 59 {
		t.Fatalf("collapsed row is not the latest: %v", p.Rows[1].At)
	}

	p, err = s.ListAuditEvents(ctx, AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 9 || len(p.Rows) != 9 {
		t.Fatalf("uncollapsed: total %d rows %d", p.Total, len(p.Rows))
	}
	for _, r := range p.Rows {
		if r.Count != 1 {
			t.Fatalf("count %d", r.Count)
		}
	}

	// Paging applies after collapsing.
	p, err = s.ListAuditEvents(ctx, AuditFilter{CollapseLoginFailures: true, PerPage: 3, Page: 2})
	if err != nil || p.Total != 4 || len(p.Rows) != 1 {
		t.Fatalf("page 2: %+v %v", p, err)
	}
}
