package importer

import (
	"fmt"

	"latch/internal/authentik"
	"latch/internal/model"
)

// Report copy for groups.
const (
	reasonUnusedGroup = "Has no members and no app uses it."
	warnNotAdmin      = "Isn't an admin group in Authentik any more. Latch leaves admin access on; " +
		"untick it on the group's page if that's right."
	warnGroupGone = "Is no longer in Authentik. Latch has left it as it is."
)

// group is a snapshot group and what the import does with it.
type group struct {
	src      authentik.Group
	metadata map[string]any // the attributes Latch keeps
	skipped  bool
	latch    *model.Group // the Latch group matched, nil for a new one; once written, as stored
	items    []Item
}

func (g *group) skip(reason string) {
	g.skipped = true
	g.items = append(g.items, Item{Kind: "group", Name: g.src.Name, Skipped: true, Reason: reason})
}

func (g *group) warn(reason string) {
	g.items = append(g.items, Item{Kind: "group", Name: g.src.Name, Reason: reason})
}

// planGroups works out each imported member's groups, decides what happens
// to each snapshot group, matches them to Latch groups, and records
// problems that block the import. It runs after planMembers.
func (r *run) planGroups() {
	parents := map[string][]string{}
	for _, p := range r.snap.Parents {
		parents[p.ChildUUID] = append(parents[p.ChildUUID], p.ParentUUID)
	}
	direct := map[int64][]string{}
	for _, ms := range r.snap.Memberships {
		direct[ms.UserPK] = append(direct[ms.UserPK], ms.GroupUUID)
	}
	// A member of a group is a member of every group above it.
	memberCount := map[string]int{}
	for _, m := range r.members {
		if !m.synced() {
			continue
		}
		m.groups = withAncestors(direct[m.src.PK], parents)
		for _, g := range m.groups {
			memberCount[g]++
		}
	}
	// Ruling E: an app uses a group when an enabled, non-negated binding
	// names it.
	used := map[string]bool{}
	for _, b := range r.snap.Bindings {
		if b.Enabled && !b.Negate && b.GroupUUID != "" {
			used[b.GroupUUID] = true
		}
	}

	byUUID, byName := map[string]*model.Group{}, map[string]*model.Group{}
	for i := range r.latchGroups {
		g := &r.latchGroups[i]
		if g.AuthentikUUID != "" {
			byUUID[g.AuthentikUUID] = g
		}
		byName[g.Name] = g
	}
	inSnap := map[string]bool{}
	names := map[string]bool{} // names of the snapshot groups Latch will have
	for _, src := range r.snap.Groups {
		inSnap[src.UUID] = true
		g := &group{src: src, metadata: r.keep(src.Attributes), latch: byUUID[src.UUID]}
		r.groups = append(r.groups, g)
		// Ruling 5. A group Latch already has is kept up to date even when
		// empty, so that memberships Authentik removed go in Latch too.
		if g.latch == nil && memberCount[src.UUID] == 0 && !used[src.UUID] {
			g.skip(reasonUnusedGroup)
			r.rep.Groups.Skipped++
			continue
		}
		// Match on Authentik UUID, then exact name.
		switch named := byName[src.Name]; {
		case named == nil:
		case g.latch == nil && named.AuthentikUUID != "":
			r.block("Authentik group %s has the same name as Latch group %s, which is linked to a different "+
				"Authentik group. Rename the Latch group on its page, then import again.", src.Name, named.Name)
		case g.latch == nil && named.IsAdmin:
			// Ruling J: adopting a Latch-only admin group would let the
			// import remove Latch's own admins from it.
			r.block(`Authentik's group "%s" has the same name as Latch's admin group. `+
				"Rename one of them before importing.", src.Name)
		case g.latch == nil:
			g.latch = named
		case named.ID != g.latch.ID:
			r.block("Authentik group %s is linked to Latch group %s, but another Latch group is already called %s. "+
				"Rename that Latch group on its page, then import again.", src.Name, g.latch.Name, src.Name)
		}
		if names[src.Name] {
			r.block("Authentik has two groups called %s. Rename one of them in Authentik.", src.Name)
		}
		names[src.Name] = true
		// Ruling 4: admin access is never turned off.
		if g.latch != nil && g.latch.IsAdmin && !src.IsSuperuser {
			g.warn(warnNotAdmin)
		}
	}

	for i := range r.latchGroups {
		if l := &r.latchGroups[i]; l.AuthentikUUID != "" && !inSnap[l.AuthentikUUID] {
			r.goneGroups = append(r.goneGroups, Item{Kind: "group", Name: l.Name, Reason: warnGroupGone})
		}
	}
}

// withAncestors returns the groups and every group above them, each once,
// in the order found. Several parents are all followed, and the seen set
// ends parent cycles.
func withAncestors(groups []string, parents map[string][]string) []string {
	seen := map[string]bool{}
	var out []string
	queue := append([]string(nil), groups...)
	for len(queue) > 0 {
		g := queue[0]
		queue = queue[1:]
		if seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
		queue = append(queue, parents[g]...)
	}
	return out
}

// writeGroups adds and updates the groups.
func (r *run) writeGroups() error {
	for _, g := range r.groups {
		switch {
		case g.skipped:
		case g.latch == nil:
			n := &model.Group{Name: g.src.Name, IsAdmin: g.src.IsSuperuser, RequireTOTP: g.src.IsSuperuser,
				Metadata: g.metadata, AuthentikUUID: g.src.UUID}
			if err := r.tx.CreateGroup(r.ctx, n); err != nil {
				return fmt.Errorf("importer: add group %s: %w", g.src.Name, err)
			}
			g.latch = n
			r.rep.Groups.Added++
		default:
			old := g.latch
			u := *old
			u.Name = g.src.Name
			u.IsAdmin = old.IsAdmin || g.src.IsSuperuser // Ruling 4
			u.RequireTOTP = g.src.IsSuperuser
			u.Metadata = g.metadata
			u.AuthentikUUID = g.src.UUID
			if groupChanged(old, &u) {
				if err := r.tx.UpdateGroup(r.ctx, &u); err != nil {
					return fmt.Errorf("importer: update group %s: %w", g.src.Name, err)
				}
			}
			g.latch = &u
			r.rep.Groups.Updated++
		}
	}
	return nil
}

// groupChanged reports whether any field the import writes differs.
func groupChanged(a, b *model.Group) bool {
	return a.Name != b.Name || a.IsAdmin != b.IsAdmin || a.RequireTOTP != b.RequireTOTP ||
		!sameJSON(a.Metadata, b.Metadata) || a.AuthentikUUID != b.AuthentikUUID
}

// writeMemberships makes each imported member's memberships of the groups
// this import wrote match Authentik's, direct and through child groups.
// Memberships of Latch-only groups, and of groups no longer in Authentik,
// are left alone (Ruling 4).
func (r *run) writeMemberships() error {
	latchID := map[string]string{} // Authentik group UUID: Latch group ID, for the groups written
	managed := map[string]bool{}   // Latch IDs of the groups written
	for _, g := range r.groups {
		if !g.skipped {
			latchID[g.src.UUID] = g.latch.ID
			managed[g.latch.ID] = true
		}
	}
	for _, m := range r.members {
		if !m.synced() {
			continue
		}
		want := map[string]bool{}
		var add []string
		for _, uuid := range m.groups {
			if id, ok := latchID[uuid]; ok && !want[id] {
				want[id] = true
				add = append(add, id)
			}
		}
		have, err := r.tx.ListGroupsForUser(r.ctx, m.latch.ID)
		if err != nil {
			return fmt.Errorf("importer: memberships of %s: %w", m.email, err)
		}
		in := map[string]bool{}
		for _, h := range have {
			in[h.ID] = true
			if managed[h.ID] && !want[h.ID] {
				if err := r.tx.RemoveMember(r.ctx, m.latch.ID, h.ID); err != nil {
					return fmt.Errorf("importer: remove %s from %s: %w", m.email, h.Name, err)
				}
			}
		}
		for _, id := range add {
			if !in[id] {
				if err := r.tx.AddMember(r.ctx, m.latch.ID, id); err != nil {
					return fmt.Errorf("importer: add %s to a group: %w", m.email, err)
				}
			}
		}
	}
	return nil
}
