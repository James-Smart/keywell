package importer

import (
	"fmt"
	"slices"

	"latch/internal/authentik"
)

// Report copy for access rules. Each "with …" phrase completes "Authentik
// limited who could use it …".
const (
	withPolicy       = "with a policy"
	withPerson       = "with a named person"
	withLeftOut      = "with a rule that left people out"
	withAllGroups    = "with several groups that all had to match"
	withMissingGroup = "with a group Latch doesn't have"

	warnAdminsOnly = "Authentik limited who could use it %s. " +
		"Only admins can use it until you choose its groups on the app's page."
	reasonNoAdminGroup = "Authentik limited who could use it %s, and Latch has no admin group to limit it to " +
		"instead. Make an admin group in Latch, then import again."

	// noteAccessFollows ends the reason of a skipped app whose groups still
	// follow Authentik (Ruling N).
	noteAccessFollows = " Who can use it still follows Authentik."
)

// accessGroups is what appAccess needs to know about Latch's groups once
// the import has written them.
type accessGroups struct {
	latchID map[string]string // Authentik group UUID: Latch group ID, for the groups imported
	admins  []string          // IDs of every Latch admin group, imported or Latch's own, sorted
}

// loadAccessGroups reads Latch's groups after the group step.
func (r *run) loadAccessGroups() (accessGroups, error) {
	ag := accessGroups{latchID: map[string]string{}}
	for _, g := range r.groups {
		if !g.skipped {
			ag.latchID[g.src.UUID] = g.latch.ID
		}
	}
	all, err := r.tx.ListGroups(r.ctx)
	if err != nil {
		return ag, fmt.Errorf("importer: load groups: %w", err)
	}
	for _, g := range all {
		if g.IsAdmin {
			ag.admins = append(ag.admins, g.ID)
		}
	}
	slices.Sort(ag.admins)
	return ag, nil
}

// access is who may use an imported app.
type access struct {
	groupIDs []string // Latch group IDs, sorted; none is open to every active member
	warning  string   // "" when Authentik's rules carried over as they were
	skip     string   // the reason, when the app can't be imported without letting more people in
}

// appAccess works out who may use an application in Latch from its
// Authentik bindings (Ruling 6), never letting in a member Authentik kept
// out. Disabled bindings count for nothing, as in Authentik.
//   - No enabled bindings: open to every active member, as in Authentik.
//   - Only group bindings, none negated, in "any" mode or just one: those
//     groups.
//   - Anything else, or a group Latch doesn't have: Latch's admin groups
//     only, with a warning naming the first reason of policy, named person,
//     negated binding and several groups that all had to match. With no
//     admin group the app is skipped, because no groups means open to all.
func appAccess(engineMode string, bindings []authentik.Binding, ag accessGroups) access {
	var enabled int
	var policy, person, negated bool
	var groups []string
	for _, b := range bindings {
		if !b.Enabled {
			continue
		}
		enabled++
		switch {
		case b.UserPK != nil:
			person = true
		case b.GroupUUID != "":
			groups = append(groups, b.GroupUUID)
		default: // a policy, or a binding Latch can't read, which it treats as one
			policy = true
		}
		if b.Negate {
			negated = true
		}
	}

	var with string
	switch {
	case enabled == 0:
		return access{}
	case policy:
		with = withPolicy
	case person:
		with = withPerson
	case negated:
		with = withLeftOut
	case len(groups) > 1 && engineMode != "any":
		with = withAllGroups
	}
	if with == "" {
		var ids []string
		for _, uuid := range groups {
			id, ok := ag.latchID[uuid]
			if !ok {
				with = withMissingGroup
				break
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		if with == "" {
			slices.Sort(ids)
			return access{groupIDs: ids}
		}
	}
	if len(ag.admins) == 0 {
		return access{skip: fmt.Sprintf(reasonNoAdminGroup, with)}
	}
	return access{groupIDs: slices.Clone(ag.admins), warning: fmt.Sprintf(warnAdminsOnly, with)}
}

// skipFollowingAccess skips a with reason. When a's Latch app came from an
// earlier import, its allowed groups still become allowed, as appAccess
// decided for this run, so that a skip never leaves an app open wider than
// Authentik (Ruling N). Every other field is left as it was, and nothing is
// written when the groups already match.
func (r *run) skipFollowingAccess(a *importApp, reason string, allowed []string) error {
	l := a.latch
	if l == nil || l.AuthentikProviderPK == nil {
		a.skip(reason)
		return nil
	}
	if !sameIDs(l.AllowedGroupIDs, allowed) {
		u := *l
		u.AllowedGroupIDs = allowed
		if err := r.tx.UpdateApplication(r.ctx, &u); err != nil {
			return fmt.Errorf("importer: set who can use app %s: %w", a.src.Name, err)
		}
	}
	a.skip(reason + noteAccessFollows)
	return nil
}

// sameIDs reports whether a and b hold the same IDs, in any order.
func sameIDs(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
