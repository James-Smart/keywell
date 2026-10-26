package importer

import (
	"errors"
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

	adminsOnlyTail = "Only admins can use it until you choose its groups on the app's page."
	warnAdminsOnly = "Authentik limited who could use it %s. " + adminsOnlyTail

	// noteAccessFollows ends the reason of a skipped app whose groups still
	// follow Authentik (Ruling N), unless they are admins only.
	noteAccessFollows = "Who can use it still follows Authentik."

	blockNoAdminGroup = `Latch has no admin group, so "%s" can't be limited to admins. ` +
		"Give a group admin access before importing."
)

// accessRule is who Authentik let use an application, as far as Latch can
// say it (Ruling 6).
type accessRule struct {
	groups []string // Authentik UUIDs of the groups that may use it; none, with no with, is everyone
	with   string   // set when only admins may use it in Latch: why, completing "Authentik limited who could use it …"
}

// decideAccess works out who may use an application in Latch from its
// Authentik bindings, never letting in a member Authentik kept out.
// imported holds the UUIDs of the snapshot groups Latch will have.
// Disabled bindings count for nothing, as in Authentik.
//   - No enabled bindings: everyone, as in Authentik.
//   - Only group bindings, none negated, in "any" mode or just one: those
//     groups.
//   - Anything else, or a group Latch won't have: admins only, with the
//     first reason of policy, named person, negated binding and several
//     groups that all had to match.
func decideAccess(engineMode string, bindings []authentik.Binding, imported map[string]bool) accessRule {
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
			if !slices.Contains(groups, b.GroupUUID) {
				groups = append(groups, b.GroupUUID)
			}
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
		return accessRule{}
	case policy:
		with = withPolicy
	case person:
		with = withPerson
	case negated:
		with = withLeftOut
	case enabled > 1 && engineMode != "any":
		with = withAllGroups
	default:
		for _, uuid := range groups {
			if !imported[uuid] {
				with = withMissingGroup
				break
			}
		}
	}
	if with != "" {
		return accessRule{with: with}
	}
	return accessRule{groups: groups}
}

// accessGroups is what resolve needs to know about Latch's groups once the
// import has written them.
type accessGroups struct {
	latchID map[string]string // Authentik group UUID: Latch group ID, for the groups imported
	admins  []string          // IDs of every Latch admin group, imported or Latch's own, sorted
}

// loadAccessGroups reads Latch's groups after the group step (Ruling M).
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

// access is who may use an app in Latch.
type access struct {
	groupIDs []string // Latch group IDs, sorted; none is every active member
	with     string   // set for admins only: why, as in accessRule
}

// resolve turns rule into Latch group IDs. Admins only is every Latch admin
// group, which is never none: planApps blocks the import first, because
// none would mean everyone.
func (ag accessGroups) resolve(rule accessRule) (access, error) {
	if rule.with != "" {
		if len(ag.admins) == 0 {
			return access{}, errors.New("importer: no admin group to limit an app to")
		}
		return access{groupIDs: slices.Clone(ag.admins), with: rule.with}, nil
	}
	var ids []string
	for _, uuid := range rule.groups {
		id, ok := ag.latchID[uuid]
		if !ok {
			return access{}, fmt.Errorf("importer: group %s was not imported", uuid)
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return access{groupIDs: slices.Compact(ids)}, nil
}

// skipFollowingAccess skips a with reason. Every skip of an app with an
// OpenID Connect provider comes here, with acc already decided. When a's
// Latch app came from an earlier import, its allowed groups still become
// acc's, so a skip never leaves it open wider than Authentik (Rulings N
// and P); every other field is left as it was, and nothing is written when
// the groups already match. The reason ends by saying who can use it.
func (r *run) skipFollowingAccess(a *importApp, reason string, acc access) error {
	l := a.latch
	if l == nil || l.AuthentikProviderPK == nil {
		a.skip(reason)
		return nil
	}
	if !sameIDs(l.AllowedGroupIDs, acc.groupIDs) {
		u := *l
		u.AllowedGroupIDs = slices.Clone(acc.groupIDs)
		if err := r.tx.UpdateApplication(r.ctx, &u); err != nil {
			return fmt.Errorf("importer: set who can use app %s: %w", a.src.Name, err)
		}
	}
	note := noteAccessFollows
	if acc.with != "" {
		note = adminsOnlyTail
	}
	a.skip(reason + " " + note)
	return nil
}

// sameIDs reports whether a and b hold the same IDs, in any order.
func sameIDs(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
