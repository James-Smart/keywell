package importer

import (
	"cmp"
	"fmt"
	"strings"
	"time"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/authentik"
	"github.com/James-Smart/keywell/internal/model"
)

// Report copy for members. Item reasons are full sentences about the
// member the item names.
const (
	reasonNoEmail   = "Has no email address, which Keywell needs to sign them in."
	reasonBadEmail  = "Has an email address Keywell can't use."
	warnBadUsername = "Has a username Keywell can't use, so it was left off."
	warnLongName    = "Has a name longer than Keywell allows. Keywell kept it, but shorten it before editing them on their page."
	warnBigMetadata = "Has more than 8 KB of metadata. Keywell kept it, but shorten it before editing them on their page."
	warnRelinked    = "Was linked to an Authentik account that no longer exists. Keywell now links them to this one, " +
		"so apps that identify people by their Authentik ID will see a new ID."
	warnMemberGone   = "Is no longer in Authentik. Keywell has left them as they are."
	warnKeptEmail    = "Has no usable email address in Authentik, so Keywell kept the one it had."
	warnNowService   = "Is now a service account in Authentik, so Keywell turned their account off."
	warnUsernameCase = "Has the username %s, which differs only in capitals from the username %s of member %s. " +
		"Keywell keeps both, but apps that ignore capitals may mix them up."
)

// member is a snapshot user who is not left out, or a Keywell member who is
// now a service account in Authentik, and what the import does with them.
type member struct {
	src                   authentik.User
	name, email, username string         // as Keywell stores them
	metadata              map[string]any // the attributes Keywell keeps
	skipped               bool
	keptEmail             bool        // email is Keywell's, as Authentik has no usable one (Ruling AB)
	turnOff               bool        // now a service account, so only turned off (Ruling AB)
	keywell               *model.User // the Keywell member matched, nil for a new one; once written, as stored
	groups                []string    // UUIDs of their Authentik groups, direct and through child groups
	items                 []Item
}

// synced reports whether the import keeps the member in step with
// Authentik: their details, memberships and credentials.
func (m *member) synced() bool { return !m.skipped && !m.turnOff }

// label names the member in the report: their email, or their username
// when they have none.
func (m *member) label() string { return cmp.Or(strings.TrimSpace(m.src.Email), m.src.Username) }

func (m *member) skip(reason string) {
	m.skipped = true
	m.items = append(m.items, Item{Kind: "member", Name: m.label(), Skipped: true, Reason: reason})
}

func (m *member) warn(reason string) {
	m.items = append(m.items, Item{Kind: "member", Name: m.label(), Reason: reason})
}

// leftOut reports whether u is a service account or one of Authentik's own
// accounts. These are not imported or listed, only counted.
func leftOut(u *authentik.User) bool {
	return u.Type == "service_account" || u.Type == "internal_service_account" || u.Username == "AnonymousUser"
}

// foldEmail lower-cases ASCII letters only, as SQLite's lower() does, so
// two emails match here exactly when Keywell's email index and sign in treat
// them as one.
func foldEmail(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// akRef names an Authentik user in a blocking message: "username (email)",
// or the username when they have no email.
func akRef(u *authentik.User) string {
	if e := strings.TrimSpace(u.Email); e != "" {
		return u.Username + " (" + e + ")"
	}
	return u.Username
}

func akMember(u *authentik.User) string { return "Authentik member " + akRef(u) }

// keywellRef names a Keywell account in a blocking message.
func keywellRef(u *model.User) string {
	if u.Type == model.UserTypeService {
		return "Keywell service account " + cmp.Or(u.Username, u.Name)
	}
	return "Keywell member " + cmp.Or(u.Email, u.Username, u.Name)
}

// keywellUsers indexes Keywell's users the ways members are matched and checked.
type keywellUsers struct {
	byUUID, byEmail, byUsername map[string]*model.User
}

// planMembers decides what happens to each snapshot user, matches them to
// Keywell members, and records problems that block the import.
func (r *run) planMembers() {
	idx := keywellUsers{map[string]*model.User{}, map[string]*model.User{}, map[string]*model.User{}}
	for i := range r.keywellUsers {
		u := &r.keywellUsers[i]
		if u.AuthentikUUID != "" {
			idx.byUUID[u.AuthentikUUID] = u
		}
		if u.Email != "" {
			idx.byEmail[foldEmail(u.Email)] = u
		}
		if u.Username != "" {
			idx.byUsername[u.Username] = u
		}
	}
	inSnap := map[string]*authentik.User{}
	for i := range r.snap.Users {
		inSnap[r.snap.Users[i].UUID] = &r.snap.Users[i]
	}

	emails := map[string]*member{}    // folded email: the first member with it
	usernames := map[string]*member{} // lower-cased username: the first member with it
	claimed := map[string]bool{}      // IDs of the Keywell members matched
	for i := range r.snap.Users {
		u := &r.snap.Users[i]
		if leftOut(u) {
			// Ruling AB. Matched by Authentik ID only: an email address shared
			// with a Keywell member is no sign they are the same person.
			if l := idx.byUUID[u.UUID]; l != nil {
				m := &member{src: *u, keywell: l, turnOff: true}
				m.warn(warnNowService)
				r.members = append(r.members, m)
				claimed[l.ID] = true
				continue
			}
			r.rep.LeftOut++
			continue
		}
		m := r.planMember(u, idx, inSnap)
		r.members = append(r.members, m)
		if m.skipped {
			r.rep.Members.Skipped++
			continue
		}
		if m.keywell != nil {
			claimed[m.keywell.ID] = true
		}
		// An email address Keywell kept isn't Authentik's, so it can't clash
		// within the snapshot. A snapshot member who has it matches this
		// Keywell member by email, and planMember blocks that.
		switch prev := emails[foldEmail(m.email)]; {
		case m.keptEmail:
		case prev != nil:
			r.block("Authentik members %s and %s have the same email address apart from capitals. "+
				"Keywell needs a different email address for each member, so change one of them in Authentik.",
				akRef(&prev.src), akRef(&m.src))
		default:
			emails[foldEmail(m.email)] = m
		}
		// Ruling 9: usernames stay unique by exact case, with a warning.
		if m.username != "" {
			if prev := usernames[strings.ToLower(m.username)]; prev == nil {
				usernames[strings.ToLower(m.username)] = m
			} else if prev.username != m.username {
				m.warn(fmt.Sprintf(warnUsernameCase, m.username, prev.username, prev.label()))
			}
		}
	}

	for i := range r.keywellUsers {
		l := &r.keywellUsers[i]
		if l.AuthentikUUID != "" && inSnap[l.AuthentikUUID] == nil && !claimed[l.ID] {
			r.goneUsers = append(r.goneUsers, Item{Kind: "member", Name: cmp.Or(l.Email, l.Username, l.Name),
				Reason: warnMemberGone})
		}
	}
}

// emailProblem is why a member with this email address can't be added to
// Keywell, or "" when Keywell can use it.
func emailProblem(email string) string {
	switch {
	case email == "":
		return reasonNoEmail
	case admin.MemberProblems("", email, "", nil)["email"] != "":
		return reasonBadEmail
	}
	return ""
}

// planMember works out how Keywell stores u, and which Keywell member u is.
func (r *run) planMember(u *authentik.User, idx keywellUsers, inSnap map[string]*authentik.User) *member {
	m := &member{src: *u}
	m.email = strings.TrimSpace(u.Email)
	m.username = strings.TrimSpace(u.Username)
	m.metadata = r.keep(u.Attributes)
	// Ruling AB: the Authentik ID is matched before the email is checked, so
	// a member Keywell has stays in step when their email address goes bad.
	linked := idx.byUUID[u.UUID]
	if reason := emailProblem(m.email); reason != "" {
		if linked == nil {
			m.skip(reason)
			return m
		}
		m.email, m.keptEmail = linked.Email, true
		m.warn(warnKeptEmail)
	}
	m.name = cmp.Or(strings.TrimSpace(u.Name), m.username, m.email)

	// Ruling D: the member pages' rules. The email address passes by now.
	probs := admin.MemberProblems(m.name, m.email, m.username, m.metadata)
	if probs["name"] != "" {
		m.warn(warnLongName)
	}
	if probs["username"] != "" {
		m.username = ""
		m.warn(warnBadUsername)
	}
	if probs["metadata"] != "" {
		m.warn(warnBigMetadata)
	}

	// Match on Authentik UUID, then email.
	if linked != nil {
		m.keywell = linked
		if other := idx.byEmail[foldEmail(m.email)]; other != nil && other.ID != linked.ID {
			r.block("%s is linked to %s, but %s already has that email address. "+
				"Change the email address of one of them in Authentik or Keywell.", akMember(u), keywellRef(linked),
				keywellRef(other))
		}
	} else if l := idx.byEmail[foldEmail(m.email)]; l != nil {
		switch old := inSnap[l.AuthentikUUID]; {
		case l.AuthentikUUID == "":
			m.keywell = l
		case old != nil:
			r.block("%s has the email address of %s, but that Keywell member is linked to %s. "+
				"Change the email address of one of them in Authentik or Keywell.", akMember(u), keywellRef(l), akMember(old))
		default: // Ruling F: the Authentik account was deleted and made again.
			m.keywell = l
			m.warn(warnRelinked)
		}
	}

	if m.username != "" {
		if other := idx.byUsername[m.username]; other != nil && (m.keywell == nil || other.ID != m.keywell.ID) {
			r.block("%s has the username %s, which %s already has. Change one of the usernames in Authentik or Keywell.",
				akMember(u), m.username, keywellRef(other))
		}
	}
	return m
}

// writeMembers adds and updates the members.
func (r *run) writeMembers() error {
	for _, m := range r.members {
		switch {
		case m.skipped:
		case m.turnOff:
			if err := r.turnOffMember(m); err != nil {
				return err
			}
			r.rep.Members.Updated++
		case m.keywell == nil:
			if err := r.addMember(m); err != nil {
				return err
			}
			r.rep.Members.Added++
		default:
			if err := r.updateMember(m); err != nil {
				return err
			}
			r.rep.Members.Updated++
		}
	}
	return nil
}

// addMember creates the member in Keywell.
func (r *run) addMember(m *member) error {
	pk := m.src.PK
	u := &model.User{
		Name:          m.name,
		Type:          model.UserTypeMember,
		Email:         m.email,
		Username:      m.username,
		IsActive:      m.src.IsActive,
		Metadata:      m.metadata,
		AuthentikPK:   &pk,
		AuthentikUUID: m.src.UUID,
		AuthentikUID:  authentik.HashedUserID(pk, r.snap.InstallID),
		LastLoginAt:   utc(m.src.LastLogin),
		CreatedAt:     m.src.DateJoined.UTC(),
	}
	if err := r.tx.CreateUser(r.ctx, u); err != nil {
		return fmt.Errorf("importer: add member %s: %w", m.email, err)
	}
	m.keywell = u
	return nil
}

// updateMember overwrites the matched Keywell member's imported fields with
// Authentik's. It never touches their password or two-step sign in. A
// member Authentik has disabled is signed out everywhere.
func (r *run) updateMember(m *member) error {
	old := m.keywell
	u := *old
	pk := m.src.PK
	u.Name, u.Email, u.Username, u.IsActive, u.Metadata = m.name, m.email, m.username, m.src.IsActive, m.metadata
	u.AuthentikPK, u.AuthentikUUID, u.AuthentikUID = &pk, m.src.UUID, authentik.HashedUserID(pk, r.snap.InstallID)
	if memberChanged(old, &u) {
		if err := r.tx.UpdateUser(r.ctx, &u); err != nil {
			return fmt.Errorf("importer: update member %s: %w", m.email, err)
		}
	}
	if at := m.src.LastLogin; at != nil && (old.LastLoginAt == nil || at.After(*old.LastLoginAt)) {
		if err := r.tx.TouchLastLogin(r.ctx, u.ID, *at); err != nil {
			return fmt.Errorf("importer: update member %s: %w", m.email, err)
		}
		u.LastLoginAt = utc(at)
	}
	if old.IsActive && !u.IsActive {
		if err := r.signOut(&u); err != nil {
			return err
		}
	}
	m.keywell = &u
	return nil
}

// turnOffMember turns off a Keywell member who is now a service account in
// Authentik, and signs them out everywhere. Nothing else about them
// changes.
func (r *run) turnOffMember(m *member) error {
	old := m.keywell
	if !old.IsActive {
		return nil
	}
	u := *old
	u.IsActive = false
	if err := r.tx.UpdateUser(r.ctx, &u); err != nil {
		return fmt.Errorf("importer: turn off member %s: %w", u.Email, err)
	}
	if err := r.signOut(&u); err != nil {
		return err
	}
	m.keywell = &u
	return nil
}

// signOut ends the member's sessions and revokes their refresh tokens.
func (r *run) signOut(u *model.User) error {
	if err := r.tx.DeleteSessionsForUser(r.ctx, u.ID); err != nil {
		return fmt.Errorf("importer: sign out member %s: %w", u.Email, err)
	}
	if err := r.tx.RevokeRefreshTokensForUser(r.ctx, u.ID); err != nil {
		return fmt.Errorf("importer: sign out member %s: %w", u.Email, err)
	}
	return nil
}

// memberChanged reports whether any field the import writes differs.
func memberChanged(a, b *model.User) bool {
	return a.Name != b.Name || a.Email != b.Email || a.Username != b.Username || a.IsActive != b.IsActive ||
		!sameJSON(a.Metadata, b.Metadata) || !samePK(a.AuthentikPK, b.AuthentikPK) ||
		a.AuthentikUUID != b.AuthentikUUID || a.AuthentikUID != b.AuthentikUID
}

func samePK(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// utc copies t in UTC, keeping nil.
func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}
