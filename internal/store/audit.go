package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
)

// InsertAuditEvent stores an audit event, filling ID and At if empty.
func (s *Store) InsertAuditEvent(ctx context.Context, e *model.AuditEvent) error {
	if e.ID == "" {
		e.ID = secrets.NewID()
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	detail, err := marshalMeta(e.Detail)
	if err != nil {
		return err
	}
	_, err = s.q.ExecContext(ctx, `INSERT INTO audit_events
		(id, at, actor_type, actor_id, action, target_type, target_id, summary, detail)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		e.ID, formatTime(e.At), string(e.ActorType), e.ActorID, e.Action, e.TargetType, e.TargetID, e.Summary, detail)
	return wrapWrite("store: insert audit event", err)
}

// AuditFilter selects and pages the events ListAuditEvents returns.
type AuditFilter struct {
	Since, Until          time.Time // zero = unbounded; Since inclusive, Until exclusive
	ActorID, TargetID     string    // exact
	Actions               []string  // action prefixes, OR-ed: "user." matches user.create, "logout" matches logout
	Query                 string    // case-insensitive substring of summary
	CollapseLoginFailures bool      // one row per target and clock hour for login.failure, with Count
	Page, PerPage         int       // as UserFilter
}

// AuditRow is an audit event; Count is 1 except for collapsed rows.
type AuditRow struct {
	model.AuditEvent
	Count int
}

// AuditPage is one page of ListAuditEvents; Total counts rows after collapsing.
type AuditPage struct {
	Rows                 []AuditRow
	Total, Page, PerPage int
}

// ListAuditEvents returns one page of events matching f, newest first. With
// CollapseLoginFailures, login.failure events for one target within one clock
// hour become a single row holding the newest of them and their number.
func (s *Store) ListAuditEvents(ctx context.Context, f AuditFilter) (AuditPage, error) {
	const op = "store: list audit events"
	page := AuditPage{}
	page.Page, page.PerPage = normPaging(f.Page, f.PerPage)

	var conds []string
	var args []any
	if !f.Since.IsZero() {
		conds = append(conds, `at >= ?`)
		args = append(args, formatTime(f.Since))
	}
	if !f.Until.IsZero() {
		conds = append(conds, `at < ?`)
		args = append(args, formatTime(f.Until))
	}
	if f.ActorID != "" {
		conds = append(conds, `actor_id = ?`)
		args = append(args, f.ActorID)
	}
	if f.TargetID != "" {
		conds = append(conds, `target_id = ?`)
		args = append(args, f.TargetID)
	}
	if len(f.Actions) > 0 {
		var ors []string
		for _, a := range f.Actions {
			ors = append(ors, `action LIKE ? ESCAPE '\'`)
			args = append(args, likeEscaper.Replace(a)+"%")
		}
		conds = append(conds, `(`+strings.Join(ors, ` OR `)+`)`)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		conds = append(conds, `summary LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscaper.Replace(q)+"%")
	}
	where := ""
	if len(conds) > 0 {
		where = ` WHERE ` + strings.Join(conds, ` AND `)
	}
	// Every row is its own group, except that collapsed login failures share
	// one per target and clock hour (at is fixed-width, so 13 characters is
	// the hour). With MAX(at) the only min/max aggregate, SQLite takes the
	// bare columns from the row holding the maximum: the newest event.
	group := `id`
	if f.CollapseLoginFailures {
		group = `CASE WHEN action = 'login.failure' THEN target_id || '|' || substr(at, 1, 13) ELSE id END`
	}

	if err := s.q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM (SELECT 1 FROM audit_events`+where+` GROUP BY `+group+`)`, args...).Scan(&page.Total); err != nil {
		return AuditPage{}, fmt.Errorf("%s: %w", op, err)
	}
	qargs := append(args, page.PerPage, (page.Page-1)*page.PerPage)
	rows, err := s.q.QueryContext(ctx, `SELECT id, MAX(at), actor_type, actor_id, action, target_type, target_id,
		summary, detail, COUNT(*) FROM audit_events`+where+` GROUP BY `+group+`
		ORDER BY MAX(at) DESC, id DESC LIMIT ? OFFSET ?`, qargs...)
	if err != nil {
		return AuditPage{}, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			r      AuditRow
			at     string
			actor  string
			detail sql.NullString
		)
		if err := rows.Scan(&r.ID, &at, &actor, &r.ActorID, &r.Action, &r.TargetType, &r.TargetID,
			&r.Summary, &detail, &r.Count); err != nil {
			return AuditPage{}, fmt.Errorf("%s: %w", op, err)
		}
		r.ActorType = model.ActorType(actor)
		if r.At, err = parseTime(at); err != nil {
			return AuditPage{}, err
		}
		if r.Detail, err = unmarshalMeta(detail); err != nil {
			return AuditPage{}, err
		}
		page.Rows = append(page.Rows, r)
	}
	if err := rows.Err(); err != nil {
		return AuditPage{}, fmt.Errorf("%s: %w", op, err)
	}
	return page, nil
}
