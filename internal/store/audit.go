package store

import (
	"context"
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
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit_events
		(id, at, actor_type, actor_id, action, target_type, target_id, summary, detail)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		e.ID, formatTime(e.At), string(e.ActorType), e.ActorID, e.Action, e.TargetType, e.TargetID, e.Summary, detail)
	return wrapWrite("store: insert audit event", err)
}
