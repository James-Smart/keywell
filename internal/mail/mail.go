// Package mail sends transactional email.
package mail

import (
	"context"
	"sync"
)

// Message is a single outgoing email with a plain text body and an HTML
// alternative.
type Message struct{ To, Subject, Text, HTML string }

// Mailer delivers messages.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// Memory is a Mailer test double that records what it is asked to send.
type Memory struct {
	mu   sync.Mutex
	Sent []Message
}

// Send records msg.
func (m *Memory) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Sent = append(m.Sent, msg)
	return nil
}

// Last returns the most recently sent message, if any.
func (m *Memory) Last() (Message, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Sent) == 0 {
		return Message{}, false
	}
	return m.Sent[len(m.Sent)-1], true
}
