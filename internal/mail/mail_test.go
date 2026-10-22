package mail

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"latch/internal/config"
)

func TestTemplatesContainLinkAndBrand(t *testing.T) {
	b := Brand{Name: "Make<Space>", SupportText: "Ask at the desk.", PublicURL: "https://id.example.org"}
	link := "https://id.example.org/reset?token=abc&x=1"

	for name, m := range map[string]Message{
		"reset":  ResetEmail(b, link, time.Hour),
		"invite": InviteEmail(b, link, 168*time.Hour),
	} {
		if !strings.Contains(m.Text, link) || !strings.Contains(m.Text, b.Name) {
			t.Errorf("%s text missing link or brand: %q", name, m.Text)
		}
		if !strings.Contains(m.Text, "Ask at the desk.") || !strings.Contains(m.HTML, "Ask at the desk.") {
			t.Errorf("%s missing support text", name)
		}
		if !strings.Contains(m.Subject, b.Name) {
			t.Errorf("%s subject missing brand: %q", name, m.Subject)
		}
		if strings.Contains(m.HTML, "Make<Space>") {
			t.Errorf("%s HTML did not escape brand name: %q", name, m.HTML)
		}
		if !strings.Contains(m.HTML, "Make&lt;Space&gt;") {
			t.Errorf("%s HTML missing escaped brand: %q", name, m.HTML)
		}
		if !strings.Contains(m.HTML, "https://id.example.org/reset?token=abc&amp;x=1") {
			t.Errorf("%s HTML missing escaped link: %q", name, m.HTML)
		}
	}
}

func TestEmailCopy(t *testing.T) {
	b := Brand{Name: "Latch"}
	r := ResetEmail(b, "L", time.Hour)
	if r.Subject != "Reset your Latch password" {
		t.Errorf("subject %q", r.Subject)
	}
	if !strings.Contains(r.Text, "within 1 hour") {
		t.Errorf("reset text: %q", r.Text)
	}
	i := InviteEmail(b, "L", 168*time.Hour)
	if i.Subject != "Set up your Latch account" {
		t.Errorf("subject %q", i.Subject)
	}
	if !strings.Contains(i.Text, "within 7 days") {
		t.Errorf("invite text: %q", i.Text)
	}
	if !strings.Contains(ResetEmail(b, "L", 5*time.Hour).Text, "within 5 hours") {
		t.Error("expected 5 hours")
	}
	if !strings.Contains(InviteEmail(b, "L", 24*time.Hour).Text, "within 1 day") {
		t.Error("expected 1 day")
	}
}

func TestMemory(t *testing.T) {
	var m Memory
	if _, ok := m.Last(); ok {
		t.Fatal("empty Memory should have no last message")
	}
	_ = m.Send(context.Background(), Message{To: "a@x", Subject: "one"})
	_ = m.Send(context.Background(), Message{To: "b@x", Subject: "two"})
	got, ok := m.Last()
	if !ok || got.Subject != "two" || len(m.Sent) != 2 {
		t.Fatalf("unexpected: %+v %v", got, ok)
	}
}

func TestNewSMTPRejectsBadTLS(t *testing.T) {
	if _, err := NewSMTP(config.SMTPConfig{Host: "h", Port: 25, From: "a@b", TLS: "bogus"}); err == nil {
		t.Fatal("expected error")
	}
	for _, mode := range []string{"starttls", "tls", "none"} {
		if _, err := NewSMTP(config.SMTPConfig{Host: "h", Port: 25, From: "a@b", TLS: mode}); err != nil {
			t.Errorf("mode %q: %v", mode, err)
		}
	}
}

type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	rcpt []string
	data string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String()}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		reply := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		reply("220 test ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				reply("250 test")
			case strings.HasPrefix(cmd, "MAIL FROM"):
				reply("250 OK")
			case strings.HasPrefix(cmd, "RCPT TO"):
				f.mu.Lock()
				f.rcpt = append(f.rcpt, strings.TrimSpace(line))
				f.mu.Unlock()
				reply("250 OK")
			case cmd == "DATA":
				reply("354 go ahead")
				var sb strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					sb.WriteString(l)
				}
				f.mu.Lock()
				f.data = sb.String()
				f.mu.Unlock()
				reply("250 queued")
			case cmd == "QUIT":
				reply("221 bye")
				return
			case cmd == "RSET", cmd == "NOOP":
				reply("250 OK")
			default:
				reply("502 not implemented")
			}
		}
	}()
	return f
}

func TestSMTPSendsViaLocalServer(t *testing.T) {
	f := startFakeSMTP(t)
	host, portStr, _ := net.SplitHostPort(f.addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSMTP(config.SMTPConfig{Host: host, Port: port, From: "latch@example.org", TLS: "none"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = s.Send(ctx, Message{To: "jo@example.org", Subject: "Hello there", Text: "plain body", HTML: "<p>html body</p>"})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rcpt) != 1 || !strings.Contains(f.rcpt[0], "RCPT TO:<jo@example.org>") {
		t.Errorf("rcpt: %v", f.rcpt)
	}
	for _, want := range []string{"Subject: Hello there", "plain body", "<p>html body</p>", "text/plain", "text/html"} {
		if !strings.Contains(f.data, want) {
			t.Errorf("data missing %q:\n%s", want, f.data)
		}
	}
}
