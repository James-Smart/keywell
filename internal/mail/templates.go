package mail

import (
	"fmt"
	"html"
	"time"
)

// Brand is the identity shown in email copy. PublicURL is not used yet.
type Brand struct{ Name, SupportText, PublicURL string }

// ResetEmail builds the password reset message.
func ResetEmail(b Brand, link string, expires time.Duration) Message {
	text := fmt.Sprintf("Someone asked to reset the password for this address at %s. "+
		"If that was you, use this link within %s: %s\n\n"+
		"If not, ignore this email; nothing changes.\n\n%s\n",
		b.Name, humanDuration(expires), link, b.SupportText)
	htmlBody := fmt.Sprintf("<p>Someone asked to reset the password for this address at %s. "+
		"If that was you, use this link within %s:</p>\n<p><a href=\"%s\">%s</a></p>\n"+
		"<p>If not, ignore this email; nothing changes.</p>\n<p>%s</p>\n",
		esc(b.Name), humanDuration(expires), esc(link), esc(link), esc(b.SupportText))
	return Message{Subject: "Reset your " + b.Name + " password", Text: text, HTML: htmlBody}
}

// InviteEmail builds the new account invitation message.
func InviteEmail(b Brand, link string, expires time.Duration) Message {
	text := fmt.Sprintf("An account has been created for you at %s. "+
		"Choose your password here within %s: %s\n\n%s\n",
		b.Name, humanDuration(expires), link, b.SupportText)
	htmlBody := fmt.Sprintf("<p>An account has been created for you at %s. "+
		"Choose your password here within %s:</p>\n<p><a href=\"%s\">%s</a></p>\n<p>%s</p>\n",
		esc(b.Name), humanDuration(expires), esc(link), esc(link), esc(b.SupportText))
	return Message{Subject: "Set up your " + b.Name + " account", Text: text, HTML: htmlBody}
}

func esc(s string) string { return html.EscapeString(s) }

// humanDuration renders d as whole days when divisible by 24 hours, otherwise
// whole hours (rounded up, minimum one).
func humanDuration(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return plural(int(d/(24*time.Hour)), "day")
	}
	h := int((d + time.Hour - 1) / time.Hour)
	if h < 1 {
		h = 1
	}
	return plural(h, "hour")
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
