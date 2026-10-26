package web_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/secrets"
	"github.com/James-Smart/keywell/internal/store"
	"github.com/James-Smart/keywell/internal/testenv"
)

var (
	codeMismatch    = html.EscapeString("That code didn't match. Check your phone's clock and try again.")
	disableMismatch = html.EscapeString("Your password or code didn't match.")
	groupRequires   = "Your group requires two-step sign in."
	requiredNotice  = "Your group requires two-step sign in. Set it up now."
	// savedButton is the codes page's way on, to next ("/" by default).
	savedButton = `<a class="button" href="/">I've saved these</a>`
)

// post sends form to path with c and returns the response and body.
func post(t *testing.T, env *testenv.Env, c *http.Client, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := c.PostForm(env.TS.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

// validCode moves env's clock on by one 30 second TOTP step and returns
// the code for secret then. Each call gives a code from a step not used
// before, as the server accepts each code once.
func validCode(t *testing.T, env *testenv.Env, secret string) string {
	t.Helper()
	env.Clock.Advance(30 * time.Second)
	return codeAt(t, secret, env.Clock.Now())
}

// codeAt is the TOTP code for secret at time at.
func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := pqtotp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// wrongCode is a six-digit code that is not valid for secret in any of the
// time steps the server accepts now (by env's clock).
func wrongCode(t *testing.T, env *testenv.Env, secret string) string {
	t.Helper()
	now := env.Clock.Now()
	valid := map[string]bool{}
	for _, at := range []time.Time{now.Add(-time.Minute), now.Add(-30 * time.Second), now, now.Add(30 * time.Second), now.Add(time.Minute)} {
		code, err := pqtotp.GenerateCode(secret, at)
		if err != nil {
			t.Fatal(err)
		}
		valid[code] = true
	}
	for i := 0; ; i++ {
		if code := fmt.Sprintf("%06d", i); !valid[code] {
			return code
		}
	}
}

var manualKeyRE = regexp.MustCompile(`<code class="key">([A-Z2-7 ]+)</code>`)

// manualKey returns the key the enrolment page shows, without spaces.
func manualKey(t *testing.T, body string) string {
	t.Helper()
	m := manualKeyRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no manual key on the page:\n%s", body)
	}
	return strings.ReplaceAll(m[1], " ", "")
}

// beginEnrolment starts enrolment with form, follows the redirect back to
// the TOTP page and returns the manual key it shows.
func beginEnrolment(t *testing.T, env *testenv.Env, c *http.Client, form url.Values) string {
	t.Helper()
	resp, _ := post(t, env, c, "/account/totp/begin", form)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/account/totp") {
		t.Fatalf("begin: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := get(t, c, env.TS.URL+resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrolment page: status %d", resp.StatusCode)
	}
	for _, want := range []string{`src="/account/totp/qr.png"`, `action="/account/totp/confirm"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("enrolment page missing %q", want)
		}
	}
	return manualKey(t, body)
}

// signInWithCode signs in with the password and then a TOTP code.
func signInWithCode(t *testing.T, env *testenv.Env, c *http.Client, email, secret string) {
	t.Helper()
	env.Login(t, c, email, testPW)
	resp, _ := post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/")
}

func getUser(t *testing.T, env *testenv.Env, id string) *model.User {
	t.Helper()
	u, err := env.Store.GetUser(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// secondFactors returns the second_factor detail of each login.success
// event that completed a two-step sign-in.
func secondFactors(t *testing.T, env *testenv.Env) []string {
	t.Helper()
	var got []string
	for _, e := range auditEvents(t, env, audit.LoginSuccess) {
		if f, _ := e.Detail["second_factor"].(string); f == "totp" || f == "recovery" {
			got = append(got, f)
		}
	}
	return got
}

var recoveryCodeRE = regexp.MustCompile(`<code>([a-z2-9]{5}-[a-z2-9]{5})</code>`)

func TestEnrolConfirmShowsCodesOnce(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	sid := jarSession(t, env, c)

	resp, body := get(t, c, env.TS.URL+"/account/totp")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/account/totp/begin"`) ||
		strings.Contains(body, "qr.png") || strings.Contains(body, requiredNotice) {
		t.Fatalf("status page before enrolment: status %d\n%s", resp.StatusCode, body)
	}
	if resp, _ := get(t, c, env.TS.URL+"/account/totp/qr.png"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("qr.png with nothing pending: status %d, want 404", resp.StatusCode)
	}

	key := beginEnrolment(t, env, c, nil)
	if len(key) != 32 {
		t.Fatalf("manual key %q", key)
	}
	// The pending secret is stored sealed.
	sealed, _, err := env.Store.GetTOTPEnrolment(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(key)) {
		t.Fatal("pending secret stored in plain text")
	}
	if plain, err := env.Enc.Open(sealed); err != nil || string(plain) != key {
		t.Fatalf("pending secret opens to %q, %v; page shows %q", plain, err, key)
	}

	resp, png := get(t, c, env.TS.URL+"/account/totp/qr.png")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/png" ||
		!strings.HasPrefix(png, "\x89PNG\r\n\x1a\n") {
		t.Fatalf("qr.png: status %d type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	resp, body = post(t, env, c, "/account/totp/confirm", url.Values{"code": {wrongCode(t, env, key)}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, codeMismatch) || manualKey(t, body) != key {
		t.Fatalf("wrong confirm code: status %d\n%s", resp.StatusCode, body)
	}
	if getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("enrolled by a wrong code")
	}

	resp, _ = post(t, env, c, "/account/totp/confirm", url.Values{"code": {validCode(t, env, key)}})
	assertRedirect(t, resp, "/account/totp/codes")

	got := getUser(t, env, u.ID)
	if !got.TOTPEnrolled() {
		t.Fatal("not enrolled after confirming")
	}
	if plain, err := env.Enc.Open(got.TOTPSecretEnc); err != nil || string(plain) != key {
		t.Fatalf("stored secret opens to %q, %v", plain, err)
	}
	if events := auditEvents(t, env, audit.TOTPEnrolled); len(events) != 1 || events[0].ActorID != u.ID {
		t.Fatalf("totp enrol events %+v", events)
	}

	resp, body = get(t, c, env.TS.URL+"/account/totp/codes")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, savedButton) {
		t.Fatalf("codes page: status %d\n%s", resp.StatusCode, body)
	}
	codes := map[string]bool{}
	for _, m := range recoveryCodeRE.FindAllStringSubmatch(body, -1) {
		codes[m[1]] = true
	}
	if len(codes) != 10 {
		t.Fatalf("codes page shows %d distinct codes, want 10:\n%s", len(codes), body)
	}
	if n, err := env.Store.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 10 {
		t.Fatalf("stored recovery codes: %d, %v", n, err)
	}
	for code := range codes {
		if ok, err := env.Store.ConsumeRecoveryCode(ctx, u.ID, secrets.HashToken(code)); !ok || err != nil {
			t.Fatalf("shown code %q is not a stored recovery code: %v", code, err)
		}
		break
	}

	resp, _ = get(t, c, env.TS.URL+"/account/totp/codes")
	assertRedirect(t, resp, "/account/totp")
	if _, _, err := env.Store.GetTOTPEnrolment(ctx, sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("enrolment kept after the codes were shown: %v", err)
	}
	if resp, _ := get(t, c, env.TS.URL+"/account/totp/qr.png"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("qr.png after enrolment: status %d, want 404", resp.StatusCode)
	}
	resp, body = get(t, c, env.TS.URL+"/account/totp")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/account/totp/disable"`) ||
		strings.Contains(body, `action="/account/totp/begin"`) {
		t.Fatalf("status page after enrolment: status %d\n%s", resp.StatusCode, body)
	}
}

// recoveryCodeRows counts every recovery code stored for userID, used or not.
func recoveryCodeRows(t *testing.T, env *testenv.Env, userID string) int {
	t.Helper()
	var n int
	if err := env.DB.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE user_id=?`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// assertCodesShownOnce follows location (where the browser was sent after
// confirming) to the codes page and checks it shows the 10 stored codes
// with a button to wantNext, and that they are then gone.
func assertCodesShownOnce(t *testing.T, env *testenv.Env, c *http.Client, u *model.User, location, wantNext string) {
	t.Helper()
	ctx := context.Background()
	for range 2 {
		if !strings.HasPrefix(location, "/account/totp/codes") {
			resp, _ := get(t, c, env.TS.URL+location)
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("GET %s: status %d, want a redirect to the codes", location, resp.StatusCode)
			}
			location = resp.Header.Get("Location")
		}
	}
	resp, body := get(t, c, env.TS.URL+location)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", location, resp.StatusCode)
	}
	if want := `<a class="button" href="` + html.EscapeString(wantNext) + `">`; !strings.Contains(body, want) {
		t.Errorf("codes page missing %q", want)
	}
	shown := recoveryCodeRE.FindAllStringSubmatch(body, -1)
	if len(shown) != 10 {
		t.Fatalf("codes page shows %d codes", len(shown))
	}
	if n := recoveryCodeRows(t, env, u.ID); n != 10 {
		t.Fatalf("%d recovery codes stored, want 10", n)
	}
	for _, m := range shown {
		if ok, err := env.Store.ConsumeRecoveryCode(ctx, u.ID, secrets.HashToken(m[1])); !ok || err != nil {
			t.Fatalf("shown code %q is not stored: %v", m[1], err)
		}
	}
	if events := auditEvents(t, env, audit.TOTPEnrolled); len(events) != 1 {
		t.Fatalf("totp enrol events: %d, want 1", len(events))
	}
	resp, _ = get(t, c, env.TS.URL+"/account/totp/codes")
	assertRedirect(t, resp, "/account/totp")
}

// A double-clicked confirm: the browser shows the second response, which
// must still lead to the codes from the first.
func TestConfirmTwiceStillShowsCodes(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	const next = "/oauth/authorize?client_id=wiki&state=x"

	key := beginEnrolment(t, env, c, url.Values{"next": {next}})
	form := url.Values{"code": {validCode(t, env, key)}, "next": {next}}
	first, _ := post(t, env, c, "/account/totp/confirm", form)
	assertRedirect(t, first, "/account/totp/codes?next="+url.QueryEscape(next))
	second, _ := post(t, env, c, "/account/totp/confirm", form)
	if second.StatusCode != http.StatusSeeOther {
		t.Fatalf("second confirm: status %d", second.StatusCode)
	}
	assertCodesShownOnce(t, env, c, u, second.Header.Get("Location"), next)
}

// Two confirms at once: whichever way they interleave, one set of codes is
// stored and that set is the one shown.
func TestConfirmConcurrentStoresOneSetOfCodes(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	key := beginEnrolment(t, env, c, nil)
	form := url.Values{"code": {validCode(t, env, key)}}

	locations := make(chan string, 2)
	for range 2 {
		go func() {
			resp, err := c.PostForm(env.TS.URL+"/account/totp/confirm", form)
			if err != nil {
				locations <- "error: " + err.Error()
				return
			}
			resp.Body.Close()
			locations <- fmt.Sprint(resp.StatusCode, " ", resp.Header.Get("Location"))
		}()
	}
	got := []string{<-locations, <-locations}
	for _, l := range got {
		if l != "303 /account/totp/codes" && l != "303 /account/totp" {
			t.Fatalf("confirm responses %q", got)
		}
	}
	assertCodesShownOnce(t, env, c, u, "/account/totp", "/")
}

func TestLoginTOTPCodeAndRecovery(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	const recovery = "abcde-fghjk"
	if err := env.Store.ReplaceRecoveryCodes(ctx, u.ID,
		[]string{secrets.HashToken(recovery), secrets.HashToken("mnpqr-stuvw")}); err != nil {
		t.Fatal(err)
	}

	c := env.Client(t)
	form := creds("alex@example.org", testPW)
	form.Set("next", "/account?tab=2")
	resp, _ := postLogin(t, env, c, form)
	assertRedirect(t, resp, "/login/totp?next=%2Faccount%3Ftab%3D2")

	resp, body := get(t, c, env.TS.URL+"/login/totp?next=%2Faccount%3Ftab%3D2")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login/totp: status %d", resp.StatusCode)
	}
	for _, want := range []string{`action="/login/totp"`, `name="code"`, `name="next" value="/account?tab=2"`} {
		if !strings.Contains(body, want) {
			t.Errorf("TOTP page missing %q", want)
		}
	}
	if strings.Contains(body, "alex@example.org") {
		t.Error("TOTP page shows the user as signed in")
	}

	resp, body = post(t, env, c, "/login/totp", url.Values{"code": {wrongCode(t, env, secret)}, "next": {"/account?tab=2"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, codeMismatch) ||
		!strings.Contains(body, `name="next" value="/account?tab=2"`) {
		t.Fatalf("wrong code: status %d\n%s", resp.StatusCode, body)
	}
	resp, _ = post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, env, secret)}, "next": {"/account?tab=2"}})
	assertRedirect(t, resp, "/account?tab=2")
	sess, err := env.Store.GetSession(ctx, jarSession(t, env, c))
	if err != nil || !sess.TOTPPassed {
		t.Fatalf("session after code: %+v, %v", sess, err)
	}
	if resp, _ := get(t, c, env.TS.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / after the code: status %d", resp.StatusCode)
	}
	// A complete session has nothing more to do here.
	resp, _ = get(t, c, env.TS.URL+"/login/totp?next=%2Faccount")
	assertRedirect(t, resp, "/account")

	// A recovery code works once, typed any way, and next is still checked.
	c2 := env.Client(t)
	env.Login(t, c2, "alex@example.org", testPW)
	resp, _ = post(t, env, c2, "/login/totp", url.Values{"code": {" ABCDE FGHJK "}, "next": {"https://evil.example"}})
	assertRedirect(t, resp, "/")
	if n, err := env.Store.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 1 {
		t.Fatalf("unused recovery codes: %d, %v", n, err)
	}

	c3 := env.Client(t)
	env.Login(t, c3, "alex@example.org", testPW)
	resp, body = post(t, env, c3, "/login/totp", url.Values{"code": {recovery}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, codeMismatch) {
		t.Fatalf("reused recovery code: status %d\n%s", resp.StatusCode, body)
	}

	if got := secondFactors(t, env); len(got) != 2 || got[0] != "totp" || got[1] != "recovery" {
		t.Fatalf("second factors audited: %v", got)
	}
	if got := getUser(t, env, u.ID); got.LastLoginAt == nil {
		t.Fatal("LastLoginAt not set")
	}
}

func TestLoginTOTPFiveFailuresEndsSession(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	sid := jarSession(t, env, c)

	// A wrong recovery code counts the same as a wrong six-digit code.
	for i, code := range []string{wrongCode(t, env, secret), "zzzzz-zzzzz", wrongCode(t, env, secret), wrongCode(t, env, secret)} {
		resp, body := post(t, env, c, "/login/totp", url.Values{"code": {code}})
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, codeMismatch) {
			t.Fatalf("failure %d: status %d", i+1, resp.StatusCode)
		}
	}
	if events := auditEvents(t, env, audit.LoginTOTPFailure); len(events) != 0 {
		t.Fatalf("failures audited before the limit: %+v", events)
	}

	resp, _ := post(t, env, c, "/login/totp", url.Values{"code": {wrongCode(t, env, secret)}})
	assertRedirect(t, resp, "/login")
	if jarSession(t, env, c) != "" {
		t.Fatal("session cookie not cleared")
	}
	if _, err := env.Store.GetSession(ctx, sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session still stored: %v", err)
	}
	events := auditEvents(t, env, audit.LoginTOTPFailure)
	if len(events) != 1 || events[0].ActorID != u.ID || events[0].TargetID != u.ID {
		t.Fatalf("totp failure events %+v", events)
	}

	// Without the session even the right code gets nowhere.
	resp, _ = post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, env, secret)}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login?") {
		t.Fatalf("code after the session ended: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := secondFactors(t, env); len(got) != 0 {
		t.Fatalf("sign-in completed: %v", got)
	}
}

// wrongGuesses posts n wrong codes at the TOTP step, each of which must be
// refused with the form shown again.
func wrongGuesses(t *testing.T, env *testenv.Env, c *http.Client, path string, form url.Values, secret string, n int) {
	t.Helper()
	for i := range n {
		f := url.Values{}
		for k, v := range form {
			f[k] = v
		}
		f.Set("code", wrongCode(t, env, secret))
		resp, body := post(t, env, c, path, f)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("wrong code %d at %s: status %d location %q", i+1, path, resp.StatusCode, resp.Header.Get("Location"))
		}
		if !strings.Contains(body, codeMismatch) && !strings.Contains(body, disableMismatch) {
			t.Fatalf("wrong code %d at %s: no mismatch message", i+1, path)
		}
	}
}

// accountThrottled reports the login.totp_failure events recorded because
// the account's budget of wrong codes was spent.
func accountThrottled(t *testing.T, env *testenv.Env) int {
	t.Helper()
	n := 0
	for _, e := range auditEvents(t, env, audit.LoginTOTPFailure) {
		if e.Detail["reason"] == "account_throttled" {
			n++
		}
	}
	return n
}

// Signing in again starts a fresh per-session count, so wrong codes are
// also capped per account: 10 per 15 minutes, after which no code is
// checked at all until the window passes.
func TestLoginTOTPAccountThrottle(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)

	// 10 wrong codes over three sessions, none reaching the per-session cap.
	var last *http.Client
	for _, n := range []int{4, 4, 2} {
		last = env.Client(t)
		env.Login(t, last, "alex@example.org", testPW)
		wrongGuesses(t, env, last, "/login/totp", nil, secret, n)
	}
	sid := jarSession(t, env, last)

	// The budget is spent: even the right code is refused, unchecked.
	resp, _ := post(t, env, last, "/login/totp", url.Values{"code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/login")
	if jarSession(t, env, last) != "" {
		t.Fatal("session cookie not cleared")
	}
	if _, err := env.Store.GetSession(ctx, sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session still stored: %v", err)
	}
	if n := accountThrottled(t, env); n != 1 {
		t.Fatalf("account_throttled events: %d, want 1", n)
	}

	// A fresh sign-in does not buy another guess.
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	resp, _ = post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/login")
	if got := secondFactors(t, env); len(got) != 0 {
		t.Fatalf("sign-in completed while throttled: %v", got)
	}

	env.Clock.Advance(16 * time.Minute)
	c = env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	resp, _ = post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/")
}

// A correct code clears the account's count of wrong ones.
func TestLoginTOTPCorrectCodeResetsAccountThrottle(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)

	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	wrongGuesses(t, env, c, "/login/totp", nil, secret, 4)
	resp, _ := post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/")

	for range 2 {
		c := env.Client(t)
		env.Login(t, c, "alex@example.org", testPW)
		wrongGuesses(t, env, c, "/login/totp", nil, secret, 4)
	}
	c = env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	resp, _ = post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/")
}

// Wrong codes when turning TOTP off use the same account budget.
func TestDisableCountsTowardTOTPThrottle(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	c := env.Client(t)
	signInWithCode(t, env, c, "alex@example.org", secret)
	sid := jarSession(t, env, c)

	// A wrong password does not get as far as the code, so it costs none of
	// the code budget (and the right one clears the sign-in budget it used).
	wrongGuesses(t, env, c, "/account/totp/disable", url.Values{"password": {"not the password"}}, secret, 3)
	wrongGuesses(t, env, c, "/account/totp/disable", url.Values{"password": {testPW}}, secret, 10)

	resp, _ := post(t, env, c, "/account/totp/disable", url.Values{"password": {testPW}, "code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/login")
	if _, err := env.Store.GetSession(ctx, sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session still stored: %v", err)
	}
	if !getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("TOTP turned off while throttled")
	}
	if n := accountThrottled(t, env); n != 1 {
		t.Fatalf("account_throttled events: %d, want 1", n)
	}
}

func TestRequiredByGroupForcesEnrolment(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	env.CreateGroup(t, "Admin", true, true)
	u := env.CreateUser(t, "admin@example.org", testPW, "Admin")
	c := env.Client(t)

	resp, _ := postLogin(t, env, c, creds("admin@example.org", testPW))
	assertRedirect(t, resp, "/account/totp?required=1&next=%2F")
	resp, _ = get(t, c, env.TS.URL+"/")
	assertRedirect(t, resp, "/account/totp?required=1&next=%2F")
	// There is no code to enter yet.
	resp, _ = get(t, c, env.TS.URL+"/login/totp")
	assertRedirect(t, resp, "/account/totp?required=1&next=%2F")

	resp, body := get(t, c, env.TS.URL+"/account/totp?required=1&next=%2F")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, requiredNotice) ||
		!strings.Contains(body, `action="/account/totp/begin"`) {
		t.Fatalf("required enrolment page: status %d\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "admin@example.org") {
		t.Error("enrolment page shows the user as signed in")
	}

	key := beginEnrolment(t, env, c, url.Values{"required": {"1"}, "next": {"/"}})
	resp, _ = post(t, env, c, "/account/totp/confirm",
		url.Values{"code": {validCode(t, env, key)}, "required": {"1"}, "next": {"/"}})
	assertRedirect(t, resp, "/account/totp/codes?next=%2F")
	sess, err := env.Store.GetSession(ctx, jarSession(t, env, c))
	if err != nil || !sess.TOTPPassed {
		t.Fatalf("session after enrolment: %+v, %v", sess, err)
	}
	if !getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("not enrolled")
	}

	resp, body = get(t, c, env.TS.URL+"/account/totp/codes?next=%2F")
	if resp.StatusCode != http.StatusOK || len(recoveryCodeRE.FindAllString(body, -1)) != 10 ||
		!strings.Contains(body, savedButton) {
		t.Fatalf("codes page: status %d\n%s", resp.StatusCode, body)
	}
	if resp, _ := get(t, c, env.TS.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / after enrolment: status %d", resp.StatusCode)
	}
}

func TestDisableRequiresPasswordAndCode(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	if err := env.Store.ReplaceRecoveryCodes(ctx, u.ID, []string{secrets.HashToken("abcde-fghjk")}); err != nil {
		t.Fatal(err)
	}
	c := env.Client(t)
	signInWithCode(t, env, c, "alex@example.org", secret)

	resp, body := get(t, c, env.TS.URL+"/account/totp")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/account/totp/disable"`) {
		t.Fatalf("status page: status %d\n%s", resp.StatusCode, body)
	}
	// Neither a begin nor a QR code is on offer while enrolled.
	resp, _ = post(t, env, c, "/account/totp/begin", nil)
	assertRedirect(t, resp, "/account/totp")
	if resp, _ := get(t, c, env.TS.URL+"/account/totp/qr.png"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("qr.png while enrolled: status %d", resp.StatusCode)
	}

	for name, form := range map[string]url.Values{
		"wrong password": {"password": {"not the password"}, "code": {validCode(t, env, secret)}},
		"wrong code":     {"password": {testPW}, "code": {wrongCode(t, env, secret)}},
		"no code":        {"password": {testPW}},
	} {
		resp, body := post(t, env, c, "/account/totp/disable", form)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, disableMismatch) {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
		if !getUser(t, env, u.ID).TOTPEnrolled() {
			t.Fatalf("%s: TOTP turned off", name)
		}
	}

	resp, _ = post(t, env, c, "/account/totp/disable", url.Values{"password": {testPW}, "code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/account/totp")
	got := getUser(t, env, u.ID)
	if got.TOTPEnrolled() || got.TOTPSecretEnc != nil {
		t.Fatalf("still enrolled: %+v", got)
	}
	if n, err := env.Store.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 0 {
		t.Fatalf("recovery codes left: %d, %v", n, err)
	}
	if events := auditEvents(t, env, audit.TOTPDisabled); len(events) != 1 || events[0].ActorID != u.ID {
		t.Fatalf("totp disable events %+v", events)
	}
	resp, body = get(t, c, env.TS.URL+"/account/totp")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/account/totp/begin"`) {
		t.Fatalf("status page after disabling: status %d\n%s", resp.StatusCode, body)
	}
}

// Recovery codes imported from Authentik are stored as the hash of the exact
// token and work once, case-sensitively, at the TOTP step and when turning
// two-step sign in off.
func TestImportedRecoveryCode(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	if err := env.Store.ReplaceRecoveryCodes(ctx, u.ID, []string{
		secrets.HashToken("RecoveryAAA1"), secrets.HashToken("AbCdEfGhJk"),
		secrets.HashToken("RecoveryBBB2"), secrets.HashToken("RecoveryCCC3"), secrets.HashToken("mnpqr-stuvw"),
	}); err != nil {
		t.Fatal(err)
	}
	step := func(code string) *http.Response {
		c := env.Client(t)
		env.Login(t, c, "alex@example.org", testPW)
		resp, _ := post(t, env, c, "/login/totp", url.Values{"code": {code}})
		return resp
	}
	refused := func(name, code string) {
		t.Helper()
		if resp := step(code); resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d; want the page again", name, resp.StatusCode)
		}
	}

	// A wrong-case try does not use the code up.
	refused("wrong case", "recoveryaaa1")
	assertRedirect(t, step("RecoveryAAA1"), "/")
	refused("reused", "RecoveryAAA1")
	refused("not a code", "RecoveryZZZ9")
	// A 10-character token normalises into Keywell's format but is still found
	// as an imported code; exact case only.
	refused("10-char wrong case", "abcdefghjk")
	assertRedirect(t, step(" AbCdEfGhJk "), "/")
	refused("10-char reused", "AbCdEfGhJk")
	// A Keywell-format code and a 6-digit TOTP code still work.
	assertRedirect(t, step("mnpqr-stuvw"), "/")
	assertRedirect(t, step(validCode(t, env, secret)), "/")

	// Turning two-step sign in off accepts an imported code.
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	resp, _ := post(t, env, c, "/login/totp", url.Values{"code": {"RecoveryCCC3"}})
	assertRedirect(t, resp, "/")
	resp, _ = post(t, env, c, "/account/totp/disable", url.Values{"password": {testPW}, "code": {"RecoveryBBB2"}})
	assertRedirect(t, resp, "/account/totp")
	if getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("still enrolled")
	}
}

func TestDisableRefusedWhenGroupRequiresTOTP(t *testing.T) {
	env := testenv.New(t)
	env.CreateGroup(t, "Admin", true, true)
	u := env.CreateUser(t, "admin@example.org", testPW, "Admin")
	secret := env.EnrolTOTP(t, u)
	c := env.Client(t)
	signInWithCode(t, env, c, "admin@example.org", secret)

	resp, body := get(t, c, env.TS.URL+"/account/totp")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, groupRequires) ||
		strings.Contains(body, `action="/account/totp/disable"`) {
		t.Fatalf("status page: status %d\n%s", resp.StatusCode, body)
	}
	resp, body = post(t, env, c, "/account/totp/disable", url.Values{"password": {testPW}, "code": {validCode(t, env, secret)}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, groupRequires) {
		t.Fatalf("disable: status %d\n%s", resp.StatusCode, body)
	}
	if !getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("TOTP turned off despite the group requirement")
	}
	if events := auditEvents(t, env, audit.TOTPDisabled); len(events) != 0 {
		t.Fatalf("totp disable events %+v", events)
	}
}

// A session still waiting for its code reaches no account page, the TOTP
// pages included. (The member home arrives in a later task; GET / stands in
// for it.)
func TestIncompleteSessionCannotReachAccount(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)

	resp, _ := get(t, c, env.TS.URL+"/")
	assertRedirect(t, resp, "/login/totp?next=%2F")
	resp, _ = get(t, c, env.TS.URL+"/account/password")
	assertRedirect(t, resp, "/login/totp?next=%2Faccount%2Fpassword")
	resp, _ = post(t, env, c, "/account/password", url.Values{"current": {testPW}, "password": {newPW}, "confirm": {newPW}})
	assertRedirect(t, resp, "/login/totp?next=%2Faccount%2Fpassword")
	if getUser(t, env, u.ID).PasswordHash != u.PasswordHash {
		t.Fatal("an incomplete session changed the password")
	}
	resp, _ = get(t, c, env.TS.URL+"/account/totp")
	assertRedirect(t, resp, "/login/totp?next=%2Faccount%2Ftotp")
	resp, _ = get(t, c, env.TS.URL+"/account/totp/qr.png")
	assertRedirect(t, resp, "/login/totp?next=%2Faccount%2Ftotp")
	resp, _ = post(t, env, c, "/account/totp/begin", nil)
	assertRedirect(t, resp, "/login/totp?next=%2Faccount%2Ftotp")
	resp, _ = post(t, env, c, "/account/totp/disable", url.Values{"password": {testPW}, "code": {validCode(t, env, secret)}})
	assertRedirect(t, resp, "/login/totp?next=%2Faccount%2Ftotp")
	if !getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("an incomplete session turned TOTP off")
	}
}

// Wrong passwords when turning TOTP off use up the account's sign-in
// budget; once it is spent nothing is checked.
func TestDisableWrongPasswordThrottled(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	c := env.Client(t)
	signInWithCode(t, env, c, "alex@example.org", secret)

	for i := range 10 {
		resp, body := post(t, env, c, "/account/totp/disable", url.Values{"password": {"not the password"}, "code": {validCode(t, env, secret)}})
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, disableMismatch) {
			t.Fatalf("wrong password %d: status %d\n%s", i+1, resp.StatusCode, body)
		}
	}
	resp, body := post(t, env, c, "/account/totp/disable", url.Values{"password": {testPW}, "code": {validCode(t, env, secret)}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, throttled) {
		t.Fatalf("throttled disable: status %d\n%s", resp.StatusCode, body)
	}
	if !getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("TOTP turned off while throttled")
	}
	assertLoginRefused(t, env, "alex@example.org", testPW, throttled)
}
