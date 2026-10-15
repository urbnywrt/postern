package egressuri

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// seedURIs are the links of the table tests, the good ones and the bad ones.
func seedURIs() []string {
	var uris []string
	for _, cases := range [][]parseCase{vlessCases, vmessCases, trojanCases, ssCases} {
		for _, tc := range cases {
			uris = append(uris, tc.uri)
		}
	}
	for _, cases := range [][]errCase{vlessErrors, vmessErrors, trojanErrors, ssErrors, genericErrors} {
		for _, tc := range cases {
			uris = append(uris, tc.uri)
		}
	}
	return uris
}

// fixedError matches every message that Parse can return but one. It is written
// out by hand on purpose: a new message has to be added here, and so gets looked
// at for what it could repeat of a link. The one other message names the scheme
// of the link, see checkErrorMessage.
var fixedError = func() *regexp.Regexp {
	const (
		queryParams = `type|security|sni|peer|servername|fp|pbk|sid|spx|path|host|serviceName|mode|alpn|extra|allowInsecure|insecure`
		vmessFields = `add|port|id|aid|scy|net|tls|sni|fp|alpn|host|path|allowInsecure|insecure`
	)
	return regexp.MustCompile(`^(?:` +
		`invalid URI: (?:missing scheme|control character)` +
		`|unsupported scheme` +
		`|vless: (?:missing (?:id|address)|invalid (?:id|address|port|encryption|flow|` + queryParams + `)` +
		`|encryption not supported|unsupported (?:network|security)|missing pbk for reality)` +
		`|trojan: (?:missing (?:password|address)|invalid (?:password|address|port|` + queryParams + `)` +
		`|unsupported (?:network|security)|missing pbk for reality)` +
		`|ss: (?:plugins not supported|legacy form not supported|missing (?:userinfo|method|password|address|port)` +
		`|invalid (?:userinfo|address|port))` +
		`|vmess: (?:missing (?:payload|add|port|id)|invalid (?:base64|json|` + vmessFields + `)` +
		`|alterId not supported|unsupported (?:network|security))` +
		`)$`)
}()

// checkErrorMessage is the machine check that no error repeats what a link
// holds: msg, the error for input, must be one of the fixed messages, or
// unsupported scheme "<s>" with <s> the scheme of the input in lower case and at
// most 16 characters long.
func checkErrorMessage(t testing.TB, input, msg string) {
	t.Helper()
	switch {
	case fixedError.MatchString(msg):
	case strings.HasPrefix(msg, `unsupported scheme "`):
		scheme, _, _ := strings.Cut(strings.TrimSpace(input), "://")
		if len(scheme) > 16 || msg != `unsupported scheme "`+strings.ToLower(scheme)+`"` {
			t.Errorf("error %q for %q names more than the scheme", msg, input)
		}
	default:
		t.Errorf("error %q for %q is not one of the fixed messages", msg, input)
	}
}

// checkNothingSecretPrinted fails when what fmt prints for s holds a secret of s
// (the ones long enough to be told from the words of the output).
func checkNothingSecretPrinted(t testing.TB, s *Server) {
	t.Helper()
	printed := fmt.Sprintf("%v|%+v|%#v|%s|%v", s, *s, s, s, []*Server{s})
	for _, secret := range []string{s.ID, s.Password, s.PublicKey, s.ShortID, s.Extra, s.Path, s.ServiceName} {
		if len(secret) < 8 || strings.Contains(s.Name, secret) || strings.Contains(s.Protocol, secret) ||
			strings.Contains(s.Key(), secret) || strings.Contains("egressuri.Server{key=, protocol=, name=}", secret) {
			continue
		}
		if strings.Contains(printed, secret) {
			t.Errorf("fmt printed the secret %q of a %s server: %s", secret, s.Protocol, printed)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, uri := range seedURIs() {
		f.Add(uri)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		s, err := Parse(uri)
		if err != nil {
			if s != nil {
				t.Fatalf("Parse returned a Server together with the error %q", err)
			}
			checkErrorMessage(t, uri, err.Error())
			return
		}
		if s == nil {
			t.Fatal("Parse returned neither a Server nor an error")
		}
		checkServer(t, s)
		checkNothingSecretPrinted(t, s)
		if again, err := Parse(uri); err != nil {
			t.Errorf("Parse is not deterministic: the second time it failed with %q", err)
		} else if *again != *s {
			t.Errorf("Parse is not deterministic:%s", diffServer(*again, *s))
		}
	})
}

var (
	linePrefix     = regexp.MustCompile(`(?s)^line ([0-9]+): (.*)$`)
	droppedSummary = regexp.MustCompile(`^([0-9]+) more lines failed to parse$`)
)

// checkSubscriptionErrors checks the errors of ParseSubscription against the
// text that it read: each one is a fixed message of the line that it names, the
// very message that Parse gives for that line, and every link is either a server
// or an error.
func checkSubscriptionErrors(t testing.TB, body []byte, servers []*Server, errs []error) {
	t.Helper()
	lines := strings.Split(subscriptionText(body), "\n")
	links := 0
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			links++
		}
	}
	failed := 0
	for _, err := range errs {
		if err == nil {
			t.Fatal("a nil error")
		}
		msg := err.Error()
		if m := droppedSummary.FindStringSubmatch(msg); m != nil {
			n, _ := strconv.Atoi(m[1])
			failed += n
			continue
		}
		m := linePrefix.FindStringSubmatch(msg)
		if m == nil {
			t.Errorf("error without a line number: %q", msg)
			continue
		}
		n, _ := strconv.Atoi(m[1])
		if n < 1 || n > len(lines) {
			t.Errorf("error %q names a line outside the %d of the text", msg, len(lines))
			continue
		}
		line := strings.TrimSpace(lines[n-1])
		checkErrorMessage(t, line, m[2])
		if _, perr := Parse(line); perr == nil || perr.Error() != m[2] {
			t.Errorf("line %d: ParseSubscription says %q, Parse says %v", n, m[2], perr)
		}
		failed++
	}
	if len(servers)+failed != links {
		t.Errorf("%d servers and %d errors for %d links", len(servers), failed, links)
	}
}

func FuzzParseSubscription(f *testing.F) {
	plain := subscriptionPlain()
	f.Add([]byte(plain))
	f.Add([]byte("\r\n# comment\r\n" + plain + "\r\n\r\n"))
	f.Add([]byte(base64.StdEncoding.EncodeToString([]byte(plain))))
	f.Add([]byte(base64.RawURLEncoding.EncodeToString([]byte(plain))))
	f.Add([]byte(wrap(base64.StdEncoding.EncodeToString([]byte(plain)), 76)))
	f.Add([]byte("\xEF\xBB\xBF" + plain))
	f.Add([]byte("not a link\n" + plain + "\nhysteria2://x@203.0.113.1:443"))
	f.Add([]byte(base64.StdEncoding.EncodeToString([]byte(plain + "\nvless://" + testUUID + "@203.0.113.60:443#bad\xFFname"))))
	f.Add([]byte("<html>\n</html>"))
	f.Add([]byte(""))
	f.Add([]byte("====\n"))
	for _, uri := range seedURIs() {
		f.Add([]byte(uri))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		servers, errs := ParseSubscription(body)
		// A link takes at least 8 bytes of the text, and the text, decoded from
		// base64 or not, is never longer than the body.
		if len(servers) > len(body)/8 {
			t.Errorf("%d servers from %d bytes", len(servers), len(body))
		}
		for _, s := range servers {
			if s == nil {
				t.Fatal("a nil Server")
			}
			checkServer(t, s)
			checkNothingSecretPrinted(t, s)
		}
		if len(errs) > maxLineErrors+1 {
			t.Errorf("%d errors", len(errs))
		}
		checkSubscriptionErrors(t, body, servers, errs)
		// Reading the same body again gives the same result.
		servers2, errs2 := ParseSubscription(body)
		if !reflect.DeepEqual(servers, servers2) || len(errs) != len(errs2) {
			t.Errorf("ParseSubscription is not deterministic")
		}
	})
}
