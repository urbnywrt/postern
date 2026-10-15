package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	kib = 1 << 10
	mib = 1 << 20
)

// padded is `{}` followed by spaces, n bytes in all: a JSON message of a size of
// our choice that costs nothing to send once it is compressed.
func padded(n int) string { return "{}" + strings.Repeat(" ", n-2) }

// exhausted reports whether a response is the refusal of a message that is too
// large: a Connect error of code resource_exhausted.
func exhausted(t *testing.T, resp *http.Response, body string) bool {
	t.Helper()
	var e struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(body), &e) != nil {
		return false
	}
	return e.Code == "resource_exhausted" && resp.StatusCode == http.StatusTooManyRequests
}

// A message that is compressed is read through the decompressor, and the
// limit that http.MaxBytesReader puts on the body counts the compressed bytes.
// Only connect.WithReadMaxBytes counts what the message is when it is read.
func TestPublicProceduresReadAtMost64KiBOfMessage(t *testing.T) {
	p := newPanel(t)
	for _, proc := range []string{
		"/api/postern.panel.v1.HealthService/Check",
		"/api/postern.panel.v1.AuthService/GetSetupStatus",
		loginPath,
		"/api/postern.panel.v1.AuthService/Setup",
		"/api/postern.panel.v1.JoinService/Join",
	} {
		t.Run(proc, func(t *testing.T) {
			gz := map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"}

			// Compressed to a few bytes, and 64 KiB + 1 when it is read.
			body := gzipped(t, padded(64*kib+1))
			if len(body) > 1*kib {
				t.Fatalf("the test message is %d bytes compressed; it was meant to be tiny", len(body))
			}
			resp, text := p.do(http.MethodPost, proc, bytes.NewReader(body), gz)
			if !exhausted(t, resp, text) {
				t.Errorf("a message of 64 KiB + 1 byte, compressed: status %d, body %.100q; want resource_exhausted", resp.StatusCode, text)
			}

			// A message of exactly 64 KiB is within the limit: whatever the
			// procedure says about it, it is not that it is too large.
			resp, text = p.do(http.MethodPost, proc, bytes.NewReader(gzipped(t, padded(64*kib))), gz)
			if exhausted(t, resp, text) {
				t.Errorf("a message of exactly 64 KiB, compressed, was refused as too large: %.100q", text)
			}

			// The same without compression.
			resp, text = p.do(http.MethodPost, proc, strings.NewReader(padded(64*kib+1)), map[string]string{"Content-Type": "application/json"})
			if !exhausted(t, resp, text) {
				t.Errorf("a message of 64 KiB + 1 byte: status %d, body %.100q; want resource_exhausted", resp.StatusCode, text)
			}
		})
	}
}

// The other services take messages of up to 4 MiB, and nothing more, whatever
// the compression.
func TestAuthenticatedProceduresReadAtMost4MiBOfMessage(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	gz := map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"}

	for _, proc := range []string{
		createNodePath,
		listProxies,
		"/api/postern.panel.v1.ListenerService/ListListeners",
		"/api/postern.panel.v1.StatsService/ProxyLive",
		// The jobs of the installs.
		"/api/postern.panel.v1.DeployService/GetJob",
	} {
		t.Run(proc, func(t *testing.T) {
			// Larger than what the public procedures take: the limit is not theirs.
			resp, text := b.do(http.MethodPost, proc, bytes.NewReader(gzipped(t, padded(1*mib))), gz)
			if exhausted(t, resp, text) {
				t.Errorf("a message of 1 MiB was refused: %.100q", text)
			}
			resp, text = b.do(http.MethodPost, proc, bytes.NewReader(gzipped(t, padded(4*mib))), gz)
			if exhausted(t, resp, text) {
				t.Errorf("a message of exactly 4 MiB was refused: %.100q", text)
			}

			// One byte more is too much, compressed to a few bytes or not.
			big := gzipped(t, padded(4*mib+1))
			if len(big) > 16*kib {
				t.Fatalf("the test message is %d bytes compressed; it was meant to be tiny", len(big))
			}
			resp, text = b.do(http.MethodPost, proc, bytes.NewReader(big), gz)
			if !exhausted(t, resp, text) {
				t.Errorf("a message of 4 MiB + 1 byte, compressed: status %d, body %.100q; want resource_exhausted", resp.StatusCode, text)
			}
			resp, text = b.do(http.MethodPost, proc, strings.NewReader(padded(4*mib+1)), map[string]string{"Content-Type": "application/json"})
			if !exhausted(t, resp, text) {
				t.Errorf("a message of 4 MiB + 1 byte: status %d, body %.100q; want resource_exhausted", resp.StatusCode, text)
			}
		})
	}
}

// Every procedure of the API has a limit: the public ones and those of the
// service of sign-in, which has both kinds, 64 KiB, and the rest 4 MiB.
func TestEveryProcedureHasAMessageLimit(t *testing.T) {
	p := newPanel(t)
	b := p.signIn()
	gz := map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"}
	huge := gzipped(t, padded(9*mib)) // 9 MiB once it is read, above every limit; a few KiB compressed

	// Logout goes last: a procedure with no limit would run it, and end the session
	// that the others use.
	list := procedures(t)
	logoutLast(list)
	for _, proc := range list {
		resp, text := b.do(http.MethodPost, "/api"+proc, bytes.NewReader(huge), gz)
		if !exhausted(t, resp, text) {
			t.Errorf("%s accepted a message of 9 MiB: status %d, body %.100q", proc, resp.StatusCode, text)
		}
		// And without the session, as a stranger sends it.
		resp, text = p.do(http.MethodPost, "/api"+proc, bytes.NewReader(huge), gz)
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s answered a stranger who sent 9 MiB: %.100q", proc, text)
		}
	}
}
