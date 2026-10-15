package warp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ---- fixtures -----------------------------------------------------------------

// RFC 7748 §6.1: Alice's private key and the public key it gives. The test
// feeds the private key in as the "random" bytes of the key pair.
const (
	rfcPrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a" // gitleaks:allow (RFC 7748 test vector)
	rfcPublic  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" // gitleaks:allow (RFC 7748 test vector)
)

var (
	// The private key that Register keeps for the RFC input: clamped as
	// WireGuard clamps (first byte & 248, last byte & 127 | 64).
	wantPrivate = mustHex("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a") // gitleaks:allow (clamped RFC 7748 test vector)

	// What the fake API hands out. None of it is real.
	peerKey  = b64(bytes.Repeat([]byte{7}, 32))
	devToken = "fake-token-0123456789abcdef-not-real" // gitleaks:allow (fake)
	devID    = "t.11111111-2222-3333-4444-555555555555"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// fixedTime is the time Register is told it is.
var fixedTime = time.Date(2026, 10, 5, 12, 30, 45, 123456789, time.FixedZone("test", 3*3600))

// deterministic makes the key pair and the clock fixed for the test.
func deterministic(t *testing.T) {
	t.Helper()
	oldRand, oldNow := randRead, now
	randRead = func(b []byte) (int, error) { return copy(b, mustHex(rfcPrivate)), nil }
	now = func() time.Time { return fixedTime }
	t.Cleanup(func() { randRead, now = oldRand, oldNow })
}

// answer is a registration answer of the shape of wgcf v2.3.0's
// openapi.Register200Response.
func answer(withConfig bool) map[string]any {
	a := map[string]any{
		"id":          devID,
		"type":        "a",
		"model":       "PC",
		"key":         "sent key echoed back",
		"token":       devToken,
		"key_type":    "curve25519",
		"tunnel_type": "wireguard",
		"account": map[string]any{
			"id": "account-id", "account_type": "free", "warp_plus": false, "license": "fake-license-not-real",
		},
	}
	if withConfig {
		a["config"] = config()
	}
	return a
}

func config() map[string]any {
	return map[string]any{
		"client_id": b64([]byte{0xab, 0x01, 0xfe}),
		"interface": map[string]any{"addresses": map[string]any{"v4": "198.51.100.2", "v6": "2001:db8:110::2"}},
		"peers": []any{map[string]any{
			"public_key": peerKey,
			"endpoint": map[string]any{
				"host":  "warp.example.com:2408",
				"v4":    "192.0.2.1:0",
				"v6":    "[2001:db8::1]:0",
				"ports": []any{2408, 500, 1701, 4500},
			},
		}},
		"services": map[string]any{"http_proxy": "198.51.100.1:2480"},
	}
}

// fakeAPI is an httptest server of the registration API. It records the
// requests it gets.
type fakeAPI struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []recorded
	// handle answers one request; the default answers like the real API.
	handle func(w http.ResponseWriter, r *http.Request, body []byte)
}

type recorded struct {
	method, path string
	header       http.Header
	body         []byte
}

func newFakeAPI(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, body []byte)) *fakeAPI {
	t.Helper()
	f := &fakeAPI{handle: handle}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, recorded{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body})
		f.mu.Unlock()
		f.handle(w, r, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) recorded() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// realAPI answers like the API: the registration with or without a config, the
// device with one.
func realAPI(withConfig bool) func(w http.ResponseWriter, r *http.Request, body []byte) {
	return func(w http.ResponseWriter, r *http.Request, body []byte) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v0a5641/reg":
			writeJSON(w, http.StatusOK, answer(withConfig))
		case r.Method == http.MethodGet && r.URL.Path == "/v0a5641/reg/"+devID:
			writeJSON(w, http.StatusOK, answer(true))
		default:
			http.NotFound(w, r)
		}
	}
}

// noSecrets fails the test when s holds a credential of the account.
func noSecrets(t *testing.T, what, s string) {
	t.Helper()
	for name, secret := range map[string]string{
		"private key (base64)": b64(wantPrivate),
		"private key (hex)":    hex.EncodeToString(wantPrivate),
		"token":                devToken,
	} {
		if strings.Contains(s, secret) {
			t.Errorf("%s holds the %s: %q", what, name, s)
		}
	}
}

// ---- the request ----------------------------------------------------------------

func TestRegisterSendsWhatWgcfSends(t *testing.T) {
	deterministic(t)
	api := newFakeAPI(t, realAPI(true))

	acct, err := register(t.Context(), api.srv.Client(), api.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	reqs := api.recorded()
	if len(reqs) != 1 {
		t.Fatalf("Register made %d requests, want 1 (the answer had a config)", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodPost || r.path != "/v0a5641/reg" {
		t.Errorf("request = %s %s, want POST /v0a5641/reg", r.method, r.path)
	}
	for name, want := range map[string]string{
		"User-Agent":        "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
		"Cf-Client-Version": "a-6.38.9-5641",
		"Content-Type":      "application/json; charset=UTF-8",
		"Accept":            "", // wgcf's transport deletes it
		"Authorization":     "", // no credential yet
	} {
		if got := r.header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
	// The body byte for byte: the fields of wgcf's RegisterRequest in the order
	// its map gives them (sorted), and the newline of json.Encoder.
	wantBody := `{"fcm_token":"","install_id":"","key":"` + b64(mustHex(rfcPublic)) + `","key_type":"curve25519",` +
		`"locale":"en_US","model":"PC","os_version":"16.0.0","serial_number":"","tos":"2026-10-05T12:30:45.123456789+03:00",` +
		`"tunnel_type":"wireguard"}` + "\n"
	if string(r.body) != wantBody {
		t.Errorf("body =\n  %s\nwant\n  %s", r.body, wantBody)
	}

	// The account.
	want := &Account{
		PrivateKey:    b64(wantPrivate),
		PeerPublicKey: peerKey,
		Endpoint:      "warp.example.com:2408",
		AddrV4:        "198.51.100.2",
		AddrV6:        "2001:db8:110::2",
		Reserved:      [3]byte{0xab, 0x01, 0xfe},
		ID:            devID,
		Token:         devToken,
	}
	if *acct != *want {
		t.Errorf("account = %#v, want %#v", fields(acct), fields(want))
	}
}

// fields shows an account with its credentials, for test failures only.
func fields(a *Account) string {
	return fmt.Sprintf("{priv %s peer %s endpoint %s v4 %s v6 %s reserved %v id %s token %s}",
		a.PrivateKey, a.PeerPublicKey, a.Endpoint, a.AddrV4, a.AddrV6, a.Reserved, a.ID, a.Token)
}

// TestKeyPair checks the key handling on its own: the private key is clamped
// like a WireGuard key, and the public key that is sent is the X25519 public
// key of it.
func TestKeyPair(t *testing.T) {
	deterministic(t)
	priv, pub := newKeyPair()
	if !bytes.Equal(priv, wantPrivate) {
		t.Errorf("private key = %x, want the clamped %x", priv, wantPrivate)
	}
	if !bytes.Equal(pub, mustHex(rfcPublic)) {
		t.Errorf("public key = %x, want %s (RFC 7748 §6.1)", pub, rfcPublic)
	}
	// And against an independent implementation.
	x, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, x) {
		t.Errorf("public key = %x, x/crypto says %x", pub, x)
	}
}

func TestKeyPairIsRandom(t *testing.T) {
	a, _ := newKeyPair()
	b, _ := newKeyPair()
	if bytes.Equal(a, b) {
		t.Fatal("two key pairs are the same")
	}
	for _, k := range [][]byte{a, b} {
		if k[0]&7 != 0 || k[31]&0x80 != 0 || k[31]&0x40 == 0 {
			t.Errorf("private key %x is not clamped", k)
		}
	}
}

// ---- the answer -------------------------------------------------------------------

// A registration answer without a config: the device is fetched with the token,
// as wgcf's generate does (GET /{v}/reg/{id}).
func TestRegisterFetchesTheDeviceWhenTheAnswerHasNoConfig(t *testing.T) {
	deterministic(t)
	api := newFakeAPI(t, realAPI(false))

	acct, err := register(t.Context(), api.srv.Client(), api.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	reqs := api.recorded()
	if len(reqs) != 2 {
		t.Fatalf("Register made %d requests, want 2", len(reqs))
	}
	r := reqs[1]
	if r.method != http.MethodGet || r.path != "/v0a5641/reg/"+devID {
		t.Errorf("second request = %s %s, want GET /v0a5641/reg/%s", r.method, r.path, devID)
	}
	for name, want := range map[string]string{
		"Authorization":     "Bearer " + devToken,
		"User-Agent":        "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
		"Cf-Client-Version": "a-6.38.9-5641",
		"Content-Type":      "",
	} {
		if got := r.header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
	if len(r.body) != 0 {
		t.Errorf("the GET has a body: %q", r.body)
	}
	if acct.PeerPublicKey != peerKey || acct.Endpoint != "warp.example.com:2408" || acct.Token != devToken {
		t.Errorf("account = %s", fields(acct))
	}
}

// The endpoint, as wgcf v2.3.0's WireGuardEndpoint makes it: the host when there
// is one, else the IPv4 (or IPv6) address with the first port, else 2408.
func TestWireGuardEndpoint(t *testing.T) {
	tests := []struct {
		name string
		e    answerEndpoint
		want string
	}{
		{"host", answerEndpoint{Host: "warp.example.com:2408", V4: "192.0.2.1:0"}, "warp.example.com:2408"},
		{"v4 with port 0, first port", answerEndpoint{V4: "192.0.2.1:0", V6: "[2001:db8::1]:0", Ports: []int32{500, 2408}}, "192.0.2.1:500"},
		{"v4 without a port, no ports", answerEndpoint{V4: "192.0.2.1"}, "192.0.2.1:2408"},
		{"v6 only", answerEndpoint{V6: "[2001:db8::1]:0"}, "[2001:db8::1]:2408"},
		{"v6 only, bare", answerEndpoint{V6: "2001:db8::1", Ports: []int32{4500}}, "[2001:db8::1]:4500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := wireGuardEndpoint(tt.e)
			if err != nil || got != tt.want {
				t.Errorf("wireGuardEndpoint = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
	if _, err := wireGuardEndpoint(answerEndpoint{}); err == nil {
		t.Error("an empty endpoint gave no error")
	}
}

func TestReservedFromClientID(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want [3]byte
	}{
		{b64([]byte{1, 2, 3}), [3]byte{1, 2, 3}},
		{"", [3]byte{}},
		{"not base64!", [3]byte{}},
		{b64([]byte{1, 2, 3, 4}), [3]byte{}}, // not three bytes: like a plain WireGuard client, none
	} {
		if got := reservedOf(tt.in); got != tt.want {
			t.Errorf("reservedOf(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestRegisterRefusesBadAnswers(t *testing.T) {
	type mutate func(a map[string]any)
	cfg := func(f func(c map[string]any)) mutate {
		return func(a map[string]any) { c := config(); f(c); a["config"] = c }
	}
	peer := func(f func(p map[string]any)) mutate {
		return cfg(func(c map[string]any) { f(c["peers"].([]any)[0].(map[string]any)) })
	}
	addrs := func(f func(m map[string]any)) mutate {
		return cfg(func(c map[string]any) { f(c["interface"].(map[string]any)["addresses"].(map[string]any)) })
	}
	tests := []struct {
		name   string
		mutate mutate
		want   string // part of the error
	}{
		{"no id", func(a map[string]any) { delete(a, "id") }, "device id"},
		{"id with a slash", func(a map[string]any) { a["id"] = "a/b" }, "device id"},
		{"no token", func(a map[string]any) { delete(a, "token") }, "token"},
		{"no peers", cfg(func(c map[string]any) { c["peers"] = []any{} }), "peer"},
		{"peer key not base64", peer(func(p map[string]any) { p["public_key"] = "not base64 at all" }), "public key"},
		{"peer key too short", peer(func(p map[string]any) { p["public_key"] = b64(make([]byte, 31)) }), "public key"},
		{"no endpoint", peer(func(p map[string]any) { p["endpoint"] = map[string]any{"v4": "", "v6": ""} }), "endpoint"},
		{"endpoint without a port", peer(func(p map[string]any) { p["endpoint"] = map[string]any{"host": "warp.example.com"} }), "endpoint"},
		{"v4 address missing", addrs(func(m map[string]any) { m["v4"] = "" }), "IPv4"},
		{"v4 address is v6", addrs(func(m map[string]any) { m["v4"] = "2001:db8::2" }), "IPv4"},
		{"v6 address is v4", addrs(func(m map[string]any) { m["v6"] = "198.51.100.3" }), "IPv6"},
		{"v4 address with a prefix", addrs(func(m map[string]any) { m["v4"] = "198.51.100.2/32" }), "IPv4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deterministic(t)
			api := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
				a := answer(true)
				tt.mutate(a)
				writeJSON(w, http.StatusOK, a)
			})
			acct, err := register(t.Context(), api.srv.Client(), api.srv.URL, nil)
			if err == nil {
				t.Fatalf("Register = %s, want an error", fields(acct))
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not say %q", err, tt.want)
			}
			noSecrets(t, "the error", err.Error())
		})
	}
}

func TestRegisterHTTPErrors(t *testing.T) {
	tests := []struct {
		name   string
		handle func(w http.ResponseWriter, r *http.Request, body []byte)
		want   []string // parts of the error
	}{
		{
			name: "rate limited, with Cloudflare's error",
			handle: func(w http.ResponseWriter, r *http.Request, body []byte) {
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"result": nil, "success": false, "messages": []any{},
					"errors": []any{map[string]any{"code": 1015, "message": "You are being rate limited"}},
				})
			},
			want: []string{"HTTP 429", "1015", "You are being rate limited"},
		},
		{
			name: "forbidden, an HTML page",
			handle: func(w http.ResponseWriter, r *http.Request, body []byte) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "<html><body>blocked, ray id 0123456789abcdef</body></html>")
			},
			want: []string{"HTTP 403"},
		},
		{
			name: "not JSON",
			handle: func(w http.ResponseWriter, r *http.Request, body []byte) {
				_, _ = io.WriteString(w, `{"id":"`+devID+`","token":"`+devToken+`",`) // cut off
			},
			want: []string{"not valid JSON"},
		},
		{
			name: "a redirect is not followed",
			handle: func(w http.ResponseWriter, r *http.Request, body []byte) {
				http.Redirect(w, r, "https://elsewhere.example.com/reg", http.StatusFound)
			},
			want: []string{"HTTP 302"},
		},
		{
			name: "the device cannot be fetched",
			handle: func(w http.ResponseWriter, r *http.Request, body []byte) {
				if r.Method == http.MethodPost {
					writeJSON(w, http.StatusOK, answer(false))
					return
				}
				writeJSON(w, http.StatusInternalServerError, map[string]any{"errors": []any{map[string]any{"code": 1000, "message": "token " + devToken + " broke"}}})
			},
			want: []string{"HTTP 500"},
		},
		{
			name: "the device has no config either",
			handle: func(w http.ResponseWriter, r *http.Request, body []byte) {
				writeJSON(w, http.StatusOK, answer(false))
			},
			want: []string{"config"},
		},
		{
			name: "an answer that is too large",
			handle: func(w http.ResponseWriter, r *http.Request, body []byte) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"pad":"`+strings.Repeat("x", 2<<20)+`"}`)
			},
			want: []string{"too large"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deterministic(t)
			api := newFakeAPI(t, tt.handle)
			_, err := register(t.Context(), api.srv.Client(), api.srv.URL, nil)
			if err == nil {
				t.Fatal("Register succeeded")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not say %q", err, w)
				}
			}
			if strings.Contains(err.Error(), "<html>") || strings.Contains(err.Error(), "ray id") {
				t.Errorf("error %q repeats the body of the answer", err)
			}
			noSecrets(t, "the error", err.Error())
		})
	}
}

func TestRegisterTimesOut(t *testing.T) {
	deterministic(t)
	old := requestTimeout
	requestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { requestTimeout = old })
	release := make(chan struct{})
	api := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)

	start := time.Now()
	_, err := register(t.Context(), api.srv.Client(), api.srv.URL, nil)
	if err == nil {
		t.Fatal("Register succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v is not a deadline", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Register took %v with a 200 ms timeout", d)
	}
}

func TestRegisterHonoursTheContext(t *testing.T) {
	deterministic(t)
	api := newFakeAPI(t, realAPI(true))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := register(ctx, api.srv.Client(), api.srv.URL, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Register = %v, want context.Canceled", err)
	}
	if n := len(api.recorded()); n != 0 {
		t.Errorf("the API got %d requests", n)
	}
}

// ---- the client -------------------------------------------------------------------

// NewHTTPClient speaks TLS 1.2 only, with the cipher suites and curves wgcf
// v2.3.0 pins, HTTP/1.1, no proxy, no redirects, a 15 s timeout, and it works
// against a TLS server.
func TestNewHTTPClient(t *testing.T) {
	c := NewHTTPClient(nil)
	if c.Timeout != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Error("the transport takes a proxy from the environment")
	}
	if tr.ForceAttemptHTTP2 {
		t.Error("the transport attempts HTTP/2")
	}
	tc := tr.TLSClientConfig
	if tc == nil {
		t.Fatal("no TLS config")
	}
	if tc.MinVersion != tls.VersionTLS12 || tc.MaxVersion != tls.VersionTLS12 {
		t.Errorf("TLS versions %x..%x, want 1.2 only", tc.MinVersion, tc.MaxVersion)
	}
	if fmt.Sprint(tc.CipherSuites) != fmt.Sprint([]uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}) {
		t.Errorf("cipher suites %v", tc.CipherSuites)
	}
	if fmt.Sprint(tc.CurvePreferences) != fmt.Sprint([]tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}) {
		t.Errorf("curves %v", tc.CurvePreferences)
	}
	if fmt.Sprint(tc.NextProtos) != "[http/1.1]" {
		t.Errorf("ALPN %v", tc.NextProtos)
	}

	// The real handshake, against a server that trusts nothing in particular.
	var gotVersion uint16
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.TLS.Version
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tc.RootCAs = pool

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if gotVersion != tls.VersionTLS12 || resp.ProtoMajor != 1 {
		t.Errorf("negotiated TLS %x, HTTP/%d, want TLS 1.2 and HTTP/1", gotVersion, resp.ProtoMajor)
	}
	resp, err = c.Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("redirect: status %d, want the 302 itself", resp.StatusCode)
	}
}

// ---- the account --------------------------------------------------------------------

func validAccount() *Account {
	return &Account{
		PrivateKey:    b64(wantPrivate),
		PeerPublicKey: peerKey,
		Endpoint:      "warp.example.com:2408",
		AddrV4:        "198.51.100.2",
		AddrV6:        "2001:db8:110::2",
		Reserved:      [3]byte{1, 2, 3},
		ID:            devID,
		Token:         devToken,
	}
}

func TestAccountValidate(t *testing.T) {
	if err := validAccount().Validate(); err != nil {
		t.Fatalf("a valid account: %v", err)
	}
	ok := []func(a *Account){
		func(a *Account) { a.AddrV6 = "" },
		func(a *Account) { a.Endpoint = "192.0.2.1:2408" },
		func(a *Account) { a.Endpoint = "[2001:db8::1]:500" },
		func(a *Account) { a.Reserved = [3]byte{} },
	}
	for i, f := range ok {
		a := validAccount()
		f(a)
		if err := a.Validate(); err != nil {
			t.Errorf("variant %d: %v", i, err)
		}
	}
	bad := map[string]func(a *Account){
		"no private key":         func(a *Account) { a.PrivateKey = "" },
		"private key not base64": func(a *Account) { a.PrivateKey = "!!!" },
		"private key short":      func(a *Account) { a.PrivateKey = b64(make([]byte, 16)) },
		// Xray would take hex too, but this package writes base64 and reads it back.
		"private key hex":           func(a *Account) { a.PrivateKey = hex.EncodeToString(wantPrivate) },
		"no peer key":               func(a *Account) { a.PeerPublicKey = "" },
		"peer key long":             func(a *Account) { a.PeerPublicKey = b64(make([]byte, 33)) },
		"no endpoint":               func(a *Account) { a.Endpoint = "" },
		"endpoint without port":     func(a *Account) { a.Endpoint = "warp.example.com" },
		"endpoint port 0":           func(a *Account) { a.Endpoint = "warp.example.com:0" },
		"endpoint port too big":     func(a *Account) { a.Endpoint = "warp.example.com:65536" },
		"endpoint host empty":       func(a *Account) { a.Endpoint = ":2408" },
		"endpoint host not a name":  func(a *Account) { a.Endpoint = "warp example.com:2408" },
		"endpoint with a path":      func(a *Account) { a.Endpoint = "warp.example.com/x:2408" },
		"v4 missing":                func(a *Account) { a.AddrV4 = "" },
		"v4 is v6":                  func(a *Account) { a.AddrV4 = "2001:db8::2" },
		"v4 with prefix":            func(a *Account) { a.AddrV4 = "198.51.100.2/32" },
		"v6 is v4":                  func(a *Account) { a.AddrV6 = "198.51.100.2" },
		"v6 is v4 mapped":           func(a *Account) { a.AddrV6 = "::ffff:198.51.100.2" },
		"v6 with zone":              func(a *Account) { a.AddrV6 = "fe80::1%eth0" },
		"no id":                     func(a *Account) { a.ID = "" },
		"no token":                  func(a *Account) { a.Token = "" },
		"token with a line break":   func(a *Account) { a.Token = "abc\ndef" },
		"id with a control":         func(a *Account) { a.ID = "abc\x00" },
		"token absurdly long":       func(a *Account) { a.Token = strings.Repeat("x", 5000) },
		"endpoint absurdly long":    func(a *Account) { a.Endpoint = strings.Repeat("a", 300) + ".example.com:2408" },
		"endpoint with a control":   func(a *Account) { a.Endpoint = "warp.example.com\x00:2408" },
		"endpoint port with a sign": func(a *Account) { a.Endpoint = "warp.example.com:+2408" },
	}
	for name, f := range bad {
		t.Run(name, func(t *testing.T) {
			a := validAccount()
			f(a)
			err := a.Validate()
			if err == nil {
				t.Fatal("Validate accepted it")
			}
			noSecrets(t, "the error", err.Error())
		})
	}
	var nilAcct *Account
	if err := nilAcct.Validate(); err == nil {
		t.Error("a nil account is valid")
	}
}

// An Account never prints its credentials: not with any fmt verb, not through
// log/slog, as a value or as a pointer.
func TestAccountIsRedacted(t *testing.T) {
	a := validAccount()
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T %v"} {
		outs = append(outs, fmt.Sprintf(verb, *a), fmt.Sprintf(verb, a))
	}
	outs = append(outs, fmt.Sprint(a), fmt.Sprintln(*a), a.String())
	for _, h := range []func(io.Writer) slog.Handler{
		func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
		func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		var buf bytes.Buffer
		log := slog.New(h(&buf))
		log.Info("account", "acct", a, "value", *a, slog.Any("any", a))
		log.Info("grouped", slog.Group("g", "acct", a))
		outs = append(outs, buf.String())
	}
	for _, out := range outs {
		noSecrets(t, "printed account", out)
		if strings.Contains(out, a.PeerPublicKey) {
			t.Errorf("printed account holds the peer key: %q", out)
		}
	}
	if !strings.Contains(a.String(), "warp.example.com:2408") {
		t.Errorf("String() = %q, want the endpoint in it", a.String())
	}
	// A nil account prints, it does not panic.
	var nilAcct *Account
	if got := fmt.Sprintf("%v", nilAcct); got != "<nil>" {
		t.Errorf("nil account prints %q", got)
	}
}

// ---- the account file -----------------------------------------------------------------

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "warp-account.json")
	a := validAccount()
	if err := Save(path, a); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("the file is not JSON: %v", err)
	}
	for _, k := range []string{"private_key", "peer_public_key", "endpoint", "addr_v4", "addr_v6", "reserved", "id", "token"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the file has no %q", k)
		}
	}
	if fmt.Sprint(m["reserved"]) != "[1 2 3]" {
		t.Errorf("reserved is written as %v, want an array of numbers", m["reserved"])
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *a {
		t.Errorf("Load = %s, want %s", fields(got), fields(a))
	}

	// Saving again replaces the file, and leaves nothing else behind.
	b := validAccount()
	b.Endpoint = "192.0.2.9:2408"
	if err := Save(path, b); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err != nil || got.Endpoint != b.Endpoint {
		t.Errorf("after the second Save: %v, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want only the account file", len(entries))
	}
}

func TestSaveRefusesAnInvalidAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp-account.json")
	a := validAccount()
	a.PeerPublicKey = ""
	if err := Save(path, a); err == nil {
		t.Fatal("Save accepted an invalid account")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Save left a file: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good, _ := json.Marshal(validAccount())
	invalid := validAccount()
	invalid.AddrV4 = "nope"
	invalidJSON, _ := json.Marshal(invalid)

	if _, err := Load(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Load of a missing file = %v, want fs.ErrNotExist", err)
	}
	for name, path := range map[string]string{
		"not JSON":      write("garbage.json", "this is not json, but it holds "+devToken),
		"invalid":       write("invalid.json", string(invalidJSON)),
		"too large":     write("large.json", `{"pad":"`+strings.Repeat("x", 128<<10)+`"}`),
		"a directory":   filepath.Join(dir, "adir"),
		"truncated":     write("truncated.json", string(good[:len(good)/2])),
		"JSON, not one": write("array.json", "[]"),
	} {
		if name == "a directory" {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(name, func(t *testing.T) {
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load succeeded")
			}
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Load = %v, which says the file does not exist", err)
			}
			noSecrets(t, "the error", err.Error())
		})
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(write("target.json", string(good)), link); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(link); err == nil {
			t.Error("Load followed a symlink")
		}
	}
}

func TestLoadOrRegister(t *testing.T) {
	deterministic(t)
	api := newFakeAPI(t, realAPI(true))
	path := filepath.Join(t.TempDir(), "egr-x", "warp-account.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	a, created, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path)
	if err != nil {
		t.Fatal(err)
	}
	if !created || len(api.recorded()) != 1 {
		t.Fatalf("created = %v after %d requests, want a registration", created, len(api.recorded()))
	}
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("account file: %v, %v", info, err)
	}

	b, created, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path)
	if err != nil {
		t.Fatal(err)
	}
	if created || len(api.recorded()) != 1 {
		t.Errorf("created = %v after %d requests, want the file reused", created, len(api.recorded()))
	}
	if *a != *b {
		t.Errorf("the reused account differs: %s vs %s", fields(a), fields(b))
	}

	// A damaged file is an error, not a reason to register again.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path); err == nil {
		t.Error("a damaged account file was accepted")
	}
	if n := len(api.recorded()); n != 1 {
		t.Errorf("a damaged file made %d registrations", n-1)
	}
}

// A registration that fails writes no file.
func TestLoadOrRegisterFailure(t *testing.T) {
	deterministic(t)
	api := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	path := filepath.Join(t.TempDir(), "warp-account.json")
	if _, _, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path); err == nil {
		t.Fatal("no error")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a failed registration left a file: %v", err)
	}
}

// ---- the device's lifecycle -----------------------------------------------------------

func TestDelete(t *testing.T) {
	var gone bool
	api := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Method == http.MethodDelete && r.URL.Path == "/v0a5641/reg/"+devID && !gone {
			gone = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []any{map[string]any{"code": 1003, "message": "no device " + devToken}}})
	})
	a := validAccount()
	if err := deleteDevice(t.Context(), api.srv.Client(), api.srv.URL, a); err != nil {
		t.Fatal(err)
	}
	r := api.recorded()[0]
	for name, want := range map[string]string{
		"Authorization":     "Bearer " + devToken,
		"User-Agent":        "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
		"Cf-Client-Version": "a-6.38.9-5641",
		"Content-Type":      "",
	} {
		if got := r.header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
	if len(r.body) != 0 {
		t.Errorf("DELETE has a body: %q", r.body)
	}

	// Gone already: the API's answer, without the token it echoes, and
	// ErrDeviceGone.
	err := deleteDevice(t.Context(), api.srv.Client(), api.srv.URL, a)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "1003") {
		t.Errorf("second Delete = %v, want the 404", err)
	}
	if !errors.Is(err, ErrDeviceGone) {
		t.Errorf("second Delete = %v, want it to wrap ErrDeviceGone", err)
	}
	noSecrets(t, "the error", fmt.Sprint(err))

	// A registration that never completed can be deleted: id and token suffice.
	gone = false
	reg := &Account{PrivateKey: b64(wantPrivate), ID: devID, Token: devToken}
	if err := deleteDevice(t.Context(), api.srv.Client(), api.srv.URL, reg); err != nil {
		t.Errorf("Delete of a bare registration = %v", err)
	}

	before := len(api.recorded())
	for _, bad := range []*Account{nil, {ID: devID}, {Token: devToken}, {ID: "a/b", Token: devToken}} {
		if err := Delete(t.Context(), api.srv.Client(), bad); err == nil {
			t.Errorf("Delete(%v) = nil", bad)
		}
	}
	if len(api.recorded()) != before {
		t.Error("Delete of an unusable account made a request")
	}
}

// Only an answer that the device is not there (404, 410) says that it is gone
// already; any other failure leaves it registered as far as anybody knows.
func TestDeleteSaysWhenTheDeviceIsGone(t *testing.T) {
	for _, tt := range []struct {
		status int
		gone   bool
	}{
		{http.StatusNotFound, true},
		{http.StatusGone, true},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusServiceUnavailable, false},
	} {
		api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			writeJSON(w, tt.status, map[string]any{"errors": []any{map[string]any{"code": 1003, "message": "token " + devToken}}})
		})
		err := deleteDevice(t.Context(), api.srv.Client(), api.srv.URL, validAccount())
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", tt.status)) {
			t.Errorf("HTTP %d: Delete = %v, want the status", tt.status, err)
		}
		if got := errors.Is(err, ErrDeviceGone); got != tt.gone {
			t.Errorf("HTTP %d: errors.Is(err, ErrDeviceGone) = %v, want %v", tt.status, got, tt.gone)
		}
		noSecrets(t, "the error", fmt.Sprint(err))
	}

	// A failure without an answer is no news of the device either.
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {})
	api.srv.Close()
	if err := deleteDevice(t.Context(), api.srv.Client(), api.srv.URL, validAccount()); err == nil || errors.Is(err, ErrDeviceGone) {
		t.Errorf("Delete without an answer = %v, want an error that is not ErrDeviceGone", err)
	}
}

// A registration that ends before the device's config comes is kept, and the
// next LoadOrRegister completes it with the same device instead of registering
// another.
func TestLoadOrRegisterResumes(t *testing.T) {
	deterministic(t)
	getFails := true
	api := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		switch {
		case r.Method == http.MethodPost:
			writeJSON(w, http.StatusOK, answer(false)) // no config: a GET follows
		case getFails:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			writeJSON(w, http.StatusOK, answer(true))
		}
	})
	path := filepath.Join(t.TempDir(), "warp-account.json")
	count := func(method string) int {
		n := 0
		for _, r := range api.recorded() {
			if r.method == method {
				n++
			}
		}
		return n
	}

	if _, _, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path); err == nil {
		t.Fatal("the first call succeeded although the device could not be fetched")
	}
	kept, err := readAccountFile(path)
	if err != nil {
		t.Fatalf("no registration was kept: %v", err)
	}
	if !kept.registeredOnly() || kept.ID != devID || kept.Token != devToken || kept.PrivateKey != b64(wantPrivate) {
		t.Fatalf("kept %s, want the key, id and token only", fields(kept))
	}
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Errorf("the registration file: %v, %v", info, err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not completed") {
		t.Errorf("Load of a registration = %v, want an error that says it is not completed", err)
	} else {
		noSecrets(t, "the error", err.Error())
	}

	getFails = false
	a, created, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path)
	if err != nil {
		t.Fatal(err)
	}
	if !created || count(http.MethodPost) != 1 {
		t.Errorf("created = %v after %d registrations, want the kept one completed", created, count(http.MethodPost))
	}
	if a.ID != devID || a.PrivateKey != b64(wantPrivate) || a.PeerPublicKey != peerKey {
		t.Errorf("account %s", fields(a))
	}
	if b, err := Load(path); err != nil || *b != *a {
		t.Errorf("Load after completion = %v, %v", b, err)
	}

	before := len(api.recorded())
	if _, created, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path); err != nil || created {
		t.Errorf("third call: created %v, %v", created, err)
	}
	if len(api.recorded()) != before {
		t.Error("a complete account file made a request")
	}
}

// When the registration cannot be kept, it stops before the device's config is
// fetched.
// When the registration could not be kept, no device is registered.
func TestLoadOrRegisterChecksTheDirectoryFirst(t *testing.T) {
	deterministic(t)
	api := newFakeAPI(t, realAPI(false))
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(dir, "missing-dir", "warp-account.json"),
		filepath.Join(file, "warp-account.json"), // the "directory" is a file
	} {
		if _, _, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path); err == nil {
			t.Errorf("%s: no error", path)
		}
	}
	if n := len(api.recorded()); n != 0 {
		t.Errorf("%d requests: a device was registered although its registration could not be kept", n)
	}
	// The probe leaves nothing behind.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want only a-file", len(entries))
	}
}

// When keeping the registration fails all the same (the directory goes away
// while the device is registered), the device is deleted again: nobody would
// know of it otherwise.
func TestLoadOrRegisterDeletesADeviceItCannotKeep(t *testing.T) {
	deterministic(t)
	dir := filepath.Join(t.TempDir(), "egr-x")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		switch r.Method {
		case http.MethodPost:
			if err := os.RemoveAll(dir); err != nil {
				t.Error(err)
			}
			writeJSON(w, http.StatusOK, answer(false))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeJSON(w, http.StatusOK, answer(true))
		}
	})
	_, _, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, filepath.Join(dir, "warp-account.json"))
	if err == nil || !strings.Contains(err.Error(), "deleted again") {
		t.Fatalf("loadOrRegister = %v, want an error that says the device was deleted again", err)
	}
	noSecrets(t, "the error", err.Error())
	var methods []string
	for _, r := range api.recorded() {
		methods = append(methods, r.method+" "+r.path)
		if r.method == http.MethodDelete && r.header.Get("Authorization") != "Bearer "+devToken {
			t.Error("the DELETE does not carry the device's token")
		}
	}
	if want := []string{"POST /v0a5641/reg", "DELETE /v0a5641/reg/" + devID}; !slices.Equal(methods, want) {
		t.Errorf("requests %q, want %q", methods, want)
	}
}

// LoadRegistration gives Delete what it needs, from a complete account or from
// a registration that was kept half-way.
func TestLoadRegistration(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "full.json")
	if err := Save(full, validAccount()); err != nil {
		t.Fatal(err)
	}
	half := filepath.Join(dir, "half.json")
	if err := saveRegistration(half, &Account{PrivateKey: b64(wantPrivate), ID: devID, Token: devToken}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{full, half} {
		a, err := LoadRegistration(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if a.ID != devID || a.Token != devToken {
			t.Errorf("%s: %s", path, fields(a))
		}
	}
	damaged := filepath.Join(dir, "damaged.json")
	if err := os.WriteFile(damaged, []byte(`{"id":"`+devID+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistration(damaged); err == nil {
		t.Error("LoadRegistration took an id without a token")
	}
	if _, err := LoadRegistration(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadRegistration of a missing file = %v, want fs.ErrNotExist", err)
	}
}

func TestLoadOrRegisterRefusesAHalfAccount(t *testing.T) {
	deterministic(t)
	api := newFakeAPI(t, realAPI(true))
	path := filepath.Join(t.TempDir(), "warp-account.json")
	half := &Account{PrivateKey: b64(wantPrivate), ID: devID, Token: devToken, PeerPublicKey: peerKey} // no endpoint
	data, err := json.Marshal(half)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrRegister(t.Context(), api.srv.Client(), api.srv.URL, path); err == nil {
		t.Fatal("a half account was taken")
	} else {
		noSecrets(t, "the error", err.Error())
	}
	if n := len(api.recorded()); n != 0 {
		t.Errorf("%d requests for a damaged file", n)
	}
}

// Temporary files that a cut-short Save left (they may hold the private key)
// are removed on load; nothing else is touched.
func TestStaleTemporaryFilesAreRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "warp-account.json")
	if err := Save(path, validAccount()); err != nil {
		t.Fatal(err)
	}
	keep := []string{"warp-account.json", ".other.json.tmp-1", "warp-account.json.bak", ".warp-account.json"}
	stale := []string{".warp-account.json.tmp-123", ".warp-account.json.tmp-"}
	for _, name := range append(slices.Clone(keep[1:]), stale...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s is still there: %v", name, err)
		}
	}
	for _, name := range keep {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
}

// A 404 that is not the API's JSON error (a proxy, a captive portal, a changed
// path) does not say that the device is gone: it is a failure to retry.
func TestDeleteNonAPI404IsNotGone(t *testing.T) {
	for name, body := range map[string]string{
		"html":                "<html><body>404 Not Found</body></html>",
		"empty":               "",
		"json without errors": `{"success":false}`,
	} {
		for _, status := range []int{http.StatusNotFound, http.StatusGone} {
			api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			})
			err := deleteDevice(t.Context(), api.srv.Client(), api.srv.URL, validAccount())
			if err == nil || errors.Is(err, ErrDeviceGone) {
				t.Errorf("%s HTTP %d: Delete = %v, want a failure that is not ErrDeviceGone", name, status, err)
			}
		}
	}
}
