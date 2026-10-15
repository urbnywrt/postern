// Package warp registers Cloudflare WARP devices. It makes a WireGuard key pair
// on the node, asks Cloudflare's client API for a free account the way the WARP
// app does, and keeps the account in a file. The WARP egress kind runs on Xray's
// WireGuard outbound with such an account (Ruling S2-4); warp-plus is not
// involved.
//
// The API is not documented. What this package sends and reads follows the
// current release of wgcf, v2.3.0 of 2026-09-18 (github.com/ViRb3/wgcf,
// cloudflare/api.go and openapi/): the API version v0a5641, the headers of the
// Android app 6.38.9 (User-Agent and CF-Client-Version), the fields of the
// registration (openapi/model_register_request.go), the answer
// (model_register_200_response.go: id, token, config) and the choice of the
// WireGuard endpoint (cloudflare.WireGuardEndpoint). wgcf also pins the TLS
// fingerprint of the app with uTLS; NewHTTPClient comes as close as crypto/tls
// allows (the same version, cipher suites, curves and ALPN). The unit tests are
// the contract of this package with the API.
package warp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Account is a registered WARP device: what Xray's WireGuard outbound needs to
// connect, and what identifies the device to the API.
//
// PrivateKey and Token are credentials. An Account never prints them: fmt and
// log/slog show a redacted form. json.Marshal writes them, for the account file
// (see Save), and nothing else should marshal an Account.
type Account struct {
	// PrivateKey is the device's WireGuard private key, made on the node and
	// never sent anywhere: 32 bytes, standard base64.
	PrivateKey string `json:"private_key"`
	// PeerPublicKey is the WireGuard public key of the endpoint, standard base64.
	PeerPublicKey string `json:"peer_public_key"`
	// Endpoint is the WireGuard endpoint, host:port. The host is a name or an IP
	// literal (an IPv6 one in brackets).
	Endpoint string `json:"endpoint"`
	// AddrV4 and AddrV6 are the addresses of the device inside the tunnel,
	// without a prefix length. AddrV6 may be empty.
	AddrV4 string `json:"addr_v4"`
	AddrV6 string `json:"addr_v6"`
	// Reserved are the three "reserved" bytes of the WireGuard header that WARP
	// reads: the device's client_id. All zero when the API gives none, as for a
	// plain WireGuard client.
	Reserved [3]byte `json:"reserved"`
	// ID and Token identify the device to the API; the token is a bearer
	// credential for it.
	ID    string `json:"id"`
	Token string `json:"token"`
}

const (
	apiBase = "https://api.cloudflareclient.com"
	// apiVersion, userAgent and clientVersion are wgcf v2.3.0's ApiVersion and
	// DefaultHeaders (cloudflare/api.go).
	apiVersion    = "v0a5641"
	userAgent     = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
	clientVersion = "a-6.38.9-5641"

	// defaultEndpointPort is the port wgcf's WireGuardEndpoint takes when the
	// answer names none.
	defaultEndpointPort = 2408

	// maxAnswerBytes bounds what is read of an answer. A real one is a few KiB.
	maxAnswerBytes = 1 << 20
	// maxAccountFile bounds what Load reads.
	maxAccountFile = 64 << 10

	keySize = 32
)

var (
	// requestTimeout bounds every request of Register. A variable for the tests.
	requestTimeout = 15 * time.Second
	// randRead and now are crypto/rand.Read and time.Now; the tests fix them.
	randRead = rand.Read
	now      = time.Now
)

// ---- registration ---------------------------------------------------------------

// Register makes a WireGuard key pair, registers a new device with its public
// key, and returns the account (POST /v0a5641/reg; when the answer carries no
// configuration, GET /v0a5641/reg/{id} with the device's token, as wgcf does).
//
// hc makes the requests; nil means NewHTTPClient(nil). Each request has 15 s,
// whatever hc's own timeout. No error holds the private key, the token or the
// body of an answer: an error answer is reported by its HTTP status and the code
// and message of Cloudflare's first error.
//
// Every call registers a new device: Register is for when there is no account
// yet. LoadOrRegister keeps the account in a file, and keeps what it has of a
// device that is registered but not complete yet, so that a later call goes on
// with that device instead of registering another.
func Register(ctx context.Context, hc *http.Client) (*Account, error) {
	return register(ctx, hc, apiBase, nil)
}

// register registers a device. persist, when not nil, is given the account as
// soon as the device exists (its key, id and token, before its config is
// fetched); an error of persist ends the registration.
func register(ctx context.Context, hc *http.Client, base string, persist func(*Account) error) (*Account, error) {
	if hc == nil {
		hc = NewHTTPClient(nil)
	}
	priv, pub := newKeyPair()

	var body bytes.Buffer
	// Encode, like wgcf's API client: the fields in the order its map gives them,
	// and a trailing newline.
	if err := json.NewEncoder(&body).Encode(registration{
		Key:        base64.StdEncoding.EncodeToString(pub),
		KeyType:    "curve25519",
		Locale:     "en_US",
		Model:      "PC",
		OSVersion:  "16.0.0",
		Tos:        now().Format(time.RFC3339Nano),
		TunnelType: "wireguard",
	}); err != nil {
		return nil, fmt.Errorf("warp: %w", err)
	}
	var dev device
	if err := call(ctx, hc, http.MethodPost, base+"/"+apiVersion+"/reg", "", body.Bytes(), &dev); err != nil {
		return nil, fmt.Errorf("warp: registration: %w", err)
	}
	if !validDeviceID(dev.ID) {
		return nil, errors.New("warp: registration: the answer has no usable device id")
	}
	if !validToken(dev.Token) {
		return nil, errors.New("warp: registration: the answer has no usable token")
	}
	reg := &Account{PrivateKey: base64.StdEncoding.EncodeToString(priv), ID: dev.ID, Token: dev.Token}
	if persist != nil {
		if err := persist(reg); err != nil {
			// A device nobody knows of any more would be left at Cloudflare:
			// delete it again, also when ctx is done.
			if derr := deleteDevice(context.WithoutCancel(ctx), hc, base, reg); derr != nil {
				return nil, fmt.Errorf("%w (and the device it registered could not be deleted again: %w)", err, derr)
			}
			return nil, fmt.Errorf("%w (the device it registered was deleted again)", err)
		}
	}
	return complete(ctx, hc, base, reg, dev.Config)
}

// complete returns the account of a registered device: reg (its key, id and
// token) with the config cfg, or, when cfg has no peer, with the config of the
// device as the API has it now (GET /v0a5641/reg/{id} with its token, as wgcf's
// generate does).
func complete(ctx context.Context, hc *http.Client, base string, reg *Account, cfg *answerConfig) (*Account, error) {
	if hc == nil {
		hc = NewHTTPClient(nil)
	}
	if cfg == nil || len(cfg.Peers) == 0 {
		var full device
		if err := call(ctx, hc, http.MethodGet, deviceURL(base, reg.ID), reg.Token, nil, &full); err != nil {
			return nil, fmt.Errorf("warp: fetching the registered device: %w", err)
		}
		if full.Config == nil {
			return nil, errors.New("warp: the registered device has no config")
		}
		cfg = full.Config
	}
	priv, err := base64.StdEncoding.DecodeString(reg.PrivateKey)
	if err != nil {
		return nil, errors.New("warp: the private key of the registration is not base64")
	}
	acct, err := accountOf(priv, reg.ID, reg.Token, cfg)
	if err != nil {
		return nil, err
	}
	if err := acct.Validate(); err != nil {
		return nil, err
	}
	return acct, nil
}

// deviceURL is the URL of a device of the API: /v0a5641/reg/{id}.
func deviceURL(base, id string) string {
	return base + "/" + apiVersion + "/reg/" + url.PathEscape(id)
}

// ErrDeviceGone is wrapped by the error of Delete when Cloudflare answers that
// the device is not there (HTTP 404 or 410 with the JSON error body of the API;
// a 404 of a proxy or a captive portal, in HTML or empty, is a failure): it was deleted already, and its
// account is of no use any more.
var ErrDeviceGone = errors.New("warp: the device is gone already")

// Delete deletes the account's device at Cloudflare (DELETE /v0a5641/reg/{id}
// with its token, wgcf's DeleteSourceDevice): what to do when the egress it
// served is removed. The account needs its id and its token only, so the device
// of a registration that never completed can be deleted too. hc makes the
// request, nil means NewHTTPClient(nil); the request has 15 s. An error never
// holds the token or the private key; a device that is gone already gives the
// error the API answers with, which wraps ErrDeviceGone. Any other error says
// nothing of the device: it may still be registered.
func Delete(ctx context.Context, hc *http.Client, a *Account) error {
	if a == nil || !validDeviceID(a.ID) || !validToken(a.Token) {
		return errors.New("warp: delete: the account has no usable device id or token")
	}
	return deleteDevice(ctx, hc, apiBase, a)
}

func deleteDevice(ctx context.Context, hc *http.Client, base string, a *Account) error {
	if hc == nil {
		hc = NewHTTPClient(nil)
	}
	if err := call(ctx, hc, http.MethodDelete, deviceURL(base, a.ID), a.Token, nil, nil); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.json && (ae.status == http.StatusNotFound || ae.status == http.StatusGone) {
			return fmt.Errorf("%w (%w)", ErrDeviceGone, err)
		}
		return fmt.Errorf("warp: deleting the device: %w", err)
	}
	return nil
}

// registration is wgcf v2.3.0's openapi.RegisterRequest as its registration
// fills it (cloudflare/api.go: registrationRequest), the fields in sorted order.
type registration struct {
	FcmToken     string `json:"fcm_token"`
	InstallID    string `json:"install_id"`
	Key          string `json:"key"`
	KeyType      string `json:"key_type"`
	Locale       string `json:"locale"`
	Model        string `json:"model"`
	OSVersion    string `json:"os_version"`
	SerialNumber string `json:"serial_number"`
	Tos          string `json:"tos"`
	TunnelType   string `json:"tunnel_type"`
}

// device is the part of a registration answer, or of a device, that is read.
type device struct {
	ID     string        `json:"id"`
	Token  string        `json:"token"`
	Config *answerConfig `json:"config"`
}

type answerConfig struct {
	ClientID  string `json:"client_id"`
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Peers []struct {
		PublicKey string         `json:"public_key"`
		Endpoint  answerEndpoint `json:"endpoint"`
	} `json:"peers"`
}

// answerEndpoint is wgcf's openapi.Endpoint.
type answerEndpoint struct {
	Host  string  `json:"host"`
	V4    string  `json:"v4"`
	V6    string  `json:"v6"`
	Ports []int32 `json:"ports"`
}

// accountOf makes the account of a registered device.
func accountOf(priv []byte, id, token string, cfg *answerConfig) (*Account, error) {
	if len(cfg.Peers) == 0 {
		return nil, errors.New("warp: the device config has no peer")
	}
	peer := cfg.Peers[0]
	if k, err := base64.StdEncoding.DecodeString(peer.PublicKey); err != nil || len(k) != keySize {
		return nil, errors.New("warp: the device config has no usable peer public key")
	}
	endpoint, err := wireGuardEndpoint(peer.Endpoint)
	if err != nil {
		return nil, err
	}
	return &Account{
		PrivateKey:    base64.StdEncoding.EncodeToString(priv),
		PeerPublicKey: peer.PublicKey,
		Endpoint:      endpoint,
		AddrV4:        cfg.Interface.Addresses.V4,
		AddrV6:        cfg.Interface.Addresses.V6,
		Reserved:      reservedOf(cfg.ClientID),
		ID:            id,
		Token:         token,
	}, nil
}

// wireGuardEndpoint is wgcf v2.3.0's cloudflare.WireGuardEndpoint: the host of
// the answer when it has one, else its IPv4 address (else its IPv6 address)
// with the first of its ports, or 2408.
func wireGuardEndpoint(e answerEndpoint) (string, error) {
	if e.Host != "" {
		return e.Host, nil
	}
	host := e.V4
	if host == "" {
		host = e.V6
	}
	if host == "" {
		return "", errors.New("warp: the device config has no endpoint")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	port := int32(defaultEndpointPort)
	if len(e.Ports) != 0 {
		port = e.Ports[0]
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// reservedOf decodes the client_id of a device config: three bytes in base64.
// Anything else gives none (all zero), which plain WireGuard clients send too.
func reservedOf(clientID string) [3]byte {
	var r [3]byte
	if b, err := base64.StdEncoding.DecodeString(clientID); err == nil && len(b) == len(r) {
		copy(r[:], b)
	}
	return r
}

// newKeyPair makes a WireGuard key pair: 32 random bytes clamped as wg genkey
// and wgcf clamp them, and their X25519 public key.
func newKeyPair() (priv, pub []byte) {
	priv = make([]byte, keySize)
	if _, err := randRead(priv); err != nil {
		panic("warp: no randomness: " + err.Error()) // crypto/rand.Read does not fail
	}
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		panic("warp: " + err.Error()) // only for a key that is not 32 bytes
	}
	return priv, k.PublicKey().Bytes()
}

// call makes one request of the API and decodes a 2xx answer into out (when out
// is not nil). token, when not empty, is sent as a bearer token.
func call(ctx context.Context, hc *http.Client, method, u, token string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	// The headers of wgcf's client and of its cloudflareResponseTransport: the
	// app's User-Agent and client version, no Accept, a keep-alive connection,
	// and a charset on the JSON of a POST.
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("Connection", "Keep-Alive")
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// The API never redirects. Whatever the client does otherwise, a redirect
	// is not followed: it is an error answer (and the token stays here).
	noRedirects := *hc
	noRedirects.CheckRedirect = refuseRedirect
	resp, err := noRedirects.Do(req)
	if err != nil {
		// A *url.Error names the URL, which holds no credential (the device id
		// of the GET is not one).
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return fmt.Errorf("reading the answer: %w", err)
	}
	if len(data) > maxAnswerBytes {
		return fmt.Errorf("the answer is too large (over %d bytes)", maxAnswerBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(resp.StatusCode, data, token)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("the answer (HTTP %d) is not valid JSON of the expected shape", resp.StatusCode)
	}
	return nil
}

// apiError is an answer of the API that is not 2xx: its status, and what
// statusError says of it.
type apiError struct {
	status int
	msg    string
	// json is true when the body was Cloudflare's JSON error ({"errors":[...]}
	// with at least one entry): only then does a 404 come from the API.
	json bool
}

func (e *apiError) Error() string { return e.msg }

// statusError describes an answer that is not 2xx: its status, and the code and
// message of the first error of Cloudflare's JSON error body when it has one.
// Nothing else of the body is repeated, and the token is taken out of the
// message in case the API echoes it.
func statusError(status int, body []byte, token string) error {
	msg := fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
	var cf struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	isJSON := json.Unmarshal(body, &cf) == nil && len(cf.Errors) > 0
	if isJSON {
		e := cf.Errors[0]
		text := e.Message
		if token != "" {
			text = strings.ReplaceAll(text, token, "[token]")
		}
		msg += fmt.Sprintf(" (Cloudflare error %d: %.120q)", e.Code, text)
	}
	return &apiError{status: status, msg: msg, json: isJSON}
}

// NewHTTPClient returns the client Register uses when it is given none: a 15 s
// timeout, no proxy from the environment, no redirects, HTTP/1.1 only, and TLS
// 1.2 only with the cipher suites (ECDHE ECDSA/RSA with AES-256-GCM-SHA384), the
// curves (X25519, P-256, P-384) and the ALPN of the TLS fingerprint that wgcf
// v2.3.0 pins for the API (cloudflare/api.go: warpClientHelloSpec). The order of
// the TLS extensions is crypto/tls's own.
//
// dial, when not nil, makes the connections: the agent passes its own, which
// resolves names through the node's resolver.
func NewHTTPClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: dial,
			TLSClientConfig: &tls.Config{ //nolint:gosec // TLS 1.2 only: the fingerprint of the WARP client, see the doc comment
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
				NextProtos:       []string{"http/1.1"},
			},
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: refuseRedirect,
	}
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ---- the account ------------------------------------------------------------------

// Validate reports whether the account can be used: both keys are 32 bytes of
// standard base64, the endpoint is host:port with a host name or an IP literal
// and a port from 1 to 65535, AddrV4 is an IPv4 address and AddrV6 empty or an
// IPv6 address, and the id and the token are there. The error names the field
// and never repeats a credential.
func (a *Account) Validate() error {
	if a == nil {
		return errors.New("warp: no account")
	}
	if !validKey(a.PrivateKey) {
		return errors.New("warp: account: the private key is not 32 bytes of base64")
	}
	if !validKey(a.PeerPublicKey) {
		return errors.New("warp: account: the peer public key is not 32 bytes of base64")
	}
	if err := checkEndpoint(a.Endpoint); err != nil {
		return err
	}
	if v4, err := netip.ParseAddr(a.AddrV4); err != nil || !v4.Is4() {
		return errors.New("warp: account: the tunnel address is not an IPv4 address")
	}
	if a.AddrV6 != "" {
		if v6, err := netip.ParseAddr(a.AddrV6); err != nil || !v6.Is6() || v6.Is4In6() || v6.Zone() != "" {
			return errors.New("warp: account: the tunnel IPv6 address is not an IPv6 address")
		}
	}
	if !validDeviceID(a.ID) {
		return errors.New("warp: account: no usable device id")
	}
	if !validToken(a.Token) {
		return errors.New("warp: account: no usable token")
	}
	return nil
}

func validKey(s string) bool {
	k, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(k) == keySize
}

// validDeviceID accepts what can be the last element of the device's URL.
func validDeviceID(id string) bool {
	return id != "" && len(id) <= 256 && printable(id) && !strings.ContainsAny(id, "/?#% ")
}

// validToken accepts what can be a bearer token: printable, at most 1 KiB.
func validToken(token string) bool {
	return token != "" && len(token) <= 1024 && printable(token)
}

// registeredOnly reports whether the account is a registration that has not
// been completed: a key, an id and a token, and nothing of the device's config.
func (a *Account) registeredOnly() bool {
	return a != nil && validKey(a.PrivateKey) && validDeviceID(a.ID) && validToken(a.Token) &&
		a.PeerPublicKey == "" && a.Endpoint == "" && a.AddrV4 == "" && a.AddrV6 == "" && a.Reserved == [3]byte{}
}

// printable reports whether s is UTF-8 without control characters.
func printable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == '�' })
}

// checkEndpoint checks a host:port endpoint.
func checkEndpoint(ep string) error {
	host, portText, err := net.SplitHostPort(ep)
	if err != nil {
		return errors.New("warp: account: the endpoint is not host:port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || portText[0] == '+' {
		return errors.New("warp: account: the endpoint port is not a port")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if !validHostName(host) {
		return errors.New("warp: account: the endpoint host is neither a name nor an IP address")
	}
	return nil
}

// validHostName accepts a DNS name: letters, digits, '-', '_' and dots, at most
// 253 characters.
func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// String is the redacted form of the account: its endpoint, and nothing that
// identifies or authenticates the device.
func (a Account) String() string {
	return "warp.Account{endpoint: " + a.Endpoint + ", credentials redacted}"
}

// GoString is String, for %#v.
func (a Account) GoString() string { return a.String() }

// Format prints String for every verb, so that no verb can reach the fields.
func (a Account) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue is the redacted form of the account for log/slog.
func (a Account) LogValue() slog.Value {
	return slog.GroupValue(slog.String("endpoint", a.Endpoint), slog.Bool("credentials_redacted", true))
}

// ---- the account file ---------------------------------------------------------------

// The functions of the account file must not run at the same time for one path:
// the agent runs them for an egress from one goroutine.

// Load reads the account file at path and validates it. A missing file is an
// error that matches fs.ErrNotExist; a file that is not a regular file (a
// symlink, say) is refused, and so is a registration that was never completed
// (LoadOrRegister completes it). No error repeats the content of the file.
// Temporary files that a Save cut short left next to it are removed.
func Load(path string) (*Account, error) {
	removeStaleTemps(path)
	a, err := readAccountFile(path)
	if err != nil {
		return nil, err
	}
	if a.registeredOnly() {
		return nil, errors.New("warp: account file " + path + " holds a registration that was not completed")
	}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("account file %s: %w", path, err)
	}
	return a, nil
}

// LoadRegistration reads the account file at path for Delete: a complete
// account, or the registration that a LoadOrRegister which stopped half-way
// kept (the device's key, id and token). So the device can be deleted when its
// egress is removed, without completing the registration first. A missing file
// is an error that matches fs.ErrNotExist. Temporary files that a Save cut
// short left next to it are removed.
func LoadRegistration(path string) (*Account, error) {
	removeStaleTemps(path)
	a, err := readAccountFile(path)
	if err != nil {
		return nil, err
	}
	if a.Validate() != nil && !a.registeredOnly() {
		return nil, errors.New("warp: account file " + path + " is neither an account nor a registration")
	}
	return a, nil
}

// readAccountFile reads the account file at path without validating it.
func readAccountFile(path string) (*Account, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("warp: account file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("warp: account file " + path + " is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("warp: account file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAccountFile+1))
	if err != nil {
		return nil, fmt.Errorf("warp: account file: %w", err)
	}
	if len(data) > maxAccountFile {
		return nil, errors.New("warp: account file " + path + " is too large")
	}
	var a Account
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, errors.New("warp: account file " + path + " is not an account (not valid JSON of the expected shape)")
	}
	return &a, nil
}

// Save writes the account to the file at path, mode 0600: to a new file next to
// it first, then renamed over it and the directory synced, so that a reader
// sees the old account or the new one and never half of one. The directory
// must exist. An invalid account is not written.
func Save(path string, a *Account) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return writeAccount(path, a)
}

// saveRegistration is Save for a registration that is not complete yet: its
// key, id and token, kept so that LoadOrRegister can go on with that device.
func saveRegistration(path string, a *Account) error {
	if !a.registeredOnly() {
		return errors.New("warp: not a registration to keep")
	}
	return writeAccount(path, a)
}

// tempPrefix starts the names of the temporary files of the account file at
// path.
func tempPrefix(path string) string { return "." + filepath.Base(path) + ".tmp-" }

func writeAccount(path string, a *Account) (err error) {
	data, err := json.MarshalIndent(a, "", "  ") //nolint:gosec // the account file holds the key on purpose; it is written 0600, never logged
	if err != nil {
		return fmt.Errorf("warp: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tempPrefix(path)+"*")
	if err != nil {
		return fmt.Errorf("warp: account file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil { // CreateTemp makes it 0600; not the umask's business
		return fmt.Errorf("warp: account file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("warp: account file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("warp: account file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("warp: account file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("warp: account file: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes the entries of a directory to disk: the rename of a Save
// survives a crash. Best effort: not every file system supports it.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// checkAccountDir checks that the directory of the account file at path exists
// and takes a new file.
func checkAccountDir(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("warp: account file directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("warp: account file directory " + dir + " is not a directory")
	}
	f, err := os.CreateTemp(dir, tempPrefix(path)+"probe-*")
	if err != nil {
		return fmt.Errorf("warp: account file directory %s takes no new file: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// removeStaleTemps removes the temporary files that a Save of the account file
// at path left behind when it was cut short (they may hold the private key).
func removeStaleTemps(path string) {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return
	}
	prefix := tempPrefix(path)
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), prefix) {
			_ = os.Remove(filepath.Join(filepath.Dir(path), e.Name()))
		}
	}
}

// LoadOrRegister returns the account of the file at path. When there is no
// file it registers a device: it keeps the device's key, id and token in the
// file as soon as the device exists, then completes the account and saves it.
// A file that holds such a registration (a call that ended before the device's
// config came) is completed with that device, not with a new one. created
// reports that this call made the account usable (registered a device, or
// completed one). A file that exists but cannot be read or is neither an
// account nor a registration is an error, never a reason to register again:
// each registration is a new device of Cloudflare's. Temporary files that a
// Save cut short left next to it are removed.
func LoadOrRegister(ctx context.Context, hc *http.Client, path string) (acct *Account, created bool, err error) {
	return loadOrRegister(ctx, hc, apiBase, path)
}

func loadOrRegister(ctx context.Context, hc *http.Client, base, path string) (*Account, bool, error) {
	removeStaleTemps(path)
	a, err := readAccountFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// The registration is kept the moment the device exists: make sure it
		// can be, before there is a device.
		if err := checkAccountDir(path); err != nil {
			return nil, false, err
		}
		a, err = register(ctx, hc, base, func(reg *Account) error { return saveRegistration(path, reg) })
		if err != nil {
			return nil, false, err
		}
	case err != nil:
		return nil, false, err
	case a.Validate() == nil:
		return a, false, nil
	case a.registeredOnly():
		if a, err = complete(ctx, hc, base, a, nil); err != nil {
			return nil, false, err
		}
	default:
		return nil, false, errors.New("warp: account file " + path + " is neither an account nor a registration to complete")
	}
	if err := Save(path, a); err != nil {
		return nil, false, err
	}
	return a, true, nil
}
