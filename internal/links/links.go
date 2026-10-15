// Package links builds the Telegram proxy links Postern hands out, and is the
// single source of truth for their format.
//
// The formats are a byte-for-byte contract (design spec, section 4): a link that
// was given to users has to come out identical as long as its proxy stays the
// same. Three rules follow from that.
//
//   - Percent-encoding has the semantics of JavaScript's encodeURIComponent,
//     see [EncodeURIComponent].
//   - Hosts, domains and secrets are used as stored. Nothing is lowercased,
//     trimmed, converted to punycode or validated, except that a secret which
//     has to be decoded to build a link (the base-path form of [Web]) must be
//     valid.
//   - Hex that this package produces is lowercase, but a stored secret keeps the
//     case it was stored in.
//
// The caller picks the host and the port: a listener's link_host_override if it
// has one, otherwise the node's link_host, and the port of the listener.
package links

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const upperHex = "0123456789ABCDEF"

// EncodeURIComponent percent-encodes s exactly like JavaScript's
// encodeURIComponent: A-Z a-z 0-9 - _ . ! ~ * ' ( ) stay as they are, and every
// other byte of the UTF-8 text becomes %XX with capital hex digits. So a space
// is %20 (never +), a slash is %2F and a colon is %3A.
//
// A JavaScript string cannot hold invalid UTF-8 (encodeURIComponent throws on a
// lone surrogate), so no reference link exists for it. Bytes that are not valid
// UTF-8 are escaped as they are, instead of being rejected or replaced.
func EncodeURIComponent(s string) string {
	escapes := 0
	for i := 0; i < len(s); i++ {
		if !isUnreserved(s[i]) {
			escapes++
		}
	}
	if escapes == 0 {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + 2*escapes)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0x0f])
	}
	return b.String()
}

// isUnreserved reports whether encodeURIComponent leaves the byte as it is.
// Every byte of a multi-byte UTF-8 character is 0x80 or above, so none is.
func isUnreserved(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '!', '~', '*', '\'', '(', ')':
		return true
	}
	return false
}

// FakeTLSSecret returns the secret of a fake-TLS link: "ee", the secret as it is
// stored, and the lowercase hex of the UTF-8 bytes of the domain. Neither input
// is normalized, so an UPPERCASE secret and a mixed-case domain stay as they are
// (the hex digits of the domain are lowercase all the same).
func FakeTLSSecret(secretHex, domain string) string {
	return "ee" + secretHex + hex.EncodeToString([]byte(domain))
}

// FakeTLS is a fake-TLS proxy as a client reaches it.
type FakeTLS struct {
	Host      string // address to connect to, as stored: the listener's link_host_override, else the node's link_host
	Port      uint16 // port of the listener
	SecretHex string // 32 hex digits, as stored
	Domain    string // fake-TLS (SNI) domain, as stored
}

// TG returns the tg://proxy link.
func (f FakeTLS) TG() string { return "tg://proxy?" + f.query() }

// HTTPS returns the https://t.me/proxy link, which carries the query of [FakeTLS.TG].
func (f FakeTLS) HTTPS() string { return "https://t.me/proxy?" + f.query() }

func (f FakeTLS) query() string {
	return "server=" + EncodeURIComponent(f.Host) +
		"&port=" + strconv.FormatUint(uint64(f.Port), 10) +
		"&secret=" + FakeTLSSecret(f.SecretHex, f.Domain)
}

// The values of a WEB proxy's secret mode (web_secret_mode in the panel).
const (
	ModePlain = "plain" // the client secret is the 16 secret bytes
	ModeDD    = "dd"    // the client secret is 0xdd followed by the 16 secret bytes
)

// secretHexLen is the length of a secret in hex digits: 16 bytes.
const secretHexLen = 32

// Web is a WEB proxy: a page that Telegram clients open through t.me/webproxy.
// It has no port, the domain is the whole address.
type Web struct {
	Domain    string // proxy domain, as stored
	BasePath  string // telemt base_path such as "telegram/web", used as it is; empty when the proxy owns the root of the host
	SecretHex string // 32 hex digits, as stored
	Mode      string // [ModePlain] or [ModeDD]
}

// Secret returns the secret parameter of the link.
//
// At the root of the host (empty BasePath) it is the secret as stored, behind
// "dd" in [ModeDD], exactly as the reference formulas build it.
//
// With a base path (telemt 3.5.8 and later) it is the unpadded URL-safe base64 of
// 0x70 followed by the client secret: the 16 secret bytes in [ModePlain], or 0xdd
// and those bytes in [ModeDD]. This is the one form that decodes SecretHex, so it
// is the one that insists on 32 hex digits (in either case).
//
// An unknown Mode is an error in both forms. No error contains the secret, nor
// any part of it.
func (w Web) Secret() (string, error) {
	if w.Mode != ModePlain && w.Mode != ModeDD {
		return "", fmt.Errorf("links: unknown web secret mode %q, want %q or %q", w.Mode, ModePlain, ModeDD)
	}

	if w.BasePath == "" {
		if w.Mode == ModeDD {
			return "dd" + w.SecretHex, nil
		}
		return w.SecretHex, nil
	}

	if len(w.SecretHex) != secretHexLen {
		return "", fmt.Errorf("links: web secret must be %d hex digits when base_path is set, got %d bytes", secretHexLen, len(w.SecretHex))
	}
	raw, err := hex.DecodeString(w.SecretHex)
	if err != nil {
		// The error of the decoder is dropped on purpose: it quotes the first
		// byte that is not hex, which is a byte of the secret.
		return "", errors.New("links: web secret is not valid hex")
	}
	clientSecret := make([]byte, 0, 2+len(raw))
	clientSecret = append(clientSecret, 0x70)
	if w.Mode == ModeDD {
		clientSecret = append(clientSecret, 0xdd)
	}
	clientSecret = append(clientSecret, raw...)
	return base64.RawURLEncoding.EncodeToString(clientSecret), nil
}

// Server returns the server parameter of the link: the domain, or the domain and
// the base path joined by a slash, percent-encoded as one component (so the slash
// becomes %2F).
func (w Web) Server() string {
	if w.BasePath == "" {
		return EncodeURIComponent(w.Domain)
	}
	return EncodeURIComponent(w.Domain + "/" + w.BasePath)
}

// HTTPS returns the https://t.me/webproxy link.
func (w Web) HTTPS() (string, error) { return w.link("https://t.me/webproxy") }

// TG returns the tg://webproxy link, which carries the query of [Web.HTTPS].
func (w Web) TG() (string, error) { return w.link("tg://webproxy") }

func (w Web) link(prefix string) (string, error) {
	secret, err := w.Secret()
	if err != nil {
		return "", err
	}
	return prefix + "?server=" + w.Server() + "&secret=" + secret, nil
}
