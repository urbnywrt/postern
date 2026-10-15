// Package totp implements time-based one-time passwords (RFC 6238) the way
// authenticator apps use them: HMAC-SHA-1, steps of 30 seconds, 6 digits.
//
// SHA-1, 6 digits and 30 seconds are what every authenticator app supports, and
// Google Authenticator ignores other values in the key URI. HMAC does not rely
// on the collision resistance that SHA-1 has lost.
//
// A secret is the base32 text that [NewSecret] returns. Code and Verify also read
// it in lower case and with the padding that RFC 4648 adds, as authenticator
// apps show it, but nothing else: no spaces, no hyphens.
//
// Steps count whole seconds since the Unix epoch, and a time before it has no
// step. [Verify] does not remember codes: a code that was accepted is accepted
// again until it has left the window, up to 90 seconds later, so a login that
// must not be replayed has to remember the codes it has accepted.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	period      = 30 // seconds in a step
	codeDigits  = 6  // digits in a code
	skew        = 1  // steps that Verify accepts before and after the current one
	secretBytes = 20 // 160 bits, the size that RFC 4226 recommends
)

var (
	errSecret = errors.New("totp: the secret is empty or not base32")
	errTime   = errors.New("totp: time is before the Unix epoch")
)

// b32 is the encoding of a secret: standard base32 without padding.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a new secret: 20 random bytes as base32 without padding
// (32 characters).
func NewSecret() (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return b32.EncodeToString(raw), nil
}

// Code returns the 6-digit code of the step that contains t. It returns an error
// for a secret that is not base32 or has no bytes, and for a time before the
// Unix epoch. The error does not contain the secret.
func Code(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	if t.Unix() < 0 {
		return "", errTime
	}
	return totpAt(key, t, codeDigits), nil
}

// Verify reports whether code is the code of the step that contains t, or of
// the step before or after it (a phone's clock is rarely exact). The code has to
// be exactly 6 ASCII digits: a caller that takes input from a person trims it
// first. A secret that cannot be used, and a time before the Unix epoch, give
// false.
func Verify(secret, code string, t time.Time) bool {
	if len(code) != codeDigits || t.Unix() < 0 {
		return false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}

	// Every step is checked and the results are combined, so that the time taken
	// does not tell which step matched, or whether one did.
	match := 0
	for offset := -skew; offset <= skew; offset++ {
		at := t.Add(time.Duration(offset*period) * time.Second)
		if at.Unix() < 0 {
			continue // there is no step before the epoch
		}
		match |= subtle.ConstantTimeCompare([]byte(totpAt(key, at, codeDigits)), []byte(code))
	}
	return match == 1
}

// URI returns the otpauth:// URI that authenticator apps read from a QR code to
// add an account:
//
//	otpauth://totp/<issuer>:<account>?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
//
// The issuer and the account are percent-encoded, so a space is %20 and
// reserved characters cannot change the structure of the URI. A colon in either
// is dropped, since the label has no way to write one: it separates the two. An
// empty issuer leaves out both the prefix of the label and the issuer parameter.
// The secret is meant to come from [NewSecret], and base32 needs no escaping, but
// it is escaped all the same so that a stray character cannot add a parameter.
func URI(secret, account, issuer string) string {
	account = escape(strings.ReplaceAll(account, ":", ""))
	issuer = escape(strings.ReplaceAll(issuer, ":", ""))

	label := account
	query := "secret=" + escape(secret)
	if issuer != "" {
		label = issuer + ":" + account
		query += "&issuer=" + issuer
	}
	return fmt.Sprintf("otpauth://totp/%s?%s&algorithm=SHA1&digits=%d&period=%d", label, query, codeDigits, period)
}

// escape percent-encodes s for the label or a query value of a URI. Only the
// unreserved characters of RFC 3986 (letters, digits and - . _ ~) and @, which
// is the usual way to write an account that is an e-mail address, stay as they
// are. Every other byte of the UTF-8 text is written as %XX with capital digits.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("-._~@", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// decodeSecret reads a secret into the key bytes. An empty key is refused:
// HMAC takes one, and anybody can compute the codes of it.
func decodeSecret(secret string) ([]byte, error) {
	secret = strings.TrimRight(secret, "=")
	// Upper-case ASCII only. strings.ToUpper would also turn a few non-ASCII
	// letters, such as the long s, into base32 digits.
	secret = strings.Map(func(r rune) rune {
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, secret)

	key, err := b32.DecodeString(secret)
	if err != nil || len(key) == 0 {
		return nil, errSecret
	}
	return key, nil
}

// totpAt is TOTP of RFC 6238 for key at t: HOTP of the number of the 30-second
// step that t is in. The time must not be before the Unix epoch.
func totpAt(key []byte, t time.Time, digits int) string {
	return hotp(key, uint64(t.Unix()/period), digits)
}

// hotp is HOTP of RFC 4226: the dynamic truncation (section 5.3) of the
// HMAC-SHA-1 of the 8-byte counter, as a number of 1 to 9 digits with leading
// zeros.
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}
