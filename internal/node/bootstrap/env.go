package bootstrap

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/urbnywrt/postern/internal/panelurl"
)

// The environment of the node container (Global Constraints).
const (
	// EnvJoin is <panel base URL>#<token>, as the panel renders it.
	EnvJoin = "POSTERN_JOIN"
	// EnvHome is the node's directory, /opt/postern unless it is set.
	EnvHome = "POSTERN_HOME"
)

// A join token is 32 random bytes in base64url without padding.
const (
	tokenBytes = 32
	tokenLen   = 43
)

// joinSpec is a parsed POSTERN_JOIN. It never prints the token.
type joinSpec struct {
	base  string // the panel URL in its normal form, https://host[:port]
	token string
}

// String names the panel and hides the token, so that a joinSpec that ends
// up in a log or an error leaks nothing.
func (j *joinSpec) String() string { return j.base + "#<token>" }

// apiURL is the base URL of the panel's Connect API.
func (j *joinSpec) apiURL() string { return j.base + "/api" }

// parseJoin reads POSTERN_JOIN. Its errors never hold the value, which carries
// the token.
func parseJoin(v string) (*joinSpec, error) {
	raw, token, ok := strings.Cut(v, "#")
	if !ok {
		return nil, errors.New(EnvJoin + " must be <panel URL>#<token>, as the panel shows it")
	}
	base, err := panelurl.Check(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: the panel URL: %w", EnvJoin, err)
	}
	if err := checkToken(token); err != nil {
		return nil, fmt.Errorf("%s: %w", EnvJoin, err)
	}
	return &joinSpec{base: base, token: token}, nil
}

// checkToken accepts 43 characters of unpadded base64url that are 32 bytes.
func checkToken(token string) error {
	const msg = "the token must be the 43 characters the panel gives (letters, digits, - and _)"
	if len(token) != tokenLen {
		return errors.New(msg)
	}
	for i := 0; i < len(token); i++ {
		switch c := token[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return errors.New(msg)
		}
	}
	if raw, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(raw) != tokenBytes {
		return errors.New(msg)
	}
	return nil
}

// lookupEnv returns the last value of key in env ("KEY=value" entries), as
// the C library does.
func lookupEnv(env []string, key string) (string, bool) {
	val, found := "", false
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			val, found = v, true
		}
	}
	return val, found
}

// agentEnv is env without POSTERN_JOIN, and with POSTERN_HOME set to home.
func agentEnv(env []string, home string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if k == EnvJoin || k == EnvHome {
			continue
		}
		out = append(out, e)
	}
	return append(out, EnvHome+"="+home)
}
