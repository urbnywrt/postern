package sshxtest

import (
	"encoding/base64"
	"strings"
)

// The forms in which package sshx sends commands, copied from it; the tests of
// sshx check that they agree. A command line is
//
//	exec sh -c '<TransportScript>' sh '<the script in base64>'
//
// and the script is the command itself for root, [SudoCheck] once per client
// for any other user, and then SudoPrefix and the command, quoted for sh.
const (
	// TransportScript is what the login shell passes to sh: it decodes the
	// script, which follows as the first argument, and replaces itself with a
	// sh that runs it. Without base64 it says so and exits with 127.
	TransportScript = `s=$(printf %s "$1" | base64 -d) || { echo "sshx: the command cannot be" "decoded: base64 is missing or failed" >&2; exit 127; }; exec sh -c -- "$s"`

	// SudoPrefix starts the script of a command that runs through sudo.
	SudoPrefix = "LC_ALL=C exec sudo -n -- sh -c -- "

	// SudoCheck is the script with which sshx finds out, before the first
	// command of a user other than root, whether sudo works without a
	// password.
	SudoCheck = "LC_ALL=C sudo -n true"
)

// Script returns what package sshx meant by a command line: the script that it
// carries, without the sudo wrapping, and whether it runs through sudo. A
// command line that is not in the form of sshx is returned as it is. A fake
// [Handler] matches on the script, whatever the user; the script of the check
// of sudo is [SudoCheck].
func Script(line string) (script string, sudo bool) {
	payload, ok := decodeTransport(line)
	if !ok {
		return line, false
	}
	if inner, ok := unsudo(payload); ok {
		return inner, true
	}
	return payload, false
}

// decodeTransport returns the script of a command line in the form of sshx.
func decodeTransport(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "exec sh -c '"+TransportScript+"' sh '")
	if !ok {
		return "", false
	}
	encoded, ok := strings.CutSuffix(rest, "'")
	if !ok {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// unsudo returns the command that a script runs through sudo.
func unsudo(script string) (string, bool) {
	quoted, ok := strings.CutPrefix(script, SudoPrefix)
	if !ok || quoted == "" {
		return "", false
	}
	// The command is a run of single-quoted strings and escaped quotes (\'),
	// as sshx quotes it.
	var b strings.Builder
	for quoted != "" {
		switch {
		case quoted[0] == '\'':
			end := strings.IndexByte(quoted[1:], '\'')
			if end < 0 {
				return "", false
			}
			b.WriteString(quoted[1 : 1+end])
			quoted = quoted[2+end:]
		case strings.HasPrefix(quoted, `\'`):
			b.WriteByte('\'')
			quoted = quoted[2:]
		default:
			return "", false
		}
	}
	return b.String(), true
}
