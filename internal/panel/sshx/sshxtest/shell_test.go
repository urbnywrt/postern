package sshxtest

import (
	"encoding/base64"
	"slices"
	"testing"
)

// line is a command line in the form of sshx for a script.
func line(script string) string {
	return "exec sh -c '" + TransportScript + "' sh '" + base64.StdEncoding.EncodeToString([]byte(script)) + "'"
}

func TestScript(t *testing.T) {
	for _, c := range []struct {
		line       string
		wantScript string
		wantSudo   bool
	}{
		{line("id -u"), "id -u", false},
		{line(SudoCheck), SudoCheck, false},
		{line(SudoPrefix + `'id -u'`), "id -u", true},
		{line(SudoPrefix + `'echo '\''it'\''s'\'''`), `echo 'it's'`, true},
		{line(SudoPrefix + `''`), "", true},
		{line(SudoPrefix + "'two\nlines'"), "two\nlines", true},
		{line(""), "", false},
		// A script that is not a well-formed sudo wrapping is the script.
		{line(SudoPrefix + `'unterminated`), SudoPrefix + `'unterminated`, false},
		{line(SudoPrefix + `'a'b`), SudoPrefix + `'a'b`, false},
		{line("sudo -n -- sh -c 'id'"), "sudo -n -- sh -c 'id'", false},
		// Not in the form of sshx: returned as it is.
		{"id -u", "id -u", false},
		{"exec sh -c '" + TransportScript + "' sh 'not base64!'", "exec sh -c '" + TransportScript + "' sh 'not base64!'", false},
		{"sh -c 'other' sh 'aWQ='", "sh -c 'other' sh 'aWQ='", false},
	} {
		script, sudo := Script(c.line)
		if script != c.wantScript || sudo != c.wantSudo {
			t.Errorf("Script(%q) = %q, %v; want %q, %v", c.line, script, sudo, c.wantScript, c.wantSudo)
		}
	}
}

func TestForeignWords(t *testing.T) {
	for _, c := range []struct {
		line string
		want []string // nil: refused
	}{
		{line("echo hi"), []string{"exec", "sh", "-c", TransportScript, "sh", base64.StdEncoding.EncodeToString([]byte("echo hi"))}},
		{"true", []string{"true"}},
		{"echo 'a b' c", []string{"echo", "a b", "c"}},
		{"echo ''", []string{"echo", ""}},
		// What only sh reads as sh does.
		{"echo hi; true", nil},
		{"echo $HOME", nil},
		{"echo 'it'\\''s'", nil},
		{"echo 'back\\slash'", nil},
		{"echo 'two\nlines'", nil},
		{"echo 'bang!'", nil},
		{"echo  two-spaces", nil},
		{"echo trailing ", nil},
		{"echo 'unterminated", nil},
		{"", nil},
	} {
		got, ok := foreignWords(c.line)
		if (c.want == nil) != !ok || !slices.Equal(got, c.want) {
			t.Errorf("foreignWords(%q) = %q, %v; want %q", c.line, got, ok, c.want)
		}
	}
}
