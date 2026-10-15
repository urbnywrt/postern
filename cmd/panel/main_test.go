package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // substring expected on stdout
		wantStderr string // substring expected on stderr
	}{
		{
			name:       "version",
			args:       []string{"version"},
			wantCode:   0,
			wantStdout: "dev (none, unknown)",
		},
		{
			name:       "no arguments",
			args:       nil,
			wantCode:   2,
			wantStderr: "Usage: postern-panel",
		},
		{
			name:       "unknown command",
			args:       []string{"bogus"},
			wantCode:   2,
			wantStderr: `unknown command "bogus"`,
		},
		{
			// serve is configured by its environment. It refuses arguments before
			// it reads that or starts anything.
			name:       "serve with an argument",
			args:       []string{"serve", "--listen=:1"},
			wantCode:   2,
			wantStderr: "serve takes no arguments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("run(%q) exit code = %d, want %d", tt.args, code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantCode == 0 && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want it empty on success", stderr.String())
			}
			if tt.wantCode != 0 && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want it empty on failure", stdout.String())
			}
		})
	}
}
