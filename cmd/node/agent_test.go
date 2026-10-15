package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/node/agent"
)

func TestAgentFlags(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		code       int
		wantStdout string
		wantStderr string
	}{
		{"help", []string{"agent", "-h"}, 0, "Usage: postern-node agent", ""},
		{"an argument", []string{"agent", "extra"}, 2, "", `unexpected argument "extra"`},
		{"an unknown flag", []string{"agent", "--bogus"}, 2, "", "bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != tc.code {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tc.code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.wantStdout) || !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
			if tc.code == 2 && !strings.Contains(stderr.String(), "Usage: postern-node agent") {
				t.Errorf("no usage after a mistake: %q", stderr.String())
			}
		})
	}
}

func TestUsageListsAgent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	run(nil, &stdout, &stderr)
	if !strings.Contains(stderr.String(), "agent ") {
		t.Errorf("usage = %q, want the agent command", stderr.String())
	}
}

// Without an installed bundle the agent stops at once with exit code 1 and
// says what is missing.
func TestAgentFailsWithoutABundle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("POSTERN_HOME", home)
	t.Setenv("POSTERN_MGMT_LISTEN", "127.0.0.1:0")
	var stdout, stderr bytes.Buffer
	code := run([]string{"agent"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), filepath.Join(home, "pki")) || !strings.Contains(stderr.String(), "bundle") {
		t.Errorf("stderr = %q, want it to name the bundle in %s", stderr.String(), filepath.Join(home, "pki"))
	}
}

// An agent that stopped after UpdateSelf exits with 75, the launcher's
// "restart me with the new binary"; another failure with 1.
func TestAgentExitCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{agent.ErrRestart, 75},
		{fmt.Errorf("wrapped: %w", agent.ErrRestart), 75},
		{errors.New("agent: not healthy 10m0s after the start: no reconcile pass has finished"), 1},
		{nil, 0},
	} {
		saved := agentRun
		agentRun = func(context.Context, agent.Options) error { return tc.err }
		var stdout, stderr bytes.Buffer
		code := run([]string{"agent"}, &stdout, &stderr)
		agentRun = saved
		if code != tc.code {
			t.Errorf("%v: exit code = %d, want %d", tc.err, code, tc.code)
		}
	}
}

func TestAgentHomeMustBeAbsolute(t *testing.T) {
	t.Setenv("POSTERN_HOME", "relative/home")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"agent"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "POSTERN_HOME") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr.String())
	}
}
