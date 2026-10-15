package telemt

import (
	"reflect"
	"testing"
)

func TestTrial(t *testing.T) {
	tr := New().Trial("3.5.13")
	if want := []string{"healthcheck", "--mode", "liveness", "/nonexistent/config.toml"}; !reflect.DeepEqual(tr.Args, want) || tr.ExitCode != 1 || tr.Output == nil {
		t.Fatalf("Trial = %+v", tr)
	}
	for output, want := range map[string]bool{
		"[telemt] healthcheck failed: config load failed: No such file or directory (os error 2)\n": true,
		"2026-10-05 INFO starting\n[telemt] healthcheck failed: config load failed: x\n":            true,
		"[telemt] healthcheck failed: connection refused\n":                                         false,
		"": false,
		"telemt: unrecognized subcommand 'healthcheck'\n": false,
	} {
		if got := tr.Output.MatchString(output); got != want {
			t.Errorf("Output.MatchString(%q) = %v, want %v", output, got, want)
		}
	}
	// The version plays no part.
	if !reflect.DeepEqual(New().Trial(""), tr) || !reflect.DeepEqual(New().Trial("9.9.9"), tr) {
		t.Error("the trial depends on the version")
	}
}
