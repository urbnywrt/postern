package xray

import (
	"reflect"
	"testing"
)

func TestTrial(t *testing.T) {
	tr := New().Trial("v26.3.27")
	if !reflect.DeepEqual(tr.Args, []string{"version"}) || tr.ExitCode != 0 || tr.Output == nil {
		t.Fatalf("Trial = %+v", tr)
	}
	for output, want := range map[string]bool{
		"Xray 26.3.27 (Xray, Penetrates Everything.) Custom (go1.25.1 linux/amd64)\nA unified platform for anti-censorship.\n": true,
		"Xray 26.3.27 (":            true,
		"Xray 26.3.2 (x)":           false,
		"Xray 26.3.271 (x)":         false,
		"Xray v26.3.27 (x)":         false,
		"xray 26.3.27 (x)":          false,
		" Xray 26.3.27 (x)":         false,
		"something\nXray 26.3.27 (": true,
		"":                          false,
	} {
		if got := tr.Output.MatchString(output); got != want {
			t.Errorf("Output.MatchString(%q) = %v, want %v", output, got, want)
		}
	}
	for _, bad := range []string{"", "v", "latest", "26.3.27 (", "v26.3.27\n"} {
		if New().Trial(bad).Output.MatchString("Xray " + bad + " (") {
			t.Errorf("Trial(%q) matches", bad)
		}
	}
}
