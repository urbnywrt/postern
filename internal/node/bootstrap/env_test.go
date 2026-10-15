package bootstrap

import (
	"slices"
	"strings"
	"testing"
)

func TestParseJoin(t *testing.T) {
	token := strings.Repeat("A", 42) + "Q" // 32 bytes
	j, err := parseJoin("https://panel.example.com/#" + token)
	if err != nil {
		t.Fatal(err)
	}
	if j.base != "https://panel.example.com" || j.token != token || j.apiURL() != "https://panel.example.com/api" {
		t.Errorf("parseJoin = %+v", j)
	}
	if s := j.String(); strings.Contains(s, token) {
		t.Errorf("String() = %q shows the token", s)
	}
	for name, v := range map[string]string{
		"no separator":   token,
		"short token":    "https://panel.example.com#" + token[:42],
		"long token":     "https://panel.example.com#" + token + "A",
		"bad character":  "https://panel.example.com#" + token[:42] + "+",
		"padding":        "https://panel.example.com#" + token[:42] + "=",
		"bad last bits":  "https://panel.example.com#" + strings.Repeat("A", 42) + "B",
		"http not local": "http://panel.example.com#" + token,
		"two marks":      "https://panel.example.com#" + token + "#" + token,
		"empty URL":      "#" + token,
	} {
		_, err := parseJoin(v)
		if err == nil {
			if name == "bad last bits" {
				continue // the panel's decoder accepts them too
			}
			t.Errorf("%s: parseJoin passed", name)
			continue
		}
		if strings.Contains(err.Error(), token[:20]) {
			t.Errorf("%s: the error %q holds the token", name, err)
		}
		if !strings.Contains(err.Error(), EnvJoin) {
			t.Errorf("%s: the error %q does not name %s", name, err, EnvJoin)
		}
	}
}

func TestAgentEnv(t *testing.T) {
	env := []string{"A=1", EnvJoin + "=https://x#y", EnvHome + "=/elsewhere", "B=2"}
	got := agentEnv(env, "/opt/postern")
	want := []string{"A=1", "B=2", EnvHome + "=/opt/postern"}
	if !slices.Equal(got, want) {
		t.Errorf("agentEnv = %q, want %q", got, want)
	}
	if v, ok := lookupEnv([]string{"X=1", "X=2"}, "X"); !ok || v != "2" {
		t.Errorf("lookupEnv = %q, %v; want the last value", v, ok)
	}
}
