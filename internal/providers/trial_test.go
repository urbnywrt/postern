package providers

import "testing"

func TestVersionOutput(t *testing.T) {
	re := VersionOutput(`^tool `, "v2.1.7-rc.1+b5", `$`)
	if !re.MatchString("tool 2.1.7-rc.1+b5") || re.MatchString("tool 2.1.7-rc.1+b55") || re.MatchString("tool 2.1.7-rc.1xb5") {
		t.Errorf("pattern %v", re)
	}
	if re := VersionOutput(`^`, "1.0", `$`); !re.MatchString("x\n1.0\ny") {
		t.Error("the pattern is not multi-line")
	}
	for _, bad := range []string{"", "v", "latest", "a.b", "1 0", "1.0\n", ".1", "-1", "1/0", "v" + string(make([]byte, 65))} {
		if VersionOutput(``, bad, ``).MatchString(bad) || VersionOutput(``, bad, ``).MatchString("anything") {
			t.Errorf("VersionOutput(%q) matches", bad)
		}
	}
}
