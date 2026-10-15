package selfupdate

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGC(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0", "v0.5.0", "v0.10.0", "v0.11.0"} {
		if err := os.WriteFile(filepath.Join(bin, "postern-node-"+v), []byte(v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// An interrupted install left a temporary file.
	if err := os.WriteFile(filepath.Join(bin, ".postern-node-v0.12.0.tmp-123"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"current": "postern-node-v0.1.0", "previous": "postern-node-v0.2.0"} {
		if err := os.Symlink(target, filepath.Join(bin, link)); err != nil {
			t.Fatal(err)
		}
	}
	mounted := filepath.Join(bin, "postern-node-v0.3.0")
	var asked []string
	removed := GC(home, func(p string) bool {
		asked = append(asked, p)
		return p == mounted
	})
	want := []string{
		filepath.Join(bin, ".postern-node-v0.12.0.tmp-123"),
		filepath.Join(bin, "postern-node-v0.4.0"),
		filepath.Join(bin, "postern-node-v0.5.0"),
		filepath.Join(bin, "postern-node-v0.10.0"),
		filepath.Join(bin, "postern-node-v0.11.0"),
	}
	if !slices.Equal(removed, want) {
		t.Errorf("removed %q, want %q", removed, want)
	}
	// Kept: current, previous and the mounted one; the others go while more
	// than three versions remain, oldest first.
	if got := Binaries(home).GetVersions(); !slices.Equal(got, []string{"v0.1.0", "v0.2.0", "v0.3.0"}) {
		t.Errorf("left %q", got)
	}
	if !slices.Contains(asked, mounted) {
		t.Errorf("keep was asked about %q, not the mounted binary", asked)
	}

	// Never a kept one, even when nothing else can go.
	if err := os.WriteFile(filepath.Join(bin, "postern-node-v0.11.0"), []byte("v0.11.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if removed := GC(home, func(string) bool { return true }); len(removed) != 0 {
		t.Errorf("removed %q although every binary is kept", removed)
	}
	if removed := GC(home, func(p string) bool { return p == mounted }); len(removed) != 1 || removed[0] != filepath.Join(bin, "postern-node-v0.11.0") {
		t.Errorf("removed %q, want only v0.11.0", removed)
	}
	if got := Binaries(home).GetVersions(); !slices.Equal(got, []string{"v0.1.0", "v0.2.0", "v0.3.0"}) {
		t.Errorf("left %q", got)
	}
}
