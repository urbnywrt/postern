package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// seedCase prepares bin/ and the image, seeds, and reports the links.
type seedResult struct {
	current, previous, launcher, signature string
}

func seedWith(t *testing.T, h *harness, prep func(bin string)) seedResult {
	t.Helper()
	b := h.boot()
	if err := b.makeLayout(); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(h.home, "bin")
	mustWrite(t, filepath.Join(bin, "launcher.sh"), "old launcher\n")
	if prep != nil {
		prep(bin)
	}
	if err := b.seed(); err != nil {
		t.Fatal(err)
	}
	var r seedResult
	r.current, _ = os.Readlink(filepath.Join(bin, "current"))
	r.previous, _ = os.Readlink(filepath.Join(bin, "previous"))
	r.launcher = readString(t, filepath.Join(bin, "launcher.sh"))
	if data, err := os.ReadFile(filepath.Join(bin, ".postern-node-"+h.opt.Version+".minisig")); err == nil {
		r.signature = string(data)
	}
	return r
}

const imageLauncher = "#!/bin/sh\n# launcher of the image\n"

func installed(t *testing.T, bin, version, content string) {
	t.Helper()
	p := filepath.Join(bin, "postern-node-"+version)
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, bin, name, target string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(bin, name)); err != nil {
		t.Fatal(err)
	}
}

func TestSeedWithoutCurrent(t *testing.T) {
	h := newHarness(t)
	r := seedWith(t, h, nil)
	if r.current != "postern-node-0.5.0" || r.previous != "" || r.launcher != imageLauncher || r.signature == "" {
		t.Errorf("seed = %+v", r)
	}
	p := filepath.Join(h.home, "bin", "postern-node-0.5.0")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o755 || readString(t, p) != "binary of 0.5.0" {
		t.Errorf("the binary: %v, %v", st, err)
	}
	if st, _ := os.Stat(filepath.Join(h.home, "bin", ".postern-node-0.5.0.minisig")); st.Mode().Perm() != 0o644 {
		t.Errorf("the signature mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Join(h.home, "bin", "launcher.sh")); st.Mode().Perm() != 0o755 {
		t.Errorf("the launcher mode %v", st.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(h.home, "bin", ".*.new.*")); len(left) != 0 {
		t.Errorf("staging files left: %q", left)
	}
}

func TestSeedOverAnOlderCurrent(t *testing.T) {
	h := newHarness(t)
	r := seedWith(t, h, func(bin string) {
		installed(t, bin, "0.4.0", "old")
		link(t, bin, "current", "postern-node-0.4.0")
	})
	if r.current != "postern-node-0.5.0" || r.previous != "postern-node-0.4.0" || r.launcher != imageLauncher {
		t.Errorf("seed = %+v", r)
	}
}

func TestSeedUnderANewerCurrent(t *testing.T) {
	h := newHarness(t)
	r := seedWith(t, h, func(bin string) {
		installed(t, bin, "0.6.0", "new")
		link(t, bin, "current", "postern-node-0.6.0")
	})
	if r.current != "postern-node-0.6.0" || r.previous != "" || r.launcher != "old launcher\n" {
		t.Errorf("seed = %+v; want current kept, launcher kept", r)
	}
	// The image's binary is installed all the same (for a rollback).
	if _, err := os.Stat(filepath.Join(h.home, "bin", "postern-node-0.5.0")); err != nil {
		t.Error(err)
	}
}

func TestSeedAtTheSameVersion(t *testing.T) {
	h := newHarness(t)
	r := seedWith(t, h, func(bin string) {
		installed(t, bin, "0.5.0", "binary of 0.5.0")
		installed(t, bin, "0.4.0", "old")
		link(t, bin, "current", "postern-node-0.5.0")
		link(t, bin, "previous", "postern-node-0.4.0")
	})
	if r.current != "postern-node-0.5.0" || r.previous != "postern-node-0.4.0" || r.launcher != imageLauncher {
		t.Errorf("seed = %+v; want links kept, launcher replaced", r)
	}
}

func TestSeedNotAVersion(t *testing.T) {
	h := newHarness(t)
	h.opt.Version = "dev"
	r := seedWith(t, h, func(bin string) {
		installed(t, bin, "0.5.0", "x")
		link(t, bin, "current", "postern-node-0.5.0")
	})
	if r.current != "postern-node-0.5.0" || r.launcher != "old launcher\n" {
		t.Errorf("seed of dev over 0.5.0 = %+v; want nothing switched", r)
	}

	h2 := newHarness(t)
	h2.opt.Version = "dev"
	if r := seedWith(t, h2, nil); r.current != "postern-node-dev" || r.launcher != imageLauncher {
		t.Errorf("seed of dev without current = %+v", r)
	}
}

func TestSeedSameNameOtherContent(t *testing.T) {
	h := newHarness(t)
	r := seedWith(t, h, func(bin string) {
		installed(t, bin, "0.5.0", "another build of 0.5.0")
		installed(t, bin, "0.4.0", "old")
		link(t, bin, "current", "postern-node-0.4.0")
	})
	if r.current != "postern-node-0.4.0" || r.signature != "" {
		t.Errorf("seed = %+v; want current kept and no signature", r)
	}
	if got := readString(t, filepath.Join(h.home, "bin", "postern-node-0.5.0")); got != "another build of 0.5.0" {
		t.Errorf("the installed version was replaced: %q", got)
	}
	h.wantLog("a version is never replaced")
}

func TestSeedDanglingCurrentIsMissing(t *testing.T) {
	h := newHarness(t)
	r := seedWith(t, h, func(bin string) { link(t, bin, "current", "postern-node-0.9.9") })
	if r.current != "postern-node-0.5.0" {
		t.Errorf("seed = %+v", r)
	}
}

func TestSeedWithoutImageSignature(t *testing.T) {
	h := newHarness(t)
	_ = os.Remove(h.opt.Signature)
	if r := seedWith(t, h, nil); r.signature != "" {
		t.Errorf("signature = %q", r.signature)
	}
	h.wantLog("the image has no signature")
}

func TestMakeLayoutNeverWidens(t *testing.T) {
	h := newHarness(t)
	if err := os.Chmod(h.home, 0o700); err != nil {
		t.Fatal(err)
	}
	pkiDir := filepath.Join(h.home, "pki")
	mustMkdir(t, pkiDir)
	if err := os.Chmod(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := h.boot().makeLayout(); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]os.FileMode{h.home: 0o700, pkiDir: 0o700, filepath.Join(h.home, "data", "artifacts"): 0o755} {
		if st, _ := os.Stat(dir); st.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", dir, st.Mode().Perm(), want)
		}
	}
	mustWrite(t, filepath.Join(h.home, "data", "edge2"), "")
	if err := os.RemoveAll(filepath.Join(h.home, "data", "certs")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(h.home, "data", "certs"), "a file")
	if err := h.boot().makeLayout(); err == nil {
		t.Error("makeLayout passed over a file where a directory belongs")
	}
}
