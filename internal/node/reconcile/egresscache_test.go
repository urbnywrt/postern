package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file of the cache that changes while it is copied (Psiphon writes it) is
// copied again; one that changes again is left out of the copy, with a
// warning, and the rest is copied.
func TestPsiphonCacheFileThatChangesWhileCopied(t *testing.T) {
	h := newHarness(t)
	var logs lockedBuffer
	h.r.Log = slog.New(slog.NewTextHandler(&logs, nil))
	h.apply(h.providerState(1, psiphonEgress("DE")))
	h.pass()
	cache1 := filepath.Join(h.paths.EgressDir("ps"), "cache-g1")
	write := func(name, data string, flag int) {
		t.Helper()
		f, err := os.OpenFile(filepath.Join(cache1, name), flag|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(data); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write("busy", "x", os.O_TRUNC)
	write("settles", "y", os.O_TRUNC)
	write("still", "z", os.O_TRUNC)
	reads := map[string]int{}
	h.r.cacheCopied = func(name string) {
		reads[name]++
		switch {
		case name == "busy":
			write("busy", "+", os.O_APPEND) // written to at every read
		case name == "settles" && reads[name] == 1:
			write("settles", "+", os.O_APPEND) // written to once
		}
	}

	h.apply(h.providerState(2, psiphonEgress("NL")))
	h.pass()
	if rec := h.runtime().Egresses["ps"]; rec.Generation != 2 {
		t.Fatalf("record = %+v, want g2", rec)
	}
	cache2 := filepath.Join(h.paths.EgressDir("ps"), "cache-g2")
	for name, want := range map[string]string{"still": "z", "settles": "y+"} {
		if b, err := os.ReadFile(filepath.Join(cache2, name)); err != nil || string(b) != want {
			t.Errorf("%s in the copy: %q, %v; want %q", name, b, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(cache2, "busy")); !os.IsNotExist(err) {
		t.Errorf("a file that changed at every read is in the copy: %v", err)
	}
	if reads["busy"] != 2 || reads["settles"] != 2 || reads["still"] != 1 {
		t.Errorf("reads = %v, want busy and settles twice, still once", reads)
	}
	if text := logs.String(); !strings.Contains(text, "changed while they were copied") || !strings.Contains(text, "first=busy") {
		t.Errorf("no warning names the file left out:\n%s", text)
	}
}

// The copy of a cache reads a directory a batch at a time: one with more
// entries than a cache may have is not read whole before the copy gives up.
func TestCacheCopyReadsDirectoriesInBatches(t *testing.T) {
	h := newHarness(t)
	src, dst := t.TempDir(), t.TempDir()
	const files = maxCacheEntries + 1000
	for i := range files {
		if err := os.WriteFile(filepath.Join(src, fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	c := &cacheCopy{p: &pass{r: h.r, ctx: context.Background()}, root: root, dst: dst, budget: maxCacheBytes}
	if err := c.dir("."); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("copy = %v, want too many entries", err)
	}
	if c.read > maxCacheEntries+cacheBatch || c.read >= files {
		t.Errorf("%d entries of %d were read, at most %d", c.read, files, maxCacheEntries+cacheBatch)
	}
}
