//go:build unix

package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO in a cache does not hold the copy of the cache: it is left out.
func TestPsiphonCacheCopyLeavesAFIFOOut(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, psiphonEgress("DE")))
	h.pass()
	cache1 := filepath.Join(h.paths.EgressDir("ps"), "cache-g1")
	if err := syscall.Mkfifo(filepath.Join(cache1, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache1, "data"), []byte("g1 data"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.apply(h.providerState(2, psiphonEgress("NL")))
	done := make(chan error, 1)
	go func() { done <- h.r.reconcileOnce(context.Background(), nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconcile pass: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the copy of a cache with a FIFO in it hangs")
	}
	cache2 := filepath.Join(h.paths.EgressDir("ps"), "cache-g2")
	if b, err := os.ReadFile(filepath.Join(cache2, "data")); err != nil || string(b) != "g1 data" {
		t.Errorf("the cache of g2: %q, %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(cache2, "fifo")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the FIFO was copied: %v", err)
	}
}
