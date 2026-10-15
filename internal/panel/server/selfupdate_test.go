package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/selfupdate"
)

// The release bundle upload is mounted under /api/releases/upload, for admins
// only, and takes a tar.
func TestReleaseUploadRoute(t *testing.T) {
	p := newPanel(t)
	resp, body := p.do(http.MethodPost, "/api/releases/upload", strings.NewReader("x"), map[string]string{"Content-Type": "application/x-tar"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: status %d, want 401", resp.StatusCode)
	}
	if code, _ := errorBody(t, body); code != "unauthenticated" {
		t.Errorf("without a session: error code %q, want unauthenticated", code)
	}
	b := p.signIn()
	resp, _ = b.do(http.MethodPost, "/api/releases/upload", strings.NewReader("x"), map[string]string{"Content-Type": "text/plain"})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a body that is not a tar: status %d, want 415", resp.StatusCode)
	}
	resp, _ = b.do(http.MethodPost, "/api/releases/upload", strings.NewReader("not a tar"), map[string]string{"Content-Type": "application/x-tar"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a body that cannot be read as a tar: status %d, want 400", resp.StatusCode)
	}
}

// A panel that Recover found updated records it once it serves, and stops
// with selfupdate.ErrRestart, as on SIGTERM, when an update asks it to.
func TestServeSettlesTheUpdateAndStopsForARestart(t *testing.T) {
	var journal string
	p := newPanel(t, func(c *Config) {
		c.Recovered = selfupdate.Outcome{Kind: selfupdate.OutcomeUpdated, From: "v0.4.0", To: "v0.5.0"}
		journal = filepath.Join(c.DataDir, "run", "selfupdate.json")
		if err := os.MkdirAll(filepath.Dir(journal), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(journal, []byte(`{"from":"v0.4.0","to":"v0.5.0","at":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	r := serve(t, p.srv)
	r.ready()
	eventually(t, "the update to be recorded", func() bool {
		events, err := p.srv.db.ListEvents(context.Background(), 50, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Kind == selfupdate.EventUpdated {
				return true
			}
		}
		return false
	})
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the journal is left: %v", err)
	}

	p.srv.restart <- struct{}{}
	select {
	case err := <-r.done:
		if !errors.Is(err, selfupdate.ErrRestart) {
			t.Fatalf("Serve: %v, want ErrRestart", err)
		}
	case <-time.After(waitFor):
		t.Fatal("Serve did not stop for the restart")
	}
	r.once.Do(func() {}) // stopped already
}
