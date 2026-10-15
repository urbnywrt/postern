package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/store"
)

func keyPath(p *panel) string { return filepath.Join(p.keysDir, "master.key") }

func readKey(t *testing.T, path string) []byte {
	t.Helper()
	key, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A new installation, whose database is empty, makes its key, and its CA with it.
func TestNewInstallationMakesTheKey(t *testing.T) {
	p := newPanel(t)

	info, err := os.Stat(keyPath(p))
	if err != nil {
		t.Fatalf("there is no master key: %v", err)
	}
	if info.Size() != 32 {
		t.Errorf("the key is %d bytes, want 32", info.Size())
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the key has mode %v, want 0600", info.Mode().Perm())
	}
	if dir, err := os.Stat(p.keysDir); err != nil || dir.Mode().Perm() != 0o700 {
		t.Errorf("the key directory: %v, %v; want mode 0700", dir, err)
	}
	if db, err := os.Stat(filepath.Join(p.dataDir, "postern.db")); err != nil || db.Mode().Perm() != 0o600 {
		t.Errorf("the database: %v, %v; want a file of mode 0600", db, err)
	}
	if _, err := os.Stat(filepath.Join(p.dataDir, "master.key")); err == nil {
		t.Error("the key was put next to the database, not in its own directory")
	}

	// The CA exists, so the database now holds sealed data.
	has, err := p.srv.db.HasSealedData(context.Background())
	if err != nil || !has {
		t.Errorf("HasSealedData = %v, %v after the first start, want true", has, err)
	}
	// The key is not in the log, and a notice to keep it is.
	if logs := p.logs.String(); strings.Contains(logs, string(readKey(t, keyPath(p)))) {
		t.Error("the log holds the key")
	}
	if logs := p.logs.String(); !strings.Contains(logs, "master key") || !strings.Contains(logs, keyPath(p)) {
		t.Errorf("the log does not say that a master key was made, and where: %s", logs)
	}
}

// A restart keeps the key and the CA.
func TestRestartKeepsTheKeyAndTheCA(t *testing.T) {
	p := newPanel(t)
	first := readKey(t, keyPath(p))
	b := p.signIn()
	_, bundle := b.createNode("n1")
	_, tarBefore := b.get(bundle)
	if err := p.srv.Close(); err != nil {
		t.Fatal(err)
	}
	p.ts.Close()

	p.start()
	if second := readKey(t, keyPath(p)); !bytes.Equal(first, second) {
		t.Error("the restart replaced the key")
	}
	// Same admin, and the same bundle: the CA and the node certificate came back
	// from the database, opened with the same key.
	jar := p.browser()
	if _, err := jar.auth.Login(context.Background(), loginRequest()); err != nil {
		t.Fatalf("Login after the restart: %v", err)
	}
	_, tarAfter := jar.get(bundle)
	if tarBefore != tarAfter {
		t.Error("the bundle of the node is not the same after the restart")
	}
	if logs := p.logs.String(); strings.Count(logs, "made the master key") != 1 {
		t.Errorf("the log says %d times that the key was made, want once", strings.Count(logs, "made the master key"))
	}
}

// The key is lost, the database is not: never make a new one over the secrets.
func TestRefusesToStartWithoutTheKeyWhenTheDatabaseHoldsSealedData(t *testing.T) {
	p := newPanel(t)
	key := readKey(t, keyPath(p))
	if err := p.srv.Close(); err != nil {
		t.Fatal(err)
	}
	p.ts.Close()
	if err := os.Remove(keyPath(p)); err != nil {
		t.Fatal(err)
	}

	srv, err := New(p.cfg)
	if err == nil {
		_ = srv.Close()
		t.Fatal("New succeeded without the key")
	}
	for _, want := range []string{keyPath(p), "sealed", "will not make a new key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	if _, err := os.Stat(keyPath(p)); err == nil {
		t.Error("a key was made over the secrets that are in the database")
	}

	// With the key back, it starts, and nothing was lost.
	if err := os.WriteFile(keyPath(p), key, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err = New(p.cfg)
	if err != nil {
		t.Fatalf("New with the key restored: %v", err)
	}
	_ = srv.Close()
}

// Anything that the key seals counts, not only the CA.
func TestRefusesToStartWithoutTheKeyForEachKindOfSealedValue(t *testing.T) {
	for _, c := range []struct {
		name string
		put  func(t *testing.T, db *store.DB)
	}{
		{"a TOTP secret", func(t *testing.T, db *store.DB) {
			a := &store.Admin{Username: "alice", PasswordHash: "hash", TOTPSecretEnc: []byte("sealed")}
			if err := db.CreateAdmin(context.Background(), a); err != nil {
				t.Fatal(err)
			}
		}},
		{"the key of a node", func(t *testing.T, db *store.DB) {
			if err := db.CreateNode(context.Background(), &store.Node{Name: "n", KeyEnc: []byte("sealed")}); err != nil {
				t.Fatal(err)
			}
		}},
		{"the CA", func(t *testing.T, db *store.DB) {
			if err := db.PutSetting(context.Background(), "pki.ca", map[string]string{"cert_pem": "x"}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := Config{DataDir: filepath.Join(dir, "data"), KeysDir: filepath.Join(dir, "keys")}
			db, err := store.Open(filepath.Join(cfg.DataDir, "postern.db"))
			if err != nil {
				t.Fatal(err)
			}
			c.put(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			srv, err := New(cfg)
			if err == nil {
				_ = srv.Close()
				t.Fatal("New succeeded without a key over sealed data")
			}
			if !strings.Contains(err.Error(), "will not make a new key") {
				t.Errorf("the error is not the clear one: %v", err)
			}
			if _, err := os.Stat(filepath.Join(cfg.KeysDir, "master.key")); err == nil {
				t.Error("a key was made")
			}
		})
	}
}

// A database that exists but holds nothing sealed, say because the first start
// stopped before it got that far, is a new installation.
func TestStartsWithoutTheKeyWhenTheDatabaseHoldsNothingSealed(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: filepath.Join(dir, "data"), KeysDir: filepath.Join(dir, "keys")}
	db, err := store.Open(filepath.Join(cfg.DataDir, "postern.db"))
	if err != nil {
		t.Fatal(err)
	}
	// An admin with a password but no TOTP: nothing of it is sealed.
	if err := db.CreateAdmin(context.Background(), &store.Admin{Username: "alice", PasswordHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if info, err := os.Stat(filepath.Join(cfg.KeysDir, "master.key")); err != nil || info.Size() != 32 {
		t.Errorf("the key was not made: %v, %v", info, err)
	}
}

// A key that is there but is not the one that sealed the data must not be
// taken for it: the CA does not open, and the panel stops, rather than make a
// new CA that no node trusts.
func TestRefusesAKeyThatDoesNotOpenTheData(t *testing.T) {
	p := newPanel(t)
	if err := p.srv.Close(); err != nil {
		t.Fatal(err)
	}
	p.ts.Close()
	other := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(keyPath(p), other, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(p.cfg)
	if err == nil {
		_ = srv.Close()
		t.Fatal("New succeeded with a key that does not open the CA")
	}
	if got := readKey(t, keyPath(p)); !bytes.Equal(got, other) {
		t.Error("the key file was changed")
	}
}

// A key file that is damaged is an error, and is not replaced.
func TestRefusesAKeyFileOfTheWrongSize(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: filepath.Join(dir, "data"), KeysDir: filepath.Join(dir, "keys")}
	if err := os.MkdirAll(cfg.KeysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	short := []byte("not a key")
	path := filepath.Join(cfg.KeysDir, "master.key")
	if err := os.WriteFile(path, short, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err == nil {
		_ = srv.Close()
		t.Fatal("New succeeded with a key of 9 bytes")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, short) {
		t.Error("the key file was changed")
	}
}

func TestNewNeedsTheDirectories(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no data directory": {KeysDir: t.TempDir()},
		"no key directory":  {DataDir: t.TempDir()},
	} {
		if srv, err := New(cfg); err == nil {
			_ = srv.Close()
			t.Errorf("%s: New succeeded", name)
		}
	}
}
