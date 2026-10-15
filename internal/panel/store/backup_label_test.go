package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupWithALabel(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "postern.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, bad := range []string{"", "../x", "a/b", "-x"} {
		if _, err := db.Backup(ctx, bad); err == nil {
			t.Errorf("Backup(%q) took the label", bad)
		}
	}
	p, err := db.Backup(ctx, "pre-v0.5.0")
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if filepath.Dir(p) != filepath.Join(dir, "backups") || !strings.HasPrefix(filepath.Base(p), "postern.db.pre-v0.5.0.") || !strings.HasSuffix(p, ".bak") {
		t.Errorf("backup at %s", p)
	}
	if newer, err := NewerSchema(p); err != nil || newer {
		t.Errorf("NewerSchema of the copy: %v %v", newer, err)
	}
	if newer, err := NewerSchema(filepath.Join(dir, "missing.db")); err != nil || newer {
		t.Errorf("NewerSchema of no file: %v %v", newer, err)
	}
}
