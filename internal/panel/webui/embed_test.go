package webui

import (
	"bytes"
	"io/fs"
	"testing"
)

func TestFSHasAnIndex(t *testing.T) {
	index, err := fs.ReadFile(FS(), "index.html")
	if err != nil {
		t.Fatalf("index.html: %v", err)
	}
	lower := bytes.ToLower(index)
	if !bytes.HasPrefix(lower, []byte("<!doctype html>")) || !bytes.Contains(lower, []byte("<title>")) {
		t.Errorf("index.html is not a page: %.80q", index)
	}
}

// What is committed is the placeholder. A developer who has built the UI into
// dist/ has the real page there, which is no failure.
func TestPlaceholder(t *testing.T) {
	index, err := fs.ReadFile(FS(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(index, []byte("<script")) {
		t.Skip("dist/ holds a built UI, not the placeholder")
	}
	if !bytes.Contains(index, []byte("Postern UI not built")) {
		t.Errorf("the placeholder does not say that the UI is not built: %s", index)
	}
}
