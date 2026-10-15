package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/urbnywrt/postern/internal/release"
)

func TestAssetNames(t *testing.T) {
	if got := NodeAsset("amd64"); got != "postern-node-linux-amd64" {
		t.Errorf("NodeAsset: %q", got)
	}
	if got := PanelAsset("arm64"); got != "postern-panel-linux-arm64" {
		t.Errorf("PanelAsset: %q", got)
	}
	for name, want := range map[string]string{
		"postern-node-linux-amd64":    "postern-node/amd64",
		"postern-panel-linux-arm64":   "postern-panel/arm64",
		"postern-node-linux-386":      "",
		"postern-node-linux-amd64/":   "",
		"../postern-node-linux-amd64": "",
		"SHA256SUMS":                  "",
		"engines-stable.json":         "",
	} {
		comp, arch, ok := ParseAsset(name)
		got := ""
		if ok {
			got = comp + "/" + arch
		}
		if got != want {
			t.Errorf("ParseAsset(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCachePutAndOpen(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	c := &Cache{Dir: t.TempDir(), Keys: s.keys}
	bin := elfBin(t, "amd64", "node")
	sig := s.sign(t, bin, "postern-node", "v0.5.0", "amd64")

	if err := c.Put(ctx, "v0.5.0", NodeAsset("amd64"), bytes.NewReader(bin), sig); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "v0.5.0", "postern-node-linux-amd64.minisig")); err != nil {
		t.Fatalf("the signature is not kept next to the asset: %v", err)
	}
	rc, gotSig, err := c.Open("v0.5.0", NodeAsset("amd64"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(data, bin) || !bytes.Equal(gotSig, sig) {
		t.Fatalf("Open gave other bytes (err %v)", err)
	}
	if _, _, err := c.Open("v0.5.0", NodeAsset("arm64")); !errors.Is(err, ErrNotCached) {
		t.Errorf("Open of a missing asset: %v, want ErrNotCached", err)
	}

	// A tampered file is not opened: Open verifies again.
	p := filepath.Join(c.Dir, "v0.5.0", "postern-node-linux-amd64")
	if err := os.WriteFile(p, append(bin, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Open("v0.5.0", NodeAsset("amd64")); !errors.Is(err, release.ErrBadSignature) {
		t.Errorf("Open of a tampered asset: %v, want ErrBadSignature", err)
	}
}

func TestCachePutRefuses(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	other := newSigner(t)
	amd := elfBin(t, "amd64", "node")
	cases := []struct {
		name    string
		version string
		asset   string
		data    []byte
		sig     []byte
		want    error
	}{
		{"bad signature", "v0.5.0", NodeAsset("amd64"), amd, other.sign(t, amd, "postern-node", "v0.5.0", "amd64"), release.ErrUntrustedKey},
		{"changed data", "v0.5.0", NodeAsset("amd64"), append(amd[:len(amd):len(amd)], 'x'), s.sign(t, amd, "postern-node", "v0.5.0", "amd64"), release.ErrBadSignature},
		{"another arch in the comment", "v0.5.0", NodeAsset("amd64"), amd, s.sign(t, amd, "postern-node", "v0.5.0", "arm64"), release.ErrWrongArtifact},
		{"a panel binary under a node name", "v0.5.0", NodeAsset("amd64"), amd, s.sign(t, amd, "postern-panel", "v0.5.0", "amd64"), release.ErrWrongArtifact},
		{"another version", "v0.5.0", NodeAsset("amd64"), amd, s.sign(t, amd, "postern-node", "v0.5.1", "amd64"), release.ErrWrongArtifact},
		{"unknown asset", "v0.5.0", "postern-node-linux-386", amd, s.sign(t, amd, "postern-node", "v0.5.0", "amd64"), ErrUnknownAsset},
		{"a path as the asset", "v0.5.0", "../postern-node-linux-amd64", amd, s.sign(t, amd, "postern-node", "v0.5.0", "amd64"), ErrUnknownAsset},
		{"an invalid version", "v0.5.0 x", NodeAsset("amd64"), amd, s.sign(t, amd, "postern-node", "v0.5.0", "amd64"), ErrBadVersion},
		{"not an ELF", "v0.5.0", NodeAsset("amd64"), []byte("#!/bin/sh\n"), s.sign(t, []byte("#!/bin/sh\n"), "postern-node", "v0.5.0", "amd64"), release.ErrNotELF},
		{"an ELF of the other arch", "v0.5.0", NodeAsset("amd64"), elfBin(t, "arm64", "n"), s.sign(t, elfBin(t, "arm64", "n"), "postern-node", "v0.5.0", "amd64"), release.ErrWrongArch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Cache{Dir: t.TempDir(), Keys: s.keys}
			err := c.Put(ctx, tc.version, tc.asset, bytes.NewReader(tc.data), tc.sig)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Put: %v, want %v", err, tc.want)
			}
			if entries, _ := os.ReadDir(c.Dir); len(entries) != 0 {
				t.Errorf("something was kept: %s", entries[0].Name())
			}
		})
	}
}

func TestCacheFetch(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	host := newFakeHost(t)
	amd, arm := elfBin(t, "amd64", "a"), elfBin(t, "arm64", "b")
	host.put("/dl/v0.5.0/postern-node-linux-amd64", amd)
	host.put("/dl/v0.5.0/postern-node-linux-amd64.minisig", s.sign(t, amd, "postern-node", "v0.5.0", "amd64"))
	host.put("/dl/v0.5.0/postern-node-linux-arm64", arm)
	host.put("/dl/v0.5.0/postern-node-linux-arm64.minisig", s.sign(t, arm, "postern-node", "v0.5.0", "arm64"))
	host.put("/api/v1/repos/o/r/releases", []byte(`[{"tag_name":"v0.5.0","assets":[`+
		`{"name":"postern-node-linux-amd64","browser_download_url":"`+host.url("/dl/v0.5.0/postern-node-linux-amd64")+`"},`+
		`{"name":"postern-node-linux-amd64.minisig","browser_download_url":"`+host.url("/dl/v0.5.0/postern-node-linux-amd64.minisig")+`"},`+
		`{"name":"postern-node-linux-arm64","browser_download_url":"`+host.url("/dl/v0.5.0/postern-node-linux-arm64")+`"},`+
		`{"name":"postern-node-linux-arm64.minisig","browser_download_url":"`+host.url("/dl/v0.5.0/postern-node-linux-arm64.minisig")+`"}]}]`))
	src := &Source{Kind: "gitea", APIBase: host.srv.URL, Repo: "o/r", Token: "tkn", http: host.srv.Client()}
	c := &Cache{Dir: t.TempDir(), Keys: s.keys}

	if err := c.Fetch(ctx, src, "v0.5.0", []string{NodeAsset("amd64"), NodeAsset("arm64")}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, a := range []string{NodeAsset("amd64"), NodeAsset("arm64")} {
		rc, _, err := c.Open("v0.5.0", a)
		if err != nil {
			t.Fatalf("Open %s after Fetch: %v", a, err)
		}
		_ = rc.Close()
	}
	// Fetch of a version the source has not got.
	if err := c.Fetch(ctx, src, "v0.6.0", []string{NodeAsset("amd64")}); !errors.Is(err, ErrNoRelease) {
		t.Errorf("Fetch of an unknown version: %v, want ErrNoRelease", err)
	}
	// The token went to the Gitea host (API and downloads are on the same host here).
	if got := host.authOf("/dl/v0.5.0/postern-node-linux-amd64"); len(got) == 0 || got[0] != "token tkn" {
		t.Errorf("the download did not carry the token of its host: %q", got)
	}
}
