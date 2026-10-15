package nodes

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"aead.dev/minisign"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// kitSigner is a release key made for one test.
type kitSigner struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newKitSigner(t *testing.T) *kitSigner {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &kitSigner{pub: pub, priv: priv}
}

func (s *kitSigner) keys(set release.KeySet) ([]minisign.PublicKey, error) {
	if set == release.ReleaseKeys {
		return []minisign.PublicKey{s.pub}, nil
	}
	return nil, release.ErrNoKeys
}

func (s *kitSigner) sign(t *testing.T, data []byte, version, arch string) []byte {
	t.Helper()
	sig, err := release.Sign(bytes.NewReader(data), s.priv, release.Signed{Component: "postern-node", Version: version, OS: "linux", Arch: arch})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// fakeReleases is the cache of releases: one binary, as a file.
type fakeReleases struct {
	t      *testing.T
	data   []byte
	err    error
	called []string
}

func (r *fakeReleases) OpenNode(_ context.Context, version, arch string) (io.ReadCloser, []byte, error) {
	r.called = append(r.called, version+"/"+arch)
	if r.err != nil {
		return nil, nil, r.err
	}
	p := filepath.Join(r.t.TempDir(), "postern-node")
	if err := os.WriteFile(p, r.data, 0o600); err != nil {
		r.t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		r.t.Fatal(err)
	}
	return f, []byte("cached sig"), nil
}

func readAllClose(t *testing.T, r io.ReadCloser) []byte {
	t.Helper()
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestKitSourcePicksTheImageKit(t *testing.T) {
	kit := newTestKit(t, "amd64")
	s := newKitSigner(t)
	kit.write("amd64/postern-node.minisig", 0o644, s.sign(t, kit.read("amd64/postern-node"), "v0.5.0", "amd64"))
	rel := &fakeReleases{t: t, data: []byte("cached")}
	src := &PanelKit{Dir: kit.dir, Version: "v0.5.0", Releases: rel, Keys: s.keys}
	r, sig, version, err := src.NodeBinary(context.Background(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got := readAllClose(t, r); !bytes.Equal(got, kit.read("amd64/postern-node")) || version != "v0.5.0" || len(sig) == 0 {
		t.Errorf("NodeBinary: version %q, the image kit's bytes: %v", version, bytes.Equal(got, kit.read("amd64/postern-node")))
	}
	if len(rel.called) != 0 {
		t.Errorf("the cache was asked: %v", rel.called)
	}
	if err := src.Known("v0.5.0", "amd64"); err != nil {
		t.Errorf("Known: %v", err)
	}
}

func TestKitSourcePicksTheCache(t *testing.T) {
	kit := newTestKit(t, "amd64")
	s := newKitSigner(t)
	// The image kit is of another version than the panel that runs.
	kit.write("amd64/postern-node.minisig", 0o644, s.sign(t, kit.read("amd64/postern-node"), "v0.4.0", "amd64"))
	rel := &fakeReleases{t: t, data: []byte("the cached v0.5.0")}
	src := &PanelKit{Dir: kit.dir, Version: "v0.5.0", Releases: rel, Keys: s.keys}
	r, _, version, err := src.NodeBinary(context.Background(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got := readAllClose(t, r); string(got) != "the cached v0.5.0" || version != "v0.5.0" {
		t.Errorf("NodeBinary = %q, version %q, want the cache's", got, version)
	}
	// The kit download sends it too.
	svc := NewService(nil, [32]byte{}, nil, nil, nil, WithKitDir(kit.dir), WithKitSource(src))
	k, err := svc.OpenKitFor(context.Background(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if got, _ := io.ReadAll(k.Files[0]); string(got) != "the cached v0.5.0" || k.Files[0].Size != int64(len(got)) {
		t.Errorf("the kit's binary = %q (size %d), want the cache's", got, k.Files[0].Size)
	}
}

func TestKitSourceFallsBackToTheImageKit(t *testing.T) {
	kit := newTestKit(t, "amd64") // unsigned
	logs := &lockedBuffer{}
	rel := &fakeReleases{t: t, err: errors.New("no release source")}
	src := &PanelKit{Dir: kit.dir, Version: "v0.5.0", Releases: rel, Keys: newKitSigner(t).keys,
		Log: slog.New(slog.NewTextHandler(logs, nil))}
	r, _, version, err := src.NodeBinary(context.Background(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got := readAllClose(t, r); !bytes.Equal(got, kit.read("amd64/postern-node")) || version != "" {
		t.Errorf("NodeBinary: version %q, want the image kit without a version", version)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "version may differ") {
		t.Errorf("no warning that the versions differ: %s", logs.String())
	}
	// Without a cache of releases, the unsigned kit is no binary of a version.
	src.Releases = nil
	if err := src.Known("v0.5.0", "amd64"); err == nil {
		t.Error("Known of an unsigned kit without a cache: nil")
	}
	if _, _, err := src.Signed(context.Background(), "v0.5.0", "amd64"); !errors.Is(err, ErrNoBinary) {
		t.Errorf("Signed of an unsigned kit: %v, want ErrNoBinary", err)
	}
}

func TestGetInfoOfUpdatesIsStoredAndShown(t *testing.T) {
	n := &store.Node{}
	info := &nodev1.GetInfoResponse{
		AgentVersion: "v0.5.0", Healthy: true, Warnings: []string{"edge-handoff-unsafe"},
		Binaries: &nodev1.NodeBinaries{Versions: []string{"v0.4.0", "v0.5.0"}, Current: "v0.5.0", Previous: "v0.4.0"},
	}
	if changed, _ := takeInfo(n, info); !changed {
		t.Fatal("takeInfo: no change")
	}
	if changed, _ := takeInfo(n, info); changed {
		t.Error("takeInfo of the same answer: a change")
	}
	healthy := &store.Node{}
	takeInfo(healthy, info)
	info.Healthy = false
	if changed, _ := takeInfo(healthy, info); !changed {
		t.Error("takeInfo: healthy going false is no change")
	}
	// The versions with a kept signature, for the plan of an edge-only roll.
	info.Binaries.SignedVersions = []string{"v0.5.0"}
	if changed, _ := takeInfo(healthy, info); !changed || !slices.Equal(healthy.HostInfo.Binaries.Signed, []string{"v0.5.0"}) {
		t.Errorf("takeInfo of a kept signature: changed %v, signed %v", changed, healthy.HostInfo.Binaries.Signed)
	}
	p := toProto(n, "stable")
	if p.GetPreviousAgentVersion() != "v0.4.0" || !p.GetHealthy() ||
		strings.Join(p.GetNodeBinaries(), ",") != "v0.4.0,v0.5.0" || strings.Join(p.GetWarnings(), ",") != "edge-handoff-unsafe" {
		t.Errorf("Node = %v", p)
	}
}
