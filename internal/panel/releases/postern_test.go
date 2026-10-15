package releases

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// The Postern components (psiphon-core) are in the release of Postern that the
// panel is: the seed names that release on the release source, and a build that
// is no release names none.
func TestSeedPosternComponent(t *testing.T) {
	ctx := context.Background()
	comp, _ := ComponentOf("psiphon-core")
	if !comp.Postern || !comp.Pinned || comp.Assets["arm64"] != "psiphon-core-linux-arm64" {
		t.Fatalf("psiphon-core = %+v", comp)
	}
	var b BuiltinRelease
	for _, r := range Builtins() {
		if r.Component == comp.Name {
			b = r
		}
	}

	tc := newTestCatalog(t)
	tc.posternTag = PosternTag("v1.2.3")
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	rel, err := tc.db.ReleaseOf(ctx, comp.Name, b.Version)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Tag != "v1.2.3" || rel.URL != "https://github.com/urbnywrt/postern/releases/tag/v1.2.3" ||
		rel.Assets["arm64"].URL != "https://github.com/urbnywrt/postern/releases/download/v1.2.3/psiphon-core-linux-arm64" {
		t.Errorf("seeded %+v", rel)
	}

	// A later panel, on a Gitea: the release of that panel.
	if err := tc.db.PutReleaseSource(ctx, store.ReleaseSource{Kind: SourceGitea, BaseURL: "https://git.example.com/", Repo: "ops/postern"}); err != nil {
		t.Fatal(err)
	}
	tc.posternTag = PosternTag("v1.3.0")
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	rel, _ = tc.db.ReleaseOf(ctx, comp.Name, b.Version)
	if rel.Tag != "v1.3.0" || rel.Assets["amd64"].URL != "https://git.example.com/ops/postern/releases/download/v1.3.0/psiphon-core-linux-amd64" ||
		rel.Assets["amd64"].SHA256 != b.Assets["amd64"].SHA256 {
		t.Errorf("reseeded %+v", rel)
	}

	for _, v := range []string{"dev", "", "1.2.3", "v1.2.3 x"} {
		if got := PosternTag(v); got != "" {
			t.Errorf("PosternTag(%q) = %q", v, got)
		}
	}
}

// A Postern component is prepared only with a signature of the release of
// Postern that holds it, by a release key, for its component, tag and
// architecture: a wrong one is a verdict, one that cannot be fetched is not.
func TestPreparePosternComponentChecksTheSignature(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bin := staticELF(t, "amd64", "psiphon")
	sign := func(s release.Signed) []byte {
		t.Helper()
		sig, err := release.Sign(bytes.NewReader(bin), priv, s)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	good := release.Signed{Component: "psiphon-core", Version: "v1.2.3", OS: "linux", Arch: "amd64"}

	for _, tc := range []struct {
		name   string
		sig    []byte // nil: none served
		want   error
		reason string
	}{
		{"good", sign(good), nil, ""},
		{"another architecture", sign(release.Signed{Component: "psiphon-core", Version: "v1.2.3", OS: "linux", Arch: "arm64"}), ErrUnusable, "signature"},
		{"another release", sign(release.Signed{Component: "psiphon-core", Version: "v1.2.2", OS: "linux", Arch: "amd64"}), ErrUnusable, "signature"},
		{"another component", sign(release.Signed{Component: "postern-node", Version: "v1.2.3", OS: "linux", Arch: "amd64"}), ErrUnusable, "signature"},
		{"no signature", nil, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCatalog(t)
			c.keys = func(set release.KeySet) ([]minisign.PublicKey, error) {
				if set != release.ReleaseKeys {
					return nil, errors.New("not the release keys")
				}
				return []minisign.PublicKey{pub}, nil
			}
			path := "/dl/v1.2.3/psiphon-core-linux-amd64"
			c.host.put(path, bin)
			if tc.sig != nil {
				c.host.put(path+".minisig", tc.sig)
			}
			rel := &store.Release{Engine: "psiphon-core", Version: "20990101-abcdef1234", Tag: "v1.2.3", Source: store.SourceStable,
				Assets: map[string]store.ReleaseAsset{"amd64": {File: "psiphon-core-linux-amd64", URL: c.host.url(path), SHA256: sum(bin), SHASource: store.SHASourceStable}}}
			if err := c.db.UpsertRelease(ctx, rel); err != nil {
				t.Fatal(err)
			}
			err := c.Prepare(ctx, "psiphon-core", rel.Version, []string{"amd64"})
			a := c.assetOf(t, "psiphon-core", rel.Version, "amd64")
			switch {
			case tc.name == "no signature":
				if err == nil || errors.Is(err, ErrUnusable) || a.State != store.AssetUnchecked {
					t.Errorf("Prepare = %v, state %s; want an error that is no verdict", err, a.State)
				}
			case tc.want == nil:
				if err != nil || a.State != store.AssetReady {
					t.Errorf("Prepare = %v, state %s", err, a.State)
				}
			default:
				if !errors.Is(err, tc.want) || a.State != store.AssetUnusable || !strings.Contains(a.Reason, tc.reason) {
					t.Errorf("Prepare = %v, state %s (%s)", err, a.State, a.Reason)
				}
			}
		})
	}
}

// scripts/psiphon-core.env, which the release build reads, and builtin.json name
// the same version: <date of the commit>-<revision of 10 digits>.
func TestPsiphonCorePinsAgree(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "psiphon-core.env"))
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			env[k] = v
		}
	}
	commit, date, ver := env["PSIPHON_CORE_COMMIT"], env["PSIPHON_CORE_DATE"], env["PSIPHON_CORE_VERSION"]
	if len(commit) != 40 || len(date) < 10 {
		t.Fatalf("psiphon-core.env = %v", env)
	}
	if want := strings.ReplaceAll(date[:10], "-", "") + "-" + commit[:10]; ver != want {
		t.Errorf("PSIPHON_CORE_VERSION = %q, want %q", ver, want)
	}
	found := false
	for _, b := range Builtins() {
		if b.Component == "psiphon-core" {
			found = found || b.Version == ver
			if len(b.Assets) != 2 {
				t.Errorf("psiphon-core %s has assets for %d architectures, want amd64 and arm64", b.Version, len(b.Assets))
			}
		}
	}
	if !found {
		t.Errorf("builtin.json pins no psiphon-core %s", ver)
	}
}

// F2 of the real-server pass: a panel that is no release of Postern (a dev or
// an air-gapped one) gets psiphon-core from a release bundle. TakeUploaded
// keeps the binary only when it is the one a release pins for the arch and its
// signature is by a release key for psiphon-core and the arch; Prepare then
// verifies it from the kept signature, with no network, and the nodes get it.
func TestTakeUploadedPosternComponent(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bin := staticELF(t, "amd64", "psiphon")
	sign := func(b []byte, s release.Signed) []byte {
		t.Helper()
		sig, err := release.Sign(bytes.NewReader(b), priv, s)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	good := release.Signed{Component: "psiphon-core", Version: "v1.2.3", OS: "linux", Arch: "amd64"}
	c := newTestCatalog(t)
	c.posternTag = "" // a dev panel: no release holds the file
	c.keys = func(set release.KeySet) ([]minisign.PublicKey, error) {
		if set != release.ReleaseKeys {
			return nil, errors.New("not the release keys")
		}
		return []minisign.PublicKey{pub}, nil
	}
	const ver = "20990101-abcdef1234"
	rel := &store.Release{Engine: "psiphon-core", Version: ver, Source: store.SourceBuiltin,
		Assets: map[string]store.ReleaseAsset{"amd64": {File: "psiphon-core-linux-amd64", SHA256: sum(bin), SHASource: store.SHASourceBuiltin}}}
	if err := c.db.UpsertRelease(ctx, rel); err != nil {
		t.Fatal(err)
	}
	if err := c.Prepare(ctx, "psiphon-core", ver, []string{"amd64"}); err == nil {
		t.Fatal("Prepare without a release and without an upload went through")
	}
	write := func(b []byte) string {
		p := filepath.Join(t.TempDir(), "psiphon-core-linux-amd64")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	kept := filepath.Join(c.dir, "psiphon-core", ver, "psiphon-core-linux-amd64")

	// Refusals keep nothing and leave the asset as it was.
	other := staticELF(t, "amd64", "another build")
	for _, r := range []struct {
		name string
		path string
		sig  []byte
		arch string
		want error
	}{
		{"bytes no release pins", write(other), sign(other, good), "amd64", ErrNotPinned},
		{"a signature for another arch", write(bin), sign(bin, release.Signed{Component: "psiphon-core", Version: "v1.2.3", OS: "linux", Arch: "arm64"}), "amd64", release.ErrWrongArtifact},
		{"a signature for another component", write(bin), sign(bin, release.Signed{Component: "postern-node", Version: "v1.2.3", OS: "linux", Arch: "amd64"}), "amd64", release.ErrWrongArtifact},
		{"no signature", write(bin), []byte("untrusted comment: x\n"), "amd64", release.ErrBadSignature},
		{"an arch no release pins", write(bin), sign(bin, release.Signed{Component: "psiphon-core", Version: "v1.2.3", OS: "linux", Arch: "arm64"}), "arm64", ErrNotPinned},
	} {
		if _, err := c.TakeUploaded(ctx, "psiphon-core", r.arch, r.path, r.sig); !errors.Is(err, r.want) {
			t.Errorf("%s: TakeUploaded = %v, want %v", r.name, err, r.want)
		}
		if a := c.assetOf(t, "psiphon-core", ver, "amd64"); a.State == store.AssetReady || a.State == store.AssetUnusable {
			t.Errorf("%s: the asset is %s", r.name, a.State)
		}
		if _, err := os.Stat(kept); err == nil {
			t.Errorf("%s: the file was kept", r.name)
		}
	}
	if _, err := c.TakeUploaded(ctx, "telemt", "amd64", write(bin), sign(bin, good)); err == nil {
		t.Error("an engine that Postern does not build was taken")
	}

	v, err := c.TakeUploaded(ctx, "psiphon-core", "amd64", write(bin), sign(bin, good))
	if err != nil || v != ver {
		t.Fatalf("TakeUploaded = %q, %v", v, err)
	}
	if a := c.assetOf(t, "psiphon-core", ver, "amd64"); a.State != store.AssetReady {
		t.Fatalf("after the upload the asset is %s (%s)", a.State, a.Reason)
	}
	// Prepare (what EnsureArtifacts and the rollouts call) verifies the kept
	// file with the kept signature, with no network.
	if err := c.Prepare(ctx, "psiphon-core", ver, []string{"amd64"}); err != nil {
		t.Fatalf("Prepare after the upload: %v", err)
	}
	if err := c.Ready(ctx, "psiphon-core", ver, "amd64"); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	r, ref, err := c.Open(ctx, "psiphon-core", ver, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || !bytes.Equal(got, bin) || ref.GetSha256() != sum(bin) || ref.GetBinary() != "psiphon-core" {
		t.Errorf("Open = %d bytes, %v, ref %v", len(got), err, ref)
	}
	// A kept signature that does not verify any more is a verdict.
	if err := os.WriteFile(kept+".minisig", sign(bin, release.Signed{Component: "psiphon-core", Version: "v1.2.3", OS: "linux", Arch: "arm64"}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Recheck(ctx, "psiphon-core", ver, "amd64"); !errors.Is(err, ErrUnusable) {
		t.Errorf("Recheck with a wrong kept signature = %v", err)
	}
}
