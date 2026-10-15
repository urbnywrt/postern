//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/release"
)

// The releases that TestVersions changes to.
var (
	// goodTelemt is the real telemt of proxies.DefaultTelemtVersion under a
	// version of its own, newer than the built-in one; or the upstream release
	// that POSTERN_E2E_TELEMT_VERSION names (overrides.go).
	goodTelemt = cmp.Or(overrideOf("telemt"), "3.5.90")
	// badTelemt is the stand-in (testdata/badengine): it passes the trial run
	// of the node and exits as an engine. With an override it is above any
	// upstream release.
	badTelemt = badTelemtVersion()
	// mtgVersion is the mtg that proxy B switches to: the built-in one, or the
	// upstream release that POSTERN_E2E_MTG_VERSION names.
	mtgVersion = cmp.Or(overrideOf("mtg"), builtinMTG)
)

// builtinMTG is the version of mtg that the panel pins.
const builtinMTG = "v2.2.8"

func badTelemtVersion() string {
	if overrideOf("telemt") != "" {
		return "999.0.1"
	}
	return "3.5.91"
}

// releaseHost is a GitHub of the run on 127.0.0.1, for the panel's
// POSTERN_GITHUB_API: the release lists of the components, in GitHub's
// shape, and their downloads.
//
//   - /repos/telemt/telemt/releases lists goodTelemt and badTelemt, each with
//     its archive for the architecture of the run and the .sha256 file next to
//     it (no digest: the checksum file is the expected SHA-256); with an
//     override (overrides.go) the release list of the component has the
//     upstream release, with the bytes and the checksum file of upstream;
//   - /repos/urbnywrt/postern/releases lists updateVersion and nodeVersion,
//     each with postern-node-linux-<arch> and its signature;
//   - the release list of any other repository is empty, so the panel knows
//     only its built-in versions of them (mtg v2.2.8 among them, which it
//     downloads from GitHub itself);
//   - /download/<tag>/<file> are the files;
//   - anything else is 404: there is no stable list.
type releaseHost struct {
	base string
	srv  *http.Server

	mu    sync.Mutex
	feeds map[string][]map[string]any // the release list of a repository, by owner/name
	files map[string][]byte           // by <tag>/<file>
}

// releasesPath is the path of the release list of a repository.
var releasesPath = regexp.MustCompile(`^/repos/([^/]+/[^/]+)/releases$`)

// versionBinaries makes sure the run has what TestVersions needs beside the
// node and panel binaries, and skips the test when it does not: a run that
// was given its binaries without them.
func (e *env) versionBinaries() {
	e.t.Helper()
	for _, f := range []struct{ name, path string }{
		{"POSTERN_E2E_NODE_UPDATE_BIN", e.updateBin},
		{"POSTERN_E2E_BADENGINE_BIN", e.badEngineBin},
		{"POSTERN_E2E_RELEASE_KEY", e.releaseKey},
	} {
		if f.path == "" {
			e.skipf("%s is not set: TestVersions needs the binaries and the key that scripts/e2e.sh makes", f.name)
		}
		if info, err := os.Stat(f.path); err != nil || !info.Mode().IsRegular() {
			e.fatalf("%s=%s: not a file (%v)", f.name, f.path, err)
		}
	}
}

// startReleaseHost builds what the release host serves and starts it. The
// real telemt comes from GitHub, checked against the SHA-256 that the panel
// pins for it.
func (e *env) startReleaseHost() *releaseHost {
	e.t.Helper()
	arch := runtime.GOARCH
	comp, ok := releases.ComponentOf("telemt")
	if !ok {
		e.fatalf("the panel knows no component telemt")
	}
	badBin, err := os.ReadFile(e.badEngineBin)
	if err != nil {
		e.fatalf("%v", err)
	}
	h := e.newReleaseHost()
	builds := []struct {
		version string
		binary  []byte
	}{{badTelemt, badBin}}
	if overrideOf("telemt") != "" {
		e.addUpstream(h, "telemt", goodTelemt)
	} else {
		builds = append(builds, struct {
			version string
			binary  []byte
		}{goodTelemt, e.realTelemt(comp, arch)})
	}
	if overrideOf("mtg") != "" {
		e.addUpstream(h, "mtg", mtgVersion)
	}
	for _, r := range builds {
		archive, err := tarGz(comp.MemberPath(r.version, arch), r.binary)
		if err != nil {
			e.fatalf("packing telemt %s: %v", r.version, err)
		}
		file := comp.AssetName(r.version, arch)
		sum := sha256.Sum256(archive)
		sums := []byte(hex.EncodeToString(sum[:]) + "  " + file + "\n")
		h.add(comp.Repo, r.version, map[string][]byte{file: archive, comp.SumsFile(r.version, file): sums})
	}

	// The node binaries, signed: the update, and the version that the node is
	// installed with, for the way back to it.
	nodeFile := "postern-node-linux-" + arch
	for _, b := range []struct{ version, path string }{{updateVersion, e.updateBin}, {nodeVersion, e.nodeBin}} {
		node, err := os.ReadFile(b.path)
		if err != nil {
			e.fatalf("%v", err)
		}
		h.add("urbnywrt/postern", b.version, map[string][]byte{nodeFile: node, nodeFile + ".minisig": e.signNode(node, b.version, arch)})
	}
	real := "the real " + proxies.DefaultTelemtVersion
	if overrideOf("telemt") != "" {
		real = "from upstream"
	}
	e.logf("the release host serves at %s: telemt %s (%s) and %s (the stand-in), mtg %s, postern-node %s and %s for %s",
		h.base, goodTelemt, real, badTelemt, mtgVersion, updateVersion, nodeVersion, arch)
	return h
}

// newReleaseHost starts a release host that serves no release yet.
func (e *env) newReleaseHost() *releaseHost {
	e.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.fatalf("%v", err)
	}
	h := &releaseHost{base: "http://" + ln.Addr().String(), feeds: map[string][]map[string]any{}, files: map[string][]byte{}}
	h.srv = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = h.srv.Serve(ln) }()
	e.t.Cleanup(func() { _ = h.srv.Close() })
	return h
}

// add puts a release of repo with the files as its assets into its release
// list, newest first, and serves the files.
func (h *releaseHost) add(repo, tag string, files map[string][]byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.feeds[repo] = append([]map[string]any{h.release(tag, files)}, h.feeds[repo]...)
}

// release returns a release of GitHub's API with the files as its assets,
// which it serves. Called with h.mu held.
func (h *releaseHost) release(tag string, files map[string][]byte) map[string]any {
	var assets []map[string]any
	for name, data := range files {
		h.files[tag+"/"+name] = data
		assets = append(assets, map[string]any{
			"name":                 name,
			"browser_download_url": h.base + "/download/" + tag + "/" + name,
			"size":                 len(data),
			"created_at":           time.Now().UTC().Format(time.RFC3339),
		})
	}
	return map[string]any{
		"tag_name":     tag,
		"draft":        false,
		"prerelease":   false,
		"published_at": time.Now().UTC().Format(time.RFC3339),
		"body":         "A release of the end-to-end test.",
		"html_url":     h.base + "/releases/" + tag,
		"assets":       assets,
	}
}

func (h *releaseHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := releasesPath.FindStringSubmatch(r.URL.Path); m != nil {
		feed := h.feeds[m[1]]
		if feed == nil {
			feed = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mustJSON(feed))
		return
	}
	if name, ok := strings.CutPrefix(r.URL.Path, "/download/"); ok {
		if data, ok := h.files[name]; ok {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(data)
			return
		}
	}
	http.NotFound(w, r)
}

// realTelemt downloads the telemt release that the panel pins for arch,
// checks it against the pinned SHA-256 and returns its binary.
func (e *env) realTelemt(comp releases.Component, arch string) []byte {
	e.t.Helper()
	ver := proxies.DefaultTelemtVersion
	want, ok := releases.BuiltinSHA("telemt", ver, arch)
	if !ok {
		e.fatalf("the panel pins no telemt %s for %s", ver, arch)
	}
	u := comp.DownloadURL(ver, comp.AssetName(ver, arch))
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		e.fatalf("%v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.fatalf("downloading telemt %s: %v", ver, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		e.fatalf("downloading telemt %s: %s", ver, resp.Status)
	}
	archive, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		e.fatalf("downloading telemt %s: %v", ver, err)
	}
	if sum := sha256.Sum256(archive); hex.EncodeToString(sum[:]) != want {
		e.fatalf("telemt %s for %s does not have the SHA-256 that the panel pins", ver, arch)
	}
	bin, err := tarGzMember(archive, comp.MemberPath(ver, arch))
	if err != nil {
		e.fatalf("telemt %s: %v", ver, err)
	}
	return bin
}

// signNode signs a node binary with the throwaway key of the run, as the
// release job signs one (release.Sign).
func (e *env) signNode(binary []byte, ver, arch string) []byte {
	e.t.Helper()
	text, err := os.ReadFile(e.releaseKey)
	if err != nil {
		e.fatalf("%v", err)
	}
	var priv minisign.PrivateKey
	if err := priv.UnmarshalText(text); err != nil {
		e.fatalf("the release key of the run is not an unencrypted minisign secret key")
	}
	sig, err := release.Sign(bytes.NewReader(binary), priv, release.Signed{Component: "postern-node", Version: ver, OS: "linux", Arch: arch})
	if err != nil {
		e.fatalf("signing postern-node %s: %v", ver, err)
	}
	return sig
}

// tarGz packs data as the one file member of a new tar.gz archive.
func tarGz(member string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: member, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Now(),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// tarGzMember returns the regular file member of a tar.gz archive.
func tarGzMember(archive []byte, member string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("the archive has no file %s", member)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && path.Clean(strings.TrimPrefix(h.Name, "./")) == member {
			return io.ReadAll(io.LimitReader(tr, 256<<20))
		}
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
