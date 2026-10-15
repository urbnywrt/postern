//go:build integration

package trial

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/mtg"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/providers/psiphoncore"
	"github.com/urbnywrt/postern/internal/providers/xray"
)

// The runner image of the node (Global Constraints).
const runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

// itestComponent is one release to try: the pinned checksums of the Global
// Constraints by architecture, or "" to take the checksum from the file
// checksum names.
type itestComponent struct {
	engine, version, binary string
	base                    string
	file                    func(arch string) (string, error)
	sums                    map[string]string
	checksum                string // "<file>.sha256" for telemt's `<hex>  <file>` files
	// local takes the file from localDir instead of downloading it.
	local    bool
	localDir string
	trial    engines.Trial
	wantOK   bool
}

func TestIntegrationTrials(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("no releases for %s", runtime.GOARCH)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	docker := dockerapi.New("")
	if _, err := docker.Ping(ctx); err != nil {
		t.Fatalf("no usable Docker daemon at %s: %v", dockerapi.DefaultSocket, err)
	}
	base, err := os.MkdirTemp("", "postern-itest-trial-")
	if err != nil {
		t.Fatal(err)
	}
	// The container runs as 65534 and must read through the scratch directory.
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	store := &artifacts.Store{Root: filepath.Join(base, "artifacts")}
	r := &Runner{Docker: docker, RunnerImage: runnerImage, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	telemtGNU := func(arch string) (string, error) {
		switch arch {
		case "amd64":
			return "telemt-x86_64-linux-gnu.tar.gz", nil
		case "arm64":
			return "telemt-aarch64-linux-gnu.tar.gz", nil
		}
		return "", errors.New("no such release")
	}
	components := []itestComponent{
		{
			engine: "telemt", version: "3.5.13", binary: "telemt",
			base: "https://github.com/telemt/telemt/releases/download/3.5.13/", file: telemt.New().ArtifactFile,
			sums: map[string]string{
				"amd64": "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43",
				"arm64": "f7b5181f1160e9ec73eb28705040bf159782055ec71f54a20214e2c9a6d997cd",
			},
			trial: telemt.New().Trial("3.5.13"), wantOK: true,
		},
		{
			// The glibc build has a dynamic loader that Alpine has not: Docker
			// cannot exec it ("no such file or directory"), which is a verdict.
			engine: "telemt-gnu", version: "3.5.13", binary: "telemt",
			base: "https://github.com/telemt/telemt/releases/download/3.5.13/", file: telemtGNU,
			checksum: ".sha256",
			trial:    telemt.New().Trial("3.5.13"), wantOK: false,
		},
		{
			engine: "mtg", version: mtg.DefaultVersion, binary: "mtg",
			base: "https://github.com/9seconds/mtg/releases/download/" + mtg.DefaultVersion + "/", file: mtg.New().ArtifactFile,
			sums: map[string]string{
				"amd64": "7ef19d079d85f4e00d4f8334ec1f3f3c8718e3d0ed1f3109ea9a8673138a2102",
				"arm64": "562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644",
			},
			trial: mtg.New().Trial(mtg.DefaultVersion), wantOK: true,
		},
		{
			engine: "xray", version: "v26.3.27", binary: "xray",
			base: "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/", file: xray.New().ArtifactFile,
			sums: map[string]string{
				"amd64": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
				"arm64": "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
			},
			trial: xray.New().Trial("v26.3.27"), wantOK: true,
		},
		{
			// The Psiphon client that a release of Postern builds
			// (scripts/psiphon-core.sh): a local file, from the directory
			// POSTERN_ITEST_PSIPHON_CORE; skipped without it.
			engine: "psiphon-core", version: "20261005-c4a09096ab", binary: "psiphon-core",
			localDir: os.Getenv("POSTERN_ITEST_PSIPHON_CORE"), local: true,
			file: psiphoncore.New().ArtifactFile,
			sums: map[string]string{
				"amd64": "c1767915e1773bd812b64238377de262b135d9aafe097b24e09190ff6e4b0b33",
				"arm64": "eadefe0c157bd6645420e5d63b124e50de223a76206eda788165505555f6b1f8",
			},
			trial: psiphoncore.New().Trial("20261005-c4a09096ab"), wantOK: true,
		},
	}

	for _, c := range components {
		t.Run(c.engine, func(t *testing.T) {
			ref := download(t, ctx, store, c)
			res := r.Run(ctx, store.BinaryPath(ref), ref.Binary, c.trial)
			t.Logf("%s %s: ran=%v ok=%v exit=%d reason=%q\n--- output (%d bytes) ---\n%s\n---",
				c.engine, c.version, res.Ran, res.OK, res.ExitCode, res.Reason, len(res.Output), res.Output)
			if !res.Ran {
				t.Fatalf("the trial did not run: %s", res.Reason)
			}
			if res.OK != c.wantOK {
				t.Errorf("ok = %v, want %v (%s)", res.OK, c.wantOK, res.Reason)
			}
			if n := len(r.InFlight()); n != 0 {
				t.Errorf("InFlight after the run has %d entries", n)
			}
		})
	}

	list, err := docker.List(ctx, Labels, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if strings.HasPrefix(c.Name, namePrefix) && time.Since(c.Created) < 15*time.Minute {
			t.Errorf("trial container left behind: %s (%s)", c.Name, c.Status)
		}
	}
}

// download stores the release of the component for this architecture, verified
// against its checksum. Network trouble skips the test; a mismatch fails it.
func download(t *testing.T, ctx context.Context, store *artifacts.Store, c itestComponent) artifacts.Ref {
	t.Helper()
	file, err := c.file(runtime.GOARCH)
	if err != nil {
		t.Skipf("no %s release for %s: %v", c.engine, runtime.GOARCH, err)
	}
	sum := c.sums[runtime.GOARCH]
	if c.local && c.localDir == "" {
		t.Skipf("set POSTERN_ITEST_PSIPHON_CORE to the directory of scripts/psiphon-core.sh for %s", c.engine)
	}
	if c.checksum != "" {
		line := strings.TrimSpace(string(get(t, ctx, c.base+file+c.checksum, 64<<10)))
		sum = strings.ToLower(strings.Fields(line)[0])
		if b, err := hex.DecodeString(sum); err != nil || len(b) != 32 || !strings.HasSuffix(line, file) {
			t.Fatalf("%s%s is not `<hex>  %s`: %q", file, c.checksum, file, line)
		}
	}
	if sum == "" {
		t.Skipf("no %s checksum is pinned for %s", c.engine, runtime.GOARCH)
	}
	ref := artifacts.Ref{Engine: c.engine, Version: c.version, Arch: runtime.GOARCH, SHA256: sum, FileName: file, Binary: c.binary}
	var body []byte
	if c.local {
		var err error
		if body, err = os.ReadFile(filepath.Join(c.localDir, file)); err != nil {
			t.Fatal(err)
		}
	} else {
		body = get(t, ctx, c.base+file, 200<<20)
	}
	switch err := store.Put(ref, bytes.NewReader(body)); {
	case errors.Is(err, artifacts.ErrChecksum):
		t.Fatalf("the download does not match the pinned checksum: %v", err)
	case err != nil:
		t.Fatalf("storing the release: %v", err)
	}
	return ref
}

func get(t *testing.T, ctx context.Context, url string, limit int64) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		t.Skipf("cannot download %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		t.Skipf("the download of %s did not complete: %v", url, err)
	}
	return b
}
