//go:build integration

package main

// TestReleaseScript runs scripts/release.sh as a release is built, on a copy of
// this repository, and checks what it makes: build and sign one after the
// other, as the jobs of the release workflow run them, sign refusing files that
// the build did not make, and the mode for a workstation, which does both:
//
//	go test -tags integration -count=1 -timeout 30m -run '^TestReleaseScript$' -v ./scripts/release/
//
// It needs bash, git, tar, Go, Node 24 with npm, and the network for npm ci and
// the Go modules. The Panel image job of CI runs it; on a workstation it runs in
// a container that has them (docs/releasing.md). Without one of them it is
// skipped, except where CI is set, where that is a failure. With Docker it also
// builds the panel image of the release (--build-arg PREBUILT=dist) and looks
// at its node kit; without Docker that part is skipped.
//
// The copy is a new git repository of the files of the working tree that git
// would take (changes that are not committed are in it, what .gitignore names is
// not). Its first commit has the tags v0.0.0-test and v0.0.0, and a second one,
// tagged v0.0.1, puts the key of the test into internal/release/keys.go as a
// production release key. The key is made by the test and encrypted with a
// password, and neither is in the output of the script.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/release"
)

// productionKeyLines matches the two production key lists of internal/release/keys.go.
var productionKeyLines = regexp.MustCompile(`(production(?:Release|Stable)Keys) = "[^"]*"`)

func TestReleaseScript(t *testing.T) {
	needReleaseTools(t)
	root := moduleRoot(t)
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	copyWorkingTree(t, root, repo)
	// The production keys of the working tree are not this test's: the copy
	// starts without them, and the test key becomes one below.
	keysGo := filepath.Join(repo, "internal", "release", "keys.go")
	writeFile(t, keysGo, productionKeyLines.ReplaceAll(readFile(t, keysGo), []byte(`$1 = ""`)))

	_, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := publicKey(priv)
	const password = "release test password"
	keyText, err := cheapEncrypt(password, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyEnv := []string{"POSTERN_RELEASE_KEY=" + string(keyText), "POSTERN_RELEASE_KEY_PASSWORD=" + password}
	_, secretLine, _ := strings.Cut(strings.TrimSpace(string(keyText)), "\n")
	secrets := []string{password, secretLine}

	git(t, repo, "init", "-q")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "test: a release of the working tree")
	git(t, repo, "tag", "v0.0.0-test")
	git(t, repo, "tag", "v0.0.0")
	const noKeys = `productionReleaseKeys = ""`
	src := readFile(t, keysGo)
	if bytes.Count(src, []byte(noKeys)) != 1 {
		t.Fatalf("%s does not have one %s", keysGo, noKeys)
	}
	writeFile(t, keysGo, bytes.Replace(src, []byte(noKeys), []byte(`productionReleaseKeys = "`+pub.String()+`"`), 1))
	git(t, repo, "commit", "-q", "-a", "-m", "test: the key of the test is a production key")
	git(t, repo, "tag", "v0.0.1")
	dist := filepath.Join(repo, "dist")

	// The test key goes into the binaries of a prerelease with
	// -X .../internal/release.extraPublicKeys. go version -m does not show
	// -ldflags of a -trimpath build (go.dev/issue/52372), so release.sh says
	// its flags, and the key is looked for in each binary that has the package
	// internal/release in it (a binary that does not use it has none of its
	// variables, and -X sets nothing there).
	const extraFlag = "-X github.com/urbnywrt/postern/internal/release.extraPublicKeys="
	// The default node image of the panel goes into the panel binaries with
	// -X .../internal/version.NodeImage when POSTERN_NODE_IMAGE is set.
	const nodeImageFlag = "-X github.com/urbnywrt/postern/internal/version.NodeImage="
	const nodeImage = "registry.example.com/release-test/postern-node"
	extraEnv := "POSTERN_EXTRA_PUBLIC_KEYS=" + pub.String()
	unsigned := filepath.Join(work, "unsigned")
	var manifestSHA string

	t.Run("build of a prerelease, without the key", func(t *testing.T) {
		out := releaseScript(t, repo, []string{"build", "v0.0.0-test", unsigned}, secrets, extraEnv)
		if out.code != 0 {
			t.Fatalf("release.sh build v0.0.0-test: %v", out)
		}
		t.Logf("release.sh build v0.0.0-test:\n%s%s", out.stdout, out.stderr)
		if !strings.Contains(out.stderr, extraFlag+pub.String()+" ") && !strings.Contains(out.stderr, extraFlag+pub.String()+`"`) {
			t.Errorf("release.sh does not say that it builds with %s<the test key>", extraFlag)
		}
		// Without POSTERN_NODE_IMAGE the panel has no default node image.
		if strings.Contains(out.stderr, nodeImageFlag) {
			t.Errorf("release.sh builds with %s without POSTERN_NODE_IMAGE", nodeImageFlag)
		}
		var got []string
		entries, err := os.ReadDir(unsigned)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if want := append(slices.Clone(buildNames), "MANIFEST"); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
			t.Fatalf("the build holds %q, want %q", got, want)
		}
		manifest := readFile(t, filepath.Join(unsigned, "MANIFEST"))
		for _, name := range buildNames {
			data := readFile(t, filepath.Join(unsigned, name))
			if sum, err := release.SumFor(name, manifest, release.SumsSHA256); err != nil || sum != sha256Hex(data) {
				t.Errorf("MANIFEST for %s: %s, %v; the file has %s", name, sum, err, sha256Hex(data))
			}
			switch {
			case !bytes.Contains(data, []byte("github.com/urbnywrt/postern/internal/release.")):
				t.Logf("%s does not use internal/release yet: no key to look for in it", name)
			case !bytes.Contains(data, []byte(pub.String())):
				t.Errorf("%s does not hold the key of POSTERN_EXTRA_PUBLIC_KEYS", name)
			}
		}
		manifestSHA = sha256Hex(manifest)
		if !strings.Contains(out.stderr, manifestSHA) {
			t.Errorf("release.sh does not say the SHA-256 of MANIFEST, %s", manifestSHA)
		}
	})

	t.Run("sign refuses what the build did not make", func(t *testing.T) {
		shaEnv := "POSTERN_MANIFEST_SHA256=" + manifestSHA
		for _, tt := range []struct {
			name, tag string
			spoil     func(dir string)
			env       []string
			want      string
		}{
			{"another MANIFEST", "v0.0.0-test", nil, []string{"POSTERN_MANIFEST_SHA256=" + strings.Repeat("0", 64)}, "not the MANIFEST of the build"},
			{"no SHA-256 of MANIFEST", "v0.0.0-test", nil, nil, "POSTERN_MANIFEST_SHA256"},
			{"a file that a build does not make", "v0.0.0-test", func(dir string) {
				writeFile(t, filepath.Join(dir, "postern-node-linux-386"), []byte("x"))
			}, []string{shaEnv}, "does not make"},
			{"a binary that was changed", "v0.0.0-test", func(dir string) {
				path := filepath.Join(dir, "postern-panel-linux-arm64")
				writeFile(t, path, append(readFile(t, path), 0))
			}, []string{shaEnv}, "MANIFEST lists"},
			{"the build of another tag", "v0.0.0", nil, []string{shaEnv}, "not a build of the version v0.0.0"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				in := filepath.Join(t.TempDir(), "in")
				copyWorkingTree(t, unsigned, in)
				if tt.spoil != nil {
					tt.spoil(in)
				}
				outDir := filepath.Join(t.TempDir(), "out")
				out := releaseScript(t, repo, []string{"sign", tt.tag, in, outDir}, secrets, append(slices.Clone(keyEnv), tt.env...)...)
				if out.code == 0 || !strings.Contains(out.stderr, tt.want) {
					t.Errorf("%v\nwant a failure that says %q", out, tt.want)
				}
				if exists(outDir) {
					t.Error("sign wrote the release")
				}
			})
		}
	})

	t.Run("sign of the prerelease", func(t *testing.T) {
		out := releaseScript(t, repo, []string{"sign", "v0.0.0-test", unsigned, dist}, secrets,
			append(slices.Clone(keyEnv), extraEnv, "POSTERN_MANIFEST_SHA256="+manifestSHA)...)
		if out.code != 0 {
			t.Fatalf("release.sh sign v0.0.0-test: %v", out)
		}
		t.Logf("release.sh sign v0.0.0-test:\n%s%s", out.stdout, out.stderr)
		checkDist(t, root, dist, "v0.0.0-test", pub)
		for _, name := range buildNames {
			if !bytes.Equal(readFile(t, filepath.Join(dist, name)), readFile(t, filepath.Join(unsigned, name))) {
				t.Errorf("%s of the release is not the file of the build", name)
			}
		}
	})

	t.Run("refused on a workstation", func(t *testing.T) {
		before := snapshot(t, dist)
		for _, tt := range []struct {
			name, tag string
			env       []string
			want      string
		}{
			{"a release with test keys", "v0.0.0", append(slices.Clone(keyEnv), extraEnv), "POSTERN_EXTRA_PUBLIC_KEYS"},
			{"a release signed by a key that is not a production key", "v0.0.0", keyEnv, "production release keys"},
			{"a tag that is not a version", "v1.0", keyEnv, "v1.0"},
			{"a tag that is not there", "v0.0.9", keyEnv, "v0.0.9"},
			{"no key", "v0.0.0-test", nil, "POSTERN_RELEASE_KEY"},
			{"a malformed test key", "v0.0.0-test", append(slices.Clone(keyEnv), "POSTERN_EXTRA_PUBLIC_KEYS=RWQ key"), "POSTERN_EXTRA_PUBLIC_KEYS"},
			{"a node image with a tag", "v0.0.1", append(slices.Clone(keyEnv), "POSTERN_NODE_IMAGE="+nodeImage+":v0.0.1"), "POSTERN_NODE_IMAGE"},
			{"a node image that is not a name", "v0.0.1", append(slices.Clone(keyEnv), "POSTERN_NODE_IMAGE=registry.example.com/x -X y=z"), "POSTERN_NODE_IMAGE"},
			{"a node image with a digest", "v0.0.1", append(slices.Clone(keyEnv), "POSTERN_NODE_IMAGE="+nodeImage+"@sha256:"+strings.Repeat("a", 64)), "POSTERN_NODE_IMAGE"},
			{"a node image in upper case", "v0.0.1", append(slices.Clone(keyEnv), "POSTERN_NODE_IMAGE=Registry.example.com/Release-Test/postern-node"), "POSTERN_NODE_IMAGE"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				out := releaseScript(t, repo, []string{tt.tag}, secrets, tt.env...)
				if out.code == 0 || !strings.Contains(out.stderr, tt.want) {
					t.Errorf("%v\nwant a failure that says %q", out, tt.want)
				}
			})
		}
		if after := snapshot(t, dist); !maps.Equal(before, after) {
			t.Error("a refused run changed dist/")
		}
	})

	t.Run("release with a production key, on a workstation", func(t *testing.T) {
		out := releaseScript(t, repo, []string{"v0.0.1"}, secrets, append(slices.Clone(keyEnv), "POSTERN_NODE_IMAGE="+nodeImage)...)
		if out.code != 0 {
			t.Fatalf("release.sh v0.0.1: %v", out)
		}
		t.Logf("release.sh v0.0.1:\n%s%s", out.stdout, out.stderr)
		if strings.Contains(out.stderr, extraFlag) {
			t.Error("release.sh builds a release with test keys")
		}
		checkDist(t, root, dist, "v0.0.1", pub)
		// The default node image of the panel (version.NodeImage): in both
		// panel binaries, in neither node binary.
		if !strings.Contains(out.stderr, nodeImageFlag+nodeImage) {
			t.Errorf("release.sh does not say that it builds the panel with %s%s", nodeImageFlag, nodeImage)
		}
		for _, a := range arches {
			if !bytes.Contains(readFile(t, filepath.Join(dist, "postern-panel-linux-"+a)), []byte(nodeImage)) {
				t.Errorf("postern-panel-linux-%s does not hold the node image of POSTERN_NODE_IMAGE", a)
			}
			if bytes.Contains(readFile(t, filepath.Join(dist, "postern-node-linux-"+a)), []byte(nodeImage)) {
				t.Errorf("postern-node-linux-%s holds the node image of POSTERN_NODE_IMAGE", a)
			}
		}
	})

	t.Run("panel image of the release", func(t *testing.T) {
		checkImage(t, repo, dist, "v0.0.1")
	})

	t.Run("node image of the release", func(t *testing.T) {
		checkNodeImage(t, repo, dist, "v0.0.1")
	})
}

// needReleaseTools skips the test, or fails it in CI, when a tool of
// release.sh is missing.
func needReleaseTools(t *testing.T) {
	t.Helper()
	missing := func(why string) {
		t.Helper()
		if os.Getenv("CI") != "" {
			t.Fatal(why)
		}
		t.Skip(why + ": run the test where the tools of scripts/release.sh are (docs/releasing.md)")
	}
	for _, name := range []string{"bash", "git", "tar", "go", "node", "npm"} {
		if _, err := exec.LookPath(name); err != nil {
			missing(name + " is not on PATH")
		}
	}
	out, err := exec.Command("node", "--version").Output()
	if err != nil || !strings.HasPrefix(string(out), "v24.") {
		missing("Node 24 is needed, and node --version says " + strings.TrimSpace(string(out)))
	}
}

// moduleRoot returns the root of the module of the test.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for ; ; dir = filepath.Dir(dir) {
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.HasPrefix(data, []byte("module github.com/urbnywrt/postern\n")) {
			return dir
		}
		if filepath.Dir(dir) == dir {
			t.Fatal("the test does not run in the module github.com/urbnywrt/postern")
		}
	}
}

// copyWorkingTree copies the files of the working tree at src to dst: all of
// them but .git and what is built or installed there (bin/, dist/, web/dist/,
// node_modules/), which git would leave out anyway, and which can be large.
func copyWorkingTree(t *testing.T, src, dst string) {
	t.Helper()
	skip := map[string]bool{".git": true, "bin": true, "dist": true, filepath.Join("web", "dist"): true}
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if skip[rel] || d.Name() == "node_modules" || d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, info.Mode().Perm())
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// releaseScript runs scripts/release.sh with args in repo, with the environment
// of the test without its POSTERN_ variables, and env. No string of secrets
// may be in what it prints.
func releaseScript(t *testing.T, repo string, args, secrets []string, env ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	tag := strings.Join(args, " ")
	cmd := exec.CommandContext(ctx, "bash", append([]string{"scripts/release.sh"}, args...)...)
	cmd.Dir = repo
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "POSTERN_") && !strings.HasPrefix(v, "SOURCE_DATE_EPOCH=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("release.sh %s: %v", tag, err)
		}
		code = exit.ExitCode()
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Errorf("release.sh %s printed a secret", tag)
		}
	}
	return result{code, stdout.String(), stderr.String()}
}

// snapshot returns the SHA-256 of every file of dir by its name.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, e := range entries {
		files[e.Name()] = sha256Hex(readFile(t, filepath.Join(dir, e.Name())))
	}
	return files
}

// checkDist checks the release tag in dist: its files, the signatures by pub,
// SHA256SUMS, the bundle, how the binaries were built, and the UI of the panel
// of this machine's architecture.
func checkDist(t *testing.T, root, dist, tag string, pub minisign.PublicKey) {
	t.Helper()
	bundle := "postern-" + tag + "-bundle.tar"
	var want []string
	for _, component := range binaries {
		for _, arch := range arches {
			want = append(want, component+"-linux-"+arch, component+"-linux-"+arch+sigSuffix)
		}
	}
	want = append(want, sumsName, sumsName+sigSuffix)
	inBundle := slices.Clone(want)
	want = append(want, bundle)
	// The Psiphon client, signed, which the bundle leaves out.
	for _, arch := range arches {
		name := psiphonCore + "-linux-" + arch
		want = append(want, name, name+sigSuffix)
		if err := verify(t, filepath.Join(dist, name), release.Signed{Component: psiphonCore, Version: tag, OS: "linux", Arch: arch}, pub); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := checkBinary(filepath.Join(dist, name), psiphonCore, arch, tag, ""); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	slices.Sort(want)
	var got []string
	entries, err := os.ReadDir(dist)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("dist/ holds %q, want %q", got, want)
	}

	sums := readFile(t, filepath.Join(dist, sumsName))
	if err := verify(t, filepath.Join(dist, sumsName), release.Signed{Component: "sha256sums", Version: tag}, pub); err != nil {
		t.Errorf("SHA256SUMS: %v", err)
	}
	for _, component := range binaries {
		for _, arch := range arches {
			name := component + "-linux-" + arch
			path := filepath.Join(dist, name)
			if err := verify(t, path, release.Signed{Component: component, Version: tag, OS: "linux", Arch: arch}, pub); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			data := readFile(t, path)
			if err := release.CheckStaticELF(bytes.NewReader(data), arch); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if sum, err := release.SumFor(name, sums, release.SumsSHA256); err != nil || sum != sha256Hex(data) {
				t.Errorf("SHA256SUMS for %s: %s, %v; the file has %s", name, sum, err, sha256Hex(data))
			}
			// -trimpath leaves -ldflags out of the build information (go.dev/issue/52372),
			// so the flags that it has are what is looked at.
			info, err := exec.Command("go", "version", "-m", path).CombinedOutput()
			if err != nil {
				t.Fatalf("go version -m %s: %v\n%s", name, err, info)
			}
			for _, setting := range []string{"-trimpath=true", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + arch} {
				if !strings.Contains(string(info), "\tbuild\t"+setting+"\n") {
					t.Errorf("go version -m %s has no %s:\n%s", name, setting, info)
				}
			}
		}
	}

	members := readTar(t, filepath.Join(dist, bundle))
	var names []string
	for _, m := range members {
		names = append(names, m.name)
		if !bytes.Equal(m.data, readFile(t, filepath.Join(dist, m.name))) {
			t.Errorf("%s in the bundle is not the file of dist/", m.name)
		}
	}
	slices.Sort(inBundle)
	if !slices.Equal(names, inBundle) {
		t.Errorf("the bundle holds %q, want %q", names, inBundle)
	}

	if runtime.GOOS != "linux" || !slices.Contains(arches, runtime.GOARCH) {
		t.Logf("the panel is not started here (%s/%s)", runtime.GOOS, runtime.GOARCH)
		return
	}
	panel := filepath.Join(dist, "postern-panel-linux-"+runtime.GOARCH)
	if out, err := exec.Command(panel, "version").Output(); err != nil || !strings.HasPrefix(string(out), tag+" (") {
		t.Errorf("postern-panel version: %q, %v; want %s (...)", out, err, tag)
	}
	checkUI(t, root, panel)
}

// checkUI starts the panel on a free port of the loopback and checks that it
// serves the UI that was built, and not the placeholder page of the source.
func checkUI(t *testing.T, root, panel string) {
	t.Helper()
	placeholder := readFile(t, filepath.Join(root, "internal", "panel", "webui", "dist", "index.html"))
	dir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	cmd := exec.Command(panel, "serve")
	cmd.Env = []string{
		"HOME=" + dir,
		"POSTERN_DATA=" + filepath.Join(dir, "data"),
		"POSTERN_KEYS=" + filepath.Join(dir, "keys"),
		"POSTERN_LISTEN=" + addr,
		"POSTERN_NODE_KIT_DIR=" + filepath.Join(dir, "no-kit"),
	}
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("the log of the panel:\n%s", log.String())
		}
	}()

	var body []byte
	client := &http.Client{Timeout: 5 * time.Second}
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		resp, err := client.Get("http://" + addr + "/")
		if err == nil {
			body, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil && resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the panel does not serve / within a minute: %v", err)
		}
	}
	if bytes.Equal(body, placeholder) || bytes.Contains(body, []byte("UI not built")) {
		t.Fatal("the panel serves the placeholder page, not the UI")
	}
	for _, part := range []string{`id="root"`, "/assets/"} {
		if !bytes.Contains(body, []byte(part)) {
			t.Errorf("the page at / has no %s:\n%s", part, body)
		}
	}
}

// checkImage builds the panel image of the release in dist with
// --build-arg PREBUILT=dist and checks that it holds the binaries of dist and
// their signatures, byte for byte.
func checkImage(t *testing.T, repo, dist, tag string) {
	t.Helper()
	image, arch := buildReleaseImage(t, repo, "deploy/panel/Dockerfile")

	if out, err := exec.Command("docker", "run", "--rm", image, "version").Output(); err != nil || !strings.HasPrefix(string(out), tag+" (") {
		t.Errorf("the image says %q, %v; want %s (...)", out, err, tag)
	}

	got := copyFromImage(t, image, "/usr/local/share/postern/node-kit", "/usr/local/bin/postern-panel")

	same := func(inImage, inDist string, mode os.FileMode) {
		t.Helper()
		if !bytes.Equal(readFile(t, filepath.Join(got, inImage)), readFile(t, filepath.Join(dist, inDist))) {
			t.Errorf("%s of the image is not %s of dist/", inImage, inDist)
		}
		checkMode(t, filepath.Join(got, inImage), mode)
	}
	same("postern-panel", "postern-panel-linux-"+arch, 0o755)
	for _, a := range arches {
		same("node-kit/"+a+"/postern-node", "postern-node-linux-"+a, 0o755)
		same("node-kit/"+a+"/postern-node.minisig", "postern-node-linux-"+a+sigSuffix, 0o644)
	}
	for _, script := range []string{"install.sh", "launcher.sh", "compose.yaml"} {
		if !exists(filepath.Join(got, "node-kit", script)) {
			t.Errorf("the node kit has no %s", script)
		}
	}
	var kit []string
	if err := filepath.WalkDir(filepath.Join(got, "node-kit"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(filepath.Join(got, "node-kit"), path)
			kit = append(kit, filepath.ToSlash(rel))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(kit)
	wantKit := []string{"amd64/postern-node", "amd64/postern-node.minisig", "arm64/postern-node", "arm64/postern-node.minisig", "compose.yaml", "install.sh", "launcher.sh"}
	if !slices.Equal(kit, wantKit) {
		t.Errorf("the node kit holds %q, want %q", kit, wantKit)
	}
}

// checkNodeImage builds the node image of the release in dist with
// --build-arg PREBUILT=dist and checks that it holds the binary of dist for the
// architecture of the daemon and its signature, byte for byte, with the
// launcher of deploy/node, and that it starts postern-node bootstrap.
func checkNodeImage(t *testing.T, repo, dist, tag string) {
	t.Helper()
	// The labels that the image job of release.yml passes; with PREBUILT the
	// build arguments VERSION and COMMIT are not given, so only these name
	// the release.
	revision := strings.TrimSpace(git(t, repo, "rev-parse", tag+"^{commit}"))
	const source = "https://git.example.com/owner/postern"
	image, arch := buildReleaseImage(t, repo, "deploy/node/Dockerfile",
		"--label", "org.opencontainers.image.source="+source,
		"--label", "org.opencontainers.image.version="+tag,
		"--label", "org.opencontainers.image.revision="+revision)

	if out, err := exec.Command("docker", "run", "--rm", image, "version").Output(); err != nil || !strings.HasPrefix(string(out), tag+" (") {
		t.Errorf("the image says %q, %v; want %s (...)", out, err, tag)
	}
	for label, want := range map[string]string{
		"org.opencontainers.image.source":   source,
		"org.opencontainers.image.version":  tag,
		"org.opencontainers.image.revision": revision,
		"postern.role":                      "agent",
	} {
		out, err := exec.Command("docker", "image", "inspect", "--format", `{{index .Config.Labels "`+label+`"}}`, image).Output()
		if got := strings.TrimSpace(string(out)); err != nil || got != want {
			t.Errorf("label %s of the image = %q, %v; want %q", label, got, err, want)
		}
	}
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{json .Config.Entrypoint}} {{json .Config.Cmd}}", image).Output()
	if want := `["/usr/local/lib/postern/postern-node"] ["bootstrap"]`; err != nil || strings.TrimSpace(string(out)) != want {
		t.Errorf("the entrypoint and command of the image are %q, %v; want %s", out, err, want)
	}

	got := filepath.Join(copyFromImage(t, image, "/usr/local/lib/postern"), "postern")
	same := func(inImage, want string, mode os.FileMode) {
		t.Helper()
		if !bytes.Equal(readFile(t, filepath.Join(got, inImage)), readFile(t, want)) {
			t.Errorf("%s of the image is not %s", inImage, want)
		}
		checkMode(t, filepath.Join(got, inImage), mode)
	}
	same("postern-node", filepath.Join(dist, "postern-node-linux-"+arch), 0o755)
	same("postern-node.minisig", filepath.Join(dist, "postern-node-linux-"+arch+sigSuffix), 0o644)
	same("launcher.sh", filepath.Join(repo, "deploy", "node", "launcher.sh"), 0o755)
	entries, err := os.ReadDir(got)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"launcher.sh", "postern-node", "postern-node.minisig"}; !slices.Equal(names, want) {
		t.Errorf("/usr/local/lib/postern of the image holds %q, want %q", names, want)
	}
}

// buildReleaseImage builds the image of dockerfile of the release in dist/ of
// repo (--build-arg PREBUILT=dist) for the architecture of the Docker daemon,
// with the arguments extra (labels, say), which it returns with the name of
// the image; the image is removed when the test ends. Without Docker it skips
// the test.
func buildReleaseImage(t *testing.T, repo, dockerfile string, extra ...string) (image, arch string) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("no Docker here (%v): the image of %s of the release is not built", err, dockerfile)
	}
	out, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	arch = map[string]string{"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[strings.TrimSpace(string(out))]
	if arch == "" {
		t.Skipf("the Docker daemon runs on %s", out)
	}

	var id [6]byte
	_, _ = rand.Read(id[:])
	image = "postern-release-test:" + hex.EncodeToString(id[:])
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	args := append([]string{"build", "--build-arg", "PREBUILT=dist", "-f", dockerfile, "-t", image}, extra...)
	build := exec.CommandContext(ctx, "docker", append(args, ".")...)
	build.Dir = repo
	build.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("docker build --build-arg PREBUILT=dist -f %s: %v\n%s", dockerfile, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", image).Run() })
	return image, arch
}

// copyFromImage copies paths out of image into a temporary directory, each
// under its base name, and returns the directory.
func copyFromImage(t *testing.T, image string, paths ...string) string {
	t.Helper()
	created, err := exec.Command("docker", "create", image).Output()
	if err != nil {
		t.Fatal(err)
	}
	container := strings.TrimSpace(string(created))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	got := t.TempDir()
	for _, p := range paths {
		if out, err := exec.Command("docker", "cp", container+":"+p, filepath.Join(got, path.Base(p))).CombinedOutput(); err != nil {
			t.Fatalf("docker cp %s: %v\n%s", p, err, out)
		}
	}
	return got
}
