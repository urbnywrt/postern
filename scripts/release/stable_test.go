package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/release"
)

// fakeAPI is a GitHub of the test: the release lists of the repositories, in
// the shape of GitHub's API, and their files. A repository it has no list of
// has none (an empty list). mu orders the test's writes before the reads of
// the server's goroutines: the script that makes the requests is another
// process, which gives the race detector no happens-before.
type fakeAPI struct {
	srv   *httptest.Server
	mu    sync.Mutex
	feeds map[string][]map[string]any // by owner/name
	files map[string][]byte           // by path
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{feeds: map[string][]map[string]any{}, files: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if repo, ok := strings.CutPrefix(r.URL.Path, "/repos/"); ok && strings.HasSuffix(repo, "/releases") {
			list := f.feeds[strings.TrimSuffix(repo, "/releases")]
			if list == nil {
				list = []map[string]any{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		if data, ok := f.files[r.URL.Path]; ok {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// release adds a release of repo with the files, and digests for the ones
// named in digests.
func (f *fakeAPI) release(repo, tag string, prerelease bool, files map[string][]byte, digests map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var assets []map[string]any
	for name, data := range files {
		p := "/download/" + repo + "/" + tag + "/" + name
		f.files[p] = data
		a := map[string]any{"name": name, "browser_download_url": f.srv.URL + p, "size": len(data)}
		if d, ok := digests[name]; ok {
			a["digest"] = "sha256:" + d
		}
		assets = append(assets, a)
	}
	f.feeds[repo] = append(f.feeds[repo], map[string]any{
		"tag_name": tag, "prerelease": prerelease, "draft": false,
		"published_at": time.Now().UTC().Format(time.RFC3339), "assets": assets,
	})
}

// telemtRelease adds a telemt release whose archives hold the program, with
// the .sha256 files that sums gives (the right ones when it is nil).
func (f *fakeAPI) telemtRelease(t *testing.T, tag string, prerelease bool, program map[string][]byte, sums func(file, sha string) string) {
	t.Helper()
	files := map[string][]byte{}
	for _, arch := range []struct{ arch, file string }{
		{"amd64", "telemt-x86_64-linux-musl.tar.gz"}, {"arm64", "telemt-aarch64-linux-musl.tar.gz"},
	} {
		archive := tarGzOf(t, "telemt", program[arch.arch])
		files[arch.file] = archive
		sha := sha256Hex(archive)
		if sums != nil {
			sha = sums(arch.file, sha)
		}
		files[arch.file+".sha256"] = []byte(sha + "  " + arch.file + "\n")
	}
	f.release("telemt/telemt", tag, prerelease, files, nil)
}

func tarGzOf(t *testing.T, member string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// goodPrograms are static programs of both architectures.
func goodPrograms() map[string][]byte {
	return map[string][]byte{"amd64": staticELF(elf.EM_X86_64), "arm64": staticELF(elf.EM_AARCH64)}
}

func readCandidates(t *testing.T, path string) candidatesFile {
	t.Helper()
	var f candidatesFile
	if err := json.Unmarshal(readFile(t, path), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCandidates(t *testing.T) {
	api := newFakeAPI(t)
	good := goodPrograms()
	wrongArch := map[string][]byte{"amd64": staticELF(elf.EM_AARCH64), "arm64": staticELF(elf.EM_AARCH64)}
	api.telemtRelease(t, "3.5.12", false, good, nil)      // older than the built-in 3.5.13
	api.telemtRelease(t, "3.5.13", false, good, nil)      // the built-in one
	api.telemtRelease(t, "3.5.15", false, good, nil)      // the candidate
	api.telemtRelease(t, "3.5.16", false, wrongArch, nil) // not a program of amd64
	api.telemtRelease(t, "3.5.17", false, good, func(string, string) string { return strings.Repeat("0", 64) })
	api.telemtRelease(t, "3.5.18-rc.1", true, good, nil) // a prerelease
	env := map[string]string{envGitHubAPI: api.srv.URL}
	out := filepath.Join(t.TempDir(), "candidates.json")

	r := tool(t, env, "candidates", "--out", out)
	if r.code != 0 {
		t.Fatalf("candidates: %v", r)
	}
	f := readCandidates(t, out)
	if len(f.Candidates) != 1 || f.Candidates[0].Component != "telemt" || f.Candidates[0].Version != "3.5.15" {
		t.Fatalf("the candidates are %+v, want telemt 3.5.15 alone (the other repositories have no release); %v", f.Candidates, r)
	}
	c := f.Candidates[0]
	for arch, file := range map[string]string{"amd64": "telemt-x86_64-linux-musl.tar.gz", "arm64": "telemt-aarch64-linux-musl.tar.gz"} {
		want := sha256Hex(api.files["/download/telemt/telemt/3.5.15/"+file])
		if a := c.Assets[arch]; a.File != file || a.SHA256 != want {
			t.Errorf("the asset of %s is %+v, want %s with the SHA-256 of the download", arch, a, file)
		}
	}
	var skippedVersions []string
	for _, s := range f.Skipped {
		skippedVersions = append(skippedVersions, s.Version+": "+s.Reason)
	}
	got := strings.Join(skippedVersions, "\n")
	if len(f.Skipped) != 2 || !strings.Contains(got, "3.5.17: ") || !strings.Contains(got, "SHA-256") ||
		!strings.Contains(got, "3.5.16: ") || !strings.Contains(got, "EM_AARCH64") {
		t.Errorf("the skipped releases are\n%s\nwant 3.5.17 (its checksum file disagrees) and 3.5.16 (not a program of amd64)", got)
	}
	if !strings.Contains(r.stdout, "candidate telemt 3.5.15\n") || !strings.Contains(r.stdout, "skipped telemt 3.5.17: ") {
		t.Errorf("the output does not say what was found:\n%s", r.stdout)
	}

	t.Run("newer than the stable list only", func(t *testing.T) {
		list := filepath.Join(t.TempDir(), "engines-stable.json")
		writeFile(t, list, []byte(`{"schema":1,"generated_at":5,"components":{"telemt":[{"version":"3.5.15","assets":{}}]}}`))
		r := tool(t, env, "candidates", "--stable", list, "--component", "telemt", "--out", out)
		if r.code != 0 {
			t.Fatalf("candidates: %v", r)
		}
		if f := readCandidates(t, out); len(f.Candidates) != 0 || len(f.Skipped) != 2 {
			t.Fatalf("with 3.5.15 stable the candidates are %+v and the skipped %+v, want none and 3.5.16, 3.5.17", f.Candidates, f.Skipped)
		}
	})

	t.Run("a digest decides, and the checksum file has to agree", func(t *testing.T) {
		api := newFakeAPI(t)
		archive := tarGzOf(t, "mtg-2.3.0-linux-amd64/mtg", staticELF(elf.EM_X86_64))
		archiveArm := tarGzOf(t, "mtg-2.3.0-linux-arm64/mtg", staticELF(elf.EM_AARCH64))
		files := map[string][]byte{
			"mtg-2.3.0-linux-amd64.tar.gz": archive, "mtg-2.3.0-linux-arm64.tar.gz": archiveArm,
			"mtg-2.3.0-checksums.txt": []byte(sha256Hex(archive) + "  mtg-2.3.0-linux-amd64.tar.gz\n" +
				sha256Hex(archiveArm) + "  mtg-2.3.0-linux-arm64.tar.gz\n"),
		}
		api.release("9seconds/mtg", "v2.3.0", false, files, map[string]string{
			"mtg-2.3.0-linux-amd64.tar.gz": strings.Repeat("1", 64), // the API says otherwise
		})
		r := tool(t, map[string]string{envGitHubAPI: api.srv.URL}, "candidates", "--component", "mtg", "--out", out)
		if r.code != 0 {
			t.Fatalf("candidates: %v", r)
		}
		f := readCandidates(t, out)
		if len(f.Candidates) != 0 || len(f.Skipped) != 1 || !strings.Contains(f.Skipped[0].Reason, "disagrees with the digest") {
			t.Fatalf("candidates %+v, skipped %+v; want v2.3.0 skipped for the digest", f.Candidates, f.Skipped)
		}
	})

	t.Run("the command line", func(t *testing.T) {
		if r := tool(t, env, "candidates"); r.code != 2 || !strings.Contains(r.stderr, "--out is missing") {
			t.Errorf("without --out: %v", r)
		}
		if r := tool(t, env, "candidates", "--component", "nginx", "--out", out); r.code != 2 {
			t.Errorf("an unknown component: %v", r)
		}
	})
}

// candidatesOf writes a file of candidates, each component@version with the
// SHA-256 sha for both architectures.
func candidatesOf(t *testing.T, dir, sha string, cands ...string) string {
	t.Helper()
	var f candidatesFile
	for _, cv := range cands {
		component, ver, _ := strings.Cut(cv, "@")
		f.Candidates = append(f.Candidates, candidate{Component: component, stableEntry: stableEntry{Version: ver, Assets: map[string]stableAsset{
			"amd64": {File: "a.tar.gz", SHA256: sha}, "arm64": {File: "b.tar.gz", SHA256: sha},
		}}})
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, fmt.Sprintf("candidates-%d.json", time.Now().UnixNano()))
	writeFile(t, path, data)
	return path
}

func readList(t *testing.T, path string) stableList {
	t.Helper()
	var l stableList
	if err := json.Unmarshal(readFile(t, path), &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func versionsOf(l stableList, component string) string {
	var vs []string
	for _, e := range l.Components[component] {
		vs = append(vs, e.Version)
	}
	return strings.Join(vs, " ")
}

func TestStableAdd(t *testing.T) {
	dir := t.TempDir()
	sha1, sha2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	list := filepath.Join(dir, "engines-stable.json")
	cands := candidatesOf(t, dir, sha1, "telemt@3.5.20", "telemt@3.5.9", "mtg@v2.3.0", "xray@v26.4.1")

	// A list made from nothing with the candidates that passed (xray did not),
	// its versions sorted however they come.
	r := tool(t, nil, "stable-add", "--from", cands, "--out", list, "telemt@3.5.20", "telemt@3.5.9", "mtg@v2.3.0")
	if r.code != 0 {
		t.Fatalf("stable-add: %v", r)
	}
	l := readList(t, list)
	if l.Schema != 1 || versionsOf(l, "telemt") != "3.5.9 3.5.20" || versionsOf(l, "mtg") != "v2.3.0" || len(l.Components["xray"]) != 0 {
		t.Fatalf("the list has schema %d, telemt %q, mtg %q, xray %q", l.Schema, versionsOf(l, "telemt"), versionsOf(l, "mtg"), versionsOf(l, "xray"))
	}

	// The same candidate again is no change; a version with another SHA-256
	// is refused, and the list stays as it is.
	r = tool(t, nil, "stable-add", "--list", list, "--from", cands, "--out", list, "telemt@3.5.20")
	if r.code != 0 || !strings.Contains(r.stdout, "kept telemt 3.5.20") || versionsOf(readList(t, list), "telemt") != "3.5.9 3.5.20" {
		t.Fatalf("adding a version that is there: %v", r)
	}
	before := readFile(t, list)
	other := candidatesOf(t, dir, sha2, "telemt@3.5.20", "telemt@3.5.21")
	r = tool(t, nil, "stable-add", "--list", list, "--from", other, "--out", list, "telemt@3.5.20")
	if r.code != 1 || !strings.Contains(r.stderr, "never changes") || !bytes.Equal(readFile(t, list), before) {
		t.Fatalf("a stable version with another SHA-256: %v", r)
	}

	// A version goes only by --drop.
	r = tool(t, nil, "stable-add", "--list", list, "--from", other, "--drop", "telemt@3.5.9", "--drop", "mtg@v2.3.0", "--out", list, "telemt@3.5.21")
	if r.code != 0 {
		t.Fatalf("stable-add --drop: %v", r)
	}
	l = readList(t, list)
	if versionsOf(l, "telemt") != "3.5.20 3.5.21" || len(l.Components["mtg"]) != 0 {
		t.Fatalf("after the drops the list has telemt %q, mtg %q", versionsOf(l, "telemt"), versionsOf(l, "mtg"))
	}
	before = readFile(t, list)
	for name, c := range map[string]struct {
		code int
		args []string
	}{
		"a drop of a version that is not there": {1, []string{"--drop", "telemt@1.0.0"}},
		"a drop without a version":              {2, []string{"--drop", "telemt"}},
		"a candidate that is not one":           {1, []string{"--from", cands, "telemt@9.9.9"}},
		"a candidate without --from":            {2, []string{"telemt@3.5.20"}},
		"an unknown component":                  {1, []string{"--from", candidatesOf(t, dir, sha1, "nginx@1.0.0"), "nginx@1.0.0"}},
		"no version":                            {1, []string{"--from", candidatesOf(t, dir, sha1, "telemt@x y"), "telemt@x y"}},
		"a short SHA-256":                       {1, []string{"--from", candidatesOf(t, dir, "abc", "telemt@3.6.0"), "telemt@3.6.0"}},
	} {
		args := append([]string{"stable-add", "--list", list, "--out", list}, c.args...)
		if r := tool(t, nil, args...); r.code != c.code {
			t.Errorf("%s: %v, want exit %d", name, r, c.code)
		}
	}
	if !bytes.Equal(readFile(t, list), before) {
		t.Error("a refused stable-add changed the list")
	}
}

func TestStableSign(t *testing.T) {
	dir := t.TempDir()
	stableKey, stablePub := newKey(t, testPassword)
	_, releasePub := newKey(t, "")
	list := filepath.Join(dir, "engines-stable.json")
	writeFile(t, list, []byte(`{"schema":1,"generated_at":1700000000,"components":{}}`))

	before := time.Now().Unix()
	r := tool(t, withPassword(testPassword), "stable-sign", "--key", stableKey, list)
	if r.code != 0 {
		t.Fatalf("stable-sign: %v", r)
	}
	l := readList(t, list)
	if l.GeneratedAt < before || l.GeneratedAt > time.Now().Unix() || strings.TrimSpace(r.stdout) != strconv.FormatInt(l.GeneratedAt, 10) {
		t.Fatalf("generated_at %d (printed %q), want now", l.GeneratedAt, r.stdout)
	}
	want := release.Signed{Component: "engines-stable", Version: strconv.FormatInt(l.GeneratedAt, 10)}
	if err := verify(t, list, want, stablePub); err != nil {
		t.Fatalf("the signature of the stable key: %v", err)
	}
	if err := verify(t, list, want, releasePub); err == nil {
		t.Fatal("the signature verifies with another key, a release key")
	}
	// The tool's verify says the same.
	if r := tool(t, nil, "verify", "--pubkey", stablePub.String(), "--component", "engines-stable", "--version", want.Version, list); r.code != 0 {
		t.Errorf("verify with the stable key: %v", r)
	}
	if r := tool(t, nil, "verify", "--pubkey", releasePub.String(), "--component", "engines-stable", "--version", want.Version, list); r.code != 1 {
		t.Errorf("verify with a release key: %v", r)
	}

	// A list dated in the future gets a later date still: a panel takes only
	// a newer list.
	future := time.Now().Add(time.Hour).Unix()
	writeFile(t, list, []byte(fmt.Sprintf(`{"schema":1,"generated_at":%d,"components":{}}`, future)))
	if r := tool(t, withPassword(testPassword), "stable-sign", "--key", stableKey, list); r.code != 0 || readList(t, list).GeneratedAt != future+1 {
		t.Fatalf("stable-sign of a list from the future: %v, generated_at %d", r, readList(t, list).GeneratedAt)
	}
	if r := tool(t, nil, "stable-sign", "--key", stableKey, filepath.Join(dir, "none.json")); r.code != 1 {
		t.Errorf("stable-sign of no list: %v", r)
	}
}

// TestStableScriptDryRun runs scripts/stable.sh --dry-run against the fake
// API: it finds the candidates, makes the list they would give, and signs and
// uploads nothing.
func TestStableScriptDryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the tool")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	api := newFakeAPI(t)
	api.telemtRelease(t, "3.5.15", false, goodPrograms(), nil)
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cmd := exec.Command(bash, filepath.Join(root, "scripts", "stable.sh"), "--dry-run", out)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), envGitHubAPI+"="+api.srv.URL, "POSTERN_STABLE_LIST_URL="+api.srv.URL+"/none",
		"GITHUB_OUTPUT=", "POSTERN_STABLE_KEY=", "POSTERN_STABLE_KEY_PASSWORD=")
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stable.sh --dry-run: %v\n%s", err, data)
	}
	if !strings.Contains(string(data), "candidate telemt 3.5.15") || !strings.Contains(string(data), "dry run") {
		t.Errorf("the dry run does not say what it found:\n%s", data)
	}
	l := readList(t, filepath.Join(out, "engines-stable.json"))
	if versionsOf(l, "telemt") != "3.5.15" {
		t.Errorf("the list of the dry run has telemt %q, want 3.5.15", versionsOf(l, "telemt"))
	}
	if exists(filepath.Join(out, "engines-stable.json.minisig")) {
		t.Error("the dry run signed the list")
	}
}
