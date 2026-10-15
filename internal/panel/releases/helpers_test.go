package releases

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// staticELF returns the headers of a static ELF64 little-endian program for
// arch ("amd64" or "arm64"), with a body that makes images differ by tag.
func staticELF(t testing.TB, arch, tag string) []byte {
	t.Helper()
	return elfImage(t, arch, elf.PT_LOAD, tag)
}

// dynamicELF is staticELF with a PT_INTERP header: a dynamically linked program.
func dynamicELF(t testing.TB, arch, tag string) []byte {
	t.Helper()
	return elfImage(t, arch, elf.PT_INTERP, tag)
}

func elfImage(t testing.TB, arch string, prog elf.ProgType, tag string) []byte {
	t.Helper()
	machine := elf.EM_X86_64
	if arch == "arm64" {
		machine = elf.EM_AARCH64
	}
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	var buf bytes.Buffer
	put := func(v any) {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	put(elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT),
		Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: 1})
	put(elf.Prog64{Type: uint32(prog), Flags: uint32(elf.PF_R)})
	buf.WriteString("body:" + tag)
	buf.Write(bytes.Repeat([]byte{0xcc}, 128))
	return buf.Bytes()
}

// A member is a file to put into a test archive.
type member struct {
	name string
	data []byte
	typ  byte   // tar: the type flag; 0 is a regular file
	link string // tar: the target of a link
	mode uint32 // zip: mode bits other than regular, 0 for a regular file
}

func tarGz(t testing.TB, members ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range members {
		hdr := &tar.Header{Name: m.name, Mode: 0o755, Size: int64(len(m.data)), Typeflag: m.typ, Linkname: m.link}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write(m.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipBytes(t testing.TB, members ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		fh := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		fh.SetMode(0o755 | fs.FileMode(m.mode))
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// A fakeHost serves files by path and records the requests it got.
type fakeHost struct {
	t     testing.TB
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
	auth  map[string]string // the Authorization header of the last request per path
	// status answers a path with that status and no body; before runs before
	// a path is served (a hook for a slow download).
	status map[string]int
	before func(path string)
}

func newFakeHost(t testing.TB) *fakeHost {
	t.Helper()
	h := &fakeHost{t: t, files: map[string][]byte{}, hits: map[string]int{}, auth: map[string]string{}, status: map[string]int{}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.hits[r.URL.Path]++
		h.auth[r.URL.Path] = r.Header.Get("Authorization")
		data, ok := h.files[r.URL.Path]
		status, before := h.status[r.URL.Path], h.before
		h.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		if before != nil {
			before(r.URL.Path)
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *fakeHost) put(path string, data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[path] = data
}

func (h *fakeHost) hitCount(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

func (h *fakeHost) url(path string) string { return h.srv.URL + path }

// A testCatalog is a catalog on a fresh database with a fake download host.
type testCatalog struct {
	*Catalog
	db   *store.DB
	host *fakeHost
	dir  string
}

func newTestCatalog(t testing.TB) *testCatalog {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	host := newFakeHost(t)
	dir := t.TempDir()
	c := New(Config{DB: db, Dir: dir, HTTP: host.srv.Client(), APIBase: host.url("/api"),
		Log: slog.New(slog.NewTextHandler(testWriter{t}, nil))})
	return &testCatalog{Catalog: c, db: db, host: host, dir: dir}
}

type testWriter struct{ t testing.TB }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

// release stores an upstream release of comp with one asset for arch, served by
// the fake host at /dl/<version>/<file>, pinned with sha of source when sha is
// not empty.
func (tc *testCatalog) release(t testing.TB, comp, version, arch, archive string, archiveData []byte, sha, source string) *store.Release {
	t.Helper()
	path := "/dl/" + version + "/" + archive
	tc.host.put(path, archiveData)
	rel := &store.Release{Engine: comp, Version: version, Tag: version, Source: store.SourceUpstream,
		Assets: map[string]store.ReleaseAsset{arch: {File: archive, URL: tc.host.url(path), SHA256: sha, SHASource: source}}}
	if err := tc.db.UpsertRelease(context.Background(), rel); err != nil {
		t.Fatal(err)
	}
	return rel
}

// sums serves a checksum file of the sha256sum shape next to the archive.
func (tc *testCatalog) sums(version, archive, sha string) {
	tc.host.put("/dl/"+version+"/"+archive+".sha256", []byte(sha+"  "+archive+"\n"))
}

func (tc *testCatalog) assetOf(t testing.TB, comp, version, arch string) store.ReleaseAsset {
	t.Helper()
	rel, err := tc.db.ReleaseOf(context.Background(), comp, version)
	if err != nil {
		t.Fatal(err)
	}
	return rel.Assets[arch]
}

func (tc *testCatalog) events(t testing.TB, kind string) []*store.Event {
	t.Helper()
	evs, err := tc.db.ListEvents(context.Background(), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []*store.Event
	for _, e := range evs {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// A fakeAPI is a GitHub- or Gitea-shaped release API with pages.
type fakeAPI struct {
	srv   *httptest.Server
	pages map[string]apiPage // by page number ("1", "2", ...)
	etag  string
	hits  atomic.Int64
	last  atomic.Pointer[http.Request]
	reset time.Time // when set, every request is a 403 with X-RateLimit-Reset
	// bigAbove makes every page asked for with more than this per_page
	// larger than the page limit; 0 is off.
	bigAbove int
	// nextLink, when set, is the Link rel="next" of every page instead of the
	// one on the fake's own host.
	nextLink string
}

type apiPage struct {
	body string
	next bool
}

func newFakeAPI(t testing.TB) *fakeAPI {
	t.Helper()
	a := &fakeAPI{pages: map[string]apiPage{}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		a.last.Store(r.Clone(context.Background()))
		if !a.reset.IsZero() {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(a.reset.Unix()))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		if per, _ := strconv.Atoi(r.URL.Query().Get("per_page")); a.bigAbove > 0 && per > a.bigAbove {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[" + strings.Repeat(" ", maxFeedPage) + "]"))
			return
		}
		if a.etag != "" && page == "1" {
			w.Header().Set("ETag", a.etag)
			if r.Header.Get("If-None-Match") == a.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		p, ok := a.pages[page]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if p.next {
			n := 0
			_, _ = fmt.Sscan(page, &n)
			per := r.URL.Query().Get("per_page")
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=%s&page=%d>; rel="next", <%s%s?per_page=%s&page=9>; rel="last"`,
				a.srv.URL, r.URL.Path, per, n+1, a.srv.URL, r.URL.Path, per))
			if a.nextLink != "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, a.nextLink))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(p.body))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAPI) github(repo string) FeedSource {
	return FeedSource{Kind: SourceGitHub, APIBase: a.srv.URL, Repo: repo}
}

// ghRelease is one GitHub release as JSON.
func ghRelease(tag string, prerelease, draft bool, assets ...string) string {
	var as []string
	for _, a := range assets {
		as = append(as, fmt.Sprintf(`{"name":%q,"browser_download_url":"https://example.com/%s/%s","digest":"sha256:%s","size":3,"created_at":"2026-10-01T00:00:00Z"}`,
			a, tag, a, sum([]byte(a))))
	}
	return fmt.Sprintf(`{"tag_name":%q,"draft":%v,"prerelease":%v,"published_at":"2026-10-01T12:00:00Z","body":"notes of %s","html_url":"https://example.com/r/%s","assets":[%s]}`,
		tag, draft, prerelease, tag, tag, joinStrings(as))
}

func joinStrings(ss []string) string {
	var b bytes.Buffer
	for i, s := range ss {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(s)
	}
	return b.String()
}

func list(items ...string) string { return "[" + joinStrings(items) + "]" }
