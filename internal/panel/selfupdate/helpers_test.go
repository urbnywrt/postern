package selfupdate

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/seal"
)

// signer holds a release key pair made for one test (no key enters the
// repository) and the Keys function that gives the cache its public key.
type signer struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

func newSigner(t testing.TB) *signer {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &signer{pub: pub, priv: priv}
}

// keys is the Keys function of a cache: the signer's key for the release set,
// another (unknown) key for the stable set, so that a signature by the release
// key can never pass as a stable one.
func (s *signer) keys(set release.KeySet) ([]minisign.PublicKey, error) {
	if set == release.ReleaseKeys {
		return []minisign.PublicKey{s.pub}, nil
	}
	return nil, release.ErrNoKeys
}

// sign signs data for the component, version and arch (linux).
func (s *signer) sign(t testing.TB, data []byte, component, version, arch string) []byte {
	t.Helper()
	sig, err := release.Sign(bytes.NewReader(data), s.priv, release.Signed{Component: component, Version: version, OS: "linux", Arch: arch})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}

// elfBin is a small static ELF for arch with tag inside, so that two binaries
// differ.
func elfBin(t testing.TB, arch, tag string) []byte {
	t.Helper()
	machine := elf.EM_X86_64
	if arch == "arm64" {
		machine = elf.EM_AARCH64
	}
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	var buf bytes.Buffer
	for _, v := range []any{
		elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT),
			Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: 1},
		elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R)},
	} {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	buf.WriteString(tag)
	buf.Write(bytes.Repeat([]byte{0xcc}, 64))
	return buf.Bytes()
}

// member is one file of a tar.
type member struct {
	name string
	data []byte
}

// tarOf writes members as a tar; truncate drops the trailer and the last bytes.
func tarOf(t testing.TB, members ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A fakeHost serves files by path and records the Authorization header of
// every request, by path.
type fakeHost struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	auth  map[string][]string
}

func newFakeHost(t testing.TB) *fakeHost {
	t.Helper()
	h := &fakeHost{files: map[string][]byte{}, auth: map[string][]string{}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.auth[r.URL.Path] = append(h.auth[r.URL.Path], r.Header.Get("Authorization"))
		data, ok := h.files[r.URL.Path]
		h.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
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

func (h *fakeHost) authOf(path string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.auth[path]...)
}

func (h *fakeHost) url(path string) string { return h.srv.URL + path }

func openDB(t testing.TB) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testKey(t testing.TB) seal.Key {
	t.Helper()
	var key seal.Key
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }
