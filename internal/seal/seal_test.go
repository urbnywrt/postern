package seal_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/seal"
)

// makeKey returns a made-up key of 32 consecutive byte values starting at
// first. No two of the keys below share a byte at any position.
func makeKey(first byte) seal.Key {
	var k seal.Key
	for i := range k {
		k[i] = first + byte(i)
	}
	return k
}

var (
	keyA = makeKey(0x00)
	keyB = makeKey(0x80)
)

const aadAdmin = "totp:01JABCDEFGHJKMNPQRSTVWXYZ0"

func mustSeal(t *testing.T, k seal.Key, plaintext, aad []byte) []byte {
	t.Helper()
	sealed, err := seal.Seal(k, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits and symlinks are not reliable on Windows")
	}
}

// ---------------------------------------------------------------------------
// Seal and Open

func TestSealOpenRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty plaintext, nil aad", nil, nil},
		{"empty plaintext, aad", []byte{}, []byte(aadAdmin)},
		{"text, nil aad", []byte("a secret"), nil},
		{"text, aad", []byte("a secret"), []byte(aadAdmin)},
		{"binary with NUL bytes", []byte{0, 1, 0, 255, 0}, []byte{0}},
		{"1 MiB", bytes.Repeat([]byte("0123456789abcdef"), 1<<16), []byte("big")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sealed := mustSeal(t, keyA, tc.plaintext, tc.aad)

			if want := 1 + 12 + len(tc.plaintext) + 16; len(sealed) != want {
				t.Errorf("len(sealed) = %d, want %d (version, nonce, ciphertext, tag)", len(sealed), want)
			}
			got, err := seal.Open(keyA, sealed, tc.aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("Open returned %d bytes that differ from the %d bytes sealed", len(got), len(tc.plaintext))
			}
		})
	}
}

// TestSealLayout decrypts a sealed value with the standard library alone, so
// that the layout (0x01 || nonce || ciphertext || tag, with the aad as the GCM
// additional data) is pinned independently of Open.
func TestSealLayout(t *testing.T) {
	plaintext := []byte("layout check: a version byte, a nonce, ciphertext and a tag")
	aad := []byte("table.column:42")
	sealed := mustSeal(t, keyA, plaintext, aad)

	if sealed[0] != 0x01 {
		t.Errorf("version byte = %#x, want 0x01", sealed[0])
	}
	block, err := aes.NewCipher(keyA[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, body := sealed[1:13], sealed[13:]
	if len(body) != len(plaintext)+gcm.Overhead() {
		t.Errorf("ciphertext and tag take %d bytes, want %d", len(body), len(plaintext)+gcm.Overhead())
	}
	got, err := gcm.Open(nil, nonce, body, aad)
	if err != nil {
		t.Fatalf("AES-256-GCM cannot open the sealed value with its nonce and aad: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("AES-256-GCM opened the sealed value to a different plaintext")
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("the plaintext appears in the sealed value")
	}
}

func TestSealUsesAFreshNonceEachTime(t *testing.T) {
	const n = 1000
	nonces := make(map[string]struct{}, n)
	for range n {
		sealed := mustSeal(t, keyA, []byte("same plaintext"), []byte("same aad"))
		nonce := string(sealed[1:13])
		if _, reused := nonces[nonce]; reused {
			t.Fatal("two sealed values share a nonce")
		}
		nonces[nonce] = struct{}{}
	}
}

func TestOpenWrongAAD(t *testing.T) {
	sealed := mustSeal(t, keyA, []byte("a secret"), []byte(aadAdmin))

	// The aad that was sealed with opens it.
	if _, err := seal.Open(keyA, sealed, []byte(aadAdmin)); err != nil {
		t.Fatalf("Open with the right aad: %v", err)
	}

	for _, aad := range [][]byte{
		nil,
		{},
		[]byte(aadAdmin[:len(aadAdmin)-1]), // shorter
		[]byte(aadAdmin + " "),             // longer
		[]byte("TOTP" + aadAdmin[4:]),      // case
		[]byte("totp:01JABCDEFGHJKMNPQRSTVWXYZ1"),  // last character
		[]byte("proxy:01JABCDEFGHJKMNPQRSTVWXYZ0"), // another column
		append([]byte{0}, []byte(aadAdmin)...),     // prefixed
	} {
		got, err := seal.Open(keyA, sealed, aad)
		if !errors.Is(err, seal.ErrDecrypt) {
			t.Errorf("Open with aad %q: err = %v, want ErrDecrypt", aad, err)
		}
		if got != nil {
			t.Errorf("Open with aad %q returned %d bytes along with the error", aad, len(got))
		}
	}
}

func TestNilAndEmptyAADAreTheSame(t *testing.T) {
	fromNil := mustSeal(t, keyA, []byte("a secret"), nil)
	if _, err := seal.Open(keyA, fromNil, []byte{}); err != nil {
		t.Errorf("value sealed with nil aad, opened with empty aad: %v", err)
	}
	fromEmpty := mustSeal(t, keyA, []byte("a secret"), []byte{})
	if _, err := seal.Open(keyA, fromEmpty, nil); err != nil {
		t.Errorf("value sealed with empty aad, opened with nil aad: %v", err)
	}
}

func TestOpenWrongKey(t *testing.T) {
	sealed := mustSeal(t, keyA, []byte("a secret"), []byte(aadAdmin))

	got, err := seal.Open(keyB, sealed, []byte(aadAdmin))
	if !errors.Is(err, seal.ErrDecrypt) {
		t.Errorf("Open with another key: err = %v, want ErrDecrypt", err)
	}
	if got != nil {
		t.Errorf("Open with another key returned %d bytes along with the error", len(got))
	}

	// One different byte of the key is enough.
	almost := keyA
	almost[31] ^= 0x01
	if _, err := seal.Open(almost, sealed, []byte(aadAdmin)); !errors.Is(err, seal.ErrDecrypt) {
		t.Errorf("Open with a key that differs in the last byte: err = %v, want ErrDecrypt", err)
	}
}

// TestOpenTamperedByte changes each byte of a sealed value in turn, with three
// different masks: version, nonce, ciphertext and tag must all be protected.
func TestOpenTamperedByte(t *testing.T) {
	aad := []byte(aadAdmin)
	sealed := mustSeal(t, keyA, []byte("tamper with this"), aad)

	for i := range sealed {
		for _, mask := range []byte{0x01, 0x80, 0xFF} {
			tampered := bytes.Clone(sealed)
			tampered[i] ^= mask

			got, err := seal.Open(keyA, tampered, aad)
			want := seal.ErrDecrypt
			if i == 0 {
				want = seal.ErrVersion // the version byte is not authenticated, but it is checked
			}
			if !errors.Is(err, want) {
				t.Errorf("byte %d ^ %#02x: err = %v, want %v", i, mask, err, want)
			}
			if got != nil {
				t.Errorf("byte %d ^ %#02x: Open returned %d bytes along with the error", i, mask, len(got))
			}
		}
	}
}

func TestOpenUnknownVersion(t *testing.T) {
	aad := []byte(aadAdmin)
	sealed := mustSeal(t, keyA, []byte("a secret"), aad)

	// The unmodified value opens, so the failures below come from the version.
	if _, err := seal.Open(keyA, sealed, aad); err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, version := range []byte{0x00, 0x02, 0x03, 0x7F, 0x80, 0xFF} {
		other := bytes.Clone(sealed)
		other[0] = version
		if _, err := seal.Open(keyA, other, aad); !errors.Is(err, seal.ErrVersion) {
			t.Errorf("version %#02x: err = %v, want ErrVersion", version, err)
		}
	}
}

func TestOpenTruncatedAndExtended(t *testing.T) {
	aad := []byte(aadAdmin)
	sealed := mustSeal(t, keyA, []byte("a secret that is long enough to cut"), aad)
	const smallestValid = 1 + 12 + 16 // version, nonce, tag: the sealed empty plaintext

	if _, err := seal.Open(keyA, nil, aad); !errors.Is(err, seal.ErrMalformed) {
		t.Errorf("Open(nil): err = %v, want ErrMalformed", err)
	}
	for n := 0; n < smallestValid; n++ {
		if _, err := seal.Open(keyA, sealed[:n], aad); !errors.Is(err, seal.ErrMalformed) {
			t.Errorf("first %d bytes: err = %v, want ErrMalformed", n, err)
		}
	}
	for n := smallestValid; n < len(sealed); n++ {
		if _, err := seal.Open(keyA, sealed[:n], aad); !errors.Is(err, seal.ErrDecrypt) {
			t.Errorf("first %d bytes: err = %v, want ErrDecrypt", n, err)
		}
	}
	extended := append(bytes.Clone(sealed), 0)
	if _, err := seal.Open(keyA, extended, aad); !errors.Is(err, seal.ErrDecrypt) {
		t.Errorf("one byte appended: err = %v, want ErrDecrypt", err)
	}

	// The smallest valid value is a sealed empty plaintext, and it opens.
	empty := mustSeal(t, keyA, nil, aad)
	if len(empty) != smallestValid {
		t.Fatalf("a sealed empty plaintext has %d bytes, want %d", len(empty), smallestValid)
	}
	if got, err := seal.Open(keyA, empty, aad); err != nil || len(got) != 0 {
		t.Errorf("Open(sealed empty plaintext) = %q, %v, want no bytes and no error", got, err)
	}
}

func TestSealAndOpenDoNotShareMemoryWithTheirInputs(t *testing.T) {
	plaintext := []byte("keep me")
	aad := []byte("ctx")
	sealed := mustSeal(t, keyA, plaintext, aad)

	// Changing the inputs afterwards does not change what was sealed.
	plaintext[0] ^= 0xFF
	aad[0] ^= 0xFF
	got, err := seal.Open(keyA, sealed, []byte("ctx"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != "keep me" {
		t.Errorf("Open returned %q, want %q", got, "keep me")
	}

	// Changing the result does not change the sealed value, or the next result.
	snapshot := bytes.Clone(sealed)
	got[0] ^= 0xFF
	if !bytes.Equal(sealed, snapshot) {
		t.Error("Open returned memory that is part of the sealed value")
	}
	again, err := seal.Open(keyA, sealed, []byte("ctx"))
	if err != nil || string(again) != "keep me" {
		t.Errorf("second Open = %q, %v, want %q", again, err, "keep me")
	}
}

// ---------------------------------------------------------------------------
// LoadOrCreateKey

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %#o, want %#o", path, got, want)
	}
}

func TestLoadOrCreateKeyCreatesTheFile(t *testing.T) {
	skipOnWindows(t)
	root := t.TempDir()
	path := filepath.Join(root, "keys", "nested", "master.key")

	k, err := seal.LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}

	data := mustRead(t, path)
	if len(data) != 32 {
		t.Fatalf("key file has %d bytes, want 32", len(data))
	}
	if !bytes.Equal(data, k[:]) {
		t.Error("the returned key is not the content of the key file")
	}
	if k == (seal.Key{}) {
		t.Error("the new key is all zero")
	}
	requireMode(t, path, 0o600)
	requireMode(t, filepath.Dir(path), 0o700)
	requireMode(t, filepath.Join(root, "keys"), 0o700)
}

// A directory that was there is not tightened: it may be a volume mount point,
// or shared with other files.
func TestLoadOrCreateKeyDoesNotChangeExistingDirectories(t *testing.T) {
	skipOnWindows(t)
	tests := []struct {
		name string
		rel  string // the key file, below the directory that exists
	}{
		{"key file directly in it", "master.key"},
		{"key file in a new directory below it", filepath.Join("inner", "master.key")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			existing := filepath.Join(t.TempDir(), "keys")
			if err := os.Mkdir(existing, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(existing, 0o755); err != nil { // the umask may have trimmed it
				t.Fatal(err)
			}
			path := filepath.Join(existing, tc.rel)

			if _, err := seal.LoadOrCreateKey(path); err != nil {
				t.Fatalf("LoadOrCreateKey: %v", err)
			}
			requireMode(t, existing, 0o755)
			requireMode(t, path, 0o600)
			if dir := filepath.Dir(path); dir != existing {
				requireMode(t, dir, 0o700)
			}
		})
	}
}

func TestLoadOrCreateKeyReturnsTheSameKeyAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	first, err := seal.LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)
	second, err := seal.LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("the second call returned a different key")
	}
	if !bytes.Equal(before, mustRead(t, path)) {
		t.Error("the second call changed the key file")
	}
}

func TestLoadOrCreateKeyMakesDifferentKeys(t *testing.T) {
	root := t.TempDir()
	a, err := seal.LoadOrCreateKey(filepath.Join(root, "a.key"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := seal.LoadOrCreateKey(filepath.Join(root, "b.key"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two new key files hold the same key")
	}
}

func TestLoadOrCreateKeyReadsAnExistingFile(t *testing.T) {
	skipOnWindows(t)
	path := filepath.Join(t.TempDir(), "master.key")
	want := makeKey(0x40)
	if err := os.WriteFile(path, want[:], 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { // the umask may have trimmed it
		t.Fatal(err)
	}

	got, err := seal.LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if got != want {
		t.Error("the key is not the content of the file")
	}
	// The mode of a file that exists is not checked and not changed: operators
	// restore keys from backups and mount them from secret stores.
	requireMode(t, path, 0o640)
}

// A key file of another size may hold a real key in another form (hex, base64,
// a trailing newline), so it is neither used nor replaced.
func TestLoadOrCreateKeyRefusesAFileThatIsNotExactly32Bytes(t *testing.T) {
	const marker = "KEYMATERIAL"
	for _, size := range []int{0, 1, 31, 33, 44, 64, 65, 4096} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			content := []byte(strings.Repeat(marker, size/len(marker)+1))[:size]
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}

			k, err := seal.LoadOrCreateKey(path)
			if err == nil {
				t.Fatal("LoadOrCreateKey succeeded")
			}
			if k != (seal.Key{}) {
				t.Error("a key was returned along with the error")
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("the error does not name the file: %v", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("the error contains the content of the file: %v", err)
			}
			if !bytes.Equal(mustRead(t, path), content) {
				t.Error("the file was changed")
			}
		})
	}
}

func TestLoadOrCreateKeyRefusesWhatIsNotAFile(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "master.key")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := seal.LoadOrCreateKey(path)
		if err == nil {
			t.Fatal("LoadOrCreateKey succeeded on a directory")
		}
		if !strings.Contains(err.Error(), "not a regular file") || !strings.Contains(err.Error(), path) {
			t.Errorf("the error does not say which file is not a regular file: %v", err)
		}
	})
	t.Run("parent is a file", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "keys")
		if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := seal.LoadOrCreateKey(filepath.Join(parent, "master.key")); err == nil {
			t.Error("LoadOrCreateKey succeeded below a regular file")
		}
	})
}

// Secret stores (Kubernetes, Docker) mount files as symbolic links.
func TestLoadOrCreateKeyFollowsASymlink(t *testing.T) {
	skipOnWindows(t)
	root := t.TempDir()
	real := filepath.Join(root, "real.key")
	link := filepath.Join(root, "master.key")
	want := makeKey(0x60)
	if err := os.WriteFile(real, want[:], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	got, err := seal.LoadOrCreateKey(link)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if got != want {
		t.Error("the key is not the content of the file behind the link")
	}
}

// A link to nothing is neither a missing file to create (the new file would
// land at an unexpected place) nor a loop to spin in.
func TestLoadOrCreateKeyRefusesADanglingSymlink(t *testing.T) {
	skipOnWindows(t)
	root := t.TempDir()
	target := filepath.Join(root, "missing.key")
	link := filepath.Join(root, "master.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := seal.LoadOrCreateKey(link); err == nil {
		t.Fatal("LoadOrCreateKey succeeded")
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link target was created: %v", err)
	}
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Errorf("the link was changed: %q, %v", got, err)
	}
}

// The sealed values of the panel are only as good as the file, so a key that
// came out of LoadOrCreateKey must work with Seal and Open.
func TestKeyFromFileWorksWithSealAndOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	k, err := seal.LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	sealed := mustSeal(t, k, []byte("a secret"), []byte(aadAdmin))

	reloaded, err := seal.LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := seal.Open(reloaded, sealed, []byte(aadAdmin))
	if err != nil || string(got) != "a secret" {
		t.Errorf("Open with the reloaded key = %q, %v, want %q", got, err, "a secret")
	}
}
