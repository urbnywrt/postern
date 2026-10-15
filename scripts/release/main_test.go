package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/scrypt"

	"github.com/urbnywrt/postern/internal/release"
)

// The tests make their keys when they run, in temporary directories; no key of
// any kind is in the repository.
const testPassword = "test password"

// result is what one run of the tool gave.
type result struct {
	code           int
	stdout, stderr string
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\n--- stdout:\n%s--- stderr:\n%s", r.code, r.stdout, r.stderr)
}

// tool runs the command line args as the binary would, with env as all of its
// environment.
func tool(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, func(name string) string { return env[name] })
	return result{code, stdout.String(), stderr.String()}
}

func withPassword(password string) map[string]string {
	return map[string]string{"POSTERN_MINISIGN_PASSWORD": password}
}

// useCheapEncryption makes keygen encrypt keys with cheapEncrypt for the rest
// of the test.
func useCheapEncryption(t *testing.T) {
	t.Helper()
	old := encryptKey
	encryptKey = cheapEncrypt
	t.Cleanup(func() { encryptKey = old })
}

// cheapEncrypt is minisign.EncryptKey with the cheapest scrypt parameters that
// minisign takes (opslimit 2^15 and memlimit 2^24, which minisign turns into
// N = 1024, r = 8, p = 1) in place of the ones of minisign and of its library
// (1 GiB of memory and seconds of work for each key, too much for a test run
// with -race). minisign.DecryptKey reads the parameters from the key file, so the
// file is a minisign key like any other.
func cheapEncrypt(password string, priv minisign.PrivateKey) ([]byte, error) {
	text, err := priv.MarshalText()
	if err != nil {
		return nil, err
	}
	_, encoded, _ := strings.Cut(string(text), "\n")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 158 {
		return nil, fmt.Errorf("the plain key is not what minisign makes: %v", err)
	}
	plain := raw[54:126] // the key id and the Ed25519 private key

	const ops, mem = 1 << 15, 1 << 24
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	keystream, err := scrypt.Key([]byte(password), salt[:], 1024, 8, 1, 104)
	if err != nil {
		return nil, err
	}
	checksum := blake2b.Sum256(append(binary.LittleEndian.AppendUint16(nil, minisign.EdDSA), plain...))
	ciphertext := append(slices.Clone(plain), checksum[:]...)
	for i := range ciphertext {
		ciphertext[i] ^= keystream[i]
	}

	out := binary.LittleEndian.AppendUint16(nil, minisign.EdDSA)
	out = binary.LittleEndian.AppendUint16(out, 0x6353) // scrypt
	out = binary.LittleEndian.AppendUint16(out, 0x3242) // BLAKE2b
	out = append(out, salt[:]...)
	out = binary.LittleEndian.AppendUint64(out, ops)
	out = binary.LittleEndian.AppendUint64(out, mem)
	out = append(out, ciphertext...)
	return []byte("untrusted comment: minisign encrypted secret key\n" + base64.StdEncoding.EncodeToString(out) + "\n"), nil
}

// newKey makes a key pair with keygen in a directory of its own and returns
// the path of the secret key and the public key. The key is encrypted (cheaply)
// with password, or not encrypted when password is empty.
func newKey(t *testing.T, password string) (string, minisign.PublicKey) {
	t.Helper()
	useCheapEncryption(t)
	dir := filepath.Join(t.TempDir(), "key")
	args := []string{"keygen", "--out", dir}
	if password == "" {
		args = append(args, "--unencrypted")
	}
	r := tool(t, withPassword(password), args...)
	if r.code != 0 {
		t.Fatalf("keygen: %v", r)
	}
	return filepath.Join(dir, "postern-release.key"), parsePublicKey(t, r.stdout)
}

func parsePublicKey(t *testing.T, text string) minisign.PublicKey {
	t.Helper()
	line := strings.TrimSuffix(text, "\n")
	if line == "" || strings.Contains(line, "\n") {
		t.Fatalf("the public key is %q, want one line", text)
	}
	var key minisign.PublicKey
	if err := key.UnmarshalText([]byte(line)); err != nil {
		t.Fatalf("the public key %q: %v", line, err)
	}
	return key
}

// staticELF returns the headers of a static ELF64 little-endian program for
// machine: all that release.CheckStaticELF reads.
func staticELF(machine elf.Machine) []byte {
	b := make([]byte, 64+56)
	copy(b, elf.ELFMAG)
	b[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	b[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	b[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	le := binary.LittleEndian
	le.PutUint16(b[16:], uint16(elf.ET_EXEC))
	le.PutUint16(b[18:], uint16(machine))
	le.PutUint32(b[20:], uint32(elf.EV_CURRENT))
	le.PutUint64(b[32:], 64) // e_phoff
	le.PutUint16(b[52:], 64) // e_ehsize
	le.PutUint16(b[54:], 56) // e_phentsize
	le.PutUint16(b[56:], 1)  // e_phnum
	le.PutUint32(b[64:], uint32(elf.PT_LOAD))
	return b
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func checkMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s has mode %v, want %v", path, got, want)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func verify(t *testing.T, file string, want release.Signed, key minisign.PublicKey) error {
	t.Helper()
	sig := readFile(t, file+".minisig")
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	return release.VerifyWith(f, sig, want, []minisign.PublicKey{key})
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"frobnicate"}, {"sign", "--no-such-flag"}} {
		r := tool(t, nil, args...)
		if r.code != 2 || (!strings.Contains(r.stderr, "Usage") && !strings.Contains(r.stderr, "usage")) {
			t.Errorf("%q: %v, want exit 2 and the usage", args, r)
		}
	}
	for _, help := range []string{"help", "-h", "--help"} {
		if r := tool(t, nil, help); r.code != 0 || !strings.Contains(r.stdout, "keygen") {
			t.Errorf("%s: %v, want exit 0 and the usage on stdout", help, r)
		}
	}
}

func TestKeygenRefusesARepository(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A linked worktree, whose .git is a file.
	worktree := filepath.Join(base, "worktree")
	writeFile(t, filepath.Join(worktree, ".git"), []byte("gitdir: /elsewhere/.git/worktrees/worktree\n"))

	cases := map[string]string{
		"a directory to make in a repository": filepath.Join(repo, "keys", "release"),
		"the repository itself":               repo,
		"a directory of it":                   filepath.Join(repo, "deep"),
		"a linked worktree":                   filepath.Join(worktree, "keys"),
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(repo, "deep"), link); err == nil {
		cases["a link into a repository"] = filepath.Join(link, "keys")
	} else {
		t.Logf("no symbolic link here (%v): that case is left out", err)
	}
	// The repository that this test is in, when it is a git checkout.
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; ; dir = filepath.Dir(dir) {
			if exists(filepath.Join(dir, ".git")) {
				cases["this repository"] = filepath.Join(wd, "keys-test")
				break
			}
			if filepath.Dir(dir) == dir {
				t.Log("the test does not run in a git checkout: that case is left out")
				break
			}
		}
	}

	useCheapEncryption(t)
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			existed := exists(out)
			r := tool(t, withPassword(testPassword), "keygen", "--out", out)
			if r.code != 1 || !strings.Contains(r.stderr, "git") {
				t.Fatalf("%v\nwant exit 1 and a word about git", r)
			}
			if r.stdout != "" {
				t.Errorf("stdout = %q, want nothing", r.stdout)
			}
			if !existed && exists(out) {
				t.Errorf("%s was made", out)
			}
			if exists(filepath.Join(out, "postern-release.key")) {
				t.Errorf("a key was written in %s", out)
			}
		})
	}

	t.Run("outside", func(t *testing.T) {
		out := filepath.Join(base, "outside", "release")
		if r := tool(t, withPassword(testPassword), "keygen", "--out", out); r.code != 0 {
			t.Fatalf("%v", r)
		}
	})
}

func TestKeygenEncrypted(t *testing.T) {
	useCheapEncryption(t)
	dir := filepath.Join(t.TempDir(), "config", "release")
	r := tool(t, withPassword(testPassword), "keygen", "--out", dir)
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	pub := parsePublicKey(t, r.stdout)

	keyFile := filepath.Join(dir, "postern-release.key")
	data := readFile(t, keyFile)
	if !minisign.IsEncrypted(data) {
		t.Fatal("the key is not encrypted")
	}
	checkMode(t, keyFile, 0o600)
	checkMode(t, dir, 0o700)
	priv, err := minisign.DecryptKey(testPassword, data)
	if err != nil {
		t.Fatalf("the key does not open with its password: %v", err)
	}
	if got := priv.Public().(minisign.PublicKey); !got.Equal(pub) {
		t.Errorf("the key printed is %s, the key in the file is that of %s", pub, got)
	}
	if !strings.Contains(r.stderr, fmt.Sprintf("%016X", pub.ID())) {
		t.Errorf("stderr does not name the key id %016X: %q", pub.ID(), r.stderr)
	}
	_, secret, _ := strings.Cut(string(data), "\n")
	if secret = strings.TrimSpace(secret); strings.Contains(r.stdout+r.stderr, secret) {
		t.Error("the output holds the secret key")
	}

	// A key is never overwritten.
	if r := tool(t, withPassword(testPassword), "keygen", "--out", dir); r.code != 1 || !strings.Contains(r.stderr, "exists") {
		t.Errorf("a second keygen in %s: %v, want exit 1 and that the key exists", dir, r)
	}
	if !bytes.Equal(readFile(t, keyFile), data) {
		t.Error("the second keygen changed the key")
	}

	// Without a password, and without --unencrypted, there is no key.
	other := filepath.Join(t.TempDir(), "other")
	for _, env := range []map[string]string{nil, withPassword("")} {
		r := tool(t, env, "keygen", "--out", other)
		if r.code != 2 || !strings.Contains(r.stderr, "POSTERN_MINISIGN_PASSWORD") {
			t.Errorf("keygen without a password: %v, want exit 2 and the name of the variable", r)
		}
		if exists(filepath.Join(other, "postern-release.key")) {
			t.Error("keygen without a password wrote a key")
		}
	}
}

func TestKeygenUnencrypted(t *testing.T) {
	keyFile, pub := newKey(t, "")
	data := readFile(t, keyFile)
	if minisign.IsEncrypted(data) {
		t.Fatal("the key is encrypted")
	}
	var priv minisign.PrivateKey
	if err := priv.UnmarshalText(data); err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(minisign.PublicKey).Equal(pub) {
		t.Error("the key printed is not the public key of the key in the file")
	}
	checkMode(t, keyFile, 0o600)
}

func TestPubkey(t *testing.T) {
	plainKey, plainPub := newKey(t, "")
	r := tool(t, nil, "pubkey", "--key", plainKey)
	if r.code != 0 || r.stdout != plainPub.String()+"\n" {
		t.Errorf("pubkey of a plain key: %v, want %s", r, plainPub)
	}

	key, pub := newKey(t, testPassword)
	if r := tool(t, nil, "pubkey", "--key", key); r.code != 1 || !strings.Contains(r.stderr, "POSTERN_MINISIGN_PASSWORD") {
		t.Errorf("pubkey of an encrypted key without its password: %v", r)
	}
	if r := tool(t, withPassword("wrong"), "pubkey", "--key", key); r.code != 1 || r.stdout != "" {
		t.Errorf("pubkey with a wrong password: %v", r)
	}
	if r := tool(t, withPassword(testPassword), "pubkey", "--key", key); r.code != 0 || r.stdout != pub.String()+"\n" {
		t.Errorf("pubkey with the password: %v, want %s", r, pub)
	}
}

func TestSignWithAnEncryptedKey(t *testing.T) {
	key, pub := newKey(t, testPassword)
	file := filepath.Join(t.TempDir(), "SHA256SUMS")
	writeFile(t, file, []byte("0000  x\n"))
	args := []string{"sign", "--key", key, "--component", "sha256sums", "--version", "v0.5.0", file}

	for name, env := range map[string]map[string]string{"no password": nil, "a wrong password": withPassword("wrong")} {
		r := tool(t, env, args...)
		if r.code != 1 {
			t.Errorf("%s: %v, want exit 1", name, r)
		}
		if exists(file + ".minisig") {
			t.Fatalf("%s: a signature was written", name)
		}
		if name == "no password" && !strings.Contains(r.stderr, "POSTERN_MINISIGN_PASSWORD") {
			t.Errorf("%s: stderr does not name the variable: %q", name, r.stderr)
		}
	}

	if r := tool(t, withPassword(testPassword), args...); r.code != 0 {
		t.Fatalf("%v", r)
	}
	if err := verify(t, file, release.Signed{Component: "sha256sums", Version: "v0.5.0"}, pub); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
}

func TestSign(t *testing.T) {
	key, pub := newKey(t, "")
	amd64, arm64 := staticELF(elf.EM_X86_64), staticELF(elf.EM_AARCH64)
	tests := []struct {
		name                     string
		component, version, arch string
		data                     []byte
		code                     int // 0: signed
	}{
		{"node amd64", "postern-node", "v0.5.0", "amd64", amd64, 0},
		{"panel arm64", "postern-panel", "v0.5.0-rc.1", "arm64", arm64, 0},
		{"checksums", "sha256sums", "v0.5.0", "", []byte("0000  x\n"), 0},
		{"stable list", "engines-stable", "1760000000", "", []byte("{}"), 0},
		{"unknown component", "postern-nod", "v0.5.0", "amd64", amd64, 2},
		{"version of two words", "postern-node", "v0.5.0 linux/amd64", "", amd64, 2},
		{"no version", "postern-node", "", "amd64", amd64, 2},
		{"unsupported architecture", "postern-node", "v0.5.0", "386", amd64, 2},
		{"binary without an architecture", "postern-panel", "v0.5.0", "", amd64, 2},
		{"checksums with an architecture", "sha256sums", "v0.5.0", "amd64", amd64, 2},
		{"binary of the other architecture", "postern-node", "v0.5.0", "amd64", arm64, 1},
		{"not a program", "postern-node", "v0.5.0", "arm64", []byte("#!/bin/sh\necho\n"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "file")
			writeFile(t, file, tt.data)
			args := []string{"sign", "--key", key, "--component", tt.component, "--version", tt.version}
			if tt.arch != "" {
				args = append(args, "--arch", tt.arch)
			}
			r := tool(t, nil, append(args, file)...)
			if r.code != tt.code {
				t.Fatalf("%v\nwant exit %d", r, tt.code)
			}
			if tt.code != 0 {
				if exists(file + ".minisig") {
					t.Error("a signature was written")
				}
				return
			}

			want := release.Signed{Component: tt.component, Version: tt.version}
			if tt.arch != "" {
				want.OS, want.Arch = "linux", tt.arch
			}
			if err := verify(t, file, want, pub); err != nil {
				t.Fatalf("the signature does not verify for %q: %v", want.TrustedComment(), err)
			}
			if tt.arch != "" {
				other := want
				other.Arch = map[string]string{"amd64": "arm64", "arm64": "amd64"}[tt.arch]
				if err := verify(t, file, other, pub); !errors.Is(err, release.ErrWrongArtifact) {
					t.Errorf("verified for %s: %v, want ErrWrongArtifact", other.Arch, err)
				}
			}
			checkMode(t, file+".minisig", 0o644)

			// The same file signed again gives the same signature.
			sig := readFile(t, file+".minisig")
			if r := tool(t, nil, append(args, file)...); r.code != 0 {
				t.Fatalf("signing again: %v", r)
			}
			if !bytes.Equal(readFile(t, file+".minisig"), sig) {
				t.Error("signing again gave another signature")
			}
		})
	}

	t.Run("command lines", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		writeFile(t, file, []byte("x"))
		for _, args := range [][]string{
			{"sign", "--key", key, "--component", "sha256sums", "--version", "v0.5.0"},
			{"sign", "--key", key, "--component", "sha256sums", "--version", "v0.5.0", file, file},
			{"sign", "--component", "sha256sums", "--version", "v0.5.0", file},
		} {
			if r := tool(t, nil, args...); r.code != 2 {
				t.Errorf("%q: %v, want exit 2", args, r)
			}
		}
		if r := tool(t, nil, "sign", "--key", key, "--component", "sha256sums", "--version", "v0.5.0", file+".missing"); r.code != 1 {
			t.Errorf("a file that is not there: %v, want exit 1", r)
		}
	})
}

func TestVerify(t *testing.T) {
	key, pub := newKey(t, "")
	_, otherPub := newKey(t, "")
	dir := t.TempDir()
	file := filepath.Join(dir, "postern-node-linux-arm64")
	writeFile(t, file, staticELF(elf.EM_AARCH64))
	if r := tool(t, nil, "sign", "--key", key, "--component", "postern-node", "--version", "v0.5.0", "--arch", "arm64", file); r.code != 0 {
		t.Fatalf("%v", r)
	}
	verifyArgs := func(pubkey, version, arch, file string) []string {
		return []string{"verify", "--pubkey", pubkey, "--component", "postern-node", "--version", version, "--arch", arch, file}
	}

	r := tool(t, nil, verifyArgs(pub.String(), "v0.5.0", "arm64", file)...)
	if r.code != 0 || !strings.Contains(r.stdout, "postern postern-node v0.5.0 linux/arm64") {
		t.Errorf("a good signature: %v", r)
	}
	// The whole file of a public key does too.
	text, _ := pub.MarshalText()
	if r := tool(t, nil, verifyArgs(string(text), "v0.5.0", "arm64", file)...); r.code != 0 {
		t.Errorf("a public key file: %v", r)
	}

	for name, args := range map[string][]string{
		"another version":      verifyArgs(pub.String(), "v0.5.1", "arm64", file),
		"another architecture": verifyArgs(pub.String(), "v0.5.0", "amd64", file),
		"another key":          verifyArgs(otherPub.String(), "v0.5.0", "arm64", file),
		"no signature":         verifyArgs(pub.String(), "v0.5.0", "arm64", filepath.Join(dir, "missing")),
	} {
		if r := tool(t, nil, args...); r.code != 1 {
			t.Errorf("%s: %v, want exit 1", name, r)
		}
	}

	tampered := filepath.Join(dir, "tampered")
	data := staticELF(elf.EM_AARCH64)
	data[len(data)-1] ^= 1
	writeFile(t, tampered, data)
	writeFile(t, tampered+".minisig", readFile(t, file+".minisig"))
	if r := tool(t, nil, verifyArgs(pub.String(), "v0.5.0", "arm64", tampered)...); r.code != 1 {
		t.Errorf("a changed file: %v, want exit 1", r)
	}

	if r := tool(t, nil, verifyArgs("RWQnotakey", "v0.5.0", "arm64", file)...); r.code != 2 {
		t.Errorf("a malformed key: %v, want exit 2", r)
	}
}

func TestSums(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"postern-panel-linux-amd64": "panel",
		"postern-node-linux-arm64":  "node for arm64",
		"postern-node-linux-amd64":  "node for amd64",
	}
	var args []string
	for _, name := range []string{"postern-panel-linux-amd64", "postern-node-linux-arm64", "postern-node-linux-amd64"} {
		writeFile(t, filepath.Join(dir, name), []byte(files[name]))
		args = append(args, filepath.Join(dir, name))
	}
	if r := tool(t, nil, append([]string{"sums"}, args...)...); r.code != 0 {
		t.Fatalf("%v", r)
	}

	got := readFile(t, filepath.Join(dir, "SHA256SUMS"))
	want := ""
	for _, name := range []string{"postern-node-linux-amd64", "postern-node-linux-arm64", "postern-panel-linux-amd64"} {
		want += sha256Hex([]byte(files[name])) + "  " + name + "\n"
	}
	if string(got) != want {
		t.Errorf("SHA256SUMS:\n%s\nwant:\n%s", got, want)
	}
	for name, content := range files {
		if sum, err := release.SumFor(name, got, release.SumsSHA256); err != nil || sum != sha256Hex([]byte(content)) {
			t.Errorf("release.SumFor(%s) = %s, %v", name, sum, err)
		}
	}
	checkMode(t, filepath.Join(dir, "SHA256SUMS"), 0o644)

	elsewhere := filepath.Join(t.TempDir(), "postern-panel-linux-arm64")
	writeFile(t, elsewhere, []byte("x"))
	for name, args := range map[string][]string{
		"no file":             {"sums"},
		"two directories":     {"sums", args[0], elsewhere},
		"a name twice":        {"sums", args[0], args[0]},
		"the checksums":       {"sums", args[0], filepath.Join(dir, "SHA256SUMS")},
		"a file not there":    {"sums", args[0], filepath.Join(dir, "missing")},
		"a name with a space": {"sums", filepath.Join(dir, "a b")},
	} {
		if name == "a name with a space" {
			writeFile(t, filepath.Join(dir, "a b"), []byte("x"))
		}
		before := readFile(t, filepath.Join(dir, "SHA256SUMS"))
		if r := tool(t, nil, args...); r.code == 0 {
			t.Errorf("%s: %v, want a failure", name, r)
		}
		if !bytes.Equal(readFile(t, filepath.Join(dir, "SHA256SUMS")), before) {
			t.Errorf("%s: SHA256SUMS was changed", name)
		}
	}
}

// releaseFiles writes the files of a release of version into dir, signed with
// a new key: the four binaries with their signatures, and SHA256SUMS with its
// signature. It returns the key and the files and what they hold.
func releaseFiles(t *testing.T, dir, version string) (minisign.PrivateKey, map[string][]byte) {
	t.Helper()
	_, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	sums := ""
	for _, component := range []string{"postern-node", "postern-panel"} {
		for arch, machine := range map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64} {
			name := component + "-linux-" + arch
			data := append(staticELF(machine), []byte(name)...)
			files[name] = data
			files[name+".minisig"] = sign(t, priv, data, release.Signed{Component: component, Version: version, OS: "linux", Arch: arch})
		}
	}
	for _, name := range []string{"postern-node-linux-amd64", "postern-node-linux-arm64", "postern-panel-linux-amd64", "postern-panel-linux-arm64"} {
		sums += sha256Hex(files[name]) + "  " + name + "\n"
	}
	files["SHA256SUMS"] = []byte(sums)
	files["SHA256SUMS.minisig"] = sign(t, priv, []byte(sums), release.Signed{Component: "sha256sums", Version: version})
	for name, data := range files {
		writeFile(t, filepath.Join(dir, name), data)
	}
	return priv, files
}

func sign(t *testing.T, priv minisign.PrivateKey, data []byte, s release.Signed) []byte {
	t.Helper()
	sig, err := release.Sign(bytes.NewReader(data), priv, s)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

type member struct {
	name    string
	mode    int64
	data    []byte
	modTime time.Time
}

func readTar(t *testing.T, path string) []member {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var members []member
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return members
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Format != tar.FormatUSTAR {
			t.Errorf("%s: type %c, owner %d:%d (%q:%q), format %v; want a regular file of 0:0 without names, USTAR",
				h.Name, h.Typeflag, h.Uid, h.Gid, h.Uname, h.Gname, h.Format)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, member{h.Name, h.Mode, data, h.ModTime})
	}
}

func TestBundle(t *testing.T) {
	dir := t.TempDir()
	priv, files := releaseFiles(t, dir, "v0.5.0")
	env := map[string]string{"SOURCE_DATE_EPOCH": "1760000000"}
	if r := tool(t, env, "bundle", "--version", "v0.5.0", dir); r.code != 0 {
		t.Fatalf("%v", r)
	}
	bundle := filepath.Join(dir, "postern-v0.5.0-bundle.tar")
	members := readTar(t, bundle)

	var names []string
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	var got []string
	for _, m := range members {
		got = append(got, m.name)
		if !bytes.Equal(m.data, files[m.name]) {
			t.Errorf("%s in the bundle is not the file", m.name)
		}
		wantMode := int64(0o644)
		if !strings.Contains(m.name, ".") && strings.HasPrefix(m.name, "postern-") {
			wantMode = 0o755
		}
		if m.mode != wantMode {
			t.Errorf("%s has mode %o in the bundle, want %o", m.name, m.mode, wantMode)
		}
		if m.modTime.Unix() != 1760000000 {
			t.Errorf("%s has time %v in the bundle, want SOURCE_DATE_EPOCH", m.name, m.modTime)
		}
	}
	if !slices.Equal(got, names) {
		t.Errorf("the bundle holds %q, want %q", got, names)
	}
	checkMode(t, bundle, 0o644)

	// The same files make the same bundle.
	first := readFile(t, bundle)
	if r := tool(t, env, "bundle", "--version", "v0.5.0", dir); r.code != 0 {
		t.Fatalf("%v", r)
	}
	if !bytes.Equal(readFile(t, bundle), first) {
		t.Error("a second bundle of the same files is another file")
	}

	t.Run("with the list of stable engines", func(t *testing.T) {
		list := []byte(`{"schema":1,"generated_at":1760000000,"components":{}}`)
		writeFile(t, filepath.Join(dir, "engines-stable.json"), list)
		writeFile(t, filepath.Join(dir, "engines-stable.json.minisig"), sign(t, priv, list, release.Signed{Component: "engines-stable", Version: "1760000000"}))
		t.Cleanup(func() {
			_ = os.Remove(filepath.Join(dir, "engines-stable.json"))
			_ = os.Remove(filepath.Join(dir, "engines-stable.json.minisig"))
		})
		if r := tool(t, env, "bundle", "--version", "v0.5.0", dir); r.code != 0 {
			t.Fatalf("%v", r)
		}
		var got []string
		for _, m := range readTar(t, bundle) {
			got = append(got, m.name)
		}
		if !slices.Contains(got, "engines-stable.json") || !slices.Contains(got, "engines-stable.json.minisig") {
			t.Errorf("the bundle holds %q, without the list", got)
		}
	})

	refused := map[string]func(dir string){
		"a signature missing": func(dir string) { _ = os.Remove(filepath.Join(dir, "postern-panel-linux-arm64.minisig")) },
		"a binary missing":    func(dir string) { _ = os.Remove(filepath.Join(dir, "postern-node-linux-amd64")) },
		"the checksums missing": func(dir string) {
			_ = os.Remove(filepath.Join(dir, "SHA256SUMS"))
		},
		"a signature of another version": func(dir string) {
			data := readFile(t, filepath.Join(dir, "postern-node-linux-amd64"))
			writeFile(t, filepath.Join(dir, "postern-node-linux-amd64.minisig"),
				sign(t, priv, data, release.Signed{Component: "postern-node", Version: "v0.5.1", OS: "linux", Arch: "amd64"}))
		},
		"a signature of the other architecture": func(dir string) {
			data := readFile(t, filepath.Join(dir, "postern-panel-linux-arm64"))
			writeFile(t, filepath.Join(dir, "postern-panel-linux-arm64.minisig"),
				sign(t, priv, data, release.Signed{Component: "postern-panel", Version: "v0.5.0", OS: "linux", Arch: "amd64"}))
		},
		"a binary that the checksums do not list": func(dir string) {
			writeFile(t, filepath.Join(dir, "postern-panel-linux-amd64"), []byte("another panel"))
		},
		"the list without its signature": func(dir string) {
			writeFile(t, filepath.Join(dir, "engines-stable.json"), []byte("{}"))
		},
		"a signature that cannot be read": func(dir string) {
			writeFile(t, filepath.Join(dir, "SHA256SUMS.minisig"), []byte("not a signature\n"))
		},
	}
	for name, spoil := range refused {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			releaseFiles(t, dir, "v0.5.0")
			spoil(dir)
			if r := tool(t, env, "bundle", "--version", "v0.5.0", dir); r.code != 1 {
				t.Errorf("%v\nwant exit 1", r)
			}
			if exists(filepath.Join(dir, "postern-v0.5.0-bundle.tar")) {
				t.Error("a bundle was written")
			}
		})
	}

	for _, args := range [][]string{{"bundle", dir}, {"bundle", "--version", "v0.5.0"}, {"bundle", "--version", "../v0.5.0", dir}} {
		if r := tool(t, env, args...); r.code != 2 {
			t.Errorf("%q: %v, want exit 2", args, r)
		}
	}
}

// git runs git in dir with a configuration of its own, and returns its output.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return gitWithEnv(t, dir, nil, args...)
}

func gitWithEnv(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// commits makes empty commits in the repository dir, a minute apart, so that
// git lists them in the order in which they were made.
type commits struct {
	t    *testing.T
	dir  string
	time int64
}

// commit makes an empty commit with message and returns its abbreviated hash.
func (c *commits) commit(message string) string {
	c.t.Helper()
	c.time += 60
	date := fmt.Sprintf("%d +0000", c.time)
	gitWithEnv(c.t, c.dir, []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date},
		"commit", "-q", "--allow-empty", "-m", message)
	return git(c.t, c.dir, "rev-parse", "--short", "HEAD")
}

// merge merges branch into the branch that is checked out.
func (c *commits) merge(branch string) {
	c.t.Helper()
	c.time += 60
	date := fmt.Sprintf("%d +0000", c.time)
	gitWithEnv(c.t, c.dir, []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date},
		"merge", "-q", "--no-ff", "-m", "Merge branch '"+branch+"'", branch)
}

func TestChangelog(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	// The tool runs git as it is configured for the user; the test makes that
	// the configuration of its own commits.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	repo := t.TempDir()
	git(t, repo, "init", "-q")
	git(t, repo, "symbolic-ref", "HEAD", "refs/heads/main")
	c := &commits{t: t, dir: repo, time: 1760000000}
	first := c.commit("feat: the first commit")
	git(t, repo, "tag", "v0.1.0")
	feat := c.commit("feat(panel): show the version of every node")
	fix := c.commit("fix: keep the port of a listener")
	chore := c.commit("chore: tidy the scripts")
	body := c.commit("perf(edge): relay without a copy\n\n" +
		"The body explains it.\n\n" +
		"fix: this line is not a commit\n\n" +
		"Co-authored-by: Somebody <somebody@example.com>\n" +
		"Signed-off-by: Test <test@example.com>")
	git(t, repo, "checkout", "-q", "-b", "side")
	side := c.commit("fix(node): a fix on a branch")
	git(t, repo, "checkout", "-q", "main")
	security := c.commit("security(auth): lock the address after five failures")
	breaking := c.commit("feat(api)!: drop the old field")
	plain := c.commit("Update the readme")
	c.merge("side")
	git(t, repo, "tag", "v0.2.0")

	t.Chdir(repo)
	r := tool(t, nil, "changelog", "--from", "v0.1.0", "--to", "v0.2.0")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	want := "## Features\n\n" +
		"- **Breaking:** api: drop the old field (" + breaking + ")\n" +
		"- panel: show the version of every node (" + feat + ")\n" +
		"\n## Fixes\n\n" +
		"- node: a fix on a branch (" + side + ")\n" +
		"- keep the port of a listener (" + fix + ")\n" +
		"\n## Performance\n\n" +
		"- edge: relay without a copy (" + body + ")\n" +
		"\n## Security\n\n" +
		"- auth: lock the address after five failures (" + security + ")\n" +
		"\n## Other\n\n" +
		"- Update the readme (" + plain + ")\n" +
		"- chore: tidy the scripts (" + chore + ")\n"
	if r.stdout != want {
		t.Errorf("the notes:\n%s\nwant:\n%s", r.stdout, want)
	}
	for _, never := range []string{"not a commit", "Co-authored-by", "Signed-off-by", "body explains", "Merge", "the first commit"} {
		if strings.Contains(r.stdout, never) {
			t.Errorf("the notes hold %q", never)
		}
	}

	// Without --from, from the first commit.
	r = tool(t, nil, "changelog", "--to", "v0.1.0")
	if want := "## Features\n\n- the first commit (" + first + ")\n"; r.code != 0 || r.stdout != want {
		t.Errorf("the notes up to the first tag: %v\nwant:\n%s", r, want)
	}
	// Nothing between two tags of one commit.
	git(t, repo, "tag", "v0.2.1")
	if r := tool(t, nil, "changelog", "--from", "v0.2.0", "--to", "v0.2.1"); r.code != 0 || r.stdout != "No changes.\n" {
		t.Errorf("no commits: %v", r)
	}

	for _, args := range [][]string{
		{"changelog", "--from", "v0.1.0"},
		{"changelog", "--from", "--output=/tmp/x", "--to", "v0.2.0"},
		{"changelog", "--to", "v0.2.0", "extra"},
	} {
		if r := tool(t, nil, args...); r.code != 2 {
			t.Errorf("%q: %v, want exit 2", args, r)
		}
	}
	if r := tool(t, nil, "changelog", "--from", "v9.9.9", "--to", "v0.2.0"); r.code != 1 || !strings.Contains(r.stderr, "v9.9.9") {
		t.Errorf("a tag that is not there: %v, want exit 1 that names it", r)
	}
}

// buildNames are the binaries of a build, sorted.
var buildNames = []string{
	"postern-node-linux-amd64", "postern-node-linux-arm64", "postern-panel-linux-amd64", "postern-panel-linux-arm64",
	"psiphon-core-linux-amd64", "psiphon-core-linux-arm64",
}

// buildFiles writes into dir what the job that builds hands over, with the
// headers of static programs in place of the binaries, and returns the SHA-256
// of its MANIFEST.
func buildFiles(t *testing.T, dir string) string {
	t.Helper()
	for _, name := range buildNames {
		machine := elf.EM_X86_64
		if strings.HasSuffix(name, "arm64") {
			machine = elf.EM_AARCH64
		}
		writeFile(t, filepath.Join(dir, name), append(staticELF(machine), name...))
	}
	return writeManifest(t, dir)
}

// writeManifest writes MANIFEST for the binaries in dir and returns its SHA-256.
func writeManifest(t *testing.T, dir string) string {
	t.Helper()
	manifest := ""
	for _, name := range buildNames {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			manifest += sha256Hex(data) + "  " + name + "\n"
		}
	}
	writeFile(t, filepath.Join(dir, "MANIFEST"), []byte(manifest))
	return sha256Hex([]byte(manifest))
}

func TestCheckBuild(t *testing.T) {
	const commit = "0123456789ab"
	tests := map[string]struct {
		spoil func(t *testing.T, dir, sha string) string // returns the SHA-256 that the build gave
		want  string
	}{
		"a file that a build does not make": {func(t *testing.T, dir, sha string) string {
			writeFile(t, filepath.Join(dir, "extra"), []byte("x"))
			return sha
		}, "does not make"},
		"a directory in place of a binary": {func(t *testing.T, dir, sha string) string {
			_ = os.Remove(filepath.Join(dir, "postern-node-linux-amd64"))
			if err := os.Mkdir(filepath.Join(dir, "postern-node-linux-amd64"), 0o755); err != nil {
				t.Fatal(err)
			}
			return sha
		}, "not a plain file"},
		"a link in place of a binary": {func(t *testing.T, dir, sha string) string {
			path := filepath.Join(dir, "postern-panel-linux-arm64")
			_ = os.Remove(path)
			if err := os.Symlink(filepath.Join(dir, "postern-node-linux-arm64"), path); err != nil {
				t.Skipf("no symbolic link here: %v", err)
			}
			return sha
		}, "not a plain file"},
		"a binary missing": {func(t *testing.T, dir, sha string) string {
			_ = os.Remove(filepath.Join(dir, "postern-panel-linux-amd64"))
			return sha
		}, "has no postern-panel-linux-amd64"},
		"no Psiphon client": {func(t *testing.T, dir, sha string) string {
			_ = os.Remove(filepath.Join(dir, "psiphon-core-linux-arm64"))
			return sha
		}, "has no psiphon-core-linux-arm64"},
		"another MANIFEST than that of the build": {func(t *testing.T, dir, sha string) string {
			return strings.Repeat("0", 64)
		}, "not the MANIFEST of the build"},
		"a binary that MANIFEST does not list": {func(t *testing.T, dir, sha string) string {
			writeFile(t, filepath.Join(dir, "postern-node-linux-arm64"), append(staticELF(elf.EM_AARCH64), "other"...))
			return sha
		}, "MANIFEST lists"},
		"a MANIFEST with one more line": {func(t *testing.T, dir, sha string) string {
			manifest := append(readFile(t, filepath.Join(dir, "MANIFEST")), []byte(strings.Repeat("1", 64)+"  extra\n")...)
			writeFile(t, filepath.Join(dir, "MANIFEST"), manifest)
			return sha256Hex(manifest)
		}, "7 lines"},
		"a binary of the other architecture": {func(t *testing.T, dir, sha string) string {
			// The first binary that step 4 looks at.
			writeFile(t, filepath.Join(dir, "postern-node-linux-amd64"), staticELF(elf.EM_AARCH64))
			return writeManifest(t, dir)
		}, "another platform"},
		// The checks of the files pass; a program that Go did not build fails the next one.
		"programs that are not Go programs": {func(t *testing.T, dir, sha string) string { return sha }, "not a Go program"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sha := tt.spoil(t, dir, buildFiles(t, dir))
			r := tool(t, nil, "check-build", "--version", "v0.5.0", "--commit", commit, "--manifest-sha256", sha, dir)
			if r.code != 1 || !strings.Contains(r.stderr, tt.want) {
				t.Errorf("%v\nwant exit 1 and %q", r, tt.want)
			}
		})
	}

	dir := t.TempDir()
	sha := buildFiles(t, dir)
	for _, args := range [][]string{
		{"--version", "v0.5.0 x", "--commit", commit, "--manifest-sha256", sha, dir},
		{"--version", "v0.5.0", "--commit", "not-hex", "--manifest-sha256", sha, dir},
		{"--version", "v0.5.0", "--commit", commit, "--manifest-sha256", sha[:63], dir},
		{"--version", "v0.5.0", "--commit", commit, "--manifest-sha256", sha},
	} {
		if r := tool(t, nil, append([]string{"check-build"}, args...)...); r.code != 2 {
			t.Errorf("%q: %v, want exit 2", args, r)
		}
	}
}

// The Psiphon client of a build is a Go build of psiphon-tunnel-core's
// ConsoleClient with the SHA-256 that the panel pins: another Go program is
// refused, and so is the client with other bytes. With
// POSTERN_ITEST_PSIPHON_CORE (the directory of scripts/psiphon-core.sh), the
// real build passes.
func TestCheckPsiphonCore(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil || testing.Short() {
		t.Skip("no go command, or -short: no program to look into")
	}
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "go.mod"), []byte("module example.com/notpsiphon\n\ngo 1.22\n"))
	writeFile(t, filepath.Join(src, "main.go"), []byte("package main\n\nfunc main() {}\n"))
	bin := filepath.Join(t.TempDir(), "psiphon-core-linux-amd64")
	cmd := exec.Command(gobin, "build", "-trimpath", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if err := checkBinary(bin, psiphonCore, "amd64", "v0.5.0", "0123456789ab"); err == nil || !strings.Contains(err.Error(), psiphonCorePath) {
		t.Errorf("checkBinary of another Go program = %v", err)
	}

	dir := os.Getenv("POSTERN_ITEST_PSIPHON_CORE")
	if dir == "" {
		t.Skip("set POSTERN_ITEST_PSIPHON_CORE for the check of the real build")
	}
	for _, arch := range arches {
		path := filepath.Join(dir, "psiphon-core-linux-"+arch)
		if err := checkBinary(path, psiphonCore, arch, "v0.5.0", "0123456789ab"); err != nil {
			t.Errorf("checkBinary of the build for %s: %v", arch, err)
		}
		// One byte more is another file: not the one that the panel pins.
		other := filepath.Join(t.TempDir(), "psiphon-core-linux-"+arch)
		writeFile(t, other, append(readFile(t, path), 0))
		if err := checkBinary(other, psiphonCore, arch, "v0.5.0", "0123456789ab"); err == nil || !strings.Contains(err.Error(), "pins") {
			t.Errorf("checkBinary of other bytes for %s = %v", arch, err)
		}
	}
}

func TestHoldsString(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil || testing.Short() {
		t.Skip("no go command, or -short: no program to look into")
	}
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "go.mod"), []byte("module example.com/holds\n\ngo 1.22\n"))
	writeFile(t, filepath.Join(src, "main.go"), []byte("package main\n\nvar version = \"dev\"\n\nfunc main() { println(version) }\n"))
	for _, arch := range arches {
		t.Run(arch, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "holds")
			cmd := exec.Command(gobin, "build", "-trimpath", "-ldflags", "-s -w -X main.version=v1.2.3-rc.1", "-o", bin, ".")
			cmd.Dir = src
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build: %v\n%s", err, out)
			}
			f, err := os.Open(bin)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			for s, want := range map[string]bool{"v1.2.3-rc.1": true, "v1.2.3": false, "rc.1": false, "v1.2.3-rc.2": false} {
				if got, err := holdsString(f, s); err != nil || got != want {
					t.Errorf("holdsString(%q) = %v, %v; want %v", s, got, err, want)
				}
			}
		})
	}
}

// TestMain runs the tool in this process as a build without production keys,
// whatever internal/release/keys.go holds: the tests sign with keys of their
// own. The builds with production keys are made by TestKeys with -ldflags.
func TestMain(m *testing.M) {
	productionKeys = func(release.KeySet) []minisign.PublicKey { return nil }
	os.Exit(m.Run())
}

func TestKeys(t *testing.T) {
	// The tool in this process has no production keys (TestMain).
	r := tool(t, nil, "keys")
	if r.code != 0 || r.stdout != "" || !strings.Contains(r.stderr, "release") || !strings.Contains(r.stderr, "stable") {
		t.Errorf("keys of a build without production keys: %v", r)
	}

	if testing.Short() {
		t.Skip("the builds with keys are left out with -short")
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build the tool with production keys")
	}
	_, releaseKey := newKey(t, "")
	_, stableKey := newKey(t, "")
	build := func(t *testing.T, releaseKeys, stableKeys string) string {
		t.Helper()
		bin := filepath.Join(t.TempDir(), "release-tool")
		const pkg = "github.com/urbnywrt/postern/internal/release"
		cmd := exec.Command(gobin, "build", "-o", bin, "-ldflags",
			"-X "+pkg+".productionReleaseKeys="+releaseKeys+" -X "+pkg+".productionStableKeys="+stableKeys, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build: %v\n%s", err, out)
		}
		return bin
	}
	runBin := func(bin string, args ...string) result {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(bin, args...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		return result{code, stdout.String(), stderr.String()}
	}

	t.Run("production keys", func(t *testing.T) {
		bin := build(t, releaseKey.String(), stableKey.String())
		r := runBin(bin, "keys")
		want := fmt.Sprintf("release\t%016X\t%s\nstable\t%016X\t%s\n", releaseKey.ID(), releaseKey, stableKey.ID(), stableKey)
		if r.code != 0 || r.stdout != want {
			t.Errorf("%v\nwant stdout:\n%s", r, want)
		}
	})
	t.Run("a malformed key", func(t *testing.T) {
		bin := build(t, releaseKey.String()+",RWQnotakey", "")
		r := runBin(bin, "keys")
		if r.code != 1 || !strings.Contains(r.stderr, "key 2") || strings.Contains(r.stderr, "RWQnotakey") {
			t.Errorf("%v\nwant exit 1 and the position of the key, not the key", r)
		}
	})
}
