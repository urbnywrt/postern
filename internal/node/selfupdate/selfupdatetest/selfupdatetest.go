// Package selfupdatetest makes signed node binaries for the tests of the
// self-update: a synthetic static ELF signed by a key generated at run time.
package selfupdatetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"aead.dev/minisign"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/release"
)

// Signer holds a release key made for one test.
type Signer struct {
	Public  minisign.PublicKey
	private minisign.PrivateKey
}

// NewSigner generates a key.
func NewSigner(t testing.TB) *Signer {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Public: pub, private: priv}
}

// Keys trusts the signer's key for the release set (a Keys field).
func (s *Signer) Keys(set release.KeySet) ([]minisign.PublicKey, error) {
	if set != release.ReleaseKeys {
		return nil, release.ErrNoKeys
	}
	return []minisign.PublicKey{s.Public}, nil
}

// Sign signs data as postern-node <version> linux/<arch>.
func (s *Signer) Sign(t testing.TB, data []byte, version, arch string) string {
	t.Helper()
	sig, err := release.Sign(bytes.NewReader(data), s.private, release.Signed{Component: "postern-node", Version: version, OS: "linux", Arch: arch})
	if err != nil {
		t.Fatal(err)
	}
	return string(sig)
}

// Binary is a static ELF program for arch whose bytes differ by tag.
func Binary(t testing.TB, arch, tag string) []byte {
	t.Helper()
	return image(t, arch, elf.PT_LOAD, tag)
}

// DynamicBinary is Binary with a PT_INTERP header.
func DynamicBinary(t testing.TB, arch, tag string) []byte {
	t.Helper()
	return image(t, arch, elf.PT_INTERP, tag)
}

// Meta describes data as the binary of version for arch, signed by s.
func (s *Signer) Meta(t testing.TB, data []byte, version, arch string) *nodev1.NodeBinary {
	t.Helper()
	sum := sha256.Sum256(data)
	return &nodev1.NodeBinary{
		Version: version, Arch: arch, Sha256: hex.EncodeToString(sum[:]), Size: uint64(len(data)),
		Signature: s.Sign(t, data, version, arch),
	}
}

// Exec is a fake Exec whose "<file> version" prints "<version> (abc1234, …)",
// as the version command of a node binary does.
func Exec(version string) func(ctx context.Context, path string, args ...string) ([]byte, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) != 1 || args[0] != "version" {
			return nil, errors.New("unexpected arguments")
		}
		return []byte(version + " (abc1234, 2026-10-07T00:00:00Z)\n"), nil
	}
}

func image(t testing.TB, arch string, prog elf.ProgType, tag string) []byte {
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
