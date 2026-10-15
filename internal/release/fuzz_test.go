package release_test

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/release"
)

// asciiLower folds the upper-case ASCII letters of s, and nothing else.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func isLowerHex64(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

// FuzzSumFor feeds arbitrary checksum files and names to SumFor in both
// formats. On every input: no panic; a sum comes with no error and an error
// with no sum; a sum is 64 lower-case hex digits that are in the file (in a
// line that names the file, or in a file that holds only the sum; for the
// .dgst, in the SHA2-256 line); the answer is the same when asked again; and
// the .dgst does not depend on the name.
func FuzzSumFor(f *testing.F) {
	seeds := []struct {
		data, name string
		format     uint8
	}{
		{telemtSum, "telemt-x86_64-linux-musl.tar.gz", 0},
		{mtgSums, "mtg-2.2.8-linux-amd64.tar.gz", 0},
		{mtgSums, "mtg-2.2.8-linux-arm64.tar.gz", 0},
		{mtgSums, "mtg-2.2.8-linux-riscv64.tar.gz", 0},
		{hexA + "\n", "x", 0},
		{hexA, "x", 0},
		{strings.ToUpper(hexA) + " *a.tar.gz\r\n", "a.tar.gz", 0},
		{hexA + "  a.tar.gz\n" + hexB + "  a.tar.gz\n", "a.tar.gz", 0},
		{hexA[:40] + "  a.tar.gz\n", "a.tar.gz", 0},
		{hexA + "  ./a.tar.gz\n", "a.tar.gz", 0},
		{hexA + "  \n", "", 0},
		{"", "a", 0},
		{"\x00\xff\n", "a", 0},
		{xrayDgst, "Xray-linux-64.zip", 1},
		{warpDgst, "warp-plus_linux-amd64.zip", 1},
		{"SHA2-256=" + hexA, "", 1},
		{"SHA2-256= " + hexA + "\nSHA2-256= " + hexB + "\n", "", 1},
		{"SHA2-256= \n", "", 1},
		{"MD5= x\n", "", 1},
		{"=\n=\n", "", 1},
	}
	for _, s := range seeds {
		f.Add([]byte(s.data), s.name, s.format)
	}

	f.Fuzz(func(t *testing.T, data []byte, name string, format uint8) {
		sf := release.SumsFormat(format % 2)
		sum, err := release.SumFor(name, data, sf)
		if err != nil {
			if sum != "" {
				t.Fatalf("SumFor returned %q along with the error %v", sum, err)
			}
			return
		}
		if !isLowerHex64(sum) {
			t.Fatalf("SumFor returned %q, want 64 lower-case hex digits", sum)
		}
		text := asciiLower(string(data))
		if !strings.Contains(text, sum) {
			t.Fatalf("SumFor returned %s, which is not in the file", sum)
		}
		// Where it came from.
		var from bool
		switch sf {
		case release.SumsSHA256:
			if strings.TrimSpace(text) == sum {
				from = true // a file that holds only the sum
			}
			for line := range strings.SplitSeq(text, "\n") {
				if strings.Contains(line, sum) && strings.Contains(line, asciiLower(name)) {
					from = true
				}
			}
		case release.SumsDgst:
			for line := range strings.SplitSeq(text, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "sha2-256") && strings.Contains(line, sum) {
					from = true
				}
			}
		}
		if !from {
			t.Fatalf("SumFor returned %s, which no line of the file gives for %q", sum, name)
		}

		again, err := release.SumFor(name, data, sf)
		if err != nil || again != sum {
			t.Fatalf("asked again: %q, %v; the first time %q", again, err, sum)
		}
		if sf == release.SumsDgst {
			other, err := release.SumFor(name+"-other", data, sf)
			if err != nil || other != sum {
				t.Fatalf("the .dgst gave %q, %v for another name, %q for this one", other, err, sum)
			}
		}
	})
}

// countingReaderAt counts the reads and the bytes that are read.
type countingReaderAt struct {
	r     io.ReaderAt
	calls int
	bytes int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.calls++
	c.bytes += n
	return n, err
}

// FuzzCheckStaticELF feeds arbitrary bytes to CheckStaticELF. On every input:
// no panic; with a supported architecture the answer is nil or one of the
// three errors about files, and with another one an error that is none of
// them; a file is never read in a quantity that is not set by the header (a
// table of 65534 entries at the most, which is less than 4 MiB, of a file that
// can be 256 MiB); and, where debug/elf can read the file, it agrees: a file is
// accepted only if the standard library sees an executable of that platform
// without an interpreter, it is called dynamic only if it sees an interpreter,
// it is called of another platform only if the platform is another one, and a
// file is refused as no ELF only for what is no program, for a table of program
// headers that the kernel refuses (no entry, or entries that are not 56 bytes
// each) or for a count of program headers that is kept in a section header
// (which is not read).
func FuzzCheckStaticELF(f *testing.F) {
	for _, s := range elfSeeds(f) {
		for sel := range uint8(3) {
			f.Add(s, sel)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte, sel uint8) {
		arch := []string{"amd64", "arm64", "386"}[sel%3]
		r := &countingReaderAt{r: bytes.NewReader(data)}
		err := release.CheckStaticELF(r, arch)

		if r.bytes > 4<<20 {
			t.Fatalf("%d bytes were read in %d reads", r.bytes, r.calls)
		}
		if arch == "386" {
			if err == nil {
				t.Fatal("an unsupported architecture was accepted")
			}
			for _, s := range elfSentinels {
				if errors.Is(err, s) {
					t.Fatalf("an unsupported architecture gave %v", err)
				}
			}
			return
		}
		if err != nil && !errors.Is(err, release.ErrNotELF) && !errors.Is(err, release.ErrWrongArch) && !errors.Is(err, release.ErrDynamic) {
			t.Fatalf("err = %v, which is none of the errors about files (the reader cannot fail)", err)
		}

		std, perr := elf.NewFile(bytes.NewReader(data))
		if perr != nil {
			return // the standard library is stricter; nothing to compare with
		}
		want := elf.EM_X86_64
		if arch == "arm64" {
			want = elf.EM_AARCH64
		}
		platformOK := std.Class == elf.ELFCLASS64 && std.Data == elf.ELFDATA2LSB && std.Machine == want
		program := platformOK && (std.Type == elf.ET_EXEC || std.Type == elf.ET_DYN)
		interp := slices.ContainsFunc(std.Progs, func(p *elf.Prog) bool { return p.Type == elf.PT_INTERP })
		// What the kernel asks of the table, and debug/elf does not: at least one
		// entry, of 56 bytes, and a count that is not the one kept in a section
		// header (which is not read).
		table := false
		if platformOK && len(data) >= 58 {
			phentsize, phnum := binary.LittleEndian.Uint16(data[54:]), binary.LittleEndian.Uint16(data[56:])
			table = phentsize == 56 && phnum != 0 && phnum != 0xffff
		}

		switch {
		case err == nil:
			if !program || interp || !table {
				t.Fatalf("accepted a file that debug/elf reads as: platform ok %v, program %v, interpreter %v, a table that the kernel takes %v", platformOK, program, interp, table)
			}
		case errors.Is(err, release.ErrDynamic):
			if !program || !interp || !table {
				t.Fatalf("called a file dynamic that debug/elf reads as: program %v, interpreter %v, a table that the kernel takes %v", program, interp, table)
			}
		case errors.Is(err, release.ErrWrongArch):
			if platformOK {
				t.Fatal("called a file of another platform that debug/elf reads as this one")
			}
		case errors.Is(err, release.ErrNotELF):
			if program && table {
				t.Fatalf("refused as no ELF a program that debug/elf reads, with a table that the kernel takes: %v", err)
			}
		}
		if program && !interp && table && err != nil {
			t.Fatalf("refused a static program that debug/elf reads: %v", err)
		}
	})
}

// keyFromSeed makes a key pair from the seed that is part of a fuzz input, so
// that every input has a key of its own, and a signature can be made for it. The
// seeds of the corpus are made when the test runs, from the system's random
// numbers, so no key is kept anywhere; and, as the key comes from the input,
// every process of the fuzz engine (each of which runs the setup of its own)
// gets the same key for the same input.
func keyFromSeed(t testing.TB, seed []byte) keyPair {
	t.Helper()
	h := sha256.Sum256(seed)
	pub, priv, err := minisign.GenerateKey(bytes.NewReader(h[:]))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return keyPair{pub, priv}
}

// FuzzVerifyWith feeds arbitrary signature bytes, data and a version to
// VerifyWith, with one key that the input makes (see keyFromSeed), for the
// artifact {postern-node, version, linux, amd64}. On every input: no panic, and
// the answer is the one that the pieces that it is made of give, worked out
// again here from minisign's own parser and Verify: a version that is not one is
// a plain error; a signature that does not parse, or does not verify, is
// ErrBadSignature; one that has another key id is ErrUntrustedKey; one that is
// good for another artifact is ErrWrongArtifact; the rest is accepted. So it is
// also checked that nothing is accepted that minisign does not, and that
// nothing that minisign accepts for this artifact is refused.
func FuzzVerifyWith(f *testing.F) {
	seed := randomBytes(f, 32)
	kp := keyFromSeed(f, seed)
	data := randomBytes(f, 200)
	prehashed := sign(f, data, kp, nodeAMD64)
	legacy := minisign.SignWithComments(kp.priv, data, nodeAMD64.TrustedComment(), "legacy")
	otherComment := bytes.Replace(prehashed, []byte("v0.5.0"), []byte("v0.5.1"), 1)

	for _, c := range []struct {
		sig     []byte
		version string
	}{
		{prehashed, "v0.5.0"},
		{legacy, "v0.5.0"},
		{prehashed, "v0.5.1"},             // good for another artifact
		{prehashed, "v0.5.0 linux/amd64"}, // a want that is not one
		{prehashed, ""},
		{otherComment, "v0.5.0"}, // a comment that was changed
		{otherComment, "v0.5.1"}, //
		{append(bytes.Clone(prehashed), "junk\n"...), "v0.5.0"},
		{prehashed[:len(prehashed)/2], "v0.5.0"},
		{bytes.ReplaceAll(prehashed, []byte("\n"), []byte("\r\n")), "v0.5.0"},
		{bytes.Replace(prehashed, []byte("RU"), []byte("RW"), 1), "v0.5.0"}, // ED made Ed
		{nil, "v0.5.0"},
		{[]byte("untrusted comment: x\n"), "v0.5.0"},
		{[]byte("untrusted comment: x\nRWQ\ntrusted comment: y\nAAAA\n"), "v0.5.0"},
		{sign(f, data, keyFromSeed(f, randomBytes(f, 32)), nodeAMD64), "v0.5.0"}, // another key
	} {
		f.Add(seed, data, c.sig, c.version)
	}
	f.Add(seed, data[:100], prehashed, "v0.5.0") // other data than what was signed

	f.Fuzz(func(t *testing.T, seed, data, sig []byte, version string) {
		kp := keyFromSeed(t, seed)
		want := release.Signed{Component: "postern-node", Version: version, OS: "linux", Arch: "amd64"}
		err := release.VerifyWith(bytes.NewReader(data), sig, want, []minisign.PublicKey{kp.pub})

		// What the answer has to be.
		const (
			accepted = iota
			bad
			untrusted
			wrong
			plain
		)
		expect := accepted
		var parsed minisign.Signature
		switch {
		case !release.ValidVersion(version):
			expect = plain
		case parsed.UnmarshalText(sig) != nil:
			expect = bad
		case parsed.KeyID != kp.pub.ID():
			expect = untrusted
		case !minisign.Verify(kp.pub, data, sig):
			expect = bad
		case parsed.TrustedComment != want.TrustedComment():
			expect = wrong
		}

		sentinels := map[int]error{bad: release.ErrBadSignature, untrusted: release.ErrUntrustedKey, wrong: release.ErrWrongArtifact}
		switch expect {
		case accepted:
			if err != nil {
				t.Fatalf("refused what minisign accepts for this artifact: %v", err)
			}
		case plain:
			if err == nil {
				t.Fatalf("accepted a want that is not valid (version %q)", version)
			}
			for _, s := range append(slices.Collect(maps.Values(sentinels)), release.ErrNoKeys) {
				if errors.Is(err, s) {
					t.Fatalf("a want that is not valid gave %v", err)
				}
			}
		default:
			for kind, s := range sentinels {
				if errors.Is(err, s) != (kind == expect) {
					t.Fatalf("err = %v, want %v (and no other of the three): errors.Is(err, %v) = %v", err, sentinels[expect], s, errors.Is(err, s))
				}
			}
		}
	})
}
