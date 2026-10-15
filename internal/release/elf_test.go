package release_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/release"
)

// image describes the headers of a synthetic ELF file. The headers are written
// with the structures of debug/elf, so that the layout is the one of the
// standard library and not the one that the test imagines.
type image struct {
	class     elf.Class
	data      elf.Data
	typ       elf.Type
	machine   elf.Machine
	progs     []elf.ProgType
	phentsize int // 0 = the size of a program header; more leaves a gap after each
	gap       int // bytes between the ELF header and the program headers
}

func (im image) bytes(t testing.TB) []byte {
	t.Helper()
	var bo binary.ByteOrder = binary.LittleEndian
	if im.data == elf.ELFDATA2MSB {
		bo = binary.BigEndian
	}
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(im.class), byte(im.data), byte(elf.EV_CURRENT)}
	var buf bytes.Buffer
	put := func(v any) {
		if err := binary.Write(&buf, bo, v); err != nil {
			t.Fatalf("binary.Write(%T): %v", v, err)
		}
	}
	ehsize, phsize := 64, 56
	if im.class == elf.ELFCLASS32 {
		ehsize, phsize = 52, 32
	}
	phentsize := phsize
	if im.phentsize != 0 {
		phentsize = im.phentsize
	}
	phoff := ehsize + im.gap

	if im.class == elf.ELFCLASS32 {
		put(elf.Header32{
			Ident: ident, Type: uint16(im.typ), Machine: uint16(im.machine), Version: uint32(elf.EV_CURRENT),
			Phoff: uint32(phoff), Ehsize: uint16(ehsize), Phentsize: uint16(phentsize), Phnum: uint16(len(im.progs)),
		})
	} else {
		put(elf.Header64{
			Ident: ident, Type: uint16(im.typ), Machine: uint16(im.machine), Version: uint32(elf.EV_CURRENT),
			Phoff: uint64(phoff), Ehsize: uint16(ehsize), Phentsize: uint16(phentsize), Phnum: uint16(len(im.progs)),
		})
	}
	buf.Write(make([]byte, im.gap))
	for _, p := range im.progs {
		start := buf.Len()
		if im.class == elf.ELFCLASS32 {
			put(elf.Prog32{Type: uint32(p), Flags: uint32(elf.PF_R)})
		} else {
			put(elf.Prog64{Type: uint32(p), Flags: uint32(elf.PF_R)})
		}
		buf.Write(make([]byte, phentsize-(buf.Len()-start)))
	}
	// A body after the headers, as a real file has; the check does not read it.
	buf.Write(bytes.Repeat([]byte{0xcc}, 128))
	return buf.Bytes()
}

// exec64 is the headers of an ELF64 little-endian file, as every binary that we
// take is.
func exec64(machine elf.Machine, typ elf.Type, progs ...elf.ProgType) image {
	return image{class: elf.ELFCLASS64, data: elf.ELFDATA2LSB, typ: typ, machine: machine, progs: progs}
}

// headersEnd is the length of the part of an ELF64 image that the check needs
// when it has program headers: up to the end of the last of them (an entry that
// is wider than a program header has padding that is not read).
func (im image) headersEnd() int {
	return 64 + im.gap + (len(im.progs)-1)*max(im.phentsize, 56) + 56
}

// progsWith returns n program header types that are PT_LOAD, but the one at
// index at, which is typ.
func progsWith(n, at int, typ elf.ProgType) []elf.ProgType {
	progs := make([]elf.ProgType, n)
	for i := range progs {
		progs[i] = elf.PT_LOAD
	}
	progs[at] = typ
	return progs
}

func poke16(b []byte, off int, v uint16) []byte {
	b = bytes.Clone(b)
	binary.LittleEndian.PutUint16(b[off:], v)
	return b
}

func poke64(b []byte, off int, v uint64) []byte {
	b = bytes.Clone(b)
	binary.LittleEndian.PutUint64(b[off:], v)
	return b
}

// The fields of an ELF64 header, by their offsets.
const (
	offType      = 16
	offPhoff     = 32
	offPhentsize = 54
	offPhnum     = 56
)

// Real headers (the ELF header and the program header table, which is all that
// the check reads) of three files. The first two are executables of the Go
// toolchain 1.27.1, built with CGO_ENABLED=0 for linux/amd64 and linux/arm64:
// the kind of binary that mtg, Xray and warp-plus ship. The third is
// /bin/busybox of the runner image alpine:3.22, a dynamic musl executable that
// asks for /lib/ld-musl-x86_64.so.1.
const (
	// upxPackedAMD64 is the first 256 bytes of psiphon-tunnel-core-x86_64 of
	// Psiphon-Labs/psiphon-tunnel-core-binaries at 33ff79e8: the headers of the
	// UPX unpacker (three program headers, none an interpreter) and the start
	// of its l_info, "UPX!" at offset 236.
	upxPackedAMD64 = `
7f454c4602010100000000000000000002003e0001000000608bdf0000000000
4000000000000000000000000000000000000000400038000300400000000000
0100000005000000000000000000000000004000000000000000400000000000
8b939f00000000008b939f000000000000000100000000000100000006000000
c0cd000000000000c0cdfd0300000000c0cdfd03000000000000000000000000
0000000000000000001000000000000051e57464060000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0800000000000000feae2a3b5550582138080d16000000000911b9010911b901`
	goStaticAMD64 = `
7f454c4602010100000000000000000002003e000100000060c2470000000000
400000000000000090010000000000000000000040003800060040001a001900
0600000004000000400000000000000040004000000000004000400000000000
5001000000000000500100000000000000100000000000000400000004000000
780f000000000000780f400000000000780f4000000000006400000000000000
6400000000000000040000000000000001000000050000000000000000000000
0000400000000000000040000000000071db07000000000071db070000000000
0010000000000000010000000400000000e007000000000000e0470000000000
00e0470000000000483b0a0000000000483b0a00000000000010000000000000
0100000006000000002012000000000000205200000000000020520000000000
a072000000000000a8ca030000000000001000000000000051e5746406000000
0000000000000000000000000000000000000000000000000000000000000000
00000000000000000800000000000000`

	goStaticARM64 = `
7f454c460201010000000000000000000200b700010000001067080000000000
400000000000000090010000000000000000000040003800060040001a001900
0600000004000000400000000000000040000100000000004000010000000000
5001000000000000500100000000000000000100000000000400000004000000
780f000000000000780f010000000000780f0100000000006400000000000000
6400000000000000040000000000000001000000050000000000000000000000
00000100000000000000010000000000847f070000000000847f070000000000
0000010000000000010000000400000000000800000000000000090000000000
0000090000000000b0a4090000000000b0a40900000000000000010000000000
0100000006000000000012000000000000001300000000000000130000000000
60720000000000000832040000000000000001000000000051e5746406000000
0000000000000000000000000000000000000000000000000000000000000000
00000000000000000800000000000000`

	alpineBusyboxDynamic = `
7f454c4602010100000000000000000003003e0001000000d16e000000000000
400000000000000008510c000000000000000000400038000c00400018001700
0600000004000000400000000000000040000000000000004000000000000000
a002000000000000a00200000000000008000000000000000300000004000000
3403000000000000340300000000000034030000000000001900000000000000
1900000000000000010000000000000001000000040000000000000000000000
00000000000000000000000000000000405b000000000000405b000000000000
0010000000000000010000000500000000600000000000000060000000000000
0060000000000000cc91090000000000cc910900000000000010000000000000
010000000400000000000a000000000000000a000000000000000a0000000000
b411020000000000b41102000000000000100000000000000100000006000000
10180c000000000010280c000000000010280c00000000002038000000000000
48430000000000000010000000000000020000000600000010420c0000000000
10520c000000000010520c0000000000f001000000000000f001000000000000
08000000000000000400000004000000e002000000000000e002000000000000
e002000000000000300000000000000030000000000000000800000000000000
0400000004000000100300000000000010030000000000001003000000000000
24000000000000002400000000000000040000000000000053e5746404000000
e002000000000000e002000000000000e0020000000000003000000000000000
3000000000000000080000000000000051e57464060000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
100000000000000052e574640400000010180c000000000010280c0000000000
10280c0000000000f037000000000000f0370000000000000100000000000000`
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// checkELF runs the check on data, with the Reader that the callers have.
func checkELF(data []byte, arch string) error {
	return release.CheckStaticELF(bytes.NewReader(data), arch)
}

var elfSentinels = []error{release.ErrNotELF, release.ErrWrongArch, release.ErrDynamic, release.ErrPacked}

// wantELF fails the test unless err is nil when want is nil and, otherwise, is
// want and no other of the three.
func wantELF(t *testing.T, err, want error) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
		return
	}
	for _, s := range elfSentinels {
		if got := errors.Is(err, s); got != (s == want) {
			t.Errorf("errors.Is(%v, %v) = %v, want %v", err, s, got, s == want)
		}
	}
}

func TestCheckStaticELF(t *testing.T) {
	const (
		amd64 = elf.EM_X86_64
		arm64 = elf.EM_AARCH64
	)
	dynamicProgs := []elf.ProgType{elf.PT_PHDR, elf.PT_INTERP, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}
	tests := []struct {
		name string
		im   image
		arch string
		want error
	}{
		// What is taken.
		{"amd64 static executable", exec64(amd64, elf.ET_EXEC, elf.PT_PHDR, elf.PT_NOTE, elf.PT_LOAD, elf.PT_LOAD, elf.PT_GNU_STACK), "amd64", nil},
		{"amd64 static-pie, a shared object without an interpreter", exec64(amd64, elf.ET_DYN, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_RELRO, elf.PT_GNU_STACK), "amd64", nil},
		{"arm64 static executable", exec64(arm64, elf.ET_EXEC, elf.PT_LOAD, elf.PT_NOTE, elf.PT_GNU_STACK), "arm64", nil},
		{"arm64 static-pie", exec64(arm64, elf.ET_DYN, elf.PT_LOAD, elf.PT_DYNAMIC), "arm64", nil},
		{"amd64 headers that name other segments than interpreters", exec64(amd64, elf.ET_EXEC, elf.PT_NULL, elf.PT_SHLIB, elf.PT_TLS, elf.PT_GNU_EH_FRAME), "amd64", nil},

		// The interpreter, wherever it is, whatever the type.
		{"amd64 dynamic executable", exec64(amd64, elf.ET_EXEC, dynamicProgs...), "amd64", release.ErrDynamic},
		{"amd64 dynamic pie", exec64(amd64, elf.ET_DYN, dynamicProgs...), "amd64", release.ErrDynamic},
		{"arm64 dynamic executable", exec64(arm64, elf.ET_EXEC, dynamicProgs...), "arm64", release.ErrDynamic},
		{"interpreter first", exec64(amd64, elf.ET_EXEC, elf.PT_INTERP), "amd64", release.ErrDynamic},
		{"interpreter last", exec64(amd64, elf.ET_EXEC, elf.PT_LOAD, elf.PT_LOAD, elf.PT_LOAD, elf.PT_NOTE, elf.PT_GNU_STACK, elf.PT_INTERP), "amd64", release.ErrDynamic},
		{"interpreter among sixty headers", exec64(amd64, elf.ET_DYN, progsWith(60, 41, elf.PT_INTERP)...), "amd64", release.ErrDynamic},
		{"sixty headers and no interpreter", exec64(amd64, elf.ET_DYN, progsWith(60, 41, elf.PT_NOTE)...), "amd64", nil},

		// Another platform.
		{"arm64 binary, amd64 wanted", exec64(arm64, elf.ET_EXEC, elf.PT_LOAD), "amd64", release.ErrWrongArch},
		{"amd64 binary, arm64 wanted", exec64(amd64, elf.ET_EXEC, elf.PT_LOAD), "arm64", release.ErrWrongArch},
		{"386 binary", image{class: elf.ELFCLASS32, data: elf.ELFDATA2LSB, typ: elf.ET_EXEC, machine: elf.EM_386, progs: []elf.ProgType{elf.PT_LOAD}}, "amd64", release.ErrWrongArch},
		{"ELFCLASS32 whatever the machine is", image{class: elf.ELFCLASS32, data: elf.ELFDATA2LSB, typ: elf.ET_EXEC, machine: elf.EM_X86_64, progs: []elf.ProgType{elf.PT_LOAD}}, "amd64", release.ErrWrongArch},
		{"ELFCLASS32 arm", image{class: elf.ELFCLASS32, data: elf.ELFDATA2LSB, typ: elf.ET_EXEC, machine: elf.EM_ARM, progs: []elf.ProgType{elf.PT_LOAD}}, "arm64", release.ErrWrongArch},
		{"big-endian amd64", image{class: elf.ELFCLASS64, data: elf.ELFDATA2MSB, typ: elf.ET_EXEC, machine: elf.EM_X86_64, progs: []elf.ProgType{elf.PT_LOAD}}, "amd64", release.ErrWrongArch},
		{"big-endian arm64", image{class: elf.ELFCLASS64, data: elf.ELFDATA2MSB, typ: elf.ET_EXEC, machine: elf.EM_AARCH64, progs: []elf.ProgType{elf.PT_LOAD}}, "arm64", release.ErrWrongArch},
		{"riscv", exec64(elf.EM_RISCV, elf.ET_EXEC, elf.PT_LOAD), "amd64", release.ErrWrongArch},
		{"ppc64", exec64(elf.EM_PPC64, elf.ET_EXEC, elf.PT_LOAD), "arm64", release.ErrWrongArch},
		{"no machine", exec64(elf.EM_NONE, elf.ET_EXEC, elf.PT_LOAD), "amd64", release.ErrWrongArch},
		{"another platform and a dynamic one", exec64(arm64, elf.ET_EXEC, dynamicProgs...), "amd64", release.ErrWrongArch},

		// ELF files that are not programs.
		{"relocatable object", exec64(amd64, elf.ET_REL, elf.PT_LOAD), "amd64", release.ErrNotELF},
		{"core dump", exec64(amd64, elf.ET_CORE, elf.PT_LOAD), "amd64", release.ErrNotELF},
		{"no type", exec64(amd64, elf.ET_NONE, elf.PT_LOAD), "amd64", release.ErrNotELF},
		{"a processor specific type", exec64(amd64, elf.Type(0xff00), elf.PT_LOAD), "amd64", release.ErrNotELF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.im.bytes(t)
			wantELF(t, checkELF(data, tc.arch), tc.want)

			// The images are what they claim to be: the standard library reads
			// them the same way, so that the test is not checking itself.
			f, err := elf.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("debug/elf does not read the image: %v", err)
			}
			if f.Class != tc.im.class || f.Data != tc.im.data || f.Type != tc.im.typ || f.Machine != tc.im.machine || len(f.Progs) != len(tc.im.progs) {
				t.Errorf("debug/elf reads %v %v %v %v with %d headers, the image is %v %v %v %v with %d", f.Class, f.Data, f.Type, f.Machine, len(f.Progs), tc.im.class, tc.im.data, tc.im.typ, tc.im.machine, len(tc.im.progs))
			}
			for i, p := range f.Progs {
				if p.Type != tc.im.progs[i] {
					t.Errorf("program header %d is %v, the image has %v", i, p.Type, tc.im.progs[i])
				}
			}
		})
	}
}

func TestCheckStaticELFLayouts(t *testing.T) {
	// Where the program headers are, and how far apart, is in the header.
	amd64 := elf.EM_X86_64
	t.Run("entries that are not 56 bytes each", func(t *testing.T) {
		// The kernel refuses a file whose e_phentsize is not the size of a program
		// header, so the file does not run, whatever its headers say: the headers
		// of the third entry, an interpreter or not, change nothing.
		for _, size := range []int{57, 64, 100, 1000} {
			for _, progs := range [][]elf.ProgType{
				{elf.PT_LOAD, elf.PT_LOAD, elf.PT_INTERP, elf.PT_LOAD},
				{elf.PT_LOAD, elf.PT_LOAD, elf.PT_NOTE, elf.PT_LOAD},
			} {
				im := exec64(amd64, elf.ET_EXEC, progs...)
				im.phentsize = size
				wantELF(t, checkELF(im.bytes(t), "amd64"), release.ErrNotELF)
			}
		}
	})
	t.Run("headers not right behind the ELF header", func(t *testing.T) {
		im := exec64(amd64, elf.ET_DYN, elf.PT_LOAD, elf.PT_INTERP)
		im.gap = 200
		wantELF(t, checkELF(im.bytes(t), "amd64"), release.ErrDynamic)
		im.progs = []elf.ProgType{elf.PT_LOAD, elf.PT_DYNAMIC}
		wantELF(t, checkELF(im.bytes(t), "amd64"), nil)
	})
	t.Run("the bytes in the gap are not headers", func(t *testing.T) {
		// A PT_INTERP type value lying where no header is.
		im := exec64(amd64, elf.ET_EXEC, elf.PT_LOAD)
		im.gap = 56
		data := im.bytes(t)
		binary.LittleEndian.PutUint32(data[64:], uint32(elf.PT_INTERP))
		wantELF(t, checkELF(data, "amd64"), nil)
	})
	t.Run("no program headers", func(t *testing.T) {
		// Linux refuses a file with no program header (ENOEXEC): it does not run,
		// so it is not taken for a static program, which would be pinned for good
		// by a checksum that has nothing to say about it.
		for _, typ := range []elf.Type{elf.ET_EXEC, elf.ET_DYN} {
			for _, arch := range []string{"amd64", "arm64"} {
				machine := elf.EM_X86_64
				if arch == "arm64" {
					machine = elf.EM_AARCH64
				}
				wantELF(t, checkELF(exec64(machine, typ).bytes(t), arch), release.ErrNotELF)
			}
		}
	})
}

func TestCheckStaticELFNotELF(t *testing.T) {
	good := exec64(elf.EM_X86_64, elf.ET_EXEC, elf.PT_PHDR, elf.PT_LOAD, elf.PT_LOAD, elf.PT_GNU_STACK)
	data := good.bytes(t)
	end := good.headersEnd()

	t.Run("not ELF at all", func(t *testing.T) {
		inputs := map[string][]byte{
			"nil":                nil,
			"empty":              {},
			"shell script":       []byte("#!/bin/sh\nexec telemt \"$@\"\n"),
			"short shell script": []byte("#!/bin/sh"),
			"long shell script":  bytes.Repeat([]byte("#!/bin/sh\necho hi\n"), 64),
			"gzip":               {0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			"zip":                append([]byte("PK\x03\x04"), make([]byte, 100)...),
			"PE":                 append([]byte("MZ"), make([]byte, 100)...),
			"Mach-O":             append([]byte{0xcf, 0xfa, 0xed, 0xfe}, make([]byte, 100)...),
			"html":               []byte("<!DOCTYPE html><html><body>404 Not Found</body></html>"),
			"zeros":              make([]byte, 4096),
			"magic with a typo":  append([]byte("\x7fELG"), data[4:]...),
			"magic in lower":     append([]byte("\x7felf"), data[4:]...),
			"magic one byte in":  append([]byte{0}, data...),
		}
		for name, in := range inputs {
			t.Run(name, func(t *testing.T) {
				for _, arch := range []string{"amd64", "arm64"} {
					wantELF(t, checkELF(in, arch), release.ErrNotELF)
				}
			})
		}
	})
	t.Run("truncated", func(t *testing.T) {
		// Every cut inside the headers, from nothing up to one byte short of the
		// last program header, is a file that was not downloaded to the end.
		for n := range end {
			wantELF(t, checkELF(data[:n], "amd64"), release.ErrNotELF)
		}
		// From there on the body does not matter.
		for _, n := range []int{end, end + 1, len(data)} {
			wantELF(t, checkELF(data[:n], "amd64"), nil)
		}
	})
	t.Run("header fields that cannot be right", func(t *testing.T) {
		tests := []struct {
			name string
			data []byte
		}{
			{"extended program header count", poke16(data, offPhnum, 0xffff)},
			{"program header entries too small", poke16(data, offPhentsize, 20)},
			{"program header entries of no size", poke16(data, offPhentsize, 0)},
			{"program header entries of 55 bytes", poke16(data, offPhentsize, 55)},
			{"program header entries of 57 bytes", poke16(data, offPhentsize, 57)},
			{"program header entries of 64 bytes", poke16(data, offPhentsize, 64)},
			{"program header entries of the biggest size", poke16(data, offPhentsize, 0xffff)},
			{"no program headers", poke16(data, offPhnum, 0)},
			{"program headers past the end", poke64(data, offPhoff, 1<<40)},
			{"program headers at the end of the address space", poke64(data, offPhoff, math.MaxUint64)},
			{"program headers at an offset that is negative as an int64", poke64(data, offPhoff, 1<<63)},
			{"program headers just short of the int64 limit", poke64(data, offPhoff, math.MaxInt64-8)},
			{"more headers than the file has", poke16(data, offPhnum, 5000)},
			{"every header the format allows, none there", poke16(data, offPhnum, 0xfffe)},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				wantELF(t, checkELF(tc.data, "amd64"), release.ErrNotELF)
			})
		}
	})
	t.Run("an extended program header count in a file that holds that many entries", func(t *testing.T) {
		// 65535 entries of zeros follow the header. A reader that took 0xffff for
		// the count would find no interpreter among them and take the file; the
		// real count is in a section header, which is not read, so it is refused.
		long := append(bytes.Clone(data[:64]), make([]byte, 65535*56)...)
		wantELF(t, checkELF(poke16(long, offPhnum, 0xffff), "amd64"), release.ErrNotELF)
	})
	t.Run("the byte order and the class of the identification decide by themselves", func(t *testing.T) {
		// A header that says big-endian and is written little-endian, which no
		// tool makes: the machine reads as the right one, so only the flag can
		// tell. And the same for the class.
		for _, v := range []byte{0, byte(elf.ELFDATA2MSB), 3, 0xff} {
			bad := bytes.Clone(data)
			bad[elf.EI_DATA] = v
			wantELF(t, checkELF(bad, "amd64"), release.ErrWrongArch)
		}
		for _, v := range []byte{0, byte(elf.ELFCLASS32), 3, 0xff} {
			bad := bytes.Clone(data)
			bad[elf.EI_CLASS] = v
			wantELF(t, checkELF(bad, "amd64"), release.ErrWrongArch)
		}
	})
	t.Run("a header count that runs past the end of a file that is long enough", func(t *testing.T) {
		// 4000 headers claimed, 4 present, the body of the image after them: the
		// entries after the fourth are body bytes, and then there are none.
		long := bytes.Clone(data)
		long = append(long, make([]byte, 56*1000)...)
		wantELF(t, checkELF(poke16(long, offPhnum, 4000), "amd64"), release.ErrNotELF)
	})
}

func TestCheckStaticELFArch(t *testing.T) {
	data := exec64(elf.EM_X86_64, elf.ET_EXEC, elf.PT_LOAD).bytes(t)
	for _, arch := range []string{"386", "arm", "riscv64", "ppc64le", "s390x", "", "AMD64", "Arm64", "x86_64", "aarch64", "amd64 ", " amd64", "amd64\n", "linux/amd64"} {
		err := checkELF(data, arch)
		if err == nil {
			t.Errorf("arch %q accepted", arch)
			continue
		}
		// A platform that is not supported is a mistake of the caller, not a
		// finding about the file.
		for _, s := range elfSentinels {
			if errors.Is(err, s) {
				t.Errorf("arch %q: err = %v, want one that is none of the three about files", arch, err)
			}
		}
		if !strings.Contains(err.Error(), "architecture") {
			t.Errorf("arch %q: err = %q, want it to say that the architecture is not supported", arch, err)
		}
	}
	// Whatever is in the file, the architecture is refused first.
	if err := checkELF([]byte("#!/bin/sh"), "386"); err == nil || errors.Is(err, release.ErrNotELF) {
		t.Errorf("a script and arch 386: err = %v, want the unsupported architecture", err)
	}
}

func TestCheckStaticELFRealHeaders(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		arch string
		want error
	}{
		{"Go, static, amd64", goStaticAMD64, "amd64", nil},
		{"Go, static, amd64, arm64 wanted", goStaticAMD64, "arm64", release.ErrWrongArch},
		{"Go, static, arm64", goStaticARM64, "arm64", nil},
		{"Go, static, arm64, amd64 wanted", goStaticARM64, "amd64", release.ErrWrongArch},
		{"busybox of alpine:3.22, dynamic", alpineBusyboxDynamic, "amd64", release.ErrDynamic},
		{"busybox of alpine:3.22, arm64 wanted", alpineBusyboxDynamic, "arm64", release.ErrWrongArch},
		// Psiphon's prebuilt client: UPX-packed, a glibc program inside, which
		// the headers of the unpacker do not show (no PT_INTERP).
		{"psiphon-tunnel-core-x86_64, UPX-packed", upxPackedAMD64, "amd64", release.ErrPacked},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantELF(t, checkELF(mustHex(t, tc.hex), tc.arch), tc.want)
		})
	}
	// Cut anywhere inside the table, a real file is a truncated one.
	data := mustHex(t, goStaticAMD64)
	for _, n := range []int{0, 15, 16, 19, 20, 63, 64, 100, 399} {
		wantELF(t, checkELF(data[:n], "amd64"), release.ErrNotELF)
	}
}

// failingReaderAt returns err from every read that starts at or after limit.
type failingReaderAt struct {
	r     io.ReaderAt
	limit int64
	err   error
}

func (f failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.limit {
		return 0, f.err
	}
	return f.r.ReadAt(p, off)
}

func TestCheckStaticELFReadError(t *testing.T) {
	// A disk that fails is not a file that is no ELF: the error of the read is
	// the answer, and none of the findings about the file.
	boom := errors.New("boom")
	data := exec64(elf.EM_X86_64, elf.ET_EXEC, elf.PT_LOAD, elf.PT_LOAD).bytes(t)
	for _, limit := range []int64{0, 10, 20, 40, 64, 100} {
		err := release.CheckStaticELF(failingReaderAt{bytes.NewReader(data), limit, boom}, "amd64")
		if !errors.Is(err, boom) {
			t.Errorf("limit %d: err = %v, want one that wraps the error of the reader", limit, err)
		}
		for _, s := range elfSentinels {
			if errors.Is(err, s) {
				t.Errorf("limit %d: err = %v: a failed read is not %v", limit, err, s)
			}
		}
	}
}

// elfSeeds is the corpus of the fuzz test and of its regular run.
func elfSeeds(t testing.TB) [][]byte {
	t.Helper()
	const (
		amd64 = elf.EM_X86_64
		arm64 = elf.EM_AARCH64
	)
	seeds := [][]byte{
		exec64(amd64, elf.ET_EXEC, elf.PT_PHDR, elf.PT_LOAD, elf.PT_GNU_STACK).bytes(t),
		exec64(amd64, elf.ET_DYN, elf.PT_LOAD, elf.PT_DYNAMIC).bytes(t),
		exec64(amd64, elf.ET_EXEC, elf.PT_PHDR, elf.PT_INTERP, elf.PT_LOAD).bytes(t),
		exec64(arm64, elf.ET_EXEC, elf.PT_LOAD).bytes(t),
		exec64(arm64, elf.ET_DYN, elf.PT_INTERP, elf.PT_LOAD).bytes(t),
		exec64(amd64, elf.ET_REL, elf.PT_LOAD).bytes(t),
		exec64(amd64, elf.ET_EXEC).bytes(t),
		image{class: elf.ELFCLASS32, data: elf.ELFDATA2LSB, typ: elf.ET_EXEC, machine: elf.EM_386, progs: []elf.ProgType{elf.PT_LOAD}}.bytes(t),
		image{class: elf.ELFCLASS64, data: elf.ELFDATA2MSB, typ: elf.ET_EXEC, machine: amd64, progs: []elf.ProgType{elf.PT_LOAD}}.bytes(t),
		mustHex(t, goStaticAMD64),
		mustHex(t, goStaticARM64),
		mustHex(t, alpineBusyboxDynamic),
		[]byte("#!/bin/sh\necho hi\n"),
		[]byte("\x7fELF"),
		{},
	}
	wide := exec64(amd64, elf.ET_EXEC, elf.PT_LOAD, elf.PT_INTERP)
	wide.phentsize, wide.gap = 64, 16
	seeds = append(seeds, wide.bytes(t))
	good := exec64(amd64, elf.ET_EXEC, elf.PT_LOAD, elf.PT_LOAD).bytes(t)
	seeds = append(seeds,
		poke16(good, offPhnum, 0xffff),
		poke16(good, offPhnum, 5000),
		poke16(good, offPhentsize, 20),
		poke64(good, offPhoff, 1<<63),
		poke64(good, offPhoff, math.MaxUint64),
		poke16(good, offType, uint16(elf.ET_DYN)),
	)
	return seeds
}
