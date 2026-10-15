package release

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

var (
	// ErrNotELF is returned for a file that is not an ELF program: there is no
	// ELF header, the file ends inside the headers, the headers cannot be right,
	// the table of program headers is one that the kernel refuses (no entry, or
	// entries of another size than 56 bytes), or it is an ELF file that is not a
	// program (an object file, a core dump).
	ErrNotELF = errors.New("release: not an ELF executable")

	// ErrWrongArch is returned for an ELF file that is for another platform than
	// the one that is wanted: it is not 64-bit, not little-endian, or it is built
	// for another machine.
	ErrWrongArch = errors.New("release: an ELF file for another platform")

	// ErrDynamic is returned for a program that has a PT_INTERP header, which
	// names the dynamic loader that has to be there for it to run. The engine
	// containers have none of the loaders of a distribution, and run static
	// programs only.
	ErrDynamic = errors.New("release: a dynamically linked ELF file")

	// ErrPacked is returned for a program that an executable packer (UPX) has
	// compressed: its headers are those of the unpacker, and the program that
	// it unpacks may well ask for a dynamic loader, which the check cannot see.
	// The detection is a heuristic: it catches the output of stock upx, and a
	// packer that hides its mark is not seen. Trust rests on the release
	// signature and the pinned SHA-256, not on this check.
	ErrPacked = errors.New("release: a packed (UPX) ELF file")
)

// upxMagic is the mark of UPX: its l_info, right after the program headers of
// the file it packs, starts with it. Finding it is a heuristic for stock upx
// output only; trust rests on the release signature and the pinned SHA-256.
// packedScan is how much of the start of
// the file is searched for it.
const (
	upxMagic   = "UPX!"
	packedScan = 4096
)

// Where the fields that the check reads are, in the ELF header and in a program
// header (Elf64_Ehdr and Elf64_Phdr of the ELF specification; debug/elf calls
// them Header64 and Prog64).
const (
	offType      = 16 // e_type, a uint16; e_machine, a uint16, is next to it
	offPhoff     = 32 // e_phoff, a uint64
	offPhentsize = 54 // e_phentsize, a uint16; e_phnum, a uint16, is next to it
	phdrSize     = 56 // the size of a program header; p_type, a uint32, is its first field
	pnXnum       = 0xffff
)

// CheckStaticELF reports whether r holds a program that can run on the
// architecture arch ("amd64" or "arm64") without a dynamic loader: an ELF64
// little-endian file for EM_X86_64 or EM_AARCH64, of type ET_EXEC or ET_DYN (a
// static PIE is the second), with no PT_INTERP among its program headers.
//
// A program packed by UPX is refused as [ErrPacked]: its headers are those of
// the unpacker, which hide whether the packed program needs a loader.
//
// It returns nil, [ErrNotELF], [ErrWrongArch], [ErrDynamic] or [ErrPacked], an error for an
// architecture that is not supported (which is no finding about the file), or
// the error of r if a read of it fails. Only the headers are read, at most
// 65534 program headers of 56 bytes whatever the size of the file.
//
// What the kernel refuses of the table of program headers, with ENOEXEC, is
// refused here as well, as [ErrNotELF]: a table with no entry, and one whose
// entries are not 56 bytes each (e_phentsize). Such a file does not run, so it
// would be pinned for good by a checksum that has nothing to say about it, and
// then fail in every trial.
func CheckStaticELF(r io.ReaderAt, arch string) error {
	var machine elf.Machine
	switch arch {
	case "amd64":
		machine = elf.EM_X86_64
	case "arm64":
		machine = elf.EM_AARCH64
	default:
		return fmt.Errorf("release: unsupported architecture %q (want amd64 or arm64)", arch)
	}

	var ident [elf.EI_NIDENT]byte
	if err := readAt(r, ident[:], 0); err != nil {
		return headerError(err)
	}
	if string(ident[:len(elf.ELFMAG)]) != elf.ELFMAG {
		return fmt.Errorf("%w: no ELF magic number", ErrNotELF)
	}
	if class := elf.Class(ident[elf.EI_CLASS]); class != elf.ELFCLASS64 {
		return fmt.Errorf("%w: %v, want %v", ErrWrongArch, class, elf.ELFCLASS64)
	}
	if data := elf.Data(ident[elf.EI_DATA]); data != elf.ELFDATA2LSB {
		return fmt.Errorf("%w: %v, want %v", ErrWrongArch, data, elf.ELFDATA2LSB)
	}

	var typeMachine [4]byte
	if err := readAt(r, typeMachine[:], offType); err != nil {
		return headerError(err)
	}
	typ := elf.Type(binary.LittleEndian.Uint16(typeMachine[0:]))
	if got := elf.Machine(binary.LittleEndian.Uint16(typeMachine[2:])); got != machine {
		return fmt.Errorf("%w: %v, want %v", ErrWrongArch, got, machine)
	}
	if typ != elf.ET_EXEC && typ != elf.ET_DYN {
		return fmt.Errorf("%w: the type is %v, not an executable or a shared object", ErrNotELF, typ)
	}

	var phoffBytes [8]byte
	if err := readAt(r, phoffBytes[:], offPhoff); err != nil {
		return headerError(err)
	}
	var sizes [4]byte
	if err := readAt(r, sizes[:], offPhentsize); err != nil {
		return headerError(err)
	}
	phoff := binary.LittleEndian.Uint64(phoffBytes[:])
	phentsize := uint64(binary.LittleEndian.Uint16(sizes[0:]))
	phnum := uint64(binary.LittleEndian.Uint16(sizes[2:]))
	switch {
	case phentsize != phdrSize:
		return fmt.Errorf("%w: program headers of %d bytes, not %d", ErrNotELF, phentsize, phdrSize)
	case phnum == 0:
		return fmt.Errorf("%w: no program headers", ErrNotELF)
	case phnum == pnXnum:
		return fmt.Errorf("%w: the number of program headers is kept in a section header", ErrNotELF)
	case phoff > math.MaxInt64 || phoff+phnum*phdrSize > math.MaxInt64:
		return fmt.Errorf("%w: the program headers are past the end of any file", ErrNotELF)
	}

	// Every header is read whole (a table that is cut short is a file that is cut
	// short), one program header size after the other.
	var entry [phdrSize]byte
	for i := range phnum {
		if err := readAt(r, entry[:], int64(phoff+i*phdrSize)); err != nil {
			return headerError(err)
		}
		if elf.ProgType(binary.LittleEndian.Uint32(entry[:])) == elf.PT_INTERP {
			return fmt.Errorf("%w: it asks for a dynamic loader (PT_INTERP)", ErrDynamic)
		}
	}
	return checkPacked(r)
}

// checkPacked refuses a file that holds the mark of UPX in its first
// packedScan bytes (a shorter file is searched whole).
func checkPacked(r io.ReaderAt) error {
	buf := make([]byte, packedScan)
	n, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("release: reading the ELF file: %w", err)
	}
	if bytes.Contains(buf[:n], []byte(upxMagic)) {
		return fmt.Errorf("%w: it holds the mark of UPX", ErrPacked)
	}
	return nil
}

// readAt fills p with the bytes of r at off. A read that falls short is
// io.ErrUnexpectedEOF, whether the reader says io.EOF or nothing; any other
// error is the reader's own.
func readAt(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil // a reader may say io.EOF together with the last bytes
	}
	if err == nil || errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// headerError turns the error of readAt into the answer of CheckStaticELF: a
// file that ends inside the headers is no ELF program, and a reader that fails
// says so as it is.
func headerError(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: the file ends inside the headers", ErrNotELF)
	}
	return fmt.Errorf("release: reading the ELF headers: %w", err)
}
