// Command release makes and checks the files of a Postern release: the key
// that signs it, the signatures of its binaries and of its checksums,
// SHA256SUMS, the bundle that a panel takes as an upload, and the notes.
// scripts/release.sh runs it to build a release, and docs/releasing.md says
// how the keys are made and kept:
//
//	go run ./scripts/release <command> [flags] [arguments]
//
// The signatures are those of internal/release: minisign, prehashed, with the
// trusted comment "postern <component> <version>", and " linux/<arch>" after it
// for a binary.
package main

import (
	"archive/tar"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/release"
)

const usageText = `Usage: go run ./scripts/release <command> [flags] [arguments]

Makes and checks the files of a Postern release (docs/releasing.md). The flags
of a command go before its arguments.

Commands:
  keygen --out <dir> [--unencrypted]
      Make a key pair. The secret key goes to <dir>/postern-release.key (0600),
      encrypted with the password in POSTERN_MINISIGN_PASSWORD unless
      --unencrypted is given (a throwaway key for tests); the public key is
      printed. <dir> must not be in a git working tree, and a key that is
      there already is never overwritten.
  pubkey --key <file>
      Print the public key of the secret key <file>.
  sign --key <file> --component <c> --version <v> [--arch <a>] <file>
      Sign <file> into <file>.minisig, with the trusted comment
      "postern <c> <v>", and " linux/<a>" after it for a binary. <c> is
      postern-node or postern-panel (with --arch amd64 or arm64, and the file
      a static program for it), sha256sums or engines-stable.
  verify --pubkey <key> --component <c> --version <v> [--arch <a>] <file>
      Check <file>.minisig: that the key <key> made it (the "RW..." line of
      a public key file, or the whole file), and for that artifact.
  sums <file>...
      Write SHA256SUMS next to the files, which are in one directory: their
      SHA-256 in the format of sha256sum, sorted by name.
  bundle --version <v> <dir>
      Write <dir>/postern-<v>-bundle.tar: the four binaries of Postern in
      <dir> and SHA256SUMS, each with its signature, and engines-stable.json
      with its signature when it is there. Every file has to be there, every
      signature has to be for its file, and every binary has to be listed in
      SHA256SUMS. A panel takes the bundle as an upload.
  changelog [--from <tag>] --to <tag>
      Print the notes of a release in Markdown: the subjects of the commits
      after --from (from the first commit without it) up to --to, merges
      left out, grouped by their conventional type into features, fixes,
      performance, security and the rest.
  keys
      Print the production keys that this build trusts, one to a line:
      <set> <key id> <public key>; the sets are release and stable.
  candidates [--stable <list>] [--component <c>]... --out <file>
      For each component of the panel (or each --component), find the newest
      upstream release that is not a prerelease, is newer than the newest
      stable version (built into the panel, or in the stable list <list>),
      and passes the checks: the files of both architectures download with
      the SHA-256 that the checksum rules expect (the digest of the API, the
      checksum file of the release), the binary comes out of the archive, and
      it is a static program of its architecture. Write the candidates and
      the newer releases that failed a check, with the reason, to <file>
      (JSON), and print a line for each: "candidate <c> <v>" or
      "skipped <c> <v>: <reason>". The API is POSTERN_GITHUB_API.
  stable-add [--list <list>] [--from <candidates>] [--drop <c>@<v>]... --out <file> [<c>@<v>...]
      Write to <file> the stable list <list> (none: an empty one) without
      the versions of --drop and with each <c>@<v>, a candidate of the file
      <candidates> that candidates wrote, which passed the end-to-end tests;
      the versions of each component sorted. A version in the list already is
      kept, and refused when its files or SHA-256 differ: a stable version
      never changes, and only a --drop removes one.
  stable-sign --key <file> <list>
      Date the stable list <list> now (generated_at, in Unix seconds, later
      than the date it had) and sign it into <list>.minisig with the trusted
      comment "postern engines-stable <generated_at>"; print generated_at.
      Once this build has production stable keys, a key that is not one of
      them is refused.
  check-build --version <v> --commit <c> --manifest-sha256 <hex> <dir>
      Check the unsigned binaries of a release before they are signed, in
      this order: <dir> holds the six binaries (postern-node, postern-panel
      and psiphon-core for amd64 and arm64) and MANIFEST and nothing else
      (no other file, link or directory); MANIFEST has the SHA-256 <hex> that
      the build gave; MANIFEST lists exactly the six binaries, with their
      sums; each binary is a static, unpacked program of its architecture,
      built by Go for linux with CGO_ENABLED=0 and -trimpath: postern-node
      and postern-panel from cmd/node or cmd/panel with a string variable
      whose value is <v> and one whose value is <c> (the version and the
      commit that the build set), psiphon-core from psiphon-tunnel-core's
      ConsoleClient with the SHA-256 that the panel pins. Nothing of the
      binaries is run.

Environment:
  POSTERN_MINISIGN_PASSWORD  the password of the secret key (keygen, pubkey, sign, stable-sign)
  POSTERN_GITHUB_API         the API of GitHub (candidates); https://api.github.com when empty
  GITHUB_TOKEN               a token for that API (candidates), sent to its host only; optional
  SOURCE_DATE_EPOCH          the time of the files in a bundle, in Unix seconds
                             (by default the time of each file)
`

// The command lines of the commands, for the message of a wrong one.
var synopsis = map[string]string{
	"keygen":      "keygen --out <dir> [--unencrypted]",
	"pubkey":      "pubkey --key <file>",
	"sign":        "sign --key <file> --component <c> --version <v> [--arch <a>] <file>",
	"verify":      "verify --pubkey <key> --component <c> --version <v> [--arch <a>] <file>",
	"sums":        "sums <file>...",
	"bundle":      "bundle --version <v> <dir>",
	"changelog":   "changelog [--from <tag>] --to <tag>",
	"keys":        "keys",
	"check-build": "check-build --version <v> --commit <c> --manifest-sha256 <hex> <dir>",
	"candidates":  "candidates [--stable <list>] [--component <c>]... --out <file>",
	"stable-add":  "stable-add [--list <list>] [--from <candidates>] [--drop <c>@<v>]... --out <file> [<c>@<v>...]",
	"stable-sign": "stable-sign --key <file> <list>",
}

const (
	envPassword = "POSTERN_MINISIGN_PASSWORD"
	envEpoch    = "SOURCE_DATE_EPOCH"

	keyFileName  = "postern-release.key"
	sumsName     = "SHA256SUMS"
	manifestName = "MANIFEST"
	stableName   = "engines-stable.json"
	sigSuffix    = ".minisig"

	// What is read of a file that is small or nothing: a secret key, a
	// signature, the checksums.
	maxKeyBytes  = 4 << 10
	maxSigBytes  = 64 << 10
	maxSumsBytes = 1 << 20
)

// The components that are binaries, and the architectures that they are built
// for. Their files in a release are <component>-linux-<arch>. binaries are
// Postern's own, which go into the bundle too; built are every binary that a
// release builds and signs: those and the Psiphon client (Ruling S2-26).
var (
	binaries = []string{"postern-node", "postern-panel"}
	built    = []string{"postern-node", "postern-panel", psiphonCore}
	arches   = []string{"amd64", "arm64"}
)

// psiphonCore is the Psiphon client that a release builds from a pinned
// upstream commit (scripts/psiphon-core.sh): psiphon-tunnel-core's
// ConsoleClient, whose files must have the SHA-256s that the panel pins.
const (
	psiphonCore     = "psiphon-core"
	psiphonCorePath = "github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient"
)

// encryptKey encrypts a new secret key with its password, as minisign does
// (the tests use cheaper parameters of the same format).
var encryptKey = minisign.EncryptKey

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

// usageError is a command line that cannot be run: exit status 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// errHelp is -h or --help after a command.
var errHelp = errors.New("help")

// cli is a run of the tool: where it writes, and its environment.
type cli struct {
	stdout, stderr io.Writer
	getenv         func(string) string
}

// run runs the command line args and returns the exit status: 0, 1 when the
// command failed, 2 for a command line that is wrong.
func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usageText)
		return 2
	}
	c := &cli{stdout: stdout, stderr: stderr, getenv: getenv}
	commands := map[string]func([]string) error{
		"keygen":      c.keygen,
		"pubkey":      c.pubkey,
		"sign":        c.sign,
		"verify":      c.verify,
		"sums":        c.sums,
		"bundle":      c.bundle,
		"changelog":   c.changelog,
		"keys":        c.keys,
		"check-build": c.checkBuild,
		"candidates":  c.candidates,
		"stable-add":  c.stableAdd,
		"stable-sign": c.stableSign,
	}
	name := args[0]
	command, ok := commands[name]
	switch {
	case name == "help" || name == "-h" || name == "-help" || name == "--help":
		_, _ = fmt.Fprint(stdout, usageText)
		return 0
	case !ok:
		_, _ = fmt.Fprintf(stderr, "release: unknown command %q\n\n%s", name, usageText)
		return 2
	}

	err := command(args[1:])
	var usage usageError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errHelp):
		_, _ = fmt.Fprintf(stdout, "usage: go run ./scripts/release %s\n\nSee go run ./scripts/release help.\n", synopsis[name])
		return 0
	case errors.As(err, &usage):
		_, _ = fmt.Fprintf(stderr, "release %s: %v\nusage: go run ./scripts/release %s\n", name, err, synopsis[name])
		return 2
	default:
		_, _ = fmt.Fprintf(stderr, "release %s: %v\n", name, err)
		return 1
	}
}

// flags returns an empty set of flags for the command name.
func flags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

// parse parses the flags of a command in args and returns the arguments after
// them: n of them, at least one when n is -1, or any number when n is -2.
func parse(set *flag.FlagSet, args []string, n int) ([]string, error) {
	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, errHelp
		}
		return nil, usageError{err.Error()}
	}
	rest := set.Args()
	switch {
	case n == -1 && len(rest) == 0:
		return nil, usagef("no file")
	case n >= 0 && len(rest) != n:
		return nil, usagef("%d arguments after the flags, and it takes %d (the flags go first)", len(rest), n)
	}
	return rest, nil
}

// keygen makes a key pair: see usageText.
func (c *cli) keygen(args []string) error {
	set := flags("keygen")
	out := set.String("out", "", "")
	unencrypted := set.Bool("unencrypted", false, "")
	if _, err := parse(set, args, 0); err != nil {
		return err
	}
	if *out == "" {
		return usagef("--out is missing")
	}
	password := c.getenv(envPassword)
	if !*unencrypted && password == "" {
		return usagef("%s is empty: it is the password that the key is encrypted with (a throwaway key for tests takes --unencrypted instead)", envPassword)
	}

	// Nothing is made before the directory is known to be outside of every
	// repository, where git add -A, or a copy of the tree, would take the key.
	dir, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	root, err := gitWorkTree(dir)
	if err != nil {
		return err
	}
	if root != "" {
		return fmt.Errorf("%s is in the git working tree %s: a secret key is kept outside of every repository, for example in ~/.config/postern/<name>", *out, root)
	}
	path := filepath.Join(dir, keyFileName)
	if present(path) {
		return fmt.Errorf("%s exists already: a key is never overwritten", path)
	}

	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var text []byte
	how := "encrypted with " + envPassword
	if *unencrypted {
		text, err = priv.MarshalText()
		how = "not encrypted"
	} else {
		text, err = encryptKey(password, priv)
	}
	if err != nil {
		return fmt.Errorf("writing the key: %w", err)
	}
	if !strings.HasSuffix(string(text), "\n") {
		text = append(text, '\n')
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeNew(path, text, 0o600); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(c.stdout, pub.String())
	_, _ = fmt.Fprintf(c.stderr, "keygen: wrote %s (%s), key id %016X; its public key is on stdout\n", path, how, pub.ID())
	return nil
}

// gitWorkTree returns the top of the git working tree that dir is in, or ""
// when it is in none. A working tree is a directory with a .git in it, a
// directory or the file of a linked worktree, and dir is in it when the tree is
// dir or a directory above it, as dir is written or as its links resolve. dir
// does not need to exist; the part of it that does is resolved.
func gitWorkTree(dir string) (string, error) {
	if root := gitAbove(dir); root != "" {
		return root, nil
	}
	existing := dir
	for !present(existing) {
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("cannot tell where %s leads: %w", existing, err)
	}
	return gitAbove(resolved), nil
}

// gitAbove returns the first of dir and the directories above it that has a
// .git, or "".
func gitAbove(dir string) string {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if present(filepath.Join(d, ".git")) {
			return d
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

// pubkey prints the public key of a secret key: see usageText.
func (c *cli) pubkey(args []string) error {
	set := flags("pubkey")
	key := set.String("key", "", "")
	if _, err := parse(set, args, 0); err != nil {
		return err
	}
	if *key == "" {
		return usagef("--key is missing")
	}
	priv, err := c.openKey(*key)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(c.stdout, publicKey(priv).String())
	return nil
}

// openKey reads the secret key of the file path, which is opened with the
// password of POSTERN_MINISIGN_PASSWORD when it is encrypted. Its errors say
// nothing of what the file holds.
func (c *cli) openKey(path string) (minisign.PrivateKey, error) {
	data, err := readSmall(path, maxKeyBytes)
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	if minisign.IsEncrypted(data) {
		password := c.getenv(envPassword)
		if password == "" {
			return minisign.PrivateKey{}, fmt.Errorf("the key %s is encrypted: set %s to its password", path, envPassword)
		}
		priv, err := minisign.DecryptKey(password, data)
		if err != nil {
			return minisign.PrivateKey{}, fmt.Errorf("the key %s does not open with the password of %s, or it is damaged", path, envPassword)
		}
		return priv, nil
	}
	var priv minisign.PrivateKey
	if err := priv.UnmarshalText(data); err != nil {
		return minisign.PrivateKey{}, fmt.Errorf("%s is not a minisign secret key", path)
	}
	return priv, nil
}

// publicKey returns the public key of priv; Public returns a minisign.PublicKey.
func publicKey(priv minisign.PrivateKey) minisign.PublicKey {
	return priv.Public().(minisign.PublicKey)
}

// artifact returns what a signature is for, from the flags of sign and verify.
// A binary has an architecture, and nothing else has one.
func artifact(component, version, arch string) (release.Signed, error) {
	if component == "" {
		return release.Signed{}, usagef("--component is missing")
	}
	if _, err := release.SetOf(component); err != nil {
		return release.Signed{}, usagef("--component %q: no key set signs it; the components are postern-node, postern-panel, sha256sums and engines-stable", component)
	}
	if !release.ValidVersion(version) {
		return release.Signed{}, usagef("--version %q is not a version", version)
	}
	s := release.Signed{Component: component, Version: version}
	switch {
	case slices.Contains(built, component) && arch == "":
		return release.Signed{}, usagef("%s is a binary: --arch is missing", component)
	case !slices.Contains(built, component) && arch != "":
		return release.Signed{}, usagef("%s is not a binary, and has no --arch", component)
	case arch != "" && !slices.Contains(arches, arch):
		return release.Signed{}, usagef("--arch %q: the architectures are amd64 and arm64", arch)
	case arch != "":
		s.OS, s.Arch = "linux", arch
	}
	return s, nil
}

// sign signs a file: see usageText.
func (c *cli) sign(args []string) error {
	set := flags("sign")
	key := set.String("key", "", "")
	component := set.String("component", "", "")
	version := set.String("version", "", "")
	arch := set.String("arch", "", "")
	files, err := parse(set, args, 1)
	if err != nil {
		return err
	}
	if *key == "" {
		return usagef("--key is missing")
	}
	want, err := artifact(*component, *version, *arch)
	if err != nil {
		return err
	}
	file := files[0]

	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// A binary is signed for its platform only if it is a program that runs
	// there: a node checks that too before it runs one, and a signature that
	// says amd64 on an arm64 file would be refused by every node.
	if want.Arch != "" {
		if err := release.CheckStaticELF(f, want.Arch); err != nil {
			return fmt.Errorf("%s is not a static program for linux/%s: %w", file, want.Arch, err)
		}
	}
	priv, err := c.openKey(*key)
	if err != nil {
		return err
	}
	sig, err := release.Sign(f, priv, want)
	if err != nil {
		return err
	}
	if err := writeAtomic(file+sigSuffix, sig, 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.stderr, "sign: %s%s: %s (key %016X)\n", file, sigSuffix, want.TrustedComment(), priv.ID())
	return nil
}

// verify checks a signature: see usageText.
func (c *cli) verify(args []string) error {
	set := flags("verify")
	pubkey := set.String("pubkey", "", "")
	component := set.String("component", "", "")
	version := set.String("version", "", "")
	arch := set.String("arch", "", "")
	files, err := parse(set, args, 1)
	if err != nil {
		return err
	}
	if *pubkey == "" {
		return usagef("--pubkey is missing")
	}
	var key minisign.PublicKey
	if err := key.UnmarshalText([]byte(strings.TrimSpace(*pubkey))); err != nil {
		return usagef("--pubkey is not a minisign public key: %v", err)
	}
	want, err := artifact(*component, *version, *arch)
	if err != nil {
		return err
	}
	file := files[0]

	sig, err := readSmall(file+sigSuffix, maxSigBytes)
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := release.VerifyWith(f, sig, want, []minisign.PublicKey{key}); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	_, _ = fmt.Fprintf(c.stdout, "%s: a good signature for %q by key %016X\n", file, want.TrustedComment(), key.ID())
	return nil
}

// sums writes SHA256SUMS: see usageText.
func (c *cli) sums(args []string) error {
	files, err := parse(flags("sums"), args, -1)
	if err != nil {
		return err
	}
	type entry struct{ name, sum string }
	var (
		dir     string
		entries []entry
	)
	for i, file := range files {
		abs, err := filepath.Abs(file)
		if err != nil {
			return err
		}
		d, name := filepath.Split(abs)
		switch {
		case i > 0 && d != dir:
			return usagef("the files are in more than one directory, and SHA256SUMS lists the files next to it")
		case !plainName(name):
			return usagef("%q: the name of a file of a release is letters, digits and ._+- only", name)
		case name == sumsName:
			return usagef("%s does not list itself", sumsName)
		case slices.ContainsFunc(entries, func(e entry) bool { return e.name == name }):
			return usagef("%s is named twice", name)
		}
		dir = d
		sum, err := fileSHA256(abs)
		if err != nil {
			return err
		}
		entries = append(entries, entry{name, sum})
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	var text strings.Builder
	for _, e := range entries {
		text.WriteString(e.sum + "  " + e.name + "\n")
	}
	path := filepath.Join(dir, sumsName)
	if err := writeAtomic(path, []byte(text.String()), 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.stderr, "sums: wrote %s (%d files)\n", path, len(entries))
	return nil
}

// plainName reports whether name is a name of a file that a release can have:
// a letter or a digit, then letters, digits and ._+-.
func plainName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for i := 0; i < len(name); i++ {
		switch b := name[i]; {
		case '0' <= b && b <= '9', 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z':
		case i > 0 && (b == '.' || b == '_' || b == '+' || b == '-'):
		default:
			return false
		}
	}
	return true
}

// bundleFile is a file of a bundle.
type bundleFile struct {
	name string
	mode int64
}

// bundle writes the bundle of a release: see usageText.
func (c *cli) bundle(args []string) error {
	set := flags("bundle")
	version := set.String("version", "", "")
	dirs, err := parse(set, args, 1)
	if err != nil {
		return err
	}
	if !release.ValidVersion(*version) {
		return usagef("--version %q is not a version", *version)
	}
	epoch, err := c.sourceDateEpoch()
	if err != nil {
		return err
	}
	dir := dirs[0]

	files, err := checkRelease(dir, *version)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "postern-"+*version+"-bundle.tar")
	err = writeAtomicFrom(path, 0o644, func(w io.Writer) error {
		tw := tar.NewWriter(w)
		for _, file := range files {
			if err := addToTar(tw, filepath.Join(dir, file.name), file, epoch); err != nil {
				return err
			}
		}
		return tw.Close()
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.stderr, "bundle: wrote %s (%d files)\n", path, len(files))
	return nil
}

// checkRelease checks the files of the release version in dir that go into
// its bundle, and returns them sorted by name: the binaries, SHA256SUMS and
// the list of stable engines when it is there, each with its signature. A
// signature has to be for its file (its trusted comment; the key is checked
// by whoever takes the bundle), and each binary has to have the SHA-256 that
// SHA256SUMS gives for it.
func checkRelease(dir, version string) ([]bundleFile, error) {
	sums, err := readSmall(filepath.Join(dir, sumsName), maxSumsBytes)
	if err != nil {
		return nil, err
	}
	type signedFile struct {
		name    string
		mode    int64
		comment string // the trusted comment of its signature, or its start
		prefix  bool   // comment is the start of the trusted comment
	}
	var want []signedFile
	for _, component := range binaries {
		for _, arch := range arches {
			s := release.Signed{Component: component, Version: version, OS: "linux", Arch: arch}
			want = append(want, signedFile{component + "-linux-" + arch, 0o755, s.TrustedComment(), false})
		}
	}
	want = append(want, signedFile{sumsName, 0o644, release.Signed{Component: "sha256sums", Version: version}.TrustedComment(), false})
	list, listSig := present(filepath.Join(dir, stableName)), present(filepath.Join(dir, stableName+sigSuffix))
	if list != listSig {
		return nil, fmt.Errorf("%s and %s go together, and only one of them is in %s", stableName, stableName+sigSuffix, dir)
	}
	if list {
		// The version of the list is the time that it was made, which is in it.
		want = append(want, signedFile{stableName, 0o644, "postern engines-stable ", true})
	}

	var files []bundleFile
	for _, w := range want {
		path := filepath.Join(dir, w.name)
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a file", path)
		}
		raw, err := readSmall(path+sigSuffix, maxSigBytes)
		if err != nil {
			return nil, err
		}
		var sig minisign.Signature
		if err := sig.UnmarshalText(raw); err != nil {
			return nil, fmt.Errorf("%s%s is not a minisign signature", path, sigSuffix)
		}
		if got := sig.TrustedComment; got != w.comment && (!w.prefix || !strings.HasPrefix(got, w.comment)) {
			return nil, fmt.Errorf("%s%s is a signature for %q, and %q is wanted", path, sigSuffix, got, w.comment)
		}
		if w.mode == 0o755 {
			sum, err := fileSHA256(path)
			if err != nil {
				return nil, err
			}
			listed, err := release.SumFor(w.name, sums, release.SumsSHA256)
			if err != nil {
				return nil, fmt.Errorf("%s for %s: %w", sumsName, w.name, err)
			}
			if listed != sum {
				return nil, fmt.Errorf("%s has the SHA-256 %s, and %s lists %s", w.name, sum, sumsName, listed)
			}
		}
		files = append(files, bundleFile{w.name, w.mode}, bundleFile{w.name + sigSuffix, 0o644})
	}
	slices.SortFunc(files, func(a, b bundleFile) int { return strings.Compare(a.name, b.name) })
	return files, nil
}

// addToTar adds the file at path to tw as file: a regular file of root without
// owner names, of the time epoch, or of its own time when epoch is the zero time.
func addToTar(tw *tar.Writer, path string, file bundleFile, epoch time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	modTime := epoch
	if modTime.IsZero() {
		modTime = fi.ModTime().Truncate(time.Second)
	}
	h := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     file.name,
		Mode:     file.mode,
		Size:     fi.Size(),
		ModTime:  modTime,
		Format:   tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	if _, err := io.CopyN(tw, f, fi.Size()); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// sourceDateEpoch returns the time of SOURCE_DATE_EPOCH, or the zero time when
// it is not set.
func (c *cli) sourceDateEpoch() (time.Time, error) {
	value := c.getenv(envEpoch)
	if value == "" {
		return time.Time{}, nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 || seconds > 1<<33-1 {
		return time.Time{}, usagef("%s=%q is not a time in Unix seconds that a tar file can hold", envEpoch, value)
	}
	return time.Unix(seconds, 0), nil
}

// conventional reads the subject of a conventional commit: its type, its scope,
// the "!" of a breaking change, and its description.
var conventional = regexp.MustCompile(`^([A-Za-z]+)(?:\(([^()]*)\))?(!)?: +(\S.*)$`)

// The groups of the notes, in their order. A commit of another type, or that
// is not a conventional commit, is in the last one.
var groups = []struct{ kind, title string }{
	{"feat", "Features"},
	{"fix", "Fixes"},
	{"perf", "Performance"},
	{"security", "Security"},
	{"", "Other"},
}

// changelog prints the notes of a release: see usageText.
func (c *cli) changelog(args []string) error {
	set := flags("changelog")
	from := set.String("from", "", "")
	to := set.String("to", "", "")
	if _, err := parse(set, args, 0); err != nil {
		return err
	}
	if *to == "" {
		return usagef("--to is missing")
	}
	for _, ref := range []string{*from, *to} {
		if strings.HasPrefix(ref, "-") {
			return usagef("%q is not a tag", ref)
		}
	}
	revisions, err := resolveCommit(*to)
	if err != nil {
		return err
	}
	if *from != "" {
		start, err := resolveCommit(*from)
		if err != nil {
			return err
		}
		revisions = start + ".." + revisions
	}
	// Subjects only: the body of a commit, and its trailers, stay out of the
	// notes. Records end in NUL, and the hash and the subject are apart by US.
	out, err := gitOutput("-c", "log.showSignature=false", "log", "--no-merges", "--no-color", "-z",
		"--format=%h%x1f%s", revisions, "--")
	if err != nil {
		return err
	}

	lines := make([][]string, len(groups))
	for record := range strings.SplitSeq(out, "\x00") {
		hash, subject, ok := strings.Cut(strings.TrimPrefix(record, "\n"), "\x1f")
		if !ok {
			continue
		}
		group, line := len(groups)-1, subject
		if m := conventional.FindStringSubmatch(subject); m != nil {
			kind := strings.ToLower(m[1])
			if i := slices.IndexFunc(groups, func(g struct{ kind, title string }) bool { return g.kind == kind }); i >= 0 {
				group, line = i, m[4]
				if m[2] != "" {
					line = m[2] + ": " + line
				}
				if m[3] != "" {
					line = "**Breaking:** " + line
				}
			}
		}
		lines[group] = append(lines[group], "- "+line+" ("+hash+")")
	}

	var notes strings.Builder
	for i, group := range groups {
		if len(lines[i]) == 0 {
			continue
		}
		if notes.Len() > 0 {
			notes.WriteString("\n")
		}
		notes.WriteString("## " + group.title + "\n\n" + strings.Join(lines[i], "\n") + "\n")
	}
	if notes.Len() == 0 {
		notes.WriteString("No changes.\n")
	}
	_, err = io.WriteString(c.stdout, notes.String())
	return err
}

// resolveCommit returns the commit that ref names in the repository of the
// working directory.
func resolveCommit(ref string) (string, error) {
	out, err := gitOutput("rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("%s is not a commit of this repository", ref)
	}
	return strings.TrimSpace(out), nil
}

// gitOutput runs git with args in the working directory and returns what it
// printed.
func gitOutput(args ...string) (string, error) {
	var stdout, stderr strings.Builder
	cmd := exec.Command("git", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// productionKeys are the production keys that this build trusts. The tests
// replace it, to run the tool as a build without production keys.
var productionKeys = release.ProductionKeys

// keys prints the production keys: see usageText.
func (c *cli) keys(args []string) error {
	if _, err := parse(flags("keys"), args, 0); err != nil {
		return err
	}
	var failed []error
	for _, set := range []release.KeySet{release.ReleaseKeys, release.StableKeys} {
		keys := productionKeys(set)
		if len(keys) == 0 {
			_, _ = fmt.Fprintf(c.stderr, "keys: no production %s keys are compiled in\n", set)
		}
		for _, key := range keys {
			_, _ = fmt.Fprintf(c.stdout, "%s\t%016X\t%s\n", set, key.ID(), key)
		}
		// ProductionKeys leaves out a key that cannot be used; TrustedKeys says
		// which one it is, by its position.
		if _, err := release.TrustedKeys(set); err != nil && !errors.Is(err, release.ErrNoKeys) {
			failed = append(failed, err)
		}
	}
	return errors.Join(failed...)
}

// checkBuild checks the unsigned binaries of a release: see usageText. It only
// reads them: they come from the job that builds, which is not trusted with the
// key, and nothing of them runs where the key is.
func (c *cli) checkBuild(args []string) error {
	set := flags("check-build")
	version := set.String("version", "", "")
	commit := set.String("commit", "", "")
	manifestSHA := set.String("manifest-sha256", "", "")
	dirs, err := parse(set, args, 1)
	if err != nil {
		return err
	}
	switch {
	case !release.ValidVersion(*version):
		return usagef("--version %q is not a version", *version)
	case !isHex(*commit, 7, 40):
		return usagef("--commit %q is not the hex of a commit", *commit)
	case !isHex(*manifestSHA, 64, 64):
		return usagef("--manifest-sha256 is not 64 hex digits")
	}
	dir := dirs[0]
	var names []string
	for _, component := range built {
		for _, arch := range arches {
			names = append(names, component+"-linux-"+arch)
		}
	}

	// 1. The six binaries and MANIFEST, as plain files, and nothing else.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		switch {
		case e.Name() != manifestName && !slices.Contains(names, e.Name()):
			return fmt.Errorf("%s holds %q, which a build does not make", dir, e.Name())
		case !e.Type().IsRegular():
			return fmt.Errorf("%s in %s is not a plain file", e.Name(), dir)
		}
	}
	for _, name := range append([]string{manifestName}, names...) {
		if !slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name }) {
			return fmt.Errorf("%s has no %s", dir, name)
		}
	}

	// 2. MANIFEST is the one that the build made.
	manifestPath := filepath.Join(dir, manifestName)
	sum, err := fileSHA256(manifestPath)
	if err != nil {
		return err
	}
	if want := strings.ToLower(*manifestSHA); sum != want {
		return fmt.Errorf("%s has the SHA-256 %s, and the build gave %s: it is not the %s of the build", manifestName, sum, want, manifestName)
	}

	// 3. MANIFEST lists the six binaries, and they have its sums.
	manifest, err := readSmall(manifestPath, maxSumsBytes)
	if err != nil {
		return err
	}
	if lines := strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n"); len(lines) != len(names) {
		return fmt.Errorf("%s has %d lines, and lists the %d binaries and nothing else", manifestName, len(lines), len(names))
	}
	for _, name := range names {
		listed, err := release.SumFor(name, manifest, release.SumsSHA256)
		if err != nil {
			return fmt.Errorf("%s for %s: %w", manifestName, name, err)
		}
		sum, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if sum != listed {
			return fmt.Errorf("%s has the SHA-256 %s, and %s lists %s", name, sum, manifestName, listed)
		}
	}

	// 4. Each binary is a static program of its architecture, built by Go from
	// its command as a release is built, for the version and the commit; the
	// Psiphon client has the SHA-256 that the panel pins.
	for _, component := range built {
		for _, arch := range arches {
			name := component + "-linux-" + arch
			if err := checkBinary(filepath.Join(dir, name), component, arch, *version, *commit); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	_, _ = fmt.Fprintf(c.stderr, "check-build: %s holds the six binaries of %s (commit %s) that its MANIFEST lists\n", dir, *version, *commit)
	return nil
}

// checkBinary is step 4 of check-build for one binary.
func checkBinary(path, component, arch, version, commit string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := release.CheckStaticELF(f, arch); err != nil {
		return err
	}
	info, err := buildinfo.Read(f)
	if err != nil {
		return fmt.Errorf("it is not a Go program with its build information: %w", err)
	}
	if component == psiphonCore {
		return checkPsiphonCore(path, arch, info)
	}
	if want := "github.com/urbnywrt/postern/cmd/" + strings.TrimPrefix(component, "postern-"); info.Path != want {
		return fmt.Errorf("it is a build of %q, not of %q", info.Path, want)
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	for _, want := range [][2]string{{"GOOS", "linux"}, {"GOARCH", arch}, {"CGO_ENABLED", "0"}, {"-trimpath", "true"}} {
		if got := settings[want[0]]; got != want[1] {
			return fmt.Errorf("it was built with %s=%q, and a release with %s=%s", want[0], got, want[0], want[1])
		}
	}
	for _, want := range [][2]string{{"version", version}, {"commit", commit}} {
		ok, err := holdsString(f, want[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no string variable of it is %q: it is not a build of the %s %s", want[1], want[0], want[1])
		}
	}
	return nil
}

// checkPsiphonCore is step 4 of check-build for the Psiphon client: a static
// Go build of the ConsoleClient for linux/arch, CGO_ENABLED=0 and -trimpath,
// whose SHA-256 is the one that the panel pins (releases.Builtins): the build
// is reproducible, and a file of other bytes is not the one that the panels
// trust.
func checkPsiphonCore(path, arch string, info *buildinfo.BuildInfo) error {
	if info.Path != psiphonCorePath {
		return fmt.Errorf("it is a build of %q, not of %q", info.Path, psiphonCorePath)
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	for _, want := range [][2]string{{"GOOS", "linux"}, {"GOARCH", arch}, {"CGO_ENABLED", "0"}, {"-trimpath", "true"}} {
		if got := settings[want[0]]; got != want[1] {
			return fmt.Errorf("it was built with %s=%q, and a release with %s=%s", want[0], got, want[0], want[1])
		}
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return err
	}
	var pins []string
	for _, b := range releases.Builtins() {
		if a, ok := b.Assets[arch]; ok && b.Component == psiphonCore {
			if a.SHA256 == sum {
				return nil
			}
			pins = append(pins, b.Version+" "+a.SHA256)
		}
	}
	return fmt.Errorf("it has the SHA-256 %s, and the panel pins %s for linux/%s (internal/panel/releases/builtin.json)", sum, strings.Join(pins, ", "), arch)
}

// holdsString reports whether the 64-bit little-endian ELF program of r has a
// string whose value is exactly s, as a variable that -X sets: a string header
// (address and length) in its data sections that points to the bytes of s in
// its read-only data. Its bytes alone would not do: v0.5.0 is in a build of
// v0.5.0-rc.1 too.
func holdsString(r io.ReaderAt, s string) (bool, error) {
	file, err := elf.NewFile(r)
	if err != nil {
		return false, err
	}
	rodata := file.Section(".rodata")
	if rodata == nil {
		return false, errors.New("it has no .rodata section")
	}
	ro, err := rodata.Data()
	if err != nil {
		return false, err
	}
	n := uint64(len(s))
	for _, name := range []string{".data", ".noptrdata"} {
		section := file.Section(name)
		if section == nil {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return false, err
		}
		for i := 0; i+16 <= len(data); i += 8 {
			addr, length := binary.LittleEndian.Uint64(data[i:]), binary.LittleEndian.Uint64(data[i+8:])
			if length != n || addr < rodata.Addr || addr-rodata.Addr+n > uint64(len(ro)) {
				continue
			}
			if off := addr - rodata.Addr; string(ro[off:off+n]) == s {
				return true, nil
			}
		}
	}
	return false, nil
}

// isHex reports whether s is from min to max hex digits.
func isHex(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// present reports whether there is a file, a directory or a link at path.
func present(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// readSmall reads the file at path, which has to hold at most limit bytes.
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes, which is too large for what it is", path, limit)
	}
	return data, nil
}

// fileSHA256 returns the SHA-256 of the file at path in lower-case hex.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeNew writes data to a new file at path, with the mode perm. A file that
// is there already is left alone: it is an error.
func writeNew(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s exists already: a key is never overwritten", path)
	}
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeAtomic writes data to the file at path with the mode perm, by a rename
// of a new file next to it: path holds the old content or the new one, never a
// part of either.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	return writeAtomicFrom(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// writeAtomicFrom is writeAtomic with the content that write writes.
func writeAtomicFrom(path string, perm os.FileMode, write func(io.Writer) error) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	if err = write(f); err != nil {
		return err
	}
	// The files of a release are public, and made to be read by everybody.
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
