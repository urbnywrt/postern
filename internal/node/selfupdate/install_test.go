package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"aead.dev/minisign"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/selfupdate/selfupdatetest"
	"github.com/urbnywrt/postern/internal/release"
)

const arch = "amd64"

// fixture is a node home with v0.5.0 running (bin/current) and v0.4.0 before
// it (bin/previous).
type fixture struct {
	home   string
	signer *selfupdatetest.Signer
	inst   *Installer
	v040   []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{home: t.TempDir(), signer: selfupdatetest.NewSigner(t)}
	bin := filepath.Join(f.home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.v040 = selfupdatetest.Binary(t, arch, "v0.4.0")
	for name, data := range map[string][]byte{
		"postern-node-v0.4.0": f.v040,
		"postern-node-v0.5.0": selfupdatetest.Binary(t, arch, "v0.5.0"),
	} {
		if err := os.WriteFile(filepath.Join(bin, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"current": "postern-node-v0.5.0", "previous": "postern-node-v0.4.0"} {
		if err := os.Symlink(target, filepath.Join(bin, link)); err != nil {
			t.Fatal(err)
		}
	}
	f.inst = &Installer{Home: f.home, Arch: arch, Running: "v0.5.0", Keys: f.signer.Keys}
	return f
}

// snapshot is everything in bin/: names, link targets, contents and modes.
func (f *fixture) snapshot(t *testing.T) []string {
	t.Helper()
	bin := filepath.Join(f.home, "bin")
	entries, err := os.ReadDir(bin)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		p := filepath.Join(bin, e.Name())
		if target, err := os.Readlink(p); err == nil {
			out = append(out, e.Name()+" -> "+target)
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(p)
		out = append(out, fmt.Sprintf("%s %v %x", e.Name(), info.Mode(), sha256.Sum256(data)))
	}
	return out
}

func (f *fixture) install(meta *nodev1.NodeBinary, data []byte) (bool, error) {
	return f.inst.Install(context.Background(), meta, bytes.NewReader(data))
}

func TestInstallRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		// make returns what is installed; it may change the fixture.
		make func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte)
		want error
		text string
	}{
		{"an untrusted key", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			return selfupdatetest.NewSigner(t).Meta(t, data, "v0.6.0", arch), data
		}, ErrSignature, "not trusted"},
		{"another arch in the trusted comment", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			meta := f.signer.Meta(t, data, "v0.6.0", arch)
			meta.Signature = f.signer.Sign(t, data, "v0.6.0", "arm64")
			return meta, data
		}, ErrSignature, "another artifact"},
		{"a SHA-256 mismatch", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			meta := f.signer.Meta(t, data, "v0.6.0", arch)
			data = selfupdatetest.Binary(t, arch, "v0.6.X")
			return meta, data
		}, ErrChecksum, "SHA-256"},
		{"more data than the size", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			return f.signer.Meta(t, data, "v0.6.0", arch), append(data, 0)
		}, ErrChecksum, "more than"},
		{"oversize", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			meta := f.signer.Meta(t, data, "v0.6.0", arch)
			meta.Size = MaxSize + 1
			return meta, data
		}, ErrTooLarge, ""},
		{"a dynamic ELF", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.DynamicBinary(t, arch, "v0.6.0")
			return f.signer.Meta(t, data, "v0.6.0", arch), data
		}, ErrUnusable, "dynamically linked"},
		{"a trial that prints another version", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			f.inst.Exec = selfupdatetest.Exec("v0.6.1")
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			return f.signer.Meta(t, data, "v0.6.0", arch), data
		}, ErrUnusable, `"v0.6.1 (`},
		{"a trial that fails", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			f.inst.Exec = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exec format error") }
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			return f.signer.Meta(t, data, "v0.6.0", arch), data
		}, ErrUnusable, "exec format error"},
		{"an older version without rollback", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			return f.signer.Meta(t, f.v040, "v0.4.0", arch), f.v040
		}, ErrDowngrade, "older than the running v0.5.0"},
		{"a rollback to something other than previous", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.3.0")
			meta := f.signer.Meta(t, data, "v0.3.0", arch)
			meta.Rollback = true
			return meta, data
		}, ErrDowngrade, "only to bin/previous (postern-node-v0.4.0)"},
		{"a rollback to a newer version", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			meta := f.signer.Meta(t, data, "v0.6.0", arch)
			meta.Rollback = true
			return meta, data
		}, ErrDowngrade, "only to bin/previous"},
		{"an existing file with other content", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			if err := os.WriteFile(filepath.Join(f.home, "bin", "postern-node-v0.6.0"), []byte("other"), 0o755); err != nil {
				t.Fatal(err)
			}
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			return f.signer.Meta(t, data, "v0.6.0", arch), data
		}, ErrExists, "version v0.6.0 exists with other content"},
		{"another arch in the meta", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, "arm64", "v0.6.0")
			return f.signer.Meta(t, data, "v0.6.0", "arm64"), data
		}, ErrInvalid, "this node is amd64"},
		{"an invalid version", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			meta := f.signer.Meta(t, data, "v0.6.0", arch)
			meta.Version = "../v0.6.0"
			return meta, data
		}, ErrInvalid, "invalid version"},
		{"no release key", func(t *testing.T, f *fixture) (*nodev1.NodeBinary, []byte) {
			f.inst.Keys = func(release.KeySet) ([]minisign.PublicKey, error) { return nil, release.ErrNoKeys }
			data := selfupdatetest.Binary(t, arch, "v0.6.0")
			return f.signer.Meta(t, data, "v0.6.0", arch), data
		}, ErrNoKeys, "this node build trusts no release key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.inst.Exec = selfupdatetest.Exec("v0.6.0")
			meta, data := tc.make(t, f)
			before := f.snapshot(t)
			changed, err := f.install(meta, data)
			if !errors.Is(err, tc.want) || !strings.Contains(fmt.Sprint(err), tc.text) || changed {
				t.Fatalf("Install = %v, %v; want %v with %q", changed, err, tc.want, tc.text)
			}
			if after := f.snapshot(t); !slices.Equal(before, after) {
				t.Errorf("bin/ changed:\n%q\nwas\n%q", after, before)
			}
		})
	}
}

func TestInstall(t *testing.T) {
	f := newFixture(t)
	f.inst.Exec = selfupdatetest.Exec("v0.6.0")
	data := selfupdatetest.Binary(t, arch, "v0.6.0")
	changed, err := f.install(f.signer.Meta(t, data, "v0.6.0", arch), data)
	if err != nil || !changed {
		t.Fatalf("Install = %v, %v", changed, err)
	}
	bin := filepath.Join(f.home, "bin")
	want := []string{"current -> postern-node-v0.6.0", "previous -> postern-node-v0.5.0"}
	for i, link := range []string{"current", "previous"} {
		if target, err := os.Readlink(filepath.Join(bin, link)); err != nil || link+" -> "+target != want[i] {
			t.Errorf("%s -> %q, %v; want %s", link, target, err, want[i])
		}
	}
	info, err := os.Stat(filepath.Join(bin, "postern-node-v0.6.0"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed binary: %v, %v", info, err)
	}
	if got, _ := os.ReadFile(filepath.Join(bin, "postern-node-v0.6.0")); !bytes.Equal(got, data) {
		t.Error("installed content differs")
	}
	for _, e := range f.snapshot(t) {
		if strings.HasPrefix(e, ".") && !strings.HasPrefix(e, ".postern-node-v0.6.0.minisig ") {
			t.Errorf("left behind: %s", e)
		}
	}
	// The signature is kept beside the binary, for UpdateEdge.
	if sig, err := os.ReadFile(filepath.Join(bin, ".postern-node-v0.6.0.minisig")); err != nil || len(sig) == 0 {
		t.Errorf("kept signature: %q, %v", sig, err)
	}
	got := Binaries(f.home)
	wantBin := &nodev1.NodeBinaries{
		Versions: []string{"v0.4.0", "v0.5.0", "v0.6.0"}, Current: "v0.6.0", Previous: "v0.5.0",
		SignedVersions: []string{"v0.6.0"}, // the one Install kept a signature for
	}
	if !proto.Equal(got, wantBin) {
		t.Errorf("Binaries = %v, want %v", got, wantBin)
	}

	// The same version again changes nothing.
	before := f.snapshot(t)
	changed, err = f.install(f.signer.Meta(t, data, "v0.6.0", arch), data)
	if err != nil || changed {
		t.Fatalf("the same version: Install = %v, %v", changed, err)
	}
	if after := f.snapshot(t); !slices.Equal(before, after) {
		t.Errorf("bin/ changed:\n%q\nwas\n%q", after, before)
	}
}

// A rollback to bin/previous swaps the two links.
func TestInstallRollsBackToPrevious(t *testing.T) {
	f := newFixture(t)
	f.inst.Exec = selfupdatetest.Exec("v0.4.0")
	meta := f.signer.Meta(t, f.v040, "v0.4.0", arch)
	meta.Rollback = true
	changed, err := f.install(meta, f.v040)
	if err != nil || !changed {
		t.Fatalf("Install = %v, %v", changed, err)
	}
	if got := Binaries(f.home); got.GetCurrent() != "v0.4.0" || got.GetPrevious() != "v0.5.0" {
		t.Errorf("Binaries = %v, want current v0.4.0, previous v0.5.0", got)
	}
}

// Without bin/current the binary becomes bin/current, and there is no
// bin/previous.
func TestInstallFirst(t *testing.T) {
	home := t.TempDir()
	s := selfupdatetest.NewSigner(t)
	inst := &Installer{Home: home, Arch: arch, Running: "dev", Keys: s.Keys, Exec: selfupdatetest.Exec("v0.6.0")}
	data := selfupdatetest.Binary(t, arch, "v0.6.0")
	changed, err := inst.Install(context.Background(), s.Meta(t, data, "v0.6.0", arch), bytes.NewReader(data))
	if err != nil || !changed {
		t.Fatalf("Install = %v, %v", changed, err)
	}
	if got := Binaries(home); got.GetCurrent() != "v0.6.0" || got.GetPrevious() != "" {
		t.Errorf("Binaries = %v", got)
	}
}

// The file is hashed again right before it goes into bin/: one that changed
// after its signature was checked (here: while it ran its trial) is refused,
// and nothing is installed.
func TestInstallRehashesBeforeTheRename(t *testing.T) {
	f := newFixture(t)
	before := f.snapshot(t)
	data := selfupdatetest.Binary(t, arch, "v0.6.0")
	f.inst.Exec = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		if err := os.WriteFile(path, append(slices.Clone(data), 'x'), 0o755); err != nil {
			return nil, err
		}
		return selfupdatetest.Exec("v0.6.0")(ctx, path, args...)
	}
	_, err := f.install(f.signer.Meta(t, data, "v0.6.0", arch), data)
	if !errors.Is(err, ErrChecksum) || !strings.Contains(err.Error(), "changed after it was verified") {
		t.Fatalf("Install = %v, want ErrChecksum for a file that changed", err)
	}
	if after := f.snapshot(t); !slices.Equal(after, before) {
		t.Errorf("bin/ changed:\n%v\nwant\n%v", after, before)
	}
}

// VerifyInstalled checks an installed binary for the edge as Install checks a
// new one: the signature Install kept (or the running agent's own file), a
// static ELF, its "version".
func TestVerifyInstalled(t *testing.T) {
	f := newFixture(t)
	bin := filepath.Join(f.home, "bin")
	put := func(v string, data []byte, sig string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, filePrefix+v), data, 0o755); err != nil {
			t.Fatal(err)
		}
		if sig != "" {
			if err := writeSignature(bin, v, sig); err != nil {
				t.Fatal(err)
			}
		}
	}
	good := selfupdatetest.Binary(t, arch, "v0.6.0")
	put("v0.6.0", good, f.signer.Meta(t, good, "v0.6.0", arch).GetSignature())
	other := selfupdatetest.Binary(t, arch, "v0.6.1")
	put("v0.6.1", other, selfupdatetest.NewSigner(t).Meta(t, other, "v0.6.1", arch).GetSignature())
	put("v0.6.2", selfupdatetest.Binary(t, arch, "v0.6.2"), "")
	dyn := selfupdatetest.DynamicBinary(t, arch, "v0.6.3")
	put("v0.6.3", dyn, f.signer.Meta(t, dyn, "v0.6.3", arch).GetSignature())
	if err := os.Symlink(filePrefix+"v0.6.0", filepath.Join(bin, filePrefix+"v0.6.4")); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(bin, filePrefix+"v0.5.0") // the running agent's, unsigned
	f.inst.SelfExe = own                           // what /proc/self/exe opens

	ctx := context.Background()
	for _, tc := range []struct {
		v    string
		says string
		want error
	}{
		{"v0.6.0", "v0.6.0", nil},
		{"v0.6.0", "v0.6.9", ErrUnusable},     // prints another version
		{"v0.6.1", "v0.6.1", ErrSignature},    // signed by an untrusted key
		{"v0.6.2", "v0.6.2", ErrSignature},    // no signature kept
		{"v0.6.3", "v0.6.3", ErrUnusable},     // not static
		{"v0.6.4", "v0.6.4", ErrUnusable},     // a symlink
		{"v0.7.0", "v0.7.0", ErrNotInstalled}, // not there
		{"../x", "../x", ErrInvalid},          // not a version
		{"v0.5.0", "v0.5.0", nil},             // the agent's own file
		{"v0.4.0", "v0.4.0", ErrSignature},    // installed by install.sh, not the running one
	} {
		path, sum, err := f.inst.VerifyInstalled(ctx, tc.v, own, selfupdatetest.Exec(tc.says))
		if !errors.Is(err, tc.want) || (err == nil) != (tc.want == nil) {
			t.Errorf("VerifyInstalled(%s) = %v, want %v", tc.v, err, tc.want)
			continue
		}
		if err == nil {
			if path != filepath.Join(bin, filePrefix+tc.v) || Rehash(path, sum) != nil {
				t.Errorf("VerifyInstalled(%s) = %s, %x", tc.v, path, sum)
			}
		}
	}

	// A file at the path of the agent's own version that is not what the process
	// runs (replaced since it started) is no own binary: it needs a signature.
	f.inst.SelfExe = filepath.Join(bin, filePrefix+"v0.6.2")
	if _, _, err := f.inst.VerifyInstalled(ctx, "v0.5.0", own, selfupdatetest.Exec("v0.5.0")); !errors.Is(err, ErrSignature) {
		t.Errorf("VerifyInstalled(own path, another running file) = %v, want %v", err, ErrSignature)
	}
}
