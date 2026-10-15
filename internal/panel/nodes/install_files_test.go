package nodes

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
)

// The kit that an install over SSH uploads is the one that the download serves:
// the same four files, in the same order, with the same content.
func TestOpenKit(t *testing.T) {
	kit := newTestKit(t, "amd64", "arm64")
	s := NewService(nil, [32]byte{}, nil, nil, nil, WithKitDir(kit.dir))

	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			k, err := s.OpenKit(arch)
			if err != nil {
				t.Fatalf("OpenKit(%s): %v", arch, err)
			}
			defer k.Close()
			if k.Arch != arch {
				t.Errorf("Arch = %q, want %q", k.Arch, arch)
			}
			want := kit.want(arch)
			if len(k.Files) != len(kitOrder) {
				t.Fatalf("%d files, want %d", len(k.Files), len(kitOrder))
			}
			for i, f := range k.Files {
				if f.Name != kitOrder[i].name {
					t.Errorf("file %d is %q, want %q", i, f.Name, kitOrder[i].name)
				}
				if f.Size != int64(len(want[i])) {
					t.Errorf("%s: Size = %d, want %d", f.Name, f.Size, len(want[i]))
				}
				got, err := io.ReadAll(f)
				if err != nil {
					t.Fatalf("%s: %v", f.Name, err)
				}
				if !bytes.Equal(got, want[i]) {
					t.Errorf("%s: the content differs from the file of the kit", f.Name)
				}
			}
		})
	}
}

func TestOpenKitThatIsMissing(t *testing.T) {
	kit := newTestKit(t, "amd64")
	s := NewService(nil, [32]byte{}, nil, nil, nil, WithKitDir(kit.dir))
	for _, arch := range []string{"arm64", "riscv64", "../amd64", ""} {
		if k, err := s.OpenKit(arch); err == nil {
			k.Close()
			t.Errorf("OpenKit(%q) = a kit, want an error", arch)
		} else if !errors.Is(err, ErrNoKit) {
			t.Errorf("OpenKit(%q): err = %v, want ErrNoKit", arch, err)
		}
	}
	none := NewService(nil, [32]byte{}, nil, nil, nil)
	if _, err := none.OpenKit("amd64"); !errors.Is(err, ErrNoKit) {
		t.Errorf("OpenKit of a panel without a kit: err = %v, want ErrNoKit", err)
	}
}

// A file that gets shorter after it was opened cannot be sent whole: reading it
// fails, so that a cut binary is never taken for the whole one.
func TestKitFileThatShrinks(t *testing.T) {
	kit := newTestKit(t, "amd64")
	s := NewService(nil, [32]byte{}, nil, nil, nil, WithKitDir(kit.dir))
	k, err := s.OpenKit("amd64")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if err := os.Truncate(kit.path("amd64/postern-node"), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(k.Files[0]); err == nil {
		t.Error("reading a file that got shorter succeeded")
	}
}

// Bundle is the bundle that the download serves, for an install that does not
// go through HTTP.
func TestBundle(t *testing.T) {
	a := newAPI(t)
	created := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443})
	id := created.GetNode().GetId()

	_, served := a.get(a.web, created.GetBundleUrl())
	b, err := a.svc.Bundle(context.Background(), id)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	data, err := b.MarshalTar()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, served) {
		t.Error("Bundle differs from the bundle that the download serves")
	}
	parsed, err := pki.ParseBundleTar(data)
	if err != nil || parsed.NodeID != id || parsed.MgmtPort != 61443 {
		t.Errorf("the bundle is of node %q port %d (%v), want %q port 61443", parsed.NodeID, parsed.MgmtPort, err, id)
	}

	if _, err := a.svc.Bundle(context.Background(), "NOPE"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Bundle of an unknown node: err = %v, want store.ErrNotFound", err)
	}
}
