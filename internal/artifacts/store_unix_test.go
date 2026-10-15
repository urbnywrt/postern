//go:build unix

package artifacts

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestPutIgnoresTheUmask: the engine runs as an unprivileged user inside its
// container and must be able to read and execute the binary, so the modes are
// the ones Put chooses, whatever umask the agent runs with.
func TestPutIgnoresTheUmask(t *testing.T) {
	// Not parallel: the umask belongs to the process.
	base := t.TempDir()
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	s := &Store{Root: filepath.Join(base, "data", "artifacts")}
	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody, mode: 0o600})
	ref := telemtRef(archive)
	if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]os.FileMode{
		s.BinaryPath(ref):                      0o755,
		filepath.Join(s.Dir(ref), ".sha256"):   0o644,
		s.Dir(ref):                             0o755,
		filepath.Dir(s.Dir(ref)):               0o755, // .../telemt/3.5.13
		filepath.Dir(filepath.Dir(s.Dir(ref))): 0o755, // .../telemt
		s.Root:                                 0o755,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s has mode %v, want %v", path, got, want)
		}
	}
}
