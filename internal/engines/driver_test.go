package engines

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newPaths makes an executable binary and an instance directory in a temp dir.
func newPaths(t *testing.T) Instance {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "telemt")
	if err := os.WriteFile(bin, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	inst := filepath.Join(dir, "instance")
	if err := os.Mkdir(inst, 0o755); err != nil {
		t.Fatal(err)
	}
	return Instance{BinaryPath: bin, InstanceDir: inst}
}

func TestCheckHostPathsAcceptsAnExecutableAndADirectory(t *testing.T) {
	if err := newPaths(t).CheckHostPaths(); err != nil {
		t.Fatal(err)
	}
}

// Docker creates a missing bind source as an empty root-owned directory and
// starts the container anyway, so an engine would "run" against an empty
// directory. CheckHostPaths is the guard to call before dockerapi Create.
func TestCheckHostPathsRefusesWhatDockerWouldInventOrMisread(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful here")
	}
	tests := []struct {
		name    string
		prepare func(t *testing.T, in *Instance)
		want    string // part of the error
	}{
		{"binary missing", func(t *testing.T, in *Instance) {
			_ = os.Remove(in.BinaryPath)
		}, "binary"},
		{"binary is a directory", func(t *testing.T, in *Instance) {
			_ = os.Remove(in.BinaryPath)
			_ = os.Mkdir(in.BinaryPath, 0o755)
		}, "regular file"},
		{"binary is not executable for others", func(t *testing.T, in *Instance) {
			_ = os.Chmod(in.BinaryPath, 0o750)
		}, "execut"},
		{"binary is not readable for others", func(t *testing.T, in *Instance) {
			_ = os.Chmod(in.BinaryPath, 0o711)
		}, "readable"},
		{"binary path empty", func(t *testing.T, in *Instance) {
			in.BinaryPath = ""
		}, "binary"},
		{"binary path relative", func(t *testing.T, in *Instance) {
			// Docker would take "telemt" for the name of a volume and create it.
			in.BinaryPath = "telemt"
		}, "absolute"},
		{"binary path has a colon", func(t *testing.T, in *Instance) {
			// It would be cut at the colon when the bind spec is parsed.
			dir := filepath.Join(filepath.Dir(in.BinaryPath), "a:b")
			_ = os.Mkdir(dir, 0o755)
			p := filepath.Join(dir, "telemt")
			_ = os.WriteFile(p, []byte("x"), 0o755)
			_ = os.Chmod(p, 0o755)
			in.BinaryPath = p
		}, "':'"},
		{"instance dir missing", func(t *testing.T, in *Instance) {
			_ = os.Remove(in.InstanceDir)
		}, "instance directory"},
		{"instance dir is a file", func(t *testing.T, in *Instance) {
			_ = os.Remove(in.InstanceDir)
			_ = os.WriteFile(in.InstanceDir, []byte("x"), 0o644)
		}, "directory"},
		{"instance dir empty path", func(t *testing.T, in *Instance) {
			in.InstanceDir = ""
		}, "instance directory"},
		{"instance dir relative", func(t *testing.T, in *Instance) {
			in.InstanceDir = "instance"
		}, "absolute"},
		{"instance dir has a colon", func(t *testing.T, in *Instance) {
			p := filepath.Join(filepath.Dir(in.InstanceDir), "i:1")
			_ = os.Mkdir(p, 0o755)
			in.InstanceDir = p
		}, "':'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := newPaths(t)
			tt.prepare(t, &in)
			err := in.CheckHostPaths()
			if err == nil {
				t.Fatal("CheckHostPaths accepted it")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// The error names the paths, which are not secret, and never anything else:
// the check has no access to the proxy.
func TestCheckHostPathsErrorNamesThePath(t *testing.T) {
	in := newPaths(t)
	_ = os.Remove(in.BinaryPath)
	err := in.CheckHostPaths()
	if err == nil || !strings.Contains(err.Error(), in.BinaryPath) {
		t.Errorf("error %v does not name %s", err, in.BinaryPath)
	}
}
