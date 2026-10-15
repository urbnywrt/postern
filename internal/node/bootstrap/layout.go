package bootstrap

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// layout is install.sh make_layout: the directories of the node and their
// modes. Everything that holds keys, credentials or client data is root only.
var layout = []struct {
	dir  string // under POSTERN_HOME; "" is POSTERN_HOME itself
	mode fs.FileMode
}{
	{"", 0o755},
	{"bin", 0o755},
	{"pki", 0o700},
	{"data", 0o700},
	{"data/state", 0o700},
	{"data/edge", 0o700},
	{"data/run", 0o700},
	{"data/run/launcher", 0o700},
	{"data/instances", 0o700},
	{"data/certs", 0o700},
	{"data/artifacts", 0o755},
}

// makeLayout creates the directories of the node with the modes of install.sh.
// The mode of a directory that exists is only ever narrowed, never widened.
func (b *boot) makeLayout() error {
	for _, d := range layout {
		if err := makeDir(b.path(filepath.FromSlash(d.dir)), d.mode); err != nil {
			return fmt.Errorf("bootstrap: layout: %w", err)
		}
	}
	return nil
}

// makeDir makes dir with mode, or narrows the mode of the directory that is
// there to what both allow.
func makeDir(dir string, mode fs.FileMode) error {
	st, err := os.Stat(dir)
	switch {
	case err == nil && !st.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case err == nil:
		if have := st.Mode().Perm(); have&^mode != 0 {
			return os.Chmod(dir, have&mode)
		}
		return nil
	case !os.IsNotExist(err):
		return err
	}
	if err := os.Mkdir(dir, mode); err != nil {
		return err
	}
	return os.Chmod(dir, mode) // the umask does not decide
}

// writeFileAtomic puts data into path with mode in one rename: a reader never
// sees half a file, and the file is never readable by others on the way.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	syncDir(filepath.Dir(path))
	return nil
}

// copyFileAtomic copies src over dst with mode, in one rename ([writeFileAtomic]);
// at most limit bytes are read.
func copyFileAtomic(src, dst string, mode fs.FileMode, limit int64) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".new.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	n, err := io.Copy(tmp, io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("%s is larger than %d bytes", src, limit)
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, dst); err != nil {
		return err
	}
	ok = true
	syncDir(filepath.Dir(dst))
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// readSmall reads at most limit bytes of path.
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

// randomHex is n random bytes in hex.
func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
