package control

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// maxConfigBytes is the largest configuration file that LoadConfig reads. A
// configuration of thousands of routes is a few megabytes; the limit is there
// so that a path that was given by mistake (a device, a log) is not read to its
// end. A variable so that a test can lower it.
var maxConfigBytes int64 = 64 << 20

// The steps of SaveConfig that touch the disk, as variables so that a test can
// see in which order they happen and make them fail.
var (
	syncFile   = (*os.File).Sync
	renameFile = os.Rename
	syncDir    = syncDirectory
)

// LoadConfig reads the configuration of the edge from the JSON file at path:
// the file that SaveConfig writes, and the one that the agent writes before it
// starts an edge generation. Both spellings of the field names (the proto names
// and lowerCamelCase) are read, and so are numbers written as strings. A field
// that this version does not know is skipped, so that an edge comes up from
// the file of a newer agent. A file that does not exist is an error that
// satisfies errors.Is(err, fs.ErrNotExist).
func LoadConfig(path string) (*edgev1.EdgeConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("control: load configuration: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("control: load configuration: read %s: %w", path, err)
	}
	if int64(len(data)) > maxConfigBytes {
		return nil, fmt.Errorf("control: load configuration: %s is larger than %d bytes", path, maxConfigBytes)
	}
	cfg := &edgev1.EdgeConfig{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("control: load configuration: parse %s: %w", path, err)
	}
	return cfg, nil
}

// SaveConfig writes cfg as JSON to path, so that the file is at every moment
// either what it was or the new configuration, complete, never a mixture and
// never absent: the content goes to a temporary file in the same directory
// (mode 0600, the configuration holds the passwords of egress members) and is
// synced to disk, the file is renamed over path, and the directory is synced so
// that the rename is on disk as well.
//
// When SaveConfig fails before the rename the file at path is as it was. If it
// fails after the rename, in the sync of the directory, the new file is in
// place but is not known to be durable; the error says so.
func SaveConfig(path string, cfg *edgev1.EdgeConfig) (err error) {
	if cfg == nil {
		return errors.New("control: save configuration: no configuration")
	}
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("control: save configuration: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*") // mode 0600
	if err != nil {
		return fmt.Errorf("control: save configuration: %w", err)
	}
	name := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = tmp.Close() // already closed on the way to the rename; the error does not matter then
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("control: save configuration: write %s: %w", name, err)
	}
	if err := syncFile(tmp); err != nil {
		return fmt.Errorf("control: save configuration: sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("control: save configuration: close %s: %w", name, err)
	}
	if err := renameFile(name, path); err != nil {
		return fmt.Errorf("control: save configuration: %w", err)
	}
	renamed = true
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("control: save configuration: the new file is in place at %s, but the directory could not be synced: %w", path, err)
	}
	return nil
}

// syncDirectory makes the entries of dir durable: a new file and the rename of
// one are not on disk until the directory is.
func syncDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil // a directory cannot be opened for a sync there
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	// Some file systems cannot sync a directory; there is nothing more to do on them.
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, errors.ErrUnsupported) {
		return nil
	}
	return err
}
