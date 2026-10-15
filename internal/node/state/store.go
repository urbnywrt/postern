// Package state keeps the node's desired state and the agent's runtime record
// on disk, validates desired states, and hands out loopback ports.
//
// The desired state (desired.json) is what the panel sent last: a whole
// nodev1.NodeState with its generation. The runtime record (runtime.json) is
// what the reconciler made of it: the ports it allocated, the engine instances
// that serve or drain, the generation of the edge, and the last generation it
// applied. Both live in <home>/data/state, readable by root only (0700/0600):
// they hold proxy secrets, egress credentials and engine API tokens.
//
// Every write is atomic: a temporary file in the same directory, fsync, rename
// over the target, fsync of the directory. A reader sees the old file or the
// new one, never a mix, and a crash leaves one of the two.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// Paths is the node's host layout under POSTERN_HOME (/opt/postern in
// production, a temporary directory in tests).
type Paths struct {
	Home string
}

// StateDir holds desired.json, desired.prev.json and runtime.json.
func (p Paths) StateDir() string { return filepath.Join(p.Home, "data", "state") }

// EdgeDir holds the edge configuration files, config-g<N>.json.
func (p Paths) EdgeDir() string { return filepath.Join(p.Home, "data", "edge") }

// RunDir holds the control sockets of the edge generations, edge-g<N>.sock.
func (p Paths) RunDir() string { return filepath.Join(p.Home, "data", "run") }

// ArtifactsDir is the root of the artifact store.
func (p Paths) ArtifactsDir() string { return filepath.Join(p.Home, "data", "artifacts") }

// InstancesDir holds one directory per engine instance.
func (p Paths) InstancesDir() string { return filepath.Join(p.Home, "data", "instances") }

// CertsDir holds the certificates of WEB proxies.
func (p Paths) CertsDir() string { return filepath.Join(p.Home, "data", "certs") }

// GeoIPDir holds the country databases the panel uploads (UploadGeoIP), each
// as <sha256>.mmdb.
func (p Paths) GeoIPDir() string { return filepath.Join(p.Home, "data", "geoip") }

// EdgeConfigPath is the configuration file of edge generation gen, written by
// the agent before the generation starts and kept up to date by the edge.
func (p Paths) EdgeConfigPath(gen uint64) string {
	return filepath.Join(p.EdgeDir(), "config-g"+strconv.FormatUint(gen, 10)+".json")
}

// EdgeSocketPath is the control socket of edge generation gen.
func (p Paths) EdgeSocketPath(gen uint64) string {
	return filepath.Join(p.RunDir(), "edge-g"+strconv.FormatUint(gen, 10)+".sock")
}

// EdgeRollPath is the file through which the operator asks the agent to roll
// the edge (Ruling 44): data/run/roll-edge. `install.sh --roll-edge` writes it
// (mode 0600; its content, the unix time of the request, is not read). The next
// reconcile pass takes the request, deleting the file, and starts a new edge
// generation, which runs the binary the agent runs, beside the one that runs,
// which then drains (spec 7). A request that the agent cannot delete is not
// acted on.
func (p Paths) EdgeRollPath() string { return filepath.Join(p.RunDir(), "roll-edge") }

// ResolvConfPath is the resolv.conf that names the DNS forwarder of the edge,
// which the containers of the node mount at /etc/resolv.conf in DNS mode doh.
func (p Paths) ResolvConfPath() string { return filepath.Join(p.RunDir(), "resolv.conf") }

// EgressDir is the directory of an egress, data/instances/egr-<id in lower
// case>, root's alone (0700). It holds the directories of its provider
// generations, egr-<id>/g<N> (the rendered files, which the container of the
// generation mounts), and what outlives them: the cached subscription of an
// XRAY_SUBSCRIPTION egress (subscription.txt, the agent's alone) and, for a
// PSIPHON egress, the cache (Psiphon's data) of each generation, cache-g<N> (which
// the container of the generation mounts), with the symlink cache to the
// canonical one (Ruling S2-18).
func (p Paths) EgressDir(id string) string {
	return filepath.Join(p.InstancesDir(), "egr-"+strings.ToLower(id))
}

// EgressStateDir is where the agent keeps what belongs to an egress and must
// not be seen by any container, data/state/egress/<id in lower case>: the
// account of the WARP device of a WARP egress (warp-account.json).
func (p Paths) EgressStateDir(id string) string {
	return filepath.Join(p.StateDir(), "egress", strings.ToLower(id))
}

// MEAddrsPath is the last good list of the addresses of Telegram's middle
// proxies, data/state/me-addrs.json.
func (p Paths) MEAddrsPath() string { return filepath.Join(p.StateDir(), "me-addrs.json") }

const (
	desiredFile     = "desired.json"
	desiredPrevFile = "desired.prev.json"
	runtimeFile     = "runtime.json"

	stateDirMode  = 0o700
	stateFileMode = 0o600
)

// Store reads and writes the files of the state directory. It is safe for
// concurrent use; writes are serialized.
type Store struct {
	Paths Paths

	mu sync.Mutex
}

// LoadDesired returns the desired state, or nil and no error when the panel has
// not sent one yet. Fields it does not know (from a newer panel) are ignored.
func (s *Store) LoadDesired() (*nodev1.NodeState, error) {
	st, err := s.readDesired(filepath.Join(s.Paths.StateDir(), desiredFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return st, err
}

// DesiredModTime is when the desired state was last stored: what it asks for
// has been asked for at least since then.
func (s *Store) DesiredModTime() (time.Time, error) {
	info, err := os.Stat(filepath.Join(s.Paths.StateDir(), desiredFile))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (s *Store) readDesired(path string) (*nodev1.NodeState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	st := &nodev1.NodeState{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("state: reading %s: %w", filepath.Base(path), err)
	}
	return st, nil
}

// SaveDesired replaces the desired state. The state it replaces is kept as
// desired.prev.json. It does not compare generations: that is the caller's
// job (the agent refuses stale generations before it saves).
func (s *Store) SaveDesired(st *nodev1.NodeState) error {
	if st == nil {
		return errors.New("state: no desired state to save")
	}
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(st)
	if err != nil {
		return fmt.Errorf("state: encoding the desired state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.Paths.StateDir()
	if err := ensureDir(dir, stateDirMode); err != nil {
		return err
	}
	// Copy, not rename: desired.json must exist at every moment, or a crash
	// in between would make the node forget its state.
	cur := filepath.Join(dir, desiredFile)
	switch old, err := os.ReadFile(cur); {
	case err == nil:
		if err := WriteFileAtomic(filepath.Join(dir, desiredPrevFile), old, stateFileMode); err != nil {
			return fmt.Errorf("state: keeping the previous desired state: %w", err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("state: %w", err)
	}
	if err := WriteFileAtomic(cur, data, stateFileMode); err != nil {
		return fmt.Errorf("state: saving the desired state: %w", err)
	}
	return nil
}

// LoadRuntime returns the runtime record, or an empty one (with non-nil maps)
// when there is none yet.
func (s *Store) LoadRuntime() (*Runtime, error) {
	data, err := os.ReadFile(filepath.Join(s.Paths.StateDir(), runtimeFile))
	if errors.Is(err, fs.ErrNotExist) {
		return NewRuntime(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	rt := NewRuntime()
	if err := json.Unmarshal(data, rt); err != nil {
		return nil, fmt.Errorf("state: reading %s: %w", runtimeFile, err)
	}
	if rt.Ports == nil {
		rt.Ports = map[string]uint16{}
	}
	if rt.Instances == nil {
		rt.Instances = map[string]InstanceRecord{}
	}
	if rt.Egresses == nil {
		rt.Egresses = map[string]EgressRecord{}
	}
	return rt, nil
}

// SaveRuntime replaces the runtime record.
func (s *Store) SaveRuntime(rt *Runtime) error {
	if rt == nil {
		return errors.New("state: no runtime record to save")
	}
	data, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		return fmt.Errorf("state: encoding the runtime record: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.Paths.StateDir()
	if err := ensureDir(dir, stateDirMode); err != nil {
		return err
	}
	if err := WriteFileAtomic(filepath.Join(dir, runtimeFile), append(data, '\n'), stateFileMode); err != nil {
		return fmt.Errorf("state: saving the runtime record: %w", err)
	}
	return nil
}

// ensureDir creates dir (and its parents) when it is missing, with mode perm
// for the directory itself.
func ensureDir(dir string, perm os.FileMode) error {
	if err := os.MkdirAll(dir, perm); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	// MkdirAll obeys the umask, and a directory that existed keeps its mode;
	// the state directory is root's alone either way.
	if err := os.Chmod(dir, perm); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	return nil
}

// WriteFileAtomic replaces the file at path with data: it writes a temporary
// file in the same directory with mode perm, flushes it, renames it over path
// and flushes the directory. Readers see the old content or the new one. The
// directory must exist.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil { // not the umask's business
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory's entries to disk. Best effort: not every file
// system supports it, and the rename is atomic without it.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
