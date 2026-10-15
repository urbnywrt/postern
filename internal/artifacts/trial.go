package artifacts

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// trialName is the file in an artifact directory that records its trial run.
// Put makes a new directory, so a replaced artifact starts without a record.
const trialName = ".trial"

// maxTrialRecord bounds what Trial reads of a record.
const maxTrialRecord = 64 << 10

// TrialRecord is the outcome of the trial run of an artifact on this node
// (package node/trial): whether the binary ran and passed, why not, when, and
// in which runner image. Only a trial that ran is recorded.
type TrialRecord struct {
	OK     bool      `json:"ok"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
	Image  string    `json:"image"`
}

// RecordTrial writes the trial record of a stored artifact into its directory,
// <dir>/.trial, atomically: a reader sees the old record or the new one. The
// reference must be valid (ErrInvalidRef) and the artifact stored (Has).
func (s *Store) RecordTrial(ref Ref, rec TrialRecord) (err error) {
	if err := ref.Validate(); err != nil {
		return err
	}
	dir, err := s.slot(ref)
	if err != nil {
		return err
	}
	if !s.Has(ref) {
		return fmt.Errorf("artifacts: no artifact %s %s for %s to record a trial for", ref.Engine, ref.Version, ref.Arch)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	tmp, err := os.CreateTemp(dir, trialName+".tmp-*")
	if err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("artifacts: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil { // not the umask's business
		_ = tmp.Close()
		return fmt.Errorf("artifacts: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("artifacts: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, trialName)); err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	syncDir(dir)
	return nil
}

// Trial returns the trial record of a stored artifact, and whether there is
// one: none for an invalid reference, an artifact that is not stored or was
// never tried, or a record that cannot be read.
func (s *Store) Trial(ref Ref) (TrialRecord, bool) {
	if !s.Has(ref) {
		return TrialRecord{}, false
	}
	dir, err := s.slot(ref)
	if err != nil {
		return TrialRecord{}, false
	}
	f, err := os.Open(filepath.Join(dir, trialName))
	if err != nil {
		return TrialRecord{}, false
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxTrialRecord))
	if err != nil {
		return TrialRecord{}, false
	}
	var rec TrialRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return TrialRecord{}, false
	}
	return rec, true
}

// Remove deletes the artifact's directory, Root/<engine>/<version>/<arch>, with
// its binary, marker and trial record, and the version and engine directories
// above it when they are left empty. An artifact that is not there is not an
// error. The reference's path elements must be valid (ErrInvalidRef): nothing
// outside an artifact slot is ever removed.
func (s *Store) Remove(ref Ref) error {
	dir, err := s.slot(ref)
	if err != nil {
		return err
	}
	commitMu.Lock()
	defer commitMu.Unlock()
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	// The parents, as far as they are empty; the root stays.
	for d := filepath.Dir(dir); d != s.Root && len(d) > len(s.Root); d = filepath.Dir(d) {
		if err := os.Remove(d); err != nil {
			break
		}
	}
	return nil
}

// List returns the verified artifacts in the store, every
// <engine>/<version>/<arch>/<binary> with a checksum marker that matches (see
// Has), sorted by engine, version and architecture as the file system lists
// them. Scratch and replaced directories, and names the store would never have
// written, are skipped.
func (s *Store) List() []Ref {
	var out []Ref
	for _, engine := range plainDirs(s.Root) {
		for _, version := range plainDirs(filepath.Join(s.Root, engine)) {
			for _, arch := range plainDirs(filepath.Join(s.Root, engine, version)) {
				dir := filepath.Join(s.Root, engine, version, arch)
				sha, ok := readMarker(filepath.Join(dir, markerName))
				if !ok {
					continue
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if !e.Type().IsRegular() || validElement("binary", e.Name()) != nil {
						continue
					}
					ref := Ref{Engine: engine, Version: version, Arch: arch, SHA256: sha, Binary: e.Name()}
					if s.Has(ref) {
						out = append(out, ref)
					}
				}
			}
		}
	}
	return out
}

// plainDirs lists the directories in dir whose names are valid path elements
// of the store (see validElement), in the file system's order.
func plainDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && validElement("directory", e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

// readMarker returns the checksum in a .sha256 marker in lower case.
func readMarker(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return "", false
	}
	sha := strings.ToLower(strings.TrimSpace(string(data)))
	if !validSHA256(sha) {
		return "", false
	}
	return sha, true
}
