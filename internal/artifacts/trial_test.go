package artifacts

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// rawRef is the reference of a raw (not archived) binary whose content is data.
func rawRef(engine, version, arch, binary string, data []byte) Ref {
	return Ref{Engine: engine, Version: version, Arch: arch, SHA256: sum(data), FileName: binary, Binary: binary}
}

func TestTrialRecordRoundTrip(t *testing.T) {
	s := newStore(t)
	ref := rawRef("mtg", "v2.2.8", "amd64", "mtg", []byte("mtg binary"))
	must(t, s.Put(ref, bytes.NewReader([]byte("mtg binary"))))

	if rec, ok := s.Trial(ref); ok || rec != (TrialRecord{}) {
		t.Errorf("Trial before any record = %+v, %v", rec, ok)
	}
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	rec := TrialRecord{OK: false, Reason: "exited with 1, want 0: ё", At: at, Image: "alpine:3.22@sha256:abc"}
	must(t, s.RecordTrial(ref, rec))
	got, ok := s.Trial(ref)
	if !ok || !reflect.DeepEqual(got, rec) {
		t.Errorf("Trial = %+v, %v; want %+v", got, ok, rec)
	}

	// A new record replaces the old one.
	rec2 := TrialRecord{OK: true, At: at.Add(time.Hour), Image: rec.Image}
	must(t, s.RecordTrial(ref, rec2))
	if got, ok := s.Trial(ref); !ok || !reflect.DeepEqual(got, rec2) {
		t.Errorf("Trial = %+v, %v; want %+v", got, ok, rec2)
	}
	entries, err := os.ReadDir(s.Dir(ref))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{".sha256", ".trial", "mtg"}; !reflect.DeepEqual(names, want) {
		t.Errorf("artifact directory holds %v, want %v (no scratch file)", names, want)
	}
	if info, err := os.Stat(filepath.Join(s.Dir(ref), ".trial")); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf(".trial: %v, %v; want mode 0644", info, err)
	}

	// Replacing the artifact drops the record.
	must(t, s.Put(ref, bytes.NewReader([]byte("mtg binary"))))
	if _, ok := s.Trial(ref); ok {
		t.Error("the record survived a new Put")
	}

	// Has does not care about the record; the record is bound to the
	// artifact's directory and checksum.
	must(t, s.RecordTrial(ref, rec2))
	other := ref
	other.SHA256 = strings.Repeat("0", 64)
	if _, ok := s.Trial(other); ok {
		t.Error("a record was returned for another checksum")
	}
}

func TestTrialRecordRefusals(t *testing.T) {
	s := newStore(t)
	ref := rawRef("mtg", "v2.2.8", "amd64", "mtg", []byte("mtg binary"))
	rec := TrialRecord{OK: true, At: time.Now(), Image: "x"}

	// No artifact: nothing to record for.
	if err := s.RecordTrial(ref, rec); err == nil {
		t.Error("RecordTrial for a missing artifact succeeded")
	}
	if _, err := os.Stat(s.Dir(ref)); !errors.Is(err, os.ErrNotExist) {
		t.Error("RecordTrial made the artifact directory")
	}
	must(t, s.Put(ref, bytes.NewReader([]byte("mtg binary"))))

	for _, bad := range []Ref{
		{Engine: "../mtg", Version: "v2.2.8", Arch: "amd64", SHA256: ref.SHA256, Binary: "mtg"},
		{Engine: "mtg", Version: ".trial", Arch: "amd64", SHA256: ref.SHA256, Binary: "mtg"},
		{Engine: "mtg", Version: "v2.2.8", Arch: "amd64", SHA256: "nothex", Binary: "mtg"},
		{Engine: "mtg", Version: "v2.2.8", Arch: "amd64", SHA256: ref.SHA256, Binary: ""},
	} {
		if err := s.RecordTrial(bad, rec); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("RecordTrial(%+v) = %v, want ErrInvalidRef", bad, err)
		}
		if _, ok := s.Trial(bad); ok {
			t.Errorf("Trial(%+v) found a record", bad)
		}
	}
	// A damaged record is no record.
	if err := os.WriteFile(filepath.Join(s.Dir(ref), ".trial"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Trial(ref); ok {
		t.Error("a damaged record was returned")
	}
}

func TestRemove(t *testing.T) {
	s := newStore(t)
	a := rawRef("mtg", "v2.2.8", "amd64", "mtg", []byte("a"))
	b := rawRef("mtg", "v2.2.8", "arm64", "mtg", []byte("b"))
	c := rawRef("telemt", "3.5.13", "amd64", "telemt", []byte("c"))
	must(t, s.Put(a, bytes.NewReader([]byte("a"))))
	must(t, s.Put(b, bytes.NewReader([]byte("b"))))
	must(t, s.Put(c, bytes.NewReader([]byte("c"))))
	must(t, s.RecordTrial(a, TrialRecord{OK: true, At: time.Now(), Image: "x"}))

	must(t, s.Remove(a))
	if s.Has(a) {
		t.Error("removed artifact is still there")
	}
	if _, err := os.Stat(s.Dir(a)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory is still there: %v", err)
	}
	if !s.Has(b) || !s.Has(c) {
		t.Error("another artifact went with it")
	}
	// Removing what is not there is fine.
	must(t, s.Remove(a))

	// The empty version and engine directories go too, down to the root.
	must(t, s.Remove(b))
	if _, err := os.Stat(filepath.Join(s.Root, "mtg")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the empty engine directory is still there: %v", err)
	}
	if _, err := os.Stat(s.Root); err != nil {
		t.Errorf("the root went away: %v", err)
	}

	// Invalid references are refused, and nothing happens.
	for _, bad := range []Ref{
		{Engine: "..", Version: "3.5.13", Arch: "amd64"},
		{Engine: "telemt", Version: "", Arch: "amd64"},
		{Engine: "telemt", Version: "3.5.13", Arch: "."},
		{Engine: "telemt", Version: "3.5.13", Arch: ".amd64.old-x"},
	} {
		if err := s.Remove(bad); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("Remove(%+v) = %v, want ErrInvalidRef", bad, err)
		}
	}
	if !s.Has(c) {
		t.Error("an invalid Remove took something")
	}
	if err := (&Store{Root: "relative"}).Remove(c); err == nil {
		t.Error("a relative root was accepted")
	}
}

func TestList(t *testing.T) {
	s := newStore(t)
	if got := s.List(); len(got) != 0 {
		t.Errorf("List of a missing store = %v", got)
	}
	a := rawRef("mtg", "v2.2.8", "amd64", "mtg", []byte("a"))
	b := rawRef("telemt", "3.5.12", "arm64", "telemt", []byte("b"))
	c := rawRef("telemt", "3.5.13", "amd64", "telemt", []byte("c"))
	must(t, s.Put(c, bytes.NewReader([]byte("c"))))
	must(t, s.Put(a, bytes.NewReader([]byte("a"))))
	must(t, s.Put(b, bytes.NewReader([]byte("b"))))
	// Leftovers that are not artifacts: scratch, a replaced directory, a binary
	// without a marker, a bad marker, a right marker beside a name the store
	// refuses, and a directory name it refuses.
	for _, dir := range []string{".stage-123", "telemt/3.5.13/.amd64.old-abc", "telemt/9.9.9/amd64", "telemt/3.5.11/amd64", "telemt/3.5.10/amd64", "tel emt/3.5.13/amd64"} {
		if err := os.MkdirAll(filepath.Join(s.Root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"telemt/9.9.9/amd64/telemt":    "no marker",
		"telemt/3.5.11/amd64/telemt":   "bad marker",
		"telemt/3.5.11/amd64/.sha256":  "not a checksum\n",
		"telemt/3.5.10/amd64/.sha256":  c.SHA256 + "\n",
		"telemt/3.5.10/amd64/tel emt":  "c",
		"tel emt/3.5.13/amd64/.sha256": c.SHA256 + "\n",
		"tel emt/3.5.13/amd64/telemt":  "c",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(s.Root, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := s.List()
	want := []Ref{
		{Engine: "mtg", Version: "v2.2.8", Arch: "amd64", SHA256: a.SHA256, Binary: "mtg"},
		{Engine: "telemt", Version: "3.5.12", Arch: "arm64", SHA256: b.SHA256, Binary: "telemt"},
		{Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: c.SHA256, Binary: "telemt"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List = %+v\nwant %+v", got, want)
	}
}
