package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
)

func testDB(t *testing.T, networks map[string]string) (data []byte, sha string) {
	t.Helper()
	data, err := geoiptest.Bytes(networks)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:])
}

func geoMeta(sha string) *nodev1.UploadGeoIPRequest {
	return &nodev1.UploadGeoIPRequest{Part: &nodev1.UploadGeoIPRequest_Meta{Meta: &nodev1.GeoIPRef{Month: "2026-10", Sha256: sha}}}
}

func geoChunks(data []byte, size int) []*nodev1.UploadGeoIPRequest {
	var out []*nodev1.UploadGeoIPRequest
	for len(data) > 0 {
		n := min(size, len(data))
		out = append(out, &nodev1.UploadGeoIPRequest{Part: &nodev1.UploadGeoIPRequest_Chunk{Chunk: data[:n]}})
		data = data[n:]
	}
	return out
}

func (r *rig) uploadGeoIP(msgs ...*nodev1.UploadGeoIPRequest) (*nodev1.UploadGeoIPResponse, error) {
	r.t.Helper()
	stream := r.client.UploadGeoIP(context.Background())
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			break // the node answered early; CloseAndReceive has its answer
		}
	}
	resp, err := stream.CloseAndReceive()
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (r *rig) geoEvents(kind string) int {
	r.t.Helper()
	recs, err := r.buf.After(0, 1000)
	if err != nil {
		r.t.Fatal(err)
	}
	n := 0
	for _, rec := range recs {
		if rec.GetEvent().GetKind() == kind {
			n++
		}
	}
	return n
}

func (r *rig) geoFiles() []string {
	r.t.Helper()
	entries, err := os.ReadDir(r.paths.GeoIPDir())
	if err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func (r *rig) storedGeoIP() []string {
	r.t.Helper()
	resp, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		r.t.Fatal(err)
	}
	return resp.Msg.GetGeoipStored()
}

func withGeoIP(st *nodev1.NodeState, sha string) *nodev1.NodeState {
	st.Settings.IpPolicy = nodev1.IpPolicy_IP_POLICY_COUNTRIES
	st.Settings.Geoip = &nodev1.GeoIPRef{Month: "2026-10", Sha256: sha}
	return st
}

func TestUploadGeoIP(t *testing.T) {
	r := newRig(t)
	dbA, shaA := testDB(t, map[string]string{"203.0.113.0/24": "DE"})
	dbB, shaB := testDB(t, map[string]string{"203.0.113.0/24": "FR"})
	dbC, shaC := testDB(t, map[string]string{"203.0.113.0/24": "NL"})

	if got := r.storedGeoIP(); len(got) != 0 {
		t.Errorf("geoip_stored before any upload = %v", got)
	}
	resp, err := r.uploadGeoIP(append([]*nodev1.UploadGeoIPRequest{geoMeta(shaA)}, geoChunks(dbA, 1000)...)...)
	if err != nil || !resp.GetStored() || resp.GetSha256() != shaA {
		t.Fatalf("UploadGeoIP = %v, %v", resp, err)
	}
	path := filepath.Join(r.paths.GeoIPDir(), shaA+".mmdb")
	if data, err := os.ReadFile(path); err != nil || !slices.Equal(data, dbA) {
		t.Fatalf("stored file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
			t.Errorf("file mode = %v", st.Mode().Perm())
		}
		if st, _ := os.Stat(r.paths.GeoIPDir()); st.Mode().Perm() != 0o700 {
			t.Errorf("directory mode = %v", st.Mode().Perm())
		}
	}
	if n := r.geoEvents(evGeoIPStored); n != 1 {
		t.Errorf("geoip_stored events = %d", n)
	}

	// Again: stored at once, no second event.
	if resp, err := r.uploadGeoIP(append([]*nodev1.UploadGeoIPRequest{geoMeta(shaA)}, geoChunks(dbA, 1000)...)...); err != nil || !resp.GetStored() {
		t.Fatalf("repeated UploadGeoIP = %v, %v", resp, err)
	}
	if n := r.geoEvents(evGeoIPStored); n != 1 {
		t.Errorf("geoip_stored events after a repeated upload = %d", n)
	}

	refused := func(what string, code connect.Code, msgs ...*nodev1.UploadGeoIPRequest) {
		t.Helper()
		if _, err := r.uploadGeoIP(msgs...); connect.CodeOf(err) != code {
			t.Errorf("%s: err = %v, want %v", what, err, code)
		}
	}
	other := sha256.Sum256([]byte("something else"))
	refused("sha256 mismatch", connect.CodeInvalidArgument, append([]*nodev1.UploadGeoIPRequest{geoMeta(hex.EncodeToString(other[:]))}, geoChunks(dbB, 1000)...)...)
	junk := []byte("this is not a MaxMind DB file at all")
	junkSum := sha256.Sum256(junk)
	refused("not a database", connect.CodeInvalidArgument, append([]*nodev1.UploadGeoIPRequest{geoMeta(hex.EncodeToString(junkSum[:]))}, geoChunks(junk, 8)...)...)
	refused("chunk before meta", connect.CodeInvalidArgument, append(geoChunks(dbB, 1000), geoMeta(shaB))...)
	refused("bad sha256", connect.CodeInvalidArgument, geoMeta("abc"))
	r.svc.geo.maxUpload = int64(len(dbB) - 1)
	refused("oversize", connect.CodeResourceExhausted, append([]*nodev1.UploadGeoIPRequest{geoMeta(shaB)}, geoChunks(dbB, 1000)...)...)
	r.svc.geo.maxUpload = maxGeoIPUpload
	if got := r.geoFiles(); !slices.Equal(got, []string{shaA + ".mmdb"}) {
		t.Errorf("files after the refused uploads = %v", got)
	}

	// Cleanup: an upload keeps itself, the one the desired state names and
	// the one loaded.
	if resp := r.apply(withGeoIP(validState(1), shaA)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	if _, err := r.uploadGeoIP(append([]*nodev1.UploadGeoIPRequest{geoMeta(shaB)}, geoChunks(dbB, 4096)...)...); err != nil {
		t.Fatal(err)
	}
	if resp := r.apply(withGeoIP(validState(2), shaB)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	if got := r.svc.geo.country("203.0.113.5"); got != "FR" {
		t.Errorf("country with B loaded = %q", got)
	}
	if _, err := r.uploadGeoIP(append([]*nodev1.UploadGeoIPRequest{geoMeta(shaC)}, geoChunks(dbC, 4096)...)...); err != nil {
		t.Fatal(err)
	}
	want := []string{shaB, shaC}
	slices.Sort(want)
	if got := r.storedGeoIP(); !slices.Equal(got, want) {
		t.Errorf("geoip_stored = %v, want %v (A is neither named nor loaded)", got, want)
	}
	if n := r.geoEvents(evGeoIPStored); n != 3 {
		t.Errorf("geoip_stored events = %d, want 3", n)
	}
}

// eventLog collects the events of a geoStore.
type eventLog struct {
	mu    sync.Mutex
	kinds []string
}

func (e *eventLog) add(kind, _, _ string, _ map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.kinds = append(e.kinds, kind)
}

func (e *eventLog) count(kind string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, k := range e.kinds {
		if k == kind {
			n++
		}
	}
	return n
}

// The loader loads the named database, swaps in another, unloads when none
// is named, and reports a named one missing for 10 minutes once.
func TestGeoIPLoader(t *testing.T) {
	clock := newTestClock()
	dir := t.TempDir()
	events := &eventLog{}
	g := newGeoStore(dir, clock.Now, events.add, discardLog())
	put := func(networks map[string]string) string {
		data, sha := testDB(t, networks)
		if err := os.WriteFile(filepath.Join(dir, sha+".mmdb"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		return sha
	}
	shaA := put(map[string]string{"203.0.113.0/24": "DE"})
	shaB := put(map[string]string{"203.0.113.0/24": "FR", "2001:db8::/32": "JP"})

	if got := g.country("203.0.113.5"); got != "" {
		t.Errorf("country without a database = %q", got)
	}
	g.sync(&nodev1.GeoIPRef{Sha256: shaA})
	g.sync(&nodev1.GeoIPRef{Sha256: shaA})
	if got := g.country("203.0.113.5"); got != "DE" {
		t.Errorf("country with A = %q", got)
	}
	g.sync(&nodev1.GeoIPRef{Sha256: shaB})
	if got, v6 := g.country("203.0.113.5"), g.country("2001:db8::1"); got != "FR" || v6 != "JP" {
		t.Errorf("country with B = %q, %q", got, v6)
	}
	g.sync(&nodev1.GeoIPRef{Sha256: shaA})
	if n := events.count(evGeoIPLoaded); n != 2 {
		t.Errorf("geoip_loaded events = %d, want one per sha256", n)
	}
	g.sync(nil)
	if got := g.country("203.0.113.5"); got != "" || g.loadedSHA() != "" {
		t.Errorf("after unloading: %q, %q", got, g.loadedSHA())
	}

	g.sync(&nodev1.GeoIPRef{Sha256: shaA})
	missing := hex.EncodeToString(make([]byte, 32))
	g.sync(&nodev1.GeoIPRef{Sha256: missing})
	if got := g.country("203.0.113.5"); got != "DE" {
		t.Errorf("a missing database unloaded the one before: %q", got)
	}
	clock.Advance(9 * time.Minute)
	g.sync(&nodev1.GeoIPRef{Sha256: missing})
	if n := events.count(evGeoIPMissing); n != 0 {
		t.Errorf("geoip_missing after 9 min = %d", n)
	}
	clock.Advance(time.Minute)
	g.sync(&nodev1.GeoIPRef{Sha256: missing})
	clock.Advance(time.Hour)
	g.sync(&nodev1.GeoIPRef{Sha256: missing})
	if n := events.count(evGeoIPMissing); n != 1 {
		t.Errorf("geoip_missing after 10 min and more = %d, want 1", n)
	}

	// A stored file that is not a database is deleted, so that it is
	// uploaded again.
	bad := hex.EncodeToString(make([]byte, 31)) + "ff"
	if err := os.WriteFile(filepath.Join(dir, bad+".mmdb"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.sync(&nodev1.GeoIPRef{Sha256: bad})
	if slices.Contains(g.stored(), bad) {
		t.Errorf("a stored file that is no database is still listed: %v", g.stored())
	}
}
