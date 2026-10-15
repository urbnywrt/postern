package insights

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/geodb"
)

// geoNode is the UploadGeoIP part of an agent: it keeps what it was sent
// whole, and answers with the sha256 of it.
type geoNode struct {
	nodev1connect.UnimplementedNodeServiceHandler

	mu      sync.Mutex
	stored  []geoUpload
	calls   int
	fail    error // answers every upload with it, after reading it
	early   bool  // answers stored after meta, without reading the chunks
	aborted int   // uploads that ended without completing
}

type geoUpload struct {
	meta *nodev1.GeoIPRef
	data []byte
}

func (g *geoNode) UploadGeoIP(_ context.Context, stream *connect.ClientStream[nodev1.UploadGeoIPRequest]) (*connect.Response[nodev1.UploadGeoIPResponse], error) {
	g.mu.Lock()
	g.calls++
	fail, early := g.fail, g.early
	g.mu.Unlock()
	if !stream.Receive() {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("empty"))
	}
	meta := stream.Msg().GetMeta()
	if meta == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("meta first"))
	}
	if early {
		return connect.NewResponse(&nodev1.UploadGeoIPResponse{Stored: true, Sha256: meta.GetSha256()}), nil
	}
	var data bytes.Buffer
	for stream.Receive() {
		data.Write(stream.Msg().GetChunk())
	}
	if err := stream.Err(); err != nil {
		g.mu.Lock()
		g.aborted++
		g.mu.Unlock()
		return nil, err
	}
	if fail != nil {
		return nil, fail
	}
	sum := sha256.Sum256(data.Bytes())
	if hex.EncodeToString(sum[:]) != meta.GetSha256() {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sha256 mismatch"))
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stored = append(g.stored, geoUpload{meta: meta, data: data.Bytes()})
	return connect.NewResponse(&nodev1.UploadGeoIPResponse{Stored: true, Sha256: meta.GetSha256()}), nil
}

func (g *geoNode) snapshot() (stored []geoUpload, calls, aborted int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]geoUpload(nil), g.stored...), g.calls, g.aborted
}

func (g *geoNode) set(fail error, early bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fail, g.early = fail, early
}

// serveGeoNode serves g like an agent does (gRPC over HTTP/2 and TLS).
func serveGeoNode(t *testing.T, g *geoNode) nodev1connect.NodeServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NewNodeServiceHandler(g))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return nodev1connect.NewNodeServiceClient(srv.Client(), srv.URL, connect.WithGRPC())
}

// geoFixture is a sync with a database file of the test and a clock it moves.
type geoFixture struct {
	t      *testing.T
	sync   *GeoIPSync
	node   *geoNode
	client nodev1connect.NodeServiceClient
	path   string
	data   []byte
	sha    string
	mu     sync.Mutex
	now    time.Time
	cur    geodb.Current
	looks  int // calls of current: one per attempt of an upload
}

func newGeoFixture(t *testing.T) *geoFixture {
	f := &geoFixture{t: t, node: &geoNode{}, now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	f.client = serveGeoNode(t, f.node)
	f.data = bytes.Repeat([]byte("mmdb-test-data-"), 200) // 3000 bytes: three chunks of 1000 and none left
	sum := sha256.Sum256(f.data)
	f.sha = hex.EncodeToString(sum[:])
	f.path = filepath.Join(t.TempDir(), "dbip-country-lite-2026-10.mmdb")
	if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
		t.Fatal(err)
	}
	f.cur = geodb.Current{Month: "2026-10", SHA256: f.sha, Path: f.path, Size: int64(len(f.data))}
	f.sync = NewGeoIPSync(func() (geodb.Current, bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.looks++
		return f.cur, f.cur.SHA256 != ""
	}, nil)
	f.sync.chunkSize = 1000
	f.sync.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	return f
}

func (f *geoFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// state names the database of the fixture, or sha when given.
func (f *geoFixture) state(sha string) *nodev1.NodeState {
	if sha == "" {
		sha = f.sha
	}
	return &nodev1.NodeState{Settings: &nodev1.NodeSettings{Geoip: &nodev1.GeoIPRef{Month: "2026-10", Sha256: sha}}}
}

func (f *geoFixture) ensure(info *nodev1.GetInfoResponse, st *nodev1.NodeState) error {
	return f.sync.EnsureArtifacts(context.Background(), "n1", info, st, f.client)
}

func TestGeoIPSyncUploadsOnce(t *testing.T) {
	f := newGeoFixture(t)
	if err := f.ensure(&nodev1.GetInfoResponse{}, f.state("")); err != nil {
		t.Fatalf("EnsureArtifacts: %v", err)
	}
	stored, calls, _ := f.node.snapshot()
	if calls != 1 || len(stored) != 1 || !bytes.Equal(stored[0].data, f.data) ||
		stored[0].meta.GetSha256() != f.sha || stored[0].meta.GetMonth() != "2026-10" {
		t.Fatalf("uploads: %d calls, stored %d", calls, len(stored))
	}
	// The node holds it now: not again, also when it says so in upper case.
	if err := f.ensure(&nodev1.GetInfoResponse{GeoipStored: []string{strings.ToUpper(f.sha)}}, f.state("")); err != nil {
		t.Fatal(err)
	}
	// A state that names none: nothing.
	if err := f.ensure(&nodev1.GetInfoResponse{}, &nodev1.NodeState{Settings: &nodev1.NodeSettings{}}); err != nil {
		t.Fatal(err)
	}
	if _, calls, _ := f.node.snapshot(); calls != 1 {
		t.Errorf("%d calls, want 1", calls)
	}
}

func TestGeoIPSyncRetriesAFailureAfter30Minutes(t *testing.T) {
	f := newGeoFixture(t)
	f.node.set(connect.NewError(connect.CodeInternal, errors.New("disk full")), false)
	if err := f.ensure(&nodev1.GetInfoResponse{}, f.state("")); err == nil {
		t.Fatal("a failed upload is no error")
	}
	f.node.set(nil, false)
	for _, d := range []time.Duration{0, 29 * time.Minute} {
		f.advance(d)
		if err := f.ensure(&nodev1.GetInfoResponse{}, f.state("")); err == nil {
			t.Errorf("after %s: no error, want the failure remembered", d)
		}
	}
	if _, calls, _ := f.node.snapshot(); calls != 1 {
		t.Fatalf("%d calls within 30 minutes of the failure, want 1", calls)
	}
	// Another node is not held back by it.
	if err := f.sync.EnsureArtifacts(context.Background(), "n2", &nodev1.GetInfoResponse{}, f.state(""), f.client); err != nil {
		t.Errorf("another node: %v", err)
	}
	f.advance(2 * time.Minute)
	if err := f.ensure(&nodev1.GetInfoResponse{}, f.state("")); err != nil {
		t.Errorf("after 31 minutes: %v", err)
	}
	if stored, calls, _ := f.node.snapshot(); calls != 3 || len(stored) != 2 {
		t.Errorf("%d calls and %d stored, want 3 and 2", calls, len(stored))
	}
}

// A node that answers before it has read the chunks (it holds the file
// already) makes Send say io.EOF: the answer is the result.
func TestGeoIPSyncTakesAnEarlyAnswer(t *testing.T) {
	f := newGeoFixture(t)
	f.node.set(nil, true)
	// A larger file, so that the answer comes while chunks are still sent.
	big := bytes.Repeat([]byte{7}, 4<<20)
	if err := os.WriteFile(f.path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(big)
	f.mu.Lock()
	f.sha = hex.EncodeToString(sum[:])
	f.cur.SHA256 = f.sha
	f.mu.Unlock()
	if err := f.ensure(&nodev1.GetInfoResponse{}, f.state("")); err != nil {
		t.Errorf("EnsureArtifacts: %v", err)
	}
}

// The file of the database is replaced while it is read: the node gets no
// complete upload, and it is not remembered as a failure of the node.
func TestGeoIPSyncAbortsAFileThatChanged(t *testing.T) {
	f := newGeoFixture(t)
	if err := os.WriteFile(f.path, bytes.Repeat([]byte("another-file"), 300), 0o600); err != nil {
		t.Fatal(err)
	}
	err := f.ensure(&nodev1.GetInfoResponse{}, f.state(""))
	if !errors.Is(err, errFileChanged) {
		t.Fatalf("err = %v, want errFileChanged", err)
	}
	// The attempts are counted where they start: the sync aborts a stream
	// that it has sent whole, and an aborted stream may never reach the
	// handler of the node, so the node's count of calls is not the count of
	// attempts.
	stored, calls, _ := f.node.snapshot()
	f.mu.Lock()
	attempts := f.looks
	f.mu.Unlock()
	if len(stored) != 0 || attempts != geoipAttempts || calls > geoipAttempts {
		t.Errorf("stored %d, %d attempts, %d calls; want nothing stored, %d attempts", len(stored), attempts, calls, geoipAttempts)
	}
	// Mended: it goes at once, no 30 minutes.
	if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure(&nodev1.GetInfoResponse{}, f.state("")); err != nil {
		t.Errorf("after the file is right: %v", err)
	}
}

// A state that names a database the panel does not have now: nothing is sent.
func TestGeoIPSyncDoesNotSendAnotherDatabase(t *testing.T) {
	f := newGeoFixture(t)
	if err := f.ensure(&nodev1.GetInfoResponse{}, f.state(strings.Repeat("cd", 32))); err == nil {
		t.Error("no error for a database that the panel does not have")
	}
	if _, calls, _ := f.node.snapshot(); calls != 0 {
		t.Errorf("%d calls, want none", calls)
	}
}
