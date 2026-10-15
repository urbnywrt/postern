package proxies

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

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// The made-up release that the tests make ready: what the panel uploads is
// opaque to it.
const (
	readyVersion = "3.5.14"
	readyFile    = "telemt-x86_64-linux-musl.tar.gz"
)

var readyArchive = bytes.Repeat([]byte("made-up archive "), 500)

// readyRelease stores an upstream release of telemt with one pinned asset for
// amd64 whose file is in the directory of the catalog, in the state given.
func (e *env) readyRelease(state string) *nodev1.ArtifactRef {
	e.t.Helper()
	rel := &store.Release{Engine: EngineTelemt, Version: readyVersion, Tag: readyVersion, Source: store.SourceUpstream,
		Assets: map[string]store.ReleaseAsset{"amd64": {File: readyFile, URL: "https://example.invalid/" + readyFile,
			SHA256: sha256Hex(readyArchive), SHASource: store.SHASourceSums}}}
	if err := e.db.UpsertRelease(e.ctx, rel); err != nil {
		e.t.Fatal(err)
	}
	dir := filepath.Join(e.relDir, EngineTelemt, readyVersion)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, readyFile), readyArchive, 0o644); err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.SetAssetState(e.ctx, EngineTelemt, readyVersion, "amd64", state, "", ""); err != nil {
		e.t.Fatal(err)
	}
	ref, err := e.catalog.Ref(e.ctx, EngineTelemt, readyVersion, "amd64")
	if err != nil {
		e.t.Fatal(err)
	}
	return ref
}

// uploadNode is the UploadArtifact part of an agent, over HTTP/2 and TLS. It
// answers every upload with the trial verdict set on it.
type uploadNode struct {
	nodev1connect.UnimplementedNodeServiceHandler

	mu      sync.Mutex
	uploads []upload
	tried   bool
	usable  bool
	reason  string
}

type upload struct {
	meta *nodev1.ArtifactRef
	data []byte
}

func (u *uploadNode) UploadArtifact(_ context.Context, stream *connect.ClientStream[nodev1.UploadArtifactRequest]) (*connect.Response[nodev1.UploadArtifactResponse], error) {
	var (
		meta *nodev1.ArtifactRef
		data bytes.Buffer
	)
	for stream.Receive() {
		switch part := stream.Msg().GetPart().(type) {
		case *nodev1.UploadArtifactRequest_Meta:
			if meta != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("meta twice"))
			}
			meta = part.Meta
		case *nodev1.UploadArtifactRequest_Chunk:
			if meta == nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a chunk before meta"))
			}
			data.Write(part.Chunk)
		}
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.uploads = append(u.uploads, upload{meta: meta, data: data.Bytes()})
	return connect.NewResponse(&nodev1.UploadArtifactResponse{Stored: true, Sha256: sha256Hex(data.Bytes()),
		Tried: u.tried, Usable: u.usable, Reason: u.reason}), nil
}

func (u *uploadNode) got() []upload {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upload(nil), u.uploads...)
}

// serveUploadNode serves u like an agent does (gRPC over HTTP/2 and TLS) and
// returns a client of it.
func serveUploadNode(t *testing.T, u *uploadNode) nodev1connect.NodeServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NewNodeServiceHandler(u))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return nodev1connect.NewNodeServiceClient(srv.Client(), srv.URL, connect.WithGRPC())
}

func stateWith(refs ...*nodev1.ArtifactRef) *nodev1.NodeState {
	return &nodev1.NodeState{Generation: 1, Artifacts: refs}
}

func infoWith(caps []string, refs ...*nodev1.ArtifactRef) *nodev1.GetInfoResponse {
	return &nodev1.GetInfoResponse{Capabilities: caps, Artifacts: refs}
}

func (e *env) assetState(version, arch string) store.ReleaseAsset {
	e.t.Helper()
	rel, err := e.db.ReleaseOf(e.ctx, EngineTelemt, version)
	if err != nil {
		e.t.Fatal(err)
	}
	return rel.Assets[arch]
}

func TestEnsureArtifactsUploadsOnlyReadyArchives(t *testing.T) {
	e := newEnv(t)
	e.catalog.chunkSize = 1000
	ready := e.readyRelease(store.AssetReady)
	// The built-in telemt is seeded but not prepared: named, not uploaded.
	builtin, err := e.catalog.Ref(e.ctx, EngineTelemt, DefaultTelemtVersion, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	node := &uploadNode{}
	client := serveUploadNode(t, node)

	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(nil), stateWith(builtin, ready), client); err != nil {
		t.Fatalf("EnsureArtifacts: %v", err)
	}
	got := node.got()
	if len(got) != 1 || !proto.Equal(got[0].meta, ready) || !bytes.Equal(got[0].data, readyArchive) {
		t.Fatalf("uploads = %d, want the one ready archive with its bytes", len(got))
	}
	if !strings.Contains(e.prepared.String(), "telemt "+DefaultTelemtVersion+" amd64") {
		t.Errorf("the unprepared built-in version was not sent to be prepared; prepared:\n%s", e.prepared.String())
	}

	// The node has it now: nothing is uploaded again.
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(nil, ready), stateWith(ready), client); err != nil {
		t.Fatalf("EnsureArtifacts again: %v", err)
	}
	if len(node.got()) != 1 {
		t.Errorf("an artifact the node has was uploaded again")
	}

	// A state that names what the catalog does not pin is an error.
	bogus := proto.Clone(ready).(*nodev1.ArtifactRef)
	bogus.Sha256 = strings.Repeat("0", 64)
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(nil), stateWith(bogus), client); err == nil {
		t.Error("a state with a SHA-256 the catalog does not pin: no error")
	}
	e.assertNoSecretsLogged()
}

func TestEnsureArtifactsSkipsAnUnusableAsset(t *testing.T) {
	e := newEnv(t)
	ready := e.readyRelease(store.AssetUnusable)
	node := &uploadNode{}
	client := serveUploadNode(t, node)
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(nil), stateWith(ready), client); err != nil {
		t.Fatalf("EnsureArtifacts: %v", err)
	}
	if len(node.got()) != 0 {
		t.Errorf("an unusable asset was uploaded")
	}
	if e.prepared.String() != "" {
		t.Errorf("an unusable asset was sent to be prepared: %s", e.prepared.String())
	}
}

func TestEnsureArtifactsTrialVerdicts(t *testing.T) {
	caps := []string{"faketls", CapArtifactTrial}
	for _, tc := range []struct {
		name          string
		caps          []string
		tried, usable bool
		wantUnusable  bool
	}{
		{"tried and unusable", caps, true, false, true},
		{"tried and usable", caps, true, true, false},
		{"not tried", caps, false, false, false},
		{"a node without the capability says unusable", nil, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			ready := e.readyRelease(store.AssetReady)
			node := &uploadNode{tried: tc.tried, usable: tc.usable, reason: "exec format error"}
			client := serveUploadNode(t, node)
			if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(tc.caps), stateWith(ready), client); err != nil {
				t.Fatalf("EnsureArtifacts: %v", err)
			}
			a := e.assetState(readyVersion, "amd64")
			if got := a.State == store.AssetUnusable; got != tc.wantUnusable {
				t.Errorf("asset state = %q (reason %q, node %q), unusable = %v, want %v", a.State, a.Reason, a.NodeID, got, tc.wantUnusable)
			}
			if tc.wantUnusable && (a.Reason != "exec format error" || a.NodeID != "n1") {
				t.Errorf("the verdict was recorded without its reason and node: %+v", a)
			}
		})
	}
}

func TestEnsureArtifactsAndTheNodesOwnVerdict(t *testing.T) {
	e := newEnv(t)
	ready := e.readyRelease(store.AssetReady)
	node := &uploadNode{tried: true, usable: true}
	client := serveUploadNode(t, node)
	caps := []string{CapArtifactTrial}

	// An artifact the node lists as unusable is not uploaded again.
	unusable := proto.Clone(ready).(*nodev1.ArtifactRef)
	unusable.State = "unusable"
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(caps, unusable), stateWith(ready), client); err != nil {
		t.Fatalf("EnsureArtifacts: %v", err)
	}
	if len(node.got()) != 0 {
		t.Errorf("an artifact the node found unusable was uploaded again")
	}
	// One it has but never tried is uploaded again.
	untried := proto.Clone(ready).(*nodev1.ArtifactRef)
	untried.State = "untried"
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(caps, untried), stateWith(ready), client); err != nil {
		t.Fatalf("EnsureArtifacts: %v", err)
	}
	if len(node.got()) != 1 {
		t.Errorf("an untried artifact was not uploaded again")
	}
	// A node without the capability that lists the artifact has it, whatever
	// the state field says.
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(nil, untried), stateWith(ready), client); err != nil {
		t.Fatalf("EnsureArtifacts: %v", err)
	}
	if len(node.got()) != 1 {
		t.Errorf("a node without artifact-trial got an upload for a state it cannot have set")
	}
}

func TestBuiltinRef(t *testing.T) {
	ref, ok := BuiltinRef(EngineXray, DefaultXrayVersion, "amd64")
	if !ok || ref.GetSha256() != "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae" || ref.GetBinary() != "xray" ||
		ref.GetUrl() != "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip" {
		t.Errorf("BuiltinRef(xray) = %v, %v", ref, ok)
	}
	if _, ok := BuiltinRef(EngineTelemt, "0.0.1", "amd64"); ok {
		t.Error("BuiltinRef of an unknown version: ok")
	}
	if _, ok := BuiltinRef("nope", DefaultTelemtVersion, "amd64"); ok {
		t.Error("BuiltinRef of an unknown component: ok")
	}
}
