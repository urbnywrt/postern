package versions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

const tgz = "telemt-x86_64-linux-musl.tar.gz"

// A fakeHost serves files by path: the release API under /api and downloads.
type fakeHost struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{files: map[string][]byte{}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		data, ok := h.files[r.URL.Path]
		h.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *fakeHost) put(path string, data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[path] = data
}

func (h *fakeHost) url(path string) string { return h.srv.URL + path }

// telemtArchive is a tar.gz with a static amd64 ELF named telemt.
func telemtArchive(t *testing.T) []byte {
	t.Helper()
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	var bin bytes.Buffer
	for _, v := range []any{
		elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
			Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: 1},
		elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R)},
	} {
		if err := binary.Write(&bin, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	bin.Write(bytes.Repeat([]byte{0xcc}, 128))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "telemt", Mode: 0o755, Size: int64(bin.Len()), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(bin.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (a *api) client() panelv1connect.VersionServiceClient {
	return panelv1connect.NewVersionServiceClient(a.web, a.srv.URL)
}

// code returns the Connect code of err, or an empty string for nil.
func code(err error) string {
	if err == nil {
		return ""
	}
	return connect.CodeOf(err).String()
}

func TestCatalogRPCs(t *testing.T) {
	ctx := context.Background()
	a := newAPI(t, true)
	vs := a.client()
	archive := telemtArchive(t)
	a.host.put("/dl/9.0.0/"+tgz, archive)
	a.host.put("/api/repos/telemt/telemt/releases", []byte(fmt.Sprintf(
		`[{"tag_name":"9.0.0","prerelease":false,"published_at":"2026-10-02T00:00:00Z","body":"notes","html_url":"https://example.com/r/9.0.0",
		  "assets":[{"name":%q,"browser_download_url":%q,"digest":"sha256:%s","size":%d,"created_at":"2026-10-01T00:00:00Z"}]}]`,
		tgz, a.host.url("/dl/9.0.0/"+tgz), sum(archive), len(archive))))

	t.Run("ListComponents", func(t *testing.T) {
		resp, err := vs.ListComponents(ctx, connect.NewRequest(&panelv1.ListComponentsRequest{}))
		if err != nil {
			t.Fatalf("ListComponents: %v", err)
		}
		if resp.Msg.DefaultChannel != store.ChannelStable || resp.Msg.IncludePrereleases {
			t.Errorf("default channel %q, prereleases %v", resp.Msg.DefaultChannel, resp.Msg.IncludePrereleases)
		}
		if len(resp.Msg.Components) != 4 {
			t.Fatalf("components = %d, want 4", len(resp.Msg.Components))
		}
		telemt := resp.Msg.Components[0]
		if telemt.Name != "telemt" || telemt.Kind != "engine" || telemt.ChannelVersions[store.ChannelStable] != "3.5.13" ||
			telemt.ChannelVersions[store.ChannelLatest] != "3.5.13" || telemt.Newest[store.ChannelLatest] != "3.5.13" ||
			telemt.CheckedUnix != 0 || telemt.FeedError != "" {
			t.Errorf("telemt = %+v", telemt)
		}
	})

	t.Run("RefreshReleases", func(t *testing.T) {
		resp, err := vs.RefreshReleases(ctx, connect.NewRequest(&panelv1.RefreshReleasesRequest{Component: "telemt"}))
		if err != nil {
			t.Fatalf("RefreshReleases: %v", err)
		}
		if len(resp.Msg.Components) != 4 || resp.Msg.Components[0].CheckedUnix == 0 || resp.Msg.Components[0].Newest[store.ChannelLatest] != "9.0.0" {
			t.Errorf("components after refresh = %+v", resp.Msg.Components)
		}
		// Within a minute of the last one: UNAVAILABLE.
		_, err = vs.RefreshReleases(ctx, connect.NewRequest(&panelv1.RefreshReleasesRequest{Component: "telemt"}))
		if code(err) != "unavailable" {
			t.Errorf("second refresh: %v, want unavailable", err)
		}
		// Every component: the others have no feed on the fake host, and the
		// answer says so; the call is UNAVAILABLE but the components are polled.
		_, err = vs.RefreshReleases(ctx, connect.NewRequest(&panelv1.RefreshReleasesRequest{}))
		if code(err) != "unavailable" {
			t.Errorf("refresh of every component: %v, want unavailable", err)
		}
		list, err := vs.ListComponents(ctx, connect.NewRequest(&panelv1.ListComponentsRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if mtg := list.Msg.Components[1]; mtg.Name != "mtg" || mtg.CheckedUnix == 0 || mtg.FeedError == "" {
			t.Errorf("mtg after the refresh = %+v, want checked, with the error of its feed", mtg)
		}
		_, err = vs.RefreshReleases(ctx, connect.NewRequest(&panelv1.RefreshReleasesRequest{Component: "nothing"}))
		if code(err) != "invalid_argument" {
			t.Errorf("refresh of an unknown component: %v, want invalid_argument", err)
		}
	})

	t.Run("ListReleases", func(t *testing.T) {
		resp, err := vs.ListReleases(ctx, connect.NewRequest(&panelv1.ListReleasesRequest{Component: "telemt"}))
		if err != nil {
			t.Fatalf("ListReleases: %v", err)
		}
		if len(resp.Msg.Releases) != 2 || resp.Msg.Releases[0].Version != "9.0.0" || resp.Msg.Releases[1].Version != "3.5.13" {
			t.Fatalf("releases = %+v, want 9.0.0 then 3.5.13", resp.Msg.Releases)
		}
		found, builtin := resp.Msg.Releases[0], resp.Msg.Releases[1]
		if found.Stable || found.Source != store.SourceUpstream || found.Notes != "notes" || len(found.Channels) != 0 ||
			len(found.Assets) != 1 || found.Assets[0].Arch != "amd64" || found.Assets[0].Sha256 != sum(archive) || found.Assets[0].ShaSource != store.SHASourceDigest {
			t.Errorf("9.0.0 = %+v", found)
		}
		if !builtin.Stable || builtin.Source != store.SourceBuiltin || strings.Join(builtin.Channels, ",") != "latest,stable" || len(builtin.Assets) != 2 {
			t.Errorf("3.5.13 = %+v", builtin)
		}
		_, err = vs.ListReleases(ctx, connect.NewRequest(&panelv1.ListReleasesRequest{Component: "nothing"}))
		if code(err) != "invalid_argument" {
			t.Errorf("unknown component: %v, want invalid_argument", err)
		}
		// F7 of the real-server pass: the component postern, which the proto
		// lists, is the releases of Postern that the panel knows (an upload).
		resp, err = vs.ListReleases(ctx, connect.NewRequest(&panelv1.ListReleasesRequest{Component: "postern"}))
		if err != nil || len(resp.Msg.Releases) != 0 {
			t.Fatalf("postern, none known: %v, %v", resp, err)
		}
		if err := a.db.UpsertRelease(ctx, &store.Release{Engine: "postern", Version: "v0.5.0", Tag: "v0.5.0", Source: store.SourceUpload,
			Assets: map[string]store.ReleaseAsset{"amd64": {File: "postern-node-linux-amd64", SHA256: strings.Repeat("ab", 32), SHASource: store.SHASourceSigned}}}); err != nil {
			t.Fatal(err)
		}
		resp, err = vs.ListReleases(ctx, connect.NewRequest(&panelv1.ListReleasesRequest{Component: "postern"}))
		if err != nil || len(resp.Msg.Releases) != 1 || resp.Msg.Releases[0].Component != "postern" || resp.Msg.Releases[0].Version != "v0.5.0" ||
			resp.Msg.Releases[0].Source != store.SourceUpload || len(resp.Msg.Releases[0].Assets) != 1 {
			t.Errorf("postern: %v, %v", resp, err)
		}
	})

	t.Run("PrepareRelease", func(t *testing.T) {
		// Without nodes there is no architecture to default to.
		_, err := vs.PrepareRelease(ctx, connect.NewRequest(&panelv1.PrepareReleaseRequest{Component: "telemt", Version: "9.0.0"}))
		if code(err) != "failed_precondition" {
			t.Errorf("prepare without nodes or archs: %v, want failed_precondition", err)
		}
		_, err = vs.PrepareRelease(ctx, connect.NewRequest(&panelv1.PrepareReleaseRequest{Component: "telemt", Version: "9.0.0", Archs: []string{"mips"}}))
		if code(err) != "invalid_argument" {
			t.Errorf("prepare for mips: %v, want invalid_argument", err)
		}
		_, err = vs.PrepareRelease(ctx, connect.NewRequest(&panelv1.PrepareReleaseRequest{Component: "telemt", Version: "9.9.9", Archs: []string{"amd64"}}))
		if code(err) != "not_found" {
			t.Errorf("prepare of an unknown version: %v, want not_found", err)
		}
		if err := a.db.CreateNode(ctx, &store.Node{Name: "n1", Arch: "amd64"}); err != nil {
			t.Fatal(err)
		}
		resp, err := vs.PrepareRelease(ctx, connect.NewRequest(&panelv1.PrepareReleaseRequest{Component: "telemt", Version: "9.0.0"}))
		if err != nil {
			t.Fatalf("PrepareRelease: %v", err)
		}
		if as := resp.Msg.Release.Assets; len(as) != 1 || as[0].State != store.AssetReady || as[0].Size != int64(len(archive)) {
			t.Errorf("assets after prepare = %+v, want amd64 ready", as)
		}
		// A download that is not there: UNAVAILABLE, and the asset as it was.
		rel, _ := a.db.ReleaseOf(ctx, "telemt", "3.5.13")
		as := rel.Assets["amd64"]
		as.URL = a.host.url("/dl/missing")
		rel.Assets = map[string]store.ReleaseAsset{"amd64": as}
		if err := a.db.UpsertRelease(ctx, rel); err != nil {
			t.Fatal(err)
		}
		_, err = vs.PrepareRelease(ctx, connect.NewRequest(&panelv1.PrepareReleaseRequest{Component: "telemt", Version: "3.5.13", Archs: []string{"amd64"}}))
		if code(err) != "unavailable" {
			t.Errorf("prepare with a missing download: %v, want unavailable", err)
		}
	})

	t.Run("RecheckRelease", func(t *testing.T) {
		if err := a.db.SetAssetState(ctx, "telemt", "9.0.0", "amd64", store.AssetUnusable, "a trial failed", "n1"); err != nil {
			t.Fatal(err)
		}
		resp, err := vs.RecheckRelease(ctx, connect.NewRequest(&panelv1.RecheckReleaseRequest{Component: "telemt", Version: "9.0.0", Arch: "amd64"}))
		if err != nil {
			t.Fatalf("RecheckRelease: %v", err)
		}
		if as := resp.Msg.Release.Assets; len(as) != 1 || as[0].State != store.AssetReady || as[0].Reason != "" || as[0].NodeId != "" {
			t.Errorf("assets after recheck = %+v, want amd64 ready again", as)
		}
		_, err = vs.RecheckRelease(ctx, connect.NewRequest(&panelv1.RecheckReleaseRequest{Component: "telemt", Version: "9.0.0", Arch: "arm64"}))
		if code(err) != "not_found" {
			t.Errorf("recheck of an asset that is not there: %v, want not_found", err)
		}
		_, err = vs.RecheckRelease(ctx, connect.NewRequest(&panelv1.RecheckReleaseRequest{Component: "telemt", Version: "9.0.0"}))
		if code(err) != "invalid_argument" {
			t.Errorf("recheck without an arch: %v, want invalid_argument", err)
		}
	})

	t.Run("audit and admin", func(t *testing.T) {
		log := strings.Join(a.auditLog(), "\n")
		for _, want := range []string{"versions.releases.refresh component:telemt", "versions.releases.prepare release:telemt/9.0.0", "versions.releases.recheck release:telemt/9.0.0"} {
			if !strings.Contains(log, a.adminID+" "+want) {
				t.Errorf("audit log lacks %q:\n%s", want, log)
			}
		}
		// telemt was refreshed once; the two refusals within the minute are not audited.
		if n := strings.Count(log, "versions.releases.refresh component:telemt"); n != 1 {
			t.Errorf("telemt refresh audited %d times, want 1:\n%s", n, log)
		}
		anon := panelv1connect.NewVersionServiceClient(a.anon, a.srv.URL)
		if _, err := anon.ListReleases(ctx, connect.NewRequest(&panelv1.ListReleasesRequest{Component: "telemt"})); code(err) != "unauthenticated" {
			t.Errorf("ListReleases without a session: %v, want unauthenticated", err)
		}
	})
}

// A service without a catalog answers that the procedures are not implemented.
func TestCatalogRPCsWithoutCatalog(t *testing.T) {
	s := New(nil, nil)
	_, err := s.ListComponents(context.Background(), connect.NewRequest(&panelv1.ListComponentsRequest{}))
	if code(err) != "unauthenticated" {
		t.Errorf("without an admin: %v, want unauthenticated", err)
	}
}
