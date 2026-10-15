package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/node/state"
)

// releaseServer serves one file and counts the requests and their headers.
type releaseServer struct {
	*httptest.Server
	mu      sync.Mutex
	hits    int
	headers []http.Header
}

func newReleaseServer(t *testing.T, h http.HandlerFunc) *releaseServer {
	t.Helper()
	s := &releaseServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits++
		s.headers = append(s.headers, r.Header.Clone())
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *releaseServer) header(i int) http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers[i]
}

func (s *releaseServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// directState is the base state with its proxy on telemt 3.5.14, an artifact
// that the store does not have, sha the pinned SHA-256 and url its url, on a
// node of artifact source source.
func (h *harness) directState(gen uint64, source, sha, url string) (*nodev1.NodeState, artifacts.Ref) {
	st := h.baseState(gen)
	st.Settings.ArtifactSource = source
	st.Proxies[0].EngineVersion = "3.5.14"
	a := &nodev1.ArtifactRef{Engine: "telemt", Version: "3.5.14", Arch: "amd64", Sha256: sha, FileName: "telemt", Binary: "telemt", Url: url}
	st.Artifacts = append(st.Artifacts, a)
	return st, artifacts.Ref{Engine: "telemt", Version: "3.5.14", Arch: "amd64", SHA256: sha, FileName: "telemt", Binary: "telemt"}
}

var newBinary = []byte("#!/bin/sh\necho 3.5.14\n")

func newBinarySHA() string {
	sum := sha256.Sum256(newBinary)
	return hex.EncodeToString(sum[:])
}

// passAndWait runs a pass and waits for the downloads it started.
func (h *harness) passAndWait() {
	h.t.Helper()
	h.pass()
	h.r.downloads.Wait()
}

func TestDirectDownloadStoredAndTried(t *testing.T) {
	h := newLocalHarness(t)
	srv := newReleaseServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newBinary) })
	st, ref := h.directState(1, state.ArtifactSourceDirect, newBinarySHA(), srv.URL+"/telemt?token=abc")
	h.apply(st)
	h.r.Version = "v0.5.0"

	h.passAndWait()
	if !h.arts.Has(ref) {
		t.Fatalf("the downloaded artifact is not in the store; events %v", h.eventKinds())
	}
	if got := srv.header(0); got.Get("User-Agent") != "postern-node/v0.5.0" || got.Get("Authorization") != "" || got.Get("Cookie") != "" {
		t.Errorf("request headers = %v, want the User-Agent and no credentials", got)
	}
	h.pass() // the pass that the download woke
	if !slices.Contains(h.trials.tried(), h.arts.BinaryPath(ref)) {
		t.Fatalf("the downloaded artifact was not tried before its first use: tried %v", h.trials.tried())
	}
	if rec, ok := h.arts.Trial(ref); !ok || !rec.OK {
		t.Errorf("trial record = %+v, %v; want a passed trial", rec, ok)
	}
	if len(h.eventsOf(evArtifactDownloadFailed)) != 0 {
		t.Errorf("events %v, want no download failure", h.eventKinds())
	}
	if srv.count() != 1 {
		t.Errorf("%d downloads, want 1", srv.count())
	}
}

func TestDirectDownloadWrongChecksumRetriedAfter10Minutes(t *testing.T) {
	h := newLocalHarness(t)
	srv := newReleaseServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("something else")) })
	st, ref := h.directState(1, state.ArtifactSourceDirect, newBinarySHA(), srv.URL+"/telemt?token=secret")
	h.apply(st)

	h.passAndWait()
	if h.arts.Has(ref) {
		t.Fatal("an artifact with the wrong SHA-256 was stored")
	}
	evs := h.eventsOf(evArtifactDownloadFailed)
	if len(evs) != 1 {
		t.Fatalf("events %v, want one %s", h.eventKinds(), evArtifactDownloadFailed)
	}
	if u := evs[0].GetDetails()["url"]; u != srv.URL+"/telemt" || strings.Contains(evs[0].GetMessage(), "secret") {
		t.Errorf("event url %q, message %q: want the url without its query", u, evs[0].GetMessage())
	}
	if !strings.Contains(evs[0].GetDetails()["reason"], "checksum") {
		t.Errorf("reason %q, want the checksum mismatch", evs[0].GetDetails()["reason"])
	}

	h.clock.Advance(9 * time.Minute)
	h.passAndWait()
	if srv.count() != 1 {
		t.Fatalf("%d downloads within 10 minutes of a failure, want 1", srv.count())
	}
	h.clock.Advance(time.Minute + time.Second)
	h.passAndWait()
	if srv.count() != 2 {
		t.Fatalf("%d downloads after 10 minutes, want 2", srv.count())
	}
	if h.trials.tried() != nil && slices.Contains(h.trials.tried(), h.arts.BinaryPath(ref)) {
		t.Error("a missing artifact was tried")
	}
}

// newLocalHarness is a harness whose downloads may go to the test servers:
// http:// and loopback addresses are allowed, which production never does.
func newLocalHarness(t *testing.T) *harness {
	h := newHarness(t)
	h.r.downloadAllowHTTP = true
	h.r.downloadAllowDial = func(ap netip.AddrPort) bool { return ap.Addr().IsLoopback() }
	return h
}

// downloadFails applies a direct state whose artifact has url, runs a pass,
// and checks that the artifact stays missing with one artifact_download_failed
// event whose reason holds reason: the panel uploads it at its next resync.
func (h *harness) downloadFails(url, reason string) {
	h.t.Helper()
	st, ref := h.directState(1, state.ArtifactSourceDirect, newBinarySHA(), url)
	h.apply(st)
	h.passAndWait()
	if h.arts.Has(ref) {
		h.t.Fatal("the artifact was stored")
	}
	evs := h.eventsOf(evArtifactDownloadFailed)
	if len(evs) != 1 || !strings.Contains(evs[0].GetDetails()["reason"], reason) {
		h.t.Fatalf("events %v (%v), want one %s about %q", h.eventKinds(), evs, evArtifactDownloadFailed, reason)
	}
	if strings.Contains(evs[0].GetMessage(), "pw@") {
		h.t.Errorf("the event shows the userinfo: %q", evs[0].GetMessage())
	}
}

// In production a download goes over https to a public address only: the
// destination policy is applied to the address connected to, before the
// connection is made.
func TestDirectDownloadDestinationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, url, reason string
	}{
		{"http to a public host", "http://203.0.113.7/telemt", "https only"},
		{"http to loopback", "http://127.0.0.1:1/telemt", "https only"},
		{"credentials in the url", "https://user:pw@203.0.113.7/telemt", "credentials"},
		{"https to a private address", "https://10.1.2.3/telemt", "is private"},
		{"https to loopback", "https://127.0.0.1:1/telemt", "is loopback"},
		{"https to localhost", "https://localhost:1/telemt", "is loopback"},
		{"https to the metadata service", "https://169.254.169.254/telemt", "is link-local"},
		{"https to an IPv4-mapped loopback", "https://[::ffff:127.0.0.1]:1/telemt", "is loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newHarness(t).downloadFails(tc.url, tc.reason)
		})
	}
}

// A redirect from an allowed server to loopback is refused, by https and by
// http: the policy meets every hop.
func TestDirectDownloadRedirectToLoopbackRefused(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newBinary) }))
	t.Cleanup(target.Close)
	var targetHits sync.Map
	target.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			targetHits.Store("hit", true)
		}
	}
	for _, tc := range []struct {
		name, location, reason string
	}{
		{"to https://127.0.0.1", target.URL + "/telemt", "is loopback"},
		{"to http://127.0.0.1", strings.Replace(target.URL, "https://", "http://", 1) + "/telemt", "https only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.location, http.StatusFound)
			}))
			t.Cleanup(redirect.Close)
			allowed := netip.MustParseAddrPort(redirect.Listener.Addr().String())
			h := newHarness(t) // production rules, but for the one redirecting server
			h.r.downloadAllowDial = func(ap netip.AddrPort) bool { return ap == allowed }
			h.r.downloadTLS = redirect.Client().Transport.(*http.Transport).TLSClientConfig
			h.downloadFails(redirect.URL+"/telemt", tc.reason)
		})
	}
	if _, hit := targetHits.Load("hit"); hit {
		t.Error("the redirect target was connected to")
	}
}

func TestDirectDownloadRefused(t *testing.T) {
	big := newReleaseServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "64")
		_, _ = w.Write(make([]byte, 64))
	})
	streamed := newReleaseServer(t, func(w http.ResponseWriter, _ *http.Request) {
		for range 8 { // no Content-Length: chunked
			_, _ = w.Write(make([]byte, 8))
			w.(http.Flusher).Flush()
		}
	})
	for _, tc := range []struct {
		name, url, reason string
	}{
		{"credentials in the url", strings.Replace(big.URL, "http://", "http://user:pw@", 1) + "/telemt", "credentials"},
		{"oversize by Content-Length", big.URL + "/telemt", "too large"},
		{"oversize streamed", streamed.URL + "/telemt", "too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLocalHarness(t)
			h.r.maxDownload = 16
			h.downloadFails(tc.url, tc.reason)
		})
	}
}

func TestPanelSourceNeverDownloads(t *testing.T) {
	for _, source := range []string{"", state.ArtifactSourcePanel} {
		h := newLocalHarness(t)
		srv := newReleaseServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newBinary) })
		st, ref := h.directState(1, source, newBinarySHA(), srv.URL+"/telemt")
		h.apply(st)
		h.passAndWait()
		h.passAndWait()
		if srv.count() != 0 || h.arts.Has(ref) {
			t.Errorf("artifact_source %q: %d downloads, stored %v; want none", source, srv.count(), h.arts.Has(ref))
		}
		if len(h.eventsOf(evArtifactMissing)) == 0 {
			t.Errorf("artifact_source %q: events %v, want %s", source, h.eventKinds(), evArtifactMissing)
		}
	}
}

func TestDownloadsAtMostTwoAtATime(t *testing.T) {
	h := newLocalHarness(t)
	release := make(chan struct{})
	var mu sync.Mutex
	running, most := 0, 0
	srv := newReleaseServer(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		<-release
		mu.Lock()
		running--
		mu.Unlock()
		_, _ = w.Write(newBinary)
	})
	for i, v := range []string{"3.5.14", "3.5.15", "3.5.16"} {
		h.r.startDownload(artifacts.Ref{Engine: "telemt", Version: v, Arch: "amd64", SHA256: newBinarySHA(), FileName: "telemt", Binary: "telemt"},
			srv.URL+"/telemt-"+string(rune('a'+i)))
	}
	deadline := time.Now().Add(5 * time.Second)
	for srv.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // a third would have arrived by now
	if n := srv.count(); n != 2 {
		t.Errorf("%d downloads at a time, want 2", n)
	}
	close(release)
	h.r.downloads.Wait()
	if srv.count() != 3 || most != 2 {
		t.Errorf("%d downloads, at most %d at a time; want 3 and 2", srv.count(), most)
	}
}
