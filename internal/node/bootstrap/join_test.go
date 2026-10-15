package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/pki"
)

// joinServer is the panel's JoinService behind HTTPS, under /api.
type joinServer struct {
	panelv1connect.UnimplementedJoinServiceHandler
	t      *testing.T
	ca     *pki.CA
	url    string
	roots  *x509.CertPool
	nodeID string
	port   uint32

	mu          sync.Mutex
	calls       int
	requests    []*panelv1.JoinRequest
	keys        []*ecdsa.PublicKey
	unavailable int                                          // HTTP 503 for this many requests
	fail        func(call int) error                         // the answer of a call, before signing
	lose        int                                          // sign, then answer Unavailable, this many times
	mutate      func(resp *panelv1.JoinResponse)             // changes a good answer
	names       func(lower string) (cn string, dns []string) // what the certificate names
}

func newJoinServer(t *testing.T) *joinServer {
	t.Helper()
	ca, _, err := pki.NewCA("Internal CA")
	if err != nil {
		t.Fatal(err)
	}
	s := &joinServer{t: t, ca: ca, nodeID: "01K6Q8Z5N4X3W2V1T0S9R8Q7P6", port: 61234}
	path, handler := panelv1connect.NewJoinServiceHandler(s)
	mux := http.NewServeMux()
	mux.Handle("/api"+path, http.StripPrefix("/api", handler))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		down := s.unavailable > 0
		if down {
			s.unavailable--
			s.calls++
		}
		s.mu.Unlock()
		if down {
			http.Error(w, "the panel restarts", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	s.roots = x509.NewCertPool()
	s.roots.AddCert(srv.Certificate())
	return s
}

func (s *joinServer) Join(_ context.Context, req *connect.Request[panelv1.JoinRequest]) (*connect.Response[panelv1.JoinResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.requests = append(s.requests, req.Msg)
	pub, err := pki.ParseServerCSR(req.Msg.GetCsr())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.keys = append(s.keys, pub)
	if s.fail != nil {
		if err := s.fail(s.calls); err != nil {
			return nil, err
		}
	}
	id := s.nodeID
	cn, dns := strings.ToLower(id), []string{strings.ToLower(id) + ".internal"}
	if s.names != nil {
		cn, dns = s.names(cn)
	}
	certPEM, err := s.ca.SignServerCSR(req.Msg.GetCsr(), cn, dns)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if s.lose > 0 {
		s.lose--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the answer was lost"))
	}
	resp := &panelv1.JoinResponse{NodeId: id, MgmtPort: s.port, CaPem: s.ca.CertPEM, CertPem: certPEM}
	if s.mutate != nil {
		s.mutate(resp)
	}
	return connect.NewResponse(resp), nil
}

// joinHarness is a harness whose environment carries a token for srv.
func joinHarness(t *testing.T) (*harness, *joinServer, string) {
	h := newHarness(t)
	srv := newJoinServer(t)
	h.opt.RootCAs = srv.roots
	token := newToken(t)
	h.opt.Env = append(h.opt.Env, EnvJoin+"="+srv.url+"#"+token)
	b := h.boot()
	if err := b.makeLayout(); err != nil {
		t.Fatal(err)
	}
	return h, srv, token
}

func TestJoinWritesTheBundle(t *testing.T) {
	h, srv, token := joinHarness(t)
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	req := srv.requests[0]
	if req.GetToken() != token || req.GetArch() != "amd64" || req.GetVersion() != "0.5.0" {
		t.Errorf("request = token %v, arch %q, version %q", req.GetToken() == token, req.GetArch(), req.GetVersion())
	}
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil || csr.Subject.CommonName != "postern-node" {
		t.Errorf("CSR = %v, %v; want CN postern-node", csr, err)
	}
	pkiPath := filepath.Join(h.home, "pki")
	if st, err := os.Stat(pkiPath); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("pki/: %v, %v", st, err)
	}
	files := map[string][]byte{}
	for _, f := range pkiFiles {
		p := filepath.Join(pkiPath, f)
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("pki/%s: %v, %v; want mode 0600", f, st, err)
		}
		files[f], _ = os.ReadFile(p)
	}
	want := `{"version":1,"node_id":"` + srv.nodeID + `","mgmt_port":61234}`
	if string(files["bundle.json"]) != want {
		t.Errorf("bundle.json = %s, want %s", files["bundle.json"], want)
	}
	// The files are what MarshalTar makes of the same bundle, byte for byte.
	b := &pki.Bundle{NodeID: srv.nodeID, MgmtPort: 61234, CAPEM: files["ca.pem"], CertPEM: files["node.pem"], KeyPEM: files["node-key.pem"]}
	data, err := b.MarshalTar()
	if err != nil {
		t.Fatal(err)
	}
	back, err := pki.ParseBundleTar(data)
	if err != nil || back.NodeID != srv.nodeID {
		t.Fatalf("ParseBundleTar = %v, %v", back, err)
	}
	if _, err := pki.ServerTLSConfig(b.CAPEM, b.CertPEM, b.KeyPEM); err != nil {
		t.Errorf("the agent cannot use the keys: %v", err)
	}
	if got := readString(t, filepath.Join(h.home, "data", "state", "join-token.sha256")); got != tokenHash(token)+"\n" {
		t.Errorf("join-token.sha256 = %q", got)
	}
	if _, err := os.Stat(filepath.Join(h.home, "data", "run", "join")); !os.IsNotExist(err) {
		t.Errorf("data/run/join is still there: %v", err)
	}
}

func TestJoinRetriesUnavailable(t *testing.T) {
	h, srv, _ := joinHarness(t)
	srv.unavailable = 2
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if srv.calls != 3 || !slices.Equal(h.sleeps, []time.Duration{2 * time.Second, 4 * time.Second}) {
		t.Errorf("calls = %d, sleeps = %v; want 3 and [2s 4s]", srv.calls, h.sleeps)
	}
}

func TestJoinGivesUpAfterFiveAttempts(t *testing.T) {
	h, srv, _ := joinHarness(t)
	srv.unavailable = 100
	err := h.boot().joinStep(t.Context())
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("joinStep = %v, want Unavailable", err)
	}
	if srv.calls != 5 || !slices.Equal(h.sleeps, retryDelays) {
		t.Errorf("calls = %d, sleeps = %v; want 5 and %v", srv.calls, h.sleeps, retryDelays)
	}
}

// A refusal is not tried again; without keys the node waits refusalWait before
// it exits, so that a container with a dead token does not hammer the panel.
func TestJoinDoesNotRetryARefusal(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeUnauthenticated, connect.CodeInvalidArgument, connect.CodeResourceExhausted} {
		t.Run(code.String(), func(t *testing.T) {
			h, srv, token := joinHarness(t)
			srv.fail = func(int) error { return connect.NewError(code, errors.New("no")) }
			err := h.boot().joinStep(t.Context())
			if connect.CodeOf(err) != code || srv.calls != 1 || !slices.Equal(h.sleeps, []time.Duration{5 * time.Minute}) {
				t.Fatalf("joinStep = %v after %d calls, sleeps %v; want %v after one wait of 5m", err, srv.calls, h.sleeps, code)
			}
			if strings.Contains(err.Error(), token) {
				t.Error("the error holds the token")
			}
			h.wantLog("the panel refused the join")
		})
	}
}

// SIGTERM during the wait after a refusal ends it at once.
func TestJoinRefusalWaitEndsOnSIGTERM(t *testing.T) {
	h, srv, _ := joinHarness(t)
	srv.fail = func(int) error { return connect.NewError(connect.CodeUnauthenticated, errors.New("expired")) }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.opt.Sleep = func(ctx context.Context, d time.Duration) error {
		h.sleeps = append(h.sleeps, d)
		cancel() // the signal arrives during the wait
		return sleep(ctx, d)
	}
	start := time.Now()
	err := h.boot().joinStep(ctx)
	if connect.CodeOf(err) != connect.CodeUnauthenticated || time.Since(start) > 10*time.Second {
		t.Fatalf("joinStep = %v after %v; want the refusal at once", err, time.Since(start))
	}
	if !slices.Equal(h.sleeps, []time.Duration{5 * time.Minute}) {
		t.Errorf("sleeps = %v", h.sleeps)
	}
}

// Other failures without keys (the network) end without that wait: Docker's
// own restart delay paces them.
func TestJoinUnavailableDoesNotWaitForARefusal(t *testing.T) {
	h, srv, _ := joinHarness(t)
	srv.unavailable = 100
	_ = h.boot().joinStep(t.Context())
	if slices.Contains(h.sleeps, 5*time.Minute) {
		t.Errorf("sleeps = %v, want no refusal wait", h.sleeps)
	}
}

func TestJoinWithALostAnswerReusesTheKey(t *testing.T) {
	h, srv, _ := joinHarness(t)
	// Within one run: the retry sends the same key.
	srv.lose = 1
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(srv.keys) != 2 || !srv.keys[0].Equal(srv.keys[1]) {
		t.Fatalf("keys = %d, the same = %v", len(srv.keys), len(srv.keys) == 2 && srv.keys[0].Equal(srv.keys[1]))
	}

	// Across runs: a run that failed leaves the key for the next one.
	h2, srv2, _ := joinHarness(t)
	srv2.unavailable = 100
	if err := h2.boot().joinStep(t.Context()); err == nil {
		t.Fatal("the join passed against a panel that is down")
	}
	srv2.unavailable = 0
	if err := h2.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(srv2.keys) != 1 {
		t.Fatalf("keys = %d", len(srv2.keys))
	}
	keyPEM := readString(t, filepath.Join(h2.home, "pki", "node-key.pem"))
	key, err := parseKey([]byte(keyPEM))
	if err != nil || !key.PublicKey.Equal(srv2.keys[0]) {
		t.Errorf("node-key.pem is not the key that was sent: %v", err)
	}

	// A new token makes a new key.
	tok2 := newToken(t)
	h2.opt.Env = []string{EnvJoin + "=" + srv2.url + "#" + tok2}
	b := h2.boot()
	if err := os.MkdirAll(filepath.Join(h2.home, "data", "run", "join"), 0o700); err != nil {
		t.Fatal(err)
	}
	pending, _, err := b.pendingKey(filepath.Join(h2.home, "data", "run", "join"), tokenHash("other"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(srv2.keys); n != 2 || srv2.keys[1].Equal(srv2.keys[0]) || srv2.keys[1].Equal(&pending.PublicKey) {
		t.Errorf("a new token sent an old key (%d keys)", n)
	}
}

func TestJoinChecksTheAnswer(t *testing.T) {
	otherCA, _, err := pki.NewCA("Other CA")
	if err != nil {
		t.Fatal(err)
	}
	otherCert, _, err := otherCA.IssueServer("x", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*panelv1.JoinResponse){
		"bad node id":   func(r *panelv1.JoinResponse) { r.NodeId = "node-1" },
		"lower node id": func(r *panelv1.JoinResponse) { r.NodeId = strings.ToLower(r.NodeId) },
		"port 0":        func(r *panelv1.JoinResponse) { r.MgmtPort = 0 },
		"port 65536":    func(r *panelv1.JoinResponse) { r.MgmtPort = 65536 },
		"ca not PEM":    func(r *panelv1.JoinResponse) { r.CaPem = []byte("nope") },
		"cert not PEM":  func(r *panelv1.JoinResponse) { r.CertPem = nil },
		"another key":   func(r *panelv1.JoinResponse) { r.CertPem = otherCert },
		"another CA":    func(r *panelv1.JoinResponse) { r.CaPem = otherCA.CertPEM },
	} {
		t.Run(name, func(t *testing.T) {
			h, srv, _ := joinHarness(t)
			srv.mutate = mutate
			err := h.boot().joinStep(t.Context())
			if err == nil || !strings.Contains(err.Error(), "the panel's answer") {
				t.Fatalf("joinStep = %v, want the answer refused", err)
			}
			if _, err := os.Stat(filepath.Join(h.home, "pki", "bundle.json")); !os.IsNotExist(err) {
				t.Error("pki/ was written from a bad answer")
			}
		})
	}
}

// installKeys gives the node a complete pki/ for node id.
func installKeys(t *testing.T, h *harness, id string) {
	t.Helper()
	ca, _, err := pki.NewCA("Internal CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer(strings.ToLower(id), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.boot().installPKI(&pki.Bundle{NodeID: id, MgmtPort: 61000, CAPEM: ca.CertPEM, CertPEM: cert, KeyPEM: key}); err != nil {
		t.Fatal(err)
	}
}

func TestJoinFailureWithKeysStartsWithThem(t *testing.T) {
	h, srv, _ := joinHarness(t)
	installKeys(t, h, "01K6Q8Z5N4X3W2V1T0S9R8Q7ZZ")
	before := readString(t, filepath.Join(h.home, "pki", "bundle.json"))
	srv.fail = func(int) error { return connect.NewError(connect.CodeUnauthenticated, errors.New("expired")) }
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatalf("joinStep = %v, want the old keys kept", err)
	}
	h.wantLog("the join failed; the node starts with the keys it has")
	if got := readString(t, filepath.Join(h.home, "pki", "bundle.json")); got != before {
		t.Error("pki/ changed")
	}

	// A malformed POSTERN_JOIN is a warning too while there are keys.
	h.opt.Env = []string{EnvJoin + "=http://panel.example.com#short"}
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatalf("joinStep with a bad POSTERN_JOIN and keys = %v", err)
	}
	// Without keys it is the end.
	if err := os.RemoveAll(filepath.Join(h.home, "pki")); err != nil {
		t.Fatal(err)
	}
	if err := h.boot().joinStep(t.Context()); err == nil || strings.Contains(err.Error(), "short") {
		t.Fatalf("joinStep with a bad POSTERN_JOIN and no keys = %v", err)
	}
}

func TestJoinWithANewTokenSwapsPKI(t *testing.T) {
	h, srv, _ := joinHarness(t)
	installKeys(t, h, "01K6Q8Z5N4X3W2V1T0S9R8Q7ZZ")
	oldJSON := readString(t, filepath.Join(h.home, "pki", "bundle.json"))
	mustMkdir(t, filepath.Join(h.home, "pki.old"))
	mustWrite(t, filepath.Join(h.home, "pki.old", "stale"), "x")
	mustMkdir(t, filepath.Join(h.home, "pki.new-1"))
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, filepath.Join(h.home, "pki.old", "bundle.json")); got != oldJSON {
		t.Errorf("pki.old/bundle.json = %q, want the old one", got)
	}
	if _, err := os.Stat(filepath.Join(h.home, "pki.old", "stale")); !os.IsNotExist(err) {
		t.Error("the older pki.old was not replaced")
	}
	if got := readString(t, filepath.Join(h.home, "pki", "bundle.json")); !strings.Contains(got, srv.nodeID) {
		t.Errorf("pki/bundle.json = %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(h.home, "pki.new-*")); len(left) != 0 {
		t.Errorf("left behind: %q", left)
	}
}

func TestJoinMovesTheStateOfAnotherNodeAside(t *testing.T) {
	h, srv, _ := joinHarness(t)
	now := time.Now()
	h.opt.Now = func() time.Time { return now }
	state := filepath.Join(h.home, "data", "state")
	mustWrite(t, filepath.Join(state, "node-id"), "01K6Q8Z5N4X3W2V1T0S9R8Q7ZZ\n")
	mustWrite(t, filepath.Join(state, "desired.json"), "{}")
	ts := strconv.FormatInt(now.Unix(), 10)
	mustMkdir(t, filepath.Join(h.home, "data", "state.bak-"+ts))
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(h.home, "data", "state.bak-"+ts+"-1")
	if got := readString(t, filepath.Join(bak, "desired.json")); got != "{}" {
		t.Errorf("the old state is not in %s", bak)
	}
	if got := readString(t, filepath.Join(state, "node-id")); got != srv.nodeID+"\n" {
		t.Errorf("node-id = %q", got)
	}
	if _, err := os.Stat(filepath.Join(state, "desired.json")); !os.IsNotExist(err) {
		t.Error("desired.json of the other node is still in data/state")
	}
	if st, _ := os.Stat(state); st.Mode().Perm() != 0o700 {
		t.Errorf("data/state mode %v", st.Mode().Perm())
	}
	h.wantLog("the state of node 01K6Q8Z5N4X3W2V1T0S9R8Q7ZZ is moved to data/state.bak-" + ts + "-1")
}

func TestJoinKeepsTheStateOfTheSameNode(t *testing.T) {
	h, srv, _ := joinHarness(t)
	state := filepath.Join(h.home, "data", "state")
	mustWrite(t, filepath.Join(state, "node-id"), srv.nodeID+"\n")
	mustWrite(t, filepath.Join(state, "desired.json"), "{}")
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, filepath.Join(state, "desired.json")); got != "{}" {
		t.Error("the state of the same node was moved")
	}
	if bak, _ := filepath.Glob(filepath.Join(h.home, "data", "state.bak-*")); len(bak) != 0 {
		t.Errorf("moved aside: %q", bak)
	}
}

func TestRetryable(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{connect.NewError(connect.CodeUnavailable, errors.New("x")), true},
		{connect.NewError(connect.CodeDeadlineExceeded, errors.New("x")), true},
		{connect.NewError(connect.CodeUnavailable, x509.UnknownAuthorityError{}), false},
		{connect.NewError(connect.CodeUnauthenticated, errors.New("x")), false},
		{connect.NewError(connect.CodeInternal, errors.New("x")), false},
	} {
		if got := retryable(c.err); got != c.want {
			t.Errorf("retryable(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestJoinDoesNotTrustAnUnknownCertificate(t *testing.T) {
	h, srv, _ := joinHarness(t)
	h.opt.RootCAs = x509.NewCertPool() // not the server's
	err := h.boot().joinStep(t.Context())
	if err == nil || srv.calls != 0 || len(h.sleeps) != 0 {
		t.Fatalf("joinStep = %v, %d sleeps; want a refusal at once", err, len(h.sleeps))
	}
}

func TestJoinChecksTheNamesOfTheCertificate(t *testing.T) {
	for name, names := range map[string]func(string) (string, []string){
		"another CN":    func(l string) (string, []string) { return "01k6q8z5n4x3w2v1t0s9r8q7zz", []string{l + ".internal"} },
		"upper-case CN": func(l string) (string, []string) { return strings.ToUpper(l), []string{l + ".internal"} },
		"another SAN":   func(l string) (string, []string) { return l, []string{"panel.example.com"} },
		"no SAN":        func(l string) (string, []string) { return l, nil },
		"an extra SAN":  func(l string) (string, []string) { return l, []string{l + ".internal", "x.internal"} },
	} {
		t.Run(name, func(t *testing.T) {
			h, srv, _ := joinHarness(t)
			srv.names = names
			err := h.boot().joinStep(t.Context())
			if err == nil || !strings.Contains(err.Error(), "the certificate names") {
				t.Fatalf("joinStep = %v, want the names refused", err)
			}
			if _, err := os.Stat(filepath.Join(h.home, "pki", "bundle.json")); !os.IsNotExist(err) {
				t.Error("pki/ was written")
			}
		})
	}
}

// With keys the node can start, the join is tried three times within a few
// seconds, so that a panel that is down does not hold back every start of the
// container for long.
func TestJoinWithKeysIsTriedThreeTimes(t *testing.T) {
	h, srv, _ := joinHarness(t)
	installKeys(t, h, "01K6Q8Z5N4X3W2V1T0S9R8Q7ZZ")
	srv.unavailable = 100
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatalf("joinStep = %v, want the old keys kept", err)
	}
	if srv.calls != 3 || !slices.Equal(h.sleeps, []time.Duration{2 * time.Second, 4 * time.Second}) {
		t.Errorf("calls = %d, sleeps = %v; want 3 calls and [2s 4s]", srv.calls, h.sleeps)
	}
	if rejoinTimeout != 10*time.Second {
		t.Errorf("rejoinTimeout = %v, want 10s", rejoinTimeout)
	}
	h.wantLog("the join failed; the node starts with the keys it has")
	// The key stays pending for the next start, with the same token.
	if _, err := os.Stat(filepath.Join(h.home, "data", "run", "join", "key.pem")); err != nil {
		t.Errorf("the pending key is gone: %v", err)
	}
}

// With keys, a re-join whose answer was lost (the panel pinned the new
// certificate already) is recovered by the next attempt with the same key.
func TestJoinWithKeysRecoversALostAnswer(t *testing.T) {
	h, srv, _ := joinHarness(t)
	installKeys(t, h, "01K6Q8Z5N4X3W2V1T0S9R8Q7ZZ")
	srv.lose = 1
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if srv.calls != 2 || !slices.Equal(h.sleeps, []time.Duration{2 * time.Second}) {
		t.Errorf("calls = %d, sleeps = %v; want 2 and [2s]", srv.calls, h.sleeps)
	}
	if len(srv.keys) != 2 || !srv.keys[0].Equal(srv.keys[1]) {
		t.Error("the second attempt used another key")
	}
	if got := readString(t, filepath.Join(h.home, "pki", "bundle.json")); !strings.Contains(got, srv.nodeID) {
		t.Errorf("pki/bundle.json = %q, want the new node", got)
	}
}

// A pending key of a token that the keys were made with already is stale.
func TestJoinSkippedRemovesAStalePendingKey(t *testing.T) {
	h, srv, token := joinHarness(t)
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	runJoin := filepath.Join(h.home, "data", "run", "join")
	if _, _, err := h.boot().pendingKey(runJoin, tokenHash(token)); err != nil {
		t.Fatal(err)
	}
	srv.calls = 0
	if err := h.boot().joinStep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if srv.calls != 0 {
		t.Errorf("join calls = %d, want the join skipped", srv.calls)
	}
	if _, err := os.Stat(runJoin); !os.IsNotExist(err) {
		t.Errorf("data/run/join is still there: %v", err)
	}
}
