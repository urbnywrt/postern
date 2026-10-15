package diagnostics

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

type api struct {
	admin, anon panelv1connect.DiagnosticsServiceClient
}

func newAPI(t *testing.T, e *env, r *Runner) *api {
	t.Helper()
	return newAPIFor(t, e, NewService(e.db, r, nil))
}

// newAPIFor serves svc behind a login as the admin "admin".
func newAPIFor(t *testing.T, e *env, svc *Service) *api {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	const password = "correct horse battery staple"
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	enc := base64.RawStdEncoding
	hash := fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version, enc.EncodeToString(salt), enc.EncodeToString(key))
	if err := e.db.CreateAdmin(e.ctx, &store.Admin{Username: "admin", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	var mk seal.Key
	if _, err := rand.Read(mk[:]); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(e.db, mk, nil)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewDiagnosticsServiceHandler(svc))
	srv := httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if _, err := panelv1connect.NewAuthServiceClient(web, srv.URL).Login(e.ctx, connect.NewRequest(&panelv1.LoginRequest{Username: "admin", Password: password})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return &api{
		admin: panelv1connect.NewDiagnosticsServiceClient(web, srv.URL),
		anon:  panelv1connect.NewDiagnosticsServiceClient(&http.Client{Timeout: 10 * time.Second}, srv.URL),
	}
}

func codeOf(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return 0
}

func auditCount(t *testing.T, e *env, action string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestService(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	l := e.listener(n.ID, 443, "")
	p := e.proxy(l, nil)
	f := &fakeNode{results: []*nodev1.DiagnosticResult{
		{Id: "engine.container", Layer: "engine", Target: "proxy:" + p.ID, Status: fail, Fix: "recreate_instance", Evidence: "exited"},
		{Id: "egress.member", Layer: "egress", Target: "member:C/s/a", Status: warn, Fix: "refresh_subscription"},
	}, hold: make(chan struct{}), started: make(chan struct{}, 1)}
	e.agent(n.ID, f)
	r := e.runner(0)
	a := newAPI(t, e, r)

	if _, err := a.anon.StartRun(e.ctx, connect.NewRequest(&panelv1.StartRunRequest{NodeId: n.ID})); codeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous: %v", err)
	}
	for req, code := range map[*panelv1.StartRunRequest]connect.Code{
		{}:                                 connect.CodeInvalidArgument,
		{NodeId: n.ID, Scope: "proxy:"}:    connect.CodeInvalidArgument,
		{NodeId: n.ID, Scope: "listener:"}: connect.CodeInvalidArgument,
		{NodeId: "nope"}:                   connect.CodeNotFound,
	} {
		if _, err := a.admin.StartRun(e.ctx, connect.NewRequest(req)); codeOf(err) != code {
			t.Errorf("StartRun(%v): %v, want %v", req, err, code)
		}
	}
	first, err := a.admin.StartRun(e.ctx, connect.NewRequest(&panelv1.StartRunRequest{NodeId: n.ID}))
	if err != nil {
		t.Fatal(err)
	}
	<-f.started
	again, err := a.admin.StartRun(e.ctx, connect.NewRequest(&panelv1.StartRunRequest{NodeId: n.ID, Scope: "proxy:" + p.ID}))
	if err != nil || again.Msg.GetRunId() != first.Msg.GetRunId() {
		t.Fatalf("a run in progress: %v %v", again, err)
	}
	if got := auditCount(t, e, "diagnostics.run"); got != 1 {
		t.Fatalf("audits %d", got)
	}
	running, err := a.admin.GetRun(e.ctx, connect.NewRequest(&panelv1.GetRunRequest{RunId: first.Msg.GetRunId()}))
	if err != nil || running.Msg.GetState() != "running" || running.Msg.GetFinishedUnix() != 0 {
		t.Fatalf("running: %v %v", running, err)
	}
	close(f.hold)
	e.wait(r, first.Msg.GetRunId())
	got, err := a.admin.GetRun(e.ctx, connect.NewRequest(&panelv1.GetRunRequest{RunId: first.Msg.GetRunId()}))
	if err != nil {
		t.Fatal(err)
	}
	m := got.Msg
	if m.GetState() != "done" || m.GetReason() != "manual" || m.GetScope() != "node" || m.GetNodeId() != n.ID || m.GetFinishedUnix() == 0 {
		t.Fatalf("run %v", m)
	}
	res := m.GetResults()
	last2 := res[len(res)-2:]
	if !last2[0].GetFixAvailable() || last2[0].GetVantage() != "node" || last2[0].GetEvidence() != "exited" ||
		last2[1].GetFixAvailable() || last2[1].GetFixUnavailableReason() == "" {
		t.Fatalf("fixes: %v", last2)
	}
	if _, err := a.admin.GetRun(e.ctx, connect.NewRequest(&panelv1.GetRunRequest{RunId: "nope"})); codeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown run: %v", err)
	}

	// ListRuns of the node and of the proxy.
	if _, err := r.CopyLight(e.ctx, n.ID, "proxy:"+p.ID, "x"); err != nil {
		t.Fatal(err)
	}
	other := e.proxy(l, nil)
	if _, err := r.CopyLight(e.ctx, n.ID, "proxy:"+other.ID, "y"); err != nil {
		t.Fatal(err)
	}
	list := func(req *panelv1.ListRunsRequest) []*panelv1.DiagnosticRun {
		t.Helper()
		out, err := a.admin.ListRuns(e.ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatal(err)
		}
		return out.Msg.GetRuns()
	}
	runs := list(&panelv1.ListRunsRequest{NodeId: n.ID})
	if len(runs) != 3 || len(runs[0].GetResults()) != 0 {
		t.Fatalf("node runs %v", runs)
	}
	// The counts of each run in the list are those of its results.
	for _, run := range runs {
		full, err := a.admin.GetRun(e.ctx, connect.NewRequest(&panelv1.GetRunRequest{RunId: run.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		c := map[string]uint32{}
		for _, x := range full.Msg.GetResults() {
			c[x.GetStatus()]++
		}
		got := []uint32{run.GetOkCount(), run.GetWarnCount(), run.GetFailCount(), run.GetSkipCount()}
		if want := []uint32{c["ok"], c["warn"], c["fail"], c["skip"]}; !slices.Equal(got, want) {
			t.Errorf("run %s counts %v, want %v", run.GetId(), got, want)
		}
	}
	if m.GetFailCount() == 0 || m.GetWarnCount() == 0 {
		t.Errorf("the first run counts no fail or warn: %v", m)
	}
	if runs := list(&panelv1.ListRunsRequest{ProxyId: p.ID}); len(runs) != 2 {
		t.Fatalf("proxy runs %v", runs)
	}
	if runs := list(&panelv1.ListRunsRequest{NodeId: n.ID, Limit: 1}); len(runs) != 1 {
		t.Fatalf("limit: %v", runs)
	}
	for req, code := range map[*panelv1.ListRunsRequest]connect.Code{
		{}:                            connect.CodeInvalidArgument,
		{NodeId: n.ID, Limit: 51}:     connect.CodeInvalidArgument,
		{NodeId: n.ID, ProxyId: p.ID}: connect.CodeInvalidArgument,
		{ProxyId: "nope"}:             connect.CodeNotFound,
		{NodeId: "nope"}:              connect.CodeNotFound,
	} {
		if _, err := a.admin.ListRuns(e.ctx, connect.NewRequest(req)); codeOf(err) != code {
			t.Errorf("ListRuns(%v): %v, want %v", req, err, code)
		}
	}

	// LatestChecks.
	since := time.Unix(1_790_000_000, 0)
	if _, err := e.db.ReplaceNodeChecks(e.ctx, n.ID, []store.NodeCheck{
		{CheckID: "host.dns", Layer: "host", Status: "fail", Fix: "set_dns_mode_doh"},
		{CheckID: "e2e.l1", Layer: "e2e", Target: "proxy:" + other.ID, Status: "ok"},
		{CheckID: "engine.ready", Layer: "engine", Target: "proxy:" + p.ID, Status: "fail", Fix: "recreate_instance"},
	}, since); err != nil {
		t.Fatal(err)
	}
	lc, err := a.admin.LatestChecks(e.ctx, connect.NewRequest(&panelv1.LatestChecksRequest{NodeId: n.ID}))
	if err != nil || len(lc.Msg.GetResults()) != 3 {
		t.Fatalf("node checks %v %v", lc, err)
	}
	for _, x := range lc.Msg.GetResults() {
		if x.GetSinceUnix() != since.Unix() {
			t.Fatalf("since %v", x)
		}
		if x.GetId() == "host.dns" && (x.GetFixAvailable() || x.GetFixUnavailableReason() == "") {
			t.Fatalf("set_dns_mode_doh without dns-forwarder: %v", x)
		}
	}
	lc, err = a.admin.LatestChecks(e.ctx, connect.NewRequest(&panelv1.LatestChecksRequest{ProxyId: p.ID}))
	if err != nil || len(lc.Msg.GetResults()) != 2 || lc.Msg.GetResults()[0].GetId() != "engine.ready" || !lc.Msg.GetResults()[0].GetFixAvailable() {
		t.Fatalf("proxy checks %v %v", lc, err)
	}

	// The procedures of Tasks 10b and 10c are not built yet.
	if _, err := a.admin.ApplyFix(e.ctx, connect.NewRequest(&panelv1.ApplyFixRequest{})); codeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("ApplyFix: %v", err)
	}
}

// A run read with its results counts them, also while it is running (its
// stored counts are written when it ends); one listed without them keeps its
// stored counts.
func TestRunProtoCounts(t *testing.T) {
	running := &store.DiagnosticRun{ID: "r", State: store.RunRunning, OK: 9,
		Results: []store.DiagnosticResult{{Status: StatusOK}, {Status: StatusFail}, {Status: StatusFail}, {Status: StatusSkip}}}
	got := runProto(running, nil)
	if c := []uint32{got.GetOkCount(), got.GetWarnCount(), got.GetFailCount(), got.GetSkipCount()}; !slices.Equal(c, []uint32{1, 0, 2, 1}) {
		t.Errorf("running run counts %v", c)
	}
	listed := runProto(&store.DiagnosticRun{ID: "l", State: store.RunDone, OK: 3, Warn: 2, Fail: 1, Skip: 4}, nil)
	if c := []uint32{listed.GetOkCount(), listed.GetWarnCount(), listed.GetFailCount(), listed.GetSkipCount()}; !slices.Equal(c, []uint32{3, 2, 1, 4}) {
		t.Errorf("listed run counts %v", c)
	}
}
