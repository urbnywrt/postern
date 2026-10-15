package probes

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

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// api is the ProbeService behind the auth middleware, with an admin signed in.
type api struct {
	svc   *Service
	admin panelv1connect.ProbeServiceClient
	anon  panelv1connect.ProbeServiceClient
}

func newAPI(t *testing.T, e *env, s *Scheduler) *api {
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
		t.Fatalf("CreateAdmin: %v", err)
	}
	svc := NewService(e.db, s, e.log)
	svc.now = e.clock.Now
	authSvc := auth.NewService(e.db, e.key, e.log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewProbeServiceHandler(svc))
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
		svc:   svc,
		admin: panelv1connect.NewProbeServiceClient(web, srv.URL),
		anon:  panelv1connect.NewProbeServiceClient(&http.Client{Timeout: 10 * time.Second}, srv.URL),
	}
}

func codeOf(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return 0
}

// audits returns the audit entries as "action target".
func audits(t *testing.T, e *env) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT action, target FROM audit_log WHERE action NOT LIKE 'auth.%' ORDER BY ts, rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a, tg string
		if err := rows.Scan(&a, &tg); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+" "+tg)
	}
	return out
}

func TestProbeNow(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	l := e.listener(n.ID, 443)
	p := e.proxy(l, "www.example.com", secretA, nil)
	web := e.proxy(l, "web.example.com", secretB, func(p *store.Proxy) {
		p.Type, p.WebSecretMode, p.CertMode = store.ProxyTypeWeb, "plain", "external"
	})
	rec := newRecorder(e.clock, true)
	a := newAPI(t, e, e.scheduler(rec.probe))
	call := func(id string) (*connect.Response[panelv1.ProbeNowResponse], error) {
		return a.admin.ProbeNow(e.ctx, connect.NewRequest(&panelv1.ProbeNowRequest{ProxyId: id}))
	}

	res, err := call(p.ID)
	if err != nil {
		t.Fatalf("ProbeNow: %v", err)
	}
	if m := res.Msg; m.GetKind() != KindL2 || !m.GetOk() || !m.GetL1Ok() || m.GetLatencyMs() != 42 || m.GetError() != "" {
		t.Errorf("ProbeNow = %v", m)
	}
	if _, err := call(p.ID); codeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("a second call at once: %v, want resource_exhausted", err)
	}
	e.clock.Add(4999 * time.Millisecond)
	if _, err := call(p.ID); codeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("a call 4.999 s later: %v, want resource_exhausted", err)
	}
	e.clock.Add(time.Millisecond)
	if _, err := call(p.ID); err != nil {
		t.Errorf("a call 5 s later: %v", err)
	}
	if got := rec.count(p.ID); got != 2 {
		t.Errorf("%d probes, want 2", got)
	}
	if want := fmt.Sprint([]string{"probe.run proxy:" + p.ID, "probe.run proxy:" + p.ID}); fmt.Sprint(audits(t, e)) != want {
		t.Errorf("audit %v, want %v", audits(t, e), want)
	}

	// A WEB proxy is probed at its URL, without its secret, as kind web.
	if res, err := call(web.ID); err != nil || res.Msg.GetKind() != KindWeb || !res.Msg.GetOk() {
		t.Errorf("a WEB proxy: %v, %v", res, err)
	}
	for _, c := range rec.calls {
		if c.ProxyID == web.ID && (c.Addr != "https://web.example.com/" || len(c.Secret) != 0) {
			t.Errorf("the WEB proxy was probed at %q with a secret of %d bytes", c.Addr, len(c.Secret))
		}
	}
	paused := e.proxy(l, "paused.example.com", secretB, func(p *store.Proxy) { p.Enabled = false })
	offNode := e.node("off.example.com", false)
	offline := e.proxy(e.listener(offNode.ID, 443), "www.example.com", secretB, nil)
	for name, id := range map[string]string{"a paused proxy": paused.ID, "a proxy of an offline node": offline.ID} {
		for range 2 { // the slot is given back: the second call is not rate limited
			if _, err := call(id); codeOf(err) != connect.CodeFailedPrecondition {
				t.Errorf("%s: %v, want failed_precondition", name, err)
			}
		}
		if got := rec.count(id); got != 0 {
			t.Errorf("%s: probed %d times", name, got)
		}
		if ps, err := e.db.Probes(e.ctx, id, "", time.Unix(0, 0), e.clock.Now().Add(time.Hour)); err != nil || len(ps) != 0 {
			t.Errorf("%s: stored %v, %v", name, ps, err)
		}
	}
	if _, err := call("nope"); codeOf(err) != connect.CodeNotFound {
		t.Errorf("no proxy: %v, want not_found", err)
	}
	if _, err := call(""); codeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("no id: %v, want invalid_argument", err)
	}
	if _, err := a.anon.ProbeNow(e.ctx, connect.NewRequest(&panelv1.ProbeNowRequest{ProxyId: p.ID})); codeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("without a session: %v, want unauthenticated", err)
	}
}

func TestUptimes(t *testing.T) {
	ps := []store.Probe{
		{Vantage: "panel", OK: true}, {Vantage: "node", OK: false}, {Vantage: "panel", OK: false},
		{Vantage: "panel", OK: true}, {Vantage: "panel", OK: true}, {Vantage: "node", OK: true},
		{Vantage: "node", OK: true}, {Vantage: "node", OK: true},
	}
	got := uptimes(ps)
	if len(got) != 2 {
		t.Fatalf("uptimes = %v", got)
	}
	if u := got[0]; u.GetVantage() != "node" || u.GetOk() != 3 || u.GetTotal() != 4 || u.GetUptime() != 0.75 {
		t.Errorf("node: %v, want 3 of 4", u)
	}
	if u := got[1]; u.GetVantage() != "panel" || u.GetOk() != 3 || u.GetTotal() != 4 || u.GetUptime() != 0.75 {
		t.Errorf("panel: %v, want 3 of 4", u)
	}
	if len(uptimes(nil)) != 0 {
		t.Error("uptimes of nothing is not empty")
	}
}

func TestProbeHistory(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	now := e.clock.Now()
	for _, pr := range []store.Probe{
		{TS: now.Add(-25 * time.Hour), Vantage: "panel", OK: false},
		{TS: now.Add(-23 * time.Hour), Vantage: "panel", OK: true, LatencyMS: 80},
		{TS: now.Add(-2 * time.Hour), Vantage: "node", OK: false, Error: ErrUnreachable},
		{TS: now, Vantage: "panel", OK: false, Error: ErrRefusedSecret},
		{TS: now.Add(-time.Hour), Vantage: "panel", OK: false, Error: ErrNoDatacenterL1},
	} {
		pr.ProxyID, pr.Kind = p.ID, KindL2
		if err := e.db.InsertProbe(e.ctx, pr); err != nil {
			t.Fatal(err)
		}
	}
	a := newAPI(t, e, e.scheduler(newRecorder(e.clock, true).probe))
	get := func(r string) (*panelv1.ProbeHistoryResponse, error) {
		res, err := a.admin.ProbeHistory(e.ctx, connect.NewRequest(&panelv1.ProbeHistoryRequest{ProxyId: p.ID, Range: r}))
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}
	day, err := get("24h")
	if err != nil {
		t.Fatal(err)
	}
	pts := day.GetPoints()
	if len(pts) != 4 || pts[0].GetLatencyMs() != 80 || pts[3].GetError() != ErrRefusedSecret || pts[3].GetTs() != now.Unix() {
		t.Errorf("24h points %v", pts)
	}
	// l1_ok: a probe that passed, and one that reached the proxy but no
	// datacenter; not one refused or unreachable.
	var l1 []bool
	for _, pt := range pts {
		l1 = append(l1, pt.GetL1Ok())
	}
	if want := []bool{true, false, true, false}; !slices.Equal(l1, want) {
		t.Errorf("l1_ok %v, want %v (points %v)", l1, want, pts)
	}
	if u := day.GetUptimes(); len(u) != 2 || u[0].GetVantage() != "node" || u[0].GetUptime() != 0 || u[1].GetUptime() != 1.0/3 {
		t.Errorf("24h uptimes %v", u)
	}
	week, err := get("7d")
	if err != nil {
		t.Fatal(err)
	}
	if len(week.GetPoints()) != 5 || week.GetUptimes()[1].GetTotal() != 4 {
		t.Errorf("7d: %v", week)
	}
	if _, err := get("30d"); codeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("range 30d: %v, want invalid_argument", err)
	}
}

func TestReleaseGivesBackOnlyItsOwnSlot(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	s := NewService(nil, nil, nil)
	s.now = c.Now
	at, ok := s.take("p")
	if !ok {
		t.Fatal("the first take failed")
	}
	s.release("p", at) // an audit write failed
	if _, ok := s.take("p"); !ok {
		t.Fatal("the slot was not given back")
	}
	if _, ok := s.take("p"); ok {
		t.Fatal("a second take at once succeeded")
	}
	c.Add(6 * time.Second)
	newer, _ := s.take("p")
	s.release("p", at) // a stale release
	if _, ok := s.take("p"); ok {
		t.Fatalf("a stale release gave back the slot taken at %v", newer)
	}
}
