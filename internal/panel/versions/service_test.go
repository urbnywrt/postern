package versions

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"

	// procedureCount is how many procedures VersionService has, so that the
	// tests that go over them all are known not to be empty.
	procedureCount = 18
)

// cheapHash is an argon2id hash with the smallest parameters, for a test that
// signs in.
func cheapHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// api is the version service as the panel serves it, behind the auth
// middleware unless the test says otherwise, with an admin who has signed in
// and a client without a session. Next to the service it serves /probe, a
// handler that uses the shared helpers: it answers the name of the admin of the
// request, and audits the call.
type api struct {
	t       *testing.T
	srv     *httptest.Server
	web     *http.Client // has the session cookie
	anon    *http.Client
	dbPath  string
	adminID string
	db      *store.DB
	catalog *releases.Catalog
	host    *fakeHost // the release feeds and downloads
	svc     *Service
}

func newAPI(t *testing.T, middleware bool) *api {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var key seal.Key
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := db.CreateAdmin(ctx, admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	authSvc := auth.NewService(db, key, log)
	svc := New(db, log)
	host := newFakeHost(t)
	catalog := releases.New(releases.Config{DB: db, Key: key, Dir: t.TempDir(), HTTP: host.srv.Client(), APIBase: host.url("/api"), Log: log})
	if err := catalog.Seed(ctx); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	svc.SetCatalog(catalog)
	svc.SetReleases(&selfupdate.Releases{DB: db, Key: key, HTTP: host.srv.Client(), APIBase: host.url("/api"), Log: log})
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(svc.Handler(connect.WithReadMaxBytes(1 << 20)))
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		who, err := requireAdmin(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		svc.audit(r.Context(), "versions.probe", "probe:1", map[string]string{"k": "v"})
		_, _ = io.WriteString(w, who.Username)
	})
	var h http.Handler = mux
	if middleware {
		h = authSvc.Middleware(mux)
	}
	a := &api{t: t, srv: httptest.NewServer(h), anon: &http.Client{}, dbPath: dbPath, adminID: admin.ID,
		db: db, catalog: catalog, host: host, svc: svc}
	t.Cleanup(a.srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	a.web = &http.Client{Jar: jar}
	login := panelv1connect.NewAuthServiceClient(a.web, a.srv.URL)
	if _, err := login.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return a
}

// post calls a procedure with an empty message and returns the status and the
// Connect error code of the answer, "" for none.
func (a *api) post(client *http.Client, procedure string) (status int, code string) {
	a.t.Helper()
	resp, err := client.Post(a.srv.URL+procedure, "application/json", strings.NewReader(`{}`))
	if err != nil {
		a.t.Fatalf("POST %s: %v", procedure, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, ""
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		a.t.Fatalf("POST %s: status %d, body %q is not a Connect error: %v", procedure, resp.StatusCode, body, err)
	}
	return resp.StatusCode, e.Code
}

// procedures lists every procedure of VersionService, as the proto defines it.
func procedures(t *testing.T) []string {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName("postern.panel.v1.VersionService")
	if err != nil {
		t.Fatalf("VersionService is not registered: %v", err)
	}
	svc, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		t.Fatalf("VersionService is a %T", d)
	}
	var list []string
	for i := range svc.Methods().Len() {
		list = append(list, "/"+string(svc.FullName())+"/"+string(svc.Methods().Get(i).Name()))
	}
	if len(list) != procedureCount {
		t.Fatalf("VersionService has %d procedures, the test expects %d: %v", len(list), procedureCount, list)
	}
	return list
}

// implemented are the procedures that have been added; the rest answer that
// they are not implemented yet.
var implemented = map[string]bool{
	"ListComponents": true, "ListReleases": true, "RefreshReleases": true, "PrepareRelease": true, "RecheckRelease": true,
	"GetReleaseSource": true, "SetReleaseSource": true, "GetPanelVersion": true, "UpdatePanel": true,
}

// Every procedure needs a session, and with one answers, or says that it is
// not implemented yet: the handler is mounted, and reached only by an admin.
func TestEveryProcedureNeedsASessionAndIsUnimplemented(t *testing.T) {
	a := newAPI(t, true)
	for _, proc := range procedures(t) {
		if status, code := a.post(a.anon, proc); status != http.StatusUnauthorized || code != "unauthenticated" {
			t.Errorf("%s without a session: %d %q, want 401 unauthenticated", proc, status, code)
		}
		status, code := a.post(a.web, proc)
		if implemented[proc[strings.LastIndex(proc, "/")+1:]] {
			if status == http.StatusUnauthorized || status == http.StatusNotImplemented {
				t.Errorf("%s with a session: %d %q, want an answer of the procedure", proc, status, code)
			}
			continue
		}
		if status != http.StatusNotImplemented || code != "unimplemented" {
			t.Errorf("%s with a session: %d %q, want 501 unimplemented", proc, status, code)
		}
	}
}

// Mounted without the middleware, nothing finds an admin for a request, and the
// handler refuses every call itself: the service is safe however it is mounted.
func TestHandlerRefusesWithoutTheMiddleware(t *testing.T) {
	a := newAPI(t, false)
	for _, proc := range procedures(t) {
		if status, code := a.post(a.web, proc); status != http.StatusUnauthorized || code != "unauthenticated" {
			t.Errorf("%s with a cookie and no middleware: %d %q, want 401 unauthenticated", proc, status, code)
		}
	}
}

func TestNewWithoutLog(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s := New(db, nil)
	if s.log == nil || s.db != db {
		t.Errorf("New(db, nil) = %+v, want the database and a log that discards", s)
	}
	var _ panelv1connect.VersionServiceHandler = s
}

// auditLog returns the audit log of the panel as "admin action target details"
// lines, oldest first, read from the database file.
func (a *api) auditLog() []string {
	a.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(a.dbPath)+"?mode=ro")
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT admin_id, action, target, details FROM audit_log WHERE action NOT LIKE 'auth.%' ORDER BY ts, id`) // not the sign-in of the test
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var admin, action, target, details string
		if err := rows.Scan(&admin, &action, &target, &details); err != nil {
			a.t.Fatal(err)
		}
		out = append(out, admin+" "+action+" "+target+" "+details)
	}
	if err := rows.Err(); err != nil {
		a.t.Fatal(err)
	}
	return out
}

// The helpers that the procedures of later changes share: requireAdmin finds
// the admin that the middleware put into the context, or refuses the call, and
// audit records what the admin did.
func TestRequireAdminAndAudit(t *testing.T) {
	if _, err := requireAdmin(context.Background()); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("requireAdmin without an admin: err = %v, want unauthenticated", err)
	}
	a := newAPI(t, true)
	resp, err := a.anon.Get(a.srv.URL + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("probe without a session: status %d, want 401", resp.StatusCode)
	}
	resp, err = a.web.Get(a.srv.URL + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != adminUser {
		t.Errorf("probe with a session: %d %q, want 200 %q", resp.StatusCode, body, adminUser)
	}
	if got, want := a.auditLog(), []string{a.adminID + ` versions.probe probe:1 {"k":"v"}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("audit log = %q, want %q", got, want)
	}
}

// What no admin did is audited without one, and without details.
func TestAuditWithoutAdmin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	New(db, nil).audit(context.Background(), "versions.stable_list", "component:telemt", nil)
	a := &api{t: t, dbPath: path}
	if got, want := a.auditLog(), []string{" versions.stable_list component:telemt {}"}; !reflect.DeepEqual(got, want) {
		t.Errorf("audit log = %q, want %q", got, want)
	}
}

// Ruling S5-11: a change of channel is never refused for want of a
// confirmation. Both responses carry the affected proxies and whether the
// change was made.
func TestChannelChangeResponsesCarryApplied(t *testing.T) {
	for _, m := range []proto.Message{&panelv1.SetDefaultChannelResponse{}, &panelv1.SetNodeChannelResponse{}} {
		fields := m.ProtoReflect().Descriptor().Fields()
		name := m.ProtoReflect().Descriptor().Name()
		list := fields.ByName("affected_proxies")
		if list == nil || list.Number() != 1 || !list.IsList() || list.Message() == nil || list.Message().Name() != "AffectedProxy" {
			t.Errorf("%s: affected_proxies = %v, want field 1, a list of AffectedProxy", name, list)
		}
		applied := fields.ByName("applied")
		if applied == nil || applied.Number() != 2 || applied.Kind() != protoreflect.BoolKind {
			t.Errorf("%s: applied = %v, want field 2, a bool", name, applied)
		}
	}
}
