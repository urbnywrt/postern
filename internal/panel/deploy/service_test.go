package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/jobs"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/sshx"
	"github.com/urbnywrt/postern/internal/panel/sshx/sshxtest"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"
	// sshPassword is the password of the test SSH servers. It must never show
	// in a log, an error or the database.
	sshPassword = "ssh-password-of-the-test" // gitleaks:allow (a made-up test value)
	waitTimeout = 20 * time.Second
)

// onlineNotifier is the connection manager of the tests: when the service
// asks it to look at a node after an install, it marks the node online, as
// the manager does once the agent answers, unless the test says the node does
// not come up.
type onlineNotifier struct {
	db *store.DB

	mu       sync.Mutex
	down     bool
	notified []string
}

func (n *onlineNotifier) Notify(nodeID string) {
	n.mu.Lock()
	n.notified = append(n.notified, nodeID)
	down := n.down
	n.mu.Unlock()
	if down {
		return
	}
	now := time.Now()
	_, _ = n.db.ModifyNode(context.Background(), nodeID, func(node *store.Node) error {
		node.Status = store.NodeStatusOnline
		node.LastSeenAt = &now
		node.AgentVersion = "0.1.0-test"
		return nil
	})
}

func (n *onlineNotifier) setDown(down bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.down = down
}

// env is a panel with the node service, the deploy service and the job
// runner, behind the auth middleware, with an admin who has signed in, a node,
// and the SSH server of the node.
type env struct {
	t        *testing.T
	db       *store.DB
	dbPath   string
	key      seal.Key
	svc      *Service
	runner   *jobs.Runner
	notifier *onlineNotifier
	logs     *lockedBuffer
	deploy   panelv1connect.DeployServiceClient
	node     *panelv1.Node
	host     *fakeHost
	ssh      *sshxtest.Server
}

type envOptions struct {
	server string   // the fake server of the preflight; ubuntu-24.04 by default
	arches []string // the node kits of the panel; amd64 and arm64 by default
	mgmt   uint32   // the management port of the node; 61001 by default
	image  string   // the node image of the panel; none by default
	sshCfg func(*sshxtest.Config)
}

func newEnv(t *testing.T, o envOptions) *env {
	t.Helper()
	if o.server == "" {
		o.server = "ubuntu-24.04"
	}
	if o.arches == nil {
		o.arches = []string{"amd64", "arm64"}
	}
	if o.mgmt == 0 {
		o.mgmt = 61001
	}
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := &env{t: t, db: db, dbPath: dbPath, logs: &lockedBuffer{}}
	if _, err := rand.Read(e.key[:]); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("panel log:\n%s", e.logs.String())
		}
	})
	ca, err := nodes.LoadOrCreateCA(ctx, db, e.key)
	if err != nil {
		t.Fatal(err)
	}
	nodeSvc := nodes.NewService(db, e.key, ca, nil, log, nodes.WithKitDir(writeKit(t, o.arches...)), nodes.WithNodeImage(o.image))
	if e.runner, err = jobs.New(ctx, db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()
		_ = e.runner.Close(closeCtx)
	})
	e.notifier = &onlineNotifier{db: db}
	e.svc = NewService(Config{DB: db, Key: e.key, Nodes: nodeSvc, Notifier: e.notifier, Jobs: e.runner, Log: log})
	e.svc.onlineTimeout = 3 * time.Second
	e.svc.onlinePoll = 10 * time.Millisecond

	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := db.CreateAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(db, e.key, log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewNodeServiceHandler(nodeSvc))
	mux.Handle(panelv1connect.NewDeployServiceHandler(e.svc))
	srv := httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Client{Jar: jar, Timeout: time.Minute}
	login := panelv1connect.NewAuthServiceClient(web, srv.URL)
	if _, err := login.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	e.deploy = panelv1connect.NewDeployServiceClient(web, srv.URL)
	created, err := panelv1connect.NewNodeServiceClient(web, srv.URL).CreateNode(ctx,
		connect.NewRequest(&panelv1.CreateNodeRequest{Name: "Frankfurt", MgmtHost: "203.0.113.10", MgmtPort: o.mgmt}))
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	e.node = created.Msg.GetNode()

	e.host = newFakeHost(t, o.server)
	cfg := sshxtest.Config{Password: sshPassword, Handler: e.host.handle}
	if o.sshCfg != nil {
		o.sshCfg(&cfg)
	}
	e.ssh = sshxtest.Start(t, cfg)
	return e
}

// target is the SSH server of the env, for user, without a host key.
func (e *env) target(user string) *panelv1.SshTarget {
	return &panelv1.SshTarget{Host: e.ssh.Host, Port: uint32(e.ssh.Port), User: user}
}

// confirmed is target with the host key of the server.
func (e *env) confirmed(user string) *panelv1.SshTarget {
	t := e.target(user)
	t.HostKey, t.HostKeyType = e.ssh.Fingerprint(), e.ssh.HostKey().Type()
	return t
}

func password() *panelv1.SshCredentials {
	return &panelv1.SshCredentials{Password: sshPassword}
}

func (e *env) preflight(req *panelv1.PreflightRequest) (*panelv1.PreflightResponse, error) {
	if req.NodeId == "" {
		req.NodeId = e.node.GetId()
	}
	resp, err := e.deploy.Preflight(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (e *env) report(req *panelv1.PreflightRequest) *panelv1.PreflightReport {
	e.t.Helper()
	resp, err := e.preflight(req)
	if err != nil {
		e.t.Fatalf("Preflight: %v", err)
	}
	if resp.GetReport() == nil {
		e.t.Fatalf("Preflight = %v, want a report", resp)
	}
	return resp.GetReport()
}

func (e *env) install(req *panelv1.InstallRequest) (string, error) {
	if req.NodeId == "" {
		req.NodeId = e.node.GetId()
	}
	resp, err := e.deploy.Install(context.Background(), connect.NewRequest(req))
	if err != nil {
		return "", err
	}
	return resp.Msg.GetJobId(), nil
}

// job waits until the job has ended and returns it.
func (e *env) job(id string) *panelv1.Job {
	e.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		resp, err := e.deploy.GetJob(context.Background(), connect.NewRequest(&panelv1.GetJobRequest{Id: id}))
		if err != nil {
			e.t.Fatalf("GetJob: %v", err)
		}
		if j := resp.Msg.GetJob(); j.GetStatus() != jobs.StatusRunning {
			return j
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("the job %s is still running:\n%s", id, resp.Msg.GetJob().GetLog())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// installed runs an install and returns the job once it has ended.
func (e *env) installed(req *panelv1.InstallRequest) *panelv1.Job {
	e.t.Helper()
	id, err := e.install(req)
	if err != nil {
		e.t.Fatalf("Install: %v", err)
	}
	return e.job(id)
}

// audit returns the audit log as "action target" lines, oldest first.
func (e *env) audit() []string {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT action, target FROM audit_log ORDER BY ts, rowid`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var action, target string
		if err := rows.Scan(&action, &target); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, action+" "+target)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func wantCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", want)
	}
	if got := connect.CodeOf(err); got != want {
		t.Fatalf("error = %v (code %v), want code %v", err, got, want)
	}
}

func issueCodes(r *panelv1.PreflightReport) []string {
	var out []string
	for _, is := range r.GetIssues() {
		out = append(out, is.GetCode()+"/"+is.GetSeverity())
	}
	return out
}

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

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// ---- host keys ---------------------------------------------------------------

// The first contact shows the key of the server and sends no credentials; the
// confirmed key is kept, and the next preflight needs no confirmation.
func TestPreflightFirstContact(t *testing.T) {
	e := newEnv(t, envOptions{})
	resp, err := e.preflight(&panelv1.PreflightRequest{Target: e.target("root"), Credentials: password()})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	hk := resp.GetHostKey()
	if hk.GetFingerprint() != e.ssh.Fingerprint() || hk.GetType() != ssh.KeyAlgoED25519 {
		t.Fatalf("Preflight = %v, want the host key %s", resp, e.ssh.Fingerprint())
	}
	if n := len(e.ssh.AuthAttempts()); n != 0 {
		t.Errorf("the server saw %d authentication attempts before its key was confirmed", n)
	}
	if got := e.host.Steps(); len(got) != 0 {
		t.Errorf("commands ran before the key was confirmed: %q", got)
	}

	r := e.report(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: password()})
	if r.GetOs() != "Ubuntu 24.04.1 LTS" || r.GetArch() != "amd64" {
		t.Errorf("report = %v", r)
	}
	target, err := e.deploy.GetTarget(context.Background(), connect.NewRequest(&panelv1.GetTargetRequest{NodeId: e.node.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	if got := target.Msg.GetTarget(); got.GetHostKey() != e.ssh.Fingerprint() || got.GetUser() != "root" ||
		got.GetHost() != e.ssh.Host || got.GetPort() != uint32(e.ssh.Port) || target.Msg.GetSavedCredentials() != "" {
		t.Errorf("GetTarget = %v, want the server with its confirmed key and no credentials", target.Msg)
	}

	// The key is kept: a preflight without it is not a first contact.
	if r := e.report(&panelv1.PreflightRequest{Target: e.target("root"), Credentials: password()}); r.GetArch() != "amd64" {
		t.Errorf("report = %v", r)
	}
}

// A server that presents another key than the confirmed one is refused with
// both, until the admin trusts the new one. The credentials that the panel
// kept for the server are never sent to the new key, and go with the old one.
func TestPreflightChangedHostKey(t *testing.T) {
	e := newEnv(t, envOptions{})
	old := sshxtest.NewEd25519Key(t)
	kind, enc, err := e.svc.sealCredentials(e.node.GetId(), sshx.Auth{Password: sshPassword})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.PutSSHTarget(context.Background(), &store.SSHTarget{NodeID: e.node.GetId(), Host: e.ssh.Host,
		Port: uint32(e.ssh.Port), User: "root", HostKey: ssh.FingerprintSHA256(old.PublicKey()), HostKeyType: ssh.KeyAlgoED25519,
		AuthKind: kind, SecretEnc: enc}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []*panelv1.SshTarget{e.target("root"), e.confirmed("root")} {
		resp, err := e.preflight(&panelv1.PreflightRequest{Target: target, Credentials: password()})
		if err != nil {
			t.Fatalf("Preflight: %v", err)
		}
		changed := resp.GetHostKeyChanged()
		if changed.GetConfirmed().GetFingerprint() != ssh.FingerprintSHA256(old.PublicKey()) ||
			changed.GetPresented().GetFingerprint() != e.ssh.Fingerprint() {
			t.Fatalf("Preflight = %v, want the changed key with both fingerprints", resp)
		}
	}
	if n := len(e.ssh.AuthAttempts()); n != 0 {
		t.Errorf("credentials went to a server whose key changed: %d attempts", n)
	}

	// The saved credentials are not for a server whose key is replaced: the
	// panel does not even connect.
	connections := e.ssh.Connections()
	_, err = e.preflight(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: &panelv1.SshCredentials{UseSaved: true},
		ReplaceHostKey: true})
	wantCode(t, err, connect.CodeInvalidArgument)
	if n := e.ssh.Connections(); n != connections {
		t.Errorf("the panel connected to the server for saved credentials and a replaced key")
	}

	// Meeting the server again: a first contact, which shows its key, and sends
	// no credentials.
	resp, err := e.preflight(&panelv1.PreflightRequest{Target: e.target("root"), Credentials: password(), ReplaceHostKey: true})
	if err != nil || resp.GetHostKey().GetFingerprint() != e.ssh.Fingerprint() {
		t.Fatalf("Preflight that replaces the key without a new one = %v, %v; want the key of the server", resp, err)
	}
	if n := len(e.ssh.AuthAttempts()); n != 0 {
		t.Errorf("credentials went to the server before its new key was confirmed: %d attempts", n)
	}

	// Trusting the new key, explicitly.
	r := e.report(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: password(), ReplaceHostKey: true})
	if r.GetArch() != "amd64" {
		t.Errorf("report = %v", r)
	}
	stored, err := e.db.SSHTargetByNode(context.Background(), e.node.GetId())
	if err != nil || stored.HostKey != e.ssh.Fingerprint() {
		t.Fatalf("the stored key is %q (%v), want the new one", stored.HostKey, err)
	}
	if stored.AuthKind != store.SSHAuthNone || stored.SecretEnc != nil {
		t.Errorf("the credentials of the old key are kept (%q) after the key was replaced", stored.AuthKind)
	}
}

// An install whose server presents another key fails, and says both.
func TestInstallRefusesAChangedHostKey(t *testing.T) {
	e := newEnv(t, envOptions{})
	old := sshxtest.NewEd25519Key(t)
	if err := e.db.PutSSHTarget(context.Background(), &store.SSHTarget{NodeID: e.node.GetId(), Host: e.ssh.Host,
		Port: uint32(e.ssh.Port), User: "root", HostKey: ssh.FingerprintSHA256(old.PublicKey()), HostKeyType: ssh.KeyAlgoED25519}); err != nil {
		t.Fatal(err)
	}
	j := e.installed(&panelv1.InstallRequest{Target: e.target("root"), Credentials: password()})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), e.ssh.Fingerprint()) ||
		!strings.Contains(j.GetError(), ssh.FingerprintSHA256(old.PublicKey())) {
		t.Errorf("job = %s %q, want failed with both fingerprints", j.GetStatus(), j.GetError())
	}
	if n := len(e.ssh.AuthAttempts()); n != 0 {
		t.Errorf("credentials went to a server whose key changed: %d attempts", n)
	}
}

func TestInstallNeedsAConfirmedHostKey(t *testing.T) {
	e := newEnv(t, envOptions{})
	_, err := e.install(&panelv1.InstallRequest{Target: e.target("root"), Credentials: password()})
	wantCode(t, err, connect.CodeFailedPrecondition)
	if n := e.ssh.Connections(); n != 0 {
		t.Errorf("the panel connected %d times for an install without a confirmed key", n)
	}
}

// ---- the preflight -----------------------------------------------------------

// The report has the facts of the server, and port 443 held by the containers
// of another stack as a blocker.
func TestPreflightReportsAPortTakenByContainers(t *testing.T) {
	e := newEnv(t, envOptions{server: "containers"})
	r := e.report(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: password()})
	if got, want := issueCodes(r), []string{"https_port_taken/blocker"}; !slices.Equal(got, want) {
		t.Errorf("issues = %q, want %q", got, want)
	}
	if p := r.GetHttpsPort(); p.GetFree() || p.GetPostern() || p.GetOwner() != "nginx (pid 4120, container shop-nginx)" {
		t.Errorf("https port = %v", p)
	}
	if r.GetDockerVersion() != "24.0.7" || r.GetComposeVersion() != "2.21.0" || r.GetInstallDir() != "/root/postern-install" ||
		r.GetDiskPath() != "/opt" || r.GetDiskFreeBytes() != 71856704<<10 || !slices.Equal(r.GetPublicIps(), []string{"203.0.113.50"}) ||
		!r.GetKitAvailable() || r.GetMgmtPort().GetPort() != 61001 || !r.GetMgmtPort().GetFree() {
		t.Errorf("report = %v", r)
	}
	var sockets []string
	for _, l := range r.GetListening() {
		sockets = append(sockets, net.JoinHostPort(l.GetAddress(), strconv.Itoa(int(l.GetPort())))+" "+strings.Join(l.GetProcesses(), ","))
	}
	if !slices.Contains(sockets, "0.0.0.0:443 nginx (pid 4120),nginx (pid 4093)") {
		t.Errorf("listening = %q", sockets)
	}
}

// A user other than root works through sudo, which runs every command as
// root: the files go to the directory of root as well.
func TestPreflightThroughSudo(t *testing.T) {
	e := newEnv(t, envOptions{})
	r := e.report(&panelv1.PreflightRequest{Target: e.confirmed("ubuntu"), Credentials: password()})
	if r.GetInstallDir() != "/root/postern-install" || len(r.GetIssues()) != 0 {
		t.Errorf("report = %v", r)
	}
}

func TestPreflightErrors(t *testing.T) {
	e := newEnv(t, envOptions{})
	ctx := context.Background()

	_, err := e.preflight(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: &panelv1.SshCredentials{Password: "wrong-password"}})
	wantCode(t, err, connect.CodePermissionDenied)

	for name, req := range map[string]*panelv1.PreflightRequest{
		"no credentials":    {Target: e.confirmed("root"), Credentials: &panelv1.SshCredentials{}},
		"no target":         {Credentials: password()},
		"a bad host":        {Target: &panelv1.SshTarget{Host: "a host", Port: 22, User: "root"}, Credentials: password()},
		"a host with port":  {Target: &panelv1.SshTarget{Host: "198.51.100.1:22", User: "root"}, Credentials: password()},
		"a bad port":        {Target: &panelv1.SshTarget{Host: "198.51.100.1", Port: 70000, User: "root"}, Credentials: password()},
		"no user":           {Target: &panelv1.SshTarget{Host: "198.51.100.1"}, Credentials: password()},
		"a bad user":        {Target: &panelv1.SshTarget{Host: "198.51.100.1", User: "ro ot"}, Credentials: password()},
		"a bad host key":    {Target: &panelv1.SshTarget{Host: "198.51.100.1", User: "root", HostKey: "MD5:aa"}, Credentials: password()},
		"a bad key type":    {Target: &panelv1.SshTarget{Host: "198.51.100.1", User: "root", HostKey: e.ssh.Fingerprint(), HostKeyType: "ssh-dss"}, Credentials: password()},
		"a huge password":   {Target: e.confirmed("root"), Credentials: &panelv1.SshCredentials{Password: strings.Repeat("p", 4096)}},
		"a key that is not": {Target: e.confirmed("root"), Credentials: &panelv1.SshCredentials{PrivateKey: "not a key"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.preflight(req)
			wantCode(t, err, connect.CodeInvalidArgument)
		})
	}

	_, err = e.deploy.Preflight(ctx, connect.NewRequest(&panelv1.PreflightRequest{NodeId: "NOPE", Target: e.confirmed("root"), Credentials: password()}))
	wantCode(t, err, connect.CodeNotFound)

	_, err = e.preflight(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: &panelv1.SshCredentials{UseSaved: true}})
	wantCode(t, err, connect.CodeFailedPrecondition)

	// A port where nothing listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	_, err = e.preflight(&panelv1.PreflightRequest{Target: &panelv1.SshTarget{Host: "127.0.0.1", Port: uint32(closed), User: "root"}, Credentials: password()})
	wantCode(t, err, connect.CodeUnavailable)

	// An answer that is not the one of the script.
	e.host.set(func(h *fakeHost) { h.preflightJunk = "Welcome!\n" })
	_, err = e.preflight(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: password()})
	wantCode(t, err, connect.CodeFailedPrecondition)

	if strings.Contains(e.logs.String(), sshPassword) {
		t.Error("the log of the panel holds the SSH password")
	}
}

func TestPreflightWhenSudoWantsAPassword(t *testing.T) {
	e := newEnv(t, envOptions{})
	inner := e.host.handle
	e2 := sshxtest.Start(t, sshxtest.Config{Password: sshPassword, Handler: func(ctx context.Context, x *sshxtest.Exec) int {
		if x.Script == sshxtest.SudoCheck {
			_, _ = x.Stderr.Write([]byte("sudo: a password is required\n"))
			return 1
		}
		return inner(ctx, x)
	}})
	target := &panelv1.SshTarget{Host: e2.Host, Port: uint32(e2.Port), User: "deploy", HostKey: e2.Fingerprint(), HostKeyType: e2.HostKey().Type()}
	_, err := e.preflight(&panelv1.PreflightRequest{Target: target, Credentials: password()})
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "passwordless sudo") {
		t.Errorf("error = %v, want it to say what sudo needs", err)
	}
}

// ---- the install -------------------------------------------------------------

// An install copies the kit of the architecture of the server and the bundle
// of the node, runs install.sh, removes the bundle, and waits for the node.
func TestInstall(t *testing.T) {
	for _, tt := range []struct {
		user, dir string
	}{
		{"root", "/root/postern-install"},
		{"ubuntu", "/root/postern-install"},
	} {
		t.Run(tt.user, func(t *testing.T) {
			e := newEnv(t, envOptions{})
			j := e.installed(&panelv1.InstallRequest{Target: e.confirmed(tt.user), Credentials: password()})
			t.Logf("the log of the job:\n%s", j.GetLog())
			if j.GetStatus() != jobs.StatusDone {
				t.Fatalf("job %s: %s\n%s", j.GetStatus(), j.GetError(), j.GetLog())
			}
			want := []string{"preflight", "mkdir",
				"upload " + tt.dir + "/postern-node", "upload " + tt.dir + "/install.sh", "upload " + tt.dir + "/launcher.sh",
				"upload " + tt.dir + "/compose.yaml", "upload " + tt.dir + "/postern-node-bundle.tar",
				"install.sh", "rm bundle"}
			if got := e.host.Steps(); !slices.Equal(got, want) {
				t.Errorf("steps:\n got %q\nwant %q", got, want)
			}
			if u := e.host.Unknown(); len(u) != 0 {
				t.Errorf("unknown commands: %q", u)
			}
			for _, f := range []struct{ name, mode, data string }{
				{"postern-node", "0700", kitBinary("amd64")},
				{"install.sh", "0600", "#!/usr/bin/env bash\n# the installer of a test kit\n"},
				{"launcher.sh", "0600", "#!/bin/sh\n# the launcher of a test kit\n"},
				{"compose.yaml", "0600", "# the compose file of a test kit\n"},
			} {
				got, ok := e.host.file(tt.dir + "/" + f.name)
				if !ok || got.mode != f.mode || string(got.data) != f.data {
					t.Errorf("%s: present %v, mode %s, %d bytes; want mode %s and the file of the kit", f.name, ok, got.mode, len(got.data), f.mode)
				}
			}
			if _, ok := e.host.file(tt.dir + "/postern-node-bundle.tar"); ok {
				t.Error("the bundle is still on the server")
			}
			var bundle *upload
			for _, u := range e.host.Uploads() {
				if strings.HasSuffix(u.path, "/postern-node-bundle.tar") {
					bundle = &u
				}
			}
			if bundle == nil || bundle.mode != "0600" {
				t.Fatalf("the bundle was not uploaded with mode 0600: %+v", bundle)
			}
			b, err := pki.ParseBundleTar(bundle.data)
			if err != nil || b.NodeID != e.node.GetId() || b.MgmtPort != 61001 {
				t.Errorf("the uploaded bundle: %v, node %q port %d", err, b.NodeID, b.MgmtPort)
			}
			n, err := e.db.NodeByID(context.Background(), e.node.GetId())
			if err != nil || n.Status != store.NodeStatusOnline {
				t.Errorf("node status %q (%v), want online", n.Status, err)
			}
			for _, line := range []string{"Connecting to " + tt.user + "@", "Checking the server", "Ubuntu 24.04.1 LTS", "Copying the node kit",
				"Running install.sh", "Postern node installed.", "Removing the bundle", "Waiting for the node", "The node is online"} {
				if !strings.Contains(j.GetLog(), line) {
					t.Errorf("the log does not say %q:\n%s", line, j.GetLog())
				}
			}
			if strings.Contains(j.GetLog(), sshPassword) || strings.Contains(e.logs.String(), sshPassword) {
				t.Error("a log holds the SSH password")
			}
			stored, err := e.db.SSHTargetByNode(context.Background(), e.node.GetId())
			if err != nil || stored.HostKey != e.ssh.Fingerprint() || stored.AuthKind != store.SSHAuthNone || stored.SecretEnc != nil {
				t.Errorf("stored target = %+v (%v), want the confirmed key and no credentials", stored, err)
			}
		})
	}
}

// Installing again does the same again: install.sh is idempotent, and the
// panel uploads and removes the same files.
func TestInstallAgain(t *testing.T) {
	e := newEnv(t, envOptions{server: "debian-12", mgmt: 61443})
	for i := range 2 {
		j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
		if j.GetStatus() != jobs.StatusDone {
			t.Fatalf("install %d: %s %s\n%s", i+1, j.GetStatus(), j.GetError(), j.GetLog())
		}
	}
	ran := 0
	for _, step := range e.host.Steps() {
		if step == "install.sh" {
			ran++
		}
	}
	if ran != 2 {
		t.Errorf("install.sh ran %d times, want 2", ran)
	}
}

// remember keeps the credentials, sealed, and a later preflight can use them;
// without it the panel forgets them.
func TestInstallRemembersCredentials(t *testing.T) {
	e := newEnv(t, envOptions{})
	ctx := context.Background()
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), Remember: true})
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job %s: %s", j.GetStatus(), j.GetError())
	}
	stored, err := e.db.SSHTargetByNode(ctx, e.node.GetId())
	if err != nil || stored.AuthKind != store.SSHAuthPassword || len(stored.SecretEnc) == 0 {
		t.Fatalf("stored = %+v (%v), want sealed password credentials", stored, err)
	}
	if bytes.Contains(stored.SecretEnc, []byte(sshPassword)) {
		t.Error("the database holds the password in the clear")
	}
	if _, err := seal.Open(e.key, stored.SecretEnc, []byte("ssh:"+e.node.GetId())); err != nil {
		t.Errorf("the credentials are not sealed with the AAD ssh:<node id>: %v", err)
	}
	got, err := e.deploy.GetTarget(ctx, connect.NewRequest(&panelv1.GetTargetRequest{NodeId: e.node.GetId()}))
	if err != nil || got.Msg.GetSavedCredentials() != "password" {
		t.Fatalf("GetTarget = %v (%v), want saved password credentials", got, err)
	}
	if r := e.report(&panelv1.PreflightRequest{Target: e.target("root"), Credentials: &panelv1.SshCredentials{UseSaved: true}}); r.GetArch() != "amd64" {
		t.Errorf("report with the saved credentials = %v", r)
	}
	// Saved credentials are for their target only.
	_, err = e.preflight(&panelv1.PreflightRequest{Target: e.confirmed("ubuntu"), Credentials: &panelv1.SshCredentials{UseSaved: true}})
	wantCode(t, err, connect.CodeFailedPrecondition)

	j = e.installed(&panelv1.InstallRequest{Target: e.target("root"), Credentials: &panelv1.SshCredentials{UseSaved: true}})
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job with the saved credentials %s: %s", j.GetStatus(), j.GetError())
	}
	stored, err = e.db.SSHTargetByNode(ctx, e.node.GetId())
	if err != nil || stored.AuthKind != store.SSHAuthNone || stored.SecretEnc != nil {
		t.Errorf("stored = %+v (%v): an install without remember must forget the credentials", stored, err)
	}
}

// An install with a private key works, and the key and its passphrase never
// show.
func TestInstallWithAPrivateKey(t *testing.T) {
	const passphrase = "passphrase-of-the-test-key"
	keyPEM, pub := sshxtest.NewClientKey(t, passphrase)
	e := newEnv(t, envOptions{sshCfg: func(c *sshxtest.Config) { c.Password = ""; c.AuthorizedKeys = []ssh.PublicKey{pub} }})
	creds := &panelv1.SshCredentials{PrivateKey: string(keyPEM), Passphrase: passphrase}
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: creds, Remember: true})
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job %s: %s", j.GetStatus(), j.GetError())
	}
	stored, err := e.db.SSHTargetByNode(context.Background(), e.node.GetId())
	if err != nil || stored.AuthKind != store.SSHAuthKey {
		t.Errorf("stored = %+v (%v), want key credentials", stored, err)
	}
	_, err = e.preflight(&panelv1.PreflightRequest{Target: e.confirmed("root"), Credentials: &panelv1.SshCredentials{PrivateKey: string(keyPEM)}})
	wantCode(t, err, connect.CodePermissionDenied)
	if strings.Contains(e.logs.String(), passphrase) || strings.Contains(j.GetLog(), passphrase) {
		t.Error("a log holds the passphrase")
	}
}

// The install is refused for what the preflight reports as a blocker, before
// anything is copied.
func TestInstallRefusals(t *testing.T) {
	tests := []struct {
		name   string
		opts   envOptions
		req    *panelv1.InstallRequest
		reason string
	}{
		{"443 taken", envOptions{server: "containers"}, &panelv1.InstallRequest{}, "port 443 is taken by nginx (pid 4120, container shop-nginx)"},
		{"userns-remap", envOptions{server: "userns", mgmt: 61000}, &panelv1.InstallRequest{}, "userns-remap"},
		{"no kit for the architecture", envOptions{arches: []string{"arm64"}}, &panelv1.InstallRequest{}, "no node kit for amd64"},
		{"no Docker", envOptions{server: "ubuntu-24.04-nodocker"}, &panelv1.InstallRequest{}, "Docker is not installed"},
		{"the management port taken", envOptions{server: "containers", mgmt: 8443}, &panelv1.InstallRequest{}, "management port 8443"},
		{"443 taken by a process of the host", envOptions{server: "alpine-3.22-ss"},
			&panelv1.InstallRequest{InstallDocker: true}, "port 443 is taken by nginx (pid 2101)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.opts)
			tt.req.Target, tt.req.Credentials = e.confirmed("root"), password()
			j := e.installed(tt.req)
			if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), tt.reason) {
				t.Errorf("job %s %q, want failed for %q\n%s", j.GetStatus(), j.GetError(), tt.reason, j.GetLog())
			}
			if got := e.host.Steps(); !slices.Equal(got, []string{"preflight"}) {
				t.Errorf("steps = %q, want the preflight only", got)
			}
		})
	}
}

// Docker is installed only when the admin asks for it.
func TestInstallWithDocker(t *testing.T) {
	e := newEnv(t, envOptions{server: "ubuntu-24.04-nodocker"})
	e.host.set(func(h *fakeHost) { h.afterDocker = "ubuntu-24.04" })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), InstallDocker: true})
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job %s: %s\n%s", j.GetStatus(), j.GetError(), j.GetLog())
	}
	steps := e.host.Steps()
	if len(steps) < 4 || !slices.Equal(steps[:3], []string{"preflight", "install docker", "preflight"}) {
		t.Errorf("steps = %q, want the preflight, the install of Docker, the preflight again, then the install", steps)
	}
	if !strings.Contains(j.GetLog(), "Setting up Docker") {
		t.Errorf("the log does not say that Docker is installed:\n%s", j.GetLog())
	}

	// Docker that is there is not installed again.
	e2 := newEnv(t, envOptions{})
	j = e2.installed(&panelv1.InstallRequest{Target: e2.confirmed("root"), Credentials: password(), InstallDocker: true})
	if j.GetStatus() != jobs.StatusDone || slices.Contains(e2.host.Steps(), "install docker") {
		t.Errorf("job %s, steps %q: Docker was installed over Docker", j.GetStatus(), e2.host.Steps())
	}
}

func TestInstallWhenDockerCannotBeInstalled(t *testing.T) {
	e := newEnv(t, envOptions{server: "ubuntu-24.04-nodocker"})
	e.host.set(func(h *fakeHost) { h.dockerCode = 1 })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password(), InstallDocker: true})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "Docker") {
		t.Errorf("job %s %q, want failed for Docker", j.GetStatus(), j.GetError())
	}
	if slices.Contains(e.host.Steps(), "install.sh") {
		t.Errorf("install.sh ran without Docker: %q", e.host.Steps())
	}
}

// A failing install.sh fails the job, and the bundle is removed all the same.
func TestInstallScriptFails(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.host.set(func(h *fakeHost) { h.installCode, h.installOutput = 1, "install.sh: error: Docker is not installed\n" })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "install.sh failed with exit code 1") {
		t.Errorf("job %s %q, want failed by install.sh", j.GetStatus(), j.GetError())
	}
	if !strings.Contains(j.GetLog(), "install.sh: error: Docker is not installed") {
		t.Errorf("the log does not have the output of install.sh:\n%s", j.GetLog())
	}
	if _, ok := e.host.file("/root/postern-install/postern-node-bundle.tar"); ok {
		t.Error("the bundle stayed on the server after install.sh failed")
	}
}

// The credentials never show in the log of a job, whatever the server prints:
// the password, a private key of SSH, and the private key of the node, which
// is in the bundle.
func TestInstallHidesTheCredentialsInTheLog(t *testing.T) {
	const passphrase = "passphrase-of-the-test-key"
	keyPEM, pub := sshxtest.NewClientKey(t, passphrase)
	for _, tt := range []struct {
		name   string
		creds  *panelv1.SshCredentials
		output string
		secret []string
	}{
		{"a password", password(), "the password is " + sshPassword + "\n", []string{sshPassword}},
		{"a private key", &panelv1.SshCredentials{PrivateKey: string(keyPEM), Passphrase: passphrase},
			string(keyPEM) + "and its passphrase " + passphrase + "\n", append(strings.Split(strings.TrimSpace(string(keyPEM)), "\n"), passphrase)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, envOptions{sshCfg: func(c *sshxtest.Config) { c.AuthorizedKeys = []ssh.PublicKey{pub} }})
			e.host.set(func(h *fakeHost) { h.installOutput, h.echoBundleKey = tt.output, true })
			j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: tt.creds})
			if j.GetStatus() != jobs.StatusDone {
				t.Fatalf("job %s: %s", j.GetStatus(), j.GetError())
			}
			var nodeKey []string
			for _, u := range e.host.Uploads() {
				if b, err := pki.ParseBundleTar(u.data); err == nil {
					nodeKey = strings.Split(strings.TrimSpace(string(b.KeyPEM)), "\n")
				}
			}
			if len(nodeKey) < 3 {
				t.Fatalf("no key of the node in the uploads: %q", nodeKey)
			}
			for _, line := range append(nodeKey, tt.secret...) {
				if len(line) >= jobs.MinSecretLen && strings.Contains(j.GetLog(), line) {
					t.Errorf("the log shows %q:\n%s", line, j.GetLog())
				}
			}
			if !strings.Contains(j.GetLog(), "***") {
				t.Errorf("the log masks nothing:\n%s", j.GetLog())
			}
		})
	}
}

// A bundle that cannot be removed from the server fails the job, also when the
// node came online: the private key of the node is left on the server.
func TestInstallReportsABundleThatStays(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.host.set(func(h *fakeHost) { h.failRemoval = true })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "the node is online, but") ||
		!strings.Contains(j.GetError(), "/root/postern-install/postern-node-bundle.tar") {
		t.Errorf("job %s %q, want failed: the bundle stayed", j.GetStatus(), j.GetError())
	}
}

// A directory of the install that another user owns is refused.
func TestInstallRefusesADirectoryOfAnotherUser(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.host.set(func(h *fakeHost) { h.foreignDir = true })
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "the directory of the install could not be made") ||
		!strings.Contains(j.GetLog(), "belongs to uid 1000") {
		t.Errorf("job %s %q, want failed for the directory\n%s", j.GetStatus(), j.GetError(), j.GetLog())
	}
	for _, step := range e.host.Steps() {
		if strings.HasPrefix(step, "upload ") {
			t.Errorf("a file was copied into a directory of another user: %s", step)
		}
	}
}

// An install that confirms a key, without a preflight before, records it as a
// preflight does.
func TestInstallAuditsANewHostKey(t *testing.T) {
	e := newEnv(t, envOptions{})
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if j.GetStatus() != jobs.StatusDone {
		t.Fatalf("job %s: %s", j.GetStatus(), j.GetError())
	}
	if got := e.audit(); !slices.Contains(got, "node.ssh_host_key node:"+e.node.GetId()) || !slices.Contains(got, "node.install node:"+e.node.GetId()) {
		t.Errorf("audit log = %q, want the confirmation of the key and the install", got)
	}
	if !strings.Contains(e.logs.String(), "SSH host key of a node confirmed") {
		t.Error("the log of the panel does not record the confirmed key")
	}
}

// A node that does not come online fails the job after the wait; one that was
// online before the install does not count, until the panel has heard from it
// since.
func TestInstallOfANodeThatStaysOffline(t *testing.T) {
	e := newEnv(t, envOptions{})
	before := time.Now().Add(-time.Hour)
	if _, err := e.db.ModifyNode(context.Background(), e.node.GetId(), func(n *store.Node) error {
		n.Status, n.LastSeenAt = store.NodeStatusOnline, &before
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.notifier.setDown(true)
	e.svc.onlineTimeout = 300 * time.Millisecond
	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if j.GetStatus() != jobs.StatusFailed || !strings.Contains(j.GetError(), "did not come online") {
		t.Errorf("job %s %q, want failed: the node did not come online", j.GetStatus(), j.GetError())
	}
	e.notifier.mu.Lock()
	notified := len(e.notifier.notified)
	e.notifier.mu.Unlock()
	if notified == 0 {
		t.Error("the connection manager was not told to look at the node")
	}
	if _, ok := e.host.file("/root/postern-install/postern-node-bundle.tar"); ok {
		t.Error("the bundle stayed on the server")
	}
}

// A cancelled install stops the command that runs, and removes the bundle.
func TestCancelInstall(t *testing.T) {
	e := newEnv(t, envOptions{})
	started := make(chan struct{})
	e.host.set(func(h *fakeHost) {
		h.block = true
		h.onInstall = func() { close(started) }
	})
	id, err := e.install(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(waitTimeout):
		t.Fatal("install.sh did not start")
	}
	// The node runs a job: another one is refused.
	_, err = e.install(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	wantCode(t, err, connect.CodeFailedPrecondition)
	got, err := e.deploy.GetTarget(context.Background(), connect.NewRequest(&panelv1.GetTargetRequest{NodeId: e.node.GetId()}))
	if err != nil || got.Msg.GetRunningJobId() != id {
		t.Errorf("GetTarget = %v (%v), want the running job %s", got, err, id)
	}

	if _, err := e.deploy.CancelJob(context.Background(), connect.NewRequest(&panelv1.CancelJobRequest{Id: id})); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	j := e.job(id)
	if j.GetStatus() != jobs.StatusCancelled || j.GetError() != jobs.CancelledError {
		t.Errorf("job %s %q, want cancelled, and nothing more to do", j.GetStatus(), j.GetError())
	}
	if _, ok := e.host.file("/root/postern-install/postern-node-bundle.tar"); ok {
		t.Error("the bundle stayed on the server after the cancel")
	}
}

// A cancelled install whose bundle could not be removed says so in its error,
// not in its log only.
func TestCancelledInstallNamesABundleThatStays(t *testing.T) {
	e := newEnv(t, envOptions{})
	started := make(chan struct{})
	e.host.set(func(h *fakeHost) {
		h.block, h.failRemoval = true, true
		h.onInstall = func() { close(started) }
	})
	id, err := e.install(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(waitTimeout):
		t.Fatal("install.sh did not start")
	}
	if _, err := e.deploy.CancelJob(context.Background(), connect.NewRequest(&panelv1.CancelJobRequest{Id: id})); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	j := e.job(id)
	want := jobs.CancelledError + "; the bundle /root/postern-install/postern-node-bundle.tar, which holds the private key of the node, " +
		"may still be on the server: remove it by hand"
	if j.GetStatus() != jobs.StatusCancelled || !strings.HasPrefix(j.GetError(), want) {
		t.Errorf("job %s %q, want cancelled with %q", j.GetStatus(), j.GetError(), want)
	}
}

func TestJobErrors(t *testing.T) {
	e := newEnv(t, envOptions{})
	ctx := context.Background()
	_, err := e.deploy.GetJob(ctx, connect.NewRequest(&panelv1.GetJobRequest{Id: "NOPE"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = e.deploy.CancelJob(ctx, connect.NewRequest(&panelv1.CancelJobRequest{Id: "NOPE"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = e.deploy.GetTarget(ctx, connect.NewRequest(&panelv1.GetTargetRequest{NodeId: "NOPE"}))
	wantCode(t, err, connect.CodeNotFound)

	j := e.installed(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	_, err = e.deploy.CancelJob(ctx, connect.NewRequest(&panelv1.CancelJobRequest{Id: j.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

// The job runner may run jobs of other kinds. The install page asks which job a node runs, reads a job
// by its id and cancels one by its id, and a job that is not an install is
// neither shown nor cancelled, whether it runs or is history: it is answered as
// a job that does not exist, which also keeps the page from telling a collection
// that has ended from an id that was never one.
func TestJobsOfOtherKindsAreNotShown(t *testing.T) {
	e := newEnv(t, envOptions{})
	ctx := context.Background()
	nodeID := e.node.GetId()

	runningJob := func() string {
		t.Helper()
		resp, err := e.deploy.GetTarget(ctx, connect.NewRequest(&panelv1.GetTargetRequest{NodeId: nodeID}))
		if err != nil {
			t.Fatalf("GetTarget: %v", err)
		}
		return resp.Msg.GetRunningJobId()
	}
	getJob := func(id string) (*panelv1.Job, error) {
		resp, err := e.deploy.GetJob(ctx, connect.NewRequest(&panelv1.GetJobRequest{Id: id}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetJob(), nil
	}
	cancelJob := func(id string) error {
		_, err := e.deploy.CancelJob(ctx, connect.NewRequest(&panelv1.CancelJobRequest{Id: id}))
		return err
	}

	// A collection runs on the node. It does not look at its context until it is
	// let go, and then returns the error of its context: it ends done unless
	// something cancelled it.
	release := make(chan struct{})
	var releaseOnce sync.Once
	stop := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(stop)
	collection, err := e.runner.Start(ctx, nodeID, "collect", nil, func(ctx context.Context, log io.Writer) error {
		_, _ = io.WriteString(log, "collecting\n")
		<-release
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("Start of a collection: %v", err)
	}

	// hidden checks what the page is told: the node runs the job want, which is
	// empty for none, and the collection is not found, nor can it be cancelled.
	hidden := func(when, want string) {
		t.Helper()
		if id := runningJob(); id != want {
			t.Errorf("%s: GetTarget says the node runs the job %q, want %q: the page would follow the log of a collection", when, id, want)
		}
		if j, err := getJob(collection); connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("%s: GetJob of the collection = %v, %v; want NOT_FOUND", when, j, err)
		}
		if err := cancelJob(collection); connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("%s: CancelJob of the collection: err = %v, want NOT_FOUND", when, err)
		}
	}
	hidden("while the collection runs", "")

	// Let it go: it ends done, so nothing of the page cancelled it.
	stop()
	deadline := time.Now().Add(waitTimeout)
	for {
		j, err := e.runner.Get(ctx, collection)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != jobs.StatusRunning {
			if j.Status != jobs.StatusDone || j.Kind != "collect" {
				t.Fatalf("the collection ended %s %q, want done: the install page cancelled it", j.Status, j.Error)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the collection is still running")
		}
		time.Sleep(10 * time.Millisecond)
	}
	hidden("after the collection has ended", "")

	// An install runs on the node now, with the collection in its history: the
	// page is told of the install, and of nothing else.
	started := make(chan struct{})
	e.host.set(func(h *fakeHost) {
		h.block = true
		h.onInstall = func() { close(started) }
	})
	install, err := e.install(&panelv1.InstallRequest{Target: e.confirmed("root"), Credentials: password()})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	select {
	case <-started:
	case <-time.After(waitTimeout):
		t.Fatal("install.sh did not start")
	}
	hidden("while the install runs", install)
	if j, err := getJob(install); err != nil || j.GetKind() != "install" || j.GetStatus() != jobs.StatusRunning {
		t.Errorf("GetJob of the install = %v, %v; want the running install", j, err)
	}
	if err := cancelJob(install); err != nil {
		t.Fatalf("CancelJob of the install: %v", err)
	}
	if j := e.job(install); j.GetStatus() != jobs.StatusCancelled {
		t.Errorf("the install is %s, want cancelled", j.GetStatus())
	}
	hidden("after the install was cancelled", "")
}

// Without a session nothing is answered.
func TestDeployNeedsAnAdmin(t *testing.T) {
	anon := NewService(Config{})
	_, err := anon.GetJob(context.Background(), connect.NewRequest(&panelv1.GetJobRequest{Id: "x"}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = anon.Install(context.Background(), connect.NewRequest(&panelv1.InstallRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = anon.Preflight(context.Background(), connect.NewRequest(&panelv1.PreflightRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = anon.GetTarget(context.Background(), connect.NewRequest(&panelv1.GetTargetRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = anon.CancelJob(context.Background(), connect.NewRequest(&panelv1.CancelJobRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
}
