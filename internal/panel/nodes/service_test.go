package nodes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/version"
)

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"
)

// notifyRecorder is a Notifier that notes the nodes it was told about.
type notifyRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (n *notifyRecorder) Notify(nodeID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = append(n.ids, nodeID)
}

func (n *notifyRecorder) got() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.ids...)
}

// api is the node service of a panel behind the auth middleware, as the panel
// serves it, with an admin who has signed in.
type api struct {
	*testPanel
	notes   *notifyRecorder
	srv     *httptest.Server
	web     *http.Client                     // a browser with the session cookie
	nodes   panelv1connect.NodeServiceClient // signed in
	anon    panelv1connect.NodeServiceClient // no session
	adminID string
}

// newAPI serves the node service, made with opts, and its downloads.
func newAPI(t *testing.T, opts ...Option) *api {
	t.Helper()
	ctx := context.Background()
	p := newTestPanel(t)
	a := &api{testPanel: p, notes: &notifyRecorder{}}
	p.svc = NewService(p.db, p.key, p.ca, a.notes, p.log, opts...)

	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := p.db.CreateAdmin(ctx, admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	a.adminID = admin.ID

	authSvc := auth.NewService(p.db, p.key, p.log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewNodeServiceHandler(p.svc))
	mux.Handle(panelv1connect.NewJoinServiceHandler(p.svc))
	mux.Handle(BundleRoute, p.svc.BundleHandler())
	mux.Handle(KitRoute, p.svc.KitHandler())
	a.srv = httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(a.srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	a.web = &http.Client{Jar: jar, Timeout: waitTimeout}
	login := panelv1connect.NewAuthServiceClient(a.web, a.srv.URL)
	if _, err := login.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	a.nodes = panelv1connect.NewNodeServiceClient(a.web, a.srv.URL)
	a.anon = panelv1connect.NewNodeServiceClient(&http.Client{Timeout: waitTimeout}, a.srv.URL)
	return a
}

func (a *api) create(req *panelv1.CreateNodeRequest) *panelv1.CreateNodeResponse {
	a.t.Helper()
	resp, err := a.nodes.CreateNode(context.Background(), connect.NewRequest(req))
	if err != nil {
		a.t.Fatalf("CreateNode: %v", err)
	}
	return resp.Msg
}

// audit returns the audit log as "action target admin" lines, oldest first.
func (a *api) audit() []string {
	a.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(a.dbPath)+"?mode=ro")
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT action, target, admin_id FROM audit_log WHERE action NOT LIKE 'auth.%' ORDER BY ts, rowid`) // not the sign-in of the test
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var action, target, admin string
		if err := rows.Scan(&action, &target, &admin); err != nil {
			a.t.Fatal(err)
		}
		out = append(out, action+" "+target+" "+admin)
	}
	if err := rows.Err(); err != nil {
		a.t.Fatal(err)
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

func TestCreateNodeIssuesACertificate(t *testing.T) {
	a := newAPI(t)
	got := a.create(&panelv1.CreateNodeRequest{
		Name:     "Frankfurt 1",
		MgmtHost: "192.0.2.10",
		MgmtPort: 61443,
		LinkHost: "proxy.example.com",
	})

	n := got.GetNode()
	id := n.GetId()
	if len(id) != 26 || strings.ToUpper(id) != id {
		t.Fatalf("node id = %q, want a ULID", id)
	}
	want := &panelv1.Node{
		Id:                   id,
		Name:                 "Frankfurt 1",
		MgmtHost:             "192.0.2.10",
		MgmtPort:             61443,
		LinkHost:             "proxy.example.com",
		Status:               "provisioning",
		EngineChannel:        "stable",
		EngineChannelDefault: true,
		MgmtMode:             "port",
		ArtifactSource:       "panel",
	}
	if !proto.Equal(n, want) {
		t.Errorf("node = %v, want %v", n, want)
	}
	if want := "/api/nodes/" + id + "/bundle.tar"; got.GetBundleUrl() != want {
		t.Errorf("bundle_url = %q, want %q", got.GetBundleUrl(), want)
	}
	if got.GetInstallCommand() != wantInstallCommand {
		t.Errorf("install_command = %q, want %q", got.GetInstallCommand(), wantInstallCommand)
	}
	if notes := a.notes.got(); !slices.Equal(notes, []string{id}) {
		t.Errorf("notified %v, want %v", notes, []string{id})
	}

	stored := a.node(id)
	cert := parseCert(t, []byte(stored.CertPEM))
	lower := strings.ToLower(id)
	if cert.Subject.CommonName != lower {
		t.Errorf("certificate common name = %q, want %q", cert.Subject.CommonName, lower)
	}
	if want := []string{lower + ".internal"}; !slices.Equal(cert.DNSNames, want) {
		t.Errorf("certificate DNS names = %v, want %v", cert.DNSNames, want)
	}
	if len(cert.IPAddresses) != 0 || len(cert.URIs) != 0 || len(cert.EmailAddresses) != 0 {
		t.Errorf("certificate names more than the node: %v %v %v", cert.IPAddresses, cert.URIs, cert.EmailAddresses)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("certificate extended key usage = %v, want serverAuth only", cert.ExtKeyUsage)
	}
	// The certificate is shown to anybody who connects to the management
	// port, so it must not say what the server is.
	for _, s := range append([]string{cert.Subject.CommonName, cert.Issuer.CommonName}, cert.DNSNames...) {
		if strings.Contains(strings.ToLower(s), "postern") {
			t.Errorf("the certificate names the product: %q", s)
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the node certificate does not verify against the CA: %v", err)
	}

	fp, err := pki.Fingerprint([]byte(stored.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if stored.CertFingerprint != fp {
		t.Errorf("stored fingerprint = %q, want %q", stored.CertFingerprint, fp)
	}
	if raw, err := hex.DecodeString(fp); err != nil || len(raw) != 32 || strings.ToLower(fp) != fp {
		t.Errorf("fingerprint %q is not lower-case hex SHA-256", fp)
	}
	keyPEM, err := seal.Open(a.key, stored.KeyEnc, []byte("node_key:"+id))
	if err != nil {
		t.Fatalf("the node key does not open with its additional data: %v", err)
	}
	if _, err := tls.X509KeyPair([]byte(stored.CertPEM), keyPEM); err != nil {
		t.Errorf("the node key does not match its certificate: %v", err)
	}
	if strings.Contains(string(stored.KeyEnc), "PRIVATE KEY") {
		t.Error("the node key is stored in the clear")
	}

	if got, want := a.audit(), []string{"node.create node:" + id + " " + a.adminID}; !slices.Equal(got, want) {
		t.Errorf("audit log = %q, want %q", got, want)
	}
}

func TestCreateNodeDefaults(t *testing.T) {
	a := newAPI(t)
	n := a.create(&panelv1.CreateNodeRequest{Name: "  edge  ", MgmtHost: " 2001:db8::7 "}).GetNode()
	if n.GetName() != "edge" {
		t.Errorf("name = %q, want it trimmed to %q", n.GetName(), "edge")
	}
	if n.GetMgmtHost() != "2001:db8::7" {
		t.Errorf("mgmt_host = %q, want %q", n.GetMgmtHost(), "2001:db8::7")
	}
	if n.GetLinkHost() != "2001:db8::7" {
		t.Errorf("link_host = %q, want the management host", n.GetLinkHost())
	}
	if p := n.GetMgmtPort(); p < 61000 || p > 65535 {
		t.Errorf("mgmt_port = %d, want a random port in 61000-65535", p)
	}
	if stored := a.node(n.GetId()); stored.MgmtPort != n.GetMgmtPort() || stored.LinkHost != "2001:db8::7" {
		t.Errorf("stored node = %+v, want the defaults of the response", stored)
	}
}

func TestCreateNodeRejectsBadInput(t *testing.T) {
	good := func() *panelv1.CreateNodeRequest {
		return &panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443, LinkHost: "proxy.example.com"}
	}
	tests := []struct {
		name  string
		spoil func(r *panelv1.CreateNodeRequest)
	}{
		{"empty name", func(r *panelv1.CreateNodeRequest) { r.Name = "" }},
		{"blank name", func(r *panelv1.CreateNodeRequest) { r.Name = " \t " }},
		{"name too long", func(r *panelv1.CreateNodeRequest) { r.Name = strings.Repeat("n", 65) }},
		{"control character in name", func(r *panelv1.CreateNodeRequest) { r.Name = "a\x00b" }},
		{"host with a scheme", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "https://example.com" }},
		{"host with a port", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "example.com:443" }},
		{"host with a space", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "exa mple.com" }},
		{"host with a path", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "example.com/x" }},
		{"IPv6 in brackets", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "[2001:db8::1]" }},
		{"IPv6 with a zone", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "fe80::1%eth0" }},
		{"label too long", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = strings.Repeat("a", 64) + ".example.com" }},
		{"host too long", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = strings.Repeat("a.", 127) + "example" }},
		{"hyphen at the start of a label", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "-a.example.com" }},
		{"hyphen at the end of a label", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "a-.example.com" }},
		{"empty label", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "a..example.com" }},
		{"trailing dot", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "example.com." }},
		{"numeric last label", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "192.0.2.300" }},
		{"underscore", func(r *panelv1.CreateNodeRequest) { r.MgmtHost = "a_b.example.com" }},
		{"port too large", func(r *panelv1.CreateNodeRequest) { r.MgmtPort = 65536 }},
		{"bad link host", func(r *panelv1.CreateNodeRequest) { r.LinkHost = "not a host" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAPI(t)
			req := good()
			tt.spoil(req)
			_, err := a.nodes.CreateNode(context.Background(), connect.NewRequest(req))
			wantCode(t, err, connect.CodeInvalidArgument)
			list, err := a.db.ListNodes(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 0 {
				t.Errorf("a node was stored: %+v", list[0])
			}
			if notes := a.notes.got(); len(notes) != 0 {
				t.Errorf("notified %v for a node that was not created", notes)
			}
		})
	}
}

// Protobuf refuses a string that is not UTF-8 before a request is sent, so
// these checks are for callers in the panel itself.
func TestTextChecksRefuseInvalidUTF8(t *testing.T) {
	if _, err := checkName("a\xffb"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("checkName of invalid UTF-8: %v", err)
	}
	if _, err := checkNote("a\xffb"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("checkNote of invalid UTF-8: %v", err)
	}
	if _, err := checkHost("mgmt_host", "a\xffb.example"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("checkHost of invalid UTF-8: %v", err)
	}
}

func TestCreateNodeAcceptsHosts(t *testing.T) {
	a := newAPI(t)
	for _, host := range []string{"192.0.2.10", "2001:db8::1", "example.com", "node-1.example.com", "Node1.Example.COM", "localhost", "xn--e1afmkfd.example"} {
		n := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: host, MgmtPort: 61443}).GetNode()
		if n.GetMgmtHost() != host {
			t.Errorf("mgmt_host %q stored as %q", host, n.GetMgmtHost())
		}
	}
}

func TestListAndGetNodes(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	first := a.create(&panelv1.CreateNodeRequest{Name: "one", MgmtHost: "192.0.2.1", MgmtPort: 61001}).GetNode()
	second := a.create(&panelv1.CreateNodeRequest{Name: "two", MgmtHost: "192.0.2.2", MgmtPort: 61002}).GetNode()

	// What the connection manager writes shows up in the API.
	seen := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	a.modify(second.GetId(), func(n *store.Node) {
		n.Status = store.NodeStatusOnline
		n.AgentVersion, n.EdgeVersion, n.Arch = "1.2.3", "1.2.4", "arm64"
		n.HostInfo.OS = "Ubuntu 24.04.3 LTS"
		n.HostInfo.Capabilities = []string{"edge-version", "faketls"}
		n.HostInfo.PortOwners = []store.PortOwner{
			{Bind: "0.0.0.0", Port: 80, Owner: "nginx (pid 812)"},
			{Bind: "0.0.0.0", Port: 443, Owner: "postern-edge-g1"},
			{Bind: "0.0.0.0", Port: 61002, Owner: "postern-agent"},
			{Bind: "::", Port: 8080, Owner: "unknown"},
			{Bind: "127.0.0.1", Port: 9000, Owner: "postern-lookalike (pid 5)"},
		}
		n.PublicIPs = []string{"198.51.100.7"}
		n.AppliedGeneration = 2
		n.LastSeenAt = &seen
		n.Note = "rack 4"
	})
	a.bump(second.GetId(), 3)

	list, err := a.nodes.ListNodes(ctx, connect.NewRequest(&panelv1.ListNodesRequest{}))
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	var gotIDs []string
	for _, n := range list.Msg.GetNodes() {
		gotIDs = append(gotIDs, n.GetId())
	}
	if want := []string{first.GetId(), second.GetId()}; !slices.Equal(gotIDs, want) {
		t.Fatalf("ListNodes ids = %v, want %v", gotIDs, want)
	}

	got, err := a.nodes.GetNode(ctx, connect.NewRequest(&panelv1.GetNodeRequest{Id: second.GetId()}))
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	want := &panelv1.Node{
		Id:                   second.GetId(),
		Name:                 "two",
		MgmtHost:             "192.0.2.2",
		MgmtPort:             61002,
		LinkHost:             "192.0.2.2",
		Status:               "online",
		AgentVersion:         "1.2.3",
		EdgeVersion:          "1.2.4",
		Arch:                 "arm64",
		Os:                   "Ubuntu 24.04.3 LTS",
		PublicIps:            []string{"198.51.100.7"},
		DesiredGeneration:    3,
		AppliedGeneration:    2,
		LastSeenUnix:         seen.Unix(),
		Note:                 "rack 4",
		EngineChannel:        "stable",
		EngineChannelDefault: true,
		MgmtMode:             "port",
		ArtifactSource:       "panel",
		Capabilities:         []string{"edge-version", "faketls"},
		PortOwners: []*panelv1.PortOwner{
			{Bind: "0.0.0.0", Port: 80, Owner: "nginx (pid 812)"},
			{Bind: "0.0.0.0", Port: 443, Owner: "postern-edge-g1", Postern: true},
			{Bind: "0.0.0.0", Port: 61002, Owner: "postern-agent", Postern: true},
			{Bind: "::", Port: 8080, Owner: "unknown"},
			{Bind: "127.0.0.1", Port: 9000, Owner: "postern-lookalike (pid 5)"},
		},
	}
	if !proto.Equal(got.Msg.GetNode(), want) {
		t.Errorf("GetNode = %v, want %v", got.Msg.GetNode(), want)
	}
	if !proto.Equal(list.Msg.GetNodes()[1], want) {
		t.Errorf("ListNodes[1] = %v, want %v", list.Msg.GetNodes()[1], want)
	}

	_, err = a.nodes.GetNode(ctx, connect.NewRequest(&panelv1.GetNodeRequest{Id: ids.New()}))
	wantCode(t, err, connect.CodeNotFound)
}

// The API says why a node does not run its desired state: why it refused the
// state of the panel, which is about the newest state, before why its last pass
// failed, which is then about an older one.
func TestNodeAPISaysWhyTheNodeDoesNotRunItsState(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	n := a.create(&panelv1.CreateNodeRequest{Name: "one", MgmtHost: "192.0.2.1", MgmtPort: 61001}).GetNode()
	const (
		lastErr   = "edge g1 does not answer"
		rejection = `invalid node state: listener "l1": port 70000 is outside 1-65535`
	)
	for _, tc := range []struct {
		name                 string
		lastError, rejection string
		want                 string
	}{
		{"neither", "", "", ""},
		{"a pass that failed", lastErr, "", lastErr},
		{"a state that was refused", "", rejection, "the node refused the desired state of the panel: " + rejection},
		{"both", lastErr, rejection, "the node refused the desired state of the panel: " + rejection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a.modify(n.GetId(), func(s *store.Node) { s.LastError, s.StateRejection = tc.lastError, tc.rejection })
			got, err := a.nodes.GetNode(ctx, connect.NewRequest(&panelv1.GetNodeRequest{Id: n.GetId()}))
			if err != nil {
				t.Fatalf("GetNode: %v", err)
			}
			if got.Msg.GetNode().GetLastError() != tc.want {
				t.Errorf("last_error = %q, want %q", got.Msg.GetNode().GetLastError(), tc.want)
			}
			list, err := a.nodes.ListNodes(ctx, connect.NewRequest(&panelv1.ListNodesRequest{}))
			if err != nil {
				t.Fatalf("ListNodes: %v", err)
			}
			if got := list.Msg.GetNodes()[0].GetLastError(); got != tc.want {
				t.Errorf("ListNodes: last_error = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUpdateNode(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	n := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443, LinkHost: "proxy.example.com"}).GetNode()
	id := n.GetId()
	a.modify(id, func(n *store.Node) {
		n.Status = store.NodeStatusOnline
		n.AgentVersion = "1.2.3"
		n.WatchCursor = 41
	})
	before := a.node(id)

	// A note alone: everything else stays.
	resp, err := a.nodes.UpdateNode(ctx, connect.NewRequest(&panelv1.UpdateNodeRequest{Id: id, Note: proto.String("rack 4")}))
	if err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if got := resp.Msg.GetNode(); got.GetNote() != "rack 4" || got.GetName() != "edge" || got.GetMgmtHost() != "192.0.2.10" ||
		got.GetMgmtPort() != 61443 || got.GetLinkHost() != "proxy.example.com" || got.GetStatus() != "online" {
		t.Errorf("UpdateNode(note) = %v", got)
	}
	after := a.node(id)
	if after.CertFingerprint != before.CertFingerprint || after.CertPEM != before.CertPEM ||
		after.WatchCursor != 41 || after.AgentVersion != "1.2.3" {
		t.Errorf("UpdateNode changed what it was not asked to: %+v", after)
	}

	// The connection settings and the names.
	_, err = a.nodes.UpdateNode(ctx, connect.NewRequest(&panelv1.UpdateNodeRequest{
		Id:       id,
		Name:     proto.String("edge 2"),
		MgmtHost: proto.String("198.51.100.20"),
		MgmtPort: proto.Uint32(62000),
		LinkHost: proto.String(""),
	}))
	if err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	after = a.node(id)
	if after.Name != "edge 2" || after.MgmtHost != "198.51.100.20" || after.MgmtPort != 62000 || after.LinkHost != "198.51.100.20" {
		t.Errorf("stored after update = %+v", after)
	}

	bad := []*panelv1.UpdateNodeRequest{
		{Id: id, Name: proto.String("")},
		{Id: id, MgmtHost: proto.String("not a host")},
		{Id: id, MgmtPort: proto.Uint32(0)},
		{Id: id, MgmtPort: proto.Uint32(70000)},
		{Id: id, LinkHost: proto.String("a..b")},
		{Id: id, Note: proto.String(strings.Repeat("n", 1025))},
	}
	for _, req := range bad {
		_, err := a.nodes.UpdateNode(ctx, connect.NewRequest(req))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	if got := a.node(id); got.Name != "edge 2" || got.MgmtPort != 62000 || got.Note != "rack 4" {
		t.Errorf("a refused update changed the node: %+v", got)
	}

	_, err = a.nodes.UpdateNode(ctx, connect.NewRequest(&panelv1.UpdateNodeRequest{Id: ids.New(), Note: proto.String("x")}))
	wantCode(t, err, connect.CodeNotFound)

	if notes := a.notes.got(); !slices.Equal(notes, []string{id, id, id}) {
		t.Errorf("notified %v, want the node once per create and update", notes)
	}
	if got := a.audit(); len(got) != 3 || !strings.HasPrefix(got[1], "node.update node:"+id) || !strings.HasPrefix(got[2], "node.update node:"+id) {
		t.Errorf("audit log = %q", got)
	}
}

func TestDeleteNode(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	id := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443}).GetNode().GetId()

	if _, err := a.nodes.DeleteNode(ctx, connect.NewRequest(&panelv1.DeleteNodeRequest{Id: id})); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	_, err := a.nodes.GetNode(ctx, connect.NewRequest(&panelv1.GetNodeRequest{Id: id}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = a.nodes.DeleteNode(ctx, connect.NewRequest(&panelv1.DeleteNodeRequest{Id: id}))
	wantCode(t, err, connect.CodeNotFound)

	if notes := a.notes.got(); !slices.Equal(notes, []string{id, id}) {
		t.Errorf("notified %v, want the node once on create and once on delete", notes)
	}
	if got := a.audit(); len(got) != 2 || got[1] != "node.delete node:"+id+" "+a.adminID {
		t.Errorf("audit log = %q", got)
	}
}

func TestNodeServiceNeedsAnAdmin(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()

	// Behind the middleware, as the panel serves it.
	_, err := a.anon.ListNodes(ctx, connect.NewRequest(&panelv1.ListNodesRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)

	// And on its own: the service does not rely on being mounted right.
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewNodeServiceHandler(a.svc))
	bare := httptest.NewServer(mux)
	t.Cleanup(bare.Close)
	client := panelv1connect.NewNodeServiceClient(&http.Client{Timeout: waitTimeout}, bare.URL)
	calls := []struct {
		name string
		call func() error
	}{
		{"ListNodes", func() error {
			_, err := client.ListNodes(ctx, connect.NewRequest(&panelv1.ListNodesRequest{}))
			return err
		}},
		{"GetNode", func() error {
			_, err := client.GetNode(ctx, connect.NewRequest(&panelv1.GetNodeRequest{Id: ids.New()}))
			return err
		}},
		{"CreateNode", func() error {
			_, err := client.CreateNode(ctx, connect.NewRequest(&panelv1.CreateNodeRequest{Name: "x", MgmtHost: "192.0.2.1", MgmtPort: 1}))
			return err
		}},
		{"UpdateNode", func() error {
			_, err := client.UpdateNode(ctx, connect.NewRequest(&panelv1.UpdateNodeRequest{Id: ids.New()}))
			return err
		}},
		{"DeleteNode", func() error {
			_, err := client.DeleteNode(ctx, connect.NewRequest(&panelv1.DeleteNodeRequest{Id: ids.New()}))
			return err
		}},
		{"GetNodeInstall", func() error {
			_, err := client.GetNodeInstall(ctx, connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: ids.New()}))
			return err
		}},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			wantCode(t, c.call(), connect.CodeUnauthenticated)
		})
	}
	if list, err := a.db.ListNodes(ctx); err != nil || len(list) != 0 {
		t.Errorf("nodes after anonymous calls: %v, %v", list, err)
	}
}

// wantInstallCommand is the install command of the API, word for word. <ARCH>
// is for the UI to fill in.
const wantInstallCommand = "tar -xf postern-node-kit-linux-<ARCH>.tar && sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node"

func TestGetNodeInstall(t *testing.T) {
	kit := newTestKit(t, "amd64") // the panel has the kit of amd64 only
	a := newAPI(t, WithKitDir(kit.dir))
	ctx := context.Background()
	created := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443})
	id := created.GetNode().GetId()

	resp, err := a.nodes.GetNodeInstall(ctx, connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: id}))
	if err != nil {
		t.Fatalf("GetNodeInstall: %v", err)
	}
	if version.Version == "" {
		t.Fatal("the panel has no version")
	}
	want := &panelv1.GetNodeInstallResponse{
		BundleUrl: "/api/nodes/" + id + "/bundle.tar",
		Kits: []*panelv1.NodeKit{
			{Arch: "amd64", Url: "/api/node-kit/amd64", Available: true, Version: version.Version},
			{Arch: "arm64", Url: "/api/node-kit/arm64", Available: false, Version: version.Version},
		},
		InstallCommand: wantInstallCommand,
	}
	if !proto.Equal(resp.Msg, want) {
		t.Errorf("GetNodeInstall = %v, want %v", resp.Msg, want)
	}
	// CreateNode words the command in the same way.
	if created.GetInstallCommand() != resp.Msg.GetInstallCommand() {
		t.Errorf("CreateNode gave the command %q, GetNodeInstall %q", created.GetInstallCommand(), resp.Msg.GetInstallCommand())
	}

	// What the panel has is looked at for each call, not once: a kit that turns
	// up later is offered.
	kit.addBinary("arm64")
	resp, err = a.nodes.GetNodeInstall(ctx, connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: id}))
	if err != nil {
		t.Fatalf("GetNodeInstall: %v", err)
	}
	for _, k := range resp.Msg.GetKits() {
		if !k.GetAvailable() {
			t.Errorf("the kit of %s is not available after it was added", k.GetArch())
		}
		// The URL is where the kit is served.
		r, body := request(t, a.web, http.MethodGet, a.srv.URL+k.GetUrl())
		if r.StatusCode != http.StatusOK || !bytes.Equal(checkKitTar(t, body)[0], kit.read(k.GetArch()+"/postern-node")) {
			t.Errorf("GET %s: status %d, or not the kit of %s", k.GetUrl(), r.StatusCode, k.GetArch())
		}
	}

	for _, unknown := range []string{ids.New(), ""} {
		_, err = a.nodes.GetNodeInstall(ctx, connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: unknown}))
		wantCode(t, err, connect.CodeNotFound)
	}
}

// A panel without a kit, run with go run, says so, and the rest is the same.
func TestGetNodeInstallWithoutAKit(t *testing.T) {
	a := newAPI(t)
	id := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443}).GetNode().GetId()

	resp, err := a.nodes.GetNodeInstall(context.Background(), connect.NewRequest(&panelv1.GetNodeInstallRequest{NodeId: id}))
	if err != nil {
		t.Fatalf("GetNodeInstall: %v", err)
	}
	want := &panelv1.GetNodeInstallResponse{
		BundleUrl: "/api/nodes/" + id + "/bundle.tar",
		Kits: []*panelv1.NodeKit{
			{Arch: "amd64", Url: "/api/node-kit/amd64", Available: false, Version: version.Version},
			{Arch: "arm64", Url: "/api/node-kit/arm64", Available: false, Version: version.Version},
		},
		InstallCommand: wantInstallCommand,
	}
	if !proto.Equal(resp.Msg, want) {
		t.Errorf("GetNodeInstall = %v, want %v", resp.Msg, want)
	}
}
