package nodes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
)

// get fetches a path of the API with a client.
func (a *api) get(client *http.Client, path string) (*http.Response, []byte) {
	a.t.Helper()
	resp, err := client.Get(a.srv.URL + path)
	if err != nil {
		a.t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.t.Fatalf("GET %s: %v", path, err)
	}
	return resp, body
}

func TestBundleDownload(t *testing.T) {
	a := newAPI(t)
	created := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443})
	id := created.GetNode().GetId()

	resp, body := a.get(a.web, created.GetBundleUrl())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-tar" {
		t.Errorf("Content-Type = %q, want application/x-tar", got)
	}
	disposition, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil || disposition != "attachment" || params["filename"] != "postern-node-bundle.tar" {
		t.Errorf("Content-Disposition = %q, want an attachment named postern-node-bundle.tar", resp.Header.Get("Content-Disposition"))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	b, err := pki.ParseBundleTar(body)
	if err != nil {
		t.Fatalf("the bundle does not parse: %v", err)
	}
	if b.NodeID != id || b.MgmtPort != 61443 {
		t.Errorf("bundle node %q port %d, want %q port 61443", b.NodeID, b.MgmtPort, id)
	}
	if !bytes.Equal(b.CAPEM, a.ca.CertPEM) {
		t.Error("the bundle does not carry the CA certificate")
	}

	// The certificate verifies against the CA and is the one whose fingerprint
	// the panel pins.
	stored := a.node(id)
	cert := parseCert(t, b.CertPEM)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b.CAPEM) {
		t.Fatal("the CA of the bundle does not parse")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the bundle certificate does not verify against the CA: %v", err)
	}
	fp, err := pki.Fingerprint(b.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if fp != stored.CertFingerprint {
		t.Errorf("bundle certificate fingerprint = %q, stored %q", fp, stored.CertFingerprint)
	}
	if _, err := tls.X509KeyPair(b.CertPEM, b.KeyPEM); err != nil {
		t.Errorf("the bundle key does not match its certificate: %v", err)
	}
	if _, err := pki.ServerTLSConfig(b.CAPEM, b.CertPEM, b.KeyPEM); err != nil {
		t.Errorf("the node cannot serve with the bundle: %v", err)
	}

	// The same bundle every time: the node certificate is not reissued.
	_, again := a.get(a.web, created.GetBundleUrl())
	if b2, err := pki.ParseBundleTar(again); err != nil || !bytes.Equal(b2.CertPEM, b.CertPEM) || !bytes.Equal(b2.KeyPEM, b.KeyPEM) {
		t.Errorf("a second download differs: %v", err)
	}

	if got, want := a.audit(), []string{
		"node.create node:" + id + " " + a.adminID,
		"node.bundle node:" + id + " " + a.adminID,
		"node.bundle node:" + id + " " + a.adminID,
	}; !slices.Equal(got, want) {
		t.Errorf("audit log = %q, want %q", got, want)
	}
	if logs := a.logs.String(); strings.Contains(logs, "PRIVATE KEY") {
		t.Error("the log holds a private key")
	}
}

func TestBundleDownloadNeedsAnAdmin(t *testing.T) {
	a := newAPI(t)
	created := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443})

	resp, body := a.get(&http.Client{Timeout: waitTimeout}, created.GetBundleUrl())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, []byte("CERTIFICATE")) {
		t.Error("an anonymous request got key material")
	}

	// A session cookie that is not a session is no better.
	req, err := http.NewRequest(http.MethodGet, a.srv.URL+created.GetBundleUrl(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: strings.Repeat("A", 43)})
	resp2, err := (&http.Client{Timeout: waitTimeout}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("status with a forged cookie = %d, want 401", resp2.StatusCode)
	}

	// The handler asks for an admin itself, whatever it is mounted behind.
	mux := http.NewServeMux()
	mux.Handle(BundleRoute, a.svc.BundleHandler())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, created.GetBundleUrl(), nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status without the middleware = %d, want 401", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Error("a request without the middleware got key material")
	}
}

func TestBundleDownloadOfMissingBundles(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()

	resp, _ := a.get(a.web, BundleURL(ids.New()))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown node: status = %d, want 404", resp.StatusCode)
	}

	// A node without a certificate (imported, say) has no bundle to give.
	bare := &store.Node{Name: "bare", MgmtHost: "192.0.2.5", MgmtPort: 61443}
	if err := a.db.CreateNode(ctx, bare); err != nil {
		t.Fatal(err)
	}
	resp, body := a.get(a.web, BundleURL(bare.ID))
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("node without a certificate: status = %d (%q), want 409", resp.StatusCode, body)
	}
}

func TestBundleURL(t *testing.T) {
	if got, want := BundleURL("01JABCDEFGHJKMNPQRSTVWXYZ0"), "/api/nodes/01JABCDEFGHJKMNPQRSTVWXYZ0/bundle.tar"; got != want {
		t.Errorf("BundleURL = %q, want %q", got, want)
	}
}
