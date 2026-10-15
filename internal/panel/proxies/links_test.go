package proxies

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// webProxy stores a WEB proxy as slice 3 will, with its secret sealed.
func (e *env) webProxy(nodeID, listenerID, domain, basePath, mode, secret string) *store.Proxy {
	e.t.Helper()
	p := &store.Proxy{
		ID: ids.New(), NodeID: nodeID, ListenerID: listenerID, Type: store.ProxyTypeWeb, Name: "web", Enabled: true,
		Domain: domain, WebBasePath: basePath, WebSecretMode: mode,
	}
	sealed, err := seal.Seal(e.key, []byte(secret), []byte("proxy:"+p.ID))
	if err != nil {
		e.t.Fatal(err)
	}
	p.SecretEnc = sealed
	if err := e.db.CreateProxy(e.ctx, p); err != nil {
		e.t.Fatalf("CreateProxy: %v", err)
	}
	return p
}

// LinksOf gives the fake-TLS links that GetProxyLinks gives, byte for byte, and
// the parameters that a client is typed: the host, the port and the secret as
// it is in the link.
func TestLinksOfIsWhatGetProxyLinksGives(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "WWW.Example.COM", Secret: secret2})

	resp, err := e.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: p.GetId()}))
	if err != nil {
		t.Fatalf("GetProxyLinks: %v", err)
	}
	got, err := LinksOf(e.ctx, e.db, e.key, e.storedProxy(p.GetId()))
	if err != nil {
		t.Fatalf("LinksOf: %v", err)
	}
	want := links.FakeTLS{Host: "203.0.113.10", Port: uint16(l.GetPort()), SecretHex: secret2, Domain: "WWW.Example.COM"}
	if got.TG != want.TG() || got.TG != resp.Msg.GetTg() {
		t.Errorf("TG = %q, want %q (GetProxyLinks: %q)", got.TG, want.TG(), resp.Msg.GetTg())
	}
	if got.HTTPS != want.HTTPS() || got.HTTPS != resp.Msg.GetHttps() {
		t.Errorf("HTTPS = %q, want %q", got.HTTPS, want.HTTPS())
	}
	if got.QRSVG != resp.Msg.GetQrSvg() || !strings.HasPrefix(got.QRSVG, "<svg") {
		t.Error("QRSVG differs from GetProxyLinks")
	}
	if got.Server != "203.0.113.10" || got.Port != strconv.Itoa(int(l.GetPort())) || got.Secret != links.FakeTLSSecret(secret2, "WWW.Example.COM") {
		t.Errorf("parameters = %q %q %q", got.Server, got.Port, got.Secret)
	}
	// The same link again comes from the memo, and is the same image.
	again, err := LinksOf(e.ctx, e.db, e.key, e.storedProxy(p.GetId()))
	if err != nil || again != got {
		t.Errorf("a second LinksOf = %+v, %v; want the first", again, err)
	}
	e.assertNoSecretsLogged()
}

// A WEB proxy's links come from links.Web, with the base path; its parameters
// are the server, with the base path and without percent-encoding, and the
// secret as the link carries it; it has no port and needs no link host.
func TestLinksOfWeb(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.LinkHost = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, basePath, mode string
	}{
		{"root dd", "", links.ModeDD},
		{"root plain", "", links.ModePlain},
		{"base path dd", "telegram/web", links.ModeDD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := e.webProxy(n.ID, l.GetId(), "web.example.com", tc.basePath, tc.mode, secret1)
			got, err := LinksOf(e.ctx, e.db, e.key, p)
			if err != nil {
				t.Fatalf("LinksOf: %v", err)
			}
			w := links.Web{Domain: "web.example.com", BasePath: tc.basePath, SecretHex: secret1, Mode: tc.mode}
			wantTG, _ := w.TG()
			wantHTTPS, _ := w.HTTPS()
			wantSecret, _ := w.Secret()
			wantServer := "web.example.com"
			if tc.basePath != "" {
				wantServer += "/" + tc.basePath
			}
			if got.TG != wantTG || got.HTTPS != wantHTTPS {
				t.Errorf("links = %q %q, want %q %q", got.TG, got.HTTPS, wantTG, wantHTTPS)
			}
			if got.Server != wantServer || got.Port != "" || got.Secret != wantSecret {
				t.Errorf("parameters = %q %q %q, want %q, no port, %q", got.Server, got.Port, got.Secret, wantServer, wantSecret)
			}
			wantSVG, _ := QRSVG(wantTG)
			if got.QRSVG != wantSVG {
				t.Error("QRSVG is not the QR code of the tg link")
			}
		})
	}
	// A mode that links does not know is an error that holds no secret.
	p := e.webProxy(n.ID, l.GetId(), "web.example.com", "", "", secret1)
	if _, err := LinksOf(e.ctx, e.db, e.key, p); err == nil || strings.Contains(err.Error(), secret1) {
		t.Errorf("LinksOf with an empty mode: %v", err)
	}
}

func TestLinksOfErrors(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	stored := e.storedProxy(p.GetId())

	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.LinkHost = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := LinksOf(e.ctx, e.db, e.key, stored); !errors.Is(err, ErrNoLinkHost) {
		t.Errorf("without a link host: %v, want ErrNoLinkHost", err)
	}
	// A proxy whose secret the key does not open.
	var other seal.Key
	other[0] = 1
	if _, err := LinksOf(e.ctx, e.db, other, stored); !errors.Is(err, errSecret) {
		t.Errorf("with the wrong key: %v, want errSecret", err)
	}
	// A proxy whose listener is gone (as a record that was read before a delete).
	gone := *stored
	gone.ListenerID = "01K6Y00000000000000000000Z"
	if _, err := LinksOf(e.ctx, e.db, e.key, &gone); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("with a listener that is gone: %v, want ErrNotFound", err)
	}
}

// The memo of QR codes is bounded: it keeps the newest 256 links.
func TestQRMemoIsBounded(t *testing.T) {
	m := &qrMemo{svgs: map[string]string{}}
	for i := range qrMemoSize + 10 {
		if _, err := m.get("tg://proxy?server=203.0.113.1&port=" + strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.svgs) != qrMemoSize || len(m.order) != qrMemoSize {
		t.Errorf("memo holds %d codes and %d keys, want %d", len(m.svgs), len(m.order), qrMemoSize)
	}
	if _, ok := m.svgs["tg://proxy?server=203.0.113.1&port=0"]; ok {
		t.Error("the oldest link is still in the memo")
	}
	if _, ok := m.svgs["tg://proxy?server=203.0.113.1&port="+strconv.Itoa(qrMemoSize+9)]; !ok {
		t.Error("the newest link is not in the memo")
	}
}
