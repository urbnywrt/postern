package proxies

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/panel/store"
)

var lowerHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// nodeWithListener is a node with one listener on 0.0.0.0:443.
func (e *env) nodeWithListener() (*store.Node, *panelv1.Listener) {
	e.t.Helper()
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	return n, l
}

func TestCreateProxyPicksAPoolDomainAndARandomSecret(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	gen := e.generation(n.ID)

	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Name: " Phone ", Note: "for testing"})
	if !slices.Contains(testPool, p.GetDomain()) {
		t.Errorf("domain %q is not one of the pool %v", p.GetDomain(), testPool)
	}
	want := &panelv1.Proxy{
		Id:             p.GetId(),
		NodeId:         n.ID,
		ListenerId:     l.GetId(),
		Type:           "faketls",
		Name:           "Phone",
		Note:           "for testing",
		Enabled:        true,
		Domain:         p.GetDomain(),
		Limits:         &panelv1.ProxyLimits{},
		Engine:         "telemt",
		EngineVersion:  DefaultTelemtVersion,
		VersionSource:  "channel",
		Channel:        "stable",
		UseMiddleProxy: "auto",
		Status:         &panelv1.ProxyStatus{Phase: "unknown"},
		CreatedUnix:    p.GetCreatedUnix(),
		UpdatedUnix:    p.GetUpdatedUnix(),
	}
	if !proto.Equal(p, want) {
		t.Errorf("proxy = %v\nwant %v", p, want)
	}
	secret := e.secretOf(p.GetId())
	if !lowerHex32.MatchString(secret) {
		t.Errorf("the random secret is not 32 lower-case hex digits (%d characters)", len(secret))
	}
	stored := e.storedProxy(p.GetId())
	if stored.EngineVersionPolicy != store.EnginePolicyChannel || stored.EngineVersion != "" || !stored.Enabled {
		t.Errorf("stored proxy: policy %q, version %q, enabled %v", stored.EngineVersionPolicy, stored.EngineVersion, stored.Enabled)
	}
	if g := e.generation(n.ID); g != gen+1 {
		t.Errorf("desired generation = %d, want %d", g, gen+1)
	}

	// Another proxy gets another secret and another domain.
	q := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	if q.GetDomain() == p.GetDomain() {
		t.Errorf("two proxies of one listener got the domain %q", q.GetDomain())
	}
	if e.secretOf(q.GetId()) == secret {
		t.Error("two proxies got the same random secret")
	}
	e.assertNoSecretsLogged()
}

func TestCreateProxyUsesUpThePool(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	// A domain of the pool in other letter case is taken all the same.
	taken := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "B.EXAMPLE"})
	if taken.GetDomain() != "B.EXAMPLE" {
		t.Fatalf("domain = %q, want it as given", taken.GetDomain())
	}

	seen := map[string]bool{"b.example": true}
	for range len(testPool) - 1 {
		p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
		d := strings.ToLower(p.GetDomain())
		if seen[d] {
			t.Fatalf("the pool gave %q twice on one listener", d)
		}
		seen[d] = true
	}
	_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)

	// Another listener has the whole pool again.
	l2 := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})
	if p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l2.GetId()}); !slices.Contains(testPool, p.GetDomain()) {
		t.Errorf("domain %q is not one of the pool", p.GetDomain())
	}
}

func TestTheDefaultPool(t *testing.T) {
	db := newEnv(t).db
	svc := NewService(db, [32]byte{}, NewCatalog(nil, nil), nil, nil, nil)
	if !slices.Equal(svc.pool, DefaultDomainPool) {
		t.Errorf("the pool of a new service is %v, want DefaultDomainPool", svc.pool)
	}
	if len(DefaultDomainPool) != 8 {
		t.Errorf("DefaultDomainPool has %d domains, want 8", len(DefaultDomainPool))
	}
	for _, d := range DefaultDomainPool {
		if _, err := checkDomain(d); err != nil {
			t.Errorf("pool domain %q: %v", d, err)
		}
	}
	b := NewStateBuilder(db, [32]byte{}, NewCatalog(nil, nil), nil)
	if !slices.Equal(b.pool, DefaultDomainPool) {
		t.Errorf("the pool of a new state builder is %v, want DefaultDomainPool", b.pool)
	}
}

func TestCreateProxyKeepsWhatItIsGiven(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{
		NodeId:        n.ID,
		ListenerId:    l.GetId(),
		Domain:        " WWW.Example.COM ",
		Secret:        secret2,
		Limits:        &panelv1.ProxyLimits{Devices: 3, ConnsTotal: 100, ConnsPerIp: 10},
		AdTag:         adTag1,
		EngineVersion: DefaultTelemtVersion,
	})
	if p.GetDomain() != "WWW.Example.COM" {
		t.Errorf("domain = %q, want WWW.Example.COM", p.GetDomain())
	}
	if !proto.Equal(p.GetLimits(), &panelv1.ProxyLimits{Devices: 3, ConnsTotal: 100, ConnsPerIp: 10}) {
		t.Errorf("limits = %v", p.GetLimits())
	}
	if p.GetAdTag() != adTag1 || p.GetEngineVersion() != DefaultTelemtVersion || !p.GetEngineVersionPinned() {
		t.Errorf("ad tag %q, version %q, pinned %v", p.GetAdTag(), p.GetEngineVersion(), p.GetEngineVersionPinned())
	}
	if got := e.secretOf(p.GetId()); got != secret2 {
		t.Error("the secret was not stored as it was given (upper case kept)")
	}
	stored := e.storedProxy(p.GetId())
	if stored.EngineVersionPolicy != store.EnginePolicyPinned || stored.EngineVersion != DefaultTelemtVersion {
		t.Errorf("stored policy %q, version %q", stored.EngineVersionPolicy, stored.EngineVersion)
	}
	if stored.LimitDevices != 3 || stored.LimitConnsTotal != 100 || stored.LimitConnsPerIP != 10 || stored.AdTag != adTag1 {
		t.Errorf("stored proxy = %+v", stored)
	}
	e.assertNoSecretsLogged()
}

func TestCreateProxyRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	other := e.addNode("n2", "203.0.113.20")
	otherListener := e.createListener(&panelv1.CreateListenerRequest{NodeId: other.ID, Port: 443})
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "taken.example.com"})
	gen, calls := e.generation(n.ID), e.notes.count()

	base := func(mod func(r *panelv1.CreateProxyRequest)) *panelv1.CreateProxyRequest {
		r := &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "new.example.com"}
		mod(r)
		return r
	}
	tests := []struct {
		name string
		req  *panelv1.CreateProxyRequest
		code connect.Code
	}{
		{"short secret", base(func(r *panelv1.CreateProxyRequest) { r.Secret = secret1[:31] }), connect.CodeInvalidArgument},
		{"long secret", base(func(r *panelv1.CreateProxyRequest) { r.Secret = secret1 + "0" }), connect.CodeInvalidArgument},
		{"secret not hex", base(func(r *panelv1.CreateProxyRequest) { r.Secret = "g" + secret1[1:] }), connect.CodeInvalidArgument},
		{"ad tag not hex", base(func(r *panelv1.CreateProxyRequest) { r.AdTag = "z" + adTag1[1:] }), connect.CodeInvalidArgument},
		{"ad tag too short", base(func(r *panelv1.CreateProxyRequest) { r.AdTag = adTag1[:16] }), connect.CodeInvalidArgument},
		{"domain with a space", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "new example.com" }), connect.CodeInvalidArgument},
		{"domain with a scheme", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "https://new.example.com" }), connect.CodeInvalidArgument},
		{"domain is an IP address", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "203.0.113.5" }), connect.CodeInvalidArgument},
		{"domain with an empty label", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "new..example.com" }), connect.CodeInvalidArgument},
		{"domain with a leading hyphen", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "-new.example.com" }), connect.CodeInvalidArgument},
		{"domain with a trailing dot", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "new.example.com." }), connect.CodeInvalidArgument},
		{"domain with an underscore", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "new_1.example.com" }), connect.CodeInvalidArgument},
		{"domain not ASCII", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "пример.example" }), connect.CodeInvalidArgument},
		{"domain too long", base(func(r *panelv1.CreateProxyRequest) { r.Domain = strings.Repeat("a.", 127) + "example" }), connect.CodeInvalidArgument},
		{"name too long", base(func(r *panelv1.CreateProxyRequest) { r.Name = strings.Repeat("я", 65) }), connect.CodeInvalidArgument},
		{"name with a control character", base(func(r *panelv1.CreateProxyRequest) { r.Name = "a\x00b" }), connect.CodeInvalidArgument},
		{"note too long", base(func(r *panelv1.CreateProxyRequest) { r.Note = strings.Repeat("n", 1025) }), connect.CodeInvalidArgument},
		{"unknown engine version", base(func(r *panelv1.CreateProxyRequest) { r.EngineVersion = "9.9.9" }), connect.CodeInvalidArgument},
		{"unknown middle-proxy setting", base(func(r *panelv1.CreateProxyRequest) { r.UseMiddleProxy = "maybe" }), connect.CodeInvalidArgument},
		{"middle-proxy setting in capitals", base(func(r *panelv1.CreateProxyRequest) { r.UseMiddleProxy = "ON" }), connect.CodeInvalidArgument},
		{"middle-proxy setting that is a bool", base(func(r *panelv1.CreateProxyRequest) { r.UseMiddleProxy = "true" }), connect.CodeInvalidArgument},
		{"domain taken", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "taken.example.com" }), connect.CodeAlreadyExists},
		{"domain taken in other case", base(func(r *panelv1.CreateProxyRequest) { r.Domain = "Taken.Example.COM" }), connect.CodeAlreadyExists},
		{"listener of another node", base(func(r *panelv1.CreateProxyRequest) { r.ListenerId = otherListener.GetId() }), connect.CodeNotFound},
		{"unknown listener", base(func(r *panelv1.CreateProxyRequest) { r.ListenerId = "01K6Y00000000000000000000Z" }), connect.CodeNotFound},
		{"unknown node", base(func(r *panelv1.CreateProxyRequest) { r.NodeId = "01K6Y00000000000000000000Z" }), connect.CodeNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, tc.code)
		})
	}
	if g := e.generation(n.ID); g != gen {
		t.Errorf("desired generation = %d after refused calls, want %d", g, gen)
	}
	if c := e.notes.count(); c != calls {
		t.Errorf("%d notifications after refused calls, want %d", c, calls)
	}
	list, err := e.db.ListProxies(e.ctx, store.ProxyFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("%d proxies stored, want 1", len(list))
	}
	e.assertNoSecretsLogged()
}

// TestDomainsAreComparedAsTheEdgeComparesThem: the edge folds the case of a
// server name and drops one dot at its end, and refuses its whole table for
// two routes of one name; so does the panel when it compares domains, also
// against a row that the service would not have written.
func TestDomainsAreComparedAsTheEdgeComparesThem(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	id := "01K6Y0000000000000000000C1"
	if err := e.db.CreateProxy(e.ctx, &store.Proxy{
		ID: id, NodeID: n.ID, ListenerID: l.GetId(), Enabled: true, Domain: "dot.example.com.",
		SecretEnc: e.sealSecret(id, secret1),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: n.ID, ListenerId: l.GetId(), Domain: "Dot.Example.COM",
	}))
	wantCode(t, err, connect.CodeAlreadyExists)

	// A domain of the pool that a row has with a dot at the end is taken.
	e.svc.pool = []string{"dot.example.com", "free.example.com"}
	for range 5 {
		p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
		if p.GetDomain() != "free.example.com" {
			t.Fatalf("the pool gave %q, want the free domain", p.GetDomain())
		}
		if _, err := e.proxies.DeleteProxy(e.ctx, connect.NewRequest(&panelv1.DeleteProxyRequest{Id: p.GetId()})); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProxyLinksMatchTheLinkBuilder(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	override := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443, LinkHostOverride: "2001:db8::10"})

	tests := []struct {
		name     string
		listener *panelv1.Listener
		host     string
		domain   string
		secret   string
	}{
		{"node link host", l, "203.0.113.10", "WWW.Example.COM", secret2},
		{"listener override", override, "2001:db8::10", "cdn.example.com", secret1},
		{"random secret and pool domain", l, "203.0.113.10", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := e.createProxy(&panelv1.CreateProxyRequest{
				NodeId: n.ID, ListenerId: tc.listener.GetId(), Domain: tc.domain, Secret: tc.secret,
			})
			resp, err := e.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: p.GetId()}))
			if err != nil {
				t.Fatalf("GetProxyLinks: %v", err)
			}
			stored := e.storedProxy(p.GetId())
			want := links.FakeTLS{
				Host:      tc.host,
				Port:      uint16(tc.listener.GetPort()),
				SecretHex: e.secretOf(p.GetId()),
				Domain:    stored.Domain,
			}
			if got := resp.Msg.GetTg(); got != want.TG() {
				t.Errorf("tg = %q\nwant %q", got, want.TG())
			}
			if got := resp.Msg.GetHttps(); got != want.HTTPS() {
				t.Errorf("https = %q\nwant %q", got, want.HTTPS())
			}
			wantSVG, err := QRSVG(want.TG())
			if err != nil {
				t.Fatalf("QRSVG: %v", err)
			}
			if resp.Msg.GetQrSvg() != wantSVG {
				t.Error("qr_svg is not the QR code of the tg link")
			}
		})
	}
	// The secret is in the links and nowhere in the log.
	e.assertNoSecretsLogged()
}

func TestProxyLinksNeedALinkHost(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.LinkHost = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	_, err := e.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: p.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	_, err = e.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestUpdateProxy(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	l2 := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "one.example.com", Secret: secret1})
	q := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "two.example.com"})
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l2.GetId(), Domain: "three.example.com"})

	update := func(req *panelv1.UpdateProxyRequest) *panelv1.Proxy {
		t.Helper()
		gen := e.generation(n.ID)
		resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatalf("UpdateProxy(%v): %v", req, err)
		}
		if g := e.generation(n.ID); g != gen+1 {
			t.Errorf("desired generation = %d, want %d", g, gen+1)
		}
		return resp.Msg.GetProxy()
	}

	got := update(&panelv1.UpdateProxyRequest{
		Id:     p.GetId(),
		Name:   proto.String("renamed"),
		Domain: proto.String("Renamed.Example.COM"),
		Limits: &panelv1.ProxyLimits{ConnsPerIp: 4},
		AdTag:  proto.String(adTag1),
	})
	if got.GetName() != "renamed" || got.GetDomain() != "Renamed.Example.COM" || got.GetLimits().GetConnsPerIp() != 4 ||
		got.GetAdTag() != adTag1 || got.GetNote() != "" || !got.GetEnabled() {
		t.Errorf("updated proxy = %v", got)
	}
	if e.secretOf(p.GetId()) != secret1 {
		t.Error("the secret changed although the request did not set it")
	}

	// An empty secret is a new random one, an empty domain a new pool domain.
	got = update(&panelv1.UpdateProxyRequest{Id: p.GetId(), Secret: proto.String(""), Domain: proto.String("")})
	if s := e.secretOf(p.GetId()); s == secret1 || !lowerHex32.MatchString(s) {
		t.Error("an empty secret did not make a new random one")
	}
	if !slices.Contains(testPool, got.GetDomain()) {
		t.Errorf("domain %q is not one of the pool", got.GetDomain())
	}

	// Pinning and following again.
	got = update(&panelv1.UpdateProxyRequest{Id: p.GetId(), EngineVersion: proto.String(DefaultTelemtVersion)})
	if !got.GetEngineVersionPinned() || got.GetEngineVersion() != DefaultTelemtVersion {
		t.Errorf("after pinning: version %q pinned %v", got.GetEngineVersion(), got.GetEngineVersionPinned())
	}
	got = update(&panelv1.UpdateProxyRequest{Id: p.GetId(), EngineVersion: proto.String("")})
	if got.GetEngineVersionPinned() || got.GetEngineVersion() != DefaultTelemtVersion {
		t.Errorf("after unpinning: version %q pinned %v", got.GetEngineVersion(), got.GetEngineVersionPinned())
	}

	// Moving to another listener keeps the domain when it is free there.
	got = update(&panelv1.UpdateProxyRequest{Id: q.GetId(), ListenerId: proto.String(l2.GetId())})
	if got.GetListenerId() != l2.GetId() || got.GetDomain() != "two.example.com" {
		t.Errorf("moved proxy = %v", got)
	}

	gen := e.generation(n.ID)
	for _, tc := range []struct {
		name string
		req  *panelv1.UpdateProxyRequest
		code connect.Code
	}{
		{"domain of another proxy", &panelv1.UpdateProxyRequest{Id: q.GetId(), Domain: proto.String("THREE.example.com")}, connect.CodeAlreadyExists},
		{"bad secret", &panelv1.UpdateProxyRequest{Id: p.GetId(), Secret: proto.String("abc")}, connect.CodeInvalidArgument},
		{"bad ad tag", &panelv1.UpdateProxyRequest{Id: p.GetId(), AdTag: proto.String("abc")}, connect.CodeInvalidArgument},
		{"bad domain", &panelv1.UpdateProxyRequest{Id: p.GetId(), Domain: proto.String("a b")}, connect.CodeInvalidArgument},
		{"bad name", &panelv1.UpdateProxyRequest{Id: p.GetId(), Name: proto.String("a\nb")}, connect.CodeInvalidArgument},
		{"unknown version", &panelv1.UpdateProxyRequest{Id: p.GetId(), EngineVersion: proto.String("0.0.1")}, connect.CodeInvalidArgument},
		{"unknown middle-proxy setting", &panelv1.UpdateProxyRequest{Id: p.GetId(), UseMiddleProxy: proto.String("maybe")}, connect.CodeInvalidArgument},
		{"unknown listener", &panelv1.UpdateProxyRequest{Id: p.GetId(), ListenerId: proto.String("01K6Y00000000000000000000Z")}, connect.CodeNotFound},
		{"unknown proxy", &panelv1.UpdateProxyRequest{Id: "01K6Y00000000000000000000Z", Name: proto.String("x")}, connect.CodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, tc.code)
		})
	}
	if g := e.generation(n.ID); g != gen {
		t.Errorf("desired generation = %d after refused updates, want %d", g, gen)
	}

	// A proxy that moves onto a listener whose proxy has its domain is refused.
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "four.example.com"})
	r := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l2.GetId(), Domain: "Four.Example.com"})
	_, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: r.GetId(), ListenerId: proto.String(l.GetId())}))
	wantCode(t, err, connect.CodeAlreadyExists)
	e.assertNoSecretsLogged()
}

func TestUpdateProxyWithoutAChangeKeepsTheGeneration(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "one.example.com", Name: "x"})
	gen := e.generation(n.ID)
	resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{
		Id: p.GetId(), Name: proto.String("x"), Domain: proto.String("one.example.com"),
	}))
	if err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if resp.Msg.GetProxy().GetUpdatedUnix() != p.GetUpdatedUnix() {
		t.Error("the proxy was written although nothing changed")
	}
	if g := e.generation(n.ID); g != gen {
		t.Errorf("desired generation = %d, want %d: nothing changed", g, gen)
	}
}

// middleProxyOf is whether the state that the panel builds for a node tells the
// node to start the engine of a proxy with the middle proxies of Telegram.
func (e *env) middleProxyOf(nodeID, proxyID string) bool {
	e.t.Helper()
	st, err := e.builder.Build(e.ctx, nodeID, 1)
	if err != nil {
		e.t.Fatalf("Build: %v", err)
	}
	for _, p := range st.GetProxies() {
		if p.GetId() == proxyID {
			return p.GetUseMiddleProxy()
		}
	}
	e.t.Fatalf("the state of node %s has no proxy %s", nodeID, proxyID)
	return false
}

// A proxy says whether its engine goes through the middle proxies of Telegram:
// "on", "off", or "auto", which is also what empty means, and which is on when the
// proxy has an ad tag, as every proxy did before it could say.
func TestProxyMiddleProxySetting(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	tests := []struct {
		name, setting, adTag string
		want                 string // what the proxy reports
		wantOn               bool   // what the node is told
	}{
		{"nothing said, no ad tag", "", "", "auto", false},
		{"nothing said, an ad tag", "", adTag1, "auto", true},
		{"auto, no ad tag", "auto", "", "auto", false},
		{"auto, an ad tag", "auto", adTag1, "auto", true},
		{"on, no ad tag", "on", "", "on", true},
		{"on, an ad tag", "on", adTag1, "on", true},
		{"off, no ad tag", "off", "", "off", false},
		{"off, an ad tag", "off", adTag1, "off", false},
		{"spaces around it", " on ", "", "on", true},
	}
	var ids []string
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := e.createProxy(&panelv1.CreateProxyRequest{
				NodeId: n.ID, ListenerId: l.GetId(), Domain: fmt.Sprintf("p%d.example.com", i), AdTag: tc.adTag, UseMiddleProxy: tc.setting,
			})
			ids = append(ids, p.GetId())
			if p.GetUseMiddleProxy() != tc.want {
				t.Errorf("CreateProxy reports %q, want %q", p.GetUseMiddleProxy(), tc.want)
			}
			got, err := e.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: p.GetId()}))
			if err != nil {
				t.Fatal(err)
			}
			if got.Msg.GetProxy().GetUseMiddleProxy() != tc.want {
				t.Errorf("GetProxy reports %q, want %q", got.Msg.GetProxy().GetUseMiddleProxy(), tc.want)
			}
			if stored := e.storedProxy(p.GetId()).UseMiddleProxy; stored != tc.want {
				t.Errorf("stored %q, want %q", stored, tc.want)
			}
			if on := e.middleProxyOf(n.ID, p.GetId()); on != tc.wantOn {
				t.Errorf("the node is told use_middle_proxy = %v, want %v", on, tc.wantOn)
			}
		})
	}
	list, err := e.proxies.ListProxies(e.ctx, connect.NewRequest(&panelv1.ListProxiesRequest{NodeId: n.ID}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetProxies()) != len(tests) {
		t.Fatalf("ListProxies has %d proxies, want %d", len(list.Msg.GetProxies()), len(tests))
	}
	for i, p := range list.Msg.GetProxies() {
		if p.GetId() != ids[i] || p.GetUseMiddleProxy() != tests[i].want {
			t.Errorf("ListProxies[%d] = %s, %q, want %s, %q", i, p.GetId(), p.GetUseMiddleProxy(), ids[i], tests[i].want)
		}
	}
}

func TestUpdateProxyMiddleProxySetting(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "one.example.com", AdTag: adTag1})
	id := p.GetId()

	steps := []struct {
		name    string
		req     *panelv1.UpdateProxyRequest
		want    string
		wantOn  bool
		changes bool // a new desired generation
	}{
		{"off, although it has an ad tag", &panelv1.UpdateProxyRequest{UseMiddleProxy: proto.String("off")}, "off", false, true},
		{"off again", &panelv1.UpdateProxyRequest{UseMiddleProxy: proto.String("off")}, "off", false, false},
		{"on", &panelv1.UpdateProxyRequest{UseMiddleProxy: proto.String("on")}, "on", true, true},
		{"empty is auto, which follows the ad tag", &panelv1.UpdateProxyRequest{UseMiddleProxy: proto.String("")}, "auto", true, true},
		{"auto again", &panelv1.UpdateProxyRequest{UseMiddleProxy: proto.String("auto")}, "auto", true, false},
		{"not set, so as it is", &panelv1.UpdateProxyRequest{Name: proto.String("renamed")}, "auto", true, true},
		{"the ad tag goes, and auto follows it", &panelv1.UpdateProxyRequest{AdTag: proto.String("")}, "auto", false, true},
		{"on without an ad tag", &panelv1.UpdateProxyRequest{UseMiddleProxy: proto.String("on")}, "on", true, true},
		{"on, with other changes at once", &panelv1.UpdateProxyRequest{UseMiddleProxy: proto.String("on"), Note: proto.String("n")}, "on", true, true},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			gen := e.generation(n.ID)
			s.req.Id = id
			resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(s.req))
			if err != nil {
				t.Fatalf("UpdateProxy: %v", err)
			}
			if got := resp.Msg.GetProxy().GetUseMiddleProxy(); got != s.want {
				t.Errorf("the answer has %q, want %q", got, s.want)
			}
			if got := e.storedProxy(id).UseMiddleProxy; got != s.want {
				t.Errorf("stored %q, want %q", got, s.want)
			}
			if on := e.middleProxyOf(n.ID, id); on != s.wantOn {
				t.Errorf("the node is told use_middle_proxy = %v, want %v", on, s.wantOn)
			}
			wantGen := gen
			if s.changes {
				wantGen++
			}
			if g := e.generation(n.ID); g != wantGen {
				t.Errorf("desired generation = %d, want %d", g, wantGen)
			}
		})
	}

	// What is refused changes nothing.
	gen, before := e.generation(n.ID), e.storedProxy(id).UseMiddleProxy
	for _, bad := range []string{"maybe", "ON", "On", "true", "false", "1", "yes", "auto,on"} {
		_, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: id, UseMiddleProxy: proto.String(bad)}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	if g := e.generation(n.ID); g != gen {
		t.Errorf("desired generation = %d after refused updates, want %d", g, gen)
	}
	if got := e.storedProxy(id).UseMiddleProxy; got != before {
		t.Errorf("a refused update changed the setting to %q", got)
	}
	e.assertNoSecretsLogged()
}

func TestSetProxyEnabled(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	gen := e.generation(n.ID)

	resp, err := e.proxies.SetProxyEnabled(e.ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: p.GetId(), Enabled: false}))
	if err != nil {
		t.Fatalf("SetProxyEnabled: %v", err)
	}
	if resp.Msg.GetProxy().GetEnabled() || e.storedProxy(p.GetId()).Enabled {
		t.Error("the proxy is still enabled")
	}
	if g := e.generation(n.ID); g != gen+1 {
		t.Errorf("desired generation = %d, want %d", g, gen+1)
	}
	// Pausing a paused proxy changes nothing.
	if _, err := e.proxies.SetProxyEnabled(e.ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: p.GetId(), Enabled: false})); err != nil {
		t.Fatalf("SetProxyEnabled: %v", err)
	}
	if g := e.generation(n.ID); g != gen+1 {
		t.Errorf("desired generation = %d, want %d: nothing changed", g, gen+1)
	}
	resp, err = e.proxies.SetProxyEnabled(e.ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: p.GetId(), Enabled: true}))
	if err != nil {
		t.Fatalf("SetProxyEnabled: %v", err)
	}
	if !resp.Msg.GetProxy().GetEnabled() {
		t.Error("the proxy was not enabled again")
	}
	_, err = e.proxies.SetProxyEnabled(e.ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestDeleteProxy(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	gen := e.generation(n.ID)
	if _, err := e.proxies.DeleteProxy(e.ctx, connect.NewRequest(&panelv1.DeleteProxyRequest{Id: p.GetId()})); err != nil {
		t.Fatalf("DeleteProxy: %v", err)
	}
	if g := e.generation(n.ID); g != gen+1 {
		t.Errorf("desired generation = %d, want %d", g, gen+1)
	}
	_, err := e.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: p.GetId()}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = e.proxies.DeleteProxy(e.ctx, connect.NewRequest(&panelv1.DeleteProxyRequest{Id: p.GetId()}))
	wantCode(t, err, connect.CodeNotFound)
	// The listener is free again.
	if _, err := e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: l.GetId()})); err != nil {
		t.Errorf("DeleteListener after the proxy went: %v", err)
	}
}

func TestListAndGetProxies(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	other := e.addNode("n2", "203.0.113.20")
	ol := e.createListener(&panelv1.CreateListenerRequest{NodeId: other.ID, Port: 443})
	p1 := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Name: "Alice", Domain: "one.example.com"})
	p2 := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Note: "office ALICE", Domain: "two.example.com"})
	p3 := e.createProxy(&panelv1.CreateProxyRequest{NodeId: other.ID, ListenerId: ol.GetId(), Name: "Bob", Domain: "alice.example"})

	ids := func(req *panelv1.ListProxiesRequest) []string {
		t.Helper()
		resp, err := e.proxies.ListProxies(e.ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatalf("ListProxies: %v", err)
		}
		var out []string
		for _, p := range resp.Msg.GetProxies() {
			out = append(out, p.GetId())
		}
		return out
	}
	for _, tc := range []struct {
		name string
		req  *panelv1.ListProxiesRequest
		want []string
	}{
		{"all", &panelv1.ListProxiesRequest{}, []string{p1.GetId(), p2.GetId(), p3.GetId()}},
		{"one node", &panelv1.ListProxiesRequest{NodeId: n.ID}, []string{p1.GetId(), p2.GetId()}},
		{"query across name, note and domain", &panelv1.ListProxiesRequest{Query: "alice"}, []string{p1.GetId(), p2.GetId(), p3.GetId()}},
		{"query and node", &panelv1.ListProxiesRequest{NodeId: other.ID, Query: "ALICE"}, []string{p3.GetId()}},
		{"query by id", &panelv1.ListProxiesRequest{Query: strings.ToLower(p2.GetId())}, []string{p2.GetId()}},
		{"no match", &panelv1.ListProxiesRequest{Query: "carol"}, nil},
		{"unknown node", &panelv1.ListProxiesRequest{NodeId: "01K6Y00000000000000000000Z"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ids(tc.req); !slices.Equal(got, tc.want) {
				t.Errorf("ids = %v, want %v", got, tc.want)
			}
		})
	}

	resp, err := e.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: p1.GetId()}))
	if err != nil {
		t.Fatalf("GetProxy: %v", err)
	}
	if !proto.Equal(resp.Msg.GetProxy(), p1) {
		t.Errorf("GetProxy = %v, want %v", resp.Msg.GetProxy(), p1)
	}
}

// TestMutationsWriteBeforeTheyRaiseTheGeneration checks the order that the
// node manager depends on: a mutation commits its change, then raises the
// generation, then notifies. Build(gen) stamps whatever it reads with gen,
// and a generation that a node accepted is never pushed again, so a state
// built when the generation goes up must already have the change.
func TestMutationsWriteBeforeTheyRaiseTheGeneration(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")

	// summary is what a state built at the moment the generation goes up
	// holds: the listeners, and per proxy its listener, domain, secret and
	// whether it is enabled.
	var atBump []string
	e.svc.nextGen = func(ctx context.Context, nodeID string) (uint64, error) {
		// The mutation holds the lock of the node data here, so this reads
		// the data as Build would, without taking the lock again.
		nd, err := loadNodeData(ctx, e.db, e.key, nodeID)
		var st *nodev1.NodeState
		if err == nil {
			st, err = e.builder.build(ctx, nd, 1)
		}
		if err != nil {
			t.Errorf("build at the bump: %v", err)
			return e.db.NextNodeGeneration(ctx, nodeID)
		}
		atBump = append(atBump, summary(st))
		return e.db.NextNodeGeneration(ctx, nodeID)
	}

	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "one.example.com", Secret: secret1})
	if _, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), Domain: proto.String("two.example.com"), Secret: proto.String(secret2)})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.proxies.SetProxyEnabled(e.ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: p.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: l.GetId(), Port: proto.Uint32(8443)})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.proxies.DeleteProxy(e.ctx, connect.NewRequest(&panelv1.DeleteProxyRequest{Id: p.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.listeners.DeleteListener(e.ctx, connect.NewRequest(&panelv1.DeleteListenerRequest{Id: l.GetId()})); err != nil {
		t.Fatal(err)
	}

	lid, pid := l.GetId(), p.GetId()
	want := []string{
		fmt.Sprintf("listeners [%s:443]; proxies []", lid),
		fmt.Sprintf("listeners [%s:443]; proxies [%s@%s one.example.com %s on]", lid, pid, lid, secret1),
		fmt.Sprintf("listeners [%s:443]; proxies [%s@%s two.example.com %s on]", lid, pid, lid, secret2),
		fmt.Sprintf("listeners [%s:443]; proxies [%s@%s two.example.com %s off]", lid, pid, lid, secret2),
		fmt.Sprintf("listeners [%s:8443]; proxies [%s@%s two.example.com %s off]", lid, pid, lid, secret2),
		fmt.Sprintf("listeners [%s:8443]; proxies []", lid),
		"listeners []; proxies []",
	}
	if !slices.Equal(atBump, want) {
		t.Errorf("states at the bumps:\n%s\nwant:\n%s", strings.Join(atBump, "\n"), strings.Join(want, "\n"))
	}
	// Each notification comes after its bump: the node already has the new
	// generation when the manager hears of it.
	if got, want := e.notes.generations(), []uint64{1, 2, 3, 4, 5, 6, 7}; !slices.Equal(got, want) {
		t.Errorf("desired generation at each notification = %v, want %v", got, want)
	}
}

// summary describes a node state in one line, for TestMutationsWriteBeforeTheyRaiseTheGeneration.
func summary(st *nodev1.NodeState) string {
	var ls, ps []string
	for _, l := range st.GetListeners() {
		ls = append(ls, fmt.Sprintf("%s:%d", l.GetId(), l.GetPort()))
	}
	for _, p := range st.GetProxies() {
		on := "off"
		if p.GetEnabled() {
			on = "on"
		}
		ps = append(ps, fmt.Sprintf("%s@%s %s %s %s", p.GetId(), p.GetListenerId(), p.GetDomain(), p.GetSecret(), on))
	}
	return fmt.Sprintf("listeners [%s]; proxies [%s]", strings.Join(ls, " "), strings.Join(ps, " "))
}

func TestMutationsAreAudited(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	if _, err := e.proxies.SetProxyEnabled(e.ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: p.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.proxies.DeleteProxy(e.ctx, connect.NewRequest(&panelv1.DeleteProxyRequest{Id: p.GetId()})); err != nil {
		t.Fatal(err)
	}
	got := auditLog(t, e)
	want := []string{
		"listener.create listener:" + l.GetId() + " " + e.adminID,
		"proxy.create proxy:" + p.GetId() + " " + e.adminID,
		"proxy.disable proxy:" + p.GetId() + " " + e.adminID,
		"proxy.delete proxy:" + p.GetId() + " " + e.adminID,
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
