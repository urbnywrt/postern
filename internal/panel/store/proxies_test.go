package store

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// proxyRowTables are the tables that hold rows of a proxy, which go with it.
// proxyRowQueries add a row to each of them for the proxy that is their one
// argument.
var (
	proxyRowTables = []string{
		"stats_proxy_1m", "stats_proxy_1h", "stats_proxy_1d", "ip_sightings",
		"stats_country_1m", "stats_country_1h", "stats_country_1d", "probes", "public_page_items",
	}
	proxyRowQueries = []string{
		`INSERT INTO stats_proxy_1m (proxy_id, ts) VALUES (?1, 60)`,
		`INSERT INTO stats_proxy_1h (proxy_id, ts) VALUES (?1, 3600)`,
		`INSERT INTO stats_proxy_1d (proxy_id, ts) VALUES (?1, 86400)`,
		`INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen) VALUES (?1, '192.0.2.1', 1, 1)`,
		`INSERT INTO stats_country_1m (proxy_id, ts, country) VALUES (?1, 60, 'DE')`,
		`INSERT INTO stats_country_1h (proxy_id, ts, country) VALUES (?1, 3600, 'DE')`,
		`INSERT INTO stats_country_1d (proxy_id, ts, country) VALUES (?1, 86400, 'DE')`,
		`INSERT INTO probes (proxy_id, ts, vantage, kind, ok) VALUES (?1, 60, 'panel', 'l2', 1)`,
		`INSERT INTO public_page_items (proxy_id, position) VALUES (?1, (SELECT count(*) FROM public_page_items))`,
	}
)

// mustProxy creates a fake TLS proxy on a listener.
func mustProxy(t *testing.T, db *DB, nodeID, listenerID, name string) *Proxy {
	t.Helper()
	p := &Proxy{NodeID: nodeID, ListenerID: listenerID, Name: name, SecretEnc: []byte("sealed-secret")}
	if err := db.CreateProxy(context.Background(), p); err != nil {
		t.Fatalf("CreateProxy(%s): %v", name, err)
	}
	return p
}

// fullProxy is a proxy with every field set to a value of its own.
func fullProxy(nodeID, listenerID, chainID string) *Proxy {
	return &Proxy{
		NodeID:              nodeID,
		ListenerID:          listenerID,
		Type:                ProxyTypeWeb,
		Name:                "alpha",
		Note:                "for friends",
		Tags:                []string{"vip", "eu"},
		Enabled:             true,
		SecretEnc:           []byte("sealed-secret"),
		Domain:              "www.example.com",
		WebBasePath:         "telegram/web",
		WebSecretMode:       "dd",
		WebCarrier:          "fake-tls",
		CertMode:            "acme-dns01",
		DNSCredentialID:     "01DNSCREDENTIAL",
		ACMEEmail:           "admin@example.com",
		CertChainEnc:        []byte("sealed-chain"),
		CertKeyEnc:          []byte("sealed-key"),
		CertSHA256:          strings.Repeat("ab", 32),
		CertNotAfter:        testNow.Add(24 * time.Hour),
		Engine:              EngineTelemt,
		EngineVersionPolicy: EnginePolicyPinned,
		EngineVersion:       "3.5.13",
		EgressChainID:       chainID,
		EgressScopeChains:   map[string]string{"me": chainID, "fetch": chainID},
		NATIP:               "203.0.113.7",
		LimitDevices:        3,
		LimitConnsTotal:     100,
		LimitConnsPerIP:     10,
		AdTag:               strings.Repeat("ab", 16),
		MaskTargetOverride:  "mask.example.com:443",
		EngineOverrides:     map[string]any{"general": map[string]any{"x": "y"}, "n": float64(3)},
		UseMiddleProxy:      MiddleProxyOff,
		RestartNonce:        2,
		CertReissueNonce:    3,
		CreatedAt:           testNow,
		UpdatedAt:           testNow.Add(time.Minute),
	}
}

func TestProxyRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	insertChain(t, db, "CHAIN1", "")
	p := fullProxy(node.ID, l.ID, "CHAIN1")
	if err := db.CreateProxy(ctx, p); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	if len(p.ID) != 26 {
		t.Fatalf("ID = %q, want a ULID", p.ID)
	}
	got, err := db.ProxyByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("ProxyByID: %v", err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Errorf("proxy = %+v\nwant    %+v", got, p)
	}
}

func TestProxyDefaults(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	p := &Proxy{NodeID: node.ID, ListenerID: l.ID, Name: "p", SecretEnc: []byte("sealed")}
	if err := db.CreateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	want := &Proxy{
		ID: p.ID, NodeID: node.ID, ListenerID: l.ID, Name: "p", SecretEnc: []byte("sealed"),
		Type: ProxyTypeFakeTLS, Engine: EngineTelemt, EngineVersionPolicy: EnginePolicyChannel, UseMiddleProxy: MiddleProxyAuto,
		CreatedAt: testNow, UpdatedAt: testNow, // not enabled: the store does not decide that
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("record after Create = %+v, want %+v", p, want)
	}
	got, err := db.ProxyByID(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored proxy = %+v, want %+v", got, want)
	}
	if got.Tags != nil || got.EgressScopeChains != nil || got.EngineOverrides != nil {
		t.Errorf("unset JSON fields came back set: %+v", got)
	}
}

// The store does not decide whether a new proxy is enabled: the column has no
// default, so a writer that leaves it out (plain SQL, say, or a later migration)
// is told, instead of getting a proxy that serves traffic by accident.
func TestProxyEnabledHasNoDefault(t *testing.T) {
	db := newTestDB(t)
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	_, err := db.sql.ExecContext(context.Background(),
		`INSERT INTO proxies (id, node_id, listener_id, secret_enc, created_at, updated_at) VALUES ('P1', ?, ?, x'01', 0, 0)`,
		node.ID, l.ID)
	if err == nil || !strings.Contains(err.Error(), "NOT NULL") {
		t.Errorf("an insert without enabled: err = %v, want a NOT NULL constraint error", err)
	}
}

// A proxy decides for itself whether its engine uses the middle proxies of Telegram:
// auto (on when it has an ad tag), on, or off. A proxy that does not say is auto.
func TestProxyUseMiddleProxy(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)

	values := []string{MiddleProxyAuto, MiddleProxyOn, MiddleProxyOff}
	for _, v := range values {
		p := &Proxy{NodeID: node.ID, ListenerID: l.ID, Name: v, SecretEnc: []byte("s"), UseMiddleProxy: v}
		if err := db.CreateProxy(ctx, p); err != nil {
			t.Fatalf("CreateProxy(%s): %v", v, err)
		}
		if got, err := db.ProxyByID(ctx, p.ID); err != nil || got.UseMiddleProxy != v {
			t.Errorf("created with %q, read back %q (%v)", v, got.UseMiddleProxy, err)
		}
		for _, next := range values {
			p.UseMiddleProxy = next
			if err := db.UpdateProxy(ctx, p); err != nil {
				t.Fatalf("UpdateProxy(%s to %s): %v", v, next, err)
			}
			if got, err := db.ProxyByID(ctx, p.ID); err != nil || got.UseMiddleProxy != next {
				t.Errorf("updated to %q, read back %q (%v)", next, got.UseMiddleProxy, err)
			}
		}
	}

	// Empty is auto, when a proxy is made and when it is changed.
	p := &Proxy{NodeID: node.ID, ListenerID: l.ID, Name: "empty", SecretEnc: []byte("s")}
	if err := db.CreateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if p.UseMiddleProxy != MiddleProxyAuto {
		t.Errorf("a new proxy without a setting has %q, want auto", p.UseMiddleProxy)
	}
	p.UseMiddleProxy = MiddleProxyOn
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.UseMiddleProxy = ""
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if p.UseMiddleProxy != MiddleProxyAuto {
		t.Errorf("after an update without a setting the proxy has %q, want auto", p.UseMiddleProxy)
	}
	if got, _ := db.ProxyByID(ctx, p.ID); got.UseMiddleProxy != MiddleProxyAuto {
		t.Errorf("stored %q, want auto", got.UseMiddleProxy)
	}
}

// Nothing but auto, on and off is stored: the database says no to anything else, so
// that the state builder never meets a setting that it does not know.
func TestProxyUseMiddleProxyRefusesOtherValues(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	for _, bad := range []string{"maybe", "ON", "true", "1", " on", "on ", "Auto", "yes"} {
		p := &Proxy{NodeID: node.ID, ListenerID: l.ID, Name: "bad", SecretEnc: []byte("s"), UseMiddleProxy: bad}
		if err := db.CreateProxy(ctx, p); err == nil {
			t.Errorf("CreateProxy took the setting %q", bad)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM proxies`); n != 0 {
		t.Errorf("refused creates left %d proxies", n)
	}
	good := mustProxy(t, db, node.ID, l.ID, "good")
	good.UseMiddleProxy = "maybe"
	if err := db.UpdateProxy(ctx, good); err == nil {
		t.Error("UpdateProxy took the setting \"maybe\"")
	}
	if got, _ := db.ProxyByID(ctx, good.ID); got.UseMiddleProxy != MiddleProxyAuto {
		t.Errorf("a refused update changed the setting to %q", got.UseMiddleProxy)
	}
}

// A database from before the setting has proxies, and they all become auto, which
// is what they did: the middle proxies when they have an ad tag.
func TestProxiesOfAnOlderDatabaseAreAuto(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	older := map[string]string{}
	for _, name := range []string{"0001_init.sql", "0002_node_errors.sql", "0003_egress.sql", "0004_versions.sql", "0005_insights.sql", "0006_ssh_jobs.sql"} {
		body, err := fs.ReadFile(embeddedMigrations(), name)
		if err != nil {
			t.Fatal(err)
		}
		older[name] = string(body)
	}
	db := mustOpenFS(t, path, older, fixedClock(testNow))
	// The node is written by hand: CreateNode writes the columns of today.
	node := &Node{ID: "N1"}
	if _, err := db.sql.ExecContext(context.Background(),
		`INSERT INTO nodes (id, name, created_at, updated_at) VALUES (?, 'n', 0, 0)`, node.ID); err != nil {
		t.Fatal(err)
	}
	l := mustListener(t, db, node.ID, 443)
	for _, id := range []string{"P1", "P2"} {
		_, err := db.sql.ExecContext(context.Background(),
			`INSERT INTO proxies (id, node_id, listener_id, enabled, secret_enc, ad_tag, created_at, updated_at) VALUES (?, ?, ?, 1, x'01', ?, 0, 0)`,
			id, node.ID, l.ID, map[string]string{"P1": "", "P2": strings.Repeat("ab", 16)}[id])
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open with the newer migrations: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if got := migrationsApplied(t, db); !slices.Equal(got, embeddedVersions(t)) {
		t.Errorf("applied migrations = %v, want %v", got, embeddedVersions(t))
	}
	for id, tag := range map[string]string{"P1": "", "P2": strings.Repeat("ab", 16)} {
		p, err := db.ProxyByID(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if p.UseMiddleProxy != MiddleProxyAuto || p.AdTag != tag {
			t.Errorf("proxy %s = setting %q, ad tag %q, want auto and %q", id, p.UseMiddleProxy, p.AdTag, tag)
		}
	}
}

func TestProxyErrors(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	a := mustNode(t, db, "a")
	b := mustNode(t, db, "b")
	la := mustListener(t, db, a.ID, 443)
	lb := mustListener(t, db, b.ID, 443)

	tests := []struct {
		name string
		p    *Proxy
	}{
		{"unknown node", &Proxy{NodeID: "no-such-node", ListenerID: la.ID, SecretEnc: []byte("s")}},
		{"unknown listener", &Proxy{NodeID: a.ID, ListenerID: "no-such-listener", SecretEnc: []byte("s")}},
		{"listener of another node", &Proxy{NodeID: a.ID, ListenerID: lb.ID, SecretEnc: []byte("s")}},
		{"unknown chain", &Proxy{NodeID: a.ID, ListenerID: la.ID, EgressChainID: "no-such-chain", SecretEnc: []byte("s")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := db.CreateProxy(ctx, tt.p); !errors.Is(err, ErrNotFound) {
				t.Errorf("CreateProxy err = %v, want ErrNotFound", err)
			}
		})
	}
	if n := count(t, db, `SELECT count(*) FROM proxies`); n != 0 {
		t.Errorf("failed creates left %d proxies", n)
	}

	if _, err := db.ProxyByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ProxyByID err = %v, want ErrNotFound", err)
	}
	if err := db.UpdateProxy(ctx, &Proxy{ID: "nope", NodeID: a.ID, ListenerID: la.ID, SecretEnc: []byte("s")}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateProxy err = %v, want ErrNotFound", err)
	}
	if err := db.DeleteProxy(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteProxy err = %v, want ErrNotFound", err)
	}
}

func TestListProxies(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	a := mustNode(t, db, "a")
	b := mustNode(t, db, "b")
	la1 := mustListener(t, db, a.ID, 443)
	la2 := mustListener(t, db, a.ID, 8443)
	lb := mustListener(t, db, b.ID, 443)

	var all []string
	mk := func(nodeID, listenerID, name string, i int) *Proxy {
		p := &Proxy{
			NodeID: nodeID, ListenerID: listenerID, Name: name, SecretEnc: []byte("s"),
			CreatedAt: testNow.Add(time.Duration(i) * time.Second),
		}
		if err := db.CreateProxy(ctx, p); err != nil {
			t.Fatal(err)
		}
		all = append(all, p.ID)
		return p
	}
	// Created out of the alphabetical order of their names.
	pa1 := mk(a.ID, la1.ID, "zulu", 0)
	pb := mk(b.ID, lb.ID, "alpha", 1)
	pa2 := mk(a.ID, la2.ID, "mike", 2)

	ids := func(ps []*Proxy) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.ID)
		}
		return out
	}
	tests := []struct {
		name   string
		filter ProxyFilter
		want   []string
	}{
		{"everything, by creation", ProxyFilter{}, all},
		{"one node", ProxyFilter{NodeID: a.ID}, []string{pa1.ID, pa2.ID}},
		{"the other node", ProxyFilter{NodeID: b.ID}, []string{pb.ID}},
		{"one listener", ProxyFilter{ListenerID: la2.ID}, []string{pa2.ID}},
		{"node and listener that do not go together", ProxyFilter{NodeID: b.ID, ListenerID: la1.ID}, nil},
		{"unknown node", ProxyFilter{NodeID: "no-such-node"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.ListProxies(ctx, tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ids(got), tt.want) {
				t.Errorf("ListProxies(%+v) = %v, want %v", tt.filter, ids(got), tt.want)
			}
		})
	}
}

func TestUpdateProxy(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	other := mustNode(t, db, "other")
	l1 := mustListener(t, db, node.ID, 443)
	l2 := mustListener(t, db, node.ID, 8443)
	lOther := mustListener(t, db, other.ID, 443)
	insertChain(t, db, "CHAIN1", "")
	insertChain(t, db, "CHAIN2", "")
	p := fullProxy(node.ID, l1.ID, "CHAIN1")
	if err := db.CreateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	untouched := mustProxy(t, db, node.ID, l1.ID, "untouched")

	db.now = fixedClock(testNow.Add(time.Hour))
	p.ListenerID = l2.ID // another listener of the same node
	p.Type = ProxyTypeFakeTLS
	p.Name = "beta"
	p.Note = ""
	p.Tags = []string{"x"}
	p.Enabled = false
	p.SecretEnc = []byte("another-sealed-secret")
	p.Domain = "alt.example.com"
	p.WebBasePath = ""
	p.WebSecretMode = "plain"
	p.WebCarrier = ""
	p.CertMode = "imported"
	p.DNSCredentialID = ""
	p.ACMEEmail = ""
	p.Engine = "mtg"
	p.EngineVersionPolicy = EnginePolicyChannel
	p.EngineVersion = ""
	p.EgressChainID = "CHAIN2"
	p.EgressScopeChains = map[string]string{"me": "CHAIN2"}
	p.NATIP = ""
	p.LimitDevices = 0
	p.LimitConnsTotal = 1
	p.LimitConnsPerIP = 2
	p.AdTag = ""
	p.MaskTargetOverride = ""
	p.EngineOverrides = nil
	p.UseMiddleProxy = MiddleProxyOn
	p.RestartNonce = 7
	p.CertReissueNonce = 8
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if !p.UpdatedAt.Equal(testNow.Add(time.Hour)) {
		t.Errorf("UpdatedAt = %v, want the time of the update", p.UpdatedAt)
	}
	got, err := db.ProxyByID(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Errorf("after update = %+v\nwant         %+v", got, p)
	}
	if !got.CreatedAt.Equal(testNow) {
		t.Errorf("CreatedAt changed to %v", got.CreatedAt)
	}

	// Back to the default chain of the node.
	p.EgressChainID = ""
	p.EgressScopeChains = nil
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ProxyByID(ctx, p.ID); got.EgressChainID != "" {
		t.Errorf("EgressChainID = %q, want empty", got.EgressChainID)
	}

	if u, _ := db.ProxyByID(ctx, untouched.ID); !reflect.DeepEqual(u, untouched) {
		t.Errorf("another proxy changed: %+v", u)
	}

	// A proxy stays on its node, and only uses listeners of that node.
	before, _ := db.ProxyByID(ctx, p.ID)
	moved := *before
	moved.NodeID = other.ID
	moved.ListenerID = lOther.ID
	if err := db.UpdateProxy(ctx, &moved); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateProxy through the wrong node: err = %v, want ErrNotFound", err)
	}
	foreign := *before
	foreign.ListenerID = lOther.ID
	if err := db.UpdateProxy(ctx, &foreign); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateProxy to a listener of another node: err = %v, want ErrNotFound", err)
	}
	unknownChain := *before
	unknownChain.EgressChainID = "no-such-chain"
	if err := db.UpdateProxy(ctx, &unknownChain); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateProxy to an unknown chain: err = %v, want ErrNotFound", err)
	}
	if after, _ := db.ProxyByID(ctx, p.ID); !reflect.DeepEqual(after, before) {
		t.Errorf("a failed update changed the proxy: %+v", after)
	}
}

func TestDeleteProxy(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	gone := mustProxy(t, db, node.ID, l.ID, "gone")
	keep := mustProxy(t, db, node.ID, l.ID, "keep")
	for _, p := range []*Proxy{gone, keep} {
		for _, q := range proxyRowQueries {
			mustExec(t, db, q, p.ID)
		}
	}

	if err := db.DeleteProxy(ctx, gone.ID); err != nil {
		t.Fatalf("DeleteProxy: %v", err)
	}
	if _, err := db.ProxyByID(ctx, gone.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted proxy is still there: %v", err)
	}
	if _, err := db.ProxyByID(ctx, keep.ID); err != nil {
		t.Errorf("another proxy was deleted: %v", err)
	}
	for _, table := range proxyRowTables {
		q := `SELECT count(*) FROM ` + table + ` WHERE proxy_id = ?`
		if n := count(t, db, q, gone.ID); n != 0 {
			t.Errorf("%s: %d rows of the deleted proxy are left", table, n)
		}
		if n := count(t, db, q, keep.ID); n != 1 {
			t.Errorf("%s: %d rows of the other proxy, want 1", table, n)
		}
	}
}

func TestProxyNoncesMustFitSQLite(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	if err := db.CreateProxy(ctx, &Proxy{NodeID: node.ID, ListenerID: l.ID, SecretEnc: []byte("s"), RestartNonce: 1 << 63}); err == nil {
		t.Error("CreateProxy accepted a restart nonce that does not fit in a SQLite integer")
	}
	p := mustProxy(t, db, node.ID, l.ID, "p")
	p.CertReissueNonce = 1 << 63
	if err := db.UpdateProxy(ctx, p); err == nil {
		t.Error("UpdateProxy accepted a reissue nonce that does not fit in a SQLite integer")
	}
	if n := count(t, db, `SELECT count(*) FROM proxies WHERE restart_nonce <> 0 OR cert_reissue_nonce <> 0`); n != 0 {
		t.Errorf("%d proxies have a nonce after the failed writes", n)
	}
}

func TestChainInUseByProxyCannotBeDeleted(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	node := mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	insertChain(t, db, "CHAIN1", "")
	p := &Proxy{NodeID: node.ID, ListenerID: l.ID, EgressChainID: "CHAIN1", SecretEnc: []byte("s")}
	if err := db.CreateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM egress_chains WHERE id = 'CHAIN1'`); err == nil {
		t.Error("a chain that a proxy uses was deleted")
	}
	if err := db.DeleteProxy(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM egress_chains WHERE id = 'CHAIN1'`); err != nil {
		t.Errorf("a chain that nothing uses could not be deleted: %v", err)
	}
}
