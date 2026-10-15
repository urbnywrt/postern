//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	_ "modernc.org/sqlite" // the panel's database, read by the test

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
	"github.com/urbnywrt/postern/internal/probe"
)

// TestInsights runs the statistics, the client countries, the probes, the
// diagnostics with their fixes, the problem feed and the journal, and the
// public page of slice 6 for real, on the harness of TestPanelToNodeFakeTLS.
// The panel reaches the node from 127.0.0.1, which the node learns as the
// panel's address and the edge exempts as a probe source (Task 14); the
// test's own clients therefore dial from clientIP, so that the exemption
// never hides them.
//
//  1. The panel, which can download no country database (its base URL is a
//     port that nothing listens on), and a node; a TLS listener on 127.0.0.1
//     whose links lead to 127.0.0.1 (so that the panel's probes and the
//     public page's links reach it), and a fake-TLS proxy on a chain of a
//     direct egress, serving; the node reports the panel's address.
//  2. A country database of the test (127.0.0.0/8 is ZZ, 203.0.113.0/24 is
//     DE) is uploaded; the panel shows it, the IP policy becomes full, and
//     the node stores the database under data/geoip/<sha256>.mmdb.
//  3. Clients make fake-TLS handshakes from clientIP, all along the test, at
//     seconds 2, 12, 22, 32 and 42 of every minute: within 3 min the series of
//     the proxy, of the node, its countries and its IP history show them.
//  4. A probe from the panel passes L2 and is in the probe history.
//  5. The proxy is moved to a chain whose only member is a SOCKS5 server that
//     does not exist: the edit records a before-run, the after-run finds
//     egress.dc and e2e.l2 failing, a probe from the panel reports that no
//     datacenter answered through the proxy (L1 ok); the change_egress fix
//     back to the first chain, offered by that run, heals it, with a
//     before/after pair.
//  6. The panel is stopped for 150 s or more, two whole minutes at least,
//     while the clients go on; after its restart the node's buffer fills
//     the gap: every minute of it once, with
//     as many new connections as handshakes were made in it, a country row
//     of one address, and the health of the chain's member. The IP history
//     lists clientIP and never the panel's address (with Task 14 merged).
//  7. The policy countries empties the IP history at once, and the
//     panel's database, its WAL and its backups hold no client address;
//     countries go on; the policy off empties the country tables, and no new
//     country row comes; then countries again.
//  8. A node run of the diagnostics ends done with its main checks ok. The
//     engine container is paused with the Docker API: the reconciler leaves
//     it, the problem feed lists engine.container of the proxy, and once
//     unpaused the problem goes. Paused again, the recreate_instance fix
//     starts a new generation of the engine that serves, an after-run without
//     regression is recorded, and the audit log has diagnostics.fix.
//  9. The public page on proxies.example.test: the proxy's link and no QR,
//     nothing of the script, links and image of its Markdown, noindex,
//     robots.txt, no admin on that host; the paused proxy is marked
//     unavailable with no link or secret on the very next request, and gone
//     with hide.
//  10. No log of the run holds a secret of it, and neither does any text of
//     the diagnostics, the problem feed or the journal, which hold no client
//     address either.
//
// It needs Telegram's datacenters, as TestPanelToNodeFakeTLS does, and takes
// some 15 min.
func TestInsights(t *testing.T) {
	e := newEnv(t)
	x := &insights{e: e}

	// 1. The panel, the node, the listener and the proxy on a direct chain.
	x.s = e.setUpFakeTLS(fakeTLSSetup{
		panelEnv: []string{"POSTERN_GEOIP_BASE_URL=http://127.0.0.1:1/"},
		linkHost: "127.0.0.1",
		chain: func(a *api, node *panelv1.Node) string {
			x.directChain = x.newChain(a, node.GetId(), "direct", "direct", nil)
			return x.directChain
		},
	})
	x.a, x.nodeID, x.proxyID = x.s.api, x.s.node.GetId(), x.s.proxy.GetId()
	// A change of the egress waits for a full run of the diagnostics first,
	// for up to 90 s.
	x.a.http.Timeout = 3 * time.Minute
	x.mustNotLeakSecretForms()
	e.waitFor("the panel's address as the node sees it", time.Minute, time.Second, func(ctx context.Context) (bool, string, error) {
		n, err := e.getNode(ctx, x.a, x.nodeID)
		if err != nil {
			return false, "", err
		}
		return slices.Equal(n.GetPanelAddrs(), []string{"127.0.0.1"}), fmt.Sprintf("panel_addrs %v", n.GetPanelAddrs()), nil
	})

	x.geoIP()                // 2
	x.traffic()              // 3
	x.probes()               // 4
	x.egressFailureAndFix()  // 5
	x.catchUp()              // 6
	x.policies()             // 7
	x.diagnostics()          // 8
	x.publicPage()           // 9
	x.clients.end()          // the clients are done
	x.checkDiagnosticTexts() // 10
	if err := x.s.panel.stop(15 * time.Second); err != nil {
		e.errorf("the panel did not stop cleanly: %v", err)
	}
	e.checkLogs()
}

const (
	// clientIP is where the clients of the test dial from: a loopback address
	// that is not the panel's, so that no exemption of the panel's probes
	// applies to them.
	clientIP = "127.0.0.3"
	// publicHost is the host of the public page.
	publicHost = "proxies.example.test"
	// gapFor is how long the panel is down in step 6 at least; it stays down
	// until two whole minutes have passed as well.
	gapFor = 150 * time.Second
)

// insights is the state of TestInsights.
type insights struct {
	e                      *env
	s                      *fakeTLS
	a                      *api
	nodeID, proxyID        string
	directChain, deadChain string
	lastBefore             string // the before-run of the last change of the egress
	clients                *clients
}

// newChain makes an egress of the node and a chain of it alone, and returns
// the id of the chain.
func (x *insights) newChain(a *api, nodeID, name, kind string, params *panelv1.EgressParams) string {
	e := x.e
	e.t.Helper()
	eg, err := a.egresses.CreateEgress(e.ctx, connect.NewRequest(&panelv1.CreateEgressRequest{
		Name: name, Kind: kind, NodeId: nodeID, Params: params,
	}))
	if err != nil {
		e.fatalf("CreateEgress %s: %v", kind, err)
	}
	ch, err := a.chains.CreateChain(e.ctx, connect.NewRequest(&panelv1.CreateChainRequest{
		Name: name, NodeId: nodeID, MemberIds: []string{eg.Msg.GetEgress().GetId()},
	}))
	if err != nil {
		e.fatalf("CreateChain %s: %v", name, err)
	}
	e.logf("chain %s: egress %s of kind %s", ch.Msg.GetChain().GetId(), eg.Msg.GetEgress().GetId(), kind)
	return ch.Msg.GetChain().GetId()
}

// mustNotLeakSecretForms notes the other forms of the proxy's secret that a
// text could hold: base64, standard and URL, with and without padding (the
// hex form is a part of the fake-TLS one, ee + secret + domain).
func (x *insights) mustNotLeakSecretForms() {
	b := x.s.secret
	x.e.mustNotLeak("the secret of the proxy in base64",
		base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b))
}

// ---- 2. GeoIP -----------------------------------------------------------------

func (x *insights) geoIP() {
	e := x.e
	e.t.Helper()
	db, err := geoiptest.Bytes(map[string]string{"127.0.0.0/8": "ZZ", "203.0.113.0/24": "DE"})
	if err != nil {
		e.fatalf("writing the country database: %v", err)
	}
	sum := sha256.Sum256(db)
	want := hex.EncodeToString(sum[:])
	req, err := http.NewRequestWithContext(e.ctx, http.MethodPut, x.a.base+"/api/geoip", bytes.NewReader(db))
	if err != nil {
		e.fatalf("%v", err)
	}
	resp, err := x.a.http.Do(req)
	if err != nil {
		e.fatalf("PUT /api/geoip: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.fatalf("PUT /api/geoip: %s: %s", resp.Status, body)
	}
	g, err := x.a.geoip.GetGeoIP(e.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{}))
	if err != nil {
		e.fatalf("GetGeoIP: %v", err)
	}
	if st := g.Msg.GetStatus(); !st.GetPresent() || st.GetSha256() != want {
		e.fatalf("GetGeoIP after the upload: present %v, sha256 %s; want the uploaded database, %s", st.GetPresent(), st.GetSha256(), want)
	}
	e.logf("the country database of the test (%d bytes, sha256 %s) is the panel's", len(db), want[:12])

	x.setPolicy("full")
	path := filepath.Join(e.home, "data", "geoip", want+".mmdb")
	e.waitFor("the country database on the node", 2*time.Minute, 2*time.Second, func(ctx context.Context) (bool, string, error) {
		code, out := e.runHelperCtx(ctx, "geoip", "none", []string{"stat", "-c", "%s", path})
		if code != 0 {
			return false, "not there", nil
		}
		return strings.TrimSpace(out) == strconv.Itoa(len(db)), "data/geoip/<sha256>.mmdb, " + strings.TrimSpace(out) + " bytes", nil
	})
}

// setPolicy sets the IP policy and keeps the other statistics settings.
func (x *insights) setPolicy(policy string) {
	e := x.e
	e.t.Helper()
	got, err := x.a.settings.GetStatsSettings(e.ctx, connect.NewRequest(&panelv1.GetStatsSettingsRequest{}))
	if err != nil {
		e.fatalf("GetStatsSettings: %v", err)
	}
	st := got.Msg.GetSettings()
	st.IpPolicy = policy
	if _, err := x.a.settings.UpdateStatsSettings(e.ctx, connect.NewRequest(&panelv1.UpdateStatsSettingsRequest{Settings: st})); err != nil {
		e.fatalf("UpdateStatsSettings with the IP policy %s: %v", policy, err)
	}
	e.logf("the IP policy is %s", policy)
}

// ---- 3. Traffic ---------------------------------------------------------------

// clients make a fake-TLS handshake from clientIP at seconds 2, 12, 22, 32 and
// 42 of every minute, until end: none in the last 18 s of a minute, so that
// the node, which takes the edge's counters every 10 s, counts each in the
// minute it was made in.
type clients struct {
	stop, done chan struct{}
	mu         sync.Mutex
	made       []handshake
}

// handshake is one of clients: when it started, whether the edge accepted the
// connection, and how the handshake ended.
type handshake struct {
	at     time.Time
	dialed bool
	err    error
}

func (x *insights) startClients() {
	c := &clients{stop: make(chan struct{}), done: make(chan struct{})}
	x.clients = c
	e := x.e
	go func() {
		defer close(c.done)
		for {
			now := time.Now()
			sec := now.Second()
			next := now.Truncate(time.Minute).Add(time.Duration((sec+8)/10*10+2) * time.Second)
			if next.Sub(now.Truncate(time.Minute)) > 42*time.Second {
				next = now.Truncate(time.Minute).Add(time.Minute + 2*time.Second)
			}
			select {
			case <-c.stop:
				return
			case <-e.ctx.Done():
				return
			case <-time.After(time.Until(next)):
			}
			h := handshake{at: time.Now()}
			h.dialed, h.err = clientHandshake(e.ctx, x.s.addr, x.s.domain, x.s.secret)
			c.mu.Lock()
			c.made = append(c.made, h)
			c.mu.Unlock()
		}
	}()
	e.t.Cleanup(c.end)
}

// end stops the clients; it may be called more than once.
func (c *clients) end() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	<-c.done
}

// in returns the handshakes that started in [from, to).
func (c *clients) in(from, to time.Time) []handshake {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []handshake
	for _, h := range c.made {
		if !h.at.Before(from) && h.at.Before(to) {
			out = append(out, h)
		}
	}
	return out
}

// clientHandshake dials addr from clientIP and makes a fake-TLS handshake on
// the connection, which it then closes. dialed says whether the edge accepted
// the connection.
func clientHandshake(ctx context.Context, addr, sni string, secret []byte) (dialed bool, err error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientIP)}, Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	return true, probe.Handshake(conn, sni, secret, probe.Options{Timeout: 7 * time.Second})
}

func (x *insights) traffic() {
	e := x.e
	e.t.Helper()
	x.startClients()
	e.waitFor("the clients' traffic in the statistics", 3*time.Minute, 5*time.Second, func(ctx context.Context) (bool, string, error) {
		var have []string
		ps, err := x.a.stats.ProxySeries(ctx, connect.NewRequest(&panelv1.ProxySeriesRequest{ProxyId: x.proxyID, Range: "1h"}))
		if err != nil {
			return false, "", fmt.Errorf("ProxySeries: %w", err)
		}
		if slices.ContainsFunc(ps.Msg.GetPoints(), func(p *panelv1.SeriesPoint) bool { return p.GetConnsNew() >= 1 && p.GetDevices() >= 1 }) {
			have = append(have, "proxy minutes")
		}
		ns, err := x.a.metrics.NodeSeries(ctx, connect.NewRequest(&panelv1.NodeSeriesRequest{NodeId: x.nodeID, Range: "1h"}))
		if err != nil {
			return false, "", fmt.Errorf("NodeSeries: %w", err)
		}
		if slices.ContainsFunc(ns.Msg.GetPoints(), func(p *panelv1.NodePoint) bool { return p.GetMemUsed() > 0 && p.GetUp()+p.GetDown() > 0 }) {
			have = append(have, "node minutes")
		}
		cs, err := x.a.metrics.Countries(ctx, connect.NewRequest(&panelv1.CountriesRequest{ProxyId: x.proxyID, Range: "1h"}))
		if err != nil {
			return false, "", fmt.Errorf("Countries: %w", err)
		}
		if slices.ContainsFunc(cs.Msg.GetCountries(), func(c *panelv1.CountryTotal) bool { return c.GetCountry() == "ZZ" && c.GetIpsPeak() >= 1 }) {
			have = append(have, "countries")
		}
		ips, err := x.sightings(ctx)
		if err != nil {
			return false, "", err
		}
		if ips[clientIP] == "ZZ" {
			have = append(have, "IP history")
		}
		return len(have) == 4, "has " + strings.Join(have, ", "), nil
	})
}

// sightings is the IP history of the proxy: the country of each address.
func (x *insights) sightings(ctx context.Context) (map[string]string, error) {
	r, err := x.a.metrics.ListIpSightings(ctx, connect.NewRequest(&panelv1.ListIpSightingsRequest{ProxyId: x.proxyID, Limit: 200}))
	if err != nil {
		return nil, fmt.Errorf("ListIpSightings: %w", err)
	}
	out := map[string]string{}
	for _, s := range r.Msg.GetSightings() {
		out[s.GetIp()] = s.GetCountry()
	}
	return out, nil
}

// ---- 4. Probes ----------------------------------------------------------------

// probeNow probes the proxy from the panel; it waits out the panel's limit of
// one probe of a proxy in 5 s.
func (x *insights) probeNow() *panelv1.ProbeNowResponse {
	e := x.e
	e.t.Helper()
	for range 3 {
		r, err := x.a.probes.ProbeNow(e.ctx, connect.NewRequest(&panelv1.ProbeNowRequest{ProxyId: x.proxyID}))
		if connect.CodeOf(err) == connect.CodeResourceExhausted {
			time.Sleep(5 * time.Second)
			continue
		}
		if err != nil {
			e.fatalf("ProbeNow: %v", err)
		}
		return r.Msg
	}
	e.fatalf("ProbeNow: the panel's limit of a probe every 5 s did not let a probe through")
	return nil
}

func (x *insights) probes() {
	e := x.e
	e.t.Helper()
	before := time.Now().Add(-time.Second).Unix()
	r := x.probeNow()
	if !r.GetOk() || r.GetKind() != "l2" {
		e.fatalf("ProbeNow: kind %s, ok %v, error %q; want an L2 probe that passes", r.GetKind(), r.GetOk(), r.GetError())
	}
	h, err := x.a.probes.ProbeHistory(e.ctx, connect.NewRequest(&panelv1.ProbeHistoryRequest{ProxyId: x.proxyID, Range: "24h"}))
	if err != nil {
		e.fatalf("ProbeHistory: %v", err)
	}
	if !slices.ContainsFunc(h.Msg.GetPoints(), func(p *panelv1.ProbePoint) bool {
		return p.GetVantage() == "panel" && p.GetKind() == "l2" && p.GetOk() && p.GetTs() >= before
	}) {
		e.fatalf("ProbeHistory has no passing L2 probe of the panel since the ProbeNow")
	}
	e.logf("a probe from the panel passes L2 in %d ms, and the probe history has it", r.GetLatencyMs())
}

// ---- 5. A failing egress and its fix --------------------------------------------

func (x *insights) egressFailureAndFix() {
	e := x.e
	e.t.Helper()
	x.deadChain = x.newChain(x.a, x.nodeID, "dead-socks", "socks5", &panelv1.EgressParams{Addr: "192.0.2.1:1080"})
	desired := e.change(x.a, x.nodeID, "UpdateProxy to the dead chain", func(ctx context.Context) error {
		r, err := x.a.proxies.UpdateProxy(ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: x.proxyID, EgressChainId: &x.deadChain}))
		if err == nil && r.Msg.GetBeforeRunId() == "" {
			return errors.New("the change of the chain recorded no before-run")
		}
		if err == nil {
			x.lastBefore = r.Msg.GetBeforeRunId()
		}
		return err
	})
	e.waitApplied(x.a, x.nodeID, x.proxyID, desired, "serving", nil)
	after := x.waitAfterRun(x.lastBefore, 4*time.Minute)
	for _, id := range []string{"egress.dc", "e2e.l2"} {
		if r := resultOf(after, id, "proxy:"+x.proxyID); r == nil || r.GetStatus() != "fail" {
			e.fatalf("the after-run of the change to the dead chain: %s is %s, want fail", id, statusOf(r))
		}
	}
	dc := resultOf(after, "egress.dc", "proxy:"+x.proxyID)
	if dc.GetFix() != "change_egress" || !dc.GetFixAvailable() {
		e.fatalf("egress.dc offers the fix %q (available %v), want change_egress", dc.GetFix(), dc.GetFixAvailable())
	}
	e.logf("the after-run of the change finds egress.dc and e2e.l2 failing: %s; %s", dc.GetSummary(),
		resultOf(after, "e2e.l2", "proxy:"+x.proxyID).GetSummary())
	r := x.probeNow()
	const noDC = "no datacenter answered through the proxy (L1 ok)"
	if r.GetOk() || r.GetError() != noDC {
		e.fatalf("ProbeNow through the dead chain: ok %v, error %q; want %q", r.GetOk(), r.GetError(), noDC)
	}
	e.logf("a probe from the panel through the dead chain: %s", r.GetError())

	fix, err := x.a.diag.ApplyFix(e.ctx, connect.NewRequest(&panelv1.ApplyFixRequest{
		NodeId: x.nodeID, CheckId: "egress.dc", Target: "proxy:" + x.proxyID, Fix: "change_egress",
		ChainId: x.directChain, OfferedRunId: after.GetId(),
	}))
	if err != nil {
		e.fatalf("ApplyFix change_egress: %v", err)
	}
	if fix.Msg.GetBeforeRunId() != after.GetId() {
		e.errorf("the fix's before-run is %s, want the run it was offered by, %s", fix.Msg.GetBeforeRunId(), after.GetId())
	}
	if got := e.proxyOf(x.a, x.proxyID).GetEgressChainId(); got != x.directChain {
		e.fatalf("after the fix the proxy goes out through chain %s, want %s", got, x.directChain)
	}
	healed := x.waitAfterRun(after.GetId(), 5*time.Minute)
	if r := resultOf(healed, "e2e.l2", "proxy:"+x.proxyID); r.GetStatus() != "ok" {
		e.fatalf("the after-run of the fix: e2e.l2 is %s, want ok", statusOf(r))
	}
	if healed.GetRegressed() {
		e.errorf("the after-run of the fix is marked regressed")
	}
	e.waitFor("a probe from the panel after the fix", time.Minute, 6*time.Second, func(context.Context) (bool, string, error) {
		r := x.probeNow()
		return r.GetOk(), fmt.Sprintf("ok %v %s", r.GetOk(), r.GetError()), nil
	})
	e.logf("the change_egress fix back to the direct chain healed the proxy: run %s before, %s after", after.GetId(), healed.GetId())
}

// waitAfterRun waits for the after_change run that is related to the run
// before and has ended, and returns it with its results.
func (x *insights) waitAfterRun(before string, timeout time.Duration) *panelv1.DiagnosticRun {
	e := x.e
	e.t.Helper()
	var run *panelv1.DiagnosticRun
	e.waitFor("the after-run of run "+before, timeout, 3*time.Second, func(ctx context.Context) (bool, string, error) {
		l, err := x.a.diag.ListRuns(ctx, connect.NewRequest(&panelv1.ListRunsRequest{NodeId: x.nodeID, Limit: 50}))
		if err != nil {
			return false, "", fmt.Errorf("ListRuns: %w", err)
		}
		for _, r := range l.Msg.GetRuns() {
			if r.GetReason() != "after_change" || r.GetRelatedRunId() != before {
				continue
			}
			if r.GetState() == "running" {
				return false, "running", nil
			}
			full, err := x.a.diag.GetRun(ctx, connect.NewRequest(&panelv1.GetRunRequest{RunId: r.GetId()}))
			if err != nil {
				return false, "", fmt.Errorf("GetRun: %w", err)
			}
			run = full.Msg
			return true, fmt.Sprintf("run %s %s: %d ok, %d warn, %d fail, %d skip", run.GetId(), run.GetState(),
				run.GetOkCount(), run.GetWarnCount(), run.GetFailCount(), run.GetSkipCount()), nil
		}
		return false, "none yet", nil
	})
	return run
}

// resultOf is the result of the check id for target in run, nil when it has
// none.
func resultOf(run *panelv1.DiagnosticRun, id, target string) *panelv1.CheckResult {
	for _, r := range run.GetResults() {
		if r.GetId() == id && r.GetTarget() == target {
			return r
		}
	}
	return nil
}

func statusOf(r *panelv1.CheckResult) string {
	if r == nil {
		return "missing"
	}
	return r.GetStatus() + " (" + r.GetSummary() + ")"
}

// ---- 6. Catch-up ----------------------------------------------------------------

func (x *insights) catchUp() {
	e := x.e
	e.t.Helper()
	if err := x.s.panel.stop(15 * time.Second); err != nil {
		e.fatalf("stopping the panel: %v", err)
	}
	stopped := time.Now().Round(0) // the wall clock alone
	// At least gapFor, and two whole minutes by the wall clock, which the
	// minutes of the node follow: the clock of a virtual machine may step
	// meanwhile.
	until := stopped.Truncate(time.Minute).Add(3*time.Minute + 2*time.Second)
	if u := stopped.Add(gapFor).Round(0); u.After(until) {
		until = u
	}
	e.logf("the panel is stopped until %s; the clients go on", until.UTC().Format(time.TimeOnly))
	for time.Now().Before(until) {
		select {
		case <-e.ctx.Done():
			e.fatalf("waiting with the panel stopped: %v", e.ctx.Err())
		case <-time.After(min(time.Until(until), 5*time.Second) + 10*time.Millisecond):
		}
	}
	x.s.panel = e.restartPanel(x.s.panel)
	restarted := time.Now().Round(0)

	// The minutes that were whole while the panel was down.
	var gap []time.Time
	for m := stopped.Truncate(time.Minute).Add(time.Minute); !m.Add(time.Minute).After(restarted); m = m.Add(time.Minute) {
		gap = append(gap, m)
	}
	if len(gap) < 2 {
		e.fatalf("the panel was down from %s to %s, %d whole minutes; want 2 or more", stopped.UTC().Format(time.TimeOnly),
			restarted.UTC().Format(time.TimeOnly), len(gap))
	}
	var points map[int64]*panelv1.SeriesPoint
	e.waitFor("the minutes of the gap", 3*time.Minute, 3*time.Second, func(ctx context.Context) (bool, string, error) {
		ps, err := x.a.stats.ProxySeries(ctx, connect.NewRequest(&panelv1.ProxySeriesRequest{ProxyId: x.proxyID, Range: "1h"}))
		if err != nil {
			return false, "", fmt.Errorf("ProxySeries: %w", err)
		}
		points = map[int64]*panelv1.SeriesPoint{}
		for _, p := range ps.Msg.GetPoints() {
			if points[p.GetTsUnix()] != nil {
				return false, "", fmt.Errorf("ProxySeries has the minute %d twice", p.GetTsUnix())
			}
			points[p.GetTsUnix()] = p
		}
		n := 0
		for _, m := range gap {
			if points[m.Unix()] != nil {
				n++
			}
		}
		return n == len(gap), fmt.Sprintf("%d of %d minutes", n, len(gap)), nil
	})

	var made, counted uint32
	for _, m := range gap {
		hs := x.clients.in(m, m.Add(time.Minute))
		var dialed uint32
		for _, h := range hs {
			if h.err != nil {
				e.errorf("a handshake of the clients at %s, while the panel was down, failed: %v", h.at.Format(time.TimeOnly), h.err)
			}
			if h.dialed {
				dialed++
			}
		}
		p := points[m.Unix()]
		if p.GetConnsNew() != dialed || p.GetDevices() != 1 {
			e.errorf("the minute %s of the gap: %d new connections and %d devices, want %d and 1",
				m.Format(time.TimeOnly), p.GetConnsNew(), p.GetDevices(), dialed)
		}
		made += dialed
		counted += p.GetConnsNew()
	}
	e.logf("the %d minutes of the gap are there once each, with %d new connections for the %d handshakes made in them",
		len(gap), counted, made)

	// The country rows and the health of the chain's member, in the database.
	first, last := gap[0].Unix(), gap[len(gap)-1].Unix()
	db := x.openPanelDB()
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(e.ctx,
		`SELECT ts, country, ips FROM stats_country_1m WHERE proxy_id = ? AND ts >= ? AND ts <= ? ORDER BY ts`,
		x.proxyID, first, last)
	if err != nil {
		e.fatalf("reading the country minutes: %v", err)
	}
	seen := map[int64]int{}
	for rows.Next() {
		var ts, ips int64
		var country string
		if err := rows.Scan(&ts, &country, &ips); err != nil {
			e.fatalf("reading the country minutes: %v", err)
		}
		seen[ts]++
		if country != "ZZ" || ips != 1 {
			e.errorf("the country minute %d of the gap: %s with %d addresses, want ZZ with 1", ts, country, ips)
		}
	}
	_ = rows.Close()
	for _, m := range gap {
		if seen[m.Unix()] != 1 {
			e.errorf("the minute %s of the gap has %d country rows, want 1", m.Format(time.TimeOnly), seen[m.Unix()])
		}
	}
	for _, m := range gap {
		var n, keys int
		if err := db.QueryRowContext(e.ctx,
			`SELECT COUNT(*), COUNT(DISTINCT member_key) FROM egress_health_1m WHERE node_id = ? AND chain_id = ? AND ts = ?`,
			x.nodeID, x.directChain, m.Unix()).Scan(&n, &keys); err != nil {
			e.fatalf("reading the member minutes: %v", err)
		}
		if n != 1 || keys != 1 {
			e.errorf("the minute %s of the gap has %d rows of the member of the direct chain (%d members), want 1",
				m.Format(time.TimeOnly), n, keys)
		}
	}
	var lastSeen int64
	if err := db.QueryRowContext(e.ctx, `SELECT last_seen FROM ip_sightings WHERE proxy_id = ? AND ip = ?`, x.proxyID, clientIP).
		Scan(&lastSeen); err != nil {
		e.fatalf("reading the IP history: %v", err)
	}
	if lastSeen < last {
		e.errorf("the IP history saw the clients last at %d, before the last minute of the gap, %d", lastSeen, last)
	}
	e.logf("the gap has one country row a minute (ZZ, 1 address), the member of the chain once a minute, and the IP history")

	// Task 14: the panel's probes are no clients.
	n, err := e.getNode(e.ctx, x.a, x.nodeID)
	if err != nil {
		e.fatalf("%v", err)
	}
	if !slices.Contains(n.GetCapabilities(), "probe-sources") {
		e.logf("the node lacks the capability probe-sources (Task 14): the panel's probes are not checked against the IP history")
		return
	}
	ips, err := x.sightings(e.ctx)
	if err != nil {
		e.fatalf("%v", err)
	}
	if _, ok := ips[clientIP]; !ok {
		e.errorf("the IP history does not list the clients' address")
	}
	if _, ok := ips["127.0.0.1"]; ok {
		e.errorf("the IP history lists the panel's address: its probes counted as a client")
	}
	e.logf("the IP history lists %d addresses: the clients' and not the panel's (Task 14)", len(ips))
}

// openPanelDB opens the panel's database, read-only.
func (x *insights) openPanelDB() *sql.DB {
	e := x.e
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(x.s.panel.data, "postern.db")+"?mode=ro")
	if err != nil {
		e.fatalf("opening the panel's database: %v", err)
	}
	db.SetMaxOpenConns(1)
	return db
}

// count is the number of rows of the query.
func (x *insights) count(query string, args ...any) int {
	e := x.e
	e.t.Helper()
	db := x.openPanelDB()
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRowContext(e.ctx, query, args...).Scan(&n); err != nil {
		e.fatalf("%s: %v", query, err)
	}
	return n
}

// ---- 7. Policies ----------------------------------------------------------------

func (x *insights) policies() {
	e := x.e
	e.t.Helper()
	x.setPolicy("countries")
	switched := time.Now()
	if n := x.count(`SELECT COUNT(*) FROM ip_sightings`); n != 0 {
		e.errorf("under the policy countries the IP history keeps %d addresses", n)
	}
	if _, err := x.sightings(e.ctx); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		e.errorf("ListIpSightings under the policy countries: %v, want failed_precondition", err)
	}
	e.waitFor("the panel's files without the clients' address", 30*time.Second, time.Second, func(context.Context) (bool, string, error) {
		files, held := x.filesHolding(clientIP)
		if len(held) == 0 {
			return true, fmt.Sprintf("none of %d files holds it", files), nil
		}
		return false, "held by " + strings.Join(held, ", "), nil
	})
	e.waitFor("a country minute under the policy countries", 3*time.Minute, 3*time.Second, func(context.Context) (bool, string, error) {
		n := x.count(`SELECT COUNT(*) FROM stats_country_1m WHERE proxy_id = ? AND ts >= ?`, x.proxyID, switched.Truncate(time.Minute).Unix()+60)
		return n > 0, fmt.Sprintf("%d minutes", n), nil
	})
	if n := x.count(`SELECT COUNT(*) FROM ip_sightings`); n != 0 {
		e.errorf("under the policy countries the IP history got %d addresses", n)
	}

	x.setPolicy("off")
	off := time.Now()
	countries := `SELECT (SELECT COUNT(*) FROM stats_country_1m) + (SELECT COUNT(*) FROM stats_country_1h) + (SELECT COUNT(*) FROM stats_country_1d)`
	if n := x.count(countries); n != 0 {
		e.errorf("under the policy off the country tables keep %d rows", n)
	}
	// A whole minute of traffic under off, after the one the policy changed in.
	e.waitFor("a minute of the proxy under the policy off", 4*time.Minute, 5*time.Second, func(context.Context) (bool, string, error) {
		n := x.count(`SELECT COUNT(*) FROM stats_proxy_1m WHERE proxy_id = ? AND ts > ? AND conns_new > 0`, x.proxyID, off.Unix())
		return n >= 1, fmt.Sprintf("%d minutes", n), nil
	})
	if n := x.count(countries); n != 0 {
		e.errorf("under the policy off %d country rows came", n)
	}
	e.logf("the policy off emptied the country tables, and no country row came in a minute of traffic")
	x.setPolicy("countries")
}

// filesHolding returns how many files of the panel's database there are (the
// file, its WAL and the backups), and those that hold text.
func (x *insights) filesHolding(text string) (files int, held []string) {
	data := x.s.panel.data
	paths := []string{filepath.Join(data, "postern.db"), filepath.Join(data, "postern.db-wal")}
	backups, _ := filepath.Glob(filepath.Join(data, "backups", "*"))
	for _, p := range append(paths, backups...) {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		files++
		if bytes.Contains(b, []byte(text)) {
			held = append(held, filepath.Base(p))
		}
	}
	return files, held
}

// ---- 8. Diagnostics ---------------------------------------------------------------

func (x *insights) diagnostics() {
	e := x.e
	e.t.Helper()
	target := "proxy:" + x.proxyID
	// A change of the IP policy opens the Watch of the node again: a run that
	// starts at that moment is skipped, as the node is not connected.
	var run *panelv1.DiagnosticRun
	for range 3 {
		if run = x.runNode(); run.GetState() != "skipped" {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if run.GetState() != "done" {
		e.fatalf("the node run %s ended %s (%s), want done", run.GetId(), run.GetState(), run.GetError())
	}
	for _, id := range []string{"host.docker", "ingress.bound", "engine.container", "engine.ready", "e2e.l1", "e2e.l2", "panel.connection"} {
		n := 0
		for _, r := range run.GetResults() {
			if r.GetId() != id {
				continue
			}
			n++
			if r.GetStatus() != "ok" {
				e.errorf("the node run: %s of %q is %s: %s", id, r.GetTarget(), r.GetStatus(), r.GetSummary())
			}
		}
		if n == 0 {
			e.errorf("the node run has no result of %s", id)
		}
	}
	e.logf("the node run %s is done: %d ok, %d warn, %d fail, %d skip", run.GetId(), run.GetOkCount(), run.GetWarnCount(),
		run.GetFailCount(), run.GetSkipCount())

	// Paused: the reconciler leaves it, and the feed lists it.
	engine, _ := e.nodeContainer("engine", x.proxyID)
	gen := e.proxyOf(x.a, x.proxyID).GetStatus().GetInstanceGeneration()
	x.pause(engine.ID, true)
	e.t.Cleanup(func() {
		_ = e.raw.do(context.Background(), http.MethodPost, "/containers/"+engine.ID+"/unpause", nil, nil)
	})
	e.waitFor("engine.container in the problem feed", 3*time.Minute, 3*time.Second, func(ctx context.Context) (bool, string, error) {
		if err := x.sameEngine(ctx, gen, engine.ID); err != nil {
			return false, "", err
		}
		p, err := x.problem(ctx, "engine.container", target)
		if err != nil || p == nil {
			return false, "not listed", err
		}
		if !strings.Contains(p.GetSummary(), "paused") {
			return false, "", fmt.Errorf("the problem of engine.container says %q, not that it is paused", p.GetSummary())
		}
		return true, p.GetSeverity() + ": " + p.GetSummary(), nil
	})
	if err := x.sameEngine(e.ctx, gen, engine.ID); err != nil {
		e.fatalf("%v", err)
	}
	x.pause(engine.ID, false)
	e.waitFor("engine.container to leave the problem feed", 2*time.Minute, 3*time.Second, func(ctx context.Context) (bool, string, error) {
		p, err := x.problem(ctx, "engine.container", target)
		if err != nil {
			return false, "", err
		}
		if p == nil {
			return true, "gone", nil
		}
		return false, "listed: " + p.GetSummary(), nil
	})

	// Paused again: the fix recreates the instance.
	x.pause(engine.ID, true)
	e.waitFor("engine.container failing in the light checks", 3*time.Minute, 3*time.Second, func(ctx context.Context) (bool, string, error) {
		l, err := x.a.diag.LatestChecks(ctx, connect.NewRequest(&panelv1.LatestChecksRequest{ProxyId: x.proxyID}))
		if err != nil {
			return false, "", fmt.Errorf("LatestChecks: %w", err)
		}
		for _, r := range l.Msg.GetResults() {
			if r.GetId() == "engine.container" && r.GetTarget() == target {
				ready := (r.GetStatus() == "warn" || r.GetStatus() == "fail") && r.GetFix() == "recreate_instance" && r.GetFixAvailable()
				return ready, fmt.Sprintf("%s, fix %s (available %v)", r.GetStatus(), r.GetFix(), r.GetFixAvailable()), nil
			}
		}
		return false, "no result", nil
	})
	fix, err := x.a.diag.ApplyFix(e.ctx, connect.NewRequest(&panelv1.ApplyFixRequest{
		NodeId: x.nodeID, CheckId: "engine.container", Target: target, Fix: "recreate_instance",
	}))
	if err != nil {
		e.fatalf("ApplyFix recreate_instance: %v", err)
	}
	// The old generation goes once the new one serves: Docker stops no paused
	// container.
	x.pause(engine.ID, false)
	e.waitApplied(x.a, x.nodeID, x.proxyID, fix.Msg.GetGeneration(), "serving", func(p *panelv1.Proxy) (bool, string) {
		g := p.GetStatus().GetInstanceGeneration()
		return g > gen, fmt.Sprintf("engine generation %d", g)
	})
	if _, err := probeUntil(e.ctx, x.s.addr, x.s.domain, x.s.secret, 10*time.Second); err != nil {
		e.fatalf("probe.FakeTLS after the recreate_instance fix: %v", err)
	}
	after := x.waitAfterRun(fix.Msg.GetBeforeRunId(), 5*time.Minute)
	if after.GetRegressed() {
		e.errorf("the after-run of the recreate_instance fix is marked regressed")
	}
	j, err := x.a.diag.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{Source: "audit", ActionPrefix: "diagnostics.fix"}))
	if err != nil {
		e.fatalf("ListJournal: %v", err)
	}
	if !slices.ContainsFunc(j.Msg.GetAudit(), func(a *panelv1.JournalAudit) bool { return a.GetDetails()["fix"] == "recreate_instance" }) {
		e.errorf("the audit log has no diagnostics.fix of recreate_instance")
	}
	e.logf("the recreate_instance fix: a new generation of the engine serves, after-run %s without regression, audited", after.GetId())
}

// runNode runs the diagnostics of the node and returns the run once it ended.
func (x *insights) runNode() *panelv1.DiagnosticRun {
	e := x.e
	e.t.Helper()
	st, err := x.a.diag.StartRun(e.ctx, connect.NewRequest(&panelv1.StartRunRequest{NodeId: x.nodeID, Scope: "node"}))
	if err != nil {
		e.fatalf("StartRun: %v", err)
	}
	var run *panelv1.DiagnosticRun
	e.waitFor("the node run "+st.Msg.GetRunId(), 4*time.Minute, 2*time.Second, func(ctx context.Context) (bool, string, error) {
		r, err := x.a.diag.GetRun(ctx, connect.NewRequest(&panelv1.GetRunRequest{RunId: st.Msg.GetRunId()}))
		if err != nil {
			return false, "", fmt.Errorf("GetRun: %w", err)
		}
		run = r.Msg
		return run.GetState() != "running", run.GetState(), nil
	})
	return run
}

// pause pauses or unpauses a container with the Docker API.
func (x *insights) pause(id string, pause bool) {
	e := x.e
	e.t.Helper()
	op := "unpause"
	if pause {
		op = "pause"
	}
	if err := e.raw.do(e.ctx, http.MethodPost, "/containers/"+id+"/"+op, nil, nil); err != nil {
		e.fatalf("%s of the engine container: %v", op, err)
	}
	e.logf("the engine container is %sd", op)
}

// sameEngine fails when the proxy has another generation or other engine
// containers than the one paused.
func (x *insights) sameEngine(ctx context.Context, gen uint64, id string) error {
	engines, err := x.e.engineContainers(ctx, x.proxyID)
	if err != nil {
		return err
	}
	if c, ok := engines[gen]; !ok || c.ID != id || len(engines) != 1 {
		return fmt.Errorf("while the engine is paused the engines of the proxy are %s, want generation %d alone", describeEngines(engines), gen)
	}
	return nil
}

// problem is the problem of the check for target in the feed, nil when none.
func (x *insights) problem(ctx context.Context, check, target string) (*panelv1.Problem, error) {
	l, err := x.a.diag.ListProblems(ctx, connect.NewRequest(&panelv1.ListProblemsRequest{NodeId: x.nodeID}))
	if err != nil {
		return nil, fmt.Errorf("ListProblems: %w", err)
	}
	for _, p := range l.Msg.GetProblems() {
		if p.GetKind() == "check" && p.GetCheckId() == check && p.GetTarget() == target && p.GetProxyId() == x.proxyID {
			return p, nil
		}
	}
	return nil, nil
}

// ---- 9. The public page --------------------------------------------------------

func (x *insights) publicPage() {
	e := x.e
	e.t.Helper()
	// Not down by its last probes (step 8 paused it).
	if r := x.probeNow(); !r.GetOk() {
		e.fatalf("ProbeNow before the public page: %s", r.GetError())
	}
	const body = "Hello **friends**.\n\n<script>alert(1)</script>\n\n[click](javascript:alert(2))\n\n" +
		"[x](javascript&colon;alert(3))\n\n![logo](https://example.com/logo.png)\n"
	page := &panelv1.PublicPage{
		Enabled: true, Host: publicHost, Title: "Proxies of the run", BodyMd: body, Unavailable: "mark", DefaultLocale: "ru",
		Items: []*panelv1.PublicPageItem{{ProxyId: x.proxyID, PublicName: "Run proxy", PublicNote: "for the test"}},
	}
	x.updatePage(page)
	links, err := x.a.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: x.proxyID}))
	if err != nil {
		e.fatalf("GetProxyLinks: %v", err)
	}

	resp, text := x.public(http.MethodGet, "/?lang=en")
	if resp.StatusCode != http.StatusOK {
		e.fatalf("GET / on %s: %s", publicHost, resp.Status)
	}
	if got := resp.Header.Get("X-Robots-Tag"); got != "noindex, nofollow, noarchive" {
		e.errorf("GET / on %s: X-Robots-Tag %q", publicHost, got)
	}
	if !strings.Contains(text, html.EscapeString(links.Msg.GetTg())) || strings.Contains(text, "<svg") {
		e.errorf("the public page lacks the tg:// link of the proxy, or shows a QR")
	}
	if !strings.Contains(text, "<strong>friends</strong>") {
		e.errorf("the public page lacks the Markdown of its body")
	}
	low := strings.ToLower(text)
	for _, bad := range []string{"alert(", "javascript", "<img", "logo.png"} {
		if strings.Contains(low, bad) {
			e.errorf("the public page holds %q of its body", bad)
		}
	}
	if resp, text := x.public(http.MethodGet, "/robots.txt"); resp.StatusCode != http.StatusOK || !strings.Contains(text, "Disallow: /") {
		e.errorf("robots.txt on %s: %s, %q", publicHost, resp.Status, text)
	}
	// The admin is not on that host: its health check is a path the page does
	// not have (404), and as the POST that Connect sends, a method the page
	// does not take (405, before the path is looked at).
	const check = "/api/postern.panel.v1.HealthService/Check"
	if resp, _ := x.public(http.MethodGet, check); resp.StatusCode != http.StatusNotFound {
		e.errorf("GET of the health check of the admin on %s: %s, want 404", publicHost, resp.Status)
	}
	if resp, _ := x.public(http.MethodPost, check); resp.StatusCode != http.StatusMethodNotAllowed {
		e.errorf("the health check of the admin on %s: %s, want 405", publicHost, resp.Status)
	}
	if code := x.health(); code != http.StatusOK {
		e.errorf("the health check on 127.0.0.1: %d, want 200", code)
	}
	e.logf("the public page on %s serves the proxy's link and no QR, none of the body's script, links or image, noindex, "+
		"and no admin", publicHost)

	// Paused, marked: on the very next request.
	if _, err := x.a.proxies.SetProxyEnabled(e.ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: x.proxyID, Enabled: false})); err != nil {
		e.fatalf("SetProxyEnabled(false): %v", err)
	}
	_, text = x.public(http.MethodGet, "/?lang=en")
	low = strings.ToLower(text)
	if !strings.Contains(text, "Run proxy") || !strings.Contains(low, "unavailable") {
		e.errorf("the paused proxy is not marked unavailable on the public page")
	}
	for _, bad := range []string{"tg://", "t.me", strings.ToLower(x.s.secretHex)} {
		if strings.Contains(low, bad) {
			e.errorf("the public page shows the paused proxy with %s", strings.ReplaceAll(bad, strings.ToLower(x.s.secretHex), "its secret"))
		}
	}
	page.Unavailable = "hide"
	x.updatePage(page)
	if _, text = x.public(http.MethodGet, "/?lang=en"); strings.Contains(text, "Run proxy") {
		e.errorf("the paused proxy is on the public page with hide")
	}
	e.logf("the paused proxy is marked unavailable without its link or secret at once, and gone with hide")
}

func (x *insights) updatePage(page *panelv1.PublicPage) {
	e := x.e
	e.t.Helper()
	if _, err := x.a.page.UpdatePublicPage(e.ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{Page: page})); err != nil {
		e.fatalf("UpdatePublicPage: %v", err)
	}
}

// public sends a request for publicHost to the panel, without a session.
func (x *insights) public(method, path string) (*http.Response, string) {
	e := x.e
	e.t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequestWithContext(e.ctx, method, x.s.panel.base+path, body)
	if err != nil {
		e.fatalf("%v", err)
	}
	req.Host = publicHost
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		e.fatalf("%s %s on %s: %v", method, path, publicHost, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp, string(b)
}

// health is the status of the panel's health check on its own address.
func (x *insights) health() int {
	e := x.e
	e.t.Helper()
	req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, x.s.panel.base+"/api/postern.panel.v1.HealthService/Check", strings.NewReader("{}"))
	if err != nil {
		e.fatalf("%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.fatalf("the health check: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// ---- 10. The texts of the diagnostics --------------------------------------------

// checkDiagnosticTexts fails the test when a text of the diagnostics (every
// run of the node with its results, the light checks), of the problem feed or
// of the journal (events and audit) holds a secret of the run or the clients'
// address.
func (x *insights) checkDiagnosticTexts() {
	e := x.e
	e.t.Helper()
	var b strings.Builder
	add := func(parts ...string) {
		for _, p := range parts {
			b.WriteString(p)
			b.WriteByte('\n')
		}
	}
	addResult := func(r *panelv1.CheckResult) { add(r.GetSummary(), r.GetEvidence(), r.GetHint()) }
	runs, err := x.a.diag.ListRuns(e.ctx, connect.NewRequest(&panelv1.ListRunsRequest{NodeId: x.nodeID, Limit: 50}))
	if err != nil {
		e.fatalf("ListRuns: %v", err)
	}
	for _, r := range runs.Msg.GetRuns() {
		full, err := x.a.diag.GetRun(e.ctx, connect.NewRequest(&panelv1.GetRunRequest{RunId: r.GetId()}))
		if err != nil {
			e.fatalf("GetRun: %v", err)
		}
		add(full.Msg.GetError(), full.Msg.GetChange())
		for _, res := range full.Msg.GetResults() {
			addResult(res)
		}
	}
	light, err := x.a.diag.LatestChecks(e.ctx, connect.NewRequest(&panelv1.LatestChecksRequest{NodeId: x.nodeID}))
	if err != nil {
		e.fatalf("LatestChecks: %v", err)
	}
	for _, res := range light.Msg.GetResults() {
		addResult(res)
	}
	problems, err := x.a.diag.ListProblems(e.ctx, connect.NewRequest(&panelv1.ListProblemsRequest{}))
	if err != nil {
		e.fatalf("ListProblems: %v", err)
	}
	for _, p := range problems.Msg.GetProblems() {
		add(p.GetSummary(), p.GetHint())
	}
	var events, audit int
	for _, source := range []string{"events", "audit"} {
		for cursor := ""; ; {
			j, err := x.a.diag.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{Source: source, Limit: 200, Cursor: cursor}))
			if err != nil {
				e.fatalf("ListJournal %s: %v", source, err)
			}
			for _, ev := range j.Msg.GetEvents() {
				events++
				add(ev.GetMessage())
				for k, v := range ev.GetDetails() {
					add(k, v)
				}
			}
			for _, a := range j.Msg.GetAudit() {
				audit++
				add(a.GetTarget())
				for k, v := range a.GetDetails() {
					add(k, v)
				}
			}
			if cursor = j.Msg.GetNextCursor(); cursor == "" {
				break
			}
		}
	}
	e.sec.mu.Lock()
	leaks := slices.Clone(e.sec.leaks)
	e.sec.mu.Unlock()
	leaks = append(leaks, leak{what: "the clients' address", value: clientIP})
	text := b.String()
	found := findLeaks([]logText{{name: "the texts of the diagnostics, the problem feed and the journal", text: text, whole: true}}, leaks)
	for _, f := range found {
		e.errorf("%s", f)
	}
	if len(found) == 0 {
		e.logf("no text of %d runs, the light checks, %d problems, %d events and %d audit entries (%d bytes) holds a secret "+
			"of the run or the clients' address", len(runs.Msg.GetRuns()), len(problems.Msg.GetProblems()), events, audit, len(text))
	}
}
