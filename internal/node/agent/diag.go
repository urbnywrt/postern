package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	// warpAccountFile is the WARP account of a WARP egress in its state
	// directory (the reconciler's file): its token and key are secrets the
	// scrubber takes out.
	warpAccountFile = "warp-account.json"
	// diagHTTPTimeout bounds one request of a check made with Env.HTTP.
	diagHTTPTimeout = 10 * time.Second
	// firstIPsTimeout bounds the lookup of the public IPs for the first
	// scrubber.
	firstIPsTimeout = 5 * time.Second
)

// diagDeps are what the node's diagnostics are made of.
type diagDeps struct {
	store     *state.Store
	docker    dockerapi.Client
	edge      func(gen uint64) reconcile.EdgeClient
	drivers   map[nodev1.Engine]engines.Driver
	artifacts *artifacts.Store
	info      *hostInfo
	home      string
	stats     *statsCollector // nil: no statistics
	certs     *acme.Manager   // nil: web.cert skips
	// egressReason is the reconciler's reason why an egress's instance does
	// not start (egress.member); nil: none.
	egressReason func(id string) string
	now          func() time.Time
	checks       []diag.Check // nil: every check (newDiagRunner)
}

// newDiagRunner makes the runner of the node's checks: the host and ingress
// catalogue, the engine, egress, end-to-end and WEB checks.
func newDiagRunner(d diagDeps) *diag.Runner {
	checks := d.checks
	if checks == nil {
		checks = slices.Concat(diag.Catalogue(), diag.EngineChecks(), diag.EgressChecks(), diag.E2EChecks(), diag.WebChecks())
	}
	return diag.NewRunner(d.env(), checks)
}

func (d diagDeps) env() diag.Env {
	var lastIPs atomic.Pointer[[]netip.Addr] // what host.public_ips last found
	dialer := &net.Dialer{Timeout: diagHTTPTimeout}
	dohClient := doh.New(doh.DefaultEndpoints)
	env := diag.Env{
		Store:     d.store,
		Docker:    d.docker,
		Drivers:   d.drivers,
		Artifacts: d.artifacts,
		HTTP: &http.Client{Timeout: diagHTTPTimeout, Transport: &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext, TLSHandshakeTimeout: diagHTTPTimeout, DisableKeepAlives: true,
		}},
		DoH:      dohClient,
		LookupIP: dohClient.LookupIP, // web.dns
		DialUDP:  (&net.Dialer{}).DialContext,
		Proc:     d.info.proc,
		Now:      d.now,
		Log:      d.info.log,
		PortOwners: func(ctx context.Context) []diag.SocketOwner {
			return socketOwners(ctx, d.info.proc, d.docker, os.Getpid())
		},
		PublicIPs: func(ctx context.Context) []netip.Addr {
			out := parseAddrs(d.info.publicIPs(ctx))
			lastIPs.Store(&out)
			return out
		},
		DiskSpace: diag.DiskSpace,
		DiskPath:  d.home,
		// The gate's checks of the way out, through the SOCKS port of a
		// proxy's serving engine.
		PingDC:      reconcile.PingDC,
		ProxySecret: reconcile.ProxySecretCheck,
		ProxyDCs:    reconcile.ProxyDCs,
	}
	if d.certs != nil {
		env.CertStatus = d.certs.Status // web.cert
		env.CertTrusted = func(domain string) error { return d.certs.Trusted(domain, nil) }
	}
	env.EgressReason = d.egressReason
	if d.edge != nil {
		env.Edge = func(gen uint64) diag.EdgeClient { return d.edge(gen) }
	}
	if d.stats != nil {
		env.StatsOverflow = d.stats.overflow
		env.AddProbe = d.stats.addProbe // the node's L2 probes (e2e.l2)
	}
	env.Scrubber = func(st *nodev1.NodeState, rt *state.Runtime) *diag.Scrubber {
		// The node's public IPs as the interfaces have them, and as the
		// last check found them (an echo service's answer): no lookup here.
		var keep []netip.Addr
		if d.info.addrs != nil {
			if list, err := d.info.addrs(); err == nil {
				keep = publicAddrs(list)
			}
		}
		p := lastIPs.Load()
		if p == nil {
			// The first run: no check has asked yet, so ask now (the echo
			// services' answer is cached), briefly, so that the node's
			// address found only by them is not redacted in that run.
			ctx, cancel := context.WithTimeout(context.Background(), firstIPsTimeout)
			ips := parseAddrs(d.info.publicIPs(ctx))
			cancel()
			lastIPs.CompareAndSwap(nil, &ips)
			p = lastIPs.Load()
		}
		keep = append(keep, *p...)
		return diagScrubber(d.store, st, rt, keep)
	}
	return env
}

// diagScrubber is the scrubber of the state and the runtime record, with the
// WARP accounts of the WARP egresses (their tokens and keys live in files of
// their own, not in the state).
func diagScrubber(store *state.Store, st *nodev1.NodeState, rt *state.Runtime, keep []netip.Addr) *diag.Scrubber {
	s := diag.NewScrubber(st, rt, keep)
	if store == nil {
		return s
	}
	var extra []string
	for _, e := range st.GetEgresses() {
		if e.GetKind() != nodev1.EgressKind_EGRESS_KIND_WARP {
			continue
		}
		data, err := readFileLimited(filepath.Join(store.Paths.EgressStateDir(e.GetId()), warpAccountFile), 64<<10)
		if err != nil {
			continue
		}
		var acct struct {
			PrivateKey string `json:"private_key"`
			Token      string `json:"token"`
		}
		if json.Unmarshal(data, &acct) == nil {
			extra = append(extra, acct.PrivateKey, acct.Token)
		}
	}
	if len(extra) == 0 {
		return s
	}
	return s.WithSecrets(extra...)
}

// parseAddrs reads the addresses of list, leaving out what is not one.
func parseAddrs(list []string) []netip.Addr {
	out := []netip.Addr{}
	for _, s := range list {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}
