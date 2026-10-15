// Package probes probes every proxy from the panel, as a client would connect
// from outside: an L2 probe (the fake-TLS handshake with the proxy's secret,
// then a datacenter's answer through the proxy) to the proxy's link host and
// listener port, or for a WEB proxy GET https://<domain>/ (web.go), on a
// schedule of its own per proxy and on request. The results are stored
// (vantage "panel", kind "l2" or "web"), turned into the events
// probe.failed and probe.recovered, and tell the public page which proxies are
// down (Scheduler.Down).
//
// The panel's probes reveal the fleet to anyone who can watch the panel's
// traffic: they connect to every proxy from the panel's address.
package probes

import (
	"context"
	"errors"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/probe"
)

// The vantage and kind of the panel's probes, as they are stored.
const (
	VantagePanel = "panel"
	KindL2       = "l2"
)

// The classes of a failed probe, which is all that is stored and shown of its
// error: the errors of package probe can name what came instead of an answer,
// which is no business of a list of probes.
const (
	ErrUnreachable    = "unreachable"
	ErrRefusedSecret  = "refused the secret"
	ErrNoDatacenterL1 = "no datacenter answered through the proxy (L1 ok)"
)

const (
	// probeTimeout bounds each of the two probes of a proxy.
	probeTimeout = 10 * time.Second
	// probeDC is the datacenter that L2 asks for through the proxy.
	probeDC = 2
)

// A Target is a proxy as the panel probes it.
type Target struct {
	ProxyID string
	Type    string
	Addr    string // the link host and the listener port, host:port; a WEB proxy's URL
	SNI     string // the proxy's domain
	Secret  []byte // the 16 bytes of the secret (none for WEB); never logged
}

// A ProbeFunc probes a target and says how it went: p.OK, p.LatencyMS and
// p.Error (one of the classes) of the result, and whether the proxy proved
// that it knows the secret (L1). The scheduler fills in the rest of p.
type ProbeFunc func(ctx context.Context, t Target) (p store.Probe, l1OK bool)

// l2Func and l1Func are probe.L2 and probe.FakeTLS for a target, which tests
// replace.
type (
	l2Func func(ctx context.Context, addr, sni string, secret []byte, dc int16, opt probe.Options) error
	l1Func func(ctx context.Context, addr, sni string, secret []byte, opt probe.Options) error
)

// RealProbe is the probe of the panel: probe.L2 to datacenter 2 through the
// proxy and, when it fails, probe.FakeTLS to say why.
func RealProbe() ProbeFunc { return newProbe(probe.L2, probe.FakeTLS, time.Now) }

func newProbe(l2 l2Func, l1 l1Func, now func() time.Time) ProbeFunc {
	return func(ctx context.Context, t Target) (store.Probe, bool) {
		opt := probe.Options{Timeout: probeTimeout}
		start := now()
		err := l2(ctx, t.Addr, t.SNI, t.Secret, probeDC, opt)
		p := store.Probe{OK: err == nil, LatencyMS: latencyMS(now().Sub(start))}
		if err == nil {
			return p, true
		}
		switch l1err := l1(ctx, t.Addr, t.SNI, t.Secret, opt); {
		case l1err == nil:
			p.Error = ErrNoDatacenterL1
			return p, true
		case errors.Is(l1err, probe.ErrBadServerDigest):
			p.Error = ErrRefusedSecret
		default:
			p.Error = ErrUnreachable
		}
		return p, false
	}
}

// latencyMS is d in whole milliseconds, 0 for less.
func latencyMS(d time.Duration) uint32 {
	switch ms := d.Milliseconds(); {
	case ms < 0:
		return 0
	case ms > int64(^uint32(0)):
		return ^uint32(0)
	default:
		return uint32(ms)
	}
}
