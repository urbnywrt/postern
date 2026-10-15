package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/probe"
)

// The defaults of the health checks, for every field of edgev1.HealthCheck that is
// zero or empty.
const (
	defaultInterval         = 30 * time.Second
	defaultFailThreshold    = 3
	defaultRecoverThreshold = 2
)

// defaultDCAddrs are the datacenters DC1 to DC5 of Telegram, on port 443. They
// are the default of a setting, and not a constant of the code: the setting is
// DcAddrs of the health check.
var defaultDCAddrs = []string{"149.154.175.50:443", "149.154.167.51:443", "149.154.175.100:443", "149.154.167.91:443", "91.108.56.130:443"}

// defaultEchoURLs are services that answer with the address the request came
// from, as plain text.
var defaultEchoURLs = []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}

const (
	// maxConcurrentProbes bounds the members that a round probes at once. A node
	// with a subscription of a hundred servers has a hundred members.
	maxConcurrentProbes = 32
	// maxEchoAnswer bounds what is read of the answer of an echo service: the
	// longest address is 45 bytes.
	maxEchoAnswer = 128
)

// DefaultHealthCheck returns the parameters of the health checks that Apply uses
// for everything that a HealthCheck leaves out: a round every 30 seconds, 4
// seconds for a dial through a member and for the check of a datacenter (the
// dial and the exchange), down after 3 failures in a row, up again after 2
// successes in a row, the datacenters DC1 to DC5 of Telegram on port 443, and
// three echo services for the exit address. The message is the caller's.
func DefaultHealthCheck() *edgev1.HealthCheck {
	return &edgev1.HealthCheck{
		IntervalSeconds:  uint32(defaultInterval / time.Second),
		TimeoutSeconds:   uint32(DefaultDialTimeout / time.Second),
		FailThreshold:    defaultFailThreshold,
		RecoverThreshold: defaultRecoverThreshold,
		DcAddrs:          slices.Clone(defaultDCAddrs),
		EchoUrls:         slices.Clone(defaultEchoURLs),
	}
}

// checkConfig is a HealthCheck with its defaults filled in and its addresses
// checked.
type checkConfig struct {
	interval, timeout time.Duration
	failThreshold     int
	recoverThreshold  int
	dcAddrs           []string
	echoURLs          []string
}

func newCheckConfig(hc *edgev1.HealthCheck) (checkConfig, error) {
	c := checkConfig{
		interval:         defaultInterval,
		timeout:          DefaultDialTimeout,
		failThreshold:    defaultFailThreshold,
		recoverThreshold: defaultRecoverThreshold,
		dcAddrs:          slices.Clone(defaultDCAddrs),
		echoURLs:         slices.Clone(defaultEchoURLs),
	}
	if s := hc.GetIntervalSeconds(); s > 0 {
		c.interval = time.Duration(s) * time.Second
	}
	if s := hc.GetTimeoutSeconds(); s > 0 {
		c.timeout = time.Duration(s) * time.Second
	}
	if n := hc.GetFailThreshold(); n > 0 {
		c.failThreshold = int(n)
	}
	if n := hc.GetRecoverThreshold(); n > 0 {
		c.recoverThreshold = int(n)
	}
	if given := hc.GetDcAddrs(); len(given) > 0 {
		for _, a := range given {
			if _, _, err := rules.ParseHostPort(a); err != nil {
				return checkConfig{}, fmt.Errorf("egress: dc_addrs: %q: %w", a, err)
			}
		}
		c.dcAddrs = slices.Clone(given)
	}
	if given := hc.GetEchoUrls(); len(given) > 0 {
		for _, raw := range given {
			u, err := url.Parse(raw)
			switch {
			case err != nil:
				return checkConfig{}, fmt.Errorf("egress: echo_urls: %q is not a URL", raw)
			case u.Scheme != "http" && u.Scheme != "https":
				return checkConfig{}, fmt.Errorf("egress: echo_urls: %q is not an http or https URL", raw)
			case u.Hostname() == "":
				return checkConfig{}, fmt.Errorf("egress: echo_urls: %q has no host", raw)
			case u.User != nil:
				return checkConfig{}, errors.New("egress: echo_urls: a URL carries credentials")
			}
		}
		c.echoURLs = slices.Clone(given)
	}
	return c, nil
}

// probeResult is what the check of the datacenters through a member found out.
type probeResult struct {
	ok      bool          // a datacenter answered with its resPQ
	latency time.Duration // the time from the start of the dial to the resPQ
	err     error         // why no datacenter did, the error of the last; nil when one did
	aborted bool          // the check was cut short by its context: it found nothing out
}

// exitResult is what the echo services said of the exit address of a member.
type exitResult struct {
	ip      string // the exit address, "" when no echo service gave it
	err     error  // why not, the error of the last echo service
	aborted bool   // cut short by its context: it says nothing about the echo services
}

// probeFunc checks the datacenters through one member, and exitFunc asks the
// echo services for its exit address. A router has the real ones, probeMember
// and probeExit, and a test can give it ones that answer from a script.
type (
	probeFunc func(ctx context.Context, m *member, c checkConfig) probeResult
	exitFunc  func(ctx context.Context, m *member, c checkConfig) exitResult
)

// RunHealth runs the health checks until ctx is done, and then returns nil. A
// router has one loop of checks: while a call runs, another returns
// ErrHealthRunning at once.
//
// The first round begins at once, and each begins an interval after the one before
// it began; a round that takes longer than the interval is followed by the next
// without a pause. In a round every member is probed, once however many chains it
// is in, a few at a time (up to 32). A probe checks the datacenters of the health
// check through the member, in order: it dials one and sends it the first message
// of MTProto's key exchange (probe.DCPing), and the member passes if a datacenter
// answers it with its resPQ; the check of a member has twice the timeout in all
// (see probeMember). Then it asks the echo services of the health check for the
// exit address of the member, in order, and takes the first answer.
//
// Hysteresis turns the passes and the failures into the status of the member:
// fail_threshold failures in a row take it down, recover_threshold successes in a
// row bring it back up, a success interrupts the failures and a failure the
// successes. A member that was never checked is up with its first success. The
// status is recorded as soon as the datacenters have spoken, before the echo
// services are asked.
//
// A member that Apply adds does not wait for the next round: it is probed as soon
// as it is added, and the members that are known are left alone until their
// round.
//
// An Apply that changes the interval moves the next round at once: it is due
// the new interval after the start of the last round (at once if that is past).
// An edge that ran with the default interval before its first chain came does
// not keep that wait for the chain's checks.
//
// Only the datacenters take a member down. A member that cannot be asked for its
// exit address is up all the same, and the loss of the address is reported with a
// warning, once. The probe of a member that is down is made like any other: that is
// how it comes back.
//
// A probe that ends because ctx is done found nothing out and is not recorded; when
// ctx ends while the echo services are asked, the status is recorded already and
// the exit address is not.
func (r *Router) RunHealth(ctx context.Context) error {
	if !r.healthRuns.CompareAndSwap(false, true) {
		return ErrHealthRunning
	}
	defer r.healthRuns.Store(false)
	var passive sync.WaitGroup // the passive rounds (passive.go), which end with the loop
	defer passive.Wait()
	clk := r.d.clock
	var started time.Time // the start of the last full round; zero before the first
	for {
		for {
			next := clk.Now() // the first round is due at once
			if !started.IsZero() {
				next = started.Add(r.cur.Load().check.interval)
			}
			wait := next.Sub(clk.Now())
			if wait <= 0 {
				break
			}
			t := clk.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C():
			case <-r.wake:
				t.Stop()
				r.probeRound(ctx, true)
			case <-r.retime:
				t.Stop() // the interval changed: the wait is worked out again
			case m := <-r.passive:
				t.Stop()
				r.startPassive(ctx, &passive, m)
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		started = clk.Now()
		r.probeRound(ctx, false)
	}
}

// probeRound probes the members of the configuration, all of them or only those
// that were never probed.
func (r *Router) probeRound(ctx context.Context, onlyNew bool) {
	cfg := r.cur.Load()
	var todo []*member
	for _, m := range cfg.members {
		if !onlyNew || !m.wasProbed() {
			todo = append(todo, m)
		}
	}
	if len(todo) == 0 {
		return
	}
	sem := make(chan struct{}, maxConcurrentProbes)
	var wg sync.WaitGroup
	for _, m := range todo {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.probeOne(ctx, cfg, m)
		}()
	}
	wg.Wait()
}

// probeOne probes a member: it checks the datacenters through it and records the
// status, and then, when the member passed and there are echo services, asks them
// for its exit address and records that. Each record says what it changed. A
// panic in the probe is logged with its stack and counts for nothing.
func (r *Router) probeOne(ctx context.Context, cfg *config, m *member) {
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("egress: health probe panicked", "member", m.key, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	res := r.d.probe(ctx, m, cfg.check)
	if res.aborted || ctx.Err() != nil {
		return
	}
	cur := r.cur.Load() // the thresholds of the configuration of now
	r.logRecorded(cur, m, res, m.record(res, cur.check, r.d.clock.Now()))
	if !res.ok || len(cfg.check.echoURLs) == 0 {
		return
	}
	ex := r.d.exit(ctx, m, cfg.check)
	if ex.aborted || ctx.Err() != nil {
		return
	}
	r.logExit(r.cur.Load(), m, ex, m.recordExit(ex))
}

func (r *Router) logRecorded(cfg *config, m *member, res probeResult, rec recorded) {
	chains := cfg.chainsOf(m)
	if rec.from != rec.to {
		switch rec.to {
		case statusDown:
			r.log.Warn("egress: member is down", "member", m.key, "chains", chains,
				"from", rec.from.String(), "to", rec.to.String(), "failures", rec.failures, "reason", errText(res.err))
		case statusUp:
			r.log.Info("egress: member is up", "member", m.key, "chains", chains,
				"from", rec.from.String(), "to", rec.to.String(), "latency_ms", latencyMs(res.latency))
		}
	}
	r.log.Debug("egress: member checked", "member", m.key, "ok", res.ok, "status", rec.to.String(),
		"latency_ms", latencyMs(res.latency), "reason", errText(res.err))
}

func (r *Router) logExit(cfg *config, m *member, ex exitResult, rec exitRecorded) {
	chains := cfg.chainsOf(m)
	switch {
	case rec.lost:
		r.log.Warn("egress: exit ip is not known: no echo service answered", "member", m.key, "chains", chains, "reason", errText(ex.err))
	case rec.back:
		r.log.Info("egress: exit ip is known again", "member", m.key, "chains", chains, "exit_ip", rec.ip)
	case rec.first:
		r.log.Info("egress: exit ip is known", "member", m.key, "chains", chains, "exit_ip", rec.ip)
	}
	if rec.change {
		r.log.Info("egress: exit ip changed", "member", m.key, "chains", chains, "from", rec.prev, "to", rec.ip)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// probeMember checks the datacenters through one member (checkDC), in order: the
// first that answers settles it, and the time it took is the latency. A member
// for which none answers fails, with the error of the last that was checked.
//
// A member has twice the timeout for its check in all, whatever the number of
// datacenters: a datacenter is given its timeout, or what is left of that when
// it is less, and the ones after the time is up are not checked. And a proxy
// that acknowledged the CONNECT to a datacenter and then hung up, the failure of
// Xray whose way out is broken, has failed the round: the other datacenters
// would fare no better through it, and are not dialed. A round of the checks
// thus costs a member that does not work two timeouts at most, which counts on a
// node with a hundred members.
func (r *Router) probeMember(ctx context.Context, m *member, c checkConfig) probeResult {
	budget, cancel := context.WithTimeout(ctx, 2*c.timeout)
	defer cancel()
	// The time is up at the deadline itself, as in Router.Dial.
	end, _ := budget.Deadline()
	proxy := m.spec.kind == KindSOCKS5 || m.spec.kind == KindHTTP
	var res probeResult
	for _, dc := range c.dcAddrs {
		if !time.Now().Before(end) {
			break
		}
		latency, acked, err := r.checkDC(budget, m, dc, c.timeout)
		if err == nil {
			return probeResult{ok: true, latency: latency}
		}
		if ctx.Err() != nil {
			return probeResult{aborted: true}
		}
		res.err = fmt.Errorf("datacenter %s: %w", dc, err)
		if proxy && acked && hungUp(err) {
			break
		}
	}
	return res
}

// hungUp reports whether err is the end of a connection that the other side
// closed or reset.
func hungUp(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
}

// checkDC dials the datacenter at dc through m and sends it the first message of
// MTProto's key exchange (probe.DCPing). It passes only when the datacenter
// answers with its resPQ: a proxy that acknowledges a connection before it has
// made it, as the SOCKS inbound of Xray does, takes the request and hangs up when
// its way out fails, and a connection alone proves nothing (F1). The dial and the
// exchange have timeout between them; the latency is the time from the start of
// the dial to the resPQ. acked says that the dial succeeded: the connection was
// made, or the proxy said it was.
func (r *Router) checkDC(ctx context.Context, m *member, dc string, timeout time.Duration) (latency time.Duration, acked bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := r.d.clock.Now()
	conn, err := dialMember(ctx, timeout, m, dc)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = conn.Close() }()
	if err := probe.DCPing(ctx, conn); err != nil {
		return 0, true, err
	}
	return r.d.clock.Now().Sub(start), true, nil
}

// probeExit asks the echo services for the exit address of a member, in order,
// through the member, and the first that answers with an address settles it.
// Each request has twice the timeout of a dial, for a request is the connection
// and a TLS handshake and an exchange.
func (r *Router) probeExit(ctx context.Context, m *member, c checkConfig) exitResult {
	var res exitResult
	for _, raw := range c.echoURLs {
		ip, err := fetchExitIP(ctx, m.dialer, raw, 2*c.timeout, r.d.echoTLS)
		if err == nil {
			return exitResult{ip: ip}
		}
		if ctx.Err() != nil {
			return exitResult{aborted: true}
		}
		res.err = err
	}
	return res
}

// newEchoTransport returns the transport of the requests to the echo services: they
// go through d and nothing else, so it has no proxy of its own and ignores the
// ones of the environment, and each connection serves one request.
func newEchoTransport(d Dialer, timeout time.Duration, tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        tlsCfg,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16 << 10,
	}
}

// fetchExitIP asks the echo service at rawURL for the address that the request
// comes from, through d, and returns it.
//
// The request is a GET, in the connection that d makes: a name in the URL is the
// business of d, as for any member, and the proxies of the environment are not
// used. TLS is checked against the roots of the system, or against tlsCfg. The
// answer must be a 200 whose body, at most 128 bytes, is an IP address and
// nothing else, and a public one: a page, or the address of the node's own
// network, is not an exit address. A redirect is not followed. The request ends
// with timeout, and its connection with it.
func fetchExitIP(ctx context.Context, d Dialer, rawURL string, timeout time.Duration, tlsCfg *tls.Config) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := newEchoTransport(d, timeout, tlsCfg)
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "postern-edge")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the echo service answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEchoAnswer+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxEchoAnswer {
		return "", errors.New("the answer of the echo service is too long")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return "", errors.New("the answer of the echo service is not an IP address")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", fmt.Errorf("the answer of the echo service, %s, is not a public address", ip)
	}
	return ip.String(), nil
}
