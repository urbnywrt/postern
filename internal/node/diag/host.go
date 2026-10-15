package diag

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	mib = 1 << 20
	gib = 1 << 30
)

// ---- host.docker ------------------------------------------------------------------

func checkDocker(ctx context.Context, env *Env) []Result {
	if env.Docker == nil {
		return []Result{{Status: Skip, Summary: "no Docker client"}}
	}
	v, err := env.Docker.Ping(ctx)
	if err != nil {
		return []Result{{Status: Fail, Summary: "Docker does not answer", Evidence: err.Error(),
			Hint: "the engines and the edge run in Docker: check that the Docker daemon runs (systemctl status docker)"}}
	}
	return []Result{{Status: OK, Summary: "Docker answers (API " + v + ")"}}
}

// ---- host.clock -------------------------------------------------------------------

const (
	clockWarn       = 2 * time.Second
	clockFail       = 30 * time.Second
	clockReqTimeout = 5 * time.Second
	minClockAnswers = 2
)

// dateSkew is how far the local clock is off by one answer: the distance from
// local, the local time when the answer arrived, to the server's time then,
// which lies in [date, date + 1 s] (Date has whole seconds) and was taken at
// most rtt before local. Never negative.
func dateSkew(local, date time.Time, rtt time.Duration) time.Duration {
	rtt = min(max(rtt, 0), time.Hour)
	d := local.Sub(date) // saturates
	switch {
	case d < 0:
		if d == time.Duration(-1<<63) {
			return time.Duration(1<<63 - 1)
		}
		return -d
	case d > time.Second+rtt:
		return d - time.Second - rtt
	}
	return 0
}

type clockAnswer struct {
	url    string
	status int
	date   time.Time
	local  time.Time
	rtt    time.Duration
	skew   time.Duration
	err    error
}

func checkClock(ctx context.Context, env *Env) []Result {
	urls := env.ClockURLs
	if len(urls) == 0 {
		urls = doh.DefaultEndpoints
	}
	dial := env.ClockDial
	if dial == nil {
		dial = (&net.Dialer{Timeout: clockReqTimeout}).DialContext
	}
	var tlsConf = env.ClockTLS
	if tlsConf != nil {
		tlsConf = tlsConf.Clone()
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: tlsConf, DisableKeepAlives: true, TLSHandshakeTimeout: clockReqTimeout},
		Timeout:   clockReqTimeout + time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()
	answers := make([]clockAnswer, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Go(func() { answers[i] = askDate(ctx, client, env, u) })
	}
	wg.Wait()

	var skews []time.Duration
	var lines []string
	for _, a := range answers {
		if a.err != nil {
			lines = append(lines, fmt.Sprintf("%s: no answer (%v)", a.url, a.err))
			continue
		}
		skews = append(skews, a.skew)
		lines = append(lines, fmt.Sprintf("%s: status %d, Date %s, local %s, round trip %s, off by %s",
			a.url, a.status, a.date.UTC().Format(time.RFC1123), a.local.UTC().Format(time.RFC3339Nano), a.rtt.Round(time.Millisecond), a.skew.Round(time.Millisecond)))
	}
	evidence := strings.Join(lines, "\n")
	if len(skews) < minClockAnswers {
		return []Result{{Status: Skip, Summary: fmt.Sprintf("%d of %d time sources answered; %d are needed", len(skews), len(urls), minClockAnswers)}}
	}
	med := median(skews)
	r := Result{Evidence: evidence, Summary: fmt.Sprintf("the clock is off by %s (median of %d sources)", med.Round(time.Millisecond), len(skews))}
	switch {
	case med > clockFail:
		r.Status = Fail
	case med > clockWarn:
		r.Status = Warn
	default:
		r.Status = OK
	}
	if r.Status != OK {
		r.Hint = "synchronise the clock of the host (chrony or systemd-timesyncd); TLS and the MTProto handshake need it"
	}
	return []Result{r}
}

func askDate(ctx context.Context, client *http.Client, env *Env, u string) clockAnswer {
	a := clockAnswer{url: u}
	ctx, cancel := context.WithTimeout(ctx, clockReqTimeout)
	defer cancel()
	var mu sync.Mutex
	var wrote, first time.Time
	trace := &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) {
			mu.Lock()
			wrote = time.Now()
			mu.Unlock()
		},
		GotFirstResponseByte: func() {
			mu.Lock()
			first = time.Now()
			mu.Unlock()
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodHead, u, nil)
	if err != nil {
		a.err = err
		return a
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		a.err = err
		return a
	}
	_ = resp.Body.Close()
	a.local = env.now()
	a.status = resp.StatusCode
	mu.Lock()
	switch {
	case !wrote.IsZero() && !first.IsZero() && !first.Before(wrote):
		a.rtt = first.Sub(wrote)
	default:
		a.rtt = time.Since(start)
	}
	mu.Unlock()
	date, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		a.err = fmt.Errorf("status %d without a Date", resp.StatusCode)
		return a
	}
	a.date = date
	a.skew = dateSkew(a.local, date, a.rtt)
	return a
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return s[n/2-1]/2 + s[n/2]/2
}

// ---- host.dns ---------------------------------------------------------------------

var defaultDNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

const udpTimeout = 4 * time.Second

// dnsAnswer is what an answer says: its code and its IPv4 addresses, sorted.
type dnsAnswer struct {
	rcode dnsmessage.RCode
	addrs []string
}

func (a dnsAnswer) String() string {
	if a.rcode != dnsmessage.RCodeSuccess {
		return strings.TrimPrefix(a.rcode.String(), "RCode")
	}
	if len(a.addrs) == 0 {
		return "no address"
	}
	return "A " + strings.Join(a.addrs, " ")
}

func (a dnsAnswer) equal(b dnsAnswer) bool {
	return a.rcode == b.rcode && slices.Equal(a.addrs, b.addrs)
}

func checkDNS(ctx context.Context, env *Env) []Result {
	var label [8]byte
	_, _ = rand.Read(label[:])
	name := hex.EncodeToString(label[:]) + ".telegram.org."
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	query, err := dnsQuery(id, name)
	if err != nil {
		return []Result{{Status: Skip, Summary: "the question cannot be made: " + err.Error()}}
	}
	servers := env.DNSServers
	if len(servers) == 0 {
		servers = defaultDNSServers
	}

	var dohAns dnsAnswer
	var dohErr error
	var dohFailed []error // the endpoints that gave no answer when one did
	udp := make([]struct {
		ans dnsAnswer
		err error
	}, len(servers))
	var wg sync.WaitGroup
	wg.Go(func() {
		if env.DoH == nil {
			dohErr = errors.New("no DoH client")
			return
		}
		var msg []byte
		var err error
		if all, ok := env.DoH.(AllExchanger); ok {
			msg, dohFailed, err = all.ExchangeAll(ctx, query)
		} else {
			msg, err = env.DoH.Exchange(ctx, query)
		}
		if err != nil {
			dohFailed = nil // they are in err
			dohErr = err
			return
		}
		dohAns, dohErr = parseDNSAnswer(msg, 0, false)
	})
	for i, s := range servers {
		wg.Go(func() { udp[i].ans, udp[i].err = askUDP(ctx, env, s, query, id) })
	}
	var fwdUp, fwdKnown bool
	var fwdErr error
	wg.Go(func() {
		e := env.edge()
		if e == nil {
			fwdErr = errors.New("no edge runs")
			return
		}
		h, err := e.Health(ctx)
		if err != nil {
			fwdErr = err
			return
		}
		fwdUp, fwdKnown = h.GetDns(), true
	})
	wg.Wait()

	var lines []string
	lines = append(lines, "question: A "+name)
	if dohErr != nil {
		lines = append(lines, "DNS over HTTPS: no answer ("+dohErr.Error()+")")
	} else {
		lines = append(lines, "DNS over HTTPS: "+dohAns.String())
		for _, e := range dohFailed {
			lines = append(lines, "DNS over HTTPS, no answer from "+e.Error())
		}
	}
	var blocked, hijacked []string
	for i, s := range servers {
		switch u := udp[i]; {
		case u.err != nil:
			blocked = append(blocked, s)
			lines = append(lines, fmt.Sprintf("UDP %s: blocked (%s)", s, udpFailure(u.err)))
		case dohErr != nil:
			lines = append(lines, fmt.Sprintf("UDP %s: %s (not compared)", s, u.ans))
		case !u.ans.equal(dohAns):
			hijacked = append(hijacked, s)
			lines = append(lines, fmt.Sprintf("UDP %s: hijacked (%s, DNS over HTTPS says %s)", s, u.ans, dohAns))
		default:
			lines = append(lines, fmt.Sprintf("UDP %s: works", s))
		}
	}
	mode := state.DNSModeOf(env.Desired.GetSettings())
	switch {
	case fwdKnown:
		lines = append(lines, fmt.Sprintf("the edge's DNS forwarder: running %t (mode %s)", fwdUp, mode))
	default:
		lines = append(lines, fmt.Sprintf("the edge's DNS forwarder: unknown, %v (mode %s)", fwdErr, mode))
	}
	r := Result{Evidence: strings.Join(lines, "\n")}
	udpTrouble := describeUDP(blocked, hijacked)
	switch {
	case mode == state.DNSModeDoH && !fwdUp:
		r.Status, r.Summary = Fail, "the DNS forwarder of the edge does not run (DNS mode doh)"
		r.Hint = "the engines resolve through the edge's forwarder on 127.0.0.2:53; see the edge's log"
	case dohErr != nil:
		r.Status, r.Summary = Warn, "DNS over HTTPS does not answer"
		r.Hint = "the forwarder falls back to the host's nameservers; check that HTTPS to 1.1.1.1 and 8.8.8.8 is not blocked"
	case udpTrouble != "" && mode == state.DNSModeDoH:
		r.Status, r.Summary = Warn, "UDP DNS is "+udpTrouble+"; the forwarder serves over DNS over HTTPS"
	case udpTrouble != "":
		r.Status, r.Summary = Fail, "UDP DNS is "+udpTrouble+" while the containers use the host's resolver (DNS mode system)"
		r.Hint = "switch the node's DNS mode to doh"
		r.Fix = FixDNSModeDoH
	default:
		r.Status, r.Summary = OK, "UDP DNS agrees with DNS over HTTPS (DNS mode "+mode+")"
	}
	if n := len(dohFailed); n > 0 && dohErr == nil {
		r.Summary += fmt.Sprintf("; %d DNS-over-HTTPS endpoint(s) did not answer", n)
	}
	return []Result{r}
}

func describeUDP(blocked, hijacked []string) string {
	var parts []string
	if len(blocked) > 0 {
		parts = append(parts, "blocked")
	}
	if len(hijacked) > 0 {
		parts = append(parts, "hijacked")
	}
	return strings.Join(parts, " and ")
}

func udpFailure(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "ICMP unreachable: " + err.Error()
	}
	return err.Error()
}

func dnsQuery(id uint16, name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// parseDNSAnswer reads an answer; with checkID, its id must be id.
func parseDNSAnswer(msg []byte, id uint16, checkID bool) (dnsAnswer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return dnsAnswer{}, err
	}
	if checkID && h.ID != id {
		return dnsAnswer{}, errWrongID
	}
	if !h.Response {
		return dnsAnswer{}, errors.New("not an answer")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return dnsAnswer{}, err
	}
	ans := dnsAnswer{rcode: h.RCode}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return dnsAnswer{}, err
		}
		if rh.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return dnsAnswer{}, err
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return dnsAnswer{}, err
		}
		ans.addrs = append(ans.addrs, netip.AddrFrom4(a.A).String())
	}
	sort.Strings(ans.addrs)
	ans.addrs = slices.Compact(ans.addrs)
	return ans, nil
}

var errWrongID = errors.New("an answer to another question")

// askUDP asks server over UDP, directly, and waits for the answer to query.
func askUDP(ctx context.Context, env *Env, server string, query []byte, id uint16) (dnsAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, udpTimeout)
	defer cancel()
	dial := env.DialUDP
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "udp", server)
	if err != nil {
		return dnsAnswer{}, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := conn.Write(query); err != nil {
		return dnsAnswer{}, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return dnsAnswer{}, ctx.Err()
			}
			return dnsAnswer{}, err
		}
		ans, err := parseDNSAnswer(buf[:n], id, true)
		if errors.Is(err, errWrongID) {
			continue
		}
		return ans, err
	}
}

// ---- host.disk, host.memory -------------------------------------------------------

func checkDisk(_ context.Context, env *Env) []Result {
	if env.DiskSpace == nil {
		return []Result{{Status: Skip, Summary: "the disk is not measured here"}}
	}
	total, avail, err := env.DiskSpace(env.DiskPath)
	if err != nil || total == 0 {
		return []Result{{Status: Skip, Summary: "the disk cannot be measured"}}
	}
	r := Result{Summary: fmt.Sprintf("%s free of %s (%.1f %%) on the node's disk", size(avail), size(total), 100*float64(avail)/float64(total))}
	switch {
	case avail < 256*mib:
		r.Status = Fail
	case avail < gib || avail*20 < total:
		r.Status = Warn
	default:
		r.Status = OK
	}
	if r.Status != OK {
		r.Evidence = fmt.Sprintf("%s: %d bytes free of %d", env.DiskPath, avail, total)
		r.Hint = "free disk space: the record buffer, the artifacts and Docker's images live there"
	}
	return []Result{r}
}

func checkMemory(_ context.Context, env *Env) []Result {
	if env.Proc == nil {
		return []Result{{Status: Skip, Summary: "the memory cannot be read"}}
	}
	data, err := fs.ReadFile(env.Proc, "meminfo")
	if err != nil {
		return []Result{{Status: Skip, Summary: "the memory cannot be read"}}
	}
	total, avail := meminfo(data)
	if total == 0 {
		return []Result{{Status: Skip, Summary: "the memory cannot be read"}}
	}
	r := Result{Summary: fmt.Sprintf("%s available of %s (%.1f %%)", size(avail), size(total), 100*float64(avail)/float64(total))}
	switch {
	case avail < 64*mib:
		r.Status = Fail
	case avail*10 < total:
		r.Status = Warn
	default:
		r.Status = OK
	}
	if r.Status != OK {
		r.Evidence = fmt.Sprintf("MemTotal %d, MemAvailable %d bytes", total, avail)
		r.Hint = "the host is short of memory: engines may be killed by the OOM killer"
	}
	return []Result{r}
}

// meminfo reads MemTotal and MemAvailable (MemFree when there is none).
func meminfo(data []byte) (total, avail uint64) {
	var free uint64
	has := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		f := strings.Fields(rest)
		if !ok || len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		switch key {
		case "MemTotal":
			total = v
		case "MemFree":
			free = v
		case "MemAvailable":
			avail, has = v, true
		}
	}
	if !has {
		avail = free
	}
	return total, min(avail, total)
}

func size(n uint64) string {
	switch {
	case n >= gib:
		return fmt.Sprintf("%.1f GiB", float64(n)/gib)
	case n >= mib:
		return fmt.Sprintf("%.0f MiB", float64(n)/mib)
	}
	return fmt.Sprintf("%d KiB", n/1024)
}

// DiskSpace is statfs of path: the size of its file system and the space an
// unprivileged process may use.
func DiskSpace(path string) (total, avail uint64, err error) { return diskSpace(path) }

// ---- host.ports -------------------------------------------------------------------

// ours reports whether a socket's owner is the node's own: a generation of the
// edge (generations share the listeners with SO_REUSEPORT) or the agent.
func ours(o SocketOwner) bool {
	return strings.HasPrefix(o.Owner, EdgeContainerPrefix) || o.Owner == OwnerAgent
}

func checkPorts(ctx context.Context, env *Env) []Result {
	listeners := env.Listeners()
	if len(listeners) == 0 {
		return nil
	}
	if env.PortOwners == nil {
		return []Result{{Status: Skip, Summary: "the owners of the ports cannot be read here"}}
	}
	socks := env.PortOwners(ctx)
	if len(socks) > 0 && !slices.ContainsFunc(socks, func(s SocketOwner) bool { return s.Known }) {
		// No owner at all can be read (the agent may not look into the
		// processes of root): one note, not a warning on every listener.
		return []Result{{Status: Warn, Summary: "the owners of the listening sockets cannot be read",
			Evidence: fmt.Sprintf("none of the %d listening sockets has an owner the agent can see", len(socks)),
			Hint:     "run the agent as root (with pid: host), so that it can tell the edge's sockets from another process's"}}
	}
	var out []Result
	for _, l := range listeners {
		r := Result{Target: ListenerTarget(l.GetId())}
		bind, err := netip.ParseAddr(l.GetBindIp())
		if err != nil || l.GetPort() == 0 || l.GetPort() > 65535 {
			r.Status, r.Summary = Skip, "the listener has no address"
			out = append(out, r)
			continue
		}
		bind = bind.Unmap()
		var foreign, unknown []string
		edge := 0
		for _, s := range socks {
			a, err := netip.ParseAddr(s.Bind)
			if err != nil || s.Port != uint16(l.GetPort()) {
				continue
			}
			if a = a.Unmap(); a != bind && !a.IsUnspecified() && !bind.IsUnspecified() {
				continue
			}
			at := net.JoinHostPort(a.String(), strconv.Itoa(int(s.Port)))
			switch {
			case !s.Known:
				unknown = append(unknown, at+": owner unknown")
			case ours(s):
				edge++
			default:
				foreign = append(foreign, fmt.Sprintf("%s: %s (pid %d)", at, s.Owner, s.PID))
			}
		}
		addr := net.JoinHostPort(bind.String(), strconv.Itoa(int(l.GetPort())))
		switch {
		case len(foreign) > 0:
			r.Status, r.Summary = Fail, "another process listens on "+addr
			r.Evidence = strings.Join(append(foreign, unknown...), "\n")
			r.Hint = "stop that process or move the listener to another port"
		case len(unknown) > 0:
			r.Status, r.Summary = Warn, "a socket on "+addr+" has an owner that cannot be read (owner unknown)"
			r.Evidence = strings.Join(unknown, "\n")
		case edge == 0:
			r.Status, r.Summary = OK, "nothing else listens on "+addr
		default:
			r.Status, r.Summary = OK, fmt.Sprintf("only the edge listens on %s (%d sockets)", addr, edge)
		}
		out = append(out, r)
	}
	return out
}

// ---- host.public_ips --------------------------------------------------------------

const ipChangeWindow = 24 * time.Hour

// publicIPHistory remembers the node's public addresses and when they last
// changed.
type publicIPHistory struct {
	mu      sync.Mutex
	known   bool
	cur     []string
	prev    []string
	changed time.Time
}

func (h *publicIPHistory) run(ctx context.Context, env *Env) []Result {
	if env.PublicIPs == nil {
		return []Result{{Status: Skip, Summary: "the public addresses are not known here"}}
	}
	set := map[netip.Addr]bool{}
	var addrs []netip.Addr
	for _, a := range env.PublicIPs(ctx) {
		a = a.Unmap()
		if !set[a] {
			set[a] = true
			addrs = append(addrs, a)
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare) // IPv4 first
	ips := make([]string, len(addrs))
	for i, a := range addrs {
		ips[i] = a.String()
	}
	now := env.now()
	h.mu.Lock()
	switch {
	case len(ips) == 0:
	case !h.known:
		h.known, h.cur = true, ips
	case !slices.Equal(h.cur, ips):
		h.prev, h.cur, h.changed = h.cur, ips, now
	}
	prev, changed := h.prev, h.changed
	h.mu.Unlock()

	if len(ips) == 0 {
		return []Result{{Status: Fail, Summary: "no public IP of the node is known",
			Evidence: "no interface has a public address and no echo service told one",
			Hint:     "the links of the proxies need the node's public address"}}
	}
	var missing []string
	for _, l := range env.Desired.GetListeners() {
		a, err := netip.ParseAddr(l.GetBindIp())
		if err != nil || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		if !set[a.Unmap()] {
			missing = append(missing, fmt.Sprintf("listener %s binds %s", l.GetId(), a))
		}
	}
	if len(missing) > 0 {
		return []Result{{Status: Fail, Summary: "a listener binds an address that is not a public IP of the node",
			Evidence: strings.Join(missing, "\n") + "\npublic IPs: " + strings.Join(ips, ", "),
			Hint:     "the address may have moved: change the listener's bind address"}}
	}
	if !changed.IsZero() && now.Sub(changed) < ipChangeWindow {
		return []Result{{Status: Warn, Summary: "the public IPs of the node changed " + now.Sub(changed).Round(time.Minute).String() + " ago",
			Evidence: "before: " + strings.Join(prev, ", ") + "\nnow: " + strings.Join(ips, ", "),
			Hint:     "links with the old address no longer reach the node"}}
	}
	return []Result{{Status: OK, Summary: "public IPs: " + strings.Join(ips, ", ")}}
}

// ---- host.reserved_ports ----------------------------------------------------------

// The node's ports (state.Allocator) are taken from this range, which
// install.sh reserves so that no outgoing connection takes one.
const reservedLo, reservedHi = 20000, 40999

func checkReservedPorts(_ context.Context, env *Env) []Result {
	if env.Proc == nil {
		return []Result{{Status: Skip, Summary: "/proc cannot be read here"}}
	}
	data, err := fs.ReadFile(env.Proc, "sys/net/ipv4/ip_local_reserved_ports")
	if err != nil {
		return []Result{{Status: Skip, Summary: "ip_local_reserved_ports cannot be read"}}
	}
	value := strings.TrimSpace(string(data))
	if reservedCovers(value, reservedLo, reservedHi) {
		return []Result{{Status: OK, Summary: fmt.Sprintf("%d-%d are reserved ports", reservedLo, reservedHi)}}
	}
	return []Result{{Status: Warn, Summary: fmt.Sprintf("%d-%d are not all reserved ports", reservedLo, reservedHi),
		Evidence: "net.ipv4.ip_local_reserved_ports = " + clip(value, 512, true),
		Hint:     "an outgoing connection may take a port the node allocates; re-run install.sh, which reserves them, or restart the node container (docker restart postern-agent) on a node installed with Docker"}}
}

// reservedCovers reports whether a list like "1000,20000-40999" has every
// port of [lo, hi].
func reservedCovers(list string, lo, hi int) bool {
	type span struct{ a, b int }
	var spans []span
	for part := range strings.SplitSeq(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		x, err1 := strconv.Atoi(strings.TrimSpace(a))
		y := x
		var err2 error
		if isRange {
			y, err2 = strconv.Atoi(strings.TrimSpace(b))
		}
		if err1 != nil || err2 != nil || y < x {
			continue
		}
		spans = append(spans, span{x, y})
	}
	slices.SortFunc(spans, func(p, q span) int { return p.a - q.a })
	next := lo
	for _, s := range spans {
		if s.a > next {
			break
		}
		next = max(next, s.b+1)
		if next > hi {
			return true
		}
	}
	return next > hi
}

// ---- host.edge_caps ---------------------------------------------------------------

const capsWindow = 10 * time.Minute

type capSample struct {
	at                       time.Time
	gen                      uint64
	prehello, total, evicted uint64
}

// edgeCaps keeps the edge's refusal counters of the last half hour, so that
// a run compares with the counters of 10 minutes before.
type edgeCaps struct {
	mu      sync.Mutex
	samples []capSample
}

func (c *edgeCaps) run(ctx context.Context, env *Env) []Result {
	e := env.edge()
	if e == nil {
		return []Result{{Status: Skip, Summary: "no edge runs"}}
	}
	snap, err := e.Snapshot(ctx)
	if err != nil {
		return []Result{{Status: Skip, Summary: "the edge does not answer: " + err.Error()}}
	}
	now := env.now()
	cur := capSample{at: now, gen: env.Runtime.EdgeGeneration, prehello: snap.GetRefusedPrehello(), total: snap.GetRefusedTotal(), evicted: snap.GetEvictedPrehello()}

	c.mu.Lock()
	var base *capSample
	kept := c.samples[:0]
	for _, s := range c.samples {
		if s.gen != cur.gen || now.Sub(s.at) > 3*capsWindow || s.at.After(now) {
			continue
		}
		kept = append(kept, s)
	}
	c.samples = kept
	// The newest sample at least 10 minutes old; else the oldest there is.
	for i := range c.samples {
		s := c.samples[i]
		if now.Sub(s.at) >= capsWindow {
			base = &s
		}
	}
	if base == nil && len(c.samples) > 0 {
		s := c.samples[0]
		base = &s
	}
	c.samples = append(c.samples, cur)
	c.mu.Unlock()

	if base == nil {
		if cur.prehello == 0 && cur.total == 0 && cur.evicted == 0 {
			return []Result{{Status: OK, Summary: "no connection refused since the edge started"}}
		}
		return []Result{{Status: Skip, Summary: "the first count of refusals; the next run compares"}}
	}
	d := capSample{prehello: delta(base.prehello, cur.prehello), total: delta(base.total, cur.total), evicted: delta(base.evicted, cur.evicted)}
	window := now.Sub(base.at).Round(time.Second)
	if d.prehello == 0 && d.total == 0 && d.evicted == 0 {
		return []Result{{Status: OK, Summary: "no connection refused or evicted in " + window.String()}}
	}
	return []Result{{Status: Warn,
		Summary:  fmt.Sprintf("the edge refused %d and evicted %d connections at its caps in %s", d.prehello+d.total, d.evicted, window),
		Evidence: fmt.Sprintf("in %s: refused before the ClientHello %d, refused at the connection cap %d, evicted before the ClientHello %d", window, d.prehello, d.total, d.evicted),
		Hint:     "a flood of connections, or caps too low for the load"}}
}

func delta(prev, cur uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// ---- host.stats -------------------------------------------------------------------

const overflowRecent = 10 * time.Minute

func checkStats(_ context.Context, env *Env) []Result {
	if env.StatsOverflow == nil {
		return nil
	}
	minute, n := env.StatsOverflow()
	now := env.now()
	if n == 0 || minute.IsZero() || now.Sub(minute) > overflowRecent {
		return []Result{{Status: OK, Summary: "the client addresses of every minute fit the statistics"}}
	}
	return []Result{{Status: Warn,
		Summary:  fmt.Sprintf("%d client addresses of a minute were left out of its countries", n),
		Evidence: fmt.Sprintf("minute %s: over the bound of the addresses a minute keeps, %d left out", minute.UTC().Format(time.RFC3339), n),
		Hint:     "the country statistics of that minute are short"}}
}
