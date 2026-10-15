package probes

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	randv2 "math/rand/v2"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// Made-up proxy secrets: none may show up in a log.
const (
	secretA = "00112233445566778899aabbccddeeff" // gitleaks:allow (a made-up test value)
	secretB = "ffeeddccbbaa99887766554433221100" // gitleaks:allow (a made-up test value)
)

// clock is a clock that the test moves.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// env is a database with a key, a clock and a log.
type env struct {
	t      *testing.T
	ctx    context.Context
	db     *store.DB
	dbPath string
	key    seal.Key
	clock  *clock
	logs   *lockedBuffer
	log    *slog.Logger
}

func newEnv(t *testing.T) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := &env{t: t, ctx: context.Background(), db: db, dbPath: path, logs: &lockedBuffer{},
		// The clock starts now: the store keeps the probes of the last 7 days by
		// its own clock, which is the real one.
		clock: &clock{t: time.Now().UTC().Truncate(time.Minute)}}
	if _, err := rand.Read(e.key[:]); err != nil {
		t.Fatal(err)
	}
	e.log = slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", e.logs.String())
		}
	})
	return e
}

// scheduler is a scheduler of the env with the probe f (for WEB proxies too),
// the env's clock and a fixed random source.
func (e *env) scheduler(f ProbeFunc) *Scheduler {
	return NewScheduler(e.db, e.key, e.log, WithProbe(f), WithWebProbe(f), WithNow(e.clock.Now), WithRand(randv2.New(randv2.NewPCG(1, 2))))
}

func (e *env) setInterval(minutes uint32) {
	e.t.Helper()
	s, _, err := e.db.StatsSettings(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	s.ProbeIntervalMinutes = minutes
	if _, err := e.db.ApplyStatsSettings(e.ctx, s); err != nil {
		e.t.Fatalf("ApplyStatsSettings: %v", err)
	}
}

func (e *env) node(linkHost string, online bool) *store.Node {
	e.t.Helper()
	n := &store.Node{Name: "n-" + ids.New()[:6], MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: linkHost, Status: store.NodeStatusOffline}
	if online {
		n.Status = store.NodeStatusOnline
	}
	if err := e.db.CreateNode(e.ctx, n); err != nil {
		e.t.Fatalf("CreateNode: %v", err)
	}
	return n
}

func (e *env) listener(nodeID string, port uint32) *store.Listener {
	e.t.Helper()
	l := &store.Listener{NodeID: nodeID, BindIP: "0.0.0.0", Port: port}
	if err := e.db.CreateListener(e.ctx, l); err != nil {
		e.t.Fatalf("CreateListener: %v", err)
	}
	return l
}

// proxy stores an enabled proxy on the listener with its secret sealed.
func (e *env) proxy(l *store.Listener, domain, secret string, change func(*store.Proxy)) *store.Proxy {
	e.t.Helper()
	p := &store.Proxy{ID: ids.New(), NodeID: l.NodeID, ListenerID: l.ID, Type: store.ProxyTypeFakeTLS, Name: "p", Enabled: true, Domain: domain}
	if change != nil {
		change(p)
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

// recorder is a probe function that records the targets it is called with
// and answers with ok.
type recorder struct {
	mu     sync.Mutex
	clock  *clock
	ok     bool
	calls  []Target
	times  []time.Time
	byID   map[string]int
	secret map[string]string // the secret each proxy was probed with, hex
}

func newRecorder(c *clock, ok bool) *recorder {
	return &recorder{clock: c, ok: ok, byID: map[string]int{}, secret: map[string]string{}}
}

func (r *recorder) probe(_ context.Context, t Target) (store.Probe, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, t)
	r.times = append(r.times, r.clock.Now())
	r.byID[t.ProxyID]++
	r.secret[t.ProxyID] = string(appendHex(nil, t.Secret))
	if r.ok {
		return store.Probe{OK: true, LatencyMS: 42}, true
	}
	return store.Probe{Error: ErrUnreachable}, false
}

func (r *recorder) count(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byID[id]
}

func appendHex(b, src []byte) []byte {
	const digits = "0123456789abcdef"
	for _, c := range src {
		b = append(b, digits[c>>4], digits[c&15])
	}
	return b
}

// runFor moves the clock by step for d, running a round at every step and
// waiting for its probes.
func runFor(s *Scheduler, c *clock, d, step time.Duration) {
	for end := c.Now().Add(d); c.Now().Before(end); c.Add(step) {
		s.round(context.Background())
		s.wg.Wait()
	}
}
