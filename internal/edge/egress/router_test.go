package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/socks5"
)

const target = "203.0.113.5:443"

// newTestRouter returns a router whose members are the fake dialers of ds and
// whose probes answer from sp, and that has been given chains and hc.
func newTestRouter(t *testing.T, ds *dialers, sp *scriptedProbe, chains []*edgev1.Chain, hc *edgev1.HealthCheck) *Router {
	t.Helper()
	r := newRouter(quiet, deps{newDialer: ds.factory(), probe: sp.probe, exit: sp.exit, clock: newFakeClock()})
	if err := r.Apply(chains, hc); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return r
}

// bringDown makes a member go down, with as many failing probes as the default
// hysteresis wants.
func bringDown(t *testing.T, r *Router, sp *scriptedProbe, key string) {
	t.Helper()
	sp.set(key, failProbe)
	for range 3 {
		r.probeRound(context.Background(), false)
	}
}

func readBanner(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(ioTimeout))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("reading the banner: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

func TestApplyRejectsBadConfigurationAndKeepsTheOld(t *testing.T) {
	good := []*edgev1.Chain{chainOf("keep", mem("k1", "direct"))}
	cases := []struct {
		name    string
		chains  []*edgev1.Chain
		hc      *edgev1.HealthCheck
		wantErr string
	}{
		{"empty chain id", []*edgev1.Chain{chainOf("", mem("a", "direct"))}, nil, "chain"},
		{"nil chain", []*edgev1.Chain{nil}, nil, "chain"},
		{"duplicate chain id", []*edgev1.Chain{chainOf("c", mem("a", "direct")), chainOf("c", mem("b", "direct"))}, nil, "duplicate"},
		{"empty member key", []*edgev1.Chain{chainOf("c", mem("", "direct"))}, nil, "key"},
		{"duplicate member key in a chain", []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("a", "direct"))}, nil, "duplicate"},
		{"unknown member kind", []*edgev1.Chain{chainOf("c", mem("a", "carrier-pigeon"))}, nil, "kind"},
		{"socks5 member without addr", []*edgev1.Chain{chainOf("c", mem("a", "socks5"))}, nil, "addr"},
		{"bad datacenter address", good, &edgev1.HealthCheck{DcAddrs: []string{"nonsense"}}, "dc_addrs"},
		{"datacenter address with port 0", good, &edgev1.HealthCheck{DcAddrs: []string{"149.154.167.51:0"}}, "dc_addrs"},
		{"empty datacenter address", good, &edgev1.HealthCheck{DcAddrs: []string{""}}, "dc_addrs"},
		{"echo url of another scheme", good, &edgev1.HealthCheck{EchoUrls: []string{"ftp://echo.example/ip"}}, "echo_urls"},
		{"echo url without a host", good, &edgev1.HealthCheck{EchoUrls: []string{"https:///ip"}}, "echo_urls"},
		{"echo url with credentials", good, &edgev1.HealthCheck{EchoUrls: []string{"https://user:pw@echo.example/ip"}}, "echo_urls"},
		{"echo url that is not a url", good, &edgev1.HealthCheck{EchoUrls: []string{"://"}}, "echo_urls"},
	}
	echo := startEcho(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(quiet)
			if err := r.Apply(good, nil); err != nil {
				t.Fatal(err)
			}
			err := r.Apply(tc.chains, tc.hc)
			if err == nil {
				t.Fatalf("Apply succeeded, want an error about %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
			// The previous configuration is still the one in effect.
			if got := statuses(r.Health()); len(got) != 1 || got["keep/k1"] != "unknown" {
				t.Errorf("health after the failed Apply: %v", got)
			}
			conn, key, err := r.Dial(context.Background(), "keep", echo)
			if err != nil || key != "k1" {
				t.Fatalf("Dial after the failed Apply: key %q, error %v", key, err)
			}
			_ = conn.Close()
		})
	}
}

func TestApplyErrorsDoNotCarryCredentials(t *testing.T) {
	r := NewRouter(quiet)
	err := r.Apply([]*edgev1.Chain{chainOf("c", &edgev1.ChainMember{Key: "m", Kind: "socks5", Addr: "no-port", Username: "alice", Password: "hunter2"})}, nil)
	if err == nil {
		t.Fatal("Apply succeeded")
	}
	for _, secret := range []string{"alice", "hunter2"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q carries %q", err, secret)
		}
	}
	if !strings.Contains(err.Error(), `"m"`) || !strings.Contains(err.Error(), `"c"`) {
		t.Errorf("error %q does not say which chain and member are wrong", err)
	}
}

func TestApplyEmptyConfigurationClearsTheChains(t *testing.T) {
	ds := newDialers("a")
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil)
	if err := r.Apply(nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := r.Health(); len(got) != 0 {
		t.Errorf("health after an empty Apply: %v", got)
	}
	if _, _, err := r.Dial(context.Background(), "c", target); !errors.Is(err, ErrUnknownChain) {
		t.Errorf("Dial after an empty Apply: error %v, want ErrUnknownChain", err)
	}
}

func TestApplyIsAtomicForConcurrentDials(t *testing.T) {
	// Every Apply is a configuration of its own: a dial sees one of them whole,
	// never a mix. Run with -race.
	ds := newDialers("a", "b")
	sp := newScriptedProbe()
	r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn, key, err := r.Dial(context.Background(), "c", target)
				if err != nil {
					t.Errorf("Dial: %v", err)
					return
				}
				if key != "a" && key != "b" {
					t.Errorf("Dial used the member %q", key)
				}
				_ = conn.Close()
				_ = r.Health()
			}
		}()
	}
	for i := range 200 {
		key := "a"
		if i%2 == 1 {
			key = "b"
		}
		if err := r.Apply([]*edgev1.Chain{chainOf("c", mem(key, "direct"))}, nil); err != nil {
			t.Fatal(err)
		}
		r.probeRound(context.Background(), false)
	}
	close(stop)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Dial: the order of the members, and what makes the router go on to the next
// ---------------------------------------------------------------------------

func TestDialUsesTheFirstMemberThatWorks(t *testing.T) {
	ds := newDialers("a", "b")
	ds.get("a").fn = func(context.Context, string) (net.Conn, error) { return echoConn("from-a"), nil }
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)

	conn, key, err := r.Dial(context.Background(), "c", target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if key != "a" {
		t.Errorf("key %q, want a", key)
	}
	if got := readBanner(t, conn, 6); got != "from-a" {
		t.Errorf("banner %q", got)
	}
	if got := ds.get("a").calls(); len(got) != 1 || got[0] != target {
		t.Errorf("a was dialed %v, want [%s]", got, target)
	}
	if got := ds.get("b").calls(); len(got) != 0 {
		t.Errorf("b was dialed %v although a worked", got)
	}
}

func TestDialFallsBackWhenTheFirstMemberRefuses(t *testing.T) {
	ds := newDialers("a", "b", "c")
	ds.get("a").fn = failing(opErr(syscall.ECONNREFUSED))
	ds.get("b").fn = func(context.Context, string) (net.Conn, error) { return echoConn("from-b"), nil }
	chains := []*edgev1.Chain{chainOf("ch", mem("a", "direct"), mem("b", "direct"), mem("c", "direct"))}
	r := newTestRouter(t, ds, newScriptedProbe(), chains, nil)

	conn, key, err := r.Dial(context.Background(), "ch", target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if key != "b" {
		t.Errorf("key %q, want b", key)
	}
	if got := readBanner(t, conn, 6); got != "from-b" {
		t.Errorf("banner %q", got)
	}
	for key, want := range map[string]int{"a": 1, "b": 1, "c": 0} {
		if got := ds.get(key).calls(); len(got) != want {
			t.Errorf("%s was dialed %d times (%v), want %d", key, len(got), got, want)
		}
	}
	// Dialing again goes through a again: a refusal is not a reason to take a out.
	conn2, key2, err := r.Dial(context.Background(), "ch", target)
	if err != nil || key2 != "b" {
		t.Fatalf("second Dial: key %q, error %v", key2, err)
	}
	_ = conn2.Close()
	if got := ds.get("a").calls(); len(got) != 2 {
		t.Errorf("a was dialed %d times in all, want 2", len(got))
	}
}

func TestDialFallsBackOnAnyErrorOfAMember(t *testing.T) {
	for name, err := range map[string]error{
		"refused":                 opErr(syscall.ECONNREFUSED),
		"unreachable":             opErr(syscall.ENETUNREACH),
		"timeout":                 context.DeadlineExceeded,
		"handshake cut short":     io.ErrUnexpectedEOF,
		"reply of a proxy":        &socks5.ReplyError{Code: 0x05},
		"http status of a proxy":  &ConnectError{Status: 502},
		"credentials of a member": &ConnectError{Status: 407},
	} {
		t.Run(name, func(t *testing.T) {
			ds := newDialers("a", "b")
			ds.get("a").fn = failing(err)
			chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}
			r := newTestRouter(t, ds, newScriptedProbe(), chains, nil)
			conn, key, derr := r.Dial(context.Background(), "c", target)
			if derr != nil || key != "b" {
				t.Fatalf("key %q, error %v, want b", key, derr)
			}
			_ = conn.Close()
		})
	}
}

func TestDialSkipsMembersThatAreDown(t *testing.T) {
	ds := newDialers("a", "b", "c")
	sp := newScriptedProbe()
	chains := []*edgev1.Chain{chainOf("ch", mem("a", "direct"), mem("b", "direct"), mem("c", "direct"))}
	r := newTestRouter(t, ds, sp, chains, nil)
	bringDown(t, r, sp, "a")
	if got := statuses(r.Health())["ch/a"]; got != "down" {
		t.Fatalf("a is %q, want down", got)
	}

	conn, key, err := r.Dial(context.Background(), "ch", target)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if key != "b" {
		t.Errorf("key %q, want b", key)
	}
	if got := ds.get("a").calls(); len(got) != 0 {
		t.Errorf("a is down and was dialed %v", got)
	}

	// With b down too, the traffic goes on to c.
	bringDown(t, r, sp, "b")
	conn, key, err = r.Dial(context.Background(), "ch", target)
	if err != nil || key != "c" {
		t.Fatalf("key %q, error %v, want c", key, err)
	}
	_ = conn.Close()
}

func TestDialTreatsUnknownAsUsable(t *testing.T) {
	ds := newDialers("a")
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil)
	if got := statuses(r.Health())["c/a"]; got != "unknown" {
		t.Fatalf("a member that was never probed is %q, want unknown", got)
	}
	conn, key, err := r.Dial(context.Background(), "c", target)
	if err != nil || key != "a" {
		t.Fatalf("key %q, error %v", key, err)
	}
	_ = conn.Close()
}

func TestDialWhenEveryMemberIsDown(t *testing.T) {
	ds := newDialers("a", "b")
	sp := newScriptedProbe()
	r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
	bringDown(t, r, sp, "a")
	bringDown(t, r, sp, "b")

	_, _, err := r.Dial(context.Background(), "c", target)
	if !errors.Is(err, ErrNoUsableMember) {
		t.Fatalf("error %v, want ErrNoUsableMember", err)
	}
	for _, k := range []string{"a", "b"} {
		if got := ds.get(k).calls(); len(got) != 0 {
			t.Errorf("%s is down and was dialed %v", k, got)
		}
	}
}

func TestDialWhenEveryMemberFails(t *testing.T) {
	ds := newDialers("a", "b")
	ds.get("a").fn = failing(opErr(syscall.ECONNREFUSED))
	ds.get("b").fn = failing(context.DeadlineExceeded)
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)

	conn, key, err := r.Dial(context.Background(), "c", target)
	if err == nil {
		_ = conn.Close()
		t.Fatal("Dial succeeded")
	}
	if conn != nil || key != "" {
		t.Errorf("a failed Dial returned the connection %v and the key %q", conn, key)
	}
	var de *DialError
	if !errors.As(err, &de) {
		t.Fatalf("error %T %v, want a *DialError", err, err)
	}
	if de.ChainID != "c" || len(de.Attempts) != 2 || de.Attempts[0].Key != "a" || de.Attempts[1].Key != "b" {
		t.Errorf("DialError = %+v", de)
	}
	if de.Attempts[0].Kind != KindDirect || de.Untried != 0 {
		t.Errorf("DialError = %+v, want the kinds of the members and no member left untried", de)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the errors of the members are not reachable through %v", err)
	}
	for _, want := range []string{`"c"`, "a:", "b:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestDialDistinguishesAProxyThatAnsweredFromOneThatIsDown(t *testing.T) {
	// A refused connection through a proxy is one of two things, and errors.Is
	// cannot tell which: the proxy that is not there, and the proxy that works and
	// reports that the target refused. The type of the error can.
	t.Run("target refused through a proxy that works", func(t *testing.T) {
		ds := newDialers("a", "b")
		ds.get("a").fn = failing(&socks5.ReplyError{Code: 0x05})
		ds.get("b").fn = failing(opErr(syscall.ECONNREFUSED))
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
		_, _, err := r.Dial(context.Background(), "c", target)
		var re *socks5.ReplyError
		if !errors.As(err, &re) || re.Code != 0x05 {
			t.Errorf("error %v, want to find the ReplyError of a", err)
		}
		if !answered(err) {
			t.Errorf("answered(%v) = false", err)
		}
		var de *DialError
		if !errors.As(err, &de) || len(de.Attempts) != 2 {
			t.Fatalf("error %v, want a DialError of two attempts", err)
		}
		// Both attempts are listed, and only the one of the member that is down is a
		// failure of a member.
		if !de.Attempts[0].Answered || de.Attempts[1].Answered || de.Failed() != 1 {
			t.Errorf("answered: a %v, b %v; failures of members: %d; want true, false and 1", de.Attempts[0].Answered, de.Attempts[1].Answered, de.Failed())
		}
	})
	t.Run("proxies that are down", func(t *testing.T) {
		ds := newDialers("a", "b")
		ds.get("a").fn = failing(opErr(syscall.ECONNREFUSED))
		ds.get("b").fn = failing(opErr(syscall.ECONNREFUSED))
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
		_, _, err := r.Dial(context.Background(), "c", target)
		var re *socks5.ReplyError
		if errors.As(err, &re) || answered(err) {
			t.Errorf("members that are down were taken for proxies that answered: %v", err)
		}
		var de *DialError
		if !errors.As(err, &de) || de.Failed() != 2 {
			t.Errorf("error %v: want two failures of members", err)
		}
	})
	t.Run("the first verdict is the one that is kept", func(t *testing.T) {
		ds := newDialers("a", "b")
		ds.get("a").fn = failing(&socks5.ReplyError{Code: 0x05})
		ds.get("b").fn = failing(&socks5.ReplyError{Code: 0x04})
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
		_, _, err := r.Dial(context.Background(), "c", target)
		var re *socks5.ReplyError
		if !errors.As(err, &re) || re.Code != 0x05 {
			t.Errorf("error %v, want the ReplyError of the first member to come first", err)
		}
	})
}

func TestFailedDialsDoNotChangeHealth(t *testing.T) {
	// Only the probes of the datacenters decide that a member is down. A target
	// that is not there makes a dial fail through a member that is perfectly
	// well, and a direct member cannot be told from it.
	ds := newDialers("a", "b")
	ds.get("a").fn = failing(opErr(syscall.ECONNREFUSED))
	ds.get("b").fn = failing(&socks5.ReplyError{Code: 0x05})
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
	for range 20 {
		if _, _, err := r.Dial(context.Background(), "c", target); err == nil {
			t.Fatal("Dial succeeded")
		}
	}
	for k, got := range statuses(r.Health()) {
		if got != "unknown" {
			t.Errorf("%s is %q after failed dials, want unknown", k, got)
		}
	}
	if got := len(ds.get("a").calls()); got != 20 {
		t.Errorf("a was dialed %d times, want 20: it must not be taken out by failures of real dials", got)
	}
}

func TestDialUnknownAndEmptyChains(t *testing.T) {
	ds := newDialers("a")
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct")), chainOf("empty")}, nil)
	for _, id := range []string{"", "nope", "C"} {
		if _, _, err := r.Dial(context.Background(), id, target); !errors.Is(err, ErrUnknownChain) {
			t.Errorf("chain %q: error %v, want ErrUnknownChain", id, err)
		}
	}
	if _, _, err := r.Dial(context.Background(), "empty", target); !errors.Is(err, ErrNoMembers) {
		t.Errorf("empty chain: error %v, want ErrNoMembers", err)
	}
}

func TestDialPassesTheNetworkAndTheTarget(t *testing.T) {
	var network, addr string
	d := &fakeDialerWithNetwork{fn: func(n, a string) (net.Conn, error) {
		network, addr = n, a
		return sinkConn(), nil
	}}
	r := newRouter(quiet, deps{newDialer: func(*edgev1.ChainMember, time.Duration) (Dialer, error) { return d, nil }})
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	for _, tg := range []string{"203.0.113.5:443", "example.com:8443", "[2001:db8::1]:443"} {
		conn, _, err := r.Dial(context.Background(), "c", tg)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if network != "tcp" || addr != tg {
			t.Errorf("the member was asked for %s %s, want tcp %s", network, addr, tg)
		}
	}
}

type fakeDialerWithNetwork struct {
	fn func(network, addr string) (net.Conn, error)
}

func (f *fakeDialerWithNetwork) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	return f.fn(network, addr)
}

// trackedConn notes that it was closed.
type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestDialToleratesDialersThatBreakTheContract(t *testing.T) {
	ds := newDialers("nothing", "both", "ok")
	ds.get("nothing").fn = func(context.Context, string) (net.Conn, error) { return nil, nil }
	var leaked *trackedConn
	ds.get("both").fn = func(context.Context, string) (net.Conn, error) {
		leaked = &trackedConn{Conn: sinkConn()}
		return leaked, errors.New("failed, with a connection")
	}
	chains := []*edgev1.Chain{chainOf("c", mem("nothing", "direct"), mem("both", "direct"), mem("ok", "direct"))}
	r := newTestRouter(t, ds, newScriptedProbe(), chains, nil)

	conn, key, err := r.Dial(context.Background(), "c", target)
	if err != nil || key != "ok" {
		t.Fatalf("key %q, error %v, want ok", key, err)
	}
	_ = conn.Close()
	if leaked == nil || !leaked.closed.Load() {
		t.Error("the connection that came with an error was not closed")
	}

	// And when nothing else is left, the error says what happened.
	ds2 := newDialers("nothing")
	ds2.get("nothing").fn = func(context.Context, string) (net.Conn, error) { return nil, nil }
	r2 := newTestRouter(t, ds2, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("nothing", "direct"))}, nil)
	if conn, _, err := r2.Dial(context.Background(), "c", target); err == nil {
		_ = conn.Close()
		t.Error("a dialer that returned no connection and no error produced a connection")
	}
}

// ---------------------------------------------------------------------------
// Dial: time and the caller's context
// ---------------------------------------------------------------------------

func TestDialAppliesTheTimeoutOfTheHealthCheckToEachMember(t *testing.T) {
	for _, tc := range []struct {
		name string
		hc   *edgev1.HealthCheck
		want time.Duration
	}{
		{"default", nil, 4 * time.Second},
		{"default for a zero", &edgev1.HealthCheck{}, 4 * time.Second},
		{"from the health check", &edgev1.HealthCheck{TimeoutSeconds: 2}, 2 * time.Second},
		{"longer", &edgev1.HealthCheck{TimeoutSeconds: 9}, 9 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ds := newDialers("slow", "fast")
				ds.get("slow").fn = func(ctx context.Context, _ string) (net.Conn, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				chains := []*edgev1.Chain{chainOf("c", mem("slow", "direct"), mem("fast", "direct"))}
				r := newTestRouter(t, ds, newScriptedProbe(), chains, tc.hc)

				start := time.Now()
				conn, key, err := r.Dial(context.Background(), "c", target)
				if err != nil || key != "fast" {
					t.Fatalf("key %q, error %v, want fast", key, err)
				}
				_ = conn.Close()
				if got := time.Since(start); got != tc.want {
					t.Errorf("the slow member held the dial for %v, want %v", got, tc.want)
				}
				// The members are built with the same timeout, for the dialers
				// that apply it themselves.
				if got := ds.timeouts["slow"]; got != tc.want {
					t.Errorf("the dialer of a member was built with the timeout %v, want %v", got, tc.want)
				}
			})
		})
	}
}

// hang is the dial of a member that never answers.
func hang(ctx context.Context, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A dial through a chain has twice the timeout of a member in all: members
// that do not answer cannot hold an engine for the timeout of each of them.
func TestDialHasABudgetOfTwiceTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ds := newDialers("a", "b", "c")
		for _, k := range []string{"a", "b", "c"} {
			ds.get(k).fn = hang
		}
		chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"), mem("c", "direct"))}
		r := newTestRouter(t, ds, newScriptedProbe(), chains, nil)

		start := time.Now()
		_, _, err := r.Dial(context.Background(), "c", target)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error %v, want a deadline", err)
		}
		if got := time.Since(start); got != 8*time.Second {
			t.Errorf("the dial took %v, want 2 x 4s", got)
		}
		var de *DialError
		if !errors.As(err, &de) || len(de.Attempts) != 2 || de.Untried != 1 {
			t.Errorf("error %v, want a DialError of the two members that were tried and one that was not", err)
		} else if !strings.Contains(err.Error(), "1 not tried") {
			t.Errorf("error %q does not say that a member was not tried", err)
		}
		if got := ds.get("c").calls(); len(got) != 0 {
			t.Errorf("c was dialed %v after the time of the dial was up", got)
		}
	})
}

// A member that comes after others is given its timeout, or what is left of
// the time of the dial, whichever is shorter.
func TestDialGivesAMemberWhatIsLeftOfTheBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ds := newDialers("a", "b", "c")
		ds.get("a").fn = hang // 4 s, its timeout
		ds.get("b").fn = func(context.Context, string) (net.Conn, error) {
			time.Sleep(time.Second)
			return nil, opErr(syscall.ECONNREFUSED)
		}
		var deadline time.Time
		ds.get("c").fn = func(ctx context.Context, addr string) (net.Conn, error) {
			deadline, _ = ctx.Deadline()
			return hang(ctx, addr)
		}
		chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"), mem("c", "direct"))}
		r := newTestRouter(t, ds, newScriptedProbe(), chains, nil)

		start := time.Now()
		if _, _, err := r.Dial(context.Background(), "c", target); err == nil {
			t.Fatal("Dial succeeded")
		}
		// c begins at 5 s: its timeout would end at 9 s, the time of the dial at 8 s.
		if want := start.Add(8 * time.Second); !deadline.Equal(want) {
			t.Errorf("c was given until %v after the start, want 8s", deadline.Sub(start))
		}
		if got := time.Since(start); got != 8*time.Second {
			t.Errorf("the dial took %v, want 8s", got)
		}
	})
}

// A destination that the policy does not allow is not allowed through any
// member: the chain stops at the refusal and the next member is not tried.
func TestDialStopsAtADestinationThatIsNotAllowed(t *testing.T) {
	ds := newDialers("a", "b")
	ds.get("a").fn = failing(&net.OpError{Op: "dial", Net: "tcp", Err: ErrDestinationNotAllowed})
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
	conn, _, err := r.Dial(context.Background(), "c", "rebinding.example:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("Dial succeeded")
	}
	if !errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("error %v, want ErrDestinationNotAllowed", err)
	}
	var de *DialError
	if errors.As(err, &de) {
		t.Errorf("a refused destination was reported as a failure of the chain: %v", err)
	}
	if got := ds.get("b").calls(); len(got) != 0 {
		t.Errorf("b was dialed %v after the destination was refused", got)
	}
}

func TestDialStopsWhenTheCallerGivesUp(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		ds := newDialers("a", "b")
		started := make(chan struct{})
		ds.get("a").fn = func(ctx context.Context, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() {
			_, _, err := r.Dial(ctx, "c", target)
			errc <- err
		}()
		<-started
		cancel()
		select {
		case err := <-errc:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("error %v, want context.Canceled", err)
			}
			var de *DialError
			if errors.As(err, &de) {
				t.Errorf("a caller that gave up got a DialError: %v", err)
			}
		case <-time.After(ioTimeout):
			t.Fatal("Dial did not return after its context was cancelled")
		}
		if got := ds.get("b").calls(); len(got) != 0 {
			t.Errorf("b was dialed %v for a caller that had gone", got)
		}
	})

	t.Run("cancelled in the dial of the only member", func(t *testing.T) {
		// The member is not to blame for the caller going away, and the error is the
		// one of the context, not the failure of a chain.
		ds := newDialers("a")
		started := make(chan struct{})
		ds.get("a").fn = func(ctx context.Context, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() {
			_, _, err := r.Dial(ctx, "c", target)
			errc <- err
		}()
		<-started
		cancel()
		select {
		case err := <-errc:
			var de *DialError
			if !errors.Is(err, context.Canceled) || errors.As(err, &de) {
				t.Errorf("error %T %v, want context.Canceled and not a DialError", err, err)
			}
		case <-time.After(ioTimeout):
			t.Fatal("Dial did not return after its context was cancelled")
		}
	})

	t.Run("deadline of the caller before the timeout of the member", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ds := newDialers("a", "b")
			ds.get("a").fn = func(ctx context.Context, _ string) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			_, _, err := r.Dial(ctx, "c", target)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("error %v, want a deadline", err)
			}
			if got := time.Since(start); got != time.Second {
				t.Errorf("Dial returned after %v, want 1s", got)
			}
			if got := ds.get("b").calls(); len(got) != 0 {
				t.Errorf("b was dialed %v after the deadline of the caller", got)
			}
		})
	})

	t.Run("already cancelled", func(t *testing.T) {
		ds := newDialers("a")
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := r.Dial(ctx, "c", target); !errors.Is(err, context.Canceled) {
			t.Errorf("error %v, want context.Canceled", err)
		}
		if got := ds.get("a").calls(); len(got) != 0 {
			t.Errorf("a was dialed %v with a context that was done", got)
		}
	})
}

func TestCancellationIsNotAMemberFailure(t *testing.T) {
	ds := newDialers("a", "b")
	ds.get("a").fn = func(ctx context.Context, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
	for range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		_, _, err := r.Dial(ctx, "c", target)
		cancel()
		if err == nil {
			t.Fatal("Dial succeeded")
		}
	}
	if got := statuses(r.Health())["c/a"]; got != "unknown" {
		t.Errorf("a is %q after callers that gave up, want unknown", got)
	}
}

// ---------------------------------------------------------------------------
// Health: the report, and what Apply keeps of it
// ---------------------------------------------------------------------------

func TestHealthListsEveryMemberOfEveryChainInOrder(t *testing.T) {
	ds := newDialers("a", "b", "c")
	chains := []*edgev1.Chain{
		chainOf("c1", mem("a", "direct"), mem("b", "direct")),
		chainOf("c2", mem("b", "direct"), mem("c", "direct")),
	}
	r := newTestRouter(t, ds, newScriptedProbe(), chains, nil)
	var got []string
	for _, h := range r.Health() {
		got = append(got, h.GetChainId()+"/"+h.GetMemberKey()+"="+h.GetStatus())
		if h.GetCheckedUnix() != 0 || h.GetExitIp() != "" || h.GetLatencyMs() != 0 {
			t.Errorf("%s/%s carries data of a probe that never ran: %v", h.GetChainId(), h.GetMemberKey(), h)
		}
	}
	want := []string{"c1/a=unknown", "c1/b=unknown", "c2/b=unknown", "c2/c=unknown"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("health %v, want %v", got, want)
	}
}

func TestHealthReturnsCopies(t *testing.T) {
	ds := newDialers("a")
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil)
	first := r.Health()
	first[0].Status = "down"
	first[0].ExitIp = "203.0.113.99"
	if got := r.Health()[0]; got.GetStatus() != "unknown" || got.GetExitIp() != "" {
		t.Errorf("a change of the returned message reached the router: %v", got)
	}
}

func TestMemberInTwoChainsIsProbedOnceAndHasOneState(t *testing.T) {
	ds := newDialers("a", "b", "c")
	sp := newScriptedProbe()
	chains := []*edgev1.Chain{
		chainOf("c1", mem("a", "direct"), mem("b", "direct")),
		chainOf("c2", mem("b", "direct"), mem("c", "direct")),
	}
	r := newTestRouter(t, ds, sp, chains, nil)
	sp.set("b", failProbe)
	for range 3 {
		r.probeRound(context.Background(), false)
	}
	if got := sp.count("b"); got != 3 {
		t.Errorf("b was probed %d times in 3 rounds, want 3", got)
	}
	got := statuses(r.Health())
	if got["c1/b"] != "down" || got["c2/b"] != "down" || got["c1/a"] != "up" || got["c2/c"] != "up" {
		t.Errorf("health %v, want b down in both chains and the others up", got)
	}
	if n := ds.built["b"]; n != 1 {
		t.Errorf("the dialer of b was built %d times, want 1", n)
	}
}

func TestSameKeyWithAnotherConfigurationIsAnotherMember(t *testing.T) {
	ds := newDialers("b")
	chains := []*edgev1.Chain{
		chainOf("c1", &edgev1.ChainMember{Key: "b", Kind: "socks5", Addr: "127.0.0.1:1"}),
		chainOf("c2", &edgev1.ChainMember{Key: "b", Kind: "socks5", Addr: "127.0.0.1:2"}),
	}
	sp := newScriptedProbe()
	_ = newTestRouter(t, ds, sp, chains, nil)
	if n := ds.built["b"]; n != 2 {
		t.Errorf("the dialer for b was built %d times, want one for each configuration", n)
	}
}

func TestApplyKeepsTheHealthOfMembersThatDoNotChange(t *testing.T) {
	ds := newDialers("a", "b")
	sp := newScriptedProbe()
	member := func(key, addr string) *edgev1.ChainMember {
		return &edgev1.ChainMember{Key: key, Kind: "socks5", Addr: addr, Username: "u", Password: "p"}
	}
	r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", member("a", "127.0.0.1:1"), member("b", "127.0.0.1:2"))}, nil)
	bringDown(t, r, sp, "a")
	sp.set("b", probeResult{ok: true, latency: 40 * time.Millisecond})
	sp.setExit("b", exitResult{ip: "203.0.113.7"})
	r.probeRound(context.Background(), false)

	check := func(step string, want map[string]string) {
		t.Helper()
		got := statuses(r.Health())
		for k, w := range want {
			if got[k] != w {
				t.Errorf("%s: %s is %q, want %q (all: %v)", step, k, got[k], w, got)
			}
		}
	}
	check("before", map[string]string{"c/a": "down", "c/b": "up"})

	// The same configuration, in new messages: nothing changes, and no dialer is
	// built again.
	if err := r.Apply([]*edgev1.Chain{chainOf("c", member("a", "127.0.0.1:1"), member("b", "127.0.0.1:2"))}, nil); err != nil {
		t.Fatal(err)
	}
	check("same configuration", map[string]string{"c/a": "down", "c/b": "up"})
	if ds.built["a"] != 1 || ds.built["b"] != 1 {
		t.Errorf("dialers built again for a configuration that did not change: %v", ds.built)
	}
	if h := r.Health()[1]; h.GetExitIp() != "203.0.113.7" || h.GetLatencyMs() != 40 {
		t.Errorf("exit ip and latency of b were lost: %v", h)
	}

	// Another order, another chain with the same member: the member is the same.
	if err := r.Apply([]*edgev1.Chain{
		chainOf("c", member("b", "127.0.0.1:2"), member("a", "127.0.0.1:1")),
		chainOf("d", member("a", "127.0.0.1:1")),
	}, nil); err != nil {
		t.Fatal(err)
	}
	check("reordered", map[string]string{"c/a": "down", "c/b": "up", "d/a": "down"})

	// A member whose address changes is a member that was never probed: the
	// provider behind it was replaced.
	if err := r.Apply([]*edgev1.Chain{chainOf("c", member("b", "127.0.0.1:2"), member("a", "127.0.0.1:9"))}, nil); err != nil {
		t.Fatal(err)
	}
	check("address of a changed", map[string]string{"c/a": "unknown", "c/b": "up"})
	if ds.built["a"] != 2 {
		t.Errorf("the dialer of a was built %d times, want 2", ds.built["a"])
	}

	// A member that goes away goes from the report.
	if err := r.Apply([]*edgev1.Chain{chainOf("c", member("a", "127.0.0.1:9"))}, nil); err != nil {
		t.Fatal(err)
	}
	if got := statuses(r.Health()); len(got) != 1 {
		t.Errorf("health %v, want only a", got)
	}
}

func TestApplyRebuildsMembersWhenTheTimeoutChanges(t *testing.T) {
	ds := newDialers("a")
	sp := newScriptedProbe()
	chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"))}
	r := newTestRouter(t, ds, sp, chains, &edgev1.HealthCheck{TimeoutSeconds: 4})
	if err := r.Apply(chains, &edgev1.HealthCheck{TimeoutSeconds: 4, IntervalSeconds: 10}); err != nil {
		t.Fatal(err)
	}
	if ds.built["a"] != 1 {
		t.Errorf("a was built again for a change of the interval: %d", ds.built["a"])
	}
	if err := r.Apply(chains, &edgev1.HealthCheck{TimeoutSeconds: 7}); err != nil {
		t.Fatal(err)
	}
	if ds.built["a"] != 2 || ds.timeouts["a"] != 7*time.Second {
		t.Errorf("a was built %d times with the timeout %v, want again with 7s", ds.built["a"], ds.timeouts["a"])
	}
}

// ---------------------------------------------------------------------------
// The real thing, from the configuration to the socket
// ---------------------------------------------------------------------------

func TestRouterWithRealMembers(t *testing.T) {
	echo := startEcho(t)
	socks := startSOCKS5(t, (&requestLog{target: echo}).dial)
	proxy, _ := startHTTPProxy(t, "u", "p")
	chains := []*edgev1.Chain{
		// The first member is down, the second is a SOCKS5 proxy, the third an
		// HTTP proxy, and the last connects directly.
		chainOf("c",
			&edgev1.ChainMember{Key: "dead", Kind: "socks5", Addr: closedAddr(t)},
			&edgev1.ChainMember{Key: "socks", Kind: "socks5", Addr: socks},
			&edgev1.ChainMember{Key: "http", Kind: "http", Addr: proxy, Username: "u", Password: "p"},
			mem("direct", "direct")),
		chainOf("http-first",
			&edgev1.ChainMember{Key: "http", Kind: "http", Addr: proxy, Username: "u", Password: "p"},
			mem("direct", "direct")),
		chainOf("direct-only", mem("direct", "direct")),
	}
	r := NewRouter(quiet)
	if err := r.Apply(chains, nil); err != nil {
		t.Fatal(err)
	}
	for chain, wantKey := range map[string]string{"c": "socks", "http-first": "http", "direct-only": "direct"} {
		conn, key, err := r.Dial(context.Background(), chain, echo)
		if err != nil {
			t.Fatalf("chain %s: %v", chain, err)
		}
		if key != wantKey {
			t.Errorf("chain %s served by %q, want %q", chain, key, wantKey)
		}
		if got := roundTrip(t, conn, "hello"); got != "hello" {
			t.Errorf("chain %s: echo returned %q", chain, got)
		}
		_ = conn.Close()
	}
}

func TestRouterIsRaceFree(t *testing.T) {
	ds := newDialers("a", "b", "c")
	sp := newScriptedProbe()
	sp.set("a", failProbe, okProbe)
	chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct")), chainOf("d", mem("b", "direct"), mem("c", "direct"))}
	r := newTestRouter(t, ds, sp, chains, nil)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				f()
			}
		}()
	}
	run(func() {
		if conn, _, err := r.Dial(ctx, "c", target); err == nil {
			_ = conn.Close()
		}
	})
	run(func() { _ = r.Health() })
	run(func() { r.probeRound(ctx, false) })
	run(func() { r.probeRound(ctx, true) })
	run(func() { _ = r.Apply(chains, &edgev1.HealthCheck{IntervalSeconds: 5}) })
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()
}
