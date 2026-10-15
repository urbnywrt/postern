package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// gate holds the password operations of a test until the test lets go, and lets
// go when the test ends, however it ends, so that no goroutine is left behind.
type gate struct {
	once sync.Once
	ch   chan struct{}
}

func newGate(t *testing.T) *gate {
	g := &gate{ch: make(chan struct{})}
	t.Cleanup(g.open)
	return g
}

func (g *gate) open() { g.once.Do(func() { close(g.ch) }) }

func (g *gate) wait() { <-g.ch }

// waitStarted waits for n signals on started, and fails the test if they do not
// come: the operations that should have sent them never began.
func waitStarted(t *testing.T, started <-chan struct{}, n int) {
	t.Helper()
	for range n {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("the password operations did not start")
		}
	}
}

// within runs f and fails the test when f does not return in time, which is
// how an implementation that blocks forever is told from one that works.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// Every password hash and check takes 64 MiB while it runs, so no more than two
// run at once, whatever the number of requests.
func TestPasswordWorkIsLimitedToTwoAtATime(t *testing.T) {
	e := newEnv(t)
	g := newGate(t)
	var running, peak atomic.Int32
	enter := func() {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		g.wait()
		running.Add(-1)
	}
	e.svc.hash = func(string) (string, error) { enter(); return "hash", nil }
	e.svc.verify = func(string, string) (bool, error) { enter(); return true, nil }

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = e.svc.hashPassword(context.Background(), "x")
			} else {
				_, _ = e.svc.checkPassword(context.Background(), "hash", "x")
			}
		}()
	}
	waitFor(t, "two password operations to start", func() bool { return running.Load() >= 2 })
	time.Sleep(100 * time.Millisecond) // time for a third to start, if it were let
	if got := running.Load(); got != 2 {
		t.Fatalf("%d password operations are running, want 2", got)
	}
	g.open()
	wg.Wait()
	if got := peak.Load(); got != 2 {
		t.Errorf("at most %d ran at once, want 2", got)
	}
}

// A request that has gone away does not wait for its turn, nor does it take
// one.
func TestPasswordWorkGivesWayToCancellation(t *testing.T) {
	e := newEnv(t)
	g := newGate(t)
	started := make(chan struct{}, 2)
	var calls atomic.Int32
	e.svc.verify = func(string, string) (bool, error) {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		g.wait()
		return true, nil
	}
	e.svc.hash = func(string) (string, error) { calls.Add(1); g.wait(); return "hash", nil }

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.svc.checkPassword(context.Background(), "hash", "x")
		}()
	}
	waitStarted(t, started, 2)

	var checkErr, hashErr, slowErr error
	within(t, 3*time.Second, "the calls that cannot get a slot", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, checkErr = e.svc.checkPassword(ctx, "hash", "x")
		_, hashErr = e.svc.hashPassword(ctx, "x")
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, slowErr = e.svc.hashPassword(ctx, "x")
	})
	if !errors.Is(checkErr, context.Canceled) {
		t.Errorf("checkPassword with a canceled context: %v", checkErr)
	}
	if !errors.Is(hashErr, context.Canceled) {
		t.Errorf("hashPassword with a canceled context: %v", hashErr)
	}
	if !errors.Is(slowErr, context.DeadlineExceeded) {
		t.Errorf("hashPassword that waited too long: %v", slowErr)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("%d operations ran, want only the two that held the slots", got)
	}
	g.open()
	wg.Wait()

	// The slots are free again.
	e.svc.verify = func(string, string) (bool, error) { return true, nil }
	within(t, 3*time.Second, "checkPassword after the others", func() {
		if ok, err := e.svc.checkPassword(context.Background(), "hash", "x"); err != nil || !ok {
			t.Errorf("checkPassword after the others: %v, %v", ok, err)
		}
	})
}

// A login whose request is gone while it waits for a slot is not counted as a
// failed one.
func TestLoginThatGivesUpWaitingIsNotAFailure(t *testing.T) {
	e := newEnvAdmin(t)
	g := newGate(t)
	started := make(chan struct{}, 2)
	e.svc.verify = func(string, string) (bool, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		g.wait()
		return false, nil
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.browser().login(testUser, wrongPassword, "")
		}()
	}
	waitStarted(t, started, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	b := e.browser()
	if _, err := b.auth.Login(ctx, connectLogin(testUser, wrongPassword)); err == nil {
		t.Fatal("Login did not wait for a slot")
	}
	// The server finds out that the client has gone a moment later. Until it
	// has, the request is alive and would take a slot that comes free.
	waitFor(t, "the request that gave up to be released", func() bool {
		return e.svc.limits.runningOn(ipKeyPrefix+"127.0.0.1") == 2 // the address of every browser here
	})
	g.open()
	wg.Wait()

	// Two failures were counted, those of the two that ran; not the third.
	e.svc.verify = func(string, string) (bool, error) { return false, nil }
	for i := range maxFailures - 2 {
		_, err := b.login(testUser, wrongPassword, "")
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("failure %d: %v", i+3, err)
		}
	}
	_, err := b.login(testUser, wrongPassword, "")
	wantCode(t, err, connect.CodeResourceExhausted)
}

// Nothing that has to stay secret is written to the log: no password, token,
// secret, and not the user name that somebody typed, which may be a password
// that went into the wrong field.
func TestLogsHoldNoSecrets(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	setupToken, _ := e.svc.SetupToken()
	secrets := map[string]string{
		"setup token":    setupToken,
		"password":       testPassword,
		"new password":   otherPassword,
		"wrong password": wrongPassword,
	}
	const typed = "typed-in-the-wrong-field-1234"
	const wrongToken = "a-setup-token-that-is-wrong-0123456789ABCDE"

	_, _ = b.setup(wrongToken, "admin", testPassword)
	if _, err := b.setup(setupToken, "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	_, _ = b.login(typed, wrongPassword, "")
	_, _ = b.login(testUser, wrongPassword, "")
	secrets["session token"] = b.mustLogin()
	secret := b.enableTotp()
	secrets["totp secret"] = secret
	_, _ = b.changePassword(wrongPassword, otherPassword)
	_, _ = b.disableTotp(wrongPassword, e.code(secret))
	if _, err := b.changePasswordWithCode(testPassword, otherPassword, e.code(secret)); err != nil {
		t.Fatal(err)
	}
	secrets["session token after the change"] = b.token()
	for range maxFailures + 1 { // up to a lock
		_, _ = e.browser().login(testUser, wrongPassword, "")
	}
	_, _ = b.logout()

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged")
	}
	for what, value := range secrets {
		if value != "" && strings.Contains(logs, value) {
			t.Errorf("the log contains the %s", what)
		}
	}
	for _, value := range []string{typed, wrongToken} {
		if strings.Contains(logs, value) {
			t.Errorf("the log contains %q, which a caller sent", value)
		}
	}
}
