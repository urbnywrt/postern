package geodb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
)

// The words that must not get out of a base URL.
var credentials = []string{"alice", "s3cret", "token-123"}

// hostPort is the host and port of a test server.
func hostPort(t *testing.T, srvURL string) string {
	t.Helper()
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// closedHostPort is a loopback address that nothing listens on.
func closedHostPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestCleanText(t *testing.T) {
	uerr := &url.Error{Op: "Get", URL: "http://alice:s3cret@mirror.example/token-123/f.gz", Err: errors.New("connection refused")}
	perr := &fs.PathError{Op: "mkdir", Path: "/data/geoip", Err: errors.New("not a directory")}
	lerr := &os.LinkError{Op: "rename", Old: "/data/geoip/.incoming-1", New: "/data/geoip/x.mmdb", Err: errors.New("is a directory")}
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"a URL error is its reason", fmt.Errorf("could not download: %w", uerr), "could not download: connection refused"},
		{"a path error is its operation and its reason", fmt.Errorf("could not make it: %w", perr), "could not make it: mkdir: not a directory"},
		{"a link error is its operation and its reason", fmt.Errorf("could not put it: %w", lerr), "could not put it: rename: is a directory"},
		{"twice wrapped", fmt.Errorf("a: %w", fmt.Errorf("b: %w", perr)), "a: b: mkdir: not a directory"},
		{"a plain error as it is", errors.New("nothing to hide"), "nothing to hide"},
		{"both in one chain", fmt.Errorf("x: %w", errors.Join(uerr, perr)), "x: connection refused\nmkdir: not a directory"},
	} {
		if got := cleanText(c.err); got != c.want {
			t.Errorf("%s: cleanText = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://download.db-ip.com/free":              "download.db-ip.com",
		"http://alice:s3cret@127.0.0.1:8080/token-123": "127.0.0.1:8080",
		"not a url":            "",
		"http://[::1]:9/x?k=v": "[::1]:9",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// A base URL may carry a user name and a password, or a token in its path, which
// a mirror asks for. None of it may get into what is stored, told or logged: the
// state, the event, the status, the log.
func TestErrorsCarryNoCredentialsOrPaths(t *testing.T) {
	for _, c := range []struct {
		name string
		base func(e *env) string
		set  func(e *env)
		want string // part of the error that is wanted
	}{
		{"an answer that is not 200", func(e *env) string {
			return "http://alice:s3cret@" + hostPort(t, e.src.srv.URL) + "/token-123"
		}, func(e *env) { e.src.answer("2026-10", http.StatusServiceUnavailable) }, "answered 503"},
		{"a month that is not published", func(e *env) string {
			return "http://alice:s3cret@" + hostPort(t, e.src.srv.URL) + "/token-123"
		}, func(*env) {}, "no country database for 2026-10 or 2026-09"},
		{"a connection that is refused", func(*env) string {
			return "http://alice:s3cret@" + closedHostPort(t) + "/token-123"
		}, func(*env) {}, "connection refused"},
		{"a file that is not a database", func(e *env) string {
			return "http://alice:s3cret@" + hostPort(t, e.src.srv.URL) + "/token-123"
		}, func(e *env) { e.src.publish("2026-10", []byte("not a database")) }, "not a MaxMind DB file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.set(e)
			m := e.manager(WithBaseURL(c.base(e)))
			st, err := m.Refresh(e.ctx)
			if err == nil {
				t.Fatal("Refresh succeeded")
			}
			if !strings.Contains(st.Error, c.want) {
				t.Errorf("the status error %q does not say %q", st.Error, c.want)
			}
			texts := []string{st.Error, err.Error(), e.state().Error, e.logs.String()}
			for _, ev := range e.events("geoip.failed") {
				texts = append(texts, ev.Message, fmt.Sprint(ev.Details))
			}
			for _, text := range texts {
				for _, word := range credentials {
					if strings.Contains(text, word) {
						t.Errorf("%q is in %q", word, text)
					}
				}
			}
			// What was asked is named by its host.
			if c.name == "an answer that is not 200" && !strings.Contains(st.Error, hostPort(t, e.src.srv.URL)) {
				t.Errorf("the error does not name the host: %q", st.Error)
			}
		})
	}
}

// A refresh follows three redirects at most, and never from https to http.
func TestCheckRedirect(t *testing.T) {
	req := func(raw string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	chain := func(n int, scheme string) []*http.Request {
		var via []*http.Request
		for range n {
			via = append(via, req(scheme+"://mirror.example/a"))
		}
		return via
	}
	for _, c := range []struct {
		name string
		next *http.Request
		via  []*http.Request
		want string // part of the refusal, "" for none
	}{
		{"the first redirect", req("http://mirror.example/b"), chain(1, "http"), ""},
		{"the third", req("http://mirror.example/b"), chain(3, "http"), ""},
		{"the fourth", req("http://mirror.example/b"), chain(4, "http"), "stopped after 3 redirects"},
		{"https to https", req("https://other.example/b"), chain(1, "https"), ""},
		{"http to https", req("https://mirror.example/b"), chain(1, "http"), ""},
		{"https to http", req("http://mirror.example/b"), chain(1, "https"), "https to http"},
		{"https to http after http", req("http://mirror.example/b"), append(chain(1, "https"), req("http://x.example/")), ""},
	} {
		err := checkRedirect(c.next, c.via)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	if defaultClient().CheckRedirect == nil {
		t.Error("the client that the manager makes follows every redirect")
	}
}

// Through a client that the manager makes itself: a chain of three redirects
// gets there, a chain of four does not, and the error names no address.
func TestRedirectsOfTheDefaultClient(t *testing.T) {
	for _, c := range []struct {
		hops int
		ok   bool
	}{{3, true}, {4, false}} {
		t.Run(fmt.Sprintf("%d hops", c.hops), func(t *testing.T) {
			e := newEnv(t)
			db := gzipped(t, monthDB(t, "2026-10", "DE"))
			e.src.handle(func(w http.ResponseWriter, r *http.Request, _ string) bool {
				var hop int
				if _, err := fmt.Sscanf(r.URL.Path, "/hop/%d", &hop); err == nil {
					if hop < c.hops {
						http.Redirect(w, r, fmt.Sprintf("/hop/%d", hop+1), http.StatusFound)
					} else {
						_, _ = w.Write(db)
					}
					return true
				}
				http.Redirect(w, r, "/hop/1", http.StatusFound)
				return true
			})
			log := slog.New(slog.NewTextHandler(e.logs, nil))
			m := NewManager(e.db, e.dir, log, WithBaseURL(e.src.srv.URL), WithNow(e.clock.Now))
			st, err := m.Refresh(e.ctx)
			if c.ok {
				if err != nil || st.Month != "2026-10" {
					t.Fatalf("Refresh = %+v, %v", st, err)
				}
				return
			}
			if err == nil || !strings.Contains(st.Error, "stopped after 3 redirects") || strings.Contains(st.Error, "/hop/") {
				t.Errorf("Refresh = %+v, %v; want the refusal, with no address in it", st, err)
			}
		})
	}
}

// A panic inside a refresh or an upload does not keep the turn: the next call is
// not left waiting for ever.
func TestTheTurnIsReleasedByAPanic(t *testing.T) {
	boom := func() time.Time { panic("boom") }
	turnIsFree := func(t *testing.T, m *Manager) {
		t.Helper()
		select {
		case m.op <- struct{}{}:
			m.release()
		default:
			t.Error("the turn is still held")
		}
	}
	try := func(f func()) {
		defer func() { _ = recover() }()
		f()
	}

	t.Run("a refresh", func(t *testing.T) {
		e := newEnv(t)
		m := e.manager(WithNow(boom))
		try(func() { _, _ = m.Refresh(e.ctx) })
		turnIsFree(t, m)
	})
	t.Run("an upload", func(t *testing.T) {
		e := newEnv(t)
		m := e.manager(WithNow(boom))
		try(func() { _, _ = m.Install(e.ctx, bytes.NewReader(monthDB(t, "2026-09", "FR"))) })
		turnIsFree(t, m)
		if got := dirNames(t, e.dir); len(got) != 0 {
			t.Errorf("the directory holds %q", got)
		}
	})
}

// The month of an uploaded file comes from its build time, which is the file's
// word: a month that no database of DB-IP can have is refused.
func TestInstallRefusesAMonthThatIsNotPlausible(t *testing.T) {
	for _, c := range []struct {
		built time.Time
		ok    bool
	}{
		{time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC), false},
		{time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC), true}, // next month: the clock of the builder may be ahead
		{time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), false},
		{time.Unix(253402214399, 0), false}, // 9999-12: above every month, so nothing would ever be downloaded again
		{time.Unix(253402300800, 0), false}, // 10000-01: no name that the panel gives a file
		{time.Unix(1, 0), false},            // 1970-01
	} {
		e := newEnv(t) // the clock is the 5th of October 2026
		db, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": "DE"}, geoiptest.WithBuilt(c.built))
		if err != nil {
			t.Fatal(err)
		}
		st, err := e.m.Install(e.ctx, bytes.NewReader(db))
		if c.ok {
			if err != nil || !st.Present {
				t.Errorf("built %v: Install = %+v, %v", c.built, st, err)
			}
			continue
		}
		if err == nil || !errors.Is(err, geoip.ErrInvalid) {
			t.Errorf("built %v: err = %v, want a refusal that is geoip.ErrInvalid", c.built, err)
		}
		if got := e.names(); len(got) != 0 {
			t.Errorf("built %v: the directory holds %q", c.built, got)
		}
	}
}

func TestUploadOfAMonthThatIsNotPlausibleIsA400(t *testing.T) {
	p := newPanel(t)
	db, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": "DE"}, geoiptest.WithBuilt(time.Unix(253402214399, 0)))
	if err != nil {
		t.Fatal(err)
	}
	resp, body := p.put(p.web, bytes.NewReader(db), nil)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "9999-12") {
		t.Errorf("status %d (%q), want a 400 that names the month", resp.StatusCode, body)
	}
	if got := p.names(); len(got) != 0 {
		t.Errorf("the directory holds %q", got)
	}
}

// start runs the loop of e.m until the test ends.
func (e *env) start() {
	e.t.Helper()
	ctx, cancel := context.WithCancel(e.ctx)
	e.t.Cleanup(func() { cancel(); e.m.Wait() })
	e.m.Start(ctx)
}

// The loop looks again after the interval, and finds the file of a new month by
// itself.
func TestTheLoopLooksAgainEveryInterval(t *testing.T) {
	e := newEnv(t)
	e.m.every = 20 * time.Millisecond
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	e.start()
	eventually(t, "October", func() bool { st, _ := e.m.Status(e.ctx); return st.Month == "2026-10" })

	e.src.publish("2026-11", gzipped(t, monthDB(t, "2026-11", "FR")))
	e.clock.Set(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	eventually(t, "the loop to find November", func() bool { st, _ := e.m.Status(e.ctx); return st.Month == "2026-11" })
}

// While there is no database the loop does not wait a day to try again.
func TestTheLoopRetriesSoonWhileThereIsNoDatabase(t *testing.T) {
	e := newEnv(t) // nothing is published
	if e.m.retry != time.Hour || e.m.every != 24*time.Hour {
		t.Errorf("retry %v, every %v; want 1 hour and 24 hours", e.m.retry, e.m.every)
	}
	e.m.retry = 20 * time.Millisecond
	e.start()
	eventually(t, "the retries", func() bool { return len(e.src.asked()) >= 6 })
}

// And while the last look failed, with a database in use.
func TestTheLoopRetriesSoonAfterAFailedLook(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	e.refresh()
	e.m.retry = 20 * time.Millisecond
	e.clock.Set(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	e.src.answer("2026-11", http.StatusServiceUnavailable)
	e.start()
	eventually(t, "the retries", func() bool { return len(e.src.asked()) >= 4 }) // October once, November at least twice

	e.src.publish("2026-11", gzipped(t, monthDB(t, "2026-11", "FR")))
	eventually(t, "November", func() bool { st, _ := e.m.Status(e.ctx); return st.Month == "2026-11" && st.Error == "" })
}

// With the database and a look that went well, the loop waits the interval.
func TestTheLoopDoesNotRetryAfterAGoodLook(t *testing.T) {
	e := newEnv(t)
	e.m.retry = 10 * time.Millisecond
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	e.start()
	eventually(t, "the database", func() bool { st, _ := e.m.Status(e.ctx); return st.Present })

	// A retry would note a later look; there is none.
	e.clock.Set(t0.Add(time.Hour))
	time.Sleep(150 * time.Millisecond)
	if st, _ := e.m.Status(e.ctx); !st.Checked.Equal(t0) {
		t.Errorf("checked = %v: the loop looked again at once, want it to wait", st.Checked)
	}
}

// Turning the lookups on looks for the database at once, and does not wait for
// the next turn of the loop.
func TestEnablingKicksTheLoop(t *testing.T) {
	e := newEnv(t)
	e.m.every = time.Hour
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	if _, err := e.m.SetEnabled(e.ctx, false); err != nil {
		t.Fatal(err)
	}
	e.start()
	// The loop has had its first turn, which did nothing: it is disabled.
	eventually(t, "the first turn", func() bool { return strings.Contains(e.logs.String(), "looked for the country database") })
	if got := e.src.asked(); len(got) != 0 {
		t.Fatalf("asked for %q while disabled", got)
	}

	if _, err := e.m.SetEnabled(e.ctx, true); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the database to come at once", func() bool { st, _ := e.m.Status(e.ctx); return st.Present })
}

// A manager that is not started takes the switch without a loop to kick.
func TestEnablingWithoutALoop(t *testing.T) {
	e := newEnv(t)
	for _, on := range []bool{false, true, false, true} {
		if _, err := e.m.SetEnabled(e.ctx, on); err != nil {
			t.Fatal(err)
		}
	}
}
