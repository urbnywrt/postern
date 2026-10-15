package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
)

// The management listeners of spec 5.3. The panel reaches the agent either on a
// plain listener of its own (mode port) or through the port of a proxy by the
// management SNI (mode hidden): the edge forwards mgmt_sni with a PROXY v2
// header to the agent's hidden listener on the loopback.
const (
	// mgmtFallbackAfter is how long the hidden listener may go without an
	// authenticated request, while the plain one is off, before the agent
	// reopens the plain listener (a failsafe against a broken hidden path).
	mgmtFallbackAfter = 15 * time.Minute
	// mgmtCheckEvery is how often the fallback is checked.
	mgmtCheckEvery = time.Minute
)

// Event kind of the fallback.
const evMgmtFallback = "mgmt.fallback"

// hiddenHostPort is "127.0.0.1:<port>".
func hiddenHostPort(port uint16) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}

// httpInstance is one management server and the listener it serves.
type httpInstance struct {
	srv *http.Server
	ln  net.Listener
}

// mgmtListeners owns the plain and the hidden management listeners and the
// fallback that reopens the plain one when the hidden path stops delivering
// authenticated requests (spec 5.3). It serves the same mTLS handler on both;
// the hidden listener reads a PROXY v2 header before the TLS bytes
// (newProxyV2Listener) and the plain one refuses PROXY.
type mgmtListeners struct {
	plainAddr    string // where the plain listener binds (0.0.0.0:<mgmt port>)
	hiddenPort   uint16 // the hidden listener on 127.0.0.1
	handler      http.Handler
	tlsConf      *tls.Config
	baseCtx      context.Context
	log          *slog.Logger
	now          func() time.Time
	event        func(kind, severity, msg string, details map[string]string)
	proxyTimeout time.Duration // the PROXY v2 header timeout of the hidden listener

	fallbackAfter time.Duration
	checkEvery    time.Duration

	// Test seams: called with the address a listener bound, when it opens.
	onPlain  func(net.Addr)
	onHidden func(net.Addr)

	mu           sync.Mutex
	plain        *httpInstance
	hidden       *httpInstance
	wantPlain    bool      // the plain listener should be open
	fallbackOpen bool      // the plain listener was reopened by the fallback
	lastHidden   time.Time // when an authenticated request last arrived through the hidden listener
	closed       bool
}

// start opens the listeners the settings call for at startup. The hidden
// listener runs when mgmt_sni is set; the plain one runs unless the hidden one
// runs and mgmt_hidden_only is set. A plain listener that cannot bind at
// startup is fatal, as it was before the hidden listener; a hidden listener
// that cannot open leaves the plain one on.
func (m *mgmtListeners) start(s *nodev1.NodeSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.GetMgmtSni() != "" {
		if err := m.openHiddenLocked(); err != nil {
			m.log.Error("agent: the hidden management listener could not be opened; the plain listener stays on", "err", err)
		}
	}
	hiddenOnly := s.GetMgmtHiddenOnly() && m.hidden != nil
	m.wantPlain = !hiddenOnly
	if m.wantPlain {
		if err := m.openPlainLocked(); err != nil {
			return err
		}
	} else {
		m.lastHidden = m.now() // the fallback clock starts now
	}
	if m.plain == nil && m.hidden == nil {
		return errors.New("no management listener could be opened")
	}
	return nil
}

// apply reconciles the listeners to the settings of a newly applied state. It
// is called from ApplyState.
func (m *mgmtListeners) apply(s *nodev1.NodeSettings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	wantHidden := s.GetMgmtSni() != ""
	switch {
	case wantHidden && m.hidden == nil:
		if err := m.openHiddenLocked(); err != nil {
			m.log.Error("agent: the hidden management listener could not be opened", "err", err)
		}
	case !wantHidden && m.hidden != nil:
		m.closeHiddenLocked()
	}
	// The plain listener may be turned off only while the hidden one runs: a
	// node with neither would be unreachable.
	wantPlain := !s.GetMgmtHiddenOnly() || m.hidden == nil
	m.wantPlain = wantPlain
	switch {
	case wantPlain && m.plain == nil:
		if err := m.openPlainLocked(); err != nil {
			m.log.Error("agent: the plain management listener could not be opened", "err", err)
		}
		m.fallbackOpen = false
	case !wantPlain && m.plain != nil:
		m.closePlainLocked()
		m.fallbackOpen = false
		m.lastHidden = m.now() // the fallback clock starts now
	}
}

// recordHidden notes that an authenticated request arrived through the hidden
// listener (every request that reaches the handler has passed mTLS). If the
// fallback had reopened the plain listener, the hidden path works again, so the
// plain one is closed.
func (m *mgmtListeners) recordHidden() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastHidden = m.now()
	if m.fallbackOpen && !m.wantPlain {
		m.closePlainLocked()
		m.fallbackOpen = false
		m.log.Info("agent: an authenticated request arrived through the hidden management listener; closing the plain listener the fallback had reopened")
	}
}

// runFallback reopens the plain listener when the hidden one has gone without
// an authenticated request for fallbackAfter while the plain one is off, until
// ctx ends.
func (m *mgmtListeners) runFallback(ctx context.Context) {
	t := time.NewTicker(m.checkEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.checkFallback()
		}
	}
}

func (m *mgmtListeners) checkFallback() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.wantPlain || m.plain != nil || m.hidden == nil {
		return
	}
	if m.now().Sub(m.lastHidden) < m.fallbackAfter {
		return
	}
	m.fallbackLocked("no authenticated request arrived through the hidden management listener for " + m.fallbackAfter.String())
}

// fallbackLocked reopens the plain listener for reason and records it as a
// mgmt.fallback event.
func (m *mgmtListeners) fallbackLocked(reason string) {
	if err := m.openPlainLocked(); err != nil {
		m.log.Error("agent: the fallback could not reopen the plain management listener", "err", err)
		return
	}
	m.fallbackOpen = true
	m.log.Warn("agent: " + reason + "; the plain management listener was reopened")
	m.event(evMgmtFallback, sevWarning, reason+"; the plain management listener was reopened", map[string]string{"reason": reason})
}

// shutdown stops both listeners, gracefully within timeout.
func (m *mgmtListeners) shutdown(timeout time.Duration) {
	m.mu.Lock()
	m.closed = true
	plain, hidden := m.plain, m.hidden
	m.plain, m.hidden = nil, nil
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, inst := range []*httpInstance{plain, hidden} {
		if inst != nil {
			if err := inst.srv.Shutdown(ctx); err != nil {
				_ = inst.srv.Close()
			}
		}
	}
}

// ---- the listeners, under m.mu --------------------------------------------------

func (m *mgmtListeners) openPlainLocked() error {
	ln, err := net.Listen("tcp", m.plainAddr)
	if err != nil {
		return err
	}
	srv := newHTTPServer(m.handler, m.tlsConf, m.log, m.baseCtx)
	m.plain = &httpInstance{srv: srv, ln: ln}
	go serveMgmt(srv, ln, "plain", m.log)
	m.log.Info("agent: the plain management listener is serving", "listen", ln.Addr().String())
	if m.onPlain != nil {
		m.onPlain(ln.Addr())
	}
	return nil
}

func (m *mgmtListeners) closePlainLocked() {
	if m.plain == nil {
		return
	}
	_ = m.plain.srv.Close()
	m.plain = nil
}

func (m *mgmtListeners) openHiddenLocked() error {
	ln, err := net.Listen("tcp", hiddenHostPort(m.hiddenPort))
	if err != nil {
		return err
	}
	pl := newProxyV2Listener(ln, m.proxyTimeout)
	// Every request that reaches the handler through the hidden listener is
	// authenticated (mTLS) and resets the fallback clock.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.recordHidden()
		m.handler.ServeHTTP(w, r)
	})
	srv := newHTTPServer(handler, m.tlsConf, m.log, m.baseCtx)
	m.hidden = &httpInstance{srv: srv, ln: pl}
	go serveMgmt(srv, pl, "hidden", m.log)
	m.log.Info("agent: the hidden management listener is serving", "listen", pl.Addr().String())
	if m.onHidden != nil {
		m.onHidden(pl.Addr())
	}
	return nil
}

func (m *mgmtListeners) closeHiddenLocked() {
	if m.hidden == nil {
		return
	}
	_ = m.hidden.srv.Close()
	m.hidden = nil
}

// serveMgmt serves srv on ln until it is closed; a closed listener is the
// normal end, anything else is logged.
func serveMgmt(srv *http.Server, ln net.Listener, which string, log *slog.Logger) {
	err := srv.ServeTLS(ln, "", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("agent: the "+which+" management listener stopped", "err", err)
	}
}

// allocHiddenPort allocates the agent's hidden management port once from the
// service range (key mgmt-hidden) and records it in runtime.json, so that the
// reconciler can render the mgmt route to it. A port already recorded is
// returned as it is.
func allocHiddenPort(store *state.Store, alloc *state.Allocator) (uint16, error) {
	rt, err := store.LoadRuntime()
	if err != nil {
		return 0, err
	}
	if rt == nil {
		rt = state.NewRuntime()
	}
	port, err := alloc.Alloc(rt, state.MgmtHiddenPortKey, state.RangeService)
	if err != nil {
		return 0, err
	}
	if err := store.SaveRuntime(rt); err != nil {
		return 0, err
	}
	return port, nil
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
