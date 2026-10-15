//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urbnywrt/postern/internal/probe"
)

// The flood of short connections that runs while the edge rolls to a new
// generation (R5-2, F2). The old edge closes its listeners and keeps the
// connections it accepted; what is still in the accept queue of a closing
// listener, and a handshake of TCP that is half done, is reset unless the
// kernel moves it to another listener of the SO_REUSEPORT group, which it
// does with net.ipv4.tcp_migrate_req = 1. So the flood sees no failure at 1,
// and at 0 it has to see one, or it never reached the accept queue and its
// run at 1 proves nothing.
const (
	// floodWorkers open connections back to back, each one at a time.
	floodWorkers = 256
	// floodTimeout bounds one connection: connecting and the handshake.
	floodTimeout = 5 * time.Second
	// floodSamples is how many errors are kept for the message.
	floodSamples = 5
)

// floodTarget is a proxy that the flood connects to.
type floodTarget struct {
	addr, sni string
	secret    []byte
}

// flood is a running flood.
type flood struct {
	stop     chan struct{}
	wg       sync.WaitGroup
	start    time.Time
	took     time.Duration
	attempts atomic.Int64
	failures atomic.Int64

	mu      sync.Mutex
	samples []string
}

// startFlood starts floodWorkers workers that connect to the targets in turn,
// do the fake-TLS handshake with the proxy's secret and close the connection
// with a reset (SO_LINGER 0), so that no TIME_WAIT of the run holds the ports
// of the host; and count the connections and the failures among them.
func (e *env) startFlood(targets []floodTarget) *flood {
	f := &flood{stop: make(chan struct{}), start: time.Now()}
	for w := range floodWorkers {
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			for i := w; ; i++ {
				select {
				case <-f.stop:
					return
				case <-e.ctx.Done():
					return
				default:
				}
				t := targets[i%len(targets)]
				f.attempts.Add(1)
				if err := floodOnce(e.ctx, t, w); err != nil && e.ctx.Err() == nil {
					f.failures.Add(1)
					f.mu.Lock()
					if len(f.samples) < floodSamples {
						f.samples = append(f.samples, err.Error())
					}
					f.mu.Unlock()
				}
			}
		}()
	}
	return f
}

// floodOnce is one connection of the flood, of the worker w. Each worker
// connects from an address of its own on the loopback: the edge holds at most
// 16 connections of one source that have not sent their ClientHello yet, and
// refuses more, which a flood from one address would take for a failure of
// the roll.
func floodOnce(ctx context.Context, t floodTarget, w int) error {
	d := net.Dialer{Timeout: floodTimeout, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, byte(1+w/250), byte(1+w%250))}}
	conn, err := d.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer func() {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	}()
	if err := probe.Handshake(conn, t.sni, t.secret, probe.Options{Timeout: floodTimeout}); err != nil {
		return fmt.Errorf("the handshake: %w", err)
	}
	return nil
}

// end stops the flood and waits for its workers.
func (f *flood) end() {
	close(f.stop)
	f.wg.Wait()
	f.took = time.Since(f.start)
}

// String says what the flood saw.
func (f *flood) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := fmt.Sprintf("%d workers, %d connections in %.1fs, %d failed", floodWorkers, f.attempts.Load(), f.took.Seconds(), f.failures.Load())
	if len(f.samples) > 0 {
		s += " (" + strings.Join(f.samples, "; ") + ")"
	}
	return s
}

// ---- net.ipv4.tcp_migrate_req ------------------------------------------------------

const migrateReq = "/proc/sys/net/ipv4/tcp_migrate_req"

// migrateReq reads net.ipv4.tcp_migrate_req of the host network of the Docker
// daemon, where the edge listens.
func (e *env) migrateReq() int {
	e.t.Helper()
	code, out := e.runPrivileged("sysctl", []string{"cat", migrateReq})
	v, err := strconv.Atoi(strings.TrimSpace(out))
	if code != 0 || err != nil {
		e.fatalf("reading net.ipv4.tcp_migrate_req of the host network: exit %d: %s (Linux 5.14 or later has it)", code, out)
	}
	return v
}

// setMigrateReq sets net.ipv4.tcp_migrate_req of the host network.
func (e *env) setMigrateReq(v int) {
	e.t.Helper()
	code, out := e.runPrivileged("sysctl", []string{"sh", "-c", "echo " + strconv.Itoa(v) + " > " + migrateReq})
	if code != 0 {
		e.fatalf("setting net.ipv4.tcp_migrate_req of the host network to %d: exit %d: %s", v, code, out)
	}
	if got := e.migrateReq(); got != v {
		e.fatalf("net.ipv4.tcp_migrate_req of the host network is %d after it was set to %d", got, v)
	}
	e.logf("net.ipv4.tcp_migrate_req of the host network is %d", v)
}

// runPrivileged runs a short command as root in a privileged container of the
// run on the host network, whose /proc/sys is writable, and returns its exit
// code and output. (dockerapi makes no privileged container: a node never
// needs one.)
func (e *env) runPrivileged(tag string, cmd []string) (int, string) {
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	name := "postern-e2e-" + e.run + "-" + tag + "-" + strings.ToLower(rand.Text())[:6]
	body := map[string]any{
		"Image":      runnerImage,
		"Entrypoint": cmd,
		"User":       "0:0",
		"Labels":     map[string]string{labelRun: e.run},
		"HostConfig": map[string]any{"NetworkMode": "host", "Privileged": true},
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := e.raw.do(ctx, "POST", "/containers/create?name="+name, body, &created); err != nil {
		return -1, err.Error()
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rcancel()
		_ = e.docker.Remove(rctx, created.ID, true)
	}()
	if err := e.docker.Start(ctx, created.ID); err != nil {
		return -1, err.Error()
	}
	return e.waitExit(ctx, created.ID)
}

// waitExit waits until the container id has exited, and returns its exit code
// and output.
func (e *env) waitExit(ctx context.Context, id string) (int, string) {
	for {
		d, err := e.docker.Inspect(ctx, id)
		if err != nil {
			return -1, err.Error()
		}
		if d.State == "exited" || d.State == "dead" {
			out := ""
			if rc, err := e.docker.Logs(ctx, id, -1, false); err == nil {
				data, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
				_ = rc.Close()
				out = strings.TrimSpace(string(data))
			}
			return d.ExitCode, out
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err().Error()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
