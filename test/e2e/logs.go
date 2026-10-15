//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/dockerapi"
)

// The logs of the run, and the check at its end that no secret is in any of
// them (spec 10): the panel's stdout and its log, and the logs of the node's
// containers, the agent, the edge and every engine, those that the agent
// removes during the run included.

// leak is a value that no log of the run may hold, and what it is.
type leak struct{ what, value string }

// mustNotLeak notes values that no log of the run may hold, which checkLogs
// looks for at the end of the run, and that the test never prints. A value
// that is noted again as the same thing is noted once.
func (e *env) mustNotLeak(what string, values ...string) {
	e.secret(values...)
	e.sec.mu.Lock()
	defer e.sec.mu.Unlock()
	for _, v := range values {
		if l := (leak{what: what, value: v}); v != "" && !slices.Contains(e.sec.leaks, l) {
			e.sec.leaks = append(e.sec.leaks, l)
		}
	}
}

// logText is one log of the run, as the check sees it.
type logText struct {
	name  string // "the panel's log", "the log of postern-edge-g1", ...
	text  string
	whole bool // false when it was cut at its size limit
}

// findLeaks returns one line for every log that holds a value of leaks, in any
// letter case, which names the log and the value and never shows the value,
// and one for every log that was cut, since what was cut was not checked.
func findLeaks(logs []logText, leaks []leak) []string {
	var found []string
	for _, l := range logs {
		if !l.whole {
			found = append(found, l.name+" was cut at its size limit, so it was not checked in full")
		}
		low := strings.ToLower(l.text)
		for _, k := range leaks {
			switch n := strings.Count(low, strings.ToLower(k.value)); n {
			case 0:
			case 1:
				found = append(found, fmt.Sprintf("%s holds %s", l.name, k.what))
			default:
				found = append(found, fmt.Sprintf("%s holds %s, %d times", l.name, k.what, n))
			}
		}
	}
	return found
}

// withoutSetupURL is the stdout of the panel without the setup URL, which the
// panel prints there once, on purpose: anywhere else the token is a leak.
func withoutSetupURL(stdout, setupURL string) string {
	if setupURL == "" {
		return stdout
	}
	return strings.Replace(stdout, setupURL, "", 1)
}

// keyLeaks are the values that show that a log holds the private key in
// keyPEM: the lines of the base64 body of its PEM block (a log that holds a
// line holds a part of the key, and the body without its line breaks holds
// every line), and the key in hex.
func keyLeaks(keyPEM []byte) ([]string, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	body := base64.StdEncoding.EncodeToString(block.Bytes)
	var values []string
	for len(body) > 64 {
		values = append(values, body[:64])
		body = body[64:]
	}
	// A last line that is short could turn up anywhere by chance.
	if len(body) >= 16 {
		values = append(values, body)
	}
	return append(values, hex.EncodeToString(block.Bytes)), nil
}

// checkLogs fails the test when a log of the run holds a value of
// mustNotLeak: the panel's stdout, where only the setup URL may hold the
// token, the panel's log, and the logs of the node's containers that the
// watch kept. The logs of the agent, of the edge and of an engine must be among
// them, or the check proves nothing, and so must those of the containers with
// the roles that the test names (egress, for one).
func (e *env) checkLogs(roles ...string) {
	e.t.Helper()
	e.checkLogsOf(append([]string{"agent", "edge", "engine"}, roles...))
}

// checkLogsOf is checkLogs with the roles whose containers the logs must have
// named in full: a node without a proxy has no engine.
func (e *env) checkLogsOf(roles []string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	containers := e.logs.finish(ctx)

	var (
		logs  []logText
		names []string
	)
	panels := e.pastPanels
	if e.panel != nil {
		panels = append(slices.Clone(panels), e.panel)
	}
	for i, p := range panels {
		// The panel's stdout and log; with a restart of the panel (restartPanel),
		// those of each process.
		of := "the panel's"
		if len(panels) > 1 {
			of = fmt.Sprintf("panel process %d's", i+1)
		}
		logs = append(logs,
			logText{name: of + " stdout", text: withoutSetupURL(p.stdout.String(), p.setupURL), whole: p.stdout.whole()},
			logText{name: of + " log", text: p.log.String(), whole: p.log.whole()})
		names = append(names, fmt.Sprintf("%s stdout (%d bytes) and log (%d bytes)", of, len(p.stdout.String()), len(p.log.String())))
	}
	seen := map[string]int{}
	for _, c := range containers {
		seen[c.role]++
		names = append(names, fmt.Sprintf("%s (%d bytes)", c.name, len(c.data)))
		logs = append(logs, logText{name: "the log of " + c.name, text: string(c.data), whole: !c.cut})
	}
	for _, role := range roles {
		if seen[role] == 0 {
			e.errorf("the logs of the node have no container with the role %s: the check of the logs proves nothing", role)
		}
	}
	e.sec.mu.Lock()
	leaks := slices.Clone(e.sec.leaks)
	e.sec.mu.Unlock()
	found := findLeaks(logs, leaks)
	for _, f := range found {
		e.errorf("%s", f)
	}
	if len(found) == 0 {
		var whats []string
		for _, k := range leaks {
			if !slices.Contains(whats, k.what) {
				whats = append(whats, k.what)
			}
		}
		e.logf("no log holds a secret of the run (%s): %s", strings.Join(whats, ", "), strings.Join(names, ", "))
	}
}

// ---- the logs of the node's containers ----------------------------------------

// logWatch keeps the logs of the node's containers from the moment that it
// first sees each: a container that runs is followed, and one that has stopped
// is read in full once more, so that the log of a container that the agent
// removes during the run (an engine of an older generation) is kept too.
type logWatch struct {
	e      *env
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu   sync.Mutex
	logs map[string]*containerLog // by the ID of the container
}

// containerLog is what the watch has of the log of one container.
type containerLog struct {
	name, role string
	data       []byte // the longest read of the log; every read starts at its beginning
	cut        bool   // that read stopped at maxContainerLog
	reading    bool   // a read runs
	done       bool   // read in full since the container stopped
}

// maxContainerLog bounds what is kept of the log of one container. The node's
// containers keep 3 files of 10 MB.
const maxContainerLog = 64 << 20

// watchLogs starts the watch of the logs of the node's containers, which
// checkLogs ends. It also ends when the test does, before the cleanup.
func (e *env) watchLogs() {
	ctx, cancel := context.WithCancel(e.ctx)
	w := &logWatch{e: e, cancel: cancel, logs: map[string]*containerLog{}}
	e.logs = w
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for {
			w.scan(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
	e.t.Cleanup(w.stop)
}

// stop ends the scans and the reads.
func (w *logWatch) stop() {
	w.cancel()
	w.wg.Wait()
}

// scan starts a read of the log of every container of the node that needs
// one: a follow of one that runs and is not followed, a full read of one that
// has stopped since it was last read.
func (w *logWatch) scan(ctx context.Context) {
	list, err := w.e.containersOfThisRun(ctx)
	if err != nil {
		return // the next scan tries again, and finish reads what is there
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range list {
		l := w.entry(c)
		if l == nil {
			continue
		}
		running := c.State == "running" || c.State == "restarting"
		if running {
			l.done = false
		}
		if l.reading || l.done {
			continue
		}
		l.reading = true
		w.wg.Add(1)
		go w.read(ctx, c.ID, running)
	}
}

// entry is the log of c, which it makes when c is new; nil for a container
// that is not one of the node (a helper of the test has no role).
func (w *logWatch) entry(c rawContainer) *containerLog {
	role := c.Labels["postern.role"]
	if role == "" {
		return nil
	}
	l := w.logs[c.ID]
	if l == nil {
		l = &containerLog{name: c.name(), role: role}
		w.logs[c.ID] = l
	}
	return l
}

// read reads the log of a container from its beginning; with follow, until
// the container stops or is removed.
func (w *logWatch) read(ctx context.Context, id string, follow bool) {
	defer w.wg.Done()
	data, cut, err := readContainerLog(ctx, w.e.docker, id, follow)
	w.mu.Lock()
	defer w.mu.Unlock()
	l := w.logs[id]
	l.reading = false
	l.keep(data, cut)
	if err == nil && !follow {
		l.done = true
	}
}

// keep keeps a read that is not shorter than the one kept.
func (l *containerLog) keep(data []byte, cut bool) {
	if len(data) >= len(l.data) {
		l.data, l.cut = data, cut
	}
}

// finish ends the watch and returns the logs of every container of the node
// that it saw, by name: those that are still there are read in full once more.
// A log that cannot be read fails the test.
func (w *logWatch) finish(ctx context.Context) []containerLog {
	w.stop()
	list, err := w.e.containersOfThisRun(ctx)
	if err != nil {
		w.e.errorf("listing the containers of the run, for their logs: %v", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range list {
		l := w.entry(c)
		if l == nil {
			continue
		}
		data, cut, err := readContainerLog(ctx, w.e.docker, c.ID, false)
		if err != nil {
			w.e.errorf("reading the log of %s: %v", c.name(), err)
			continue
		}
		l.keep(data, cut)
	}
	out := make([]containerLog, 0, len(w.logs))
	for _, l := range w.logs {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b containerLog) int { return strings.Compare(a.name, b.name) })
	return out
}

// readContainerLog reads the log of a container from its beginning, up to
// maxContainerLog bytes; with follow, until the container stops.
func readContainerLog(ctx context.Context, d dockerapi.Client, id string, follow bool) (data []byte, cut bool, err error) {
	rc, err := d.Logs(ctx, id, -1, follow)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rc.Close() }()
	data, err = io.ReadAll(io.LimitReader(rc, maxContainerLog+1))
	if len(data) > maxContainerLog {
		data, cut = data[:maxContainerLog], true
	}
	return data, cut, err
}
