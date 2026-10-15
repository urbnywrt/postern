package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
)

const (
	// agentLogLines is how many lines of its own log the agent keeps for
	// StreamLogs.
	agentLogLines = 2000
	// maxLogLine is the longest line kept or sent; the rest of a longer line
	// is dropped.
	maxLogLine = 8 << 10

	// defaultLogTail is the tail of a StreamLogs call that asks for none
	// (proto3 cannot tell 0 from unset), and maxLogTail the most it may ask.
	defaultLogTail = 100
	maxLogTail     = 5000

	// Streams of StreamLogsResponse: the agent logs to stderr; Docker's log
	// of a container mixes stdout and stderr, and dockerapi does not tell
	// them apart.
	streamAgent     = "stderr"
	streamContainer = "combined"
)

// logLine is a line of the agent's log; n counts the lines from 1.
type logLine struct {
	n    uint64
	ts   time.Time
	text string
}

// logRing keeps the last lines of the agent's own log, for StreamLogs with
// the target "agent". It is an io.Writer for the log handler.
type logRing struct {
	now func() time.Time

	mu      sync.Mutex
	lines   []logLine // circular
	start   int       // index of the oldest line
	count   int
	next    uint64 // number of the last line written
	partial []byte // a line without its newline yet
	changed chan struct{}
}

func newLogRing(size int, now func() time.Time) *logRing {
	return &logRing{now: now, lines: make([]logLine, size), changed: make(chan struct{})}
}

// Write takes log output; every newline ends a line.
func (r *logRing) Write(p []byte) (int, error) {
	n := len(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	added := false
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			r.appendPartial(p)
			break
		}
		r.appendPartial(p[:i])
		r.pushLocked(string(r.partial))
		r.partial = r.partial[:0]
		added = true
		p = p[i+1:]
	}
	if added {
		close(r.changed)
		r.changed = make(chan struct{})
	}
	return n, nil
}

func (r *logRing) appendPartial(b []byte) {
	if room := maxLogLine - len(r.partial); room > 0 {
		r.partial = append(r.partial, b[:min(len(b), room)]...)
	}
}

func (r *logRing) pushLocked(text string) {
	r.next++
	l := logLine{n: r.next, ts: r.now(), text: strings.ToValidUTF8(text, "\uFFFD")}
	if r.count < len(r.lines) {
		r.lines[(r.start+r.count)%len(r.lines)] = l
		r.count++
		return
	}
	r.lines[r.start] = l
	r.start = (r.start + 1) % len(r.lines)
}

// since returns the lines after line number after, in order; how many lines
// after it are gone from the ring; and a channel that the next line closes.
func (r *logRing) since(after uint64) ([]logLine, uint64, <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []logLine
	var skipped uint64
	if r.count > 0 {
		oldest := r.next - uint64(r.count) + 1
		if after+1 < oldest {
			skipped = oldest - (after + 1)
		}
		for i := range r.count {
			if l := r.lines[(r.start+i)%len(r.lines)]; l.n > after {
				out = append(out, l)
			}
		}
	}
	return out, skipped, r.changed
}

// tail returns the last k lines.
func (r *logRing) tail(k int) []logLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	k = min(k, r.count)
	out := make([]logLine, 0, k)
	for i := r.count - k; i < r.count; i++ {
		out = append(out, r.lines[(r.start+i)%len(r.lines)])
	}
	return out
}

// last is the number of the last line written.
func (r *logRing) last() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.next
}

// ---- StreamLogs -------------------------------------------------------------------

// StreamLogs sends the tail of a log, and with follow what comes after. The
// targets are "agent" (the agent's own log), "edge" (the current edge
// container) and "proxy:<id>" (the engine container that serves the proxy).
func (s *Service) StreamLogs(ctx context.Context, req *connect.Request[nodev1.StreamLogsRequest], stream *connect.ServerStream[nodev1.StreamLogsResponse]) error {
	target := req.Msg.GetTarget()
	tail := int(req.Msg.GetTail())
	if tail == 0 {
		tail = defaultLogTail
	}
	tail = min(tail, maxLogTail)
	follow := req.Msg.GetFollow()

	if target == "agent" {
		return s.agentLogs(ctx, stream, tail, follow)
	}
	name, err := s.logContainer(target)
	if err != nil {
		return err
	}
	return s.containerLogs(ctx, stream, name, tail, follow)
}

// logContainer is the container whose log a target names.
func (s *Service) logContainer(target string) (string, error) {
	id, isProxy := strings.CutPrefix(target, "proxy:")
	if target != "edge" && (!isProxy || id == "") {
		return "", connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf(`unknown log target %.100q: use "agent", "edge" or "proxy:<id>"`, target))
	}
	rt, err := s.store.LoadRuntime()
	if err != nil {
		return "", connect.NewError(connect.CodeUnavailable, fmt.Errorf("reading the runtime record: %w", err))
	}
	if !isProxy {
		if rt.EdgeGeneration == 0 {
			return "", connect.NewError(connect.CodeNotFound, errors.New("there is no edge yet"))
		}
		return fmt.Sprintf("postern-edge-g%d", rt.EdgeGeneration), nil
	}
	rec, ok := rt.Instances[id]
	if !ok || rec.Generation == 0 {
		return "", connect.NewError(connect.CodeNotFound, fmt.Errorf("proxy %.100q has no engine that serves it", id))
	}
	return fmt.Sprintf("postern-eng-%s-g%d", strings.ToLower(id), rec.Generation), nil
}

func (s *Service) agentLogs(ctx context.Context, stream *connect.ServerStream[nodev1.StreamLogsResponse], tail int, follow bool) error {
	lines := s.ring.tail(tail)
	last := s.ring.last()
	if len(lines) > 0 {
		last = lines[len(lines)-1].n
	}
	if err := sendLogLines(stream, lines); err != nil {
		return err
	}
	if !follow {
		return nil
	}
	for {
		lines, skipped, changed := s.ring.since(last)
		if skipped > 0 {
			note := logLine{ts: s.now(), text: fmt.Sprintf("[%d lines skipped]", skipped)}
			if err := sendLogLines(stream, []logLine{note}); err != nil {
				return err
			}
		}
		if err := sendLogLines(stream, lines); err != nil {
			return err
		}
		if len(lines) > 0 {
			last = lines[len(lines)-1].n
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		}
	}
}

func sendLogLines(stream *connect.ServerStream[nodev1.StreamLogsResponse], lines []logLine) error {
	for _, l := range lines {
		err := stream.Send(&nodev1.StreamLogsResponse{TsUnixNano: l.ts.UnixNano(), Stream: streamAgent, Line: l.text})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) containerLogs(ctx context.Context, stream *connect.ServerStream[nodev1.StreamLogsResponse], name string, tail int, follow bool) error {
	rc, err := s.docker.Logs(ctx, name, tail, follow)
	switch {
	case errors.Is(err, dockerapi.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("the container %s does not exist", name))
	case err != nil:
		return connect.NewError(connect.CodeUnavailable, fmt.Errorf("reading the log of %s: %w", name, err))
	}
	defer func() { _ = rc.Close() }()
	br := bufio.NewReaderSize(rc, 64<<10)
	for {
		line, err := readLogLine(br)
		if line != nil {
			msg := &nodev1.StreamLogsResponse{
				TsUnixNano: s.now().UnixNano(), // when it was read: Docker's own times are not asked for
				Stream:     streamContainer,
				Line:       strings.ToValidUTF8(string(line), "\uFFFD"),
			}
			if serr := stream.Send(msg); serr != nil {
				return serr
			}
		}
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil && ctx.Err() != nil:
			return nil
		case err != nil:
			return connect.NewError(connect.CodeUnavailable, fmt.Errorf("reading the log of %s: %w", name, err))
		}
	}
}

// readLogLine reads one line without its newline, cut to maxLogLine bytes. A
// last line without a newline is returned with io.EOF.
func readLogLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if room := maxLogLine - len(line); room > 0 {
			line = append(line, chunk[:min(len(chunk), room)]...)
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err != nil:
			if len(line) == 0 {
				return nil, err
			}
			return bytes.TrimRight(line, "\r\n"), err
		}
		return bytes.TrimRight(line, "\r\n"), nil
	}
}
