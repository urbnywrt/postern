package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func lineTexts(lines []logLine) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.text
	}
	return out
}

func TestLogRingKeepsTheLastLines(t *testing.T) {
	clock := newTestClock()
	r := newLogRing(3, clock.Now)
	for i := 1; i <= 5; i++ {
		_, _ = fmt.Fprintf(r, "line %d\n", i)
	}
	lines, skipped, _ := r.since(0)
	if got := strings.Join(lineTexts(lines), "|"); got != "line 3|line 4|line 5" {
		t.Errorf("lines = %q", got)
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2", skipped)
	}
	if !lines[0].ts.Equal(clock.Now()) {
		t.Errorf("ts = %v, want %v", lines[0].ts, clock.Now())
	}
	tail := r.tail(2)
	if got := strings.Join(lineTexts(tail), "|"); got != "line 4|line 5" {
		t.Errorf("tail(2) = %q", got)
	}
	if got := len(r.tail(10)); got != 3 {
		t.Errorf("tail(10) has %d lines, want 3", got)
	}
}

func TestLogRingJoinsPartialWrites(t *testing.T) {
	r := newLogRing(10, time.Now)
	_, _ = r.Write([]byte("hel"))
	_, _ = r.Write([]byte("lo\nwor"))
	_, _ = r.Write([]byte("ld\n\n"))
	lines, _, _ := r.since(0)
	if got := strings.Join(lineTexts(lines), "|"); got != "hello|world|" {
		t.Errorf("lines = %q", got)
	}
}

func TestLogRingCutsLongLines(t *testing.T) {
	r := newLogRing(10, time.Now)
	_, _ = r.Write([]byte(strings.Repeat("x", maxLogLine*2) + "\nnext\n"))
	lines, _, _ := r.since(0)
	if len(lines) != 2 || len(lines[0].text) > maxLogLine || lines[1].text != "next" {
		t.Errorf("lines: %d, first %d bytes", len(lines), len(lines[0].text))
	}
	// A line that never ends is cut too, and does not grow without bound.
	_, _ = r.Write([]byte(strings.Repeat("y", maxLogLine*3)))
	_, _ = r.Write([]byte("\n"))
	lines, _, _ = r.since(lines[1].n)
	if len(lines) != 1 || len(lines[0].text) > maxLogLine {
		t.Errorf("an endless line gave %d lines", len(lines))
	}
}

func TestLogRingSinceAndChanged(t *testing.T) {
	r := newLogRing(10, time.Now)
	_, _ = r.Write([]byte("a\nb\n"))
	lines, _, ch := r.since(0)
	last := lines[len(lines)-1].n
	select {
	case <-ch:
		t.Fatal("changed before a new line")
	default:
	}
	_, _ = r.Write([]byte("c\n"))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("a new line did not signal")
	}
	lines, skipped, _ := r.since(last)
	if got := strings.Join(lineTexts(lines), "|"); got != "c" || skipped != 0 {
		t.Errorf("since(%d) = %q, skipped %d", last, got, skipped)
	}
}
