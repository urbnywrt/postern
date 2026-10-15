package agent

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

func eventRecord(kind string) *nodev1.WatchResponse {
	return &nodev1.WatchResponse{Payload: &nodev1.WatchResponse_Event{Event: &nodev1.NodeEvent{Kind: kind, Severity: "info", Message: kind}}}
}

func statsRecord(minute int64, ips ...string) *nodev1.WatchResponse {
	b := &nodev1.StatsBatch{
		MinuteUnix: minute,
		Proxies:    []*nodev1.ProxyMinute{{ProxyId: "p1", Up: 10, Down: 20}},
		Node:       &nodev1.NodeMinute{Cpu: 1.5},
	}
	for _, ip := range ips {
		b.Ips = append(b.Ips, &nodev1.IpSighting{ProxyId: "p1", Ip: ip, FirstSeen: minute, LastSeen: minute + 5, Bytes: 7})
	}
	return &nodev1.WatchResponse{Payload: &nodev1.WatchResponse_Stats{Stats: b}}
}

func openTestBuffer(t *testing.T, path, nodeID string, clock *testClock) *Buffer {
	t.Helper()
	b, err := openBuffer(path, nodeID, clock.Now, discardLog())
	if err != nil {
		t.Fatalf("openBuffer: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func appendAll(t *testing.T, b *Buffer, recs ...*nodev1.WatchResponse) []uint64 {
	t.Helper()
	var seqs []uint64
	for _, r := range recs {
		seq, err := b.Append(r)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		seqs = append(seqs, seq)
	}
	return seqs
}

func kindsOf(recs []*nodev1.WatchResponse) []string {
	var out []string
	for _, r := range recs {
		switch p := r.GetPayload().(type) {
		case *nodev1.WatchResponse_Event:
			out = append(out, "event:"+p.Event.GetKind())
		case *nodev1.WatchResponse_State:
			out = append(out, "state")
		case *nodev1.WatchResponse_Stats:
			out = append(out, "stats")
		default:
			out = append(out, "?")
		}
	}
	return out
}

func TestBufferAppendAndReplay(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)

	start := clock.Now().UnixMilli()
	seqs := appendAll(t, b, eventRecord("a"), statsRecord(clock.Now().Unix()), eventRecord("c"))
	// A new file numbers its records after the time it was made in
	// milliseconds, so that a file made again later never repeats a number the
	// panel has already seen.
	if seqs[0] != uint64(start)+1 || seqs[1] != seqs[0]+1 || seqs[2] != seqs[1]+1 {
		t.Fatalf("seqs = %v, want %d, %d, %d", seqs, start+1, start+2, start+3)
	}

	all, err := b.After(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got := kindsOf(all); strings.Join(got, ",") != "event:a,stats,event:c" {
		t.Fatalf("records = %v", got)
	}
	for i, r := range all {
		if r.GetSeq() != seqs[i] {
			t.Errorf("record %d has seq %d, want %d", i, r.GetSeq(), seqs[i])
		}
		if r.GetTsUnix() != clock.Now().Unix() {
			t.Errorf("record %d has ts %d, want %d", i, r.GetTsUnix(), clock.Now().Unix())
		}
	}
	if !proto.Equal(all[1].GetStats(), statsRecord(clock.Now().Unix()).GetStats()) {
		t.Errorf("stats = %v, want what was appended", all[1].GetStats())
	}

	rest, err := b.After(seqs[0], 100)
	if err != nil {
		t.Fatal(err)
	}
	if got := kindsOf(rest); strings.Join(got, ",") != "stats,event:c" {
		t.Errorf("after the first: %v", got)
	}
	page, err := b.After(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[1].GetSeq() != seqs[1] {
		t.Errorf("a page of 2 = %v", kindsOf(page))
	}
	last, err := b.LastSeq()
	if err != nil || last != seqs[2] {
		t.Errorf("LastSeq = %d, %v, want %d", last, err, seqs[2])
	}
}

func TestBufferKeepsATimestampItIsGiven(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	rec := eventRecord("x")
	rec.TsUnix = 12345
	appendAll(t, b, rec)
	all, _ := b.After(0, 10)
	if len(all) != 1 || all[0].GetTsUnix() != 12345 {
		t.Errorf("records = %v", all)
	}
	// The caller's record is not changed.
	if rec.GetSeq() != 0 {
		t.Errorf("the appended record got seq %d", rec.GetSeq())
	}
}

func TestBufferRefusesARecordWithoutPayload(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	if _, err := b.Append(&nodev1.WatchResponse{}); err == nil {
		t.Error("a record without payload was taken")
	}
}

// Numbers are never used twice: not after the records are pruned, not after
// a restart, and not when the file is made again.
func TestBufferNeverReusesSequenceNumbers(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "stats.db")
	b, err := openBuffer(path, testNodeID, clock.Now, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	seqs := appendAll(t, b, eventRecord("a"), eventRecord("b"))
	clock.Advance(8 * 24 * time.Hour)
	if n, err := b.Prune(); err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v, want 2 removed", n, err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b = openTestBuffer(t, path, testNodeID, clock)
	if last, err := b.LastSeq(); err != nil || last != seqs[1] {
		t.Errorf("LastSeq after pruning everything = %d, %v, want %d", last, err, seqs[1])
	}
	next := appendAll(t, b, eventRecord("c"))
	if next[0] <= seqs[1] {
		t.Errorf("after a restart the next seq is %d, want more than %d", next[0], seqs[1])
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// The file is lost and made again a minute later.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	clock.Advance(time.Minute)
	b = openTestBuffer(t, path, testNodeID, clock)
	again := appendAll(t, b, eventRecord("d"))
	if again[0] <= next[0] {
		t.Errorf("a new file starts at %d, want more than %d", again[0], next[0])
	}
}

// A buffer kept for another node is wiped, so that its records never reach
// the panel as records of this one.
func TestBufferOfAnotherNodeIsWiped(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "stats.db")
	b, err := openBuffer(path, otherNodeID, clock.Now, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	old := appendAll(t, b, statsRecord(clock.Now().Unix(), "203.0.113.7"), eventRecord("old"))
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	clock.Advance(time.Second)
	b = openTestBuffer(t, path, testNodeID, clock)
	all, err := b.After(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Errorf("records of the other node survived: %v", kindsOf(all))
	}
	seqs := appendAll(t, b, eventRecord("new"))
	if seqs[0] <= old[1] {
		t.Errorf("first seq for the new node = %d, want more than %d", seqs[0], old[1])
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	// The address of the other node's client is gone from the file too.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "203.0.113.7") {
		t.Error("the file still holds a client address of the other node")
	}

	// The same node again keeps its records.
	b = openTestBuffer(t, path, testNodeID, clock)
	if all, _ := b.After(0, 100); len(all) != 1 {
		t.Errorf("records after reopening = %v, want the one", kindsOf(all))
	}
}

func TestBufferPrunesByAgeAndCount(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	b.maxRows = 3
	appendAll(t, b, eventRecord("old1"), eventRecord("old2"))
	clock.Advance(6 * 24 * time.Hour)
	appendAll(t, b, eventRecord("mid"))
	clock.Advance(2 * 24 * time.Hour) // old1/old2 are 8 days old, mid 2 days
	if n, err := b.Prune(); err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v, want 2", n, err)
	}
	appendAll(t, b, eventRecord("n1"), eventRecord("n2"), eventRecord("n3"))
	if n, err := b.Prune(); err != nil || n != 1 {
		t.Fatalf("Prune by count = %d, %v, want 1", n, err)
	}
	all, _ := b.After(0, 100)
	if got := strings.Join(kindsOf(all), ","); got != "event:n1,event:n2,event:n3" {
		t.Errorf("left = %s", got)
	}
}

func TestBufferScrubsClientAddresses(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	seqs := appendAll(t, b, statsRecord(60, "203.0.113.7", "2001:db8::7"), eventRecord("e"), statsRecord(120))
	n, err := b.ScrubIPs()
	if err != nil || n != 1 {
		t.Fatalf("ScrubIPs = %d, %v, want 1", n, err)
	}
	all, _ := b.After(0, 100)
	if len(all) != 3 {
		t.Fatalf("records = %v", kindsOf(all))
	}
	want := statsRecord(60).GetStats()
	if !proto.Equal(all[0].GetStats(), want) || all[0].GetSeq() != seqs[0] {
		t.Errorf("scrubbed record = %v (seq %d), want %v (seq %d)", all[0].GetStats(), all[0].GetSeq(), want, seqs[0])
	}
	if n, err := b.ScrubIPs(); err != nil || n != 0 {
		t.Errorf("second ScrubIPs = %d, %v, want 0", n, err)
	}
}

func TestBufferChangedWakesWaiters(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	ch := b.Changed()
	select {
	case <-ch:
		t.Fatal("changed before anything was appended")
	default:
	}
	appendAll(t, b, eventRecord("a"))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("Append did not signal the change")
	}
	if b.Changed() == ch {
		t.Error("the change signal was not renewed")
	}
}

func TestBufferReplacesACorruptFile(t *testing.T) {
	clock := newTestClock()
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")
	if err := os.WriteFile(path, []byte(strings.Repeat("not a database ", 512)), 0o600); err != nil {
		t.Fatal(err)
	}
	b := openTestBuffer(t, path, testNodeID, clock)
	appendAll(t, b, eventRecord("a"))
	entries, _ := os.ReadDir(dir)
	var aside bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "stats.db.corrupt-") {
			aside = true
		}
	}
	if !aside {
		t.Errorf("the corrupt file was not kept aside: %v", entries)
	}
}

func TestBufferFileIsPrivate(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "stats.db")
	openTestBuffer(t, path, testNodeID, clock)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("stats.db mode = %v, want 0600 (it holds client addresses)", perm)
	}
}

func TestBufferStoresItsNodeID(t *testing.T) {
	clock := newTestClock()
	path := filepath.Join(t.TempDir(), "stats.db")
	b, err := openBuffer(path, testNodeID, clock.Now, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var id string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'node_id'`).Scan(&id); err != nil || id != testNodeID {
		t.Errorf("node id in stats.db = %q, %v, want %q", id, err, testNodeID)
	}
}

// A page holds a bounded amount of records in memory; the next page goes on
// where it stopped.
func TestBufferPagesAreBoundedInBytes(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	big := statsRecord(60)
	for i := range 40000 {
		big.GetStats().Ips = append(big.GetStats().Ips, &nodev1.IpSighting{ProxyId: "p1", Ip: fmt.Sprintf("2001:db8::%x", i), Bytes: uint64(i)})
	}
	if size := proto.Size(big); 8*size < 3*maxPageBytes/2 {
		t.Fatalf("the test records (%d bytes each) do not fill two pages", size)
	}
	seqs := appendAll(t, b, big, big, big, big, big, big, big, big, eventRecord("small"))

	var got []uint64
	cursor := uint64(0)
	pages := 0
	for {
		recs, last, full, err := b.page(cursor, 256)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		var size int
		for _, r := range recs {
			got = append(got, r.GetSeq())
			size += proto.Size(r)
		}
		if size > maxPageBytes+2*proto.Size(big) {
			t.Errorf("a page of %d bytes", size)
		}
		cursor = last
		if !full {
			break
		}
	}
	if pages < 2 {
		t.Errorf("everything came in %d page", pages)
	}
	if !slices.Equal(got, seqs) {
		t.Errorf("records = %v, want %v", got, seqs)
	}
}

// An event whose text is not valid UTF-8 (an error message can quote bytes)
// is still buffered and sent.
func TestJournalCleansEventTexts(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	j := newJournal(b, discardLog(), clock.Now)
	j.event(&nodev1.NodeEvent{Kind: "k", Severity: "error", Message: "bad \xff byte", Details: map[string]string{"x\xfe": "y\xfd"}})
	recs, err := b.After(0, 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("records = %v, %v", recs, err)
	}
	ev := recs[0].GetEvent()
	if ev.GetMessage() != "bad \uFFFD byte" || ev.GetDetails()["x\uFFFD"] != "y\uFFFD" {
		t.Errorf("event = %v", ev)
	}
}

// A state report that only went to the open streams is superseded by a newer
// one that is buffered: a stream that is behind must not send the older one
// after the newer.
func TestJournalNewerStateSupersedesAPendingLiveOne(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	j := newJournal(b, discardLog(), clock.Now)
	w := j.watch()
	defer j.unwatch(w)

	old := &nodev1.StateReport{AppliedGeneration: 1}
	j.state(old)
	j.state(proto.Clone(old).(*nodev1.StateReport)) // unchanged: live only
	if len(w.live) != 1 {
		t.Fatalf("pending live records = %d, want 1", len(w.live))
	}
	j.state(&nodev1.StateReport{AppliedGeneration: 2})
	if len(w.live) != 0 {
		t.Errorf("the older live report is still pending: %v", <-w.live)
	}

	// A live record that is not a state report (an event the buffer could not
	// take) stays.
	ev := eventRecord("kept")
	j.mu.Lock()
	j.liveLocked(ev)
	j.mu.Unlock()
	j.state(&nodev1.StateReport{AppliedGeneration: 3})
	if len(w.live) != 1 || (<-w.live).GetEvent().GetKind() != "kept" {
		t.Error("a pending live event was dropped")
	}
}

// The live report that is superseded goes before the new one is buffered, not
// after. Append wakes the open streams up, and a stream that reads the new record
// from the buffer and then takes the live one that is still waiting would send the
// older report after the newer. The buffer is held here, so that Append cannot
// finish: whatever has happened to the live report by then happened before it.
func TestJournalDropsASupersededLiveStateBeforeBufferingTheNewOne(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	j := newJournal(b, discardLog(), clock.Now)
	w := j.watch()
	defer j.unwatch(w)

	first := &nodev1.StateReport{AppliedGeneration: 1}
	j.state(first)
	j.state(proto.Clone(first).(*nodev1.StateReport)) // unchanged: live only
	if len(w.live) != 1 {
		t.Fatalf("pending live records = %d, want 1", len(w.live))
	}

	b.mu.Lock() // Append, and so the new report, waits here
	held := true
	defer func() {
		if held {
			b.mu.Unlock()
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		j.state(&nodev1.StateReport{AppliedGeneration: 2})
	}()
	deadline := time.Now().Add(3 * time.Second)
	for len(w.live) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the older live report was still waiting while the new one was being buffered")
		}
		time.Sleep(2 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("state returned while the buffer was held, so the test does not show what it means to")
	default:
	}
	b.mu.Unlock()
	held = false
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("state did not return once the buffer was let go")
	}

	recs, err := b.After(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var gens []uint64
	for _, r := range recs {
		gens = append(gens, r.GetState().GetAppliedGeneration())
	}
	if !slices.Equal(gens, []uint64{1, 2}) {
		t.Errorf("buffered state reports of generations %v, want [1 2]", gens)
	}
	if len(w.live) != 0 {
		t.Errorf("pending live records = %d, want none: the new report is in the buffer", len(w.live))
	}
}

// A buffer that cannot take the new report does not leave the older live one
// behind either: the new one goes live in its place.
func TestJournalNewerStateReplacesALiveOneWhenTheBufferIsClosed(t *testing.T) {
	clock := newTestClock()
	b := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	j := newJournal(b, discardLog(), clock.Now)
	w := j.watch()
	defer j.unwatch(w)

	j.state(&nodev1.StateReport{AppliedGeneration: 1})
	j.state(&nodev1.StateReport{AppliedGeneration: 1}) // unchanged: live
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	j.state(&nodev1.StateReport{AppliedGeneration: 2})
	if len(w.live) != 1 {
		t.Fatalf("pending live records = %d, want 1", len(w.live))
	}
	if rec := <-w.live; rec.GetState().GetAppliedGeneration() != 2 {
		t.Errorf("the live report is of generation %d, want 2", rec.GetState().GetAppliedGeneration())
	}
}

func TestBufferAfterClose(t *testing.T) {
	clock := newTestClock()
	b, err := openBuffer(filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock.Now, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	ch := b.Changed()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	default:
		t.Error("Close did not wake the waiters")
	}
	if _, err := b.Append(eventRecord("late")); err == nil {
		t.Error("Append after Close succeeded")
	}
	if err := b.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
