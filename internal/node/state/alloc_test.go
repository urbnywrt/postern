package state

import (
	"net"
	"testing"
)

func TestDefaultRanges(t *testing.T) {
	for name, want := range map[string]PortRange{
		RangeEngine:      {20000, 24999},
		RangeEngineAPI:   {25000, 29999},
		RangeEdgeSocks:   {30000, 34999},
		RangeEgressSocks: {35000, 39999},
		RangeService:     {40000, 40999},
	} {
		got, ok := DefaultRange(name)
		if !ok || got != want {
			t.Errorf("DefaultRange(%q) = %v, %v; want %v", name, got, ok, want)
		}
	}
	if _, ok := DefaultRange("nope"); ok {
		t.Error("DefaultRange(nope) is ok")
	}
}

// The allocator probe-binds 127.0.0.1:port and skips a port that something
// else listens on.
func TestAllocSkipsPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	busy := uint16(ln.Addr().(*net.TCPAddr).Port)
	if busy > 65535-20 {
		t.Skipf("ephemeral port %d too close to the end of the port space", busy)
	}

	a := &Allocator{Ranges: map[string]PortRange{RangeEngine: {busy, busy + 20}}}
	rt := NewRuntime()
	got, err := a.Alloc(rt, "k", RangeEngine)
	if err != nil {
		t.Fatal(err)
	}
	if got == busy || got < busy || got > busy+20 {
		t.Errorf("Alloc = %d; want a port in %d-%d other than %d", got, busy, busy+20, busy)
	}
	if rt.Ports["k"] != got {
		t.Errorf("runtime records %d, want %d", rt.Ports["k"], got)
	}

	// The only port of a range is busy: nothing to allocate.
	only := &Allocator{Ranges: map[string]PortRange{RangeEngine: {busy, busy}}}
	if p, err := only.Alloc(NewRuntime(), "k", RangeEngine); err == nil {
		t.Errorf("Alloc = %d, nil; want an error", p)
	}
}

func alwaysFree(uint16) bool { return true }

func TestAllocSkipsRuntimePorts(t *testing.T) {
	a := &Allocator{Ranges: map[string]PortRange{RangeEngine: {100, 110}}, IsFree: alwaysFree}
	rt := NewRuntime()
	rt.Ports["other-1"] = 100
	rt.Ports["other-2"] = 101
	got, err := a.Alloc(rt, "k", RangeEngine)
	if err != nil {
		t.Fatal(err)
	}
	if got != 102 {
		t.Errorf("Alloc = %d, want 102", got)
	}
}

func TestAllocIsIdempotentPerKey(t *testing.T) {
	a := &Allocator{Ranges: map[string]PortRange{RangeEngine: {100, 110}}, IsFree: alwaysFree}
	rt := NewRuntime()
	first, err := a.Alloc(rt, "k", RangeEngine)
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.Alloc(rt, "k", RangeEngine)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Errorf("second Alloc = %d, want %d", again, first)
	}
	if len(rt.Ports) != 1 {
		t.Errorf("runtime has %d ports, want 1", len(rt.Ports))
	}
}

func TestAllocDistinctAndRelease(t *testing.T) {
	a := &Allocator{Ranges: map[string]PortRange{RangeEngine: {100, 102}}, IsFree: alwaysFree}
	rt := NewRuntime()
	seen := map[uint16]bool{}
	for _, k := range []string{"a", "b", "c"} {
		p, err := a.Alloc(rt, k, RangeEngine)
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("port %d allocated twice", p)
		}
		seen[p] = true
	}
	if p, err := a.Alloc(rt, "d", RangeEngine); err == nil {
		t.Fatalf("Alloc in a full range = %d, nil; want an error", p)
	}
	freed := rt.Ports["b"]
	a.Release(rt, "b")
	if _, ok := rt.Ports["b"]; ok {
		t.Fatal("Release left the key")
	}
	p, err := a.Alloc(rt, "d", RangeEngine)
	if err != nil {
		t.Fatal(err)
	}
	if p != freed {
		t.Errorf("Alloc after Release = %d, want the freed %d", p, freed)
	}
}

// A port that was just released is not handed out again while others are
// free: the next search starts after the last allocation.
func TestAllocDoesNotReuseAtOnce(t *testing.T) {
	a := &Allocator{Ranges: map[string]PortRange{RangeEngine: {100, 110}}, IsFree: alwaysFree}
	rt := NewRuntime()
	first, _ := a.Alloc(rt, "a", RangeEngine)
	a.Release(rt, "a")
	second, err := a.Alloc(rt, "b", RangeEngine)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Errorf("Alloc reused the port %d released a moment ago", first)
	}
}

func TestAllocUnknownRange(t *testing.T) {
	a := &Allocator{IsFree: alwaysFree}
	if p, err := a.Alloc(NewRuntime(), "k", "nope"); err == nil {
		t.Errorf("Alloc = %d, nil; want an error", p)
	}
}

func TestAllocZeroValueUsesDefaults(t *testing.T) {
	a := &Allocator{IsFree: alwaysFree}
	p, err := a.Alloc(NewRuntime(), "k", RangeService)
	if err != nil {
		t.Fatal(err)
	}
	if p < 40000 || p > 40999 {
		t.Errorf("Alloc = %d, want a port in 40000-40999", p)
	}
}

// Reserved ports are never handed out, whatever the runtime says and even
// when they are free: the listeners of the desired state hold them.
func TestAllocSkipsReservedPorts(t *testing.T) {
	a := &Allocator{IsFree: func(uint16) bool { return true }}
	a.Reserve(40000, 40001)
	rt := NewRuntime()
	for i := range 20 {
		p, err := a.Alloc(rt, "k"+string(rune('a'+i)), RangeService)
		if err != nil {
			t.Fatal(err)
		}
		if p == 40000 || p == 40001 {
			t.Fatalf("allocated the reserved port %d", p)
		}
	}
	if p, _ := a.Alloc(rt, "ka", RangeService); p != 40002 {
		t.Errorf("first allocation = %d, want 40002, the first free port past the reserved ones", p)
	}
}
