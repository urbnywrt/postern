package reconcile

import (
	"slices"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines/telemt"
)

// The log environment of the container is in the instance hash (Ruling S6-4):
// an engine started without it, or with another one, gets a new hash; the same
// one keeps its hash; none adds nothing.
func TestLogEnvInTheInstanceHash(t *testing.T) {
	pr := &nodev1.Proxy{UseMiddleProxy: true}
	files := map[string][]byte{"config.toml": []byte("a")}
	cur := telemt.New().LogEnv()
	before := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, nil, pr, files)
	now := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, cur, pr, files)
	if now == before {
		t.Error("the log environment does not change the hash: old engines would keep logging clients")
	}
	if again := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, slices.Clone(cur), pr, files); again != now {
		t.Error("the same log environment gives another hash: every pass would roll")
	}
	if other := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, []string{"RUST_LOG=warn"}, pr, files); other == now || other == before {
		t.Error("another log environment is not a hash of its own")
	}
	if got := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, []string{}, pr, files); got != before {
		t.Error("an empty log environment changes the hash")
	}
}

// An engine whose hash is that of before the log environment rolls once by
// blue-green through the gate; then nothing rolls.
func TestOldLogEnvRollsTheEngineOnce(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	rt := h.runtime()
	old := rt.Instances[proxyID]
	cur := old.Hash
	// The engine as an agent before Ruling S6-4 recorded it.
	old.Hash = "hash-without-the-log-environment"
	rt.Instances[proxyID] = old
	if err := h.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	h.fakeEdge(1).setActive(proxyID, old.ListenPort, 2)
	probes := len(h.prober.callList())

	h.apply(h.baseState(2))
	h.pass()
	rec := h.runtime().Instances[proxyID]
	if rec.Generation != 2 || rec.Hash != cur || len(rec.Draining) != 1 || rec.Draining[0].Generation != 1 {
		t.Fatalf("runtime instance = %+v, want g2 with the current hash, g1 draining", rec)
	}
	if c := h.container(engName2); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	if n := len(h.prober.callList()); n <= probes {
		t.Errorf("the new generation was not probed by the gate (%d probes before, %d after)", probes, n)
	}

	h.apply(h.baseState(3))
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 2 {
		t.Errorf("generation = %d after another pass, want 2: rolled again", rec.Generation)
	}
}
