package nodes

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestPanelAddrs(t *testing.T) {
	v4, v6 := []string{"198.51.100.1"}, []string{"198.51.100.1", "2001:db8::1"}
	for _, tc := range []struct {
		prev []string
		peer string
		want []string
	}{
		{nil, "198.51.100.1", v4},
		{v4, "2001:db8::1", v6},
		{v6, "198.51.100.2", []string{"198.51.100.2", "2001:db8::1"}},
		{v6, "2001:DB8::2", []string{"198.51.100.1", "2001:db8::2"}},
		{nil, "::ffff:198.51.100.1", v4}, // a mapped address is its IPv4 one
		{[]string{"2001:db8::1"}, "198.51.100.1", v6},
		// Not the unicast address of one host: nothing changes.
		{v6, "", v6},
		{v6, "not an address", v6},
		{v6, "0.0.0.0", v6},
		{v6, "::", v6},
		{v6, "224.0.0.1", v6},
		{v6, "ff02::1", v6},
		{v6, "255.255.255.255", v6},
		{v6, "fe80::1%eth0", v6},
		{v6, "198.51.100.0/24", v6},
	} {
		if got := panelAddrs(tc.prev, tc.peer); !slices.Equal(got, tc.want) {
			t.Errorf("panelAddrs(%q, %q) = %q, want %q", tc.prev, tc.peer, got, tc.want)
		}
	}
}

func TestManagerLearnsTheAddressOfThePanel(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	info := func(peer string) *nodev1.GetInfoResponse {
		return &nodev1.GetInfoResponse{AgentVersion: "1.2.3", Arch: "amd64", PeerAddr: peer}
	}
	f.setInfo(info("198.51.100.30"))
	b := &fakeBuilder{}
	m := p.newManager()
	m.SetStateBuilder(b)
	m.cfg.resyncEvery = 20 * time.Millisecond // GetInfo is asked again at every resync
	m.Start(context.Background())

	// Learned at the connection: kept, and a new generation for it.
	waitFor(t, "the address and a state with it", func() bool {
		got := p.node(n.ID)
		return slices.Equal(got.PanelAddrs, []string{"198.51.100.30"}) && got.DesiredGeneration == 1 && slices.Contains(b.generations(), 1)
	})

	// The node sees the panel come over IPv6 too: both are kept.
	f.setInfo(info("2001:db8::30"))

	waitFor(t, "the IPv6 address and another generation", func() bool {
		got := p.node(n.ID)
		return slices.Equal(got.PanelAddrs, []string{"198.51.100.30", "2001:db8::30"}) && got.DesiredGeneration == 2
	})

	// An address that is not unicast changes nothing, and bumps nothing.
	f.setInfo(info("ff02::1"))
	p.bump(n.ID, 1) // generation 3, so that the manager looks at the node again
	m.Notify(n.ID)
	waitFor(t, "generation 3 at the node", func() bool { return slices.Contains(b.generations(), 3) })
	if got := p.node(n.ID); !slices.Equal(got.PanelAddrs, []string{"198.51.100.30", "2001:db8::30"}) || got.DesiredGeneration != 3 {
		t.Errorf("after a multicast peer: panel addrs %q, generation %d; want them as they were, 3", got.PanelAddrs, got.DesiredGeneration)
	}
}

func TestManagerWatchesWithThePolicyOfThePanel(t *testing.T) {
	for _, tc := range []struct {
		policy string // "" stores none: the default
		want   nodev1.IpPolicy
	}{
		{"", nodev1.IpPolicy_IP_POLICY_COUNTRIES},
		{store.IPPolicyFull, nodev1.IpPolicy_IP_POLICY_FULL},
		{store.IPPolicyOff, nodev1.IpPolicy_IP_POLICY_OFF},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			p := newTestPanel(t)
			if tc.policy != "" {
				s := store.DefaultStatsSettings()
				s.IPPolicy = tc.policy
				if _, err := p.db.ApplyStatsSettings(context.Background(), s); err != nil {
					t.Fatal(err)
				}
			}
			f := newFakeNode(t, nil)
			n := p.addNode("edge-1", f)
			m := p.newManager()
			m.Start(context.Background())
			p.waitStatus(n.ID, store.NodeStatusOnline)
			waitFor(t, "a Watch", func() bool {
				f.mu.Lock()
				defer f.mu.Unlock()
				return len(f.policies) > 0
			})
			f.mu.Lock()
			got := f.policies[0]
			f.mu.Unlock()
			if got != tc.want {
				t.Errorf("WatchRequest.ip_policy = %v, want %v", got, tc.want)
			}
		})
	}
}

// ensurerFunc is an ArtifactEnsurer of a function.
type ensurerFunc func() error

func (f ensurerFunc) EnsureArtifacts(context.Context, string, *nodev1.GetInfoResponse, *nodev1.NodeState, nodev1connect.NodeServiceClient) error {
	return f()
}

func TestMultiEnsurerRunsEachAndJoinsTheErrors(t *testing.T) {
	a, b := errors.New("a failed"), errors.New("b failed")
	var ran []string
	mk := func(name string, err error) ArtifactEnsurer {
		return ensurerFunc(func() error { ran = append(ran, name); return err })
	}
	err := MultiEnsurer(mk("1", a), nil, mk("2", nil), mk("3", b)).EnsureArtifacts(context.Background(), "n", nil, nil, nil)
	if !errors.Is(err, a) || !errors.Is(err, b) {
		t.Errorf("err = %v, want both errors", err)
	}
	if !slices.Equal(ran, []string{"1", "2", "3"}) {
		t.Errorf("ran %q, want every one in order, also after a failure", ran)
	}
	if err := MultiEnsurer(mk("4", nil)).EnsureArtifacts(context.Background(), "n", nil, nil, nil); err != nil {
		t.Errorf("no failure: %v", err)
	}
}

// A Watch that was opened under one IP policy filters by it on the node: a
// node watched under countries never sends a client address. So when the
// panel's policy changes, the manager opens the Watch again with the new one,
// once the change pokes it.
func TestManagerWatchesAgainWhenThePolicyChanges(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	m := p.newManager()
	b := &fakeBuilder{}
	m.SetStateBuilder(b)
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)
	policies := func() []nodev1.IpPolicy {
		f.mu.Lock()
		defer f.mu.Unlock()
		return slices.Clone(f.policies)
	}
	waitFor(t, "a Watch", func() bool { return len(policies()) > 0 })

	s := store.DefaultStatsSettings()
	s.IPPolicy = store.IPPolicyFull
	if _, err := p.db.ApplyStatsSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	p.bump(n.ID, 1)
	m.Notify(n.ID)
	waitFor(t, "a Watch under the policy full", func() bool {
		got := policies()
		return got[len(got)-1] == nodev1.IpPolicy_IP_POLICY_FULL
	})
	if got := policies(); got[0] != nodev1.IpPolicy_IP_POLICY_COUNTRIES {
		t.Errorf("the first Watch had the policy %v, want countries", got[0])
	}

	// A poke without a change of the policy opens no new Watch.
	before := len(policies())
	gen := p.bump(n.ID, 1)
	m.Notify(n.ID)
	waitFor(t, "the next generation at the node", func() bool { return slices.Contains(b.generations(), gen) })
	if got := policies(); len(got) != before {
		t.Errorf("a poke without a change of the policy opened %d more Watches", len(got)-before)
	}
}
