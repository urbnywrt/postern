package proxies

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// testGeoIPRef is the country database of the state builder tests.
var testGeoIPRef = &nodev1.GeoIPRef{Month: "2026-10", Sha256: strings.Repeat("ab", 32)}

// insightsNode is the golden node with the statistics of slice 6 set: the
// capabilities given, the addresses the node saw the panel come from, an edge
// roll nonce, and a restart nonce on P1.
func (e *env) insightsNode(caps ...string) *store.Node {
	e.t.Helper()
	n := e.goldenNode("amd64")
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error {
		n.HostInfo.Capabilities = caps
		n.PanelAddrs = []string{"198.51.100.20", "2001:db8::20"}
		n.EdgeRollNonce = 4
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	e.exec(`UPDATE proxies SET restart_nonce = 7 WHERE id = ?`, goldenP1)
	return n
}

// applyStats stores statistics settings.
func (e *env) applyStats(policy string, ipDays uint32, extra ...string) {
	e.t.Helper()
	s := store.DefaultStatsSettings()
	s.IPPolicy, s.IPDays, s.ExtraProbeSources = policy, ipDays, extra
	if _, err := e.db.ApplyStatsSettings(e.ctx, s); err != nil {
		e.t.Fatal(err)
	}
}

func TestStateBuilderGoldenInsights(t *testing.T) {
	e := newEnv(t)
	n := e.insightsNode("faketls", capStatsV2)
	e.applyStats(store.IPPolicyFull, 3, "203.0.113.50", "198.51.100.20")
	e.builder.SetGeoIP(GeoIP{Ref: func() *nodev1.GeoIPRef { return testGeoIPRef }})

	st, err := e.builder.Build(e.ctx, n.ID, 3)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	redacted := proto.Clone(st).(*nodev1.NodeState)
	for _, p := range redacted.GetProxies() {
		p.Secret = "<secret of " + p.GetId() + ">"
	}
	got := goldenJSON(t, redacted)
	path := filepath.Join("testdata", "state_insights.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the golden file (run with -update to write it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the state differs from %s (run with -update to accept a change):\ngot:\n%s", path, got)
	}

	// What the golden file holds, said once more in code.
	set := st.GetSettings()
	if set.GetIpPolicy() != nodev1.IpPolicy_IP_POLICY_FULL || set.GetIpRetentionHours() != 72 {
		t.Errorf("policy %v, retention %d h; want full, 72 h", set.GetIpPolicy(), set.GetIpRetentionHours())
	}
	if !proto.Equal(set.GetGeoip(), testGeoIPRef) {
		t.Errorf("geoip = %v, want %v", set.GetGeoip(), testGeoIPRef)
	}
	if want := []string{"198.51.100.20", "2001:db8::20", "203.0.113.50"}; !slices.Equal(set.GetProbeSources(), want) {
		t.Errorf("probe sources = %q, want %q (the panel's, then the extra ones, each once)", set.GetProbeSources(), want)
	}
	if set.GetEdgeRollNonce() != 4 || st.GetProxies()[0].GetRestartNonce() != 7 || st.GetProxies()[1].GetRestartNonce() != 0 {
		t.Errorf("nonces: edge %d, proxies %d %d; want 4, 7, 0", set.GetEdgeRollNonce(), st.GetProxies()[0].GetRestartNonce(), st.GetProxies()[1].GetRestartNonce())
	}
	if err := validateState(st); err != nil {
		t.Errorf("validateState: %v", err)
	}
}

// The country database goes only to a node that takes it, and only while the
// policy uses countries; the default policy is countries, with 7 days.
func TestStateBuilderGeoIPOnlyForStatsV2(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  string // "" leaves the defaults
		caps    []string
		ref     *nodev1.GeoIPRef
		want    nodev1.IpPolicy
		wantRef bool
	}{
		{"defaults, stats-v2", "", []string{capStatsV2}, testGeoIPRef, nodev1.IpPolicy_IP_POLICY_COUNTRIES, true},
		{"full, stats-v2", store.IPPolicyFull, []string{capStatsV2}, testGeoIPRef, nodev1.IpPolicy_IP_POLICY_FULL, true},
		{"countries, without stats-v2", store.IPPolicyCountries, []string{"faketls"}, testGeoIPRef, nodev1.IpPolicy_IP_POLICY_COUNTRIES, false},
		{"off, stats-v2", store.IPPolicyOff, []string{capStatsV2}, testGeoIPRef, nodev1.IpPolicy_IP_POLICY_OFF, false},
		{"countries, no database", store.IPPolicyCountries, []string{capStatsV2}, nil, nodev1.IpPolicy_IP_POLICY_COUNTRIES, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := e.insightsNode(tc.caps...)
			if tc.policy != "" {
				e.applyStats(tc.policy, 7)
			}
			e.builder.SetGeoIP(GeoIP{Ref: func() *nodev1.GeoIPRef { return tc.ref }})
			st, err := e.builder.Build(e.ctx, n.ID, 1)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			set := st.GetSettings()
			if set.GetIpPolicy() != tc.want || set.GetIpRetentionHours() != 168 {
				t.Errorf("policy %v, retention %d; want %v, 168", set.GetIpPolicy(), set.GetIpRetentionHours(), tc.want)
			}
			if got := set.GetGeoip() != nil; got != tc.wantRef {
				t.Errorf("geoip named: %v, want %v", got, tc.wantRef)
			}
		})
	}
}
