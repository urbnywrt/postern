package insights

import (
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// defaults is the API form of the default settings.
var defaults = &panelv1.StatsSettings{MinutesHours: 48, HoursDays: 90, IpDays: 7, IpPolicy: "countries", ProbeIntervalMinutes: 5}

func (e *env) update(s *panelv1.StatsSettings) (*panelv1.GetStatsSettingsResponse, error) {
	resp, err := e.api.UpdateStatsSettings(e.ctx, connect.NewRequest(&panelv1.UpdateStatsSettingsRequest{Settings: s}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func TestEnsureDefaultsBumpsOnceAndOnlyOnce(t *testing.T) {
	e := newEnv(t)
	a, b := e.node("a", nil), e.node("b", []string{CapStatsV2})
	if _, stored, _ := e.db.StatsSettings(e.ctx); stored {
		t.Fatal("a new panel has the policy stored")
	}
	if err := e.svc.EnsureDefaults(e.ctx); err != nil {
		t.Fatalf("EnsureDefaults: %v", err)
	}
	s, stored, err := e.db.StatsSettings(e.ctx)
	if err != nil || !stored || s.IPPolicy != store.IPPolicyCountries {
		t.Fatalf("after EnsureDefaults: %+v, stored %v, %v", s, stored, err)
	}
	if got := e.notes.take(); !slices.Equal(got, slices.Sorted(slices.Values([]string{a.ID, b.ID}))) {
		t.Errorf("notified %q, want both nodes", got)
	}
	if e.generation(a.ID) != 1 || e.generation(b.ID) != 1 {
		t.Errorf("generations %d %d, want 1 1", e.generation(a.ID), e.generation(b.ID))
	}
	// The next start: nothing.
	if err := e.svc.EnsureDefaults(e.ctx); err != nil {
		t.Fatalf("EnsureDefaults again: %v", err)
	}
	if got := e.notes.take(); len(got) != 0 || e.generation(a.ID) != 1 {
		t.Errorf("the second start notified %q and moved the generation to %d", got, e.generation(a.ID))
	}
}

func TestSettingsNeedAnAdmin(t *testing.T) {
	e := newEnv(t)
	if _, err := e.anon.GetStatsSettings(e.ctx, connect.NewRequest(&panelv1.GetStatsSettingsRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("GetStatsSettings: %v", err)
	}
	if _, err := e.anon.UpdateStatsSettings(e.ctx, connect.NewRequest(&panelv1.UpdateStatsSettingsRequest{Settings: defaults})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("UpdateStatsSettings: %v", err)
	}
	if _, err := e.anon.GetStorage(e.ctx, connect.NewRequest(&panelv1.GetStorageRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("GetStorage: %v", err)
	}
}

func TestUpdateStatsSettingsValidates(t *testing.T) {
	e := newEnv(t)
	n := e.node("a", nil)
	for name, mod := range map[string]func(*panelv1.StatsSettings){
		"a prefix":          func(s *panelv1.StatsSettings) { s.ExtraProbeSources = []string{"198.51.100.0/24"} },
		"not an address":    func(s *panelv1.StatsSettings) { s.ExtraProbeSources = []string{"probe.example.com"} },
		"17 sources":        func(s *panelv1.StatsSettings) { s.ExtraProbeSources = slices.Repeat([]string{"192.0.2.1"}, 17) },
		"an unknown policy": func(s *panelv1.StatsSettings) { s.IpPolicy = "some" },
		"minutes for 2 h":   func(s *panelv1.StatsSettings) { s.MinutesHours = 2 },
		"addresses 31 days": func(s *panelv1.StatsSettings) { s.IpDays = 31 },
	} {
		s := proto.Clone(defaults).(*panelv1.StatsSettings)
		mod(s)
		if _, err := e.update(s); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want invalid argument", name, err)
		}
	}
	if _, err := e.update(nil); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("no settings: %v", err)
	}
	if _, stored, _ := e.db.StatsSettings(e.ctx); stored {
		t.Error("a refused update stored settings")
	}
	if got := e.notes.take(); len(got) != 0 || e.generation(n.ID) != 0 {
		t.Errorf("a refused update bumped %q", got)
	}
}

func TestUpdateStatsSettingsStoresAuditsAndBumps(t *testing.T) {
	e := newEnv(t)
	a := e.node("a", nil, "198.51.100.40", "2001:db8::40")
	b := e.node("b", nil, "10.1.2.3", "fd00::1")
	c := e.node("c", nil, "100.64.0.9", "fe80::1")
	all := slices.Sorted(slices.Values([]string{a.ID, b.ID, c.ID}))

	// Full, with an extra source written in another form: kept in the usual one.
	full := proto.Clone(defaults).(*panelv1.StatsSettings)
	full.IpPolicy, full.ExtraProbeSources, full.MinutesHours = "full", []string{"2001:DB8::99", "::ffff:192.0.2.5", "192.0.2.5"}, 24
	resp, err := e.update(full)
	if err != nil {
		t.Fatalf("UpdateStatsSettings: %v", err)
	}
	wantSettings := proto.Clone(full).(*panelv1.StatsSettings)
	wantSettings.ExtraProbeSources = []string{"2001:db8::99", "192.0.2.5"}
	if !proto.Equal(resp.GetSettings(), wantSettings) {
		t.Errorf("settings = %v, want %v", resp.GetSettings(), wantSettings)
	}
	if got := e.notes.take(); !slices.Equal(got, all) {
		t.Errorf("notified %q, want every node", got)
	}
	var audit string
	e.query(&audit, `SELECT action || ' ' || target || ' ' || admin_id || ' ' || details FROM audit_log WHERE action NOT LIKE 'auth.%'`) // not the sign-in of the test
	if !strings.HasPrefix(audit, "settings.update settings:stats "+e.admin) || !strings.Contains(audit, `"ip_policy":"full"`) {
		t.Errorf("audit = %q", audit)
	}

	// The panel's addresses, with the shared ones flagged.
	shared := map[string]bool{}
	for _, pa := range resp.GetPanelAddresses() {
		shared[pa.GetAddr()] = pa.GetShared()
	}
	want := map[string]bool{"198.51.100.40": false, "2001:db8::40": false, "10.1.2.3": true, "fd00::1": true, "100.64.0.9": true, "fe80::1": true}
	if len(shared) != len(want) {
		t.Errorf("panel addresses %v, want %v", shared, want)
	}
	for addr, w := range want {
		if got, ok := shared[addr]; !ok || got != w {
			t.Errorf("%s: shared %v (listed %v), want %v", addr, got, ok, w)
		}
	}

	// A change of the retention of minutes only: no node is concerned.
	only := proto.Clone(wantSettings).(*panelv1.StatsSettings)
	only.MinutesHours, only.ProbeIntervalMinutes = 72, 10
	if _, err := e.update(only); err != nil {
		t.Fatal(err)
	}
	if got := e.notes.take(); len(got) != 0 {
		t.Errorf("a change of what the nodes do not hold notified %q", got)
	}

	// A sighting, and leaving full: deleted in the same transaction.
	minute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	l := &store.Listener{NodeID: a.ID, BindIP: "0.0.0.0", Port: 443}
	if err := e.db.CreateListener(e.ctx, l); err != nil {
		t.Fatal(err)
	}
	p := &store.Proxy{NodeID: a.ID, ListenerID: l.ID, Name: "p", SecretEnc: []byte("x"), Domain: "cdn.example.com"}
	if err := e.db.CreateProxy(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.IngestMinute(e.ctx, store.MinuteBatch{NodeID: a.ID, Minute: minute,
		Sightings: []store.Sighting{{ProxyID: p.ID, IP: "192.0.2.77", FirstSeen: minute, LastSeen: minute, Bytes: 1}}}); err != nil {
		t.Fatal(err)
	}
	var n int
	e.query(&n, `SELECT count(*) FROM ip_sightings`)
	if n != 1 {
		t.Fatalf("sightings before = %d", n)
	}
	off := proto.Clone(only).(*panelv1.StatsSettings)
	off.IpPolicy = "countries"
	if _, err := e.update(off); err != nil {
		t.Fatal(err)
	}
	e.query(&n, `SELECT count(*) FROM ip_sightings`)
	if n != 0 {
		t.Errorf("sightings after leaving full = %d", n)
	}
	if got := e.notes.take(); !slices.Equal(got, all) {
		t.Errorf("a change of the policy notified %q, want every node", got)
	}
	// ip_days and the extra sources bump too.
	for name, mod := range map[string]func(*panelv1.StatsSettings){
		"ip_days": func(s *panelv1.StatsSettings) { s.IpDays = 3 },
		"sources": func(s *panelv1.StatsSettings) { s.ExtraProbeSources = []string{"192.0.2.6"} },
	} {
		mod(off)
		if _, err := e.update(off); err != nil {
			t.Fatal(err)
		}
		if got := e.notes.take(); !slices.Equal(got, all) {
			t.Errorf("%s: notified %q, want every node", name, got)
		}
	}

	got, err := e.api.GetStatsSettings(e.ctx, connect.NewRequest(&panelv1.GetStatsSettingsRequest{}))
	if err != nil || !proto.Equal(got.Msg.GetSettings(), off) {
		t.Errorf("GetStatsSettings = %v, %v; want %v", got.Msg.GetSettings(), err, off)
	}
	st, err := e.api.GetStorage(e.ctx, connect.NewRequest(&panelv1.GetStorageRequest{}))
	if err != nil || st.Msg.GetFileBytes() <= 0 || st.Msg.GetRows()["stats_proxy_1m"] != 0 || len(st.Msg.GetRows()) == 0 {
		t.Errorf("GetStorage = %v, %v", st.Msg, err)
	}
}

func TestGeoIPChangedBumpsStatsV2NodesWhileCountriesAreUsed(t *testing.T) {
	e := newEnv(t)
	old := e.node("old", []string{"faketls"})
	v2 := e.node("v2", []string{"faketls", CapStatsV2})
	_ = old
	e.svc.GeoIPChanged(e.ctx) // the default policy, countries
	if got := e.notes.take(); !slices.Equal(got, []string{v2.ID}) || e.generation(v2.ID) != 1 || e.generation(old.ID) != 0 {
		t.Errorf("notified %q; want only the stats-v2 node, with a new generation", got)
	}
	s := store.DefaultStatsSettings()
	s.IPPolicy = store.IPPolicyOff
	if _, err := e.db.ApplyStatsSettings(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	e.svc.GeoIPChanged(e.ctx)
	if got := e.notes.take(); len(got) != 0 {
		t.Errorf("under off: notified %q", got)
	}
}

func TestShared(t *testing.T) {
	for addr, want := range map[string]bool{
		"10.0.0.1": true, "172.16.5.4": true, "192.168.1.1": true, "fd12::1": true, "fe80::1": true, "169.254.1.1": true,
		"100.64.0.1": true, "100.127.255.254": true, "100.128.0.1": false, "::ffff:10.0.0.1": true,
		"198.51.100.1": false, "2001:db8::1": false, "bad": false,
	} {
		if got := Shared(addr); got != want {
			t.Errorf("Shared(%s) = %v, want %v", addr, got, want)
		}
	}
}
