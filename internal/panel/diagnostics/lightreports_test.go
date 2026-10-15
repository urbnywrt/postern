package diagnostics

import (
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

func report(rs ...*nodev1.DiagnosticResult) *nodev1.DiagnosticsReport {
	return &nodev1.DiagnosticsReport{Results: rs}
}

func TestLightReportsReplaceAndRecordTransitions(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	now := time.Unix(1_790_000_000, 0)
	l := NewLights(e.db, nil, func() time.Time { return now })
	step := func(d time.Duration, rep *nodev1.DiagnosticsReport) {
		t.Helper()
		now = now.Add(d)
		if err := l.OnDiagnostics(e.ctx, n.ID, now, rep); err != nil {
			t.Fatal(err)
		}
	}
	kinds := func() []string {
		var out []string
		for _, k := range []string{"check.failed", "check.warning", "check.recovered"} {
			for range events(t, e.db, k) {
				out = append(out, k)
			}
		}
		return out
	}
	t0 := now
	step(0, report(nodeResult("host.docker", "", ok, "dropped"), nodeResult("ingress.bound", "listener:L1", fail, "kept"),
		nodeResult("e2e.l1", "proxy:p1", ok, "")))
	if got := kinds(); len(got) != 1 || got[0] != "check.failed" {
		t.Fatalf("events after the first report: %v (an ok check that is new is no event)", got)
	}
	failed := events(t, e.db, "check.failed")[0]
	if failed.Severity != "error" || !strings.Contains(failed.Message, "ingress.bound (listener:L1)") || failed.Details["to"] != "fail" {
		t.Fatalf("event %+v", failed)
	}
	checks, _ := e.db.NodeChecks(e.ctx, n.ID)
	if len(checks) != 3 || checks[0].CheckID != "e2e.l1" || checks[1].Evidence != "" || checks[2].Evidence != "kept" {
		t.Fatalf("checks %+v", checks)
	}

	// Recovered within 10 minutes: the rate limit keeps it quiet; the proxy
	// check warns: an event of its own.
	step(2*time.Minute, report(nodeResult("host.docker", "", ok, ""), nodeResult("ingress.bound", "listener:L1", ok, ""),
		nodeResult("e2e.l1", "proxy:p1", warn, "slow")))
	if got := kinds(); len(got) != 2 || got[1] != "check.warning" {
		t.Fatalf("events: %v", got)
	}
	if w := events(t, e.db, "check.warning")[0]; w.ProxyID != "p1" || w.Severity != "warning" {
		t.Fatalf("warning %+v", w)
	}
	checks, _ = e.db.NodeChecks(e.ctx, n.ID)
	for _, c := range checks {
		if c.CheckID == "host.docker" && !c.Since.Equal(t0) {
			t.Fatalf("an unchanged status lost its since: %+v", c)
		}
		if c.CheckID == "ingress.bound" && !c.Since.Equal(now) {
			t.Fatalf("a changed status kept its since: %+v", c)
		}
	}

	// After 10 minutes it may tell again.
	step(10*time.Minute, report(nodeResult("ingress.bound", "listener:L1", fail, ""), nodeResult("e2e.l1", "proxy:p1", ok, "")))
	if got := kinds(); len(got) != 4 || got[1] != "check.failed" || got[3] != "check.recovered" {
		t.Fatalf("events: %v", got)
	}
	checks, _ = e.db.NodeChecks(e.ctx, n.ID)
	if len(checks) != 2 {
		t.Fatalf("a check that the node no longer reports stays: %+v", checks)
	}
	// A report that changes nothing records nothing.
	step(30*time.Minute, report(nodeResult("ingress.bound", "listener:L1", fail, ""), nodeResult("e2e.l1", "proxy:p1", ok, "")))
	if got := kinds(); len(got) != 4 {
		t.Fatalf("events: %v", got)
	}
}

func TestLightReportEvidenceLimit(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	var rs []*nodev1.DiagnosticResult
	for i := range 40 {
		rs = append(rs, nodeResult("x.fail", "proxy:"+string(rune('a'+i)), fail, strings.Repeat("e", 3000)))
	}
	if err := NewLights(e.db, nil, nil).OnDiagnostics(e.ctx, n.ID, time.Now(), report(rs...)); err != nil {
		t.Fatal(err)
	}
	checks, _ := e.db.NodeChecks(e.ctx, n.ID)
	total := 0
	for _, c := range checks {
		if len(c.Evidence) > maxEvidence {
			t.Fatalf("evidence %d", len(c.Evidence))
		}
		total += len(c.Evidence)
	}
	if len(checks) != 40 || total > maxRunEvidence {
		t.Fatalf("%d checks, evidence %d", len(checks), total)
	}
}

func TestFixAvailable(t *testing.T) {
	all := []string{"restart-nonce", "edge-roll-nonce", "egress-xray", "dns-forwarder", "web-diagnostics"}
	for _, c := range []struct {
		fix, target string
		caps        []string
		want        bool
		why         string
	}{
		{"", "", all, false, ""},
		{"recreate_instance", "proxy:p1", all, true, ""},
		{"recreate_instance", "proxy:p1", nil, false, "restart-nonce"},
		{"recreate_instance", "", all, false, "does not apply"},
		{"recreate_instance", "proxy:", all, false, "does not apply"},
		{"roll_edge", "", all, true, ""},
		{"roll_edge", "proxy:p1", all, false, "applies to the node"},
		{"roll_edge", "", []string{"restart-nonce"}, false, "edge-roll-nonce"},
		{"change_egress", "proxy:p1", nil, true, ""},
		{"change_egress", "member:C/a", nil, false, "does not apply"},
		{"refresh_subscription", "member:C/s/a", all, true, ""},
		{"refresh_subscription", "member:C/s/a", nil, false, "egress-xray"},
		{"set_dns_mode_doh", "", all, true, ""},
		{"set_dns_mode_doh", "", nil, false, "dns-forwarder"},
		{"reissue_cert", "proxy:p1", nil, false, "web-diagnostics"},
		{"rm_rf", "", all, false, "does not know"},
	} {
		got, why := FixAvailable(c.fix, c.target, c.caps)
		if got != c.want || !strings.Contains(why, c.why) || (c.why == "" && why != "") {
			t.Errorf("FixAvailable(%q, %q, %v) = %v %q", c.fix, c.target, c.caps, got, why)
		}
	}
}
