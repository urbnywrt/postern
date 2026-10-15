package diagnostics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func findProblem(ps []*panelv1.Problem, kind, checkID string) *panelv1.Problem {
	for _, p := range ps {
		if p.Kind == kind && p.CheckId == checkID {
			return p
		}
	}
	return nil
}

// Every problem has a key of its own, which stays the same across refreshes.
func TestProblemKeysAreStableAndDistinct(t *testing.T) {
	f := newFeedFixture(t)
	first, err := f.feed.List(f.e.ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range first {
		if p.Key == "" || seen[p.Key] {
			t.Errorf("%s %s: key %q empty or twice", p.Kind, p.CheckId, p.Key)
		}
		seen[p.Key] = true
	}
	f.e.now = f.e.now.Add(time.Minute)
	again, err := f.feed.List(f.e.ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range again {
		if !seen[p.Key] {
			t.Errorf("%s %s: key %q is new on a refresh", p.Kind, p.CheckId, p.Key)
		}
	}
	if k := findProblem(first, KindCheck, "engine.container").Key; !strings.Contains(k, f.alpha.ID) || !strings.Contains(k, "proxy:"+f.p1.ID) {
		t.Errorf("key of a check = %q, want its node and target", k)
	}
}

// A hidden problem stays hidden while it is the same; a change of its summary
// or its status shows it again and deletes the hide, and so does its clearing.
func TestHiddenProblemComesBackWhenItChanges(t *testing.T) {
	f := newFeedFixture(t)
	ctx := f.e.ctx
	all, err := f.feed.List(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	dns := findProblem(all, KindCheck, "host.dns")
	engine := findProblem(all, KindCheck, "engine.container")
	for _, p := range []*panelv1.Problem{dns, engine} {
		if _, err := f.feed.Hide(ctx, p.Key, "adm"); err != nil {
			t.Fatalf("Hide %s: %v", p.CheckId, err)
		}
	}
	if _, err := f.feed.Hide(ctx, "check|nope||", "adm"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Hide of no problem = %v, want not found", err)
	}

	visible, err := f.feed.Visible(ctx, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != len(all)-2 || findProblem(visible, KindCheck, "host.dns") != nil {
		t.Errorf("visible = %d problems, want %d without the hidden ones", len(visible), len(all)-2)
	}
	withHidden, err := f.feed.Visible(ctx, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if p := findProblem(withHidden, KindCheck, "host.dns"); p == nil || !p.Hidden || p.HiddenAtUnix != f.e.now.Unix() {
		t.Errorf("host.dns with include_hidden = %+v, want it marked hidden", p)
	}
	if p := findProblem(withHidden, KindNodeOffline, ""); p == nil || p.Hidden {
		t.Errorf("node.offline = %+v, want it not hidden", p)
	}

	// host.dns: its summary changes; engine.container: its status, warn to
	// fail, with the same summary.
	checks := []store.NodeCheck{
		{CheckID: "host.dns", Layer: "host", Status: StatusFail, Summary: "the resolver is gone", Fix: "set_dns_mode_doh"},
		{CheckID: "engine.container", Layer: "engine", Target: "proxy:" + f.p1.ID, Status: StatusFail, Summary: "the container restarted"},
	}
	if _, err := f.e.db.ReplaceNodeChecks(ctx, f.alpha.ID, checks, f.e.now); err != nil {
		t.Fatal(err)
	}
	visible, err = f.feed.Visible(ctx, f.alpha.ID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if findProblem(visible, KindCheck, "host.dns") == nil || findProblem(visible, KindCheck, "engine.container") == nil {
		t.Errorf("changed problems are not shown again: %d problems", len(visible))
	}
	if held, _ := f.e.db.SettleProblemHides(ctx, nil, false); len(held) != 0 {
		t.Errorf("hides of changed problems are left: %v", held)
	}

	// Hide host.dns again; it clears; when it comes back it shows.
	if _, err := f.feed.Hide(ctx, dns.Key, "adm"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.db.ReplaceNodeChecks(ctx, f.alpha.ID, checks[1:], f.e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.feed.Visible(ctx, "", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.db.ReplaceNodeChecks(ctx, f.alpha.ID, checks, f.e.now); err != nil {
		t.Fatal(err)
	}
	visible, err = f.feed.Visible(ctx, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if findProblem(visible, KindCheck, "host.dns") == nil {
		t.Errorf("a problem that cleared and came back is still hidden")
	}
}

func TestHideProblemAPI(t *testing.T) {
	f := newFeedFixture(t)
	ctx := f.e.ctx
	a := newAPIFor(t, f.e, NewService(f.e.db, nil, nil, WithFeed(f.feed)))
	res, err := a.admin.ListProblems(ctx, connect.NewRequest(&panelv1.ListProblemsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	total := len(res.Msg.GetProblems())
	key := findProblem(res.Msg.GetProblems(), KindNodeOffline, "").GetKey()

	if _, err := a.anon.HideProblem(ctx, connect.NewRequest(&panelv1.HideProblemRequest{Key: key})); codeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("anonymous hide: %v", err)
	}
	if _, err := a.anon.UnhideProblem(ctx, connect.NewRequest(&panelv1.UnhideProblemRequest{Key: key})); codeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("anonymous unhide: %v", err)
	}
	for _, k := range []string{"", strings.Repeat("k", maxProblemKey+1)} {
		if _, err := a.admin.HideProblem(ctx, connect.NewRequest(&panelv1.HideProblemRequest{Key: k})); codeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("hide key of %d bytes: %v", len(k), err)
		}
	}
	if _, err := a.admin.HideProblem(ctx, connect.NewRequest(&panelv1.HideProblemRequest{Key: "node|x|node.offline|"})); codeOf(err) != connect.CodeNotFound {
		t.Errorf("hide of no problem: %v", err)
	}
	if n := auditCount(t, f.e, "problem.hide"); n != 0 {
		t.Errorf("refused hides were audited: %d", n)
	}

	if _, err := a.admin.HideProblem(ctx, connect.NewRequest(&panelv1.HideProblemRequest{Key: key})); err != nil {
		t.Fatalf("HideProblem: %v", err)
	}
	if n := auditCount(t, f.e, "problem.hide"); n != 1 {
		t.Errorf("problem.hide audited %d times, want 1", n)
	}
	res, err = a.admin.ListProblems(ctx, connect.NewRequest(&panelv1.ListProblemsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Msg.GetProblems()) != total-1 || findProblem(res.Msg.GetProblems(), KindNodeOffline, "") != nil {
		t.Errorf("after the hide: %d problems, want %d", len(res.Msg.GetProblems()), total-1)
	}
	res, err = a.admin.ListProblems(ctx, connect.NewRequest(&panelv1.ListProblemsRequest{IncludeHidden: true}))
	if err != nil {
		t.Fatal(err)
	}
	if p := findProblem(res.Msg.GetProblems(), KindNodeOffline, ""); len(res.Msg.GetProblems()) != total || p == nil || !p.GetHidden() {
		t.Errorf("include_hidden: %d problems, node.offline %v", len(res.Msg.GetProblems()), p)
	}

	if _, err := a.admin.UnhideProblem(ctx, connect.NewRequest(&panelv1.UnhideProblemRequest{Key: key})); err != nil {
		t.Fatalf("UnhideProblem: %v", err)
	}
	// Twice is no error, and audited once.
	if _, err := a.admin.UnhideProblem(ctx, connect.NewRequest(&panelv1.UnhideProblemRequest{Key: key})); err != nil {
		t.Fatalf("UnhideProblem twice: %v", err)
	}
	if n := auditCount(t, f.e, "problem.unhide"); n != 1 {
		t.Errorf("problem.unhide audited %d times, want 1", n)
	}
	res, err = a.admin.ListProblems(ctx, connect.NewRequest(&panelv1.ListProblemsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Msg.GetProblems()) != total {
		t.Errorf("after the unhide: %d problems, want %d", len(res.Msg.GetProblems()), total)
	}
}

// The kinds whose summary ends with an error text that changes from one
// report to the next are compared by their severity, kind and lead-in only;
// the others by their whole summary.
func TestProblemFingerprintIgnoresChangingErrorText(t *testing.T) {
	fp := func(severity, kind, summary string) string {
		return problemFingerprint(&panelv1.Problem{Severity: severity, Kind: kind, Summary: summary})
	}
	for _, kind := range []string{KindProxyDown, KindProxyFailed, KindNodeError, KindNodeLastError, KindNodeStateRejected} {
		a := fp(SeverityError, kind, "the lead-in: timeout after 5s")
		if b := fp(SeverityError, kind, "the lead-in: refused by <ip>:443"); a != b {
			t.Errorf("%s: a new error text changes the fingerprint", kind)
		}
		if b := fp(SeverityWarning, kind, "the lead-in: timeout after 5s"); a == b {
			t.Errorf("%s: a new severity keeps the fingerprint", kind)
		}
		if b := fp(SeverityError, kind, "another lead-in: timeout after 5s"); a == b {
			t.Errorf("%s: a new lead-in keeps the fingerprint", kind)
		}
	}
	if fp(SeverityError, KindProxyDown, "x: y") == fp(SeverityError, KindProxyFailed, "x: y") {
		t.Errorf("two kinds with the same text share a fingerprint")
	}
	for _, kind := range []string{KindCheck, KindEdgeOutdated} {
		if fp(SeverityWarning, kind, "the edge runs: 1.1.0") == fp(SeverityWarning, kind, "the edge runs: 1.2.0") {
			t.Errorf("%s: a change of the whole summary keeps the fingerprint", kind)
		}
	}
}

// A hidden proxy.down stays hidden while only the error of its newest probe
// changes.
func TestHiddenProxyDownStaysHiddenWhenOnlyItsErrorChanges(t *testing.T) {
	f := newFeedFixture(t)
	ctx := f.e.ctx
	all, err := f.feed.List(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	down := findProblem(all, KindProxyDown, "")
	if _, err := f.feed.Hide(ctx, down.Key, "adm"); err != nil {
		t.Fatal(err)
	}
	f.feed.OnProbe(store.Probe{ProxyID: f.p2.ID, Vantage: VantagePanel, Error: "i/o timeout after 10s", TS: f.e.now})
	visible, err := f.feed.Visible(ctx, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	p := findProblem(visible, KindProxyDown, "")
	if p == nil || !p.Hidden || !strings.Contains(p.Summary, "i/o timeout after 10s") {
		t.Errorf("proxy.down after a new probe error = %+v, want it hidden with the new error", p)
	}
}
