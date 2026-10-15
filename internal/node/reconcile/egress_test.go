package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/psiphoncore"
	"github.com/urbnywrt/postern/internal/providers/xray"
)

// vlessID is the id of the VLESS servers of the tests.
const vlessID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// vless is the share link of a VLESS server on host:port named name.
func vless(host string, port int, name string) string {
	return fmt.Sprintf("vless://%s@%s:%d?type=tcp&security=none#%s", vlessID, host, port, name)
}

// keyOf is the member key of the server of a share link.
func keyOf(t *testing.T, link string) string {
	t.Helper()
	s, err := egressuri.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return s.Key()
}

func uriEgress(id, link string) *nodev1.Egress {
	return &nodev1.Egress{Id: id, Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_URI, ParamsJson: `{"uri":` + jsonString(link) + `}`}
}

// providerState is the base state with egresses that the proxy takes, as the
// chain "alt" in that order.
func (h *harness) providerState(gen uint64, egresses ...*nodev1.Egress) *nodev1.NodeState {
	st := h.baseState(gen)
	var ids []string
	for _, e := range egresses {
		st.Egresses = append(st.Egresses, e)
		ids = append(ids, e.GetId())
	}
	st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "alt", MemberEgressIds: ids})
	st.Proxies[0].EgressChainId = "alt"
	return st
}

// chainMembers is the members of a chain of a config, as "key=kind:addr".
func chainMembers(cfg *edgev1.EdgeConfig, id string) []string {
	var out []string
	for _, c := range cfg.GetChains() {
		if c.GetId() != id {
			continue
		}
		for _, m := range c.GetMembers() {
			out = append(out, m.GetKey()+"="+m.GetKind()+":"+m.GetAddr())
		}
	}
	return out
}

func (h *harness) egressDir(id string, gen uint64) string {
	return filepath.Join(h.paths.EgressDir(id), fmt.Sprintf("g%d", gen))
}

func (h *harness) xrayBinary() string {
	a := h.xrayArtifact
	return h.arts.BinaryPath(artifacts.Ref{Engine: a.Engine, Version: a.Version, Arch: a.Arch, SHA256: a.Sha256, FileName: a.FileName, Binary: a.Binary})
}

// An egress of a chain that an enabled proxy takes gets a provider instance:
// its files, its container as the driver describes it, a SOCKS port for its
// member, readiness, and then the member in the chains of the edge, before the
// engine that goes out through it starts. An egress that no chain in use takes
// gets none.
func TestProviderInstanceServesAChainInUse(t *testing.T) {
	h := newHarness(t)
	link := vless("vpn.example.com", 443, "a")
	key := keyOf(t, link)
	st := h.providerState(1, uriEgress("nl", link))
	st.Egresses = append(st.Egresses, uriEgress("idle", vless("idle.example.com", 443, "b")))
	st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "spare", MemberEgressIds: []string{"idle"}})
	h.apply(st)

	var chainAtEngine []string
	h.docker.onCreate = func(spec dockerapi.ContainerSpec) {
		if spec.Labels["postern.role"] == "engine" {
			chainAtEngine = chainMembers(h.lastSetConfig(), "alt")
		}
	}
	h.pass()

	c := h.container("postern-egr-nl-g1")
	if c == nil || c.State != "running" {
		t.Fatalf("egress container = %+v, want running", c)
	}
	if h.container("postern-egr-idle-g1") != nil {
		t.Error("an egress that no chain in use takes got an instance")
	}
	rt := h.runtime()
	rec := rt.Egresses["nl"]
	if rec.Generation != 1 || rec.Provider != "xray" || rec.Version != "v26.3.27" || rec.Hash == "" || len(rec.Members) != 1 {
		t.Fatalf("egress record = %+v", rec)
	}
	m := rec.Members[0]
	if m.Key != key || m.Port < providers.MinPort || m.Port > providers.MaxPort || rt.Ports[state.EgressPortKey("nl", 1, key)] != m.Port {
		t.Errorf("member = %+v, ports %v", m, rt.Ports)
	}
	if !rec.ServingSince.Equal(h.clock.Now()) {
		t.Errorf("serving since %v", rec.ServingSince)
	}

	// The container and the files, as the driver makes them.
	in := providers.Instance{
		EgressID: "nl", Generation: 1, Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_URI,
		Members:     []providers.Member{{Key: key, Port: m.Port}},
		InstanceDir: h.egressDir("nl", 1), BinaryPath: h.xrayBinary(), RunnerImage: runnerImage,
	}
	specs := h.creates("egress")
	if len(specs) != 1 || !specEqual(specs[0], xray.New().Container(in)) {
		t.Errorf("egress containers = %+v, want\n%+v", specs, xray.New().Container(in))
	}
	data, err := os.ReadFile(filepath.Join(in.InstanceDir, "config.json"))
	if err != nil || !strings.Contains(string(data), fmt.Sprintf(`"port": %d`, m.Port)) || !strings.Contains(string(data), "vpn.example.com") {
		t.Errorf("config.json = %s, %v", data, err)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{in.InstanceDir: 0o750, filepath.Join(in.InstanceDir, "config.json"): 0o640} {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
				t.Errorf("%s: %v, %v; want mode %v", path, info, err, want)
			}
		}
	}
	if ready := h.xray.readyCalls(); len(ready) == 0 || ready[0].Members[0].Port != m.Port {
		t.Errorf("Ready calls = %+v", ready)
	}

	// The chains of the edge.
	want := []string{"nl/" + key + "=socks5:" + addr(m.Port)}
	cfg := h.fakeEdge(1).lastConfig(t)
	if got := chainMembers(cfg, "alt"); !slices.Equal(got, want) {
		t.Errorf("chain alt = %v, want %v", got, want)
	}
	if got := chainMembers(cfg, "spare"); len(got) != 0 {
		t.Errorf("chain spare = %v, want no members: its egress has no instance", got)
	}
	if !slices.Equal(chainAtEngine, want) {
		t.Errorf("chain alt when the engine was created = %v, want %v", chainAtEngine, want)
	}
	var order []string
	for _, c := range h.docker.Calls() {
		if c.Method == "Create" {
			order = append(order, c.Spec.Labels["postern.role"])
		}
	}
	if !slices.Equal(order, []string{"edge", "egress", "engine"}) {
		t.Errorf("containers created %v, want the edge, the egress, then the engine", order)
	}
	for _, kind := range []string{"egress_starting", "egress_serving"} {
		evs := h.eventsOf(kind)
		if len(evs) != 1 || evs[0].GetDetails()["egress"] != "nl" || evs[0].GetDetails()["generation"] != "1" {
			t.Errorf("%s events = %v", kind, evs)
		}
	}
	assertNoEgressSecretsInEvents(t, h)

	// Another pass changes nothing.
	h.docker.ResetCalls()
	h.pass()
	for _, c := range h.docker.Calls() {
		if c.Method == "Create" || c.Method == "Remove" {
			t.Errorf("%s %s on a pass without changes", c.Method, c.Target)
		}
	}
}

// A change of what the instance runs makes a new generation beside the old
// one; once it is ready the edge takes its ports, and the old generation is
// removed two minutes later.
func TestProviderBlueGreen(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	h.pass()
	old := h.runtime().Egresses["nl"]

	link := vless("vpn.example.com", 8443, "a")
	h.apply(h.providerState(2, uriEgress("nl", link)))
	h.pass()

	if c := h.container("postern-egr-nl-g2"); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	g1 := h.container("postern-egr-nl-g1")
	if g1 == nil || g1.State != "running" || g1.RestartPolicy != "no" {
		t.Fatalf("g1 = %+v, want running with restart policy no", g1)
	}
	rec := h.runtime().Egresses["nl"]
	if rec.Generation != 2 || rec.Hash == old.Hash || len(rec.Members) != 1 || rec.Members[0].Key != keyOf(t, link) {
		t.Fatalf("record = %+v", rec)
	}
	if len(rec.Draining) != 1 || rec.Draining[0].Generation != 1 || !rec.Draining[0].Since.Equal(h.clock.Now()) {
		t.Errorf("draining = %+v", rec.Draining)
	}
	want := []string{"nl/" + rec.Members[0].Key + "=socks5:" + addr(rec.Members[0].Port)}
	if got := chainMembers(h.fakeEdge(1).lastConfig(t), "alt"); !slices.Equal(got, want) {
		t.Errorf("chain alt = %v, want the member of g2 only: %v", got, want)
	}
	if n := len(h.eventsOf("egress_draining")); n != 1 {
		t.Errorf("egress_draining events = %d", n)
	}

	h.clock.Advance(2*time.Minute - time.Second)
	h.pass()
	if h.container("postern-egr-nl-g1") == nil {
		t.Fatal("g1 removed before two minutes")
	}
	h.clock.Advance(time.Second)
	h.pass()
	if c := h.container("postern-egr-nl-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed after two minutes", c)
	}
	rt := h.runtime()
	if d := rt.Egresses["nl"].Draining; len(d) != 0 {
		t.Errorf("draining = %+v", d)
	}
	for k := range rt.Ports {
		if strings.HasPrefix(k, state.EgressPortPrefix("nl", 1)) {
			t.Errorf("port %s of g1 still allocated", k)
		}
	}
	if _, err := os.Stat(h.egressDir("nl", 1)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory of g1 is still there: %v", err)
	}
	if n := len(h.eventsOf("egress_removed")); n != 1 {
		t.Errorf("egress_removed events = %d", n)
	}
}

// A new generation that does not get ready is removed; the old one goes on, and
// the same configuration is not tried again for a while.
func TestProviderNotReadyKeepsTheOldGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	h.pass()
	old := h.runtime().Egresses["nl"]
	h.xray.setReady(func(context.Context, providers.Instance) error {
		return errors.New("member x (port 1): not accepting connections")
	})

	h.apply(h.providerState(2, uriEgress("nl", vless("vpn.example.com", 8443, "a"))))
	h.pass()
	if c := h.container("postern-egr-nl-g2"); c != nil {
		t.Errorf("g2 = %+v, want removed", c)
	}
	rec := h.runtime().Egresses["nl"]
	if rec.Generation != 1 || rec.Hash != old.Hash {
		t.Errorf("record = %+v, want g1 serving", rec)
	}
	if got := chainMembers(h.fakeEdge(1).lastConfig(t), "alt"); len(got) != 1 || !strings.HasSuffix(got[0], addr(old.Members[0].Port)) {
		t.Errorf("chain alt = %v, want g1's member", got)
	}
	evs := h.eventsOf("egress_failed")
	if len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "not ready") {
		t.Errorf("egress_failed events = %v", evs)
	}
	for k := range h.runtime().Ports {
		if strings.HasPrefix(k, state.EgressPortPrefix("nl", 2)) {
			t.Errorf("port %s of g2 still allocated", k)
		}
	}
	tries := len(h.xray.readyCalls())
	h.pass()
	if got := len(h.xray.readyCalls()); got != tries {
		t.Errorf("tried again at once (%d Ready calls, %d before)", got, tries)
	}
	h.xray.setReady(nil)
	h.clock.Advance(defaultRetryAfter)
	h.pass()
	if rec := h.runtime().Egresses["nl"]; rec.Generation != 3 {
		t.Errorf("after the retry delay: g%d, want g3", rec.Generation)
	}
}

// An egress that no chain in use takes any more drains, and is removed after
// two minutes; one that is not desired at all goes with everything it had.
func TestUnneededEgressDrains(t *testing.T) {
	h := newHarness(t)
	st := h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a")))
	h.apply(st)
	h.pass()

	st = h.providerState(2, uriEgress("nl", vless("vpn.example.com", 443, "a")))
	st.Proxies[0].EgressChainId = "" // the default chain: direct
	h.apply(st)
	h.pass()
	rec := h.runtime().Egresses["nl"]
	if rec.Generation != 0 || len(rec.Draining) != 1 {
		t.Fatalf("record = %+v, want g1 draining", rec)
	}
	if got := chainMembers(h.fakeEdge(1).lastConfig(t), "alt"); len(got) != 0 {
		t.Errorf("chain alt = %v, want no members", got)
	}
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if c := h.container("postern-egr-nl-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}

	// Needed again: a new generation.
	h.apply(h.providerState(3, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	h.pass()
	if rec := h.runtime().Egresses["nl"]; rec.Generation != 2 {
		t.Errorf("record = %+v, want g2", rec)
	}

	// Not desired at all: drained, then forgotten with its directory.
	st = h.baseState(4)
	h.apply(st)
	h.pass()
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if _, ok := h.runtime().Egresses["nl"]; ok {
		t.Error("the record of a deleted egress is still there")
	}
	if _, err := os.Stat(h.paths.EgressDir("nl")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory of a deleted egress is still there: %v", err)
	}
}

// A member that the provider cannot take is left out, and said so by its key
// and field; an egress that has no member left gets no instance.
func TestInvalidMemberIsLeftOut(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, uriEgress("nl", vless("127.0.0.1", 443, "loop"))))
	h.pass()
	if c := h.container("postern-egr-nl-g1"); c != nil {
		t.Errorf("an egress without a usable member got an instance: %+v", c)
	}
	evs := h.eventsOf("egress_member_invalid")
	if len(evs) != 1 || evs[0].GetDetails()["field"] != "address" || evs[0].GetDetails()["member"] == "" {
		t.Fatalf("egress_member_invalid events = %v", evs)
	}
	if strings.Contains(protoText(evs[0]), "127.0.0.1") || strings.Contains(protoText(evs[0]), vlessID) {
		t.Errorf("the event repeats the server: %v", evs[0])
	}
	if evs := h.eventsOf("egress_failed"); len(evs) != 1 {
		t.Errorf("egress_failed events = %v", evs)
	}
	// Reported once while it lasts.
	h.pass()
	if n := len(h.eventsOf("egress_member_invalid")); n != 1 {
		t.Errorf("egress_member_invalid events = %d after another pass", n)
	}
}

// Without the provider's binary on the node, the egress gets no instance and
// that is reported.
func TestProviderArtifactMissing(t *testing.T) {
	h := newHarness(t)
	st := h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a")))
	st.Artifacts = st.Artifacts[:1] // telemt only
	h.apply(st)
	h.pass()
	if c := h.container("postern-egr-nl-g1"); c != nil {
		t.Errorf("egress container without its binary: %+v", c)
	}
	evs := h.eventsOf("egress_failed")
	if len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "xray") {
		t.Errorf("egress_failed events = %v", evs)
	}
}

// The resolv.conf of the edge's forwarder is mounted in a provider's container
// while the edge says that the forwarder runs (Rulings S2-1, S2-8).
func TestProviderMountsTheResolvConfWhileTheForwarderRuns(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.apply(h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	h.pass()
	spec := h.creates("egress")[0]
	if !slices.Contains(spec.Binds, h.paths.ResolvConfPath()+":/etc/resolv.conf:ro") {
		t.Errorf("binds %q lack the resolv.conf", spec.Binds)
	}

	h2 := newHarness(t)
	st := h2.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a")))
	st.Settings.DnsMode = state.DNSModeSystem
	h2.apply(st)
	h2.pass()
	for _, b := range h2.creates("egress")[0].Binds {
		if strings.Contains(b, "resolv") {
			t.Errorf("DNS mode system: bind %q", b)
		}
	}
}

// A restarted agent adopts the provider containers of its record: a stopped
// one is started again, a missing one replaced, and one it does not know is
// removed.
func TestRestartAdoptsProviderContainers(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	h.pass()
	if err := h.docker.Stop(context.Background(), "postern-egr-nl-g1", time.Second); err != nil {
		t.Fatal(err)
	}
	h.addContainer("postern-egr-stray-g4", "egress", "stray", 4, true)

	h.r = h.newReconciler()
	h.pass()
	if c := h.container("postern-egr-nl-g1"); c == nil || c.State != "running" {
		t.Errorf("g1 = %+v, want started again", c)
	}
	if c := h.container("postern-egr-stray-g4"); c != nil {
		t.Errorf("unknown egress container = %+v, want removed", c)
	}
	if n := len(h.eventsOf("egress_restarted")); n != 1 {
		t.Errorf("egress_restarted events = %d", n)
	}

	if err := h.docker.Remove(context.Background(), "postern-egr-nl-g1", true); err != nil {
		t.Fatal(err)
	}
	h.r = h.newReconciler()
	h.pass()
	if rec := h.runtime().Egresses["nl"]; rec.Generation != 2 {
		t.Errorf("record = %+v, want g2 for the missing g1", rec)
	}
	if c := h.container("postern-egr-nl-g2"); c == nil || c.State != "running" {
		t.Errorf("g2 = %+v", c)
	}
}

// protoText is the text of a message, for a test to look into.
func protoText(m proto.Message) string { return fmt.Sprint(m) }

// assertNoEgressSecretsInEvents checks that no event holds the id of the VLESS
// servers of the tests, the WARP keys or a subscription token.
func assertNoEgressSecretsInEvents(t *testing.T, h *harness) {
	t.Helper()
	a := testWARPAccount()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ev := range h.events {
		text := protoText(ev)
		for _, s := range []string{vlessID, a.PrivateKey, a.Token, subToken} {
			if strings.Contains(text, s) {
				t.Errorf("event reveals a secret: %s", text)
			}
		}
	}
}

// A WARP egress gets its device registered once, its account kept where no
// container sees it (data/state/egress/<id>, 0700), and an Xray instance with
// the WireGuard member; when the egress is deleted and its last generation is
// gone, the device is deleted at Cloudflare and the account goes.
func TestWARPEgress(t *testing.T) {
	h := newHarness(t)
	st := h.providerState(1, &nodev1.Egress{Id: "cf", Kind: nodev1.EgressKind_EGRESS_KIND_WARP, ParamsJson: "{}"})
	h.apply(st)
	h.pass()

	acctPath := filepath.Join(h.paths.EgressStateDir("cf"), "warp-account.json")
	if len(h.warp.registered) == 0 || h.warp.registered[0] != acctPath {
		t.Fatalf("registrations = %v, want %s", h.warp.registered, acctPath)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(h.paths.EgressStateDir("cf")); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("account directory: %v, %v; want 0700", info, err)
		}
	}
	rec := h.runtime().Egresses["cf"]
	if rec.Generation != 1 || len(rec.Members) != 1 || rec.Members[0].Key != "warp" {
		t.Fatalf("record = %+v", rec)
	}
	data, err := os.ReadFile(filepath.Join(h.egressDir("cf", 1), "config.json"))
	if err != nil || !strings.Contains(string(data), `"protocol": "wireguard"`) {
		t.Errorf("config.json = %s, %v", data, err)
	}
	for _, b := range h.creates("egress")[0].Binds {
		if strings.Contains(b, h.paths.StateDir()) {
			t.Errorf("a container mounts the state directory: %s", b)
		}
	}
	if got := chainMembers(h.fakeEdge(1).lastConfig(t), "alt"); len(got) != 1 || !strings.HasPrefix(got[0], "cf/warp=socks5:") {
		t.Errorf("chain alt = %v", got)
	}
	assertNoEgressSecretsInEvents(t, h)

	// Another pass registers nothing: the account is in its file.
	h.pass()
	if len(h.warp.deleted) != 0 {
		t.Errorf("deleted %v", h.warp.deleted)
	}

	// Deleted: drained first, then the device and the account go.
	h.apply(h.baseState(2))
	h.pass()
	if len(h.warp.deleted) != 0 {
		t.Error("the device was deleted while its generation drains")
	}
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if !slices.Equal(h.warp.deleted, []string{testWARPAccount().ID}) {
		t.Errorf("deleted devices = %v", h.warp.deleted)
	}
	if _, err := os.Stat(h.paths.EgressStateDir("cf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the account directory is still there: %v", err)
	}
}

// The end of the agent cuts the deletion of the WARP device of a deleted
// egress short: its record and its account stay, and the agent deletes the
// device when it starts again.
func TestWARPDeletionCutShortIsTriedAgain(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, &nodev1.Egress{Id: "cf", Kind: nodev1.EgressKind_EGRESS_KIND_WARP, ParamsJson: "{}"}))
	h.pass()
	h.apply(h.baseState(2))
	h.pass()
	h.clock.Advance(2 * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.warp.setDeleteHook(func(dctx context.Context) error {
		cancel() // the agent stops
		select {
		case <-dctx.Done():
			return dctx.Err()
		case <-time.After(10 * time.Second):
			t.Error("the deletion of the device was not cut short with the agent")
			return errors.New("not cut short")
		}
	})
	if err := h.r.reconcileOnce(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("pass = %v, want it cut short", err)
	}
	if rec, ok := h.runtime().Egresses["cf"]; !ok || rec.Generation != 0 || len(rec.Draining) != 0 {
		t.Fatalf("record = %+v, %v; want it kept without a generation", rec, ok)
	}
	acct := filepath.Join(h.paths.EgressStateDir("cf"), "warp-account.json")
	if _, err := os.Stat(acct); err != nil {
		t.Fatalf("the account: %v, want it kept", err)
	}

	// The agent starts again.
	h.warp.setDeleteHook(nil)
	h.r = h.newReconciler()
	h.pass()
	if !slices.Equal(h.warp.deleted, []string{testWARPAccount().ID}) {
		t.Errorf("deleted devices = %v", h.warp.deleted)
	}
	if _, ok := h.runtime().Egresses["cf"]; ok {
		t.Error("the record is still there")
	}
	if _, err := os.Stat(acct); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the account is still there: %v", err)
	}
}

// A registration that fails leaves the egress without an instance, and is
// tried again later.
func TestWARPRegistrationFailure(t *testing.T) {
	h := newHarness(t)
	h.warp.regErr = errors.New("warp: registration: HTTP 429 Too Many Requests")
	h.apply(h.providerState(1, &nodev1.Egress{Id: "cf", Kind: nodev1.EgressKind_EGRESS_KIND_WARP}))
	h.pass()
	if c := h.container("postern-egr-cf-g1"); c != nil {
		t.Errorf("container = %+v", c)
	}
	if evs := h.eventsOf("egress_failed"); len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "429") {
		t.Errorf("egress_failed events = %v", evs)
	}
	// Cloudflare limits the rate of registrations: not again at the next pass.
	h.warp.regErr = nil
	h.pass()
	if n := len(h.warp.registered); n != 1 {
		t.Errorf("registered %d times, want once before the retry delay", n)
	}
	h.clock.Advance(defaultRetryAfter)
	h.pass()
	if rec := h.runtime().Egresses["cf"]; rec.Generation == 0 {
		t.Errorf("record = %+v, want an instance once the registration works", rec)
	}
}

// psiphonEgress is a PSIPHON egress "ps" that exits in country.
func psiphonEgress(country string) *nodev1.Egress {
	return &nodev1.Egress{Id: "ps", Kind: nodev1.EgressKind_EGRESS_KIND_PSIPHON, ParamsJson: `{"country":"` + country + `"}`}
}

// A PSIPHON egress runs Psiphon's own client: its configuration is a file of
// the generation, 0600, with the partner ids of the egress; the container runs
// the client on it, and there is no WARP device.
func TestPsiphonRunsTheTunnelCore(t *testing.T) {
	h := newHarness(t)
	e := psiphonEgress("DE")
	e.ParamsJson = `{"country":"de","propagation_channel_id":"0123456789abcdef","sponsor_id":"FEDCBA9876543210"}`
	h.apply(h.providerState(1, e))
	h.pass()
	specs := h.creates("egress")
	if len(specs) != 1 || !slices.Contains(specs[0].Entrypoint, providers.InstanceMount+"/"+psiphoncore.ConfigFile) {
		t.Fatalf("containers = %+v", specs)
	}
	path := filepath.Join(h.paths.EgressDir("ps"), "g1", psiphoncore.ConfigFile)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config = %v, %v; want mode 0600", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c["ListenInterface"] != "lo" || c["DisableLocalHTTPProxy"] != true || c["EgressRegion"] != "DE" ||
		c["PropagationChannelId"] != "0123456789ABCDEF" || c["SponsorId"] != "FEDCBA9876543210" ||
		c["LocalSocksProxyPort"] != float64(h.runtime().Egresses["ps"].Members[0].Port) {
		t.Errorf("config = %s", data)
	}
	if len(h.warp.registered) != 0 {
		t.Error("a PSIPHON egress registered a WARP device")
	}
}

// canonicalCacheOf is where the canonical cache of an egress points, "" for
// nowhere.
func (h *harness) canonicalCacheOf(id string) string {
	target, _ := os.Readlink(filepath.Join(h.paths.EgressDir(id), "cache"))
	return target
}

// A PSIPHON egress runs Psiphon's client with a cache that outlives its
// generations (Ruling S2-18): each generation has a cache directory of its
// own, a copy of the canonical cache made as it starts (without the notices of
// the generation before), so that no two Psiphon processes
// open the same file; once the generation it replaced is removed, its cache is
// the canonical one, and the old one goes. An egress that no chain takes keeps
// its canonical cache for its next generation. What is no regular file or
// directory is not copied.
func TestPsiphonGenerationsHaveTheirOwnCache(t *testing.T) {
	h := newHarness(t)
	dir := h.paths.EgressDir("ps")
	cacheOf := func(gen int) string { return filepath.Join(dir, fmt.Sprintf("cache-g%d", gen)) }
	datastore := func(gen int) string { return filepath.Join(cacheOf(gen), "psiphon", "datastore.boltdb") }
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	region := func(gen int) string {
		t.Helper()
		var c struct{ EgressRegion, DataRootDirectory string }
		if err := json.Unmarshal([]byte(read(filepath.Join(dir, fmt.Sprintf("g%d", gen), psiphoncore.ConfigFile))), &c); err != nil {
			t.Fatal(err)
		}
		if c.DataRootDirectory != providers.CacheMount {
			t.Errorf("g%d: the data root is %q, want the cache", gen, c.DataRootDirectory)
		}
		return c.EgressRegion
	}
	notices := func(gen int) string {
		return filepath.Join(cacheOf(gen), filepath.FromSlash(psiphoncore.NoticeFiles[0]))
	}

	h.apply(h.providerState(1, psiphonEgress("DE")))
	h.pass()
	spec := h.creates("egress")[0]
	if !slices.Contains(spec.Binds, cacheOf(1)+":"+providers.CacheMount) || region(1) != "DE" {
		t.Errorf("container = %+v", spec)
	}
	rec := h.runtime().Egresses["ps"]
	if rec.Generation != 1 || rec.Provider != "psiphon-core" || len(rec.Members) != 1 || rec.Members[0].Key != "psiphon" {
		t.Fatalf("record = %+v", rec)
	}
	if got := h.canonicalCacheOf("ps"); got != "cache-g1" {
		t.Errorf("canonical cache = %q, want cache-g1: the generation serves alone", got)
	}

	// Psiphon of g1 fills its cache, and something that is not to be copied
	// is in it: a link to a file of the host, and its notices.
	write(datastore(1), "g1 data")
	write(notices(1), `{"data":{"count":1},"noticeType":"Tunnels"}`+"\n")
	secret := filepath.Join(h.paths.Home, "host-secret")
	write(secret, "a file of the host")
	if err := os.Symlink(secret, filepath.Join(cacheOf(1), "link-out")); err != nil {
		t.Fatal(err)
	}

	// Another country: g2 has a copy of the cache of g1, in its own directory,
	// while g1 drains with its own.
	h.apply(h.providerState(2, psiphonEgress("NL")))
	h.pass()
	specs := h.creates("egress")
	if len(specs) != 2 || !slices.Contains(specs[1].Binds, cacheOf(2)+":"+providers.CacheMount) || region(2) != "NL" {
		t.Fatalf("g2 = %+v", specs[len(specs)-1])
	}
	if got := read(datastore(2)); got != "g1 data" {
		t.Errorf("the cache of g2 holds %q, want the copy of g1's", got)
	}
	if _, err := os.Stat(notices(2)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the notices of g1 were copied into the cache of g2: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cacheOf(2), "link-out")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a link out of the cache was copied: %v", err)
	}
	if got := h.canonicalCacheOf("ps"); got != "cache-g1" {
		t.Errorf("while g1 drains, the canonical cache = %q, want cache-g1", got)
	}
	write(datastore(2), "g2 data")
	if got := read(datastore(1)); got != "g1 data" {
		t.Errorf("the cache of g1 holds %q: the generations share a file", got)
	}

	// g1 is removed: the cache of g2 is the canonical one, and that of g1 goes.
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if got := h.canonicalCacheOf("ps"); got != "cache-g2" {
		t.Errorf("canonical cache = %q, want cache-g2", got)
	}
	if _, err := os.Stat(cacheOf(1)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cache of g1 is still there: %v", err)
	}

	// The next generation is seeded from it.
	h.apply(h.providerState(3, psiphonEgress("FR")))
	h.pass()
	if got := read(datastore(3)); got != "g2 data" {
		t.Errorf("the cache of g3 holds %q, want the copy of g2's", got)
	}
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if got := h.canonicalCacheOf("ps"); got != "cache-g3" {
		t.Errorf("canonical cache = %q, want cache-g3", got)
	}

	// No chain takes the egress: its generation drains and goes, and its cache
	// stays the canonical one, for the next generation.
	unused := h.providerState(4, psiphonEgress("FR"))
	unused.Proxies[0].EgressChainId = ""
	h.apply(unused)
	h.pass()
	h.clock.Advance(2 * time.Minute)
	h.pass()
	if rec := h.runtime().Egresses["ps"]; rec.Generation != 0 || len(rec.Draining) != 0 {
		t.Fatalf("record = %+v, want no generation", rec)
	}
	if got := h.canonicalCacheOf("ps"); got != "cache-g3" || read(datastore(3)) != "g2 data" {
		t.Errorf("canonical cache = %q, want cache-g3 with what it holds", got)
	}
	h.apply(h.providerState(5, psiphonEgress("FR")))
	h.pass()
	if got := read(datastore(4)); got != "g2 data" {
		t.Errorf("the cache of g4 holds %q", got)
	}
	if got := h.canonicalCacheOf("ps"); got != "cache-g4" {
		t.Errorf("canonical cache = %q, want cache-g4", got)
	}
	if _, err := os.Stat(cacheOf(3)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cache of g3 is still there: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"cache", "cache-g4", "g4"}; !slices.Equal(names, want) {
		t.Errorf("the directory of the egress holds %v, want %v", names, want)
	}
}

// A cache too large to copy is not copied: the new generation starts with an
// empty one, and starts.
func TestPsiphonCacheTooLargeIsNotCopied(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, psiphonEgress("DE")))
	h.pass()
	dir := h.paths.EgressDir("ps")
	for i := range maxCacheEntries + 1 {
		if err := os.WriteFile(filepath.Join(dir, "cache-g1", fmt.Sprintf("f%d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.apply(h.providerState(2, psiphonEgress("NL")))
	h.pass()
	if rec := h.runtime().Egresses["ps"]; rec.Generation != 2 {
		t.Fatalf("record = %+v, want g2", rec)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "cache-g2"))
	if err != nil || len(entries) != 0 {
		t.Errorf("the cache of g2 holds %d entries (%v), want none", len(entries), err)
	}
}

// A chain in use is one of an enabled proxy, its scope chains included: an
// egress that only the scope chain "me" of a proxy takes gets an instance, and
// drains when the proxy is paused.
func TestProviderOfAScopeChain(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Egresses = append(st.Egresses, uriEgress("me-out", vless("me.example.com", 443, "m")))
	st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "me-chain", MemberEgressIds: []string{"me-out"}})
	st.Proxies[0].EgressScopeChains = map[string]string{"me": "me-chain"}
	h.apply(st)
	h.pass()
	if c := h.container("postern-egr-me-out-g1"); c == nil || c.State != "running" {
		t.Fatalf("egress of the scope chain = %+v, want running", c)
	}
	socks := h.fakeEdge(1).lastConfig(t).GetSocks()
	if len(socks) != 1 || socks[0].GetScopeChains()["me"] != "me-chain" {
		t.Errorf("socks = %v", socks)
	}

	paused := proto.Clone(st).(*nodev1.NodeState)
	paused.Generation = 2
	paused.Proxies[0].Enabled = false
	h.apply(paused)
	h.pass()
	if rec := h.runtime().Egresses["me-out"]; rec.Generation != 0 || len(rec.Draining) != 1 {
		t.Errorf("record = %+v, want g1 draining: no chain in use takes the egress", rec)
	}
}
