package reconcile

import (
	"log/slog"
	"strings"
	"testing"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/node/state"
)

// hostsForParity are addresses of proxies and of DCs, good and bad.
var hostsForParity = []string{
	"198.51.100.9:1080", "[2001:db8::9]:1080", "proxy.example.com:1080", "proxy.example.com:65535",
	"proxy.example.com", "proxy.example.com:0", "proxy.example.com:65536", "proxy.example.com:+80", ":1080",
	"[198.51.100.9]:1080", "2001:db8::9:1080", "[proxy.example.com]:1080", "proxy.example.com/x:1080",
	"user@proxy.example.com:1080", "proxy example.com:1080", "proxy\r\n.example.com:1080", "proxy%2e.example.com:1080",
	"proxy#.example.com:1080", "proxy?.example.com:1080", `proxy\.example.com:1080`, "proxy .example.com:1080",
}

// jsonString quotes s for a JSON document of a test.
func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\r", `\r`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// The node takes no egress that its edge refuses (I2): the router of the edge
// refuses its whole configuration, and with it the edge's, for one member it
// cannot dial. So for every egress below, when state.Validate takes the state,
// the router of the edge takes the chains and the health check that the
// reconciler makes of it. (A state the node refuses never reaches the edge;
// the reconciler leaves out an egress whose parameters do not parse, which is
// why the edge takes some of those.) The parameters of a member are also held
// against the dialer of the edge directly.
func TestNodeTakesNoEgressItsEdgeRefuses(t *testing.T) {
	router := egress.NewRouter(slog.New(slog.DiscardHandler))
	var taken, refused int
	check := func(what string, e *nodev1.Egress, dcAddrs []string) {
		t.Helper()
		st := &nodev1.NodeState{
			Generation: 1,
			Settings:   &nodev1.NodeSettings{DefaultChainId: "c1"},
			Egresses:   []*nodev1.Egress{e},
			Chains:     []*nodev1.EgressChain{{Id: "c1", MemberEgressIds: []string{e.GetId()}, Check: &nodev1.HealthCheck{DcAddrs: dcAddrs}}},
		}
		nodeErr := state.Validate(st, nil)
		cfg := buildEdgeConfig(st, state.NewRuntime(), 1, nil)
		edgeErr := router.Apply(cfg.GetChains(), cfg.GetHealth())
		switch {
		case nodeErr == nil && edgeErr != nil:
			t.Errorf("%s: the node takes the egress, but the edge refuses its configuration: %v", what, edgeErr)
		case nodeErr == nil:
			taken++
		default:
			refused++
		}
	}

	for _, kind := range []nodev1.EgressKind{nodev1.EgressKind_EGRESS_KIND_SOCKS5, nodev1.EgressKind_EGRESS_KIND_HTTP} {
		edgeKind := egress.KindSOCKS5
		if kind == nodev1.EgressKind_EGRESS_KIND_HTTP {
			edgeKind = egress.KindHTTP
		}
		for _, h := range hostsForParity {
			params := `{"addr":` + jsonString(h) + `}`
			check(kind.String()+" "+h, &nodev1.Egress{Id: "e1", Kind: kind, ParamsJson: params}, nil)
			// The address rule against the dialer of the edge itself.
			_, nodeErr := state.ParseProxyParams(params)
			_, edgeErr := egress.NewMemberDialer(&edgev1.ChainMember{Key: "e1", Kind: edgeKind, Addr: h}, 0)
			if nodeErr == nil && edgeErr != nil {
				t.Errorf("%s %q: the node takes the address, the edge's dialer refuses it: %v", edgeKind, h, edgeErr)
			}
		}
		for _, cred := range [][2]string{
			{"u", "p"}, {"a:b", "p"}, {"", ""}, {strings.Repeat("u", 255), strings.Repeat("p", 255)},
			{strings.Repeat("u", 256), "p"}, {"u", strings.Repeat("p", 256)},
			{strings.Repeat("u", 1024), strings.Repeat("p", 1024)}, {strings.Repeat("u", 1025), "p"}, {"u", strings.Repeat("p", 1025)},
		} {
			params := `{"addr":"198.51.100.9:1080","username":` + jsonString(cred[0]) + `,"password":` + jsonString(cred[1]) + `}`
			check(kind.String()+" credentials", &nodev1.Egress{Id: "e1", Kind: kind, ParamsJson: params}, nil)
		}
	}
	direct := &nodev1.Egress{Id: "e1", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}
	for _, h := range hostsForParity {
		check("dc_addrs "+h, direct, []string{h})
	}

	if taken < 10 || refused < 30 {
		t.Errorf("taken %d, refused %d: the test shows little", taken, refused)
	}
}
