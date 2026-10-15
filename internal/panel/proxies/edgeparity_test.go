package proxies

import (
	"slices"
	"testing"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/edge"
)

// applyListener makes the edge check a table with one listener, which has the
// given trusted CIDRs. The edge reads the trusted CIDRs of a listener of any
// kind; the listener is of kind tls, so that this is all it judges of them (an
// http-upstream listener also has to trust private prefixes only, see
// rules.CheckUpstreamTrusted). edge.CheckConfig binds nothing, so that no socket
// is opened by the test.
func applyListener(trusted ...string) error {
	return edge.CheckConfig(&edgev1.EdgeConfig{Listeners: []*edgev1.EdgeListener{{
		Id: "L1", BindIp: "192.0.2.1", Port: 443, Kind: "tls", StrangerAction: "mask", NonTlsAction: "drop",
		TrustedCidrs: trusted,
	}}})
}

// The trusted CIDRs of a listener are judged by validateState as the edge judges
// them, since the edge refuses its whole table for one that it cannot read, and the
// panel must not send a state like that: a prefix, or a single address, which is
// the prefix of its whole length, and nothing else.
func TestTrustedCIDRsAreJudgedAsTheEdgeJudgesThem(t *testing.T) {
	good := []string{
		"192.0.2.0/24", "192.0.2.5/24", "192.0.2.1/32", "198.51.100.7", "0.0.0.0/0", "::/0",
		"2001:db8::/32", "2001:db8::1", "::ffff:192.0.2.1", "::ffff:192.0.2.0/120",
	}
	bad := []string{
		"", " ", "192.0.2.0/33", "192.0.2.0/-1", "192.0.2.0/", "/24", "192.0.2.0/24 ", " 192.0.2.0/24",
		"192.0.2.256", "192.0.2", "192.0.2.1.5", "0x7f.0.0.1", "2001:db8::/129", "[2001:db8::1]",
		"fe80::1%eth0", "fe80::1%eth0/64", "proxy.example.com", "192.0.2.0/24,198.51.100.0/24", "192.0.2.0/24/8", "192.0.2.0/024",
	}
	for _, c := range slices.Concat(good, bad) {
		edgeErr := applyListener(c)
		st := validState()
		st.Listeners[0].TrustedCidrs = []string{c}
		stateErr := validateState(st)
		if (edgeErr == nil) != (stateErr == nil) {
			t.Errorf("trusted CIDR %q: the edge says %v, validateState says %v", c, edgeErr, stateErr)
		}
	}
	// The lists are what they claim to be, so that the two cannot agree on nothing.
	for _, c := range good {
		if applyListener(c) != nil {
			t.Errorf("the edge refuses %q, which the test takes for good", c)
		}
	}
	for _, c := range bad {
		if applyListener(c) == nil {
			t.Errorf("the edge takes %q, which the test takes for bad", c)
		}
	}
}

func TestValidateStateAcceptsTrustedCIDRs(t *testing.T) {
	st := validState()
	st.Listeners[0].TrustedCidrs = []string{"192.0.2.0/24", "198.51.100.7", "2001:db8::/32", "2001:db8::1"}
	st.Listeners[1].TrustedCidrs = []string{"203.0.113.0/24"}
	if err := validateState(st); err != nil {
		t.Errorf("validateState: %v", err)
	}
}
