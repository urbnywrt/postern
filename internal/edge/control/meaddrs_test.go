package control

import (
	"bytes"
	"strings"
	"testing"
)

// The middle-proxy addresses of a configuration reach the router with it; a
// configuration with one that is not an IP address and a port is refused
// whole, and the previous addresses stay.
func TestSetConfigAppliesTheMiddleProxyAddresses(t *testing.T) {
	r := newRig(t)
	be := echoBackend(t)
	ports := freePorts(t, 2)

	cfg := withEgress(routeConfig(7, ports[0], be), "c1", "m1", ports[1])
	cfg.MeAddrs = []string{"203.0.113.7:8888", "[2001:db8::d]:8888"}
	r.mustSet(cfg)
	if got := r.router.ScopeOf("", "203.0.113.7", 8888); got != "me" {
		t.Errorf("after the configuration: ScopeOf = %q, want me", got)
	}
	if got := r.router.ScopeOf("", "203.0.113.7", 443); got != "" {
		t.Errorf("another port of the address: ScopeOf = %q, want no scope", got)
	}
	if got := r.savedConfig().GetMeAddrs(); len(got) != 2 {
		t.Errorf("saved me_addrs = %v", got)
	}
	saved := r.savedBytes()

	bad := withEgress(routeConfig(7, ports[0], be), "c1", "m1", ports[1])
	bad.MeAddrs = []string{"203.0.113.8:8888", "203.0.113.9"}
	if reason := r.mustRefuse(bad); !strings.Contains(reason, `"203.0.113.9"`) {
		t.Errorf("the reason, %q, does not name the address that is wrong", reason)
	}
	if got := r.router.ScopeOf("", "203.0.113.7", 8888); got != "me" {
		t.Errorf("after a refused configuration: ScopeOf = %q, want the previous addresses", got)
	}
	if got := r.router.ScopeOf("", "203.0.113.8", 8888); got != "" {
		t.Errorf("after a refused configuration: ScopeOf = %q for an address of it", got)
	}
	if !bytes.Equal(r.savedBytes(), saved) {
		t.Error("the configuration file was touched")
	}

	cfg.MeAddrs = nil
	r.mustSet(cfg)
	if got := r.router.ScopeOf("", "203.0.113.7", 8888); got != "" {
		t.Errorf("after a configuration without addresses: ScopeOf = %q", got)
	}
}

// The process comes up from its file with the addresses in it.
func TestApplyTakesTheMiddleProxyAddresses(t *testing.T) {
	r := newRig(t)
	cfg := routeConfig(3, freePorts(t, 1)[0], echoBackend(t))
	cfg.MeAddrs = []string{"203.0.113.7:8888"}
	if err := r.srv.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.router.ScopeOf("", "203.0.113.7", 8888); got != "me" {
		t.Errorf("ScopeOf = %q, want me", got)
	}
	cfg.MeAddrs = []string{"not an address"}
	if err := r.srv.Apply(cfg); err == nil {
		t.Error("Apply took a configuration with a bad address")
	}
}
