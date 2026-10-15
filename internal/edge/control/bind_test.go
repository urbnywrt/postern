package control

import (
	"net"
	"slices"
	"strings"
	"testing"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// A listener whose port is held by a foreign socket does not refuse the
// configuration: it is applied and saved, the other listener serves, and the
// failure is in the answer and in Health, with the address. The next
// configuration without the listener clears it.
func TestSetConfigReportsTheListenersThatCannotBind(t *testing.T) {
	be := echoBackend(t)
	r := newRig(t)
	ports := freePorts(t, 2)
	ln, err := net.Listen("tcp4", addr(ports[1])) // no SO_REUSEPORT: it does not share
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	cfg := routeConfig(7, ports[0], be)
	cfg.Listeners = append(cfg.Listeners, &edgev1.EdgeListener{
		Id: "l2", BindIp: "127.0.0.1", Port: ports[1], Kind: "tls", StrangerAction: "reject", NonTlsAction: "drop",
	})
	resp := r.set(cfg)
	if !resp.GetApplied() {
		t.Fatalf("SetConfig refused the configuration: %s", resp.GetError())
	}
	f := resp.GetListenerFailures()
	if len(f) != 1 || f[0].GetListenerId() != "l2" || !strings.Contains(f[0].GetReason(), addr(ports[1])) {
		t.Fatalf("listener_failures = %v, want l2 with a reason that names %s", f, addr(ports[1]))
	}
	h := r.health()
	if !slices.Equal(h.GetBound(), []string{addr(ports[0])}) || !h.GetListening() {
		t.Errorf("Health bound = %v, listening %v; want the first listener, listening", h.GetBound(), h.GetListening())
	}
	if hf := h.GetListenerFailures(); len(hf) != 1 || hf[0].GetListenerId() != "l2" {
		t.Errorf("Health listener_failures = %v, want l2", hf)
	}
	if saved, err := LoadConfig(r.cfgPath); err != nil || saved.GetGeneration() != 7 || len(saved.GetListeners()) != 2 {
		t.Errorf("saved configuration = %v, %v; want the applied one", saved, err)
	}
	relay(t, ports[0], "proxy.example.com")

	r.mustSet(routeConfig(7, ports[0], be))
	if h := r.health(); len(h.GetListenerFailures()) != 0 {
		t.Errorf("Health listener_failures = %v after the listener went, want none", h.GetListenerFailures())
	}
}
