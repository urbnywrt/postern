package control

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/edge/dns"
)

// answerAll stands in for the DNS-over-HTTPS endpoints: every A question has
// the answer 192.0.2.10.
type answerAll struct{}

func (answerAll) Exchange(_ context.Context, query []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil {
		return nil, err
	}
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: q.Questions,
	}
	if q.Questions[0].Type == dnsmessage.TypeA {
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
		}}
	}
	return resp.Pack()
}

// newDNSRig is newRig with a DNS forwarder on addr ("127.0.0.1:0" for a free
// port) that asks answerAll.
func newDNSRig(t *testing.T, addr string) (*rig, *dns.Forwarder) {
	t.Helper()
	r := newRig(t)
	f := dns.New(quiet, dns.Options{Addr: addr, NewUpstream: func([]string) dns.Upstream { return answerAll{} }})
	r.srv.SetDNS(f)
	return r, f
}

// withDNS adds an enabled DNS forwarder to cfg.
func withDNS(cfg *edgev1.EdgeConfig) *edgev1.EdgeConfig {
	cfg.Dns = &edgev1.Dns{Enabled: true, DohUrls: []string{"https://192.0.2.1/dns-query"}, Fallback: []string{"192.0.2.53"}}
	return cfg
}

// resolves checks that the forwarder at addr answers a question for
// www.example.com with the answer of answerAll.
func resolves(t *testing.T, addr netip.AddrPort) {
	t.Helper()
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 77, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("the forwarder at %s does not answer: %v", addr, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil || m.ID != 77 || len(m.Answers) != 1 {
		t.Fatalf("answer = %+v, %v", m, err)
	}
}

// The forwarder runs while the configuration enables it, and Health says so.
func TestDNSForwarderFollowsTheConfiguration(t *testing.T) {
	r, f := newDNSRig(t, "127.0.0.1:0")
	if r.health().GetDns() {
		t.Error("Health reports DNS before any configuration")
	}
	be := echoBackend(t) // before the port: a backend bound after it could take it
	port := freePorts(t, 1)[0]
	r.mustSet(withDNS(routeConfig(3, port, be)))
	if !r.health().GetDns() || !f.Running() {
		t.Fatalf("Health dns %v, running %v; want the forwarder up", r.health().GetDns(), f.Running())
	}
	resolves(t, f.Addr())
	if saved := r.savedConfig(); !proto.Equal(saved.GetDns(), withDNS(&edgev1.EdgeConfig{}).GetDns()) {
		t.Errorf("saved dns = %v", saved.GetDns())
	}

	r.mustSet(routeConfig(3, port, be))
	if r.health().GetDns() || f.Running() {
		t.Error("the forwarder still runs after a configuration without it")
	}
}

// A DNS section that is not valid makes the whole configuration refused, and
// nothing changes.
func TestBadDNSConfigurationIsRefused(t *testing.T) {
	r, f := newDNSRig(t, "127.0.0.1:0")
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	good := withDNS(routeConfig(3, port, be))
	r.mustSet(good)
	before := r.savedBytes()

	bad := withDNS(routeConfig(3, port, be))
	bad.Dns.DohUrls = []string{"http://192.0.2.1/dns-query"}
	if reason := r.mustRefuse(bad); !strings.Contains(reason, "dns") {
		t.Errorf("reason %q does not name the DNS part", reason)
	}
	if !f.Running() || string(r.savedBytes()) != string(before) {
		t.Error("the refused configuration changed the forwarder or the file")
	}
}

// A configuration that is refused for another part leaves the forwarder as it
// was, both ways.
func TestRefusedConfigurationLeavesTheDNSAlone(t *testing.T) {
	r, f := newDNSRig(t, "127.0.0.1:0")
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	r.mustSet(withDNS(routeConfig(3, port, be)))
	r.mustRefuse(duplicateListener(routeConfig(3, port, be))) // without DNS
	if !f.Running() {
		t.Error("a refused configuration without DNS stopped the forwarder")
	}

	r.mustSet(routeConfig(3, port, be))
	r.mustRefuse(duplicateListener(withDNS(routeConfig(3, port, be))))
	if f.Running() {
		t.Error("a refused configuration with DNS started the forwarder")
	}
}

// The configuration is in effect even when the forwarder cannot bind its
// address: the proxies of the node must not depend on DNS. Health says that the
// forwarder does not run, the error is logged once, and the next SetConfig
// tries again.
func TestDNSBindFailureDoesNotRefuseTheConfiguration(t *testing.T) {
	taken, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r, f := newDNSRig(t, taken.Addr().String())
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	cfg := withDNS(routeConfig(3, port, be))
	r.mustSet(cfg)
	r.mustSet(cfg)
	if h := r.health(); h.GetDns() || !h.GetListening() || f.Running() {
		t.Errorf("health = %v; want listening, without DNS", h)
	}
	if n := strings.Count(r.logs.String(), "DNS forwarder does not run"); n != 1 {
		t.Errorf("the failure is logged %d times, want once:\n%s", n, r.logs.String())
	}
	relay(t, port, "proxy.example.com")

	_ = taken.Close()
	r.mustSet(cfg)
	if !r.health().GetDns() {
		t.Error("the forwarder does not run after its address came free")
	}
	resolves(t, f.Addr())
	if !strings.Contains(r.logs.String(), "DNS forwarder runs again") {
		t.Errorf("the recovery is not logged:\n%s", r.logs.String())
	}
}

// A configuration that cannot be saved is not in effect, and that includes its
// DNS part.
func TestSaveFailureLeavesTheDNSAlone(t *testing.T) {
	r, f := newDNSRig(t, "127.0.0.1:0")
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	r.mustSet(routeConfig(3, port, be))
	if err := os.Remove(r.cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.cfgPath, 0o700); err != nil {
		t.Fatal(err)
	}
	r.mustRefuse(withDNS(routeConfig(3, port, be)))
	if f.Running() || r.health().GetDns() {
		t.Error("the forwarder runs for a configuration that was refused")
	}
}

// The drain stops the forwarder with the SOCKS ports and the listeners: the
// generation that takes over runs its own.
func TestDrainStopsTheDNSForwarder(t *testing.T) {
	r, f := newDNSRig(t, "127.0.0.1:0")
	be := echoBackend(t)
	r.mustSet(withDNS(routeConfig(3, freePorts(t, 1)[0], be)))
	if !f.Running() {
		t.Fatal("the forwarder does not run")
	}
	r.drain(1)
	if f.Running() || r.health().GetDns() {
		t.Error("the forwarder runs after the drain began")
	}
}

// The process starts from its file with Apply: the forwarder starts there too.
func TestApplyStartsTheDNSForwarder(t *testing.T) {
	r, f := newDNSRig(t, "127.0.0.1:0")
	be := echoBackend(t)
	if err := r.srv.Apply(withDNS(routeConfig(3, freePorts(t, 1)[0], be))); err != nil {
		t.Fatal(err)
	}
	if !f.Running() || !r.health().GetDns() {
		t.Error("the forwarder does not run after Apply")
	}
}
