//go:build integration

package egress

// TestIntegrationCheckRealDatacenters checks the five datacenters of the
// default health check with the code of the health checks (checkDC, and in it
// probe.DCPing): through a direct member, and through a SOCKS5 member whose
// proxy, in the test process, connects to them. It reaches Telegram's
// datacenters, and runs only with POSTERN_E2E_ONLINE=1:
//
//	POSTERN_E2E_ONLINE=1 go test -tags integration -run Integration ./internal/edge/egress/

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/socks5"
)

func TestIntegrationCheckRealDatacenters(t *testing.T) {
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("reaches Telegram's datacenters: set POSTERN_E2E_ONLINE=1 to run it")
	}
	proxy := startSOCKS5(t, func(ctx context.Context, req socks5.Request) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
	})
	r := NewRouter(quiet)
	chain := chainOf("c", mem("direct", KindDirect), &edgev1.ChainMember{Key: "socks5", Kind: KindSOCKS5, Addr: proxy})
	if err := r.Apply([]*edgev1.Chain{chain}, nil); err != nil {
		t.Fatal(err)
	}
	cfg := r.cur.Load()
	for _, m := range cfg.members {
		for _, dc := range defaultDCs {
			latency, _, err := r.checkDC(context.Background(), m, dc, cfg.check.timeout)
			if err != nil {
				t.Errorf("%s through the %s member: %v", dc, m.key, err)
				continue
			}
			if latency <= 0 {
				t.Errorf("%s through the %s member: latency %v", dc, m.key, latency)
			}
			t.Logf("%s through the %s member: resPQ in %v", dc, m.key, latency)
		}
	}
}
