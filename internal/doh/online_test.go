//go:build integration

package doh

// This test asks the real endpoints of DefaultEndpoints, one at a time, so that
// it shows that their certificates are valid for their IP addresses and that
// they speak RFC 8484 the way the client does:
//
//	POSTERN_E2E_ONLINE=1 go test -tags integration -run Online ./internal/doh/
//
// Without POSTERN_E2E_ONLINE=1 it is skipped: it needs the internet.

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestOnlineDefaultEndpoints(t *testing.T) {
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("set POSTERN_E2E_ONLINE=1 to ask the real DNS-over-HTTPS endpoints")
	}
	for _, ep := range DefaultEndpoints {
		t.Run(ep, func(t *testing.T) {
			c := New([]string{ep})
			defer c.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			addrs, err := c.LookupIP(ctx, "example.com")
			if err != nil {
				t.Fatalf("LookupIP(example.com): %v", err)
			}
			if len(addrs) == 0 {
				t.Fatal("LookupIP(example.com) returned no address")
			}
			txt, err := c.LookupTXT(ctx, "example.com")
			if err != nil {
				t.Fatalf("LookupTXT(example.com): %v", err)
			}
			t.Logf("%s: example.com has %d addresses (first %s) and %d TXT records", ep, len(addrs), addrs[0], len(txt))

			if _, err := c.LookupIP(ctx, "name-that-does-not-exist.example.com"); err == nil {
				t.Error("LookupIP of a name that does not exist succeeded")
			}
		})
	}
}
