package engines_test

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/mtg"
	"github.com/urbnywrt/postern/internal/engines/telemt"
)

// instanceFor is a fake-TLS instance that both drivers take, but for its
// domain: the engine is left unset (each driver takes that for its own), and
// it has what either driver needs (an API token for telemt, a fronting address
// for mtg).
func instanceFor(domain string) engines.Instance {
	return engines.Instance{
		Proxy: &nodev1.Proxy{
			Id:     "01J9ZZ0000000000000000TEST",
			Type:   nodev1.ProxyType_PROXY_TYPE_FAKETLS,
			Secret: "00112233445566778899aabbccddeeff", // gitleaks:allow (a fake secret)
			Domain: domain,
		},
		InstanceID:   "01J9ZZ0000000000000000TEST-g1",
		Generation:   1,
		ListenPort:   20123,
		APIPort:      25123,
		SocksPort:    30123,
		APIToken:     "api-token-api-token",
		InstanceDir:  "/opt/postern/data/instances/01J9ZZ0000000000000000TEST-g1",
		BinaryPath:   "/opt/postern/data/artifacts/engine/1/amd64/engine",
		RunnerImage:  "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
		FrontingAddr: netip.MustParseAddrPort("203.0.113.80:443"),
	}
}

// TestDriversTakeTheSameDomains: a domain one engine takes, the other takes as
// well, and one that one engine refuses, the other refuses too. A proxy that
// switches between telemt and mtg keeps its domain (it is part of the link),
// so a switch must never fail on it.
func TestDriversTakeTheSameDomains(t *testing.T) {
	tests := []struct {
		domain string
		ok     bool
	}{
		{"www.example.com", true},
		{"WWW.EXAMPLE.COM", true},
		{"www.example.com.", true},
		{"пример.example", true},
		{"xn--e1afmkfd.example", true},
		{"_service.example.com", true},
		{"localhost", true}, // a character policy: where a name leads is not the drivers' business
		{"a", true},
		{strings.Repeat("a", 253), true},
		{strings.Repeat("я", 126), true}, // 252 bytes of UTF-8

		{"", false},
		{strings.Repeat("a", 254), false},
		{strings.Repeat("я", 127), false}, // 254 bytes
		{"www example.com", false},
		{"www\texample.com", false},
		{"www.example.com/x", false},
		{`www.example.com\x`, false},
		{`www.example.com"`, false},
		{"www.example.com\n[evil]", false},
		{"www.example.com\r", false},
		{"www.example.com\x00", false},
		{"www.example.com\x7f", false},
		{"www.example.com" + string(rune(0x85)), false},        // next line (C1)
		{"www.example.com" + string(rune(0xa0)), false},        // no-break space
		{"www.example.com" + string(rune(0x2028)), false},      // line separator
		{"www.example.com" + string(rune(0x202e)), false},      // right-to-left override
		{"www." + string(rune(0x2066)) + "example.com", false}, // left-to-right isolate
		{"www.example.com" + string(rune(0x200e)), false},      // left-to-right mark
		{"www.example.com" + string(rune(0x61c)), false},       // Arabic letter mark
		{"www.example.com\xff", false},
	}
	drivers := []engines.Driver{telemt.New(), mtg.New()}
	for _, tt := range tests {
		t.Run(strconv.Quote(tt.domain), func(t *testing.T) {
			for _, d := range drivers {
				_, err := d.Render(instanceFor(tt.domain))
				switch {
				case tt.ok && err != nil:
					t.Errorf("%s refuses the domain: %v", d.Engine(), err)
				case !tt.ok && err == nil:
					t.Errorf("%s takes the domain", d.Engine())
				case !tt.ok && !strings.Contains(err.Error(), "domain"):
					t.Errorf("%s refuses it for another reason than its domain: %v", d.Engine(), err)
				}
			}
		})
	}
}
