package state

import (
	"fmt"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// The settings of slice 6: ip_policy known (unspecified = off),
// ip_retention_hours 0 or 1-720, geoip only with policy full or countries
// (month YYYY-MM, sha256 of 64 hex digits), probe_sources at most 32 single
// addresses (prefixes refused, IPv4-mapped unmapped), the nonces free.
func TestValidateSliceSixSettings(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("203.0.113.%d", i)
	}
	cases := []struct {
		name   string
		mutate func(s *nodev1.NodeSettings)
		want   string // a substring of the error; "" means valid
	}{
		{name: "policy unspecified", mutate: func(s *nodev1.NodeSettings) { s.IpPolicy = nodev1.IpPolicy_IP_POLICY_UNSPECIFIED }},
		{name: "policy off", mutate: func(s *nodev1.NodeSettings) { s.IpPolicy = nodev1.IpPolicy_IP_POLICY_OFF }},
		{name: "policy unknown", want: "ip_policy", mutate: func(s *nodev1.NodeSettings) { s.IpPolicy = nodev1.IpPolicy(99) }},

		{name: "retention 0", mutate: func(s *nodev1.NodeSettings) { s.IpRetentionHours = 0 }},
		{name: "retention 1", mutate: func(s *nodev1.NodeSettings) { s.IpRetentionHours = 1 }},
		{name: "retention 720", mutate: func(s *nodev1.NodeSettings) { s.IpRetentionHours = 720 }},
		{name: "retention 721", want: "ip_retention_hours", mutate: func(s *nodev1.NodeSettings) { s.IpRetentionHours = 721 }},

		{name: "geoip with full", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_FULL
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-10", Sha256: sha}
		}},
		{name: "geoip with countries, upper-case sha", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_COUNTRIES
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-01", Sha256: strings.ToUpper(sha)}
		}},
		{name: "geoip with off", want: "geoip", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_OFF
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-10", Sha256: sha}
		}},
		{name: "geoip with the policy unset", want: "geoip", mutate: func(s *nodev1.NodeSettings) {
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-10", Sha256: sha}
		}},
		{name: "geoip month without the zero", want: "month", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_COUNTRIES
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-1", Sha256: sha}
		}},
		{name: "geoip month 13", want: "month", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_COUNTRIES
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-13", Sha256: sha}
		}},
		{name: "geoip month empty", want: "month", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_COUNTRIES
			s.Geoip = &nodev1.GeoIPRef{Month: "", Sha256: sha}
		}},
		{name: "geoip sha short", want: "sha256", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_COUNTRIES
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-10", Sha256: sha[:63]}
		}},
		{name: "geoip sha not hex", want: "sha256", mutate: func(s *nodev1.NodeSettings) {
			s.IpPolicy = nodev1.IpPolicy_IP_POLICY_COUNTRIES
			s.Geoip = &nodev1.GeoIPRef{Month: "2026-10", Sha256: strings.Repeat("zz", 32)}
		}},

		{name: "probe sources, single addresses", mutate: func(s *nodev1.NodeSettings) {
			s.ProbeSources = []string{"203.0.113.5", "2001:db8::10", "::ffff:198.51.100.7"}
		}},
		{name: "probe sources, 32", mutate: func(s *nodev1.NodeSettings) { s.ProbeSources = many[:32] }},
		{name: "probe sources, 33", want: "probe_sources", mutate: func(s *nodev1.NodeSettings) { s.ProbeSources = many }},
		{name: "probe source, a /32 prefix", want: "probe_sources", mutate: func(s *nodev1.NodeSettings) {
			s.ProbeSources = []string{"203.0.113.5/32"}
		}},
		{name: "probe source, a prefix", want: "probe_sources", mutate: func(s *nodev1.NodeSettings) {
			s.ProbeSources = []string{"2001:db8::/64"}
		}},
		{name: "probe source, a zone", want: "probe_sources", mutate: func(s *nodev1.NodeSettings) {
			s.ProbeSources = []string{"fe80::1%eth0"}
		}},
		{name: "probe source, a name", want: "probe_sources", mutate: func(s *nodev1.NodeSettings) {
			s.ProbeSources = []string{"panel.example.com"}
		}},
		{name: "probe source, empty", want: "probe_sources", mutate: func(s *nodev1.NodeSettings) {
			s.ProbeSources = []string{""}
		}},

		{name: "nonces", mutate: func(s *nodev1.NodeSettings) { s.EdgeRollNonce = 1<<64 - 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := validState()
			tc.mutate(st.Settings)
			err := Validate(st, telemtOnly)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("Validate = %v, want nil", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("Validate = %v, want an error about %s", err, tc.want)
			}
		})
	}
}

// A proxy's restart nonce is free.
func TestValidateRestartNonceIsFree(t *testing.T) {
	st := validState()
	st.Proxies[0].RestartNonce = 1<<64 - 1
	if err := Validate(st, telemtOnly); err != nil {
		t.Errorf("Validate = %v, want nil", err)
	}
}

// ProbeSource reads one probe source as the validator does: a single
// address, an IPv4-mapped one unmapped.
func TestProbeSource(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"203.0.113.5", "203.0.113.5"},
		{"::ffff:203.0.113.5", "203.0.113.5"},
		{"2001:db8::10", "2001:db8::10"},
		{"203.0.113.5/32", ""},
		{"2001:db8::10%eth0", ""},
		{"", ""},
	}
	for _, tc := range cases {
		a, err := ProbeSource(tc.in)
		switch {
		case tc.want == "" && err == nil:
			t.Errorf("ProbeSource(%q) = %s, want an error", tc.in, a)
		case tc.want != "" && (err != nil || a.String() != tc.want):
			t.Errorf("ProbeSource(%q) = %s, %v; want %s", tc.in, a, err, tc.want)
		}
	}
}
