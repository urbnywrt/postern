package state

import (
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// testUUID is the id of a VLESS server of the tests.
const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// kindParams makes the egress "web" of validState one of kind with params.
func kindParams(st *nodev1.NodeState, kind nodev1.EgressKind, params string) {
	for _, e := range st.Egresses {
		if e.Id == "web" {
			e.Kind, e.ParamsJson = kind, params
		}
	}
}

// The egresses of the providers, with their parameters as the panel sends
// them (Task 6): a share link, a subscription and how to pick its servers, a
// WARP device without parameters, a Psiphon exit country.
func TestValidateAcceptsTheProviderEgresses(t *testing.T) {
	for _, tc := range []struct {
		kind   nodev1.EgressKind
		params string
	}{
		{nodev1.EgressKind_EGRESS_KIND_XRAY_URI, `{"uri":"vless://` + testUUID + `@vpn.example.com:443?type=tcp&security=none#a"}`},
		{nodev1.EgressKind_EGRESS_KIND_XRAY_URI, `{"uri":"trojan://` + testPassword + `@203.0.113.9:443?sni=t.example.com"}`},
		{nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https://sub.example.com/s/` + testPassword + `"}`},
		{nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"http://203.0.113.9:8080/sub?token=` + testPassword + `","select":"all"}`},
		{nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https://sub.example.com/s","select":"first"}`},
		{nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https://sub.example.com/s","select":"name:Amsterdam 🇳🇱"}`},
		{nodev1.EgressKind_EGRESS_KIND_WARP, ``},
		{nodev1.EgressKind_EGRESS_KIND_WARP, `{}`},
		{nodev1.EgressKind_EGRESS_KIND_PSIPHON, `{"country":"DE"}`},
		{nodev1.EgressKind_EGRESS_KIND_PSIPHON, `{"country":"nl"}`},
	} {
		st := validState()
		kindParams(st, tc.kind, tc.params)
		if err := Validate(st, telemtOnly); err != nil {
			t.Errorf("%v %.60s: Validate = %v, want nil", tc.kind, tc.params, err)
		}
	}
}

func TestParseProviderParams(t *testing.T) {
	uri, err := ParseXrayURIParams(`{"uri":" vless://` + testUUID + `@vpn.example.com:443?type=tcp&security=none#a "}`)
	if err != nil || uri.Server == nil || uri.Server.Address != "vpn.example.com" || uri.Server.ID != testUUID {
		t.Errorf("ParseXrayURIParams = %+v, %v", uri, err)
	}

	for _, tc := range []struct {
		params, url string
		sel         Select
	}{
		{`{"url":"https://sub.example.com/s"}`, "https://sub.example.com/s", Select{Mode: SelectAll}},
		{`{"url":"https://sub.example.com/s","select":"all"}`, "https://sub.example.com/s", Select{Mode: SelectAll}},
		{`{"url":"https://sub.example.com/s","select":"first"}`, "https://sub.example.com/s", Select{Mode: SelectFirst}},
		{`{"url":"https://sub.example.com/s","select":"name:NL"}`, "https://sub.example.com/s", Select{Mode: SelectName, Name: "NL"}},
		{`{"url":" HTTPS://Sub.Example.com/s ","select":" name:NL "}`, "HTTPS://Sub.Example.com/s", Select{Mode: SelectName, Name: "NL"}},
	} {
		p, err := ParseSubscriptionParams(tc.params)
		if err != nil || p.URL != tc.url || p.Select != tc.sel {
			t.Errorf("ParseSubscriptionParams(%s) = %+v, %v; want %s, %+v", tc.params, p, err, tc.url, tc.sel)
		}
	}
	if _, err := ParseSubscriptionParams(`{"url":"https://sub.example.com/` + strings.Repeat("x", 4096) + `"}`); err == nil {
		t.Error("ParseSubscriptionParams took a URL of 4 KiB")
	}
	if _, err := ParseSubscriptionParams(`{"url":"https://sub.example.com/s","select":"name:` + strings.Repeat("x", 300) + `"}`); err == nil {
		t.Error("ParseSubscriptionParams took a name of 300 bytes")
	}

	for params, want := range map[string]string{`{"country":"de"}`: "DE", `{"country":" SG "}`: "SG"} {
		if p, err := ParsePsiphonParams(params); err != nil || p.Country != want {
			t.Errorf("ParsePsiphonParams(%s) = %+v, %v; want %s", params, p, err, want)
		}
	}
	// The partner ids: both or neither, 16 hex digits, upper-cased.
	p, err := ParsePsiphonParams(`{"country":"DE","propagation_channel_id":" 0123456789abcdef","sponsor_id":"FEDCBA9876543210"}`)
	if err != nil || p.PropagationChannelID != "0123456789ABCDEF" || p.SponsorID != "FEDCBA9876543210" {
		t.Errorf("ParsePsiphonParams with partner ids = %+v, %v", p, err)
	}
	for _, bad := range []string{
		`{"country":"DE","propagation_channel_id":"0123456789ABCDEF"}`,
		`{"country":"DE","sponsor_id":"0123456789ABCDEF"}`,
		`{"country":"DE","propagation_channel_id":"0123456789ABCDE","sponsor_id":"0123456789ABCDEF"}`,
		`{"country":"DE","propagation_channel_id":"0123456789ABCDEF","sponsor_id":"0123456789ABCDEG"}`,
		`{"country":"DE","propagation_channel_id":"0123456789ABCDEF\"","sponsor_id":"0123456789ABCDEF"}`,
	} {
		if p, err := ParsePsiphonParams(bad); err == nil {
			t.Errorf("ParsePsiphonParams(%s) = %+v", bad, p)
		}
	}
	if err := ParseWARPParams(`{"anything":1}`); err != nil {
		t.Errorf("ParseWARPParams of an object = %v", err)
	}
}

// The selection of the servers of a subscription.
func TestSelectMatches(t *testing.T) {
	cases := []struct {
		sel   Select
		name  string
		match bool
	}{
		{Select{Mode: SelectAll}, "anything", true},
		{Select{Mode: SelectFirst}, "anything", true},
		{Select{Mode: SelectName, Name: "nl"}, "Amsterdam NL 1", true}, // in any letter case
		{Select{Mode: SelectName, Name: "Amsterdam"}, "AMSTERDAM-2", true},
		{Select{Mode: SelectName, Name: "de"}, "Amsterdam NL 1", false},
		{Select{Mode: SelectName, Name: "🇳🇱"}, "🇳🇱 Amsterdam", true},
	}
	for _, tc := range cases {
		if got := tc.sel.Matches(tc.name); got != tc.match {
			t.Errorf("%+v.Matches(%q) = %v, want %v", tc.sel, tc.name, got, tc.match)
		}
	}
}
