package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/providers/psiphoncore"
)

// The parameters of the egresses that a provider serves (params_json): Xray for
// XRAY_URI, XRAY_SUBSCRIPTION and WARP, Psiphon's client for PSIPHON. They hold
// credentials (a share link holds the id or the password of its server, the URL
// of a subscription often a token): no error repeats them, and none is logged.

const (
	// maxSubscriptionURL bounds the URL of a subscription.
	maxSubscriptionURL = 2048
	// maxSelectName bounds the text a "name:" selection looks for.
	maxSelectName = 128
)

// XrayURIParams are the parameters of an XRAY_URI egress: {"uri": "<share
// link>"}.
type XrayURIParams struct {
	// URI is the share link, without the spaces around it.
	URI string
	// Server is the server the link describes. It holds credentials: log its
	// Key.
	Server *egressuri.Server
}

// ParseXrayURIParams reads the params_json of an XRAY_URI egress: the link
// must be one that egressuri.Parse reads. Whether Xray takes every value of it
// is the driver's to tell (providers/xray), when the instance is rendered.
// Errors never quote the link.
func ParseXrayURIParams(raw string) (XrayURIParams, error) {
	var p struct {
		URI string `json:"uri"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return XrayURIParams{}, err
	}
	uri := strings.TrimSpace(p.URI)
	if uri == "" {
		return XrayURIParams{}, errors.New("params_json has no uri")
	}
	s, err := egressuri.Parse(uri)
	if err != nil {
		return XrayURIParams{}, fmt.Errorf("uri: %w", err) // egressuri never repeats the link
	}
	return XrayURIParams{URI: uri, Server: s}, nil
}

// The ways to pick the servers of a subscription (the "select" of its
// parameters).
const (
	// SelectAll takes every server; the default.
	SelectAll = "all"
	// SelectFirst takes the first server that can be read (Ruling S2-5).
	SelectFirst = "first"
	// SelectName takes the servers whose name holds Select.Name, in any letter
	// case ("name:<text>").
	SelectName = "name"
)

// Select is how the servers of a subscription are picked.
type Select struct {
	Mode string // SelectAll, SelectFirst or SelectName
	Name string // what the name of a server must hold, for SelectName
}

// Matches reports whether a server of this name is picked; SelectFirst picks
// any, and the caller takes the first of those.
func (s Select) Matches(name string) bool {
	if s.Mode != SelectName {
		return true
	}
	return strings.Contains(strings.ToLower(name), strings.ToLower(s.Name))
}

// SubscriptionParams are the parameters of an XRAY_SUBSCRIPTION egress:
// {"url": "https://...", "select": "all" | "first" | "name:<text>"}.
type SubscriptionParams struct {
	// URL is where the subscription is fetched, http or https. It may hold a
	// credential (a token in its path or query).
	URL    string
	Select Select
}

// ParseSubscriptionParams reads the params_json of an XRAY_SUBSCRIPTION egress:
// an absolute http or https URL with a host, of at most 2048 bytes, without a
// space or a control character, and a select of "" (all), "all", "first" or
// "name:" followed by 1 to 128 bytes. Errors never quote the URL.
func ParseSubscriptionParams(raw string) (SubscriptionParams, error) {
	var p struct {
		URL    string `json:"url"`
		Select string `json:"select"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return SubscriptionParams{}, err
	}
	rawURL := strings.TrimSpace(p.URL)
	switch {
	case rawURL == "":
		return SubscriptionParams{}, errors.New("params_json has no url")
	case len(rawURL) > maxSubscriptionURL:
		return SubscriptionParams{}, fmt.Errorf("url: longer than %d bytes", maxSubscriptionURL)
	case strings.ContainsFunc(rawURL, func(r rune) bool { return r <= ' ' || r == 0x7f || unicode.IsSpace(r) }):
		return SubscriptionParams{}, errors.New("url: has a space or a control character")
	}
	u, err := url.Parse(rawURL)
	switch {
	case err != nil:
		return SubscriptionParams{}, errors.New("url: not a URL") // url's errors quote it
	case u.Scheme != "http" && u.Scheme != "https":
		return SubscriptionParams{}, errors.New("url: not an http or https URL")
	case u.Hostname() == "":
		return SubscriptionParams{}, errors.New("url: has no host")
	}
	sel, err := parseSelect(strings.TrimSpace(p.Select))
	if err != nil {
		return SubscriptionParams{}, err
	}
	return SubscriptionParams{URL: rawURL, Select: sel}, nil
}

func parseSelect(s string) (Select, error) {
	switch s {
	case "", SelectAll:
		return Select{Mode: SelectAll}, nil
	case SelectFirst:
		return Select{Mode: SelectFirst}, nil
	}
	name, ok := strings.CutPrefix(s, SelectName+":")
	switch {
	case !ok:
		return Select{}, fmt.Errorf("select %.40q is none of %q, %q and %q", s, SelectAll, SelectFirst, SelectName+":<text>")
	case name == "":
		return Select{}, errors.New("select: name: is followed by nothing")
	case len(name) > maxSelectName:
		return Select{}, fmt.Errorf("select: the name is longer than %d bytes", maxSelectName)
	}
	return Select{Mode: SelectName, Name: name}, nil
}

// ParseWARPParams reads the params_json of a WARP egress: empty or a JSON
// object, whose fields mean nothing (the device is the node's own, registered
// by the agent).
func ParseWARPParams(raw string) error {
	var p map[string]json.RawMessage
	return decodeParams(raw, &p)
}

// PsiphonParams are the parameters of a PSIPHON egress: {"country": "DE"},
// with "propagation_channel_id" and "sponsor_id" for an operator who has
// Psiphon partner ids.
type PsiphonParams struct {
	Country string // two upper-case letters, one of psiphoncore.Countries
	// PropagationChannelID and SponsorID are both "" (the client's defaults,
	// psiphoncore.DefaultPartnerID) or both 16 hex digits, in upper case.
	PropagationChannelID, SponsorID string
}

// ParsePsiphonParams reads the params_json of a PSIPHON egress: an exit country
// that Psiphon serves, in any letter case, and the partner ids, both or
// neither, each 16 hex digits in any letter case.
func ParsePsiphonParams(raw string) (PsiphonParams, error) {
	var p struct {
		Country              string `json:"country"`
		PropagationChannelID string `json:"propagation_channel_id"`
		SponsorID            string `json:"sponsor_id"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return PsiphonParams{}, err
	}
	c := strings.ToUpper(strings.TrimSpace(p.Country))
	switch {
	case c == "":
		return PsiphonParams{}, errors.New("params_json has no country")
	case !slices.Contains(psiphoncore.Countries(), c):
		return PsiphonParams{}, fmt.Errorf("country %.8q is not one Psiphon can exit in (%s)", c, strings.Join(psiphoncore.Countries(), ", "))
	}
	prop := strings.ToUpper(strings.TrimSpace(p.PropagationChannelID))
	sponsor := strings.ToUpper(strings.TrimSpace(p.SponsorID))
	switch {
	case prop == "" && sponsor == "":
	case prop == "" || sponsor == "":
		return PsiphonParams{}, errors.New("propagation_channel_id and sponsor_id go together: set both or neither")
	case !psiphoncore.ValidPartnerID(prop):
		return PsiphonParams{}, errors.New("propagation_channel_id is not 16 hex digits")
	case !psiphoncore.ValidPartnerID(sponsor):
		return PsiphonParams{}, errors.New("sponsor_id is not 16 hex digits")
	}
	return PsiphonParams{Country: c, PropagationChannelID: prop, SponsorID: sponsor}, nil
}
