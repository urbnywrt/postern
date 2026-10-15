package egress

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/providers"
)

// This file holds the parameters of the egresses: what each kind has, the JSON
// that the node reads (params_json, internal/node/state), what of them an
// answer may show, and the checks of the panel, which are those of the node.

// fieldsOf are the parameters of each kind, by their names in EgressParams. A
// kind that is not here is not a kind.
var fieldsOf = map[string][]string{
	store.EgressKindDirect:           {"interface", "bind_ip"},
	store.EgressKindSOCKS5:           {"addr", "username", "password"},
	store.EgressKindHTTP:             {"addr", "username", "password"},
	store.EgressKindXrayURI:          {"uri"},
	store.EgressKindXraySubscription: {"url", "select"},
	store.EgressKindWARP:             nil,
	store.EgressKindPsiphon:          {"country", "propagation_channel_id", "sponsor_id"},
}

// kindList is the kinds, as an error names them.
const kindList = "direct, socks5, http, xray-uri, xray-subscription, warp or psiphon"

func validKind(kind string) bool {
	_, ok := fieldsOf[kind]
	return ok
}

// The JSON of the parameters of each kind, as the node reads it.
type (
	directJSON struct {
		Interface string `json:"interface,omitempty"`
		BindIP    string `json:"bind_ip,omitempty"`
	}
	proxyJSON struct {
		Addr     string `json:"addr"`
		Username string `json:"username,omitempty"`
		Password string `json:"password,omitempty"`
	}
	uriJSON struct {
		URI string `json:"uri"`
	}
	subscriptionJSON struct {
		URL    string `json:"url"`
		Select string `json:"select"`
	}
	psiphonJSON struct {
		Country              string `json:"country"`
		PropagationChannelID string `json:"propagation_channel_id,omitempty"`
		SponsorID            string `json:"sponsor_id,omitempty"`
	}
)

// errParams is what a check of the parameters says; it never quotes a secret.
var errParams = errors.New("params")

// paramsJSON checks the parameters of a request for an egress of kind and
// returns them as the JSON that the node reads. stored is the JSON of the
// parameters that the egress has, "" for a new one: a secret that p leaves
// empty is the stored one (the share link, the URL of a subscription, and the
// password of a proxy whose address and username stay as they are; with a new
// address or username it has to be given again). The parameters are checked by
// the rules of the node, and a share link by the rules of the providers for the
// address of its server. The error wraps errParams and never quotes a secret.
func paramsJSON(kind string, p *panelv1.EgressParams, stored string) (string, error) {
	allowed, ok := fieldsOf[kind]
	if !ok {
		return "", fmt.Errorf("%w: the kind must be %s", errParams, kindList)
	}
	given := map[string]string{
		"interface": p.GetInterface(), "bind_ip": p.GetBindIp(), "addr": p.GetAddr(), "username": p.GetUsername(),
		"password": p.GetPassword(), "uri": p.GetUri(), "url": p.GetUrl(), "select": p.GetSelect(), "country": p.GetCountry(),
		"propagation_channel_id": p.GetPropagationChannelId(), "sponsor_id": p.GetSponsorId(),
	}
	for _, name := range slices.Sorted(maps.Keys(given)) {
		if given[name] != "" && !slices.Contains(allowed, name) {
			return "", fmt.Errorf("%w: %s does not apply to an egress of kind %s", errParams, name, kind)
		}
	}
	var v any
	switch kind {
	case store.EgressKindDirect:
		v = directJSON{Interface: strings.TrimSpace(p.GetInterface()), BindIP: strings.TrimSpace(p.GetBindIp())}
	case store.EgressKindSOCKS5, store.EgressKindHTTP:
		var old proxyJSON
		_ = json.Unmarshal([]byte(stored), &old) // the stored JSON is the panel's own
		d := proxyJSON{Addr: strings.TrimSpace(p.GetAddr()), Username: p.GetUsername(), Password: p.GetPassword()}
		switch {
		case d.Username == "" && d.Password != "":
			return "", fmt.Errorf("%w: a password needs a username", errParams)
		case d.Username != "" && d.Password == "" && old.Password != "":
			// A stored password goes only where it went: to the same proxy,
			// for the same user. Otherwise the panel would hand it to a proxy
			// that it never was for.
			if d.Addr != old.Addr || d.Username != old.Username {
				return "", fmt.Errorf("%w: password: the address or the username is new, so give the password again "+
					"(a stored password is kept for the same address and username only)", errParams)
			}
			d.Password = old.Password
		}
		v = d
	case store.EgressKindXrayURI:
		var old uriJSON
		_ = json.Unmarshal([]byte(stored), &old)
		v = uriJSON{URI: cmp.Or(strings.TrimSpace(p.GetUri()), old.URI)}
	case store.EgressKindXraySubscription:
		var old subscriptionJSON
		_ = json.Unmarshal([]byte(stored), &old)
		v = subscriptionJSON{
			URL:    cmp.Or(strings.TrimSpace(p.GetUrl()), old.URL),
			Select: cmp.Or(strings.TrimSpace(p.GetSelect()), state.SelectAll),
		}
	case store.EgressKindWARP:
		v = struct{}{}
	case store.EgressKindPsiphon:
		v = psiphonJSON{
			Country:              strings.ToUpper(strings.TrimSpace(p.GetCountry())),
			PropagationChannelID: strings.ToUpper(strings.TrimSpace(p.GetPropagationChannelId())),
			SponsorID:            strings.ToUpper(strings.TrimSpace(p.GetSponsorId())),
		}
	}
	raw, err := marshal(v)
	if err != nil {
		return "", err
	}
	if err := checkParams(kind, raw); err != nil {
		return "", fmt.Errorf("%w: %w", errParams, err)
	}
	return raw, nil
}

// marshal is json.Marshal without the escapes for HTML: a share link keeps its
// & as it is.
func marshal(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

// checkParams checks the JSON of the parameters of an egress of kind by the
// rules of the node (state.Validate takes the same parsers) and of the edge
// for the credentials of a proxy, and the server of a share link by the rules
// of the providers: a node leaves out a member whose server is the loopback or
// a metadata service. No error quotes a secret.
func checkParams(kind, raw string) error {
	switch kind {
	case store.EgressKindDirect:
		_, err := state.ParseDirectParams(raw)
		return err
	case store.EgressKindSOCKS5, store.EgressKindHTTP:
		p, err := state.ParseProxyParams(raw)
		switch {
		case err != nil:
			return err
		case kind == store.EgressKindSOCKS5:
			return rules.CheckSOCKS5Credentials(p.Username, p.Password)
		}
		return rules.CheckHTTPCredentials(p.Username, p.Password)
	case store.EgressKindXrayURI:
		p, err := state.ParseXrayURIParams(raw)
		if err != nil {
			return err
		}
		if err := providers.CheckServerAddress(p.Server.Address); err != nil {
			return fmt.Errorf("uri: the address of the server is %w", err)
		}
		return nil
	case store.EgressKindXraySubscription:
		_, err := state.ParseSubscriptionParams(raw)
		return err
	case store.EgressKindWARP:
		return state.ParseWARPParams(raw)
	case store.EgressKindPsiphon:
		_, err := state.ParsePsiphonParams(raw)
		return err
	}
	return fmt.Errorf("the kind must be %s", kindList)
}

// paramsView is what an answer shows of the parameters of an egress: all but
// the secrets, and whether a proxy has a password.
func paramsView(kind, raw string) (view *panelv1.EgressParams, passwordSet bool) {
	view = &panelv1.EgressParams{}
	switch kind {
	case store.EgressKindDirect:
		var d directJSON
		if json.Unmarshal([]byte(raw), &d) == nil {
			view.Interface, view.BindIp = d.Interface, d.BindIP
		}
	case store.EgressKindSOCKS5, store.EgressKindHTTP:
		var d proxyJSON
		if json.Unmarshal([]byte(raw), &d) == nil {
			view.Addr, view.Username, passwordSet = d.Addr, d.Username, d.Password != ""
		}
	case store.EgressKindXraySubscription:
		var d subscriptionJSON
		if json.Unmarshal([]byte(raw), &d) == nil {
			view.Select = cmp.Or(d.Select, state.SelectAll)
		}
	case store.EgressKindPsiphon:
		var d psiphonJSON
		if json.Unmarshal([]byte(raw), &d) == nil {
			view.Country, view.PropagationChannelId, view.SponsorId = d.Country, d.PropagationChannelID, d.SponsorID
		}
	}
	return view, passwordSet
}

// masked is what an answer shows of the share link of an xray-uri egress or of
// the URL of an xray-subscription egress: the scheme and the host, with the
// port of a share link; "" for the other kinds, and for parameters that cannot
// be read.
func masked(kind, raw string) string {
	switch kind {
	case store.EgressKindXrayURI:
		p, err := state.ParseXrayURIParams(raw)
		if err != nil {
			return ""
		}
		return schemeOf(p.Server) + "://" + net.JoinHostPort(p.Server.Address, strconv.Itoa(int(p.Server.Port)))
	case store.EgressKindXraySubscription:
		p, err := state.ParseSubscriptionParams(raw)
		if err != nil {
			return ""
		}
		u, err := url.Parse(p.URL)
		if err != nil {
			return ""
		}
		return u.Scheme + "://" + u.Host // u.Host leaves the user and the password of a URL out
	}
	return ""
}

// schemeOf is the scheme of the share link of a server.
func schemeOf(s *egressuri.Server) string {
	if s.Protocol == "shadowsocks" {
		return "ss"
	}
	return s.Protocol
}
