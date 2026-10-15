package egress

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// Every kind is made with its parameters, which come back without their
// secrets, and are stored as the JSON that the node reads.
func TestCreateEgressOfEachKind(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n")
	for _, tc := range []struct {
		name     string
		req      *panelv1.CreateEgressRequest
		stored   string // the JSON that the node gets
		view     *panelv1.EgressParams
		masked   string
		password bool
	}{
		{"direct", &panelv1.CreateEgressRequest{Kind: "direct"}, `{}`, &panelv1.EgressParams{}, "", false},
		{"direct through an interface of a node", &panelv1.CreateEgressRequest{
			Kind: "direct", NodeId: n.ID, Params: &panelv1.EgressParams{Interface: " wg0 ", BindIp: "198.51.100.7"},
		}, `{"interface":"wg0","bind_ip":"198.51.100.7"}`, &panelv1.EgressParams{Interface: "wg0", BindIp: "198.51.100.7"}, "", false},
		{"socks5 with a user", &panelv1.CreateEgressRequest{
			Kind: "socks5", Params: &panelv1.EgressParams{Addr: " 198.51.100.9:1080 ", Username: "user", Password: fakePassword},
		}, `{"addr":"198.51.100.9:1080","username":"user","password":"` + fakePassword + `"}`,
			&panelv1.EgressParams{Addr: "198.51.100.9:1080", Username: "user"}, "", true},
		{"http without a user", &panelv1.CreateEgressRequest{
			Kind: "http", Params: &panelv1.EgressParams{Addr: "proxy.example.com:3128"},
		}, `{"addr":"proxy.example.com:3128"}`, &panelv1.EgressParams{Addr: "proxy.example.com:3128"}, "", false},
		{"xray-uri", &panelv1.CreateEgressRequest{
			Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: " " + fakeVLESS + " "},
		}, `{"uri":"` + fakeVLESS + `"}`, &panelv1.EgressParams{}, "vless://vless.example.com:443", false},
		{"xray-uri of trojan on IPv6", &panelv1.CreateEgressRequest{
			Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: fakeTrojan},
		}, `{"uri":"` + fakeTrojan + `"}`, &panelv1.EgressParams{}, "trojan://[2001:db8::7]:8443", false},
		{"xray-subscription of every server", &panelv1.CreateEgressRequest{
			Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL},
		}, `{"url":"` + fakeSubURL + `","select":"all"}`, &panelv1.EgressParams{Select: "all"}, "https://sub.example.com:8443", false},
		{"xray-subscription by name", &panelv1.CreateEgressRequest{
			Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL, Select: "name:Germany"},
		}, `{"url":"` + fakeSubURL + `","select":"name:Germany"}`, &panelv1.EgressParams{Select: "name:Germany"}, "https://sub.example.com:8443", false},
		{"warp", &panelv1.CreateEgressRequest{Kind: "warp"}, `{}`, &panelv1.EgressParams{}, "", false},
		{"psiphon", &panelv1.CreateEgressRequest{
			Kind: "psiphon", Params: &panelv1.EgressParams{Country: "de"},
		}, `{"country":"DE"}`, &panelv1.EgressParams{Country: "DE"}, "", false},
		{"psiphon with partner ids", &panelv1.CreateEgressRequest{
			Kind: "psiphon", Params: &panelv1.EgressParams{Country: "DE", PropagationChannelId: "0123456789abcdef", SponsorId: " FEDCBA9876543210 "},
		}, `{"country":"DE","propagation_channel_id":"0123456789ABCDEF","sponsor_id":"FEDCBA9876543210"}`,
			&panelv1.EgressParams{Country: "DE", PropagationChannelId: "0123456789ABCDEF", SponsorId: "FEDCBA9876543210"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Name = " " + tc.name + " "
			got := e.createEgress(tc.req)
			if got.GetName() != tc.name || got.GetKind() != tc.req.GetKind() || got.GetNodeId() != tc.req.GetNodeId() {
				t.Errorf("egress = %v", got)
			}
			if !proto.Equal(got.GetParams(), tc.view) || got.GetMasked() != tc.masked || got.GetPasswordSet() != tc.password {
				t.Errorf("params %v, masked %q, password set %v; want %v, %q, %v",
					got.GetParams(), got.GetMasked(), got.GetPasswordSet(), tc.view, tc.masked, tc.password)
			}
			if p := e.storedParams(got.GetId()); p != tc.stored {
				t.Errorf("stored parameters %s, want %s", p, tc.stored)
			}
			resp, err := e.egresses.GetEgress(e.ctx, connect.NewRequest(&panelv1.GetEgressRequest{Id: got.GetId()}))
			if err != nil || !proto.Equal(resp.Msg.GetEgress(), got) {
				t.Errorf("GetEgress = %v, %v; want %v", resp.Msg.GetEgress(), err, got)
			}
		})
	}

	list, err := e.egresses.ListEgresses(e.ctx, connect.NewRequest(&panelv1.ListEgressesRequest{}))
	if err != nil || len(list.Msg.GetEgresses()) != 11 {
		t.Fatalf("ListEgresses = %d, %v; want 11", len(list.Msg.GetEgresses()), err)
	}
	// Another node sees the egresses of every node, not those of n.
	other := e.addNode("other")
	list, err = e.egresses.ListEgresses(e.ctx, connect.NewRequest(&panelv1.ListEgressesRequest{NodeId: other.ID}))
	if err != nil || len(list.Msg.GetEgresses()) != 10 || slices.ContainsFunc(list.Msg.GetEgresses(), func(eg *panelv1.Egress) bool { return eg.GetNodeId() != "" }) {
		t.Errorf("ListEgresses of another node = %v, %v; want the 10 of every node", list.Msg.GetEgresses(), err)
	}
	e.assertNoSecretsLogged()
}

func TestCreateEgressRefusesWhatTheNodeWouldNotRun(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("u", 256)
	for _, tc := range []struct {
		name string
		req  *panelv1.CreateEgressRequest
		code connect.Code
		want string
	}{
		{"no name", &panelv1.CreateEgressRequest{Kind: "direct", Name: " "}, connect.CodeInvalidArgument, "name"},
		{"a name of 65 characters", &panelv1.CreateEgressRequest{Kind: "direct", Name: strings.Repeat("я", 65)}, connect.CodeInvalidArgument, "name"},
		{"a kind that does not exist", &panelv1.CreateEgressRequest{Kind: "tor"}, connect.CodeInvalidArgument, "kind"},
		{"no kind", &panelv1.CreateEgressRequest{}, connect.CodeInvalidArgument, "kind"},
		{"a node that does not exist", &panelv1.CreateEgressRequest{Kind: "direct", NodeId: "01K6Y00000000000000000000Z"}, connect.CodeNotFound, "node"},
		{"a parameter of another kind", &panelv1.CreateEgressRequest{Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080", Uri: fakeVLESS}}, connect.CodeInvalidArgument, "uri"},
		{"a parameter of warp", &panelv1.CreateEgressRequest{Kind: "warp", Params: &panelv1.EgressParams{Country: "DE"}}, connect.CodeInvalidArgument, "country"},
		{"direct through a bad interface", &panelv1.CreateEgressRequest{Kind: "direct", Params: &panelv1.EgressParams{Interface: "eth0/1"}}, connect.CodeInvalidArgument, "interface"},
		{"direct from a bad address", &panelv1.CreateEgressRequest{Kind: "direct", Params: &panelv1.EgressParams{BindIp: "x"}}, connect.CodeInvalidArgument, "bind_ip"},
		{"socks5 without an address", &panelv1.CreateEgressRequest{Kind: "socks5"}, connect.CodeInvalidArgument, "addr"},
		{"socks5 with brackets around IPv4", &panelv1.CreateEgressRequest{Kind: "socks5", Params: &panelv1.EgressParams{Addr: "[198.51.100.9]:1080"}}, connect.CodeInvalidArgument, "addr"},
		{"socks5 with a user name of 256 bytes", &panelv1.CreateEgressRequest{Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080", Username: long}}, connect.CodeInvalidArgument, "username"},
		{"a password without a user", &panelv1.CreateEgressRequest{Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080", Password: fakePassword}}, connect.CodeInvalidArgument, "username"},
		{"http with a colon in the user name", &panelv1.CreateEgressRequest{Kind: "http", Params: &panelv1.EgressParams{Addr: "198.51.100.9:3128", Username: "a:b"}}, connect.CodeInvalidArgument, "colon"},
		{"http with a user name of more than 1 KiB", &panelv1.CreateEgressRequest{Kind: "http", Params: &panelv1.EgressParams{Addr: "198.51.100.9:3128", Username: strings.Repeat("u", 1025)}}, connect.CodeInvalidArgument, "username"},
		{"http with a password of more than 1 KiB", &panelv1.CreateEgressRequest{Kind: "http", Params: &panelv1.EgressParams{Addr: "198.51.100.9:3128", Username: "u", Password: strings.Repeat("p", 1025)}}, connect.CodeInvalidArgument, "password"},
		{"xray-uri without a link", &panelv1.CreateEgressRequest{Kind: "xray-uri"}, connect.CodeInvalidArgument, "uri"},
		{"xray-uri of a link that cannot be read", &panelv1.CreateEgressRequest{Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: "vless://" + fakeUUID + "@"}}, connect.CodeInvalidArgument, "uri"},
		{"xray-uri of a scheme that Xray does not take here", &panelv1.CreateEgressRequest{Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: "socks://" + fakeUUID + "@198.51.100.9:1080"}}, connect.CodeInvalidArgument, "uri"},
		{"xray-uri to the loopback", &panelv1.CreateEgressRequest{Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: "vless://" + fakeUUID + "@127.0.0.1:443?type=tcp"}}, connect.CodeInvalidArgument, "uri"},
		{"xray-subscription without a URL", &panelv1.CreateEgressRequest{Kind: "xray-subscription"}, connect.CodeInvalidArgument, "url"},
		{"xray-subscription of an ftp URL", &panelv1.CreateEgressRequest{Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: "ftp://sub.example.com/" + fakeSubToken}}, connect.CodeInvalidArgument, "url"},
		{"xray-subscription with a selection that does not exist", &panelv1.CreateEgressRequest{Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL, Select: "best"}}, connect.CodeInvalidArgument, "select"},
		{"psiphon without a country", &panelv1.CreateEgressRequest{Kind: "psiphon"}, connect.CodeInvalidArgument, "country"},
		{"psiphon out of a country that Psiphon does not serve", &panelv1.CreateEgressRequest{Kind: "psiphon", Params: &panelv1.EgressParams{Country: "ZZ"}}, connect.CodeInvalidArgument, "country"},
		{"psiphon with one partner id", &panelv1.CreateEgressRequest{Kind: "psiphon", Params: &panelv1.EgressParams{Country: "DE", SponsorId: "0123456789ABCDEF"}}, connect.CodeInvalidArgument, "sponsor_id"},
		{"psiphon with a partner id that is not hex", &panelv1.CreateEgressRequest{Kind: "psiphon", Params: &panelv1.EgressParams{Country: "DE", PropagationChannelId: "0123456789ABCDEZ", SponsorId: "0123456789ABCDEF"}}, connect.CodeInvalidArgument, "propagation_channel_id"},
		{"partner ids on another kind", &panelv1.CreateEgressRequest{Kind: "warp", Params: &panelv1.EgressParams{SponsorId: "0123456789ABCDEF"}}, connect.CodeInvalidArgument, "sponsor_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.req.Name == "" {
				tc.req.Name = "egress"
			}
			_, err := e.egresses.CreateEgress(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, tc.code)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			for _, s := range append(slices.Clone(secrets), long) {
				if strings.Contains(err.Error(), s) {
					t.Errorf("the error has a credential in it: %q", err)
				}
			}
		})
	}
	if list, err := e.db.ListEgresses(e.ctx); err != nil || len(list) != 0 {
		t.Errorf("stored egresses = %d, %v; want none", len(list), err)
	}
}

// The credentials of the egresses are sealed in the database, and no answer of
// the panel holds them.
func TestEgressSecretsAreSealedAndNeverReturned(t *testing.T) {
	e := newEnv(t)
	var answers [][]byte
	keep := func(m proto.Message) {
		b, err := protojson.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, b)
	}
	socks := e.createEgress(&panelv1.CreateEgressRequest{Name: "s", Kind: "socks5",
		Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080", Username: "user", Password: fakePassword}})
	uri := e.createEgress(&panelv1.CreateEgressRequest{Name: "u", Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: fakeVLESS}})
	sub := e.createEgress(&panelv1.CreateEgressRequest{Name: "sub", Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL}})
	keep(socks)
	keep(uri)
	keep(sub)
	upd, err := e.egresses.UpdateEgress(e.ctx, connect.NewRequest(&panelv1.UpdateEgressRequest{Id: socks.GetId(), Name: proto.String("renamed")}))
	if err != nil {
		t.Fatalf("UpdateEgress: %v", err)
	}
	keep(upd.Msg)
	list, err := e.egresses.ListEgresses(e.ctx, connect.NewRequest(&panelv1.ListEgressesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	keep(list.Msg)
	val, err := e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{Kind: "xray-uri", Id: uri.GetId()}))
	if err != nil || !val.Msg.GetValid() {
		t.Fatalf("ValidateEgress = %v, %v", val.Msg, err)
	}
	keep(val.Msg)
	for _, a := range answers {
		for _, s := range secrets {
			if bytes.Contains(a, []byte(s)) {
				t.Errorf("an answer holds a credential: %s", a)
			}
		}
	}

	// The database holds them sealed only: the rows, and the file.
	for _, id := range []string{socks.GetId(), uri.GetId(), sub.GetId()} {
		eg, err := e.db.EgressByID(e.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(eg.ParamsEnc) == 0 {
			t.Errorf("egress %s has no sealed parameters", id)
		}
		for _, s := range secrets {
			if bytes.Contains(eg.ParamsEnc, []byte(s)) {
				t.Errorf("the sealed parameters of %s hold a credential", id)
			}
		}
	}
	if err := e.db.Close(); err != nil { // flush the write-ahead log into the file
		t.Fatal(err)
	}
	for _, path := range []string{e.dbPath, e.dbPath + "-wal"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, s := range secrets {
			if bytes.Contains(raw, []byte(s)) {
				t.Errorf("%s holds a credential in plain text", path)
			}
		}
	}
	e.assertNoSecretsLogged()
}

// An update that leaves a secret empty keeps the stored one; an empty username
// takes the password with it.
func TestUpdateEgressKeepsTheSecretsThatItLeavesOut(t *testing.T) {
	e := newEnv(t)
	update := func(id string, params *panelv1.EgressParams) *panelv1.Egress {
		t.Helper()
		resp, err := e.egresses.UpdateEgress(e.ctx, connect.NewRequest(&panelv1.UpdateEgressRequest{Id: id, Params: params}))
		if err != nil {
			t.Fatalf("UpdateEgress: %v", err)
		}
		return resp.Msg.GetEgress()
	}
	socks := e.createEgress(&panelv1.CreateEgressRequest{Name: "s", Kind: "socks5",
		Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080", Username: "user", Password: fakePassword}})
	stored := `{"addr":"198.51.100.9:1080","username":"user","password":"` + fakePassword + `"}`
	// The same proxy and user keep the password.
	got := update(socks.GetId(), &panelv1.EgressParams{Addr: " 198.51.100.9:1080 ", Username: "user"})
	if e.storedParams(socks.GetId()) != stored || !got.GetPasswordSet() {
		t.Errorf("after an update without a password: %s, password set %v", e.storedParams(socks.GetId()), got.GetPasswordSet())
	}
	// A stored password does not follow a new address or a new user: it has to
	// be given again (an admin could otherwise send it to a proxy of their own).
	for _, params := range []*panelv1.EgressParams{
		{Addr: "198.51.100.10:1080", Username: "user"},
		{Addr: "198.51.100.9:1080", Username: "other"},
	} {
		_, err := e.egresses.UpdateEgress(e.ctx, connect.NewRequest(&panelv1.UpdateEgressRequest{Id: socks.GetId(), Params: params}))
		wantCode(t, err, connect.CodeInvalidArgument)
		if !strings.Contains(err.Error(), "give the password again") {
			t.Errorf("error %q does not ask for the password", err)
		}
		if e.storedParams(socks.GetId()) != stored {
			t.Errorf("a refused update changed the parameters: %s", e.storedParams(socks.GetId()))
		}
		resp, err := e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{Kind: "socks5", Id: socks.GetId(), Params: params}))
		if err != nil || resp.Msg.GetValid() || !strings.Contains(resp.Msg.GetProblem(), "give the password again") {
			t.Errorf("ValidateEgress with a new address or user and no password = %v, %v", resp.Msg, err)
		}
	}
	got = update(socks.GetId(), &panelv1.EgressParams{Addr: "198.51.100.10:1080", Username: "other", Password: fakePassword + "2"})
	if want := `{"addr":"198.51.100.10:1080","username":"other","password":"` + fakePassword + `2"}`; e.storedParams(socks.GetId()) != want || !got.GetPasswordSet() {
		t.Errorf("after an update of the address with a password: %s, password set %v", e.storedParams(socks.GetId()), got.GetPasswordSet())
	}
	got = update(socks.GetId(), &panelv1.EgressParams{Addr: "198.51.100.10:1080"})
	if want := `{"addr":"198.51.100.10:1080"}`; e.storedParams(socks.GetId()) != want || got.GetPasswordSet() {
		t.Errorf("after an update without a user: %s, password set %v", e.storedParams(socks.GetId()), got.GetPasswordSet())
	}
	// Without a stored password there is nothing to keep, and nothing to ask for.
	got = update(socks.GetId(), &panelv1.EgressParams{Addr: "198.51.100.11:1080", Username: "nobody"})
	if want := `{"addr":"198.51.100.11:1080","username":"nobody"}`; e.storedParams(socks.GetId()) != want || got.GetPasswordSet() {
		t.Errorf("after an update of a user without a password: %s, password set %v", e.storedParams(socks.GetId()), got.GetPasswordSet())
	}

	uri := e.createEgress(&panelv1.CreateEgressRequest{Name: "u", Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: fakeVLESS}})
	update(uri.GetId(), &panelv1.EgressParams{})
	if want := `{"uri":"` + fakeVLESS + `"}`; e.storedParams(uri.GetId()) != want {
		t.Errorf("the share link after an update without one: %s", e.storedParams(uri.GetId()))
	}
	got = update(uri.GetId(), &panelv1.EgressParams{Uri: fakeTrojan})
	if got.GetMasked() != "trojan://[2001:db8::7]:8443" {
		t.Errorf("masked = %q after a new link", got.GetMasked())
	}

	sub := e.createEgress(&panelv1.CreateEgressRequest{Name: "sub", Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL}})
	update(sub.GetId(), &panelv1.EgressParams{Select: "first"})
	if want := `{"url":"` + fakeSubURL + `","select":"first"}`; e.storedParams(sub.GetId()) != want {
		t.Errorf("the subscription after an update of its selection: %s", e.storedParams(sub.GetId()))
	}

	// The kind of the egress decides what may change: a parameter that it does
	// not have is refused, and so is an egress that does not exist.
	_, err := e.egresses.UpdateEgress(e.ctx, connect.NewRequest(&panelv1.UpdateEgressRequest{Id: sub.GetId(), Params: &panelv1.EgressParams{Country: "DE"}}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.egresses.UpdateEgress(e.ctx, connect.NewRequest(&panelv1.UpdateEgressRequest{Id: "01K6Y00000000000000000000Z", Name: proto.String("x")}))
	wantCode(t, err, connect.CodeNotFound)
	e.assertNoSecretsLogged()
}

func TestDeleteEgress(t *testing.T) {
	e := newEnv(t)
	a := e.createEgress(&panelv1.CreateEgressRequest{Name: "a", Kind: "direct"})
	b := e.createEgress(&panelv1.CreateEgressRequest{Name: "b", Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080"}})
	c := e.createChain(&panelv1.CreateChainRequest{Name: "main", MemberIds: []string{a.GetId(), b.GetId()}})

	_, err := e.egresses.DeleteEgress(e.ctx, connect.NewRequest(&panelv1.DeleteEgressRequest{Id: b.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "main") {
		t.Errorf("error %q does not name the chain", err)
	}
	if _, err := e.chains.UpdateChain(e.ctx, connect.NewRequest(&panelv1.UpdateChainRequest{
		Id: c.GetId(), Members: &panelv1.ChainMembers{Ids: []string{a.GetId()}},
	})); err != nil {
		t.Fatalf("UpdateChain: %v", err)
	}
	if _, err := e.egresses.DeleteEgress(e.ctx, connect.NewRequest(&panelv1.DeleteEgressRequest{Id: b.GetId()})); err != nil {
		t.Fatalf("DeleteEgress of an egress that no chain has: %v", err)
	}
	_, err = e.egresses.GetEgress(e.ctx, connect.NewRequest(&panelv1.GetEgressRequest{Id: b.GetId()}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = e.egresses.DeleteEgress(e.ctx, connect.NewRequest(&panelv1.DeleteEgressRequest{Id: b.GetId()}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestChains(t *testing.T) {
	e := newEnv(t)
	// The own egress of n goes out through an interface (egress-interface).
	n := e.addNode("n", proxies.CapEgressInterface)
	other := e.addNode("other")
	a := e.createEgress(&panelv1.CreateEgressRequest{Name: "a", Kind: "direct"})
	b := e.createEgress(&panelv1.CreateEgressRequest{Name: "b", Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080"}})
	own := e.createEgress(&panelv1.CreateEgressRequest{Name: "own", Kind: "direct", NodeId: n.ID, Params: &panelv1.EgressParams{Interface: "wg0"}})

	c := e.createChain(&panelv1.CreateChainRequest{
		Name: " main ", MemberIds: []string{b.GetId(), a.GetId()},
		Check: &panelv1.ChainCheck{IntervalSeconds: 5, TimeoutSeconds: 3, DcAddrs: []string{"149.154.167.51:443"}},
	})
	if c.GetName() != "main" || !slices.Equal(c.GetMemberIds(), []string{b.GetId(), a.GetId()}) || c.GetCheck().GetIntervalSeconds() != 5 || c.GetNodeId() != "" {
		t.Errorf("chain = %v", c)
	}
	ownChain := e.createChain(&panelv1.CreateChainRequest{Name: "own", NodeId: n.ID, MemberIds: []string{own.GetId(), a.GetId()}})

	for _, tc := range []struct {
		name string
		req  *panelv1.CreateChainRequest
		code connect.Code
		want string
	}{
		{"no members", &panelv1.CreateChainRequest{Name: "x"}, connect.CodeInvalidArgument, "member"},
		{"a member twice", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{a.GetId(), a.GetId()}}, connect.CodeInvalidArgument, "twice"},
		{"a member that does not exist", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{"01K6Y00000000000000000000Z"}}, connect.CodeNotFound, "egress"},
		{"an egress of a node in a chain of every node", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{own.GetId()}}, connect.CodeInvalidArgument, "node"},
		{"an egress of a node in a chain of another node", &panelv1.CreateChainRequest{Name: "x", NodeId: other.ID, MemberIds: []string{own.GetId()}}, connect.CodeInvalidArgument, "node"},
		{"a node that does not exist", &panelv1.CreateChainRequest{Name: "x", NodeId: "01K6Y00000000000000000000Z", MemberIds: []string{a.GetId()}}, connect.CodeNotFound, "node"},
		{"no name", &panelv1.CreateChainRequest{MemberIds: []string{a.GetId()}}, connect.CodeInvalidArgument, "name"},
		{"an interval of two hours", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{a.GetId()}, Check: &panelv1.ChainCheck{IntervalSeconds: 7200}}, connect.CodeInvalidArgument, "interval"},
		{"a timeout of two minutes", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{a.GetId()}, Check: &panelv1.ChainCheck{TimeoutSeconds: 120}}, connect.CodeInvalidArgument, "timeout"},
		{"a threshold of 101", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{a.GetId()}, Check: &panelv1.ChainCheck{FailThreshold: 101}}, connect.CodeInvalidArgument, "threshold"},
		{"a datacenter that is not host:port", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{a.GetId()}, Check: &panelv1.ChainCheck{DcAddrs: []string{"149.154.167.51"}}}, connect.CodeInvalidArgument, "dc_addrs"},
		{"17 datacenters", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{a.GetId()}, Check: &panelv1.ChainCheck{DcAddrs: slices.Repeat([]string{"149.154.167.51:443"}, 17)}}, connect.CodeInvalidArgument, "dc_addrs"},
		// The node refuses a space in a host that is not ASCII, which the edge's
		// parser alone would take.
		{"a datacenter with a space that is not ASCII", &panelv1.CreateChainRequest{Name: "x", MemberIds: []string{a.GetId()}, Check: &panelv1.ChainCheck{DcAddrs: []string{"dc one.example:443"}}}, connect.CodeInvalidArgument, "dc_addrs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.chains.CreateChain(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, tc.code)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	// A chain that a node uses: its changes reach the node.
	e.setDefaultChain(n.ID, c.GetId())
	gen, genOther := e.generation(n.ID), e.generation(other.ID)
	upd, err := e.chains.UpdateChain(e.ctx, connect.NewRequest(&panelv1.UpdateChainRequest{
		Id: c.GetId(), Members: &panelv1.ChainMembers{Ids: []string{a.GetId(), b.GetId()}},
	}))
	if err != nil {
		t.Fatalf("UpdateChain: %v", err)
	}
	if !slices.Equal(upd.Msg.GetChain().GetMemberIds(), []string{a.GetId(), b.GetId()}) || e.generation(n.ID) != gen+1 || e.generation(other.ID) != genOther {
		t.Errorf("after a new order: %v, generations %d→%d, %d→%d", upd.Msg.GetChain().GetMemberIds(), gen, e.generation(n.ID), genOther, e.generation(other.ID))
	}
	st, err := e.states.Build(e.ctx, n.ID, 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	chain := st.GetChains()[slices.IndexFunc(st.GetChains(), func(ch *nodev1.EgressChain) bool { return ch.GetId() == c.GetId() })]
	if !slices.Equal(chain.GetMemberEgressIds(), []string{a.GetId(), b.GetId()}) || chain.GetCheck().GetIntervalSeconds() != 5 {
		t.Errorf("the chain in the state of the node = %v", chain)
	}
	// A rename changes no state.
	if _, err := e.chains.UpdateChain(e.ctx, connect.NewRequest(&panelv1.UpdateChainRequest{Id: c.GetId(), Name: proto.String("renamed")})); err != nil || e.generation(n.ID) != gen+1 {
		t.Errorf("a rename: %v, generation %d", err, e.generation(n.ID))
	}

	// Who uses a chain is listed with it, and keeps it from being deleted.
	l, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443}))
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: n.ID, ListenerId: l.Msg.GetListener().GetId(), Domain: "own.example.com",
		EgressScopeChains: map[string]string{"fetch": ownChain.GetId()},
	}))
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	list, err := e.chains.ListChains(e.ctx, connect.NewRequest(&panelv1.ListChainsRequest{NodeId: other.ID}))
	if err != nil || len(list.Msg.GetChains()) != 1 || list.Msg.GetChains()[0].GetId() != c.GetId() {
		t.Fatalf("ListChains of another node = %v, %v; want main alone", list.Msg.GetChains(), err)
	}
	if got := list.Msg.GetChains()[0].GetDefaultOf(); !slices.Equal(got, []string{n.ID}) {
		t.Errorf("default_of = %v, want n", got)
	}
	got, err := e.chains.GetChain(e.ctx, connect.NewRequest(&panelv1.GetChainRequest{Id: ownChain.GetId()}))
	if err != nil || !slices.Equal(got.Msg.GetChain().GetProxyIds(), []string{p.Msg.GetProxy().GetId()}) {
		t.Errorf("GetChain = %v, %v; want the proxy among its users", got.Msg.GetChain(), err)
	}
	for _, id := range []string{c.GetId(), ownChain.GetId()} {
		_, err := e.chains.DeleteChain(e.ctx, connect.NewRequest(&panelv1.DeleteChainRequest{Id: id}))
		wantCode(t, err, connect.CodeFailedPrecondition)
	}
	e.setDefaultChain(n.ID, "")
	if _, err := e.chains.DeleteChain(e.ctx, connect.NewRequest(&panelv1.DeleteChainRequest{Id: c.GetId()})); err != nil {
		t.Errorf("DeleteChain of a chain that nothing uses: %v", err)
	}
	_, err = e.chains.GetChain(e.ctx, connect.NewRequest(&panelv1.GetChainRequest{Id: c.GetId()}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestSetNodeDefaultChain(t *testing.T) {
	e := newEnv(t)
	old := e.addNode("old one")
	current := e.addNode("current", proxies.CapEgressXray)
	other := e.addNode("other")
	uri := e.createEgress(&panelv1.CreateEgressRequest{Name: "u", Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: fakeVLESS}})
	xray := e.createChain(&panelv1.CreateChainRequest{Name: "xray", MemberIds: []string{uri.GetId()}})
	direct := e.createEgress(&panelv1.CreateEgressRequest{Name: "d", Kind: "direct", NodeId: other.ID})
	ownChain := e.createChain(&panelv1.CreateChainRequest{Name: "own", NodeId: other.ID, MemberIds: []string{direct.GetId()}})

	gen := e.generation(old.ID)
	_, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: old.ID, ChainId: xray.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "upgrade node old one to use Xray egresses (egress-xray)") {
		t.Errorf("error %q does not ask to upgrade the node", err)
	}
	if e.generation(old.ID) != gen || e.node(old.ID).DefaultChainID != "" {
		t.Error("a refused change was stored")
	}

	gen = e.generation(current.ID)
	resp, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: current.ID, ChainId: xray.GetId()}))
	if err != nil {
		t.Fatalf("SetNodeDefaultChain: %v", err)
	}
	if resp.Msg.GetNode().GetDefaultChainId() != xray.GetId() || e.generation(current.ID) != gen+1 || !slices.Contains(e.notes.got(), current.ID) {
		t.Errorf("node %v, generation %d → %d", resp.Msg.GetNode(), gen, e.generation(current.ID))
	}
	st, err := e.states.Build(e.ctx, current.ID, 1)
	if err != nil || st.GetSettings().GetDefaultChainId() != xray.GetId() {
		t.Fatalf("Build = %v, %v", st.GetSettings(), err)
	}
	// The same again changes nothing.
	if _, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: current.ID, ChainId: xray.GetId()})); err != nil || e.generation(current.ID) != gen+1 {
		t.Errorf("the same chain again: %v, generation %d", err, e.generation(current.ID))
	}

	_, err = e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: current.ID, ChainId: ownChain.GetId()}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: current.ID, ChainId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)

	// Back to going out directly.
	e.setDefaultChain(current.ID, "")
	if st, err := e.states.Build(e.ctx, current.ID, 1); err != nil || st.GetSettings().GetDefaultChainId() != proxies.ImplicitChainID {
		t.Errorf("after no default chain: %v, %v", st.GetSettings(), err)
	}
	// A node of the baseline takes a chain of its own, of a direct egress from
	// its own node, as its default chain: it asks for no capability.
	e.setDefaultChain(other.ID, ownChain.GetId())
	if e.node(other.ID).DefaultChainID != ownChain.GetId() {
		t.Error("the node did not take its own chain")
	}
}

func TestSetNodeDnsMode(t *testing.T) {
	e := newEnv(t)
	old := e.addNode("old one")
	current := e.addNode("current", proxies.CapDNSForwarder)

	_, err := e.egresses.SetNodeDnsMode(e.ctx, connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: old.ID, DnsMode: "doh"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "upgrade node old one to use the DNS forwarder of the edge (dns-forwarder)") {
		t.Errorf("error %q does not ask to upgrade the node", err)
	}
	// The resolver of the host is what an old node has anyway.
	gen := e.generation(old.ID)
	resp, err := e.egresses.SetNodeDnsMode(e.ctx, connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: old.ID, DnsMode: "system"}))
	if err != nil || resp.Msg.GetNode().GetDnsMode() != "system" || e.generation(old.ID) != gen+1 {
		t.Errorf("system on an old node: %v, %v, generation %d → %d", resp.Msg.GetNode(), err, gen, e.generation(old.ID))
	}
	gen = e.generation(current.ID)
	if _, err := e.egresses.SetNodeDnsMode(e.ctx, connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: current.ID, DnsMode: "doh"})); err != nil {
		t.Fatalf("doh on a node with the forwarder: %v", err)
	}
	if st, err := e.states.Build(e.ctx, current.ID, 1); err != nil || st.GetSettings().GetDnsMode() != "doh" || e.generation(current.ID) != gen+1 {
		t.Errorf("the state = %v, %v", st.GetSettings(), err)
	}
	_, err = e.egresses.SetNodeDnsMode(e.ctx, connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: current.ID, DnsMode: "dot"}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.egresses.SetNodeDnsMode(e.ctx, connect.NewRequest(&panelv1.SetNodeDnsModeRequest{NodeId: "01K6Y00000000000000000000Z", DnsMode: "system"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestRefreshSubscription(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n", proxies.CapEgressXray)
	idle := e.addNode("idle", proxies.CapEgressXray)
	sub := e.createEgress(&panelv1.CreateEgressRequest{Name: "sub", Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL}})
	c := e.createChain(&panelv1.CreateChainRequest{Name: "subs", MemberIds: []string{sub.GetId()}})
	e.setDefaultChain(n.ID, c.GetId())
	gen, genIdle := e.generation(n.ID), e.generation(idle.ID)

	resp, err := e.egresses.RefreshSubscription(e.ctx, connect.NewRequest(&panelv1.RefreshSubscriptionRequest{Id: sub.GetId()}))
	if err != nil {
		t.Fatalf("RefreshSubscription: %v", err)
	}
	if !slices.Equal(resp.Msg.GetNodeIds(), []string{n.ID}) || e.generation(n.ID) != gen+1 || e.generation(idle.ID) != genIdle {
		t.Errorf("nodes %v, generations %d → %d, %d → %d", resp.Msg.GetNodeIds(), gen, e.generation(n.ID), genIdle, e.generation(idle.ID))
	}
	st, err := e.states.Build(e.ctx, n.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, eg := range st.GetEgresses() {
		if eg.GetId() == sub.GetId() && eg.GetRefreshNonce() != 1 {
			t.Errorf("refresh nonce = %d, want 1", eg.GetRefreshNonce())
		}
	}
	socks := e.createEgress(&panelv1.CreateEgressRequest{Name: "s", Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080"}})
	_, err = e.egresses.RefreshSubscription(e.ctx, connect.NewRequest(&panelv1.RefreshSubscriptionRequest{Id: socks.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	_, err = e.egresses.RefreshSubscription(e.ctx, connect.NewRequest(&panelv1.RefreshSubscriptionRequest{Id: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

// A change of an egress or a chain that a node uses is judged by that node: a
// chain of a baseline node that gets an Xray member is refused.
func TestChangesAreJudgedByTheNodesThatTheyReach(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("old one")
	d := e.createEgress(&panelv1.CreateEgressRequest{Name: "d", Kind: "direct"})
	c := e.createChain(&panelv1.CreateChainRequest{Name: "c", MemberIds: []string{d.GetId()}})
	e.setDefaultChain(n.ID, c.GetId())
	uri := e.createEgress(&panelv1.CreateEgressRequest{Name: "u", Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: fakeVLESS}})
	gen := e.generation(n.ID)
	_, err := e.chains.UpdateChain(e.ctx, connect.NewRequest(&panelv1.UpdateChainRequest{
		Id: c.GetId(), Members: &panelv1.ChainMembers{Ids: []string{d.GetId(), uri.GetId()}},
	}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "upgrade node old one") || e.generation(n.ID) != gen {
		t.Errorf("error %q, generation %d → %d", err, gen, e.generation(n.ID))
	}
	if got, err := e.db.ChainByID(e.ctx, c.GetId()); err != nil || len(got.Members) != 1 {
		t.Errorf("the chain after a refused change = %v, %v", got, err)
	}
}

// A direct egress through an interface is refused on a node of slice 1, which
// would refuse its whole state for it (Ruling S2-19), and taken by a node that
// reports egress-interface. One from an address only needs nothing.
func TestInterfaceEgressNeedsTheCapability(t *testing.T) {
	e := newEnv(t)
	old := e.addNode("old one")
	current := e.addNode("current", proxies.CapEgressInterface)
	wg := e.createEgress(&panelv1.CreateEgressRequest{Name: "wg", Kind: "direct", Params: &panelv1.EgressParams{Interface: "wg0"}})
	viaWG := e.createChain(&panelv1.CreateChainRequest{Name: "through wg0", MemberIds: []string{wg.GetId()}})
	from := e.createEgress(&panelv1.CreateEgressRequest{Name: "from", Kind: "direct", Params: &panelv1.EgressParams{BindIp: "198.51.100.7"}})
	fromAddr := e.createChain(&panelv1.CreateChainRequest{Name: "from an address", MemberIds: []string{from.GetId()}})

	gen := e.generation(old.ID)
	_, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: old.ID, ChainId: viaWG.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "old one") || !strings.Contains(err.Error(), "(egress-interface)") {
		t.Errorf("error %q does not name the node and the capability", err)
	}
	if e.generation(old.ID) != gen || e.node(old.ID).DefaultChainID != "" {
		t.Error("a refused change was stored")
	}
	e.setDefaultChain(old.ID, fromAddr.GetId())
	e.setDefaultChain(current.ID, viaWG.GetId())
	if e.node(current.ID).DefaultChainID != viaWG.GetId() {
		t.Error("the node that reports egress-interface did not take the chain")
	}
}

// A node that has never connected has reported no capabilities yet: a change
// that needs one says so, rather than asking to upgrade a node that may well be
// of this version.
func TestNodeThatHasNotConnectedHasNotReportedItsCapabilities(t *testing.T) {
	e := newEnv(t)
	fresh := &store.Node{Name: "fresh", MgmtHost: "198.51.100.1", MgmtPort: 61000}
	if err := e.db.CreateNode(e.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	uri := e.createEgress(&panelv1.CreateEgressRequest{Name: "u", Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: fakeVLESS}})
	xray := e.createChain(&panelv1.CreateChainRequest{Name: "xray", MemberIds: []string{uri.GetId()}})
	_, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: fresh.ID, ChainId: xray.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "node fresh has not reported its capabilities yet") || strings.Contains(err.Error(), "upgrade") {
		t.Errorf("error %q, want that the node has not reported its capabilities yet", err)
	}
	if !strings.Contains(err.Error(), "(egress-xray)") {
		t.Errorf("error %q does not name the capability", err)
	}
}

func TestValidateEgress(t *testing.T) {
	e := newEnv(t)
	resp, err := e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{
		Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: fakeVLESS},
	}))
	if err != nil {
		t.Fatalf("ValidateEgress: %v", err)
	}
	want := &panelv1.ValidateEgressResponse{Valid: true, Masked: "vless://vless.example.com:443", Protocol: "vless", Security: "reality", Network: "tcp"}
	if !proto.Equal(resp.Msg, want) {
		t.Errorf("ValidateEgress = %v, want %v", resp.Msg, want)
	}
	resp, err = e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{
		Kind: "xray-uri", Params: &panelv1.EgressParams{Uri: "vless://" + fakeUUID + "@"},
	}))
	if err != nil || resp.Msg.GetValid() || !strings.Contains(resp.Msg.GetProblem(), "uri") || strings.Contains(resp.Msg.GetProblem(), fakeUUID) {
		t.Errorf("ValidateEgress of a bad link = %v, %v", resp.Msg, err)
	}
	resp, err = e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{
		Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL, Select: "first"},
	}))
	if err != nil || !resp.Msg.GetValid() || resp.Msg.GetMasked() != "https://sub.example.com:8443" {
		t.Errorf("ValidateEgress of a subscription = %v, %v", resp.Msg, err)
	}
	// With the id of an egress, the secrets that it leaves out are the stored ones.
	socks := e.createEgress(&panelv1.CreateEgressRequest{Name: "s", Kind: "socks5",
		Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080", Username: "user", Password: fakePassword}})
	resp, err = e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{
		Kind: "socks5", Id: socks.GetId(), Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080", Username: "user"},
	}))
	if err != nil || !resp.Msg.GetValid() {
		t.Errorf("ValidateEgress with the id of an egress = %v, %v", resp.Msg, err)
	}
	_, err = e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{Kind: "socks5", Id: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
	resp, err = e.egresses.ValidateEgress(e.ctx, connect.NewRequest(&panelv1.ValidateEgressRequest{Kind: "tor"}))
	if err != nil || resp.Msg.GetValid() || !strings.Contains(resp.Msg.GetProblem(), "kind") {
		t.Errorf("ValidateEgress of an unknown kind = %v, %v", resp.Msg, err)
	}
}

func TestGetNodeEgressHealth(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n", proxies.CapEgressXray, proxies.CapEgressWARP)
	sub := e.createEgress(&panelv1.CreateEgressRequest{Name: "Subscription", Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL}})
	warp := e.createEgress(&panelv1.CreateEgressRequest{Name: "WARP", Kind: "warp"})
	c := e.createChain(&panelv1.CreateChainRequest{Name: "Main", MemberIds: []string{sub.GetId(), warp.GetId()}})
	e.setDefaultChain(n.ID, c.GetId())
	e.setStatus(n.ID, store.NodeStatusOnline)

	resp, err := e.egresses.GetNodeEgressHealth(e.ctx, connect.NewRequest(&panelv1.GetNodeEgressHealthRequest{NodeId: n.ID}))
	before := &panelv1.GetNodeEgressHealthResponse{NodeStatus: store.NodeStatusOnline, Stale: true}
	if err != nil || !proto.Equal(resp.Msg, before) {
		t.Fatalf("health before a report = %v, %v; want %v", resp.Msg, err, before)
	}
	at := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	report := &nodev1.StateReport{Egress: []*nodev1.EgressMemberHealth{
		{ChainId: c.GetId(), MemberKey: sub.GetId() + "/0123456789ab", Status: "up", LatencyMs: 87, ExitIp: "198.51.100.20", CheckedUnix: at.Unix() - 3},
		{ChainId: c.GetId(), MemberKey: warp.GetId() + "/warp", Status: "down", CheckedUnix: at.Unix() - 3},
		{ChainId: "default", MemberKey: "direct", Status: "unknown"},
		{ChainId: "01K6Y0000000000000000000C9", MemberKey: "01K6Y0000000000000000000E9", Status: "up"},
	}}
	if err := e.ingest.OnWatch(e.ctx, n.ID, &nodev1.WatchResponse{Seq: 9, TsUnix: at.Unix(), Payload: &nodev1.WatchResponse_State{State: report}}); err != nil {
		t.Fatal(err)
	}
	resp, err = e.egresses.GetNodeEgressHealth(e.ctx, connect.NewRequest(&panelv1.GetNodeEgressHealthRequest{NodeId: n.ID}))
	if err != nil {
		t.Fatalf("GetNodeEgressHealth: %v", err)
	}
	want := &panelv1.GetNodeEgressHealthResponse{
		ReportedUnix: at.Unix(),
		NodeStatus:   store.NodeStatusOnline,
		Members: []*panelv1.EgressMemberHealth{
			{ChainId: c.GetId(), ChainName: "Main", EgressId: sub.GetId(), EgressName: "Subscription", EgressKind: "xray-subscription",
				Member: "0123456789ab", Status: "up", LatencyMs: 87, ExitIp: "198.51.100.20", CheckedUnix: at.Unix() - 3},
			{ChainId: c.GetId(), ChainName: "Main", EgressId: warp.GetId(), EgressName: "WARP", EgressKind: "warp",
				Member: "warp", Status: "down", CheckedUnix: at.Unix() - 3},
			{ChainId: "default", EgressId: "direct", EgressKind: "direct", Status: "unknown"},
			{ChainId: "01K6Y0000000000000000000C9", EgressId: "01K6Y0000000000000000000E9", Status: "up"},
		},
	}
	if !proto.Equal(resp.Msg, want) {
		t.Errorf("GetNodeEgressHealth = %v\nwant %v", resp.Msg, want)
	}
	_, err = e.egresses.GetNodeEgressHealth(e.ctx, connect.NewRequest(&panelv1.GetNodeEgressHealthRequest{NodeId: "01K6Y00000000000000000000Z"}))
	wantCode(t, err, connect.CodeNotFound)
}

// Health that says nothing about now is marked stale: the whole report when
// the node is not online or the report is old, a member when its last check
// is old. Old is more than three intervals of the checks of the node, and at
// least two minutes.
func TestNodeEgressHealthSaysWhatIsStale(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n", proxies.CapEgressXray, proxies.CapEgressWARP)
	sub := e.createEgress(&panelv1.CreateEgressRequest{Name: "sub", Kind: "xray-subscription", Params: &panelv1.EgressParams{Url: fakeSubURL}})
	warp := e.createEgress(&panelv1.CreateEgressRequest{Name: "warp", Kind: "warp"})
	c := e.createChain(&panelv1.CreateChainRequest{Name: "Main", MemberIds: []string{sub.GetId(), warp.GetId()}})
	e.setDefaultChain(n.ID, c.GetId())
	e.setStatus(n.ID, store.NodeStatusOnline)
	now := time.Now().Truncate(time.Second)
	e.svc.now = func() time.Time { return now }

	seq := uint64(0)
	report := func(at time.Time, members ...*nodev1.EgressMemberHealth) {
		t.Helper()
		seq++
		ev := &nodev1.WatchResponse{Seq: seq, TsUnix: at.Unix(), Payload: &nodev1.WatchResponse_State{State: &nodev1.StateReport{Egress: members}}}
		if err := e.ingest.OnWatch(e.ctx, n.ID, ev); err != nil {
			t.Fatal(err)
		}
	}
	member := func(id string, checked time.Duration) *nodev1.EgressMemberHealth {
		m := &nodev1.EgressMemberHealth{ChainId: c.GetId(), MemberKey: id, Status: "up"}
		if checked > 0 {
			m.CheckedUnix = now.Add(-checked).Unix()
		}
		return m
	}
	health := func() (bool, []bool) {
		t.Helper()
		resp, err := e.egresses.GetNodeEgressHealth(e.ctx, connect.NewRequest(&panelv1.GetNodeEgressHealthRequest{NodeId: n.ID}))
		if err != nil {
			t.Fatal(err)
		}
		var members []bool
		for _, m := range resp.Msg.GetMembers() {
			members = append(members, m.GetStale())
		}
		return resp.Msg.GetStale(), members
	}
	reportAll := func(at time.Time) {
		report(at, member(sub.GetId()+"/0123456789ab", 30*time.Second), member(warp.GetId()+"/warp", 200*time.Second), member(sub.GetId()+"/ba9876543210", 0))
	}

	// The default checks every 30 s: stale after 120 s.
	reportAll(now.Add(-10 * time.Second))
	if stale, members := health(); stale || !slices.Equal(members, []bool{false, true, false}) {
		t.Errorf("checks every 30 s: report stale %v, members %v; want false, [false true false]", stale, members)
	}
	// Checks every 100 s: stale after 300 s.
	if _, err := e.chains.UpdateChain(e.ctx, connect.NewRequest(&panelv1.UpdateChainRequest{Id: c.GetId(), Check: &panelv1.ChainCheck{IntervalSeconds: 100}})); err != nil {
		t.Fatal(err)
	}
	if stale, members := health(); stale || !slices.Equal(members, []bool{false, false, false}) {
		t.Errorf("checks every 100 s: report stale %v, members %v; want false, all fresh", stale, members)
	}
	// A report older than that says nothing of now.
	reportAll(now.Add(-400 * time.Second))
	if stale, members := health(); !stale || !slices.Equal(members, []bool{true, true, true}) {
		t.Errorf("an old report: stale %v, members %v; want all stale", stale, members)
	}
	// Nor does one of a node that is not online.
	reportAll(now.Add(-10 * time.Second))
	e.setStatus(n.ID, store.NodeStatusOffline)
	if stale, members := health(); !stale || !slices.Equal(members, []bool{true, true, true}) {
		t.Errorf("an offline node: stale %v, members %v; want all stale", stale, members)
	}
	resp, err := e.egresses.GetNodeEgressHealth(e.ctx, connect.NewRequest(&panelv1.GetNodeEgressHealthRequest{NodeId: n.ID}))
	if err != nil || resp.Msg.GetNodeStatus() != store.NodeStatusOffline {
		t.Errorf("node status = %q, %v; want offline", resp.Msg.GetNodeStatus(), err)
	}
}

// Parameters that cannot be opened (another master key) are logged once per
// call, not once per egress.
func TestParamsThatCannotBeOpenedAreLoggedOncePerCall(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"a", "b", "c"} {
		eg := e.createEgress(&panelv1.CreateEgressRequest{Name: name, Kind: "socks5", Params: &panelv1.EgressParams{Addr: "198.51.100.9:1080"}})
		sealed, err := proxies.SealEgressParams(e.key, "another egress", `{"addr":"198.51.100.9:1080"}`)
		if err != nil {
			t.Fatal(err)
		}
		e.exec(`UPDATE egresses SET params_enc = ? WHERE id = ?`, sealed, eg.GetId())
	}
	resp, err := e.egresses.ListEgresses(e.ctx, connect.NewRequest(&panelv1.ListEgressesRequest{}))
	if err != nil || len(resp.Msg.GetEgresses()) != 3 {
		t.Fatalf("ListEgresses = %v, %v", resp.Msg, err)
	}
	if n := strings.Count(e.logs.String(), "could not open the parameters"); n != 1 {
		t.Errorf("%d log lines about parameters that cannot be opened, want 1", n)
	}
}

func TestEgressServicesNeedASession(t *testing.T) {
	e := newEnv(t)
	_, err := e.anonEgresses.ListEgresses(e.ctx, connect.NewRequest(&panelv1.ListEgressesRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = e.anonEgresses.CreateEgress(e.ctx, connect.NewRequest(&panelv1.CreateEgressRequest{Name: "x", Kind: "direct"}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = e.anonChains.ListChains(e.ctx, connect.NewRequest(&panelv1.ListChainsRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = e.anonChains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
	if list, _ := e.db.ListEgresses(e.ctx); len(list) != 0 {
		t.Error("an egress was made without a session")
	}
}
