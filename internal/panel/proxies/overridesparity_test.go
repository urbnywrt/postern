package proxies

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines/telemt/overrides"
	"github.com/urbnywrt/postern/internal/node/state"
)

// telemtServesFakeTLS is the table of drivers of the node in this version.
func telemtServesFakeTLS(e nodev1.Engine, t nodev1.ProxyType) bool {
	return e == nodev1.Engine_ENGINE_TELEMT && t == nodev1.ProxyType_PROXY_TYPE_FAKETLS
}

// overridesCorpus is documents of engine overrides, good and bad, of every kind of
// mistake there is: the tests below judge each of them twice, once as the panel
// does and once as the node does.
func overridesCorpus() []string {
	corpus := []string{
		// nothing
		"", " ", "{}", " {} ", "null",
		// good
		`{"fast_mode":false}`,
		`{"tls_emulation":false,"tls_front_dir":"tlsfront/cache"}`,
		`{"update_every":30,"tg_connect":10,"rst_on_close":"errors","me_writer_pick_mode":"sorted_rr"}`,
		// bad
		`{"workers":4}`, `{"log_level":"debug"}`, `{"stun_use":true}`, `{"beobachten":true}`, `{"unknown_dc_file_log_enabled":true}`,
		`{"listeners":[]}`, `{"upstreams":[]}`, `{"users":{}}`, `{"ad_tag":"0123456789abcdef0123456789abcdef"}`,
		`{"middle_proxy_nat_ip":"203.0.113.9"}`, `{"use_middle_proxy":true}`,
		`{"general":{"fast_mode":false}}`, `{"network_prefer":"system"}`, `{"server_client_mss":1360}`,
		`{"fast_mode":"yes"}`, `{"fast_mode":1}`, `{"fast_mode":null}`,
		`{"tg_connect":0}`, `{"tg_connect":601}`, `{"tg_connect":"10"}`, `{"tg_connect":10.5}`, `{"tg_connect":1e1}`,
		`{"upstream_connect_retry_attempts":0}`, `{"me_keepalive_jitter_secs":-1}`,
		`{"me_writer_pick_mode":"fast"}`, `{"rst_on_close":true}`,
		`{"tls_front_dir":"/etc"}`, `{"tls_front_dir":"../x"}`, `{"tls_front_dir":""}`, `{"tls_front_dir":"a b"}`,
		`{"fast_mode":true,"fast_mode":false}`,
		`[]`, `[1]`, `"x"`, `5`, `true`, `{`, `{"a":}`, `garbage`, `{} {}`,
		`{"tg_connect":0,"workers":1,"log_level":"debug"}`,
	}
	// Every key of the whitelist, at the ends of its range and just outside it, and
	// with a value of another type.
	for _, s := range overrides.Specs() {
		key := strconv.Quote(s.Key)
		switch s.Kind {
		case overrides.Bool:
			corpus = append(corpus, "{"+key+":true}", "{"+key+":false}", "{"+key+`:"true"}`, "{"+key+":0}")
		case overrides.Int:
			for _, n := range []int64{s.Min - 1, s.Min, s.Max, s.Max + 1} {
				corpus = append(corpus, fmt.Sprintf("{%s:%d}", key, n))
			}
			corpus = append(corpus, "{"+key+`:"1"}`, "{"+key+":true}")
		case overrides.Enum:
			for _, v := range s.Values {
				corpus = append(corpus, "{"+key+":"+strconv.Quote(v)+"}")
			}
			corpus = append(corpus, "{"+key+`:"nope"}`, "{"+key+":1}")
		case overrides.Dir:
			corpus = append(corpus, "{"+key+`:"tlsfront"}`, "{"+key+`:"a/b"}`, "{"+key+`:"/a"}`, "{"+key+`:"a/../b"}`, "{"+key+":1}")
		}
	}
	return corpus
}

// The panel and the node judge the engine overrides of a state alike: both read
// the whitelist of internal/engines/telemt/overrides, and neither has a rule of
// its own about them. What the panel sends, the node takes; what the node would
// refuse, the panel does not send, and says the same about it.
func TestEngineOverridesAreJudgedAsTheNodeJudgesThem(t *testing.T) {
	if err := state.Validate(validState(), telemtServesFakeTLS); err != nil {
		t.Fatalf("the node refuses the state that the test starts from: %v", err)
	}
	var accepted, refused int
	for _, raw := range overridesCorpus() {
		t.Run(raw, func(t *testing.T) {
			st := validState()
			st.Proxies[1].EngineOverridesJson = raw
			panelErr := validateState(st)
			nodeErr := state.Validate(st, telemtServesFakeTLS)
			if (panelErr == nil) != (nodeErr == nil) {
				t.Fatalf("the panel says %v, and the node says %v", panelErr, nodeErr)
			}
			if panelErr == nil {
				accepted++
				return
			}
			refused++
			var fromPanel *stateError
			var fromNode *state.ValidationError
			if !errors.As(panelErr, &fromPanel) || !errors.As(nodeErr, &fromNode) {
				t.Fatalf("the errors are %T and %T", panelErr, nodeErr)
			}
			if !slices.Equal(fromPanel.problems, fromNode.Problems) {
				t.Errorf("the panel and the node tell different problems:\n panel %q\n node  %q", fromPanel.problems, fromNode.Problems)
			}
		})
	}
	// The corpus has both kinds, or the test judges nothing.
	if accepted < 10 || refused < 40 {
		t.Errorf("the corpus has %d documents that are taken and %d that are refused", accepted, refused)
	}
}

// Every key of the whitelist has a document that both take, and the one table is
// what they both read: a key that is added to it is judged by the two at once.
func TestEveryWhitelistedKeyIsTakenByThePanelAndTheNode(t *testing.T) {
	for _, s := range overrides.Specs() {
		var value string
		switch s.Kind {
		case overrides.Bool:
			value = "true"
		case overrides.Int:
			value = strconv.FormatInt(s.Max, 10)
		case overrides.Enum:
			value = strconv.Quote(s.Values[0])
		case overrides.Dir:
			value = `"tlsfront"`
		}
		st := validState()
		st.Proxies[1].EngineOverridesJson = "{" + strconv.Quote(s.Key) + ":" + value + "}"
		if err := validateState(st); err != nil {
			t.Errorf("the panel refuses %s: %v", st.Proxies[1].EngineOverridesJson, err)
		}
		if err := state.Validate(st, telemtServesFakeTLS); err != nil {
			t.Errorf("the node refuses %s: %v", st.Proxies[1].EngineOverridesJson, err)
		}
	}
}
