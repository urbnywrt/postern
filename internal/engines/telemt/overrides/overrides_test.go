package overrides

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// contract is the whitelist as task 3 of slice 4 specifies it, key by key and in
// the order that the keys are written to the config. It is a second copy on
// purpose: a change of the table has to be a change of this test as well.
//
// Two keys of the task are not here because telemt 3.5.13 does not have them
// (see TestKeysOfTheSourceThatTelemtDoesNotHave), and one range differs
// from the task's: upstream_connect_retry_attempts starts at 1 because telemt
// refuses 0 at start-up (general.upstream_connect_retry_attempts must be > 0).
var contract = []struct {
	key      string
	section  Section
	kind     Kind
	min, max int64
	values   []string
}{
	{key: "fast_mode", section: General, kind: Bool},
	{key: "me2dc_fallback", section: General, kind: Bool},
	{key: "me2dc_fast", section: General, kind: Bool},
	{key: "me_keepalive_enabled", section: General, kind: Bool},
	{key: "me_keepalive_interval_secs", section: General, kind: Int, min: 1, max: 3600},
	{key: "me_keepalive_jitter_secs", section: General, kind: Int, min: 0, max: 600},
	{key: "me_keepalive_payload_random", section: General, kind: Bool},
	{key: "me_reconnect_backoff_base_ms", section: General, kind: Int, min: 1, max: 600000},
	{key: "me_reconnect_backoff_cap_ms", section: General, kind: Int, min: 1, max: 600000},
	{key: "me_reconnect_fast_retry_count", section: General, kind: Int, min: 0, max: 1000},
	{key: "desync_all_full", section: General, kind: Bool},
	{key: "me_writer_pick_mode", section: General, kind: Enum, values: []string{"p2c", "sorted_rr"}},
	{key: "me_warmup_stagger_enabled", section: General, kind: Bool},
	{key: "me_warmup_step_delay_ms", section: General, kind: Int, min: 0, max: 60000},
	{key: "me_warmup_step_jitter_ms", section: General, kind: Int, min: 0, max: 60000},
	{key: "upstream_connect_retry_attempts", section: General, kind: Int, min: 1, max: 100},
	{key: "upstream_connect_retry_backoff_ms", section: General, kind: Int, min: 0, max: 600000},
	{key: "tg_connect", section: General, kind: Int, min: 1, max: 600},
	{key: "rst_on_close", section: General, kind: Enum, values: []string{"off", "errors", "always"}},
	{key: "update_every", section: General, kind: Int, min: 1, max: 86400},
	{key: "me_init_retry_attempts", section: General, kind: Int, min: 0, max: 1000},
	{key: "tls_emulation", section: Censorship, kind: Bool},
	{key: "tls_front_dir", section: Censorship, kind: Dir},
}

func TestWhitelistIsWhatTheTaskSpecifies(t *testing.T) {
	specs := Specs()
	if len(specs) != len(contract) {
		t.Fatalf("the whitelist has %d keys, the task has %d", len(specs), len(contract))
	}
	for i, want := range contract {
		got := specs[i]
		if got.Key != want.key || got.Section != want.section || got.Kind != want.kind ||
			got.Min != want.min || got.Max != want.max || !slices.Equal(got.Values, want.values) {
			t.Errorf("key %d is %+v, want %+v", i, got, want)
		}
	}
}

// The task lists keys that its source has and telemt 3.5.13 does not:
// telemt keeps the preference for an IP family in [network] prefer, which is 4
// or 6, and the MSS of the clients in [server] client_mss, which is a string
// (reference at tag 3.5.13; no trace of either name in the source). Both stay
// out, so that an override is never something telemt silently ignores.
func TestKeysOfTheSourceThatTelemtDoesNotHave(t *testing.T) {
	for _, key := range []string{"network_prefer", "server_client_mss"} {
		if _, ok := Lookup(key); ok {
			t.Errorf("%s is whitelisted, but telemt 3.5.13 has no such key", key)
		}
		if _, ok := Owned(key); ok {
			t.Errorf("%s is owned: it is not a key that Postern writes, telemt just does not have it", key)
		}
		_, problems := Parse(`{"` + key + `":1}`)
		if len(problems) != 1 || problems[0].Class != ProblemUnsupported {
			t.Errorf("%s: problems = %+v, want one that says it is not supported", key, problems)
		}
	}
}

func TestSpecsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Specs() {
		if s.Key == "" || strings.Trim(s.Key, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
			t.Errorf("key %q is not a plain TOML key in lower case", s.Key)
		}
		if seen[s.Key] {
			t.Errorf("key %s is in the table twice", s.Key)
		}
		seen[s.Key] = true
		if s.Section != General && s.Section != Censorship {
			t.Errorf("%s: section %q is not one that the renderer writes", s.Key, s.Section)
		}
		switch s.Kind {
		case Bool, Dir:
			if s.Min != 0 || s.Max != 0 || s.Values != nil {
				t.Errorf("%s: a %v has a range or values: %+v", s.Key, s.Kind, s)
			}
		case Int:
			if s.Min < 0 || s.Min > s.Max || s.Values != nil {
				t.Errorf("%s: a bad range %d-%d", s.Key, s.Min, s.Max)
			}
		case Enum:
			if len(s.Values) < 2 || s.Min != 0 || s.Max != 0 {
				t.Errorf("%s: an enum needs at least two values and no range: %+v", s.Key, s)
			}
			for i, v := range s.Values {
				if v == "" || slices.Index(s.Values, v) != i {
					t.Errorf("%s: value %q is empty or listed twice", s.Key, v)
				}
			}
		default:
			t.Errorf("%s: kind %d is not known", s.Key, s.Kind)
		}
	}
}

func TestSpecsReturnsACopy(t *testing.T) {
	a := Specs()
	if len(a) == 0 {
		t.Fatal("the whitelist is empty")
	}
	a[0].Key = "changed"
	for i := range a {
		if a[i].Kind == Enum {
			a[i].Values[0] = "changed"
		}
	}
	b := Specs()
	if b[0].Key != contract[0].key {
		t.Errorf("a change of the slice reached the table: %s", b[0].Key)
	}
	for _, s := range b {
		if s.Kind == Enum && s.Values[0] == "changed" {
			t.Errorf("%s: a change of the values reached the table", s.Key)
		}
	}
}

// A value that Parse returns is the caller's: changing it does not change the table.
func TestParseGivesValuesThatAreTheirOwn(t *testing.T) {
	set := parse(t, `{"me_writer_pick_mode":"p2c","rst_on_close":"off"}`)
	for _, v := range set {
		v.Values[0] = "changed"
	}
	if got, ok := Lookup("me_writer_pick_mode"); !ok || got.Values[0] != "p2c" {
		t.Errorf("a change of a parsed value reached the table: %+v", got)
	}
	if got := parse(t, `{"me_writer_pick_mode":"p2c","rst_on_close":"off"}`); len(got) != 2 {
		t.Errorf("the table no longer parses its own values: %v", got)
	}
	if got, _ := Lookup("rst_on_close"); got.Values[0] != "off" {
		t.Errorf("rst_on_close values = %v", got.Values)
	}
}

func TestLookup(t *testing.T) {
	for _, want := range contract {
		got, ok := Lookup(want.key)
		if !ok || got.Key != want.key || got.Kind != want.kind || got.Section != want.section {
			t.Errorf("Lookup(%q) = %+v, %v", want.key, got, ok)
		}
	}
	for _, key := range []string{"", "FAST_MODE", "fast_mode ", "log_level", "workers", "general"} {
		if got, ok := Lookup(key); ok {
			t.Errorf("Lookup(%q) = %+v, want nothing", key, got)
		}
	}
}

// ---- reading a document ---------------------------------------------------------

func parse(t *testing.T, raw string) Set {
	t.Helper()
	set, problems := Parse(raw)
	if len(problems) > 0 {
		t.Fatalf("Parse(%s): %v", raw, messages(problems))
	}
	return set
}

func messages(ps []Problem) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Msg
	}
	return out
}

func TestParseOfNothingIsNothing(t *testing.T) {
	for _, raw := range []string{"", " ", "\n\t ", "{}", " {} ", "{ }", "\n{\n}\n", "null", " null\n"} {
		set, problems := Parse(raw)
		if len(set) != 0 || len(problems) != 0 {
			t.Errorf("Parse(%q) = %v, %v, want nothing", raw, set, problems)
		}
	}
}

func TestParseKeepsTheValuesAndOrdersThemAsTheTable(t *testing.T) {
	// The document has its keys in no order that matters; the set has them as
	// the table does, so that a config is the same whatever order the JSON had.
	set := parse(t, `{
		"tls_front_dir": "tlsfront/cache",
		"update_every": 30,
		"rst_on_close": "errors",
		"me_writer_pick_mode": "sorted_rr",
		"tg_connect": 10,
		"tls_emulation": false,
		"fast_mode": true,
		"me_keepalive_jitter_secs": 0
	}`)
	var keys []string
	for _, v := range set {
		keys = append(keys, v.Key)
	}
	wantKeys := []string{
		"fast_mode", "me_keepalive_jitter_secs", "me_writer_pick_mode", "tg_connect", "rst_on_close", "update_every",
		"tls_emulation", "tls_front_dir",
	}
	if !slices.Equal(keys, wantKeys) {
		t.Fatalf("keys = %v, want %v", keys, wantKeys)
	}

	if v, ok := set.Get("fast_mode"); !ok || v.Kind != Bool || !v.Bool {
		t.Errorf("fast_mode = %+v, %v", v, ok)
	}
	if v, ok := set.Get("tls_emulation"); !ok || v.Kind != Bool || v.Bool || v.Section != Censorship {
		t.Errorf("tls_emulation = %+v, %v", v, ok)
	}
	if v, ok := set.Get("me_keepalive_jitter_secs"); !ok || v.Kind != Int || v.Int != 0 {
		t.Errorf("me_keepalive_jitter_secs = %+v, %v", v, ok)
	}
	if v, ok := set.Get("update_every"); !ok || v.Int != 30 {
		t.Errorf("update_every = %+v, %v", v, ok)
	}
	if v, ok := set.Get("rst_on_close"); !ok || v.Kind != Enum || v.Str != "errors" {
		t.Errorf("rst_on_close = %+v, %v", v, ok)
	}
	if v, ok := set.Get("tls_front_dir"); !ok || v.Kind != Dir || v.Str != "tlsfront/cache" {
		t.Errorf("tls_front_dir = %+v, %v", v, ok)
	}
	if v, ok := set.Get("tg_connect"); !ok || v.Int != 10 {
		t.Errorf("tg_connect = %+v, %v", v, ok)
	}
	if v, ok := set.Get("desync_all_full"); ok {
		t.Errorf("desync_all_full = %+v, but the document has none", v)
	}

	general, censorship := set.In(General), set.In(Censorship)
	if len(general) != 6 || len(censorship) != 2 {
		t.Fatalf("In: %d general and %d censorship values, want 6 and 2", len(general), len(censorship))
	}
	for _, v := range general {
		if v.Section != General {
			t.Errorf("%s is in the general list", v.Key)
		}
	}
	if censorship[0].Key != "tls_emulation" || censorship[1].Key != "tls_front_dir" {
		t.Errorf("censorship values = %v", censorship)
	}
}

func TestParseAcceptsEveryKeyAtItsLimits(t *testing.T) {
	var all []string
	for _, want := range contract {
		var values []string
		switch want.kind {
		case Bool:
			values = []string{"true", "false"}
		case Int:
			mid := (want.min + want.max) / 2
			values = []string{itoa(want.min), itoa(want.max), itoa(mid)}
		case Enum:
			for _, v := range want.values {
				values = append(values, strconv.Quote(v))
			}
		case Dir:
			values = []string{`"tlsfront"`, `"a/b-c_d.e"`, `".cache"`}
		}
		for _, v := range values {
			raw := `{"` + want.key + `":` + v + `}`
			set, problems := Parse(raw)
			if len(problems) != 0 || len(set) != 1 || set[0].Key != want.key {
				t.Errorf("Parse(%s) = %v, %v", raw, set, messages(problems))
			}
		}
		all = append(all, `"`+want.key+`":`+values[0])
	}
	// All keys in one document.
	set, problems := Parse("{" + strings.Join(all, ",") + "}")
	if len(problems) != 0 || len(set) != len(contract) {
		t.Errorf("all keys: %d values, problems %v", len(set), messages(problems))
	}
	for i, v := range set {
		if v.Key != contract[i].key {
			t.Errorf("value %d is %s, want %s", i, v.Key, contract[i].key)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- type and range errors ---------------------------------------------------------

// onlyProblem is the one problem that Parse finds in raw.
func onlyProblem(t *testing.T, raw string) Problem {
	t.Helper()
	set, problems := Parse(raw)
	if len(problems) != 1 {
		t.Fatalf("Parse(%s) = %v and %d problems %v, want exactly one", raw, set, len(problems), messages(problems))
	}
	if len(set) != 0 {
		t.Errorf("Parse(%s) returned values %v together with a problem", raw, set)
	}
	return problems[0]
}

func TestParseRefusesWrongTypes(t *testing.T) {
	wrong := map[Kind][]string{
		Bool: {`"true"`, `"false"`, `"yes"`, `1`, `0`, `1.0`, `null`, `[]`, `{}`, `[true]`, `""`},
		Int:  {`"5"`, `true`, `false`, `null`, `1.5`, `1e2`, `5.0`, `[]`, `{}`, `[5]`, `99999999999999999999`, `-99999999999999999999`, `""`},
		Enum: {`1`, `true`, `null`, `""`, `"P2C"`, `"p2c "`, `" p2c"`, `"p2c\u0000"`, `["p2c"]`, `{}`, `"nope"`},
		Dir:  {`1`, `true`, `null`, `[]`, `{}`, `["a"]`},
	}
	for _, want := range contract {
		for _, v := range wrong[want.kind] {
			raw := `{"` + want.key + `":` + v + `}`
			p := onlyProblem(t, raw)
			if p.Class != ProblemInvalid || p.Key != want.key {
				t.Errorf("Parse(%s): %+v, want an invalid value of %s", raw, p, want.key)
			}
			if !strings.Contains(p.Msg, strconv.Quote(want.key)) {
				t.Errorf("Parse(%s): %q does not name the key", raw, p.Msg)
			}
		}
	}
}

func TestParseRefusesValuesOutsideTheRange(t *testing.T) {
	for _, want := range contract {
		if want.kind != Int {
			continue
		}
		for _, n := range []int64{want.min - 1, want.max + 1, -1, 1 << 40} {
			if n >= want.min && n <= want.max {
				continue
			}
			raw := `{"` + want.key + `":` + itoa(n) + `}`
			p := onlyProblem(t, raw)
			if p.Class != ProblemInvalid || p.Key != want.key {
				t.Errorf("Parse(%s): %+v", raw, p)
			}
			if wantRange := fmt.Sprintf("from %d to %d", want.min, want.max); !strings.Contains(p.Msg, wantRange) {
				t.Errorf("Parse(%s): %q does not say %q", raw, p.Msg, wantRange)
			}
		}
	}
}

func TestMessagesSayWhatIsAllowed(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{`{"fast_mode":"yes"}`, []string{`"fast_mode"`, "true or false"}},
		{`{"tg_connect":0}`, []string{`"tg_connect"`, "integer from 1 to 600"}},
		{`{"me_keepalive_jitter_secs":601}`, []string{`"me_keepalive_jitter_secs"`, "integer from 0 to 600"}},
		{`{"upstream_connect_retry_attempts":0}`, []string{`"upstream_connect_retry_attempts"`, "integer from 1 to 100"}},
		{`{"me_writer_pick_mode":"fast"}`, []string{`"me_writer_pick_mode"`, `"p2c"`, `"sorted_rr"`}},
		{`{"rst_on_close":true}`, []string{`"rst_on_close"`, `"off"`, `"errors"`, `"always"`}},
		{`{"tls_front_dir":""}`, []string{`"tls_front_dir"`, "empty"}},
		{`{"tls_front_dir":"/tmp/front"}`, []string{`"tls_front_dir"`, "relative"}},
		{`{"tls_front_dir":"../front"}`, []string{`"tls_front_dir"`, `".."`}},
		{`{"tls_front_dir":"a b"}`, []string{`"tls_front_dir"`, "letters"}},
		{`{"tls_front_dir":5}`, []string{`"tls_front_dir"`, "string"}},
	}
	for _, tt := range tests {
		p := onlyProblem(t, tt.raw)
		for _, w := range tt.want {
			if !strings.Contains(p.Msg, w) {
				t.Errorf("Parse(%s): %q does not contain %q", tt.raw, p.Msg, w)
			}
		}
	}
}

// A value that is wrong is not repeated in the message: an admin may have put
// something into the wrong field, and the message ends up in logs and in the
// answer of the API.
func TestMessagesDoNotEchoValues(t *testing.T) {
	const marker = "HUNTER2-A-VALUE-THAT-IS-NOT-FOR-LOGS"
	var docs []string
	for _, want := range contract {
		if want.kind == Dir {
			continue // the marker is a good directory name: the cases below are the bad ones
		}
		docs = append(docs, `{"`+want.key+`":"`+marker+`"}`)
	}
	docs = append(docs,
		`{"tls_front_dir":"`+marker+` x"}`,
		`{"tls_front_dir":"../`+marker+`"}`,
		`{"tls_front_dir":"/`+marker+`"}`,
		`{"log_level":"`+marker+`"}`,
		`{"workers":"`+marker+`"}`,
		`{"general":{"fast_mode":"`+marker+`"}}`,
		`{"fast_mode":"`+marker+`","fast_mode":"`+marker+`"}`,
	)
	for _, raw := range docs {
		_, problems := Parse(raw)
		if len(problems) == 0 {
			t.Errorf("Parse(%s) found nothing wrong", raw)
		}
		for _, p := range problems {
			if strings.Contains(p.Msg, marker) {
				t.Errorf("Parse(%s): %q repeats the value", raw, p.Msg)
			}
		}
	}
}

func TestParseOfADirectoryName(t *testing.T) {
	good := []string{"tlsfront", "tls-front", "tls_front", "front.d", ".cache", "a/b", "a/b/c/d", "A1.b-2_c", strings.Repeat("a", 128)}
	bad := []string{
		"", "/", "/tmp/front", "/etc/telemt/data/tlsfront", "../front", "a/../b", "a/..", "..", ".", "./a", "a/.", "a//b", "a/", "//a",
		"a b", " a", "a ", "a\tb", "a\nb", "a\x00b", "a\"b", `a\b`, "a'b", "a:b", "a;b", "a$b", "a*b", "a?b", "~", "~/a", "a" + string(rune(0x202e)) + "b",
		"ключ", "front́", strings.Repeat("a", 129), strings.Repeat("a/", 70) + "a",
	}
	for _, s := range good {
		raw := `{"tls_front_dir":` + jsonString(t, s) + `}`
		if set, problems := Parse(raw); len(problems) != 0 || len(set) != 1 || set[0].Str != s {
			t.Errorf("Parse(%s) = %v, %v, want it accepted as it is", raw, set, messages(problems))
		}
	}
	for _, s := range bad {
		raw := `{"tls_front_dir":` + jsonString(t, s) + `}`
		set, problems := Parse(raw)
		if len(problems) != 1 || problems[0].Class != ProblemInvalid || len(set) != 0 {
			t.Errorf("Parse(%s) = %v, %v, want one invalid value", raw, set, messages(problems))
		}
	}
}

func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- keys that are not the admin's ------------------------------------------------

// owned is what the task names as Postern's: refused with the reason. The values
// are plausible ones, so that the key is what is wrong and not the value.
var owned = map[string]string{
	// telemt prints links at higher levels
	"log_level": `"debug"`,
	// no STUN
	"stun_servers": `["stun.example.com:3478"]`, "stun_use": `true`,
	// no files in a read-only container
	"beobachten": `true`, "beobachten_minutes": `10`, "beobachten_flush_secs": `15`, "beobachten_file": `"/tmp/b.txt"`,
	"unknown_dc_file_log_enabled": `true`, "unknown_dc_log_path": `"/tmp/dc.txt"`,
	// listeners
	"server": `{}`, "listeners": `[]`, "port": `443`, "listen_addr_ipv4": `"0.0.0.0"`, "listen_addr_ipv6": `"::"`,
	"listen_unix_sock": `"/run/t.sock"`, "listen_tcp": `true`, "listen_backlog": `1024`,
	"proxy_protocol": `false`, "proxy_protocol_trusted_cidrs": `["0.0.0.0/0"]`,
	"metrics_port": `9090`, "metrics_listen": `"0.0.0.0:9090"`, "metrics_whitelist": `["0.0.0.0/0"]`,
	"max_connections": `10`, "client_mss": `"tspu"`, "client_mss_bulk": `"1400"`, "api": `{}`, "admin_api": `{}`,
	// upstreams
	"upstreams": `[]`,
	// users
	"access": `{}`, "users": `{}`, "user_ad_tags": `{}`, "user_max_tcp_conns": `{}`, "user_max_unique_ips": `{}`,
	"user_expirations": `{}`, "user_data_quota": `{}`,
	// the proxy's own settings
	"ad_tag": `"0123456789abcdef0123456789abcdef"`, "middle_proxy_nat_ip": `"203.0.113.10"`, "middle_proxy_nat_probe": `false`,
	"use_middle_proxy": `true`, "data_path": `"/tmp"`, "tls_domain": `"www.example.com"`, "tls_domains": `[]`,
	"mask": `true`, "mask_host": `"www.example.com"`, "mask_port": `443`, "mask_unix_sock": `"/run/m.sock"`, "tls_fetch_scope": `"x"`,
	"classic": `true`, "secure": `true`, "tls": `true`, "show": `"*"`, "show_link": `"*"`,
	"http_ip_detect_urls": `[]`, "network": `{}`,
}

func TestParseRefusesTheKeysThatPosternOwns(t *testing.T) {
	for key, value := range owned {
		raw := `{"` + key + `":` + value + `}`
		p := onlyProblem(t, raw)
		if p.Class != ProblemOwned || p.Key != key {
			t.Errorf("Parse(%s): %+v, want an owned key", raw, p)
			continue
		}
		if !strings.Contains(p.Msg, strconv.Quote(key)) || !strings.Contains(p.Msg, "owned by Postern") {
			t.Errorf("Parse(%s): %q does not say that Postern owns %q", raw, p.Msg, key)
		}
		reason, ok := Owned(key)
		if !ok || len(reason) < 20 || !strings.Contains(p.Msg, reason) {
			t.Errorf("Owned(%q) = %q, %v: want a reason, which the message gives", key, reason, ok)
		}
	}
}

func TestTheReasonsNameTheCause(t *testing.T) {
	tests := map[string]string{
		"log_level":                   "link",
		"stun_use":                    "STUN",
		"stun_servers":                "STUN",
		"beobachten":                  "read-only",
		"beobachten_file":             "read-only",
		"unknown_dc_file_log_enabled": "read-only",
		"listeners":                   "listener",
		"port":                        "listener",
		"upstreams":                   "upstream",
		"users":                       "user",
		"access":                      "user",
		"ad_tag":                      "ad tag",
		"middle_proxy_nat_ip":         "NAT",
	}
	for key, word := range tests {
		reason, ok := Owned(key)
		if !ok || !strings.Contains(strings.ToLower(reason), strings.ToLower(word)) {
			t.Errorf("Owned(%q) = %q, %v, want a reason that mentions %q", key, reason, ok, word)
		}
	}
}

func TestOwnedKeysAreNotTheWhitelist(t *testing.T) {
	for _, s := range Specs() {
		if reason, ok := Owned(s.Key); ok {
			t.Errorf("%s is whitelisted and also owned (%q)", s.Key, reason)
		}
	}
	// Names that look like owned ones, or begin like them, but are not.
	for _, key := range []string{
		"upstream_connect_retry_attempts", "upstream_connect_retry_backoff_ms", "update_every", "tg_connect",
		"me_keepalive_enabled", "tls_emulation", "tls_front_dir", "fast_mode", "hardswap", "disable_colors",
		"me_floor_mode", "workers", "", "LOG_LEVEL", "log_level ", " log_level",
	} {
		if reason, ok := Owned(key); ok {
			t.Errorf("Owned(%q) = %q, but Postern owns no such key", key, reason)
		}
	}
}

func TestParseRefusesKeysThatAreNotKnown(t *testing.T) {
	for _, raw := range []string{
		`{"workers":4}`, `{"a":null}`, `{"":""}`, `{"FAST_MODE":true}`, `{"fast_mode ":true}`, `{"me_floor_mode":"static"}`,
		`{"hardswap":false}`, `{"disable_colors":true}`, `{"unknown_sni_action":"drop"}`,
		`{"general.fast_mode":true}`, `{"general":{"fast_mode":false}}`, `{"censorship":{"tls_emulation":false}}`,
	} {
		p := onlyProblem(t, raw)
		if p.Class != ProblemUnsupported {
			t.Errorf("Parse(%s): %+v, want a key that is not supported", raw, p)
		}
		if !strings.Contains(p.Msg, "not supported") {
			t.Errorf("Parse(%s): %q does not say so", raw, p.Msg)
		}
	}
	// A table is the likeliest mistake, and the message says what to write.
	p := onlyProblem(t, `{"general":{"fast_mode":false}}`)
	if !strings.Contains(p.Msg, "flat") {
		t.Errorf("%q does not say that overrides are flat keys", p.Msg)
	}
}

// ---- documents that are not an object ----------------------------------------------

func TestParseRefusesWhatIsNotAnObject(t *testing.T) {
	for _, raw := range []string{
		"[]", "[{}]", `"x"`, "5", "true", "false", "{", `{"a":}`, `{"a"}`, "garbage", "{} {}", "{}{}", `{"fast_mode":true} x`,
		`{"fast_mode":true,}`, `{fast_mode:true}`, `{'fast_mode':true}`, "null null", "nul", "{}}", "{\"a\":1", "\x00", "{\"fast_mode\":true}\x00",
	} {
		p := onlyProblem(t, raw)
		if p.Class != ProblemMalformed || p.Key != "" {
			t.Errorf("Parse(%q): %+v, want a malformed document", raw, p)
		}
		if !strings.Contains(p.Msg, "engine_overrides_json is not a JSON object") {
			t.Errorf("Parse(%q): %q", raw, p.Msg)
		}
	}
}

func TestParseRefusesAKeyGivenTwice(t *testing.T) {
	for _, raw := range []string{
		`{"fast_mode":true,"fast_mode":false}`,
		`{"fast_mode":true,"fast_mode":true}`,
		`{"tg_connect":10,"me2dc_fast":true,"tg_connect":20}`,
	} {
		_, problems := Parse(raw)
		if len(problems) != 1 || problems[0].Class != ProblemMalformed || !strings.Contains(problems[0].Msg, "more than once") {
			t.Errorf("Parse(%s) = %v, want a key that is given more than once", raw, messages(problems))
		}
	}
	// Whatever the key is, a repeat is refused, and a key that is not allowed
	// is reported for what it is.
	_, problems := Parse(`{"log_level":"debug","log_level":"silent"}`)
	if len(problems) != 2 {
		t.Errorf("problems = %v, want the repeat and the owned key", messages(problems))
	}
}

func TestParseRefusesAnOversizeDocument(t *testing.T) {
	big := `{"fast_mode":true,"pad":"` + strings.Repeat("x", 20<<10) + `"}`
	p := onlyProblem(t, big)
	if p.Class != ProblemMalformed || !strings.Contains(p.Msg, "larger than") {
		t.Errorf("problem = %+v", p)
	}
}

// ---- every problem, in order ----------------------------------------------------

func TestParseReportsEveryProblemSortedByKey(t *testing.T) {
	set, problems := Parse(`{"zzz":1,"tg_connect":0,"log_level":"debug","fast_mode":"x","aaa":2,"update_every":30}`)
	if len(set) != 0 {
		t.Errorf("a set %v together with problems", set)
	}
	var keys []string
	var classes []ProblemClass
	for _, p := range problems {
		keys = append(keys, p.Key)
		classes = append(classes, p.Class)
	}
	if want := []string{"aaa", "fast_mode", "log_level", "tg_connect", "zzz"}; !slices.Equal(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
	wantClasses := []ProblemClass{ProblemUnsupported, ProblemInvalid, ProblemOwned, ProblemInvalid, ProblemUnsupported}
	if !reflect.DeepEqual(classes, wantClasses) {
		t.Errorf("classes = %v, want %v", classes, wantClasses)
	}
	// The same document gives the same problems again.
	_, again := Parse(`{"zzz":1,"tg_connect":0,"log_level":"debug","fast_mode":"x","aaa":2,"update_every":30}`)
	if !reflect.DeepEqual(problems, again) {
		t.Errorf("two runs differ:\n%v\n%v", messages(problems), messages(again))
	}
	// The order of the keys in the document does not matter.
	_, reordered := Parse(`{"update_every":30,"aaa":2,"fast_mode":"x","log_level":"debug","tg_connect":0,"zzz":1}`)
	if !reflect.DeepEqual(problems, reordered) {
		t.Errorf("a different key order gives different problems:\n%v\n%v", messages(problems), messages(reordered))
	}
}

func TestParseCapsTheProblems(t *testing.T) {
	var parts []string
	for i := range 100 {
		parts = append(parts, fmt.Sprintf(`"k%03d":1`, i))
	}
	_, problems := Parse("{" + strings.Join(parts, ",") + "}")
	if len(problems) != 17 {
		t.Fatalf("%d problems, want the first 16 and one that says there are more", len(problems))
	}
	for i, p := range problems[:16] {
		if p.Class != ProblemUnsupported || p.Key != fmt.Sprintf("k%03d", i) {
			t.Errorf("problem %d = %+v", i, p)
		}
	}
	if last := problems[16]; last.Class != ProblemMore || !strings.Contains(last.Msg, "84 more") {
		t.Errorf("last problem = %+v, want one that says 84 more", last)
	}
}

func TestEveryProblemHasAMessage(t *testing.T) {
	for _, raw := range []string{"[]", `{"a":1}`, `{"log_level":"x"}`, `{"tg_connect":0}`, `{"fast_mode":true,"fast_mode":true}`} {
		_, problems := Parse(raw)
		if len(problems) == 0 {
			t.Errorf("Parse(%s) found nothing wrong", raw)
		}
		for _, p := range problems {
			if p.Msg == "" || p.Class == 0 {
				t.Errorf("Parse(%s): a problem without a message or a class: %+v", raw, p)
			}
			if strings.ContainsAny(p.Msg, "\n\r\x00") {
				t.Errorf("Parse(%s): the message %q spans lines", raw, p.Msg)
			}
		}
	}
}

// A key is quoted and cut short in a message, so that a hostile key cannot fill a log.
func TestMessagesCutLongKeysShort(t *testing.T) {
	key := strings.Repeat("k", 500)
	p := onlyProblem(t, `{"`+key+`":1}`)
	if len(p.Msg) > 200 {
		t.Errorf("a message of %d bytes for a key of 500", len(p.Msg))
	}
	p = onlyProblem(t, `{"bad\nkey\u0000":1}`)
	if strings.ContainsAny(p.Msg, "\n\x00") {
		t.Errorf("the message %q has a raw control character", p.Msg)
	}
}
