// Package overrides is the whitelist of the engine overrides of telemt: the
// settings of the engine that an admin may change on a proxy, each with its type and range, and the keys that Postern
// owns and so refuses.
//
// It is the one table that the node (internal/node/state), the panel
// (internal/panel/proxies) and the telemt driver (internal/engines/telemt) all
// read, so that the three cannot drift apart: what the panel lets through is
// what the node accepts is what the driver renders. It imports nothing of
// Postern, so that the panel does not need the Docker client of the driver.
//
// engine_overrides_json is a JSON object of flat keys, {"fast_mode": false},
// and not of tables. The driver writes every override to the table of its
// Section, after the lines that Postern writes itself, in the order of the
// table below, whatever the order of the JSON was. Postern's own lines stay
// authoritative: a key that Postern writes is owned by it and refused (see
// Owned), and no key is ever written twice. tls_emulation is the one whitelisted
// key that Postern also writes, as true: that line is its default, an override
// changes the value of the line, and there is never a second one.
//
// # Where the keys come from
//
// Every key was checked against the configuration reference of telemt 3.5.13,
// the default version of the engine (docs/Config_params/CONFIG_PARAMS.en.md at
// the tag 3.5.13, commit d3de9865cf5d088809fdf728059bcb2b0841db67):
//
//	https://github.com/telemt/telemt/blob/3.5.13/docs/Config_params/CONFIG_PARAMS.en.md
//
// Each of them has a section of its own there, "## <key>", under "# [general]"
// or "# [censorship]", with its type and what telemt checks. The source at the
// same tag agrees: the table of the keys that telemt knows, which its
// config_strict mode holds a config to (src/config/load/strict_keys.rs), has
// the 21 [general] keys below in GENERAL_CONFIG_KEYS and the 2 [censorship]
// keys in CENSORSHIP_CONFIG_KEYS, and the checks that telemt makes of a config
// at start-up (src/config/load/validate_core.rs and its neighbours) are the
// ones that the ranges below respect. The ranges are Postern's own and lie
// inside what telemt accepts; where telemt is stricter than the source that the
// keys come from, the range follows telemt.
//
// Two keys of that source are not here, because telemt 3.5.13 has no key
// of their name, in any of the tables of strict_keys.rs: network_prefer, which
// telemt keeps as [network] prefer, the integer 4 or 6, and server_client_mss,
// which it keeps as [server] client_mss, a string (a preset, or a number from
// 88 to 4096). A key that telemt does not know it ignores, unless config_strict
// is set, so such a value never did anything and leaving it out changes
// nothing.
//
// The table is for telemt 3.5.13. Another version of telemt may have other keys
// and other limits: check the table again before the default version moves.
package overrides

import (
	"slices"
)

// Section is the table of the telemt config that an override is written to.
type Section string

// The sections that overrides are written to.
const (
	General    Section = "general"
	Censorship Section = "censorship"
)

// Kind is the type of an override.
type Kind int

// The kinds of override.
const (
	// Bool is true or false.
	Bool Kind = iota + 1
	// Int is an integer in the range of the spec.
	Int
	// Enum is one of the strings in Values.
	Enum
	// Dir is the name of a directory below the data directory of the engine:
	// relative, of plain characters, and not climbing out.
	Dir
)

// Spec describes one override that is allowed.
type Spec struct {
	// Key is the key of the JSON document and of the telemt config.
	Key string
	// Section is the table of the telemt config that the key is written to.
	Section Section
	Kind    Kind
	// Min and Max are the limits of an Int, both included.
	Min, Max int64
	// Values are the strings that an Enum may have, in the order of the reference
	// of telemt.
	Values []string
}

// specs is the table. Its order is the order in which the overrides are written
// to the config (and the order of the source that they come from).
var specs = []Spec{
	{Key: "fast_mode", Section: General, Kind: Bool},
	{Key: "me2dc_fallback", Section: General, Kind: Bool},
	{Key: "me2dc_fast", Section: General, Kind: Bool},
	{Key: "me_keepalive_enabled", Section: General, Kind: Bool},
	{Key: "me_keepalive_interval_secs", Section: General, Kind: Int, Min: 1, Max: 3600},
	{Key: "me_keepalive_jitter_secs", Section: General, Kind: Int, Min: 0, Max: 600},
	{Key: "me_keepalive_payload_random", Section: General, Kind: Bool},
	{Key: "me_reconnect_backoff_base_ms", Section: General, Kind: Int, Min: 1, Max: 600000},
	{Key: "me_reconnect_backoff_cap_ms", Section: General, Kind: Int, Min: 1, Max: 600000},
	{Key: "me_reconnect_fast_retry_count", Section: General, Kind: Int, Min: 0, Max: 1000},
	{Key: "desync_all_full", Section: General, Kind: Bool},
	{Key: "me_writer_pick_mode", Section: General, Kind: Enum, Values: []string{"p2c", "sorted_rr"}},
	{Key: "me_warmup_stagger_enabled", Section: General, Kind: Bool},
	{Key: "me_warmup_step_delay_ms", Section: General, Kind: Int, Min: 0, Max: 60000},
	{Key: "me_warmup_step_jitter_ms", Section: General, Kind: Int, Min: 0, Max: 60000},
	// telemt refuses 0: "general.upstream_connect_retry_attempts must be > 0".
	{Key: "upstream_connect_retry_attempts", Section: General, Kind: Int, Min: 1, Max: 100},
	{Key: "upstream_connect_retry_backoff_ms", Section: General, Kind: Int, Min: 0, Max: 600000},
	{Key: "tg_connect", Section: General, Kind: Int, Min: 1, Max: 600},
	{Key: "rst_on_close", Section: General, Kind: Enum, Values: []string{"off", "errors", "always"}},
	{Key: "update_every", Section: General, Kind: Int, Min: 1, Max: 86400},
	{Key: "me_init_retry_attempts", Section: General, Kind: Int, Min: 0, Max: 1000},
	// Postern writes tls_emulation = true itself: that is the default of the line
	// and an override changes its value (see the package comment).
	{Key: "tls_emulation", Section: Censorship, Kind: Bool},
	{Key: "tls_front_dir", Section: Censorship, Kind: Dir},
}

// byKey and order are the lookups of the table.
var (
	byKey = map[string]Spec{}
	order = map[string]int{}
)

func init() {
	for i, s := range specs {
		byKey[s.Key] = s
		order[s.Key] = i
	}
}

// Specs returns the whitelist, in the order in which the overrides are written
// to the config. The caller may change what it gets.
func Specs() []Spec {
	out := slices.Clone(specs)
	for i := range out {
		out[i].Values = slices.Clone(out[i].Values)
	}
	return out
}

// Lookup returns the spec of a key that is whitelisted.
func Lookup(key string) (Spec, bool) {
	s, ok := byKey[key]
	if ok {
		s.Values = slices.Clone(s.Values)
	}
	return s, ok
}

// Value is one override that was read and checked. Bool, Int or Str holds the
// value, by Kind: Str for an Enum and for a Dir.
type Value struct {
	Spec
	Bool bool
	Int  int64
	Str  string
}

// Set is the overrides of a proxy, in the order of the table.
type Set []Value

// Get returns the override of a key.
func (s Set) Get(key string) (Value, bool) {
	for _, v := range s {
		if v.Key == key {
			return v, true
		}
	}
	return Value{}, false
}

// In returns the overrides that are written to a section, in the order of the
// table.
func (s Set) In(sec Section) []Value {
	var out []Value
	for _, v := range s {
		if v.Section == sec {
			out = append(out, v)
		}
	}
	return out
}
