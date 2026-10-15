package state

import (
	"log/slog"
	"strconv"
	"time"
)

// Runtime is the reconciler's record of what runs on the node, saved as
// runtime.json. Only the reconciler writes it.
type Runtime struct {
	// Ports are the allocated loopback ports by key (see EnginePortKey and
	// TestListenerPortKey).
	Ports map[string]uint16 `json:"ports"`
	// Instances are the engine instances by proxy id: the one that serves the
	// proxy, if any, and the older generations that drain.
	Instances map[string]InstanceRecord `json:"instances"`
	// Egresses are the provider instances by egress id (Xray, Psiphon): the
	// one that serves the egress, if any, the older generations that drain, and
	// what is known of its subscription.
	Egresses map[string]EgressRecord `json:"egresses,omitempty"`
	// EdgeGeneration is the generation of the edge container that carries the
	// traffic.
	EdgeGeneration uint64 `json:"edge_generation"`
	// EdgeLastGeneration is the highest edge generation ever made, also one
	// that did not come up and was removed, so that a generation number is
	// never used twice.
	EdgeLastGeneration uint64 `json:"edge_last_generation,omitempty"`
	// EdgeNetRaw is the edge generation that the reconciler created with
	// CAP_NET_RAW, which the edge needs while a member of a chain is tied to an
	// interface; 0 when the last one it created has none. No other generation
	// has the capability: no agent gave it before this record was kept.
	EdgeNetRaw uint64 `json:"edge_net_raw,omitempty"`
	// EdgeRollNonce is the NodeSettings.edge_roll_nonce the reconciler last
	// took: a desired value other than this one rolls the edge like the
	// operator's roll file does. It is recorded when the roll starts, whatever
	// its outcome, so that a roll that fails is not tried again on every pass;
	// on a node without a running edge it is recorded without a roll.
	EdgeRollNonce uint64 `json:"edge_roll_nonce,omitempty"`
	// EdgeBinaries are the host paths of the node binary that each edge
	// generation mounts, by generation: the one UpdateEdge asked for, or the
	// one a generation made for another reason took (that of the generation it
	// replaced, else the agent's own). A generation without an entry, made
	// before this record was kept, mounts the agent's own.
	EdgeBinaries map[uint64]string `json:"edge_binaries,omitempty"`
	// EdgePreviousBinary is the binary the edge ran before its last roll that
	// went through: UpdateEdge's rollback goes only to its version.
	EdgePreviousBinary string `json:"edge_previous_binary,omitempty"`
	// AppliedGeneration is the generation of the last desired state a reconcile
	// pass went all the way through.
	AppliedGeneration uint64 `json:"applied_generation"`
	// EdgeDNS is the state of the edge's DNS forwarder that the engines follow:
	// they mount the resolv.conf that names it only while it is true. It is what
	// the edge answers (Health dns), the first answer at once and a change only
	// once the edge has answered the other state for 60 s in a row
	// (EdgeDNSChangeSince). An edge that does not answer changes nothing.
	EdgeDNS bool `json:"edge_dns,omitempty"`
	// EdgeDNSKnown is set by the first answer of the edge about its forwarder.
	EdgeDNSKnown bool `json:"edge_dns_known,omitempty"`
	// EdgeDNSChangeSince is when the edge began to answer the other state than
	// EdgeDNS, in every answer since; zero while it answers EdgeDNS. It is kept
	// here so that a restart of the agent does not start the wait over.
	EdgeDNSChangeSince time.Time `json:"edge_dns_change_since,omitzero"`
	// EdgeDNSAwaitUp is set once the edge has the configuration of another DNS
	// mode than doh, and stays set in mode doh until the edge answers that its
	// forwarder runs: the forwarder of a mode that has just become doh again is
	// unknown (the edge gets it with the configuration of the pass), so EdgeDNS
	// is false until that answer, which applies at once; the answers that it
	// does not run change nothing meanwhile.
	EdgeDNSAwaitUp bool `json:"edge_dns_await_up,omitempty"`
}

// InstanceRecord is the serving engine instance of a proxy and the
// generations that drain. Generation 0 means that no instance serves the proxy
// (it was deleted and only drains, or no instance could be started yet); the
// other serving fields are then zero.
type InstanceRecord struct {
	Generation uint64 `json:"generation"`
	// Hash identifies what the instance runs: engine, version, rendered files
	// (without the per-generation ports and token) and the middle-proxy settings.
	// A different hash for the desired proxy means a new generation.
	Hash string `json:"hash"`
	// Engine and Version are what the serving instance runs (for example
	// "telemt" and "3.5.13").
	Engine  string `json:"engine,omitempty"`
	Version string `json:"version,omitempty"`
	// ListenerID and Domain are the route key the serving instance was
	// rendered for: the edge routes this (listener, SNI) to it. They follow the
	// desired proxy only when a new generation takes over (or at once when the
	// change does not touch the engine), so that during a blue-green the old
	// domain keeps reaching the old generation.
	ListenerID string `json:"listener_id,omitempty"`
	Domain     string `json:"domain,omitempty"`
	// BinaryPath is the host path of the engine binary the serving container
	// mounts, checked before a stopped container is started again.
	BinaryPath string `json:"binary_path,omitempty"`
	// PreviousBinaryPath is the binary the proxy ran before BinaryPath: the
	// rollback target, kept through artifact collection. Set when a new
	// generation replaces the binary, unchanged when it runs the same one.
	PreviousBinaryPath string `json:"previous_binary_path,omitempty"`
	// NatIP is the address the serving instance presents to the middle proxy
	// (middle_proxy_nat_ip), "" for none. When the exit address of the egress
	// it takes is not known for a while, a new generation keeps it.
	NatIP string `json:"nat_ip,omitempty"`

	ListenPort uint16 `json:"listen_port"`
	APIPort    uint16 `json:"api_port"`
	SocksPort  uint16 `json:"socks_port"`
	// APIToken is the Authorization value of the engine's API. Never log it.
	APIToken     string    `json:"api_token"`
	ServingSince time.Time `json:"serving_since"`

	// Draining are older generations that take no new connections and are
	// removed once their connections are gone or the drain time is over.
	Draining []DrainingInstance `json:"draining,omitempty"`

	// LastGeneration is the highest generation ever started for the proxy,
	// also one that failed and was removed, so that a generation number is
	// never used twice.
	LastGeneration uint64 `json:"last_generation,omitempty"`
}

// LogValue keeps the API token out of logs.
func (r InstanceRecord) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("generation", r.Generation),
		slog.String("engine", r.Engine),
		slog.String("version", r.Version),
		slog.Int("listen_port", int(r.ListenPort)),
		slog.Int("draining", len(r.Draining)),
	)
}

// DrainingInstance is an engine generation on its way out.
type DrainingInstance struct {
	Generation    uint64    `json:"generation"`
	ContainerName string    `json:"container_name"`
	Since         time.Time `json:"since"`
	ListenPort    uint16    `json:"listen_port"`
}

// EgressRecord is the provider instance of an egress and the generations that
// drain, as InstanceRecord is an engine's. Generation 0 means that no instance
// serves the egress; the other serving fields are then zero.
type EgressRecord struct {
	Generation uint64 `json:"generation,omitempty"`
	// Hash identifies what the instance runs: the provider, its binary, the
	// rendered files (without the per-generation ports), the mounts. A different
	// hash for the desired egress means a new generation.
	Hash string `json:"hash,omitempty"`
	// Provider and Version are what the serving instance runs ("xray",
	// "v26.3.27").
	Provider string `json:"provider,omitempty"`
	Version  string `json:"version,omitempty"`
	// BinaryPath is the host path of the provider binary the serving container
	// mounts, checked before a stopped container is started again.
	BinaryPath string `json:"binary_path,omitempty"`
	// PreviousBinaryPath is the binary the egress ran before BinaryPath (or
	// before it retired): the rollback target, kept through artifact
	// collection. Set when a new generation replaces the binary.
	PreviousBinaryPath string `json:"previous_binary_path,omitempty"`
	// Members are the members of the serving instance, each with its SOCKS port,
	// in the order the chains take them (the order of a subscription).
	Members      []EgressMember `json:"members,omitempty"`
	ServingSince time.Time      `json:"serving_since,omitzero"`

	// Draining are older generations, which take no new connections: the edge
	// no longer has their ports in a chain. They are removed after two minutes.
	Draining []DrainingEgress `json:"draining,omitempty"`

	// LastGeneration is the highest generation ever started for the egress,
	// also one that failed, so that a generation number is never used twice.
	LastGeneration uint64 `json:"last_generation,omitempty"`

	// SubscriptionFetched is when the subscription of an XRAY_SUBSCRIPTION
	// egress was fetched last, SubscriptionURL the SHA-256 of the URL it was
	// fetched from (the URL may hold a token), in hex, and SubscriptionNonce
	// the refresh nonce of the egress then (Egress.refresh_nonce, Ruling
	// S2-17): another URL, or another nonce, is fetched at once.
	SubscriptionFetched time.Time `json:"subscription_fetched,omitzero"`
	SubscriptionURL     string    `json:"subscription_url,omitempty"`
	SubscriptionNonce   uint64    `json:"subscription_nonce,omitempty"`

	// WARPDeletion is how the deletion of the WARP device of an egress that is
	// no longer desired goes while it fails; nil before its first failure. The
	// record and the account of the egress stay until the device is deleted.
	WARPDeletion *WARPDeletion `json:"warp_deletion,omitempty"`
}

// WARPDeletion is the deletion of a WARP device that failed: Failures attempts
// in a row, the first at FirstFailed, and the next one due at NextAttempt.
// GaveUp says that it failed for a week and is not tried any more: the account
// stays, for the owner of the node to delete the device by hand.
type WARPDeletion struct {
	Failures    int       `json:"failures"`
	FirstFailed time.Time `json:"first_failed"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
	GaveUp      bool      `json:"gave_up,omitempty"`
}

// EgressMember is a member of a provider instance: its key and its SOCKS port
// on 127.0.0.1.
type EgressMember struct {
	Key  string `json:"key"`
	Port uint16 `json:"port"`
}

// DrainingEgress is a provider generation on its way out.
type DrainingEgress struct {
	Generation    uint64    `json:"generation"`
	ContainerName string    `json:"container_name"`
	Since         time.Time `json:"since"`
}

// NewRuntime returns an empty runtime record with its maps made.
func NewRuntime() *Runtime {
	return &Runtime{Ports: map[string]uint16{}, Instances: map[string]InstanceRecord{}, Egresses: map[string]EgressRecord{}}
}

// EgressPortKey is the runtime key of the SOCKS port of a member of a provider
// instance, for example "egr:<egressID>:g3:<memberKey>".
func EgressPortKey(egressID string, generation uint64, memberKey string) string {
	return EgressPortPrefix(egressID, generation) + memberKey
}

// EgressPortPrefix is the common prefix of the keys of one provider instance.
func EgressPortPrefix(egressID string, generation uint64) string {
	return "egr:" + egressID + ":g" + strconv.FormatUint(generation, 10) + ":"
}

// The ports of an engine instance, by role.
const (
	PortListen = "listen" // where the edge hands it connections
	PortAPI    = "api"    // its control API
	PortSocks  = "socks"  // the edge's SOCKS port that is its way out
)

// EnginePortKey is the runtime key of a port of an engine instance, for
// example "eng:<proxyID>:g3:listen".
func EnginePortKey(proxyID string, generation uint64, role string) string {
	return "eng:" + proxyID + ":g" + strconv.FormatUint(generation, 10) + ":" + role
}

// EnginePortPrefix is the common prefix of the keys of one engine instance.
func EnginePortPrefix(proxyID string, generation uint64) string {
	return "eng:" + proxyID + ":g" + strconv.FormatUint(generation, 10) + ":"
}

// TestListenerPortKey is the runtime key of the service port of a listener's
// test listener (the loopback twin the node probes through).
func TestListenerPortKey(listenerID string) string {
	return "svc:test:" + listenerID
}

// MgmtHiddenPortKey is the runtime key of the agent's hidden management
// listener on 127.0.0.1 (spec 5.3): the port it binds, allocated once from the
// service range and kept here, which the edge forwards mgmt_sni to with PROXY
// v2. The agent allocates and records it; the reconciler reads it for the mgmt
// route.
const MgmtHiddenPortKey = "mgmt-hidden"
