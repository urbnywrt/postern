package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The values of Node.Status.
const (
	NodeStatusProvisioning = "provisioning" // created, the agent has not connected yet
	NodeStatusOnline       = "online"
	NodeStatusOffline      = "offline"
	NodeStatusError        = "error"
)

// The values of Node.MgmtMode.
const (
	MgmtModePort   = "port"   // the agent listens on a port of its own
	MgmtModeHidden = "hidden" // the agent is reached through the port of a proxy, by SNI
)

// HostInfo is what the agent of a node tells about itself and its host, as its
// GetInfo said it last. Keys that this type does not name are dropped when a
// node is stored.
type HostInfo struct {
	OS string `json:"os,omitempty"` // for example the pretty name of /etc/os-release
	// Capabilities name what the build of the node can do, sorted, such as
	// "faketls" and "edge-roll" (GetInfoResponse.capabilities). None is a
	// node older than the report: the slice-1 baseline, fake-TLS on telemt.
	Capabilities []string `json:"capabilities,omitempty"`
	// PortOwners are the processes that listen on TCP ports of the host
	// (GetInfoResponse.port_owners).
	PortOwners []PortOwner `json:"port_owners,omitempty"`
	// Binaries are the agent binaries installed in bin/ of the node
	// (GetInfoResponse.binaries).
	Binaries NodeBinaries `json:"binaries,omitzero"`
	// Healthy says that the running agent wrote the launcher's healthy marker
	// (GetInfoResponse.healthy), as its last answer said.
	Healthy bool `json:"healthy,omitempty"`
	// Warnings are the codes of what is unusual about the build of the node
	// (GetInfoResponse.warnings).
	Warnings []string `json:"warnings,omitempty"`
}

// NodeBinaries are the agent versions installed on a node, sorted, and the
// ones that bin/current and bin/previous point to ("" for a missing link), and
// the installed versions whose signature the node keeps beside the binary
// (NodeBinaries.signed_versions), the only ones besides its agent's own that
// its edge rolls to.
type NodeBinaries struct {
	Versions []string `json:"versions,omitempty"`
	Current  string   `json:"current,omitempty"`
	Previous string   `json:"previous,omitempty"`
	Signed   []string `json:"signed_versions,omitempty"`
}

// A PortOwner is a process that listens on a TCP port of a node.
type PortOwner struct {
	Bind string `json:"bind"` // the address, 0.0.0.0 or :: for all of them
	Port uint32 `json:"port"`
	// Owner names the process: a container of Postern (postern-edge-g1), or
	// another process with its id or its container ("nginx (pid 812)",
	// "caddy (container web)"), or "unknown".
	Owner string `json:"owner"`
}

// Postern reports whether the owner is Postern itself: a container of its own,
// which the node names bare (postern-edge-g1, postern-agent), never with the
// process id or the container that it gives the name of another process.
func (o PortOwner) Postern() bool {
	return strings.HasPrefix(o.Owner, "postern-") && !strings.ContainsAny(o.Owner, " (")
}

// A Node is a server that runs the Postern agent.
//
// DesiredGeneration is the number of the newest desired state of the node. It
// only ever goes up, through [DB.NextNodeGeneration], and no other method writes
// it.
type Node struct {
	ID       string
	Name     string
	MgmtHost string
	MgmtPort uint32
	MgmtMode string // MgmtModePort (the default) or MgmtModeHidden
	MgmtSNI  string
	// MgmtPublicPort is the port of the public tls listener that the panel
	// reaches the agent through, with the TLS SNI MgmtSNI, in mode hidden; 0 in
	// mode port. MgmtPort stays the plain management port in both modes.
	MgmtPublicPort uint32
	LinkHost       string // the host that proxy links on this node use

	CertFingerprint string // lower-case hex SHA-256 of the certificate of the node
	CertPEM         string // the certificate, to serve the bundle of the node again
	KeyEnc          []byte // the private key of that certificate, sealed

	DefaultChainID string // "": the node has no default egress chain of its own
	// DNSMode is how the containers of the node resolve names
	// (NodeSettings.dns_mode): "doh", "system", or "" for the default of the
	// node, doh.
	DNSMode string
	// ArtifactSource is where the node gets the engine and provider binaries
	// (NodeSettings.artifact_source): "" for the default, ArtifactSourcePanel
	// (stored as such, read back as ""), or ArtifactSourceDirect.
	ArtifactSource string

	DesiredGeneration uint64
	AppliedGeneration uint64
	WatchCursor       uint64

	AgentVersion string
	EdgeVersion  string
	Arch         string
	HostInfo     HostInfo
	PublicIPs    []string

	Status     string // one of the NodeStatus values, NodeStatusProvisioning by default
	LastSeenAt *time.Time
	Note       string

	// LastError is why the last reconcile pass of the node failed, as its
	// state report said (StateReport.last_error); "" after a pass that went
	// through. StateRejection is why the node refused the desired state that
	// the panel sent it last (ApplyStateResponse.reason); "" once the node
	// has the desired generation. The node words both, without secrets.
	LastError      string
	StateRejection string

	// EngineChannel is the channel that the proxies of the node follow,
	// ChannelStable or ChannelLatest, or "" for the default of the panel (the
	// setting SettingDefaultChannel).
	EngineChannel string
	// ProviderVersions is the version of an egress provider (xray, psiphon-core)
	// that the node runs while one is set for it, by component; a provider
	// that has none runs the version of the channel of the node. Set by
	// [DB.SetNodeProviderVersion].
	ProviderVersions map[string]string

	// PanelAddrs are the addresses that the node sees the panel come from,
	// the last IPv4 and the last IPv6 one, which it lets probe its proxies.
	PanelAddrs []string
	// EdgeRollNonce is raised by one to have the node start a new generation
	// of its edge (the fix roll_edge).
	EdgeRollNonce uint64

	CreatedAt time.Time
	UpdatedAt time.Time
}

const nodeColumns = `id, name, mgmt_host, mgmt_port, mgmt_mode, mgmt_sni, mgmt_public_port, link_host,
	cert_fingerprint, cert_pem, key_enc, default_chain_id, dns_mode, artifact_source,
	desired_generation, applied_generation, watch_cursor,
	agent_version, edge_version, arch, host_info, public_ips,
	status, last_seen_at, note, last_error, state_rejection,
	engine_channel, provider_versions, panel_addrs, edge_roll_nonce, created_at, updated_at`

func scanNode(s scanner) (*Node, error) {
	var (
		n                               Node
		mgmtPort, mgmtPublicPort        int64
		defaultChain                    sql.NullString
		desired, applied, cursor        int64
		hostInfo, publicIPs, panelAddrs string
		providerVersions                string
		edgeRollNonce                   int64
		lastSeen                        sql.NullInt64
		created, updated                int64
	)
	if err := s.Scan(&n.ID, &n.Name, &n.MgmtHost, &mgmtPort, &n.MgmtMode, &n.MgmtSNI, &mgmtPublicPort, &n.LinkHost,
		&n.CertFingerprint, &n.CertPEM, &n.KeyEnc, &defaultChain, &n.DNSMode, &n.ArtifactSource,
		&desired, &applied, &cursor,
		&n.AgentVersion, &n.EdgeVersion, &n.Arch, &hostInfo, &publicIPs,
		&n.Status, &lastSeen, &n.Note, &n.LastError, &n.StateRejection,
		&n.EngineChannel, &providerVersions, &panelAddrs, &edgeRollNonce, &created, &updated); err != nil {
		return nil, err
	}
	n.MgmtPort, n.MgmtPublicPort = uint32Of(mgmtPort), uint32Of(mgmtPublicPort)
	n.DefaultChainID = defaultChain.String
	if n.ArtifactSource == ArtifactSourcePanel {
		n.ArtifactSource = "" // the default reads as the zero value
	}
	n.DesiredGeneration, n.AppliedGeneration, n.WatchCursor = uint64Of(desired), uint64Of(applied), uint64Of(cursor)
	n.EdgeRollNonce = uint64Of(edgeRollNonce)
	if err := json.Unmarshal([]byte(hostInfo), &n.HostInfo); err != nil {
		return nil, fmt.Errorf("decode host_info: %w", err)
	}
	var err error
	if n.PublicIPs, err = decodeStrings(publicIPs); err != nil {
		return nil, fmt.Errorf("decode public_ips: %w", err)
	}
	if n.ProviderVersions, err = decodeMap[string](providerVersions); err != nil {
		return nil, fmt.Errorf("decode provider_versions: %w", err)
	}
	if n.PanelAddrs, err = decodeStrings(panelAddrs); err != nil {
		return nil, fmt.Errorf("decode panel_addrs: %w", err)
	}
	n.LastSeenAt = timePtrFromDB(lastSeen)
	n.CreatedAt, n.UpdatedAt = timeFromDB(created), timeFromDB(updated)
	return &n, nil
}

// nodeEncoded is the columns of a node that are not plain strings or times.
type nodeEncoded struct {
	hostInfo, publicIPs, panelAddrs, providerVersions string
	desired, applied, cursor                          int64
	edgeRollNonce                                     int64
}

func encodeNode(n *Node) (nodeEncoded, error) {
	var e nodeEncoded
	hostInfo, err := json.Marshal(n.HostInfo)
	if err != nil {
		return e, fmt.Errorf("encode host_info: %w", err)
	}
	e.hostInfo = string(hostInfo)
	if e.publicIPs, err = encodeStrings(n.PublicIPs); err != nil {
		return e, fmt.Errorf("encode public_ips: %w", err)
	}
	if e.providerVersions, err = encodeMap(n.ProviderVersions); err != nil {
		return e, fmt.Errorf("encode provider_versions: %w", err)
	}
	if e.panelAddrs, err = encodeStrings(n.PanelAddrs); err != nil {
		return e, fmt.Errorf("encode panel_addrs: %w", err)
	}
	if e.edgeRollNonce, err = int64Of("edge roll nonce", n.EdgeRollNonce); err != nil {
		return e, err
	}
	if e.desired, err = int64Of("desired generation", n.DesiredGeneration); err != nil {
		return e, err
	}
	if e.applied, err = int64Of("applied generation", n.AppliedGeneration); err != nil {
		return e, err
	}
	if e.cursor, err = int64Of("watch cursor", n.WatchCursor); err != nil {
		return e, err
	}
	return e, nil
}

// CreateNode stores n. It gives n an ID if it has none, a creation time if it
// has none, MgmtModePort as the mode of management and NodeStatusProvisioning
// as the status if they are empty, and the creation time as the time of the
// last update if that is not set.
func (db *DB) CreateNode(ctx context.Context, n *Node) error {
	c := *n
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.MgmtMode == "" {
		c.MgmtMode = MgmtModePort
	}
	if c.Status == "" {
		c.Status = NodeStatusProvisioning
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = db.now()
	}
	c.CreatedAt = normTime(c.CreatedAt)
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	c.UpdatedAt = normTime(c.UpdatedAt)
	c.LastSeenAt = normTimePtr(c.LastSeenAt)
	enc, err := encodeNode(&c)
	if err != nil {
		return fmt.Errorf("store: create node: %w", err)
	}

	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO nodes (`+nodeColumns+`) VALUES (`+placeholders(33)+`)`,
		c.ID, c.Name, c.MgmtHost, int64(c.MgmtPort), c.MgmtMode, c.MgmtSNI, int64(c.MgmtPublicPort), c.LinkHost,
		c.CertFingerprint, c.CertPEM, nullBlob(c.KeyEnc), nullString(c.DefaultChainID), c.DNSMode, artifactSourceOr(c.ArtifactSource),
		enc.desired, enc.applied, enc.cursor,
		c.AgentVersion, c.EdgeVersion, c.Arch, enc.hostInfo, enc.publicIPs,
		c.Status, nullTime(c.LastSeenAt), c.Note, c.LastError, c.StateRejection,
		c.EngineChannel, enc.providerVersions, enc.panelAddrs, enc.edgeRollNonce,
		c.CreatedAt.Unix(), c.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create node: %w", mapErr(err, fkMissing))
	}
	*n = c
	return nil
}

// NodeByID returns the node with this id, or [ErrNotFound].
func (db *DB) NodeByID(ctx context.Context, id string) (*Node, error) {
	n, err := scanNode(db.sql.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: node by id: %w", queryNotFound(err, "node"))
	}
	return n, nil
}

// ListNodes returns every node, in the order they were created.
func (db *DB) ListNodes(ctx context.Context) ([]*Node, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list nodes: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	return out, nil
}

const updateNodeSQL = `UPDATE nodes SET
	name = ?, mgmt_host = ?, mgmt_port = ?, mgmt_mode = ?, mgmt_sni = ?, mgmt_public_port = ?, link_host = ?,
	cert_fingerprint = ?, cert_pem = ?, key_enc = ?, default_chain_id = ?, dns_mode = ?, artifact_source = ?,
	applied_generation = ?, watch_cursor = ?,
	agent_version = ?, edge_version = ?, arch = ?, host_info = ?, public_ips = ?,
	status = ?, last_seen_at = ?, note = ?, last_error = ?, state_rejection = ?,
	engine_channel = ?, provider_versions = ?, panel_addrs = ?, edge_roll_nonce = ?, updated_at = ?
	WHERE id = ?`

// updateNode writes every column of n except the id, the desired generation and
// the creation time.
func updateNode(ctx context.Context, q dbtx, n *Node, updated time.Time) error {
	enc, err := encodeNode(n)
	if err != nil {
		return err
	}
	res, err := q.ExecContext(ctx, updateNodeSQL,
		n.Name, n.MgmtHost, int64(n.MgmtPort), n.MgmtMode, n.MgmtSNI, int64(n.MgmtPublicPort), n.LinkHost,
		n.CertFingerprint, n.CertPEM, nullBlob(n.KeyEnc), nullString(n.DefaultChainID), n.DNSMode, artifactSourceOr(n.ArtifactSource),
		enc.applied, enc.cursor,
		n.AgentVersion, n.EdgeVersion, n.Arch, enc.hostInfo, enc.publicIPs,
		n.Status, nullTime(normTimePtr(n.LastSeenAt)), n.Note, n.LastError, n.StateRejection,
		n.EngineChannel, enc.providerVersions, enc.panelAddrs, enc.edgeRollNonce, updated.Unix(),
		n.ID)
	if err != nil {
		return mapErr(err, fkMissing)
	}
	if rows, err := res.RowsAffected(); err != nil {
		return err
	} else if rows == 0 {
		return notFound("node")
	}
	return nil
}

// UpdateNode writes every field of n, except the id, the creation time and the
// desired generation, which only [DB.NextNodeGeneration] changes: a record that
// was read before the generation went up does not take it back. It sets the time
// of the last update. A node that does not exist is [ErrNotFound].
//
// The whole record is written, so two writers that read a node and write it back
// can undo each other's changes. A writer that changes some fields of a node
// that others change as well, such as the connection to the agent, uses
// [DB.ModifyNode].
func (db *DB) UpdateNode(ctx context.Context, n *Node) error {
	updated := normTime(db.now())
	if err := updateNode(ctx, db.sql, n, updated); err != nil {
		return fmt.Errorf("store: update node: %w", err)
	}
	n.UpdatedAt = updated
	n.LastSeenAt = normTimePtr(n.LastSeenAt)
	return nil
}

// ModifyNode reads the node with this id, calls fn to change it, and writes it
// back, all in one transaction, so that no one else changes the node in between.
// It returns the node as it was written. If fn returns an error nothing is
// written and ModifyNode returns that error. Whatever fn does to the id, the
// creation time or the desired generation is ignored. A node that does not exist
// is [ErrNotFound].
//
// fn runs inside the write transaction: while it runs, every other writer waits,
// and it holds one connection of the pool. It has to be quick, and it must not
// call other methods of the DB. A write of its own would wait for the lock that
// this transaction holds and fail after the busy timeout of five seconds, and any
// call can queue for a connection behind the writers that are waiting for this
// transaction. It only changes the node that it is given.
func (db *DB) ModifyNode(ctx context.Context, id string, fn func(*Node) error) (*Node, error) {
	var out *Node
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id))
		if err != nil {
			return queryNotFound(err, "node")
		}
		created, desired := n.CreatedAt, n.DesiredGeneration
		if err := fn(n); err != nil {
			return err
		}
		n.ID, n.CreatedAt, n.DesiredGeneration = id, created, desired
		updated := normTime(db.now())
		if err := updateNode(ctx, tx, n, updated); err != nil {
			return err
		}
		n.UpdatedAt = updated
		n.LastSeenAt = normTimePtr(n.LastSeenAt)
		out = n
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: modify node: %w", err)
	}
	return out, nil
}

// DeleteNode deletes a node together with everything that belongs to it:
// listeners, proxies, the statistics of both (with the countries, the health of
// the members of chains, the probes and where addresses were seen), the items of
// its proxies on the public page, its diagnostic runs and checks, the egresses
// and chains of the node, its entries in the pool of domains and the
// blacklist, and its join token. It is refused ([ErrConflict]) while a chain of
// the node is used by another node or a proxy of another node. A node that does
// not exist is [ErrNotFound].
func (db *DB) DeleteNode(ctx context.Context, id string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		// The proxies go first although the node would take them with it: a
		// proxy keeps its listener from being deleted, and which of the two a
		// cascade reaches first is up to SQLite and the order of the tables.
		if _, err := tx.ExecContext(ctx, `DELETE FROM proxies WHERE node_id = ?`, id); err != nil {
			return mapErr(err, fkInUse)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
		if err != nil {
			return mapErr(err, fkInUse)
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return notFound("node")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: delete node: %w", err)
	}
	return nil
}

// SetNodeProviderVersion sets the version of an egress provider that a node
// runs (Node.ProviderVersions), by component, and the time of the last update;
// an empty version removes it, so that the provider follows the channel of the
// node again. It changes nothing else of the node, in one transaction, so it is
// safe next to writers of other fields. A node that does not exist is
// [ErrNotFound].
func (db *DB) SetNodeProviderVersion(ctx context.Context, nodeID, component, version string) error {
	if component == "" {
		return errors.New("store: set node provider version: no component")
	}
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT provider_versions FROM nodes WHERE id = ?`, nodeID).Scan(&raw); err != nil {
			return queryNotFound(err, "node")
		}
		versions, err := decodeMap[string](raw)
		if err != nil {
			return fmt.Errorf("decode provider_versions: %w", err)
		}
		if version == "" {
			delete(versions, component)
		} else {
			if versions == nil {
				versions = map[string]string{}
			}
			versions[component] = version
		}
		enc, err := encodeMap(versions)
		if err != nil {
			return fmt.Errorf("encode provider_versions: %w", err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE nodes SET provider_versions = ?, updated_at = ? WHERE id = ?`,
			enc, normTime(db.now()).Unix(), nodeID)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: set node provider version: %w", err)
	}
	return nil
}

// NextNodeGeneration adds one to the desired generation of a node and returns
// the new value, the first time 1. The increment and the read are one statement,
// so callers that run at the same time get different numbers, and the number a
// caller gets is the one that was stored by its own increment. A node that does
// not exist is [ErrNotFound]. When the node had applied the generation before,
// the time becomes the one since which it is behind (see [DB.NodeBehindSince]).
func (db *DB) NextNodeGeneration(ctx context.Context, nodeID string) (uint64, error) {
	var gen int64
	err := db.sql.QueryRowContext(ctx,
		`UPDATE nodes SET desired_generation = desired_generation + 1, updated_at = ?1,
		   behind_since = CASE WHEN applied_generation >= desired_generation THEN ?1 ELSE behind_since END
		 WHERE id = ?2 RETURNING desired_generation`,
		normTime(db.now()).Unix(), nodeID).Scan(&gen)
	if err != nil {
		return 0, fmt.Errorf("store: next node generation: %w", queryNotFound(err, "node"))
	}
	return uint64Of(gen), nil
}

// The artifact sources of a node (Node.ArtifactSource).
const (
	ArtifactSourcePanel  = "panel"
	ArtifactSourceDirect = "direct"
)

// artifactSourceOr is the artifact source as it is stored: panel when empty.
func artifactSourceOr(s string) string {
	if s == "" {
		return ArtifactSourcePanel
	}
	return s
}
