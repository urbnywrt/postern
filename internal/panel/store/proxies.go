package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The values of Proxy.Type.
const (
	ProxyTypeFakeTLS = "faketls"
	ProxyTypeWeb     = "web"
)

// The values of Proxy.Engine.
const (
	EngineTelemt = "telemt"
	EngineMtg    = "mtg"
)

// The values of Proxy.EngineVersionPolicy.
const (
	EnginePolicyChannel = "channel" // follows the version of the channel of its node
	EnginePolicyPinned  = "pinned"  // stays on EngineVersion
	EnginePolicyRollout = "rollout" // runs EngineVersion while a rollout holds the proxy
)

// The values of Proxy.UseMiddleProxy: whether the engine of the proxy goes
// through the middle proxies of Telegram.
const (
	// MiddleProxyAuto is on when the proxy has an ad tag and off when it has none:
	// what every proxy did before the setting existed.
	MiddleProxyAuto = "auto"
	MiddleProxyOn   = "on"
	MiddleProxyOff  = "off"
)

// A Proxy is one MTProto proxy that a node serves on one of its listeners.
type Proxy struct {
	ID         string
	NodeID     string // fixed when the proxy is created
	ListenerID string // a listener of the same node
	Type       string // ProxyTypeFakeTLS by default
	Name       string
	Note       string
	Tags       []string
	// Enabled is stored as it is. A new proxy is not enabled unless the caller
	// says so.
	Enabled bool
	// SecretEnc is the sealed secret of the proxy.
	SecretEnc []byte
	Domain    string

	// WEB proxies only.
	WebBasePath   string
	WebSecretMode string // plain or dd
	WebCarrier    string
	CertMode      string // acme-tls-alpn, acme-dns01, imported or external
	// DNSCredentialID names the credential for DNS-01. It is not a foreign key:
	// the table of credentials belongs to a later slice.
	DNSCredentialID string
	ACMEEmail       string
	// The imported certificate of the proxy (cert mode imported): the chain
	// and its key, sealed (Ruling S3-1), the SHA-256 of the chain as the node
	// serves the route by it, and when the certificate expires. Nil, "" and
	// zero without one.
	CertChainEnc []byte
	CertKeyEnc   []byte
	CertSHA256   string
	CertNotAfter time.Time
	// WebPublicAddr is the public IPv4 address of a WEB proxy that the state
	// names (WebSettings.public_addr), "" to leave it to the node.
	WebPublicAddr string

	Engine              string // EngineTelemt by default
	EngineVersionPolicy string // EnginePolicyChannel by default
	EngineVersion       string

	// EgressChainID is "" for the default chain of the node.
	EgressChainID string
	// EgressScopeChains maps a scope ("me", "fetch") to the chain that it uses.
	EgressScopeChains map[string]string

	NATIP              string // the address presented to the middle proxy; "" for the node's own
	LimitDevices       uint32 // unique IPs; 0 is no limit, as for the others
	LimitConnsTotal    uint32
	LimitConnsPerIP    uint32
	AdTag              string
	MaskTargetOverride string
	// EngineOverrides are the settings of the engine that the proxy changes, as
	// JSON values by key: the keys of the whitelist of
	// internal/engines/telemt/overrides, which the panel checks them against.
	EngineOverrides map[string]any
	// UseMiddleProxy is MiddleProxyAuto, MiddleProxyOn or MiddleProxyOff;
	// MiddleProxyAuto by default.
	UseMiddleProxy string

	// RestartNonce is raised by one to have the node start a new generation of
	// the engine of the proxy (the fix recreate_instance), CertReissueNonce to
	// have it issue the certificate of a WEB proxy again (reissue_cert).
	RestartNonce     uint64
	CertReissueNonce uint64

	CreatedAt time.Time
	UpdatedAt time.Time
}

// ProxyFilter selects proxies. A field that is empty does not select.
type ProxyFilter struct {
	NodeID     string
	ListenerID string
}

const proxyColumns = `id, node_id, listener_id, type, name, note, tags, enabled, secret_enc, domain,
	web_base_path, web_secret_mode, web_carrier, cert_mode, dns_credential_id, acme_email,
	engine, engine_version_policy, engine_version, egress_chain_id, egress_scope_chains,
	nat_ip, limit_devices, limit_conns_total, limit_conns_per_ip,
	ad_tag, mask_target_override, engine_overrides, use_middle_proxy, restart_nonce, cert_reissue_nonce, created_at, updated_at,
	cert_chain_enc, cert_key_enc, cert_sha256, cert_not_after, web_public_addr`

// proxyColumnCount is how many columns proxyColumns names.
const proxyColumnCount = 38

func scanProxy(s scanner) (*Proxy, error) {
	var (
		p                                    Proxy
		tags, scope, overrides               string
		enabled                              int64
		chain                                sql.NullString
		limitDevices, limitTotal, limitPerIP int64
		restartNonce, reissueNonce           int64
		created, updated, certNotAfter       int64
	)
	if err := s.Scan(&p.ID, &p.NodeID, &p.ListenerID, &p.Type, &p.Name, &p.Note, &tags, &enabled, &p.SecretEnc, &p.Domain,
		&p.WebBasePath, &p.WebSecretMode, &p.WebCarrier, &p.CertMode, &p.DNSCredentialID, &p.ACMEEmail,
		&p.Engine, &p.EngineVersionPolicy, &p.EngineVersion, &chain, &scope,
		&p.NATIP, &limitDevices, &limitTotal, &limitPerIP,
		&p.AdTag, &p.MaskTargetOverride, &overrides, &p.UseMiddleProxy, &restartNonce, &reissueNonce, &created, &updated,
		&p.CertChainEnc, &p.CertKeyEnc, &p.CertSHA256, &certNotAfter, &p.WebPublicAddr); err != nil {
		return nil, err
	}
	p.Enabled = enabled != 0
	if certNotAfter != 0 {
		p.CertNotAfter = timeFromDB(certNotAfter)
	}
	p.EgressChainID = chain.String
	p.LimitDevices, p.LimitConnsTotal, p.LimitConnsPerIP = uint32Of(limitDevices), uint32Of(limitTotal), uint32Of(limitPerIP)
	p.RestartNonce, p.CertReissueNonce = uint64Of(restartNonce), uint64Of(reissueNonce)
	var err error
	if p.Tags, err = decodeStrings(tags); err != nil {
		return nil, fmt.Errorf("decode tags: %w", err)
	}
	if p.EgressScopeChains, err = decodeMap[string](scope); err != nil {
		return nil, fmt.Errorf("decode egress_scope_chains: %w", err)
	}
	if p.EngineOverrides, err = decodeMap[any](overrides); err != nil {
		return nil, fmt.Errorf("decode engine_overrides: %w", err)
	}
	p.CreatedAt, p.UpdatedAt = timeFromDB(created), timeFromDB(updated)
	return &p, nil
}

// proxyEncoded is the columns of a proxy that are JSON, and the nonces.
type proxyEncoded struct {
	tags, scope, overrides     string
	restartNonce, reissueNonce int64
}

func encodeProxy(p *Proxy) (proxyEncoded, error) {
	var (
		e   proxyEncoded
		err error
	)
	if e.restartNonce, err = int64Of("restart nonce", p.RestartNonce); err != nil {
		return e, err
	}
	if e.reissueNonce, err = int64Of("certificate reissue nonce", p.CertReissueNonce); err != nil {
		return e, err
	}
	if e.tags, err = encodeStrings(p.Tags); err != nil {
		return e, fmt.Errorf("encode tags: %w", err)
	}
	if e.scope, err = encodeMap(p.EgressScopeChains); err != nil {
		return e, fmt.Errorf("encode egress_scope_chains: %w", err)
	}
	if e.overrides, err = encodeMap(p.EngineOverrides); err != nil {
		return e, fmt.Errorf("encode engine_overrides: %w", err)
	}
	return e, nil
}

// CreateProxy stores p. It gives p an ID if it has none, a creation time if it
// has none, ProxyTypeFakeTLS, EngineTelemt, EnginePolicyChannel and
// MiddleProxyAuto for the type, the engine, the version policy and the
// middle-proxy setting if they are empty, and the creation time as the time of
// the last update if that is not set.
//
// A node, a listener of that node, or a chain that does not exist is
// [ErrNotFound]: a proxy can only use a listener of its own node. A
// middle-proxy setting that is not one of the three is an error.
func (db *DB) CreateProxy(ctx context.Context, p *Proxy) error {
	return insertProxy(ctx, db.sql, db.now(), p)
}

// insertProxy is [DB.CreateProxy] on q, with now as the time of the clock.
func insertProxy(ctx context.Context, q dbtx, now time.Time, p *Proxy) error {
	c := *p
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.UseMiddleProxy == "" {
		c.UseMiddleProxy = MiddleProxyAuto
	}
	if c.Type == "" {
		c.Type = ProxyTypeFakeTLS
	}
	if c.Engine == "" {
		c.Engine = EngineTelemt
	}
	if c.EngineVersionPolicy == "" {
		c.EngineVersionPolicy = EnginePolicyChannel
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.CreatedAt = normTime(c.CreatedAt)
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	c.UpdatedAt = normTime(c.UpdatedAt)
	enc, err := encodeProxy(&c)
	if err != nil {
		return fmt.Errorf("store: create proxy: %w", err)
	}

	_, err = q.ExecContext(ctx,
		`INSERT INTO proxies (`+proxyColumns+`) VALUES (`+placeholders(proxyColumnCount)+`)`,
		c.ID, c.NodeID, c.ListenerID, c.Type, c.Name, c.Note, enc.tags, boolInt(c.Enabled), blobValue(c.SecretEnc), c.Domain,
		c.WebBasePath, c.WebSecretMode, c.WebCarrier, c.CertMode, c.DNSCredentialID, c.ACMEEmail,
		c.Engine, c.EngineVersionPolicy, c.EngineVersion, nullString(c.EgressChainID), enc.scope,
		c.NATIP, int64(c.LimitDevices), int64(c.LimitConnsTotal), int64(c.LimitConnsPerIP),
		c.AdTag, c.MaskTargetOverride, enc.overrides, c.UseMiddleProxy, enc.restartNonce, enc.reissueNonce,
		c.CreatedAt.Unix(), c.UpdatedAt.Unix(),
		blobValue(c.CertChainEnc), blobValue(c.CertKeyEnc), c.CertSHA256, certNotAfterOf(&c), c.WebPublicAddr)
	if err != nil {
		return fmt.Errorf("store: create proxy: %w", mapErr(err, fkMissing))
	}
	*p = c
	return nil
}

// ProxyByID returns the proxy with this id, or [ErrNotFound].
func (db *DB) ProxyByID(ctx context.Context, id string) (*Proxy, error) {
	p, err := scanProxy(db.sql.QueryRowContext(ctx, `SELECT `+proxyColumns+` FROM proxies WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: proxy by id: %w", queryNotFound(err, "proxy"))
	}
	return p, nil
}

// ListProxies returns the proxies that the filter selects, in the order they
// were created.
func (db *DB) ListProxies(ctx context.Context, f ProxyFilter) ([]*Proxy, error) {
	query := `SELECT ` + proxyColumns + ` FROM proxies`
	var (
		where []string
		args  []any
	)
	if f.NodeID != "" {
		where = append(where, `node_id = ?`)
		args = append(args, f.NodeID)
	}
	if f.ListenerID != "" {
		where = append(where, `listener_id = ?`)
		args = append(args, f.ListenerID)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY created_at, id`
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list proxies: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list proxies: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list proxies: %w", err)
	}
	return out, nil
}

// UpdateProxy writes every field of p except the id, the node and the creation
// time, and sets the time of the last update. An empty middle-proxy setting is
// MiddleProxyAuto, and p gets it. The proxy is found by its id and its node
// together: a proxy of another node, whatever its id, is [ErrNotFound], and
// nothing is changed. So is a listener of another node, or a chain that does not
// exist. A middle-proxy setting that is not one of the three is an error.
func (db *DB) UpdateProxy(ctx context.Context, p *Proxy) error {
	enc, err := encodeProxy(p)
	if err != nil {
		return fmt.Errorf("store: update proxy: %w", err)
	}
	if p.UseMiddleProxy == "" {
		p.UseMiddleProxy = MiddleProxyAuto
	}
	updated := normTime(db.now())
	res, err := db.sql.ExecContext(ctx,
		`UPDATE proxies SET listener_id = ?, type = ?, name = ?, note = ?, tags = ?, enabled = ?, secret_enc = ?, domain = ?,
		 web_base_path = ?, web_secret_mode = ?, web_carrier = ?, cert_mode = ?, dns_credential_id = ?, acme_email = ?,
		 engine = ?, engine_version_policy = ?, engine_version = ?, egress_chain_id = ?, egress_scope_chains = ?,
		 nat_ip = ?, limit_devices = ?, limit_conns_total = ?, limit_conns_per_ip = ?,
		 ad_tag = ?, mask_target_override = ?, engine_overrides = ?, use_middle_proxy = ?,
		 restart_nonce = ?, cert_reissue_nonce = ?, updated_at = ?,
		 cert_chain_enc = ?, cert_key_enc = ?, cert_sha256 = ?, cert_not_after = ?, web_public_addr = ?
		 WHERE id = ? AND node_id = ?`,
		p.ListenerID, p.Type, p.Name, p.Note, enc.tags, boolInt(p.Enabled), blobValue(p.SecretEnc), p.Domain,
		p.WebBasePath, p.WebSecretMode, p.WebCarrier, p.CertMode, p.DNSCredentialID, p.ACMEEmail,
		p.Engine, p.EngineVersionPolicy, p.EngineVersion, nullString(p.EgressChainID), enc.scope,
		p.NATIP, int64(p.LimitDevices), int64(p.LimitConnsTotal), int64(p.LimitConnsPerIP),
		p.AdTag, p.MaskTargetOverride, enc.overrides, p.UseMiddleProxy, enc.restartNonce, enc.reissueNonce, updated.Unix(),
		blobValue(p.CertChainEnc), blobValue(p.CertKeyEnc), p.CertSHA256, certNotAfterOf(p), p.WebPublicAddr,
		p.ID, p.NodeID)
	if err != nil {
		return fmt.Errorf("store: update proxy: %w", mapErr(err, fkMissing))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: update proxy: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: update proxy: %w", notFound("proxy"))
	}
	p.UpdatedAt = updated
	return nil
}

// certNotAfterOf is the cert_not_after column of a proxy: 0 without a
// certificate.
func certNotAfterOf(p *Proxy) int64 {
	if p.CertNotAfter.IsZero() {
		return 0
	}
	return p.CertNotAfter.Unix()
}

// NodesUsingDNSCredential returns the ids of the nodes that have a proxy
// naming the credential, each once, in no particular order.
func (db *DB) NodesUsingDNSCredential(ctx context.Context, credentialID string) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT DISTINCT node_id FROM proxies WHERE dns_credential_id = ?`, credentialID)
	if err != nil {
		return nil, fmt.Errorf("store: nodes using dns credential: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: nodes using dns credential: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: nodes using dns credential: %w", err)
	}
	return out, nil
}

// DeleteProxy deletes a proxy, its statistics (with the countries, the probes
// and where addresses were seen) and its item on the public page. A proxy that
// does not exist is [ErrNotFound].
func (db *DB) DeleteProxy(ctx context.Context, id string) error {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM proxies WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete proxy: %w", mapErr(err, fkInUse))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: delete proxy: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: delete proxy: %w", notFound("proxy"))
	}
	return nil
}
