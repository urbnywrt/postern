package proxies

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/webrules"
)

// A ClientSource gives the client of a connected node: the node manager.
type ClientSource interface {
	Client(nodeID string) (nodev1connect.NodeServiceClient, error)
}

// pushTimeout bounds one push of the certificates of a node; putTimeout
// bounds each PutCertificate inside it, so that one node that hangs on one
// certificate does not spend the whole budget on it.
const (
	pushTimeout = 60 * time.Second
	putTimeout  = 10 * time.Second
)

// CertSync sends the imported certificates of the WEB proxies to their nodes
// with PutCertificate (Ruling S3-1): when a certificate changes (the service
// calls PushCertificates) and whenever a node connects (the node manager
// calls OnConnected). PutCertificate is idempotent by content, so every
// imported certificate of the node is sent each time; the node serves a
// route once the chain it stores is the one that the state names.
type CertSync struct {
	db      *store.DB
	key     seal.Key
	clients ClientSource
	log     *slog.Logger
}

// NewCertSync returns a sync that opens the certificates with key and reaches
// the nodes through clients. A nil log discards the log.
func NewCertSync(db *store.DB, key seal.Key, clients ClientSource, log *slog.Logger) *CertSync {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &CertSync{db: db, key: key, clients: clients, log: log}
}

// PushCertificates sends the imported certificates of a node in the
// background. A node that is not connected gets them when it connects.
func (c *CertSync) PushCertificates(nodeID string) {
	client, err := c.clients.Client(nodeID)
	if err != nil {
		c.log.Debug("the certificates of a node are not pushed now: it is not connected", "node", nodeID, "err", err)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
		defer cancel()
		c.push(ctx, nodeID, client)
	}()
}

// OnConnected sends the imported certificates of a node that connected,
// before its state is pushed.
func (c *CertSync) OnConnected(ctx context.Context, nodeID string, client nodev1connect.NodeServiceClient) {
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	c.push(ctx, nodeID, client)
}

// push sends every imported certificate of the node. Faults are logged
// without any part of the certificates.
func (c *CertSync) push(ctx context.Context, nodeID string, client nodev1connect.NodeServiceClient) {
	ps, err := c.db.ListProxies(ctx, store.ProxyFilter{NodeID: nodeID})
	if err != nil {
		c.log.Error("could not list the proxies of a node to push its certificates", "node", nodeID, "err", err)
		return
	}
	for _, p := range ps {
		if p.Type != store.ProxyTypeWeb || p.CertMode != webrules.CertModeImported || p.CertChainEnc == nil {
			continue
		}
		log := c.log.With("node", nodeID, "proxy", p.ID)
		chain, key, err := openCert(c.key, p)
		if err != nil {
			log.Error("could not open an imported certificate", "err", err)
			continue
		}
		domain, err := webrules.CertDomain(p.Domain)
		if err != nil {
			log.Error("the domain of a web proxy names no certificate", "err", err)
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, putTimeout)
		resp, err := client.PutCertificate(callCtx, connect.NewRequest(&nodev1.PutCertificateRequest{
			Domain: domain, FullchainPem: chain, KeyPem: key,
		}))
		cancel()
		if err != nil {
			// The next certificate is tried all the same; only the end of
			// the whole budget stops the push.
			log.Warn("could not put an imported certificate on the node", "domain", domain, "err", err)
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if resp.Msg.GetSha256() != p.CertSHA256 {
			log.Warn("the node stored a certificate whose digest is not the one the panel knows", "domain", domain,
				"node_sha256", resp.Msg.GetSha256(), "panel_sha256", p.CertSHA256)
			continue
		}
		if resp.Msg.GetStored() {
			log.Info("imported certificate put on the node", "domain", domain, "not_after", resp.Msg.GetNotAfter())
		}
	}
}
