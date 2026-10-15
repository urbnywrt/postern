// Package nodes is the registry of nodes and the connection of the panel to
// them.
//
// The panel owns a certificate authority, kept in the settings with its key
// sealed. CreateNode issues each node a server certificate from it, and the
// node is installed from a bundle that carries that certificate, its key and
// the CA. The panel itself holds a client certificate of the same CA.
//
// The Manager keeps one connection to every node: gRPC over HTTP/2 and mutual
// TLS, pinned to the fingerprint of the certificate that the node was issued.
// Over it the manager pushes the desired state of the node (ApplyState) and
// consumes the records that the node streams (Watch).
//
// The names in the certificates are neutral on purpose. The management port
// shows its certificate to anybody who connects, and a product name in it
// would tell a scanner what runs there.
package nodes

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
)

// The names in the certificates.
const (
	caCommonName     = "Internal CA"
	clientCommonName = "client"
	nodeDomainSuffix = ".internal"
)

// The settings that hold the PKI of the panel, and the additional data that
// their keys are sealed with. Both are a sealedCert.
const (
	settingCA          = "pki.ca"
	settingPanelClient = "pki.panel_client"
)

// sealedCert is a certificate with its private key, as the settings keep it.
// KeyEnc is the PEM of the key, sealed with the master key and the name of the
// setting (or, for a node, nodeKeyAAD) as additional data.
type sealedCert struct {
	CertPEM string `json:"cert_pem"`
	KeyEnc  []byte `json:"key_enc"`
}

// pkiMu makes the creation of the CA and of the client certificate happen
// once: two callers that both find nothing must not both create one, or the
// second would replace what the first may have used already.
var pkiMu sync.Mutex

// LoadOrCreateCA returns the CA of the panel, which is kept in the setting
// "pki.ca" with its key sealed by key. The first call creates it: an ECDSA
// P-256 CA named "Internal CA", valid for 20 years.
//
// A CA that is stored but cannot be loaded (another master key, a damaged
// setting) is an error. It is never replaced, since every node trusts it.
func LoadOrCreateCA(ctx context.Context, db *store.DB, key seal.Key) (*pki.CA, error) {
	pkiMu.Lock()
	defer pkiMu.Unlock()

	certPEM, keyPEM, found, err := loadSealed(ctx, db, key, settingCA)
	if err != nil {
		return nil, fmt.Errorf("nodes: load the CA: %w", err)
	}
	if found {
		ca, err := pki.LoadCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("nodes: load the CA: %w", err)
		}
		return ca, nil
	}

	ca, keyPEM, err := pki.NewCA(caCommonName)
	if err != nil {
		return nil, fmt.Errorf("nodes: create the CA: %w", err)
	}
	if err := storeSealed(ctx, db, key, settingCA, ca.CertPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("nodes: store the CA: %w", err)
	}
	return ca, nil
}

// loadOrCreateClientCert returns the client certificate of the panel and its
// key, as PEM, from the setting "pki.panel_client". The first call issues it
// from ca: a certificate named "client" for client authentication only.
//
// A stored certificate that ca did not issue is an error and is left as it
// is: the nodes would refuse it, and that is for an operator to look into.
func loadOrCreateClientCert(ctx context.Context, db *store.DB, key seal.Key, ca *pki.CA) (certPEM, keyPEM []byte, err error) {
	pkiMu.Lock()
	defer pkiMu.Unlock()

	certPEM, keyPEM, found, err := loadSealed(ctx, db, key, settingPanelClient)
	if err != nil {
		return nil, nil, fmt.Errorf("nodes: load the panel client certificate: %w", err)
	}
	if found {
		if err := checkIssuedBy(certPEM, ca); err != nil {
			return nil, nil, fmt.Errorf("nodes: the panel client certificate: %w", err)
		}
		return certPEM, keyPEM, nil
	}

	certPEM, keyPEM, err = ca.IssueClient(clientCommonName)
	if err != nil {
		return nil, nil, fmt.Errorf("nodes: issue the panel client certificate: %w", err)
	}
	if err := storeSealed(ctx, db, key, settingPanelClient, certPEM, keyPEM); err != nil {
		return nil, nil, fmt.Errorf("nodes: store the panel client certificate: %w", err)
	}
	return certPEM, keyPEM, nil
}

// loadSealed reads a sealedCert setting and opens its key. found is false when
// the setting does not exist.
func loadSealed(ctx context.Context, db *store.DB, key seal.Key, setting string) (certPEM, keyPEM []byte, found bool, err error) {
	var s sealedCert
	found, err = db.GetSetting(ctx, setting, &s)
	if err != nil || !found {
		return nil, nil, found, err
	}
	if s.CertPEM == "" || len(s.KeyEnc) == 0 {
		return nil, nil, true, fmt.Errorf("setting %q has no certificate or no key", setting)
	}
	keyPEM, err = seal.Open(key, s.KeyEnc, []byte(setting))
	if err != nil {
		return nil, nil, true, fmt.Errorf("open the key of setting %q: %w", setting, err)
	}
	return []byte(s.CertPEM), keyPEM, true, nil
}

// storeSealed seals keyPEM and stores it with certPEM in a setting.
func storeSealed(ctx context.Context, db *store.DB, key seal.Key, setting string, certPEM, keyPEM []byte) error {
	keyEnc, err := seal.Seal(key, keyPEM, []byte(setting))
	if err != nil {
		return err
	}
	return db.PutSetting(ctx, setting, sealedCert{CertPEM: string(certPEM), KeyEnc: keyEnc})
}

// checkIssuedBy checks that the first certificate in certPEM chains to ca and
// is good for client authentication.
func checkIssuedBy(certPEM []byte, ca *pki.CA) error {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("no certificate found in PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return fmt.Errorf("it was not issued by the CA of the panel: %w", err)
	}
	return nil
}

// nodeCommonName is the common name of the certificate of a node: its id in
// lower case.
func nodeCommonName(id string) string { return ids.Lower(id) }

// nodeDNSName is the DNS name in the certificate of a node, and the SNI that
// the panel sends when the node has no management SNI of its own.
func nodeDNSName(id string) string { return ids.Lower(id) + nodeDomainSuffix }

// nodeKeyAAD is the additional data that the private key of a node is sealed
// with, which ties the sealed key to its node.
func nodeKeyAAD(id string) []byte { return []byte("node_key:" + id) }
