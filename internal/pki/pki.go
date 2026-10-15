// Package pki is the private PKI that secures the panel-to-node channel.
//
// The panel owns a certificate authority. Every node gets a server certificate
// from it and the panel gets a client certificate; the two sides then
// authenticate each other over TLS 1.3. The panel does not look at host names:
// it checks the chain against the CA, the purpose of the certificate and the
// fingerprint it remembered for the node. That is why the SNI of a management
// connection can be any plausible domain.
//
// A Bundle carries a node's credentials to the machine it is installed on.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	pemCertificate = "CERTIFICATE"
	pemPrivateKey  = "PRIVATE KEY"    // PKCS #8
	pemECPrivate   = "EC PRIVATE KEY" // SEC 1

	caYears   = 20
	leafYears = 10

	// clockSkew is how far NotBefore is set back from the moment of issue.
	// Nodes are ordinary servers, and one whose clock runs a little slow
	// would otherwise refuse a certificate issued seconds ago.
	clockSkew = time.Hour
)

// CA is the panel's certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// CertPEM is the CA certificate alone, PEM encoded: the trust anchor that
	// goes into node bundles.
	CertPEM []byte
}

// NewCA creates a self-signed CA with a fresh ECDSA P-256 key, valid for 20
// years. The CA signs end-entity certificates only.
//
// keyPEM is the private key as a PKCS #8 PEM block, for the caller to store. It
// is the root of all trust here, so it must be stored encrypted; this package
// persists nothing itself.
func NewCA(commonName string) (ca *CA, keyPEM []byte, err error) {
	now := time.Now()
	return newCA(commonName, now.Add(-clockSkew), now.AddDate(caYears, 0, 0))
}

// newCA is NewCA with an explicit validity period, which the tests use to
// build CAs that are about to expire or already have.
func newCA(commonName string, notBefore, notAfter time.Time) (*CA, []byte, error) {
	if commonName == "" {
		return nil, nil, errors.New("pki: CA common name is empty")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		// No intermediate CAs below this one: if a bug ever made it sign a
		// CA certificate, chains through that certificate would not verify.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: encodeCert(der)}, keyPEM, nil
}

// LoadCA restores a CA from its certificate and private key, as returned by
// NewCA. The key may be a PKCS #8 or a SEC 1 (EC PRIVATE KEY) block.
//
// Only the first certificate and the first key found in the input are used,
// and CertPEM is rebuilt from the certificate alone. A file that holds the key
// next to the certificate therefore cannot leak the key into node bundles.
//
// The validity period is not checked here, so that an expired CA can still be
// loaded and reported on; IssueServer and IssueClient refuse to sign with one.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("pki: certificate is not a CA certificate")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("pki: CA certificate key usage does not allow signing certificates")
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("pki: CA key does not match the CA certificate")
	}
	return &CA{Cert: cert, Key: key, CertPEM: encodeCert(cert.Raw)}, nil
}

// IssueServer issues a server certificate for a node, valid for 10 years (but
// never beyond the CA's own validity) and for server authentication only. The
// key is a fresh ECDSA P-256 key, returned as a PKCS #8 PEM block.
//
// dnsNames and ips become subject alternative names. The panel never checks
// them, so they matter only to other tools that talk to the node.
func (ca *CA) IssueServer(cn string, dnsNames []string, ips []net.IP) (certPEM, keyPEM []byte, err error) {
	return ca.issue(serverTemplate(cn, dnsNames, ips))
}

// MaxCSRSize bounds the DER encoding of a certificate request that
// SignServerCSR accepts. A P-256 request with a short subject is a few hundred
// bytes.
const MaxCSRSize = 8 << 10

// SignServerCSR issues a node server certificate for the public key of a
// certificate request, with exactly the fields IssueServer gives (cn, the DNS
// names, server authentication only, the same validity). The request's
// subject and extensions are ignored: only its key is used, and only after its
// signature proves the sender holds the private key.
func (ca *CA) SignServerCSR(csrDER []byte, cn string, dnsNames []string) (certPEM []byte, err error) {
	pub, err := ParseServerCSR(csrDER)
	if err != nil {
		return nil, err
	}
	return ca.sign(serverTemplate(cn, dnsNames, nil), pub)
}

// ParseServerCSR checks a DER certificate request the way SignServerCSR does
// (size, signature, an ECDSA P-256 key, the only kind this PKI issues) and
// returns its public key.
func ParseServerCSR(csrDER []byte) (*ecdsa.PublicKey, error) {
	if len(csrDER) == 0 {
		return nil, errors.New("pki: the certificate request is empty")
	}
	if len(csrDER) > MaxCSRSize {
		return nil, fmt.Errorf("pki: the certificate request is larger than %d bytes", MaxCSRSize)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("pki: parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: certificate request signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("pki: the certificate request key is not an ECDSA P-256 key")
	}
	return pub, nil
}

// serverTemplate is what a node server certificate says, shared by
// IssueServer and SignServerCSR so that the two cannot drift apart.
func serverTemplate(cn string, dnsNames []string, ips []net.IP) *x509.Certificate {
	return &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dnsNames,
		IPAddresses: ips,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// IssueClient issues a client certificate for the panel, with the same
// validity and key as IssueServer but for client authentication only.
//
// The two purposes are kept apart on purpose: a node's own certificate is not
// accepted as a panel credential, so a captured node cannot manage the others.
func (ca *CA) IssueClient(cn string) (certPEM, keyPEM []byte, err error) {
	return ca.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// issue makes a fresh key and signs tmpl for it.
func (ca *CA) issue(tmpl *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	if err := ca.checkIssue(tmpl); err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate key: %w", err)
	}
	certPEM, err = ca.sign(tmpl, &key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// checkIssue refuses what no certificate of this CA may be: one without a
// common name, or one signed by an expired CA.
func (ca *CA) checkIssue(tmpl *x509.Certificate) error {
	if tmpl.Subject.CommonName == "" {
		return errors.New("pki: certificate common name is empty")
	}
	if !time.Now().Before(ca.Cert.NotAfter) {
		return fmt.Errorf("pki: the CA certificate expired on %s", ca.Cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// sign completes tmpl with what every end-entity certificate of this CA has
// in common, and signs it for pub.
func (ca *CA) sign(tmpl *x509.Certificate, pub *ecdsa.PublicKey) (certPEM []byte, err error) {
	if err := ca.checkIssue(tmpl); err != nil {
		return nil, err
	}
	now := time.Now()
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	tmpl.SerialNumber = serial
	tmpl.NotBefore = now.Add(-clockSkew)
	tmpl.NotAfter = now.AddDate(leafYears, 0, 0)
	if tmpl.NotAfter.After(ca.Cert.NotAfter) {
		tmpl.NotAfter = ca.Cert.NotAfter // never outlive the issuer
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.BasicConstraintsValid = true // with IsCA unset: an explicit CA:FALSE

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: create certificate: %w", err)
	}
	return encodeCert(der), nil
}

// Fingerprint returns the lowercase hex SHA-256 of the DER encoding of the
// first certificate in certPEM, which for a chain is the leaf. The panel stores
// it for each node and pins connections to it.
func Fingerprint(certPEM []byte) (string, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return "", err
	}
	return fingerprintOf(cert), nil
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// newSerial returns a random serial number in [1, 2^128).
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	limit.Sub(limit, big.NewInt(1))
	n, err := rand.Int(rand.Reader, limit) // [0, 2^128-1)
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial number: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: der})
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: der}), nil
}

// parseCertificate parses the first CERTIFICATE block of data. Other blocks
// are skipped, as crypto/tls does.
func parseCertificate(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("pki: no certificate found in PEM data")
		}
		if block.Type != pemCertificate {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate: %w", err)
		}
		return cert, nil
	}
}

// parseKey parses the first ECDSA private key in data, PKCS #8 or SEC 1.
func parseKey(data []byte) (*ecdsa.PrivateKey, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("pki: no private key found in PEM data")
		}
		switch block.Type {
		case pemPrivateKey:
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parse private key: %w", err)
			}
			key, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("pki: private key is not an ECDSA key")
			}
			return key, nil
		case pemECPrivate:
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parse private key: %w", err)
			}
			return key, nil
		}
	}
}
