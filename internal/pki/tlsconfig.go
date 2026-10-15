package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrPinMismatch is the cause of a failed handshake when the server's
// certificate is valid but is not the one pinned for the node. It is wrapped
// with the fingerprint that was presented and the one that was pinned, so use
// errors.Is to recognise it.
var ErrPinMismatch = errors.New("pki: server certificate does not match the pinned fingerprint")

var (
	errNoServerAuth = errors.New("pki: server certificate lacks the serverAuth extended key usage")
	errNoClientAuth = errors.New("pki: client certificate lacks the clientAuth extended key usage")
)

// ServerTLSConfig returns the TLS configuration of a node's management
// listener: TLS 1.3 only, presenting certPEM and keyPEM, and accepting only
// clients whose certificate was issued by the CA in caPEM for client
// authentication.
//
// The returned configuration sets no ALPN protocols; the caller adds what its
// HTTP stack needs.
func ServerTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	roots, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load server certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// RequireAndVerifyClientCert checks the chain against ClientCAs for
		// the clientAuth usage. verifyClient adds the checks it leaves out.
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        roots,
		VerifyConnection: verifyClient,
	}, nil
}

// ClientTLSConfig returns the TLS configuration with which the panel dials a
// node: TLS 1.3 only, presenting certPEM and keyPEM as its client certificate.
//
// serverName is sent as the SNI and used for nothing else. The server's
// certificate is not checked against any host name; it must instead
//
//   - chain to the CA in caPEM,
//   - be issued for server authentication, and
//   - when pinnedFingerprint is not empty, have exactly that fingerprint (see
//     Fingerprint; the comparison ignores case).
//
// A failed pin check yields an error that wraps ErrPinMismatch. A pin that is
// not a fingerprint at all can never match, so it fails the same way.
//
// The returned configuration sets no ALPN protocols; the caller adds what its
// HTTP stack needs.
func ClientTLSConfig(caPEM, certPEM, keyPEM []byte, serverName, pinnedFingerprint string) (*tls.Config, error) {
	roots, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load client certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		// The standard verification insists on checking serverName against
		// the certificate. The management SNI is arbitrary by design, so
		// verification is switched off here and done in full by
		// verifyServer, minus the host name. VerifyConnection runs on every
		// connection, resumed ones included.
		InsecureSkipVerify: true, //nolint:gosec // replaced by verifyServer below
		VerifyConnection:   verifyServer(roots, strings.ToLower(pinnedFingerprint)),
		// Not consulted while InsecureSkipVerify is set. It keeps the
		// configuration confined to our CA, not the system's, should a caller
		// ever turn the standard verification back on.
		RootCAs: roots,
	}, nil
}

// verifyClient is the server's VerifyConnection. By the time it runs, crypto/tls
// has verified the client's chain. It then insists that the certificate states
// the clientAuth usage outright: the standard library takes a certificate with
// no extended key usages, or with anyExtendedKeyUsage, for good in every role.
func verifyClient(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
		return errors.New("pki: client certificate required")
	}
	if !slices.Contains(cs.PeerCertificates[0].ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return errNoClientAuth
	}
	return nil
}

// verifyServer returns the client's VerifyConnection. pin is the lowercase
// fingerprint to require, or empty for none.
func verifyServer(roots *x509.CertPool, pin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("pki: server presented no certificate")
		}
		leaf := cs.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		// DNSName is left empty on purpose: no host name check.
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return fmt.Errorf("pki: verify server certificate: %w", err)
		}
		// See verifyClient: the usage must be stated, not merely not excluded.
		if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			return errNoServerAuth
		}
		// The pin comes on top of the chain check, never instead of it.
		if pin != "" {
			if got := fingerprintOf(leaf); got != pin {
				return fmt.Errorf("%w: presented %s, pinned %s", ErrPinMismatch, got, pin)
			}
		}
		return nil
	}
}

// certPool returns a pool of the certificates in caPEM.
func certPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("pki: no CA certificate found in PEM data")
	}
	return pool, nil
}
