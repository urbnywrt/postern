package acme

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Domains returns the domains that have a certificate directory under
// data/certs, sorted. A name that is not a domain (validDomain) is left out.
func (m *Manager) Domains() ([]string, error) {
	entries, err := os.ReadDir(m.Paths.CertsDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && validDomain(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Remove deletes the certificate of domain from the node: its directory (the
// chain, the private key, meta.json), and what the manager keeps of the domain
// (Forget). A domain whose issuance or import runs is left alone: removed is
// then false. The ACME account, which every domain shares, stays.
func (m *Manager) Remove(domain string) (removed bool, err error) {
	if err := validDomain(domain); err != nil {
		return false, err
	}
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flights[domain] != nil {
		return false, nil
	}
	delete(m.tracked, domain)
	delete(m.failures, domain)
	delete(m.nonces, domain)
	delete(m.touched, domain)
	if err := os.RemoveAll(m.certDir(domain)); err != nil {
		return false, err
	}
	return true, nil
}

// ErrNoRoots is returned by Trusted when the system's roots cannot be loaded:
// nothing is known about the chain then.
var ErrNoRoots = errors.New("acme: the system's root certificates cannot be loaded")

// Trusted verifies the stored chain of domain against roots (nil: the
// system's) for the domain, as a client that checks the certificate would; nil
// when it is trusted. A chain before its notBefore is judged at its notBefore
// (the clock tolerance), one after its notAfter at its notAfter: expiry is
// web.cert's to judge, not this.
func (m *Manager) Trusted(domain string, roots *x509.CertPool) error {
	if err := validDomain(domain); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(m.certDir(domain), fullchainFile))
	if err != nil {
		return err
	}
	var chain []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("the chain cannot be parsed: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return errors.New("the chain holds no certificate")
	}
	if roots == nil {
		if roots, err = x509.SystemCertPool(); err != nil || roots == nil {
			return ErrNoRoots
		}
	}
	leaf := chain[0]
	at := m.now()
	if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore
	}
	if at.After(leaf.NotAfter) {
		at = leaf.NotAfter
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: domain, Roots: roots, Intermediates: inter, CurrentTime: at})
	return err
}
