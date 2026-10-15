package edge

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/urbnywrt/postern/internal/webrules"
)

// The certificates of the WEB domains.
//
// The node keeps the certificate of a WEB domain in a directory of the domain
// under its certificate directory, data/certs/<domain>/: the chain in
// fullchain.pem and the key in privkey.pem. The ACME manager of the agent writes
// them there, and an imported certificate is copied there. The edge sees the
// directory read-only.
//
// The configuration names the domains with a generation each (CertRef). The
// edge reads the files of a domain when the domain first comes and whenever its
// generation changes, and at no other time: the agent raises the generation
// when it writes new files. Reading them never fails Apply. While the files of
// a generation cannot be read, the edge serves the certificate of an earlier
// generation if it has one, and tries the files again with every Apply, which
// the agent makes every pass. A connection for a web route is served the
// certificate of its name when there is one that is valid for the name now;
// otherwise it gets the TLS alert unrecognized_name.
//
// The key is never logged, and neither is any part of the files.

const (
	certChainFile = "fullchain.pem"
	certKeyFile   = "privkey.pem"
	// maxCertFile is the most bytes read of either file: a chain of a few
	// certificates is some kilobytes, and a key less.
	maxCertFile = 1 << 20
	// certWarnInterval is how often, at most, a certificate that cannot be read
	// or served is logged, for one domain.
	certWarnInterval = time.Minute
)

var (
	errNoCert          = errors.New("no certificate is configured for the domain")
	errCertExpired     = errors.New("the certificate has expired")
	errCertNotYetValid = errors.New("the certificate is not valid yet")
)

// certRef is a certificate the configuration names: CertRef, with its domain
// folded (rules.FoldName).
type certRef struct {
	domain string
	gen    uint64
}

// certEntry is the state of the certificate of one domain. Nothing in it
// changes once update has made it.
type certEntry struct {
	gen  uint64           // the generation the configuration names
	cert *tls.Certificate // the certificate served, with its Leaf; nil when there is none
	err  error            // why the files of gen could not be read; nil once they were
}

// certStore holds the certificates of the WEB domains, by folded domain. A
// lookup takes no lock: update replaces the whole map.
type certStore struct {
	dir     string
	entries atomic.Pointer[map[string]*certEntry]
}

func newCertStore(dir string) *certStore {
	s := &certStore{dir: dir}
	s.entries.Store(&map[string]*certEntry{})
	return s
}

// certLoad is a reading of the files of a domain by update, for the log.
type certLoad struct {
	domain   string
	gen      uint64
	err      error     // why they could not be read; nil when they were
	kept     bool      // they could not be read, and the certificate of an earlier generation is still served
	notAfter time.Time // when the certificate read expires
}

// update makes refs the certificates of the store, and returns what it read.
// It reads the files of a domain that is new, whose generation changed, or
// whose generation could not be read before, and of no other. A domain that
// refs does not name is forgotten. update is called by one goroutine at a time.
func (s *certStore) update(refs []certRef) []certLoad {
	old := *s.entries.Load()
	next := make(map[string]*certEntry, len(refs))
	var loads []certLoad
	for _, r := range refs {
		prev := old[r.domain]
		if prev != nil && prev.gen == r.gen && prev.err == nil {
			next[r.domain] = prev
			continue
		}
		cert, err := s.load(r.domain)
		entry := &certEntry{gen: r.gen, cert: cert, err: err}
		l := certLoad{domain: r.domain, gen: r.gen, err: err}
		switch {
		case err == nil:
			l.notAfter = cert.Leaf.NotAfter
		case prev != nil && prev.cert != nil:
			entry.cert, l.kept = prev.cert, true
		}
		next[r.domain] = entry
		loads = append(loads, l)
	}
	s.entries.Store(&next)
	return loads
}

// lookup returns the certificate of domain, a folded name, when there is one
// that is valid at now, or why there is none.
func (s *certStore) lookup(domain string, now time.Time) (*tls.Certificate, error) {
	e := (*s.entries.Load())[domain]
	switch {
	case e == nil:
		return nil, errNoCert
	case e.cert == nil:
		return nil, e.err
	case now.Add(webrules.ClockTolerance).Before(e.cert.Leaf.NotBefore):
		return nil, errCertNotYetValid
	case now.After(e.cert.Leaf.NotAfter):
		return nil, errCertExpired
	}
	return e.cert, nil
}

// load reads the certificate of domain from its directory. The certificate
// has to go with the key, and be valid for the domain.
func (s *certStore) load(domain string) (*tls.Certificate, error) {
	dir := filepath.Join(s.dir, domain)
	chain, err := readCertFile(filepath.Join(dir, certChainFile))
	if err != nil {
		return nil, err
	}
	key, err := readCertFile(filepath.Join(dir, certKeyFile))
	if err != nil {
		return nil, err
	}
	// The key is kept parsed, in the certificate, and nowhere else.
	defer clear(key)
	cert, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, fmt.Errorf("%s with %s: %w", certChainFile, certKeyFile, err)
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("%s: %w", certChainFile, err)
		}
	}
	if err := cert.Leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("the certificate is not one of %s: %w", domain, err)
	}
	return &cert, nil
}

// readCertFile reads one of the files of a certificate, up to maxCertFile
// bytes.
func readCertFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCertFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxCertFile {
		clear(b)
		return nil, fmt.Errorf("%s is longer than %d bytes", filepath.Base(path), maxCertFile)
	}
	return b, nil
}
