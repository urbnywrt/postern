package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// ---------------------------------------------------------------------------
// A certificate authority of the tests
// ---------------------------------------------------------------------------

// testCA is a certificate authority of the tests: it issues the certificates
// of the WEB domains, and the clients of the tests trust it alone.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	next atomic.Int64 // the serial number of the next certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "postern test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &testCA{cert: cert, key: key, pool: x509.NewCertPool()}
	ca.pool.AddCert(cert)
	ca.next.Store(100)
	return ca
}

// issue makes a certificate for names, valid from notBefore to notAfter, with a
// key of its own. It returns the PEM of the chain (the certificate, then the
// CA), the PEM of the key and the serial number of the certificate.
func (ca *testCA) issue(t *testing.T, notBefore, notAfter time.Time, names ...string) (chain, key []byte, serial *big.Int) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial = big.NewInt(ca.next.Add(1))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return chain, key, serial
}

// install writes a certificate for domain, or for names when there are any,
// valid from an hour ago for a day, to dir/<domain>/, in place of what is
// there. It returns its serial number.
func (ca *testCA) install(t *testing.T, dir, domain string, names ...string) *big.Int {
	t.Helper()
	if len(names) == 0 {
		names = []string{domain}
	}
	chain, key, serial := ca.issue(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), names...)
	writeCertFiles(t, dir, domain, chain, key)
	return serial
}

// writeCertFiles writes the files of the certificate of domain under dir, as
// the node keeps them.
func writeCertFiles(t *testing.T, dir, domain string, chain, key []byte) {
	t.Helper()
	d := filepath.Join(dir, domain)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if chain != nil {
		if err := os.WriteFile(filepath.Join(d, "fullchain.pem"), chain, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if key != nil {
		if err := os.WriteFile(filepath.Join(d, "privkey.pem"), key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

// servedSerial returns the serial number of the certificate the store serves
// for domain now, or fails the test.
func servedSerial(t *testing.T, s *certStore, domain string) *big.Int {
	t.Helper()
	c, err := s.lookup(domain, time.Now())
	if err != nil {
		t.Fatalf("lookup(%q): %v", domain, err)
	}
	return c.Leaf.SerialNumber
}

func TestCertStoreReadsADomainAgainOnlyForANewGeneration(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	first := ca.install(t, dir, "web.example.com")
	s := newCertStore(dir)

	loads := s.update([]certRef{{domain: "web.example.com", gen: 1}})
	if len(loads) != 1 || loads[0].err != nil || loads[0].domain != "web.example.com" || loads[0].gen != 1 {
		t.Fatalf("first update: %+v, want one load of web.example.com at generation 1", loads)
	}
	if got := servedSerial(t, s, "web.example.com"); got.Cmp(first) != 0 {
		t.Fatalf("serial %v, want %v", got, first)
	}

	// New files under the same generation are not read: the agent raises the
	// generation when it writes them.
	second := ca.install(t, dir, "web.example.com")
	if loads := s.update([]certRef{{domain: "web.example.com", gen: 1}}); len(loads) != 0 {
		t.Fatalf("an update with the same generation read files: %+v", loads)
	}
	if got := servedSerial(t, s, "web.example.com"); got.Cmp(first) != 0 {
		t.Fatalf("serial %v after an update with the same generation, want %v still", got, first)
	}

	if loads := s.update([]certRef{{domain: "web.example.com", gen: 2}}); len(loads) != 1 || loads[0].err != nil {
		t.Fatalf("update to generation 2: %+v", loads)
	}
	if got := servedSerial(t, s, "web.example.com"); got.Cmp(second) != 0 {
		t.Fatalf("serial %v after generation 2, want %v", got, second)
	}

	// A domain that the configuration no longer names is forgotten.
	s.update(nil)
	if _, err := s.lookup("web.example.com", time.Now()); !errors.Is(err, errNoCert) {
		t.Fatalf("lookup of a domain no longer configured: %v, want errNoCert", err)
	}
}

func TestCertStoreKeepsServingWhileNewFilesCannotBeRead(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	first := ca.install(t, dir, "web.example.com")
	s := newCertStore(dir)
	s.update([]certRef{{domain: "web.example.com", gen: 1}})

	writeCertFiles(t, dir, "web.example.com", nil, []byte("not a key at all"))
	loads := s.update([]certRef{{domain: "web.example.com", gen: 2}})
	if len(loads) != 1 || loads[0].err == nil || !loads[0].kept {
		t.Fatalf("update to a generation whose files are broken: %+v, want a failed load that keeps the certificate", loads)
	}
	if got := servedSerial(t, s, "web.example.com"); got.Cmp(first) != 0 {
		t.Fatalf("serial %v while the new files are broken, want the old %v", got, first)
	}

	// A generation that failed is read again by the next update, and taken
	// once its files are good.
	if loads := s.update([]certRef{{domain: "web.example.com", gen: 2}}); len(loads) != 1 || loads[0].err == nil {
		t.Fatalf("the failed generation was not read again: %+v", loads)
	}
	fixed := ca.install(t, dir, "web.example.com")
	if loads := s.update([]certRef{{domain: "web.example.com", gen: 2}}); len(loads) != 1 || loads[0].err != nil {
		t.Fatalf("update once the files are good: %+v", loads)
	}
	if got := servedSerial(t, s, "web.example.com"); got.Cmp(fixed) != 0 {
		t.Fatalf("serial %v, want %v", got, fixed)
	}
	// And once it is in, the same generation is not read again.
	if loads := s.update([]certRef{{domain: "web.example.com", gen: 2}}); len(loads) != 0 {
		t.Fatalf("a loaded generation was read again: %+v", loads)
	}
}

func TestCertStoreServesOnlyAValidCertificateOfTheDomain(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	day := 24 * time.Hour
	otherKey := func(t *testing.T) []byte {
		_, key, _ := ca.issue(t, now.Add(-time.Hour), now.Add(day), "web.example.com")
		return key
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		ok    bool // served now
		err   error
	}{
		{"a good certificate", func(t *testing.T, dir string) {
			ca.install(t, dir, "web.example.com")
		}, true, nil},
		{"a wildcard that covers the domain", func(t *testing.T, dir string) {
			ca.install(t, dir, "web.example.com", "*.example.com")
		}, true, nil},
		{"one name among others", func(t *testing.T, dir string) {
			ca.install(t, dir, "web.example.com", "a.example.com", "web.example.com")
		}, true, nil},
		{"no directory", func(t *testing.T, dir string) {}, false, nil},
		{"no key", func(t *testing.T, dir string) {
			chain, _, _ := ca.issue(t, now.Add(-time.Hour), now.Add(day), "web.example.com")
			writeCertFiles(t, dir, "web.example.com", chain, nil)
		}, false, nil},
		{"no chain", func(t *testing.T, dir string) {
			writeCertFiles(t, dir, "web.example.com", nil, otherKey(t))
		}, false, nil},
		{"a chain that is not PEM", func(t *testing.T, dir string) {
			writeCertFiles(t, dir, "web.example.com", []byte("garbage"), otherKey(t))
		}, false, nil},
		{"the key of another certificate", func(t *testing.T, dir string) {
			chain, _, _ := ca.issue(t, now.Add(-time.Hour), now.Add(day), "web.example.com")
			writeCertFiles(t, dir, "web.example.com", chain, otherKey(t))
		}, false, nil},
		{"a certificate of another name", func(t *testing.T, dir string) {
			ca.install(t, dir, "web.example.com", "other.example.com")
		}, false, nil},
		{"an expired certificate", func(t *testing.T, dir string) {
			chain, key, _ := ca.issue(t, now.Add(-2*day), now.Add(-day), "web.example.com")
			writeCertFiles(t, dir, "web.example.com", chain, key)
		}, false, errCertExpired},
		{"a certificate valid in two minutes (F5: clock tolerance)", func(t *testing.T, dir string) {
			chain, key, _ := ca.issue(t, now.Add(2*time.Minute), now.Add(day), "web.example.com")
			writeCertFiles(t, dir, "web.example.com", chain, key)
		}, true, nil},
		{"a certificate not valid yet", func(t *testing.T, dir string) {
			chain, key, _ := ca.issue(t, now.Add(day), now.Add(2*day), "web.example.com")
			writeCertFiles(t, dir, "web.example.com", chain, key)
		}, false, errCertNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			s := newCertStore(dir)
			s.update([]certRef{{domain: "web.example.com", gen: 1}})
			c, err := s.lookup("web.example.com", now)
			if tc.ok {
				if err != nil || c == nil {
					t.Fatalf("lookup: %v, want the certificate", err)
				}
				return
			}
			if err == nil || c != nil {
				t.Fatalf("lookup served a certificate, want an error")
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("lookup: %v, want %v", err, tc.err)
			}
		})
	}
}

// A certificate that the configuration names in any letter case, with a dot at
// its end, is the certificate of the folded domain: its files are read from
// <dir>/<folded domain>, as the node writes them, and it is served for the
// folded name of a route.
func TestCertStoreReadsTheFoldedDomain(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	serial := ca.install(t, dir, "web.example.com")
	tbl, err := buildTable(&edgev1.EdgeConfig{Certs: []*edgev1.CertRef{{Domain: "Web.EXAMPLE.com.", Generation: 7}}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []certRef{{domain: "web.example.com", gen: 7}}; !slices.Equal(tbl.certs, want) {
		t.Fatalf("certificates of the table %+v, want %+v", tbl.certs, want)
	}
	s := newCertStore(dir)
	if loads := s.update(tbl.certs); len(loads) != 1 || loads[0].err != nil {
		t.Fatalf("update: %+v", loads)
	}
	if got := servedSerial(t, s, "web.example.com"); got.Cmp(serial) != 0 {
		t.Fatalf("serial %v, want %v", got, serial)
	}
	if _, err := s.lookup("other.example.com", time.Now()); !errors.Is(err, errNoCert) {
		t.Fatalf("lookup of a domain never configured: %v, want errNoCert", err)
	}
}
