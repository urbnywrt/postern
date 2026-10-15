package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// testCAName is the subject of the CA most tests create. Tests that need a
// foreign CA with the same subject reuse it on purpose.
const testCAName = "Postern Test CA"

// cred is a certificate and its private key, both PEM encoded.
type cred struct{ certPEM, keyPEM []byte }

// testPKI is a CA with one node certificate and one panel certificate.
type testPKI struct {
	ca       *CA
	caKeyPEM []byte
	node     cred // server certificate "node-1", SAN node.example and 127.0.0.1
	panel    cred // client certificate "postern-panel"
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	ca, caKeyPEM := mustCA(t, testCAName)
	return &testPKI{
		ca:       ca,
		caKeyPEM: caKeyPEM,
		node:     mustServer(t, ca, "node-1"),
		panel:    mustClient(t, ca, "postern-panel"),
	}
}

func mustCA(t *testing.T, commonName string) (*CA, []byte) {
	t.Helper()
	ca, keyPEM, err := NewCA(commonName)
	if err != nil {
		t.Fatalf("NewCA(%q): %v", commonName, err)
	}
	return ca, keyPEM
}

func mustServer(t *testing.T, ca *CA, cn string) cred {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueServer(cn, []string{"node.example"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("IssueServer(%q): %v", cn, err)
	}
	return cred{certPEM, keyPEM}
}

func mustClient(t *testing.T, ca *CA, cn string) cred {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueClient(cn)
	if err != nil {
		t.Fatalf("IssueClient(%q): %v", cn, err)
	}
	return cred{certPEM, keyPEM}
}

// mustCert parses the first certificate in certPEM.
func mustCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("no CERTIFICATE block in PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func mustFingerprint(t *testing.T, certPEM []byte) string {
	t.Helper()
	fp, err := Fingerprint(certPEM)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	return fp
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// craft signs tmpl with the CA key. It is how the tests build certificates that
// IssueServer and IssueClient would never produce. Validity, serial number and
// the CA:FALSE constraint are filled in unless tmpl sets them.
func craft(t *testing.T, ca *CA, tmpl x509.Certificate) cred {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if tmpl.SerialNumber == nil {
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			t.Fatalf("serial number: %v", err)
		}
		tmpl.SerialNumber = serial.Add(serial, big.NewInt(1))
	}
	now := time.Now()
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = now.Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = now.Add(time.Hour)
	}
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return cred{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func TestNewCA(t *testing.T) {
	before := time.Now()
	ca, keyPEM, err := NewCA(testCAName)
	after := time.Now()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	cert := ca.Cert

	if cert.Subject.CommonName != testCAName {
		t.Errorf("subject = %q, want %q", cert.Subject.CommonName, testCAName)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Errorf("IsCA = %v, BasicConstraintsValid = %v, want both true", cert.IsCA, cert.BasicConstraintsValid)
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("path length constraint = %d (explicit zero: %v), want an explicit 0: the CA signs leaves only", cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
		t.Errorf("KeyUsage = %b, want %b (CertSign|CRLSign)", cert.KeyUsage, want)
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		t.Errorf("a CA must not restrict the usages of what it signs, got ExtKeyUsage %v", cert.ExtKeyUsage)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("CA public key = %T, want an ECDSA P-256 key", cert.PublicKey)
	}
	if ca.Key.Curve != elliptic.P256() {
		t.Errorf("CA private key curve = %v, want P-256", ca.Key.Curve.Params().Name)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("CA certificate is not self-signed: %v", err)
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Error("CA certificate has no subject key identifier")
	}

	// 20 years from "now", where "now" lies between the two clock readings and
	// the certificate keeps whole seconds only.
	lo, hi := before.AddDate(20, 0, 0).Add(-time.Second), after.AddDate(20, 0, 0)
	if cert.NotAfter.Before(lo) || cert.NotAfter.After(hi) {
		t.Errorf("NotAfter = %v, want about %v (20 years)", cert.NotAfter, hi)
	}
	if !cert.NotBefore.Before(before) {
		t.Errorf("NotBefore = %v is not backdated from %v: nodes with a slow clock would refuse the CA", cert.NotBefore, before)
	}

	block, rest := pem.Decode(ca.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, cert.Raw) || len(bytes.TrimSpace(rest)) != 0 {
		t.Error("CertPEM is not exactly the PEM encoding of Cert")
	}

	block, rest = pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("keyPEM is not a single PKCS #8 PRIVATE KEY block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse keyPEM: %v", err)
	}
	if key, ok := parsed.(*ecdsa.PrivateKey); !ok || !key.Equal(ca.Key) {
		t.Error("keyPEM does not hold the CA private key")
	}
}

func TestNewCAIsUnique(t *testing.T) {
	a, _ := mustCA(t, testCAName)
	b, _ := mustCA(t, testCAName)
	if a.Key.Equal(b.Key) {
		t.Error("two CAs share a private key")
	}
	if a.Cert.SerialNumber.Cmp(b.Cert.SerialNumber) == 0 {
		t.Error("two CAs share a serial number")
	}
	if _, _, err := NewCA(""); err == nil {
		t.Error("NewCA(\"\") succeeded, want an error")
	}
}

func TestLoadCA(t *testing.T) {
	orig, keyPEM := mustCA(t, testCAName)

	t.Run("round trip", func(t *testing.T) {
		loaded, err := LoadCA(orig.CertPEM, keyPEM)
		if err != nil {
			t.Fatalf("LoadCA: %v", err)
		}
		if !loaded.Cert.Equal(orig.Cert) {
			t.Error("loaded certificate differs from the original")
		}
		if !loaded.Key.Equal(orig.Key) {
			t.Error("loaded key differs from the original")
		}
		if !bytes.Equal(loaded.CertPEM, orig.CertPEM) {
			t.Error("loaded CertPEM differs from the original")
		}

		// A loaded CA is a working CA: its certificates chain to the original.
		certPEM, _, err := loaded.IssueServer("node-1", []string{"node.example"}, nil)
		if err != nil {
			t.Fatalf("IssueServer on the loaded CA: %v", err)
		}
		_, err = mustCert(t, certPEM).Verify(x509.VerifyOptions{
			Roots:     poolOf(orig.Cert),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Errorf("certificate from the loaded CA does not verify against the original: %v", err)
		}
	})

	t.Run("SEC 1 key", func(t *testing.T) {
		der, err := x509.MarshalECPrivateKey(orig.Key)
		if err != nil {
			t.Fatal(err)
		}
		sec1 := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		loaded, err := LoadCA(orig.CertPEM, sec1)
		if err != nil {
			t.Fatalf("LoadCA with an EC PRIVATE KEY: %v", err)
		}
		if !loaded.Key.Equal(orig.Key) {
			t.Error("loaded key differs from the original")
		}
	})

	t.Run("CertPEM carries the certificate only", func(t *testing.T) {
		// CertPEM goes into every node bundle. A file that holds the key next
		// to the certificate must not leak the key through it.
		combined := slices.Concat(keyPEM, orig.CertPEM, keyPEM)
		loaded, err := LoadCA(combined, keyPEM)
		if err != nil {
			t.Fatalf("LoadCA: %v", err)
		}
		if bytes.Contains(loaded.CertPEM, []byte("PRIVATE KEY")) {
			t.Error("CertPEM contains key material")
		}
		if !bytes.Equal(loaded.CertPEM, orig.CertPEM) {
			t.Error("CertPEM is not the plain certificate")
		}
	})

	_, otherKeyPEM := mustCA(t, "Some Other CA")
	node := mustServer(t, orig, "node-1")
	edDER, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	edKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER})
	// A CA certificate whose key usage extension forbids signing certificates.
	noSign, noSignKeyPEM := func() (certPEM, keyPEM []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "No Sign CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}()

	tests := []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
		want    string // substring of the error
	}{
		{"empty input", nil, nil, "no certificate"},
		{"certificate is not PEM", []byte("not a certificate"), keyPEM, "no certificate"},
		{"certificate block holds garbage", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}), keyPEM, "parse certificate"},
		{"no key", orig.CertPEM, nil, "no private key"},
		{"key is not PEM", orig.CertPEM, []byte("not a key"), "no private key"},
		{"key block holds garbage", orig.CertPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}), "parse private key"},
		{"key of another CA", orig.CertPEM, otherKeyPEM, "does not match"},
		{"key is not ECDSA", orig.CertPEM, edKeyPEM, "not an ECDSA"},
		{"certificate is not a CA", node.certPEM, node.keyPEM, "not a CA"},
		{"CA may not sign certificates", noSign, noSignKeyPEM, "key usage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca, err := LoadCA(tt.certPEM, tt.keyPEM)
			if err == nil {
				t.Fatalf("LoadCA succeeded (%v), want an error containing %q", ca.Cert.Subject, tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestIssuedCertificates(t *testing.T) {
	ca, _ := mustCA(t, testCAName)
	roots := poolOf(ca.Cert)

	tests := []struct {
		name  string
		issue func() (certPEM, keyPEM []byte, err error)
		usage x509.ExtKeyUsage // the one usage the certificate carries
		other x509.ExtKeyUsage // a usage it must be refused for
	}{
		{
			name:  "server",
			issue: func() ([]byte, []byte, error) { return ca.IssueServer("node-1", []string{"node.example"}, nil) },
			usage: x509.ExtKeyUsageServerAuth,
			other: x509.ExtKeyUsageClientAuth,
		},
		{
			name:  "client",
			issue: func() ([]byte, []byte, error) { return ca.IssueClient("postern-panel") },
			usage: x509.ExtKeyUsageClientAuth,
			other: x509.ExtKeyUsageServerAuth,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			certPEM, keyPEM, err := tt.issue()
			after := time.Now()
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			cert := mustCert(t, certPEM)

			if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{tt.usage}) || len(cert.UnknownExtKeyUsage) != 0 {
				t.Errorf("ExtKeyUsage = %v, want exactly [%v]", cert.ExtKeyUsage, tt.usage)
			}
			if cert.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Errorf("KeyUsage = %b, want DigitalSignature only", cert.KeyUsage)
			}
			if cert.IsCA || !cert.BasicConstraintsValid {
				t.Errorf("IsCA = %v, BasicConstraintsValid = %v, want an explicit CA:FALSE", cert.IsCA, cert.BasicConstraintsValid)
			}
			if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
				t.Errorf("public key = %T, want an ECDSA P-256 key", cert.PublicKey)
			}
			if len(cert.AuthorityKeyId) == 0 || !bytes.Equal(cert.AuthorityKeyId, ca.Cert.SubjectKeyId) {
				t.Errorf("authority key id %x does not name the CA (%x)", cert.AuthorityKeyId, ca.Cert.SubjectKeyId)
			}
			lo, hi := before.AddDate(10, 0, 0).Add(-time.Second), after.AddDate(10, 0, 0)
			if cert.NotAfter.Before(lo) || cert.NotAfter.After(hi) {
				t.Errorf("NotAfter = %v, want about %v (10 years)", cert.NotAfter, hi)
			}
			if !cert.NotBefore.Before(before) {
				t.Errorf("NotBefore = %v is not backdated from %v", cert.NotBefore, before)
			}

			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{tt.usage}}); err != nil {
				t.Errorf("does not verify for %v: %v", tt.usage, err)
			}
			_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{tt.other}})
			var invalid x509.CertificateInvalidError
			if !errors.As(err, &invalid) || invalid.Reason != x509.IncompatibleUsage {
				t.Errorf("verification for %v: error = %v, want an incompatible key usage", tt.other, err)
			}

			// The key belongs to the certificate and is a PKCS #8 P-256 key.
			if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
				t.Errorf("certificate and key do not form a key pair: %v", err)
			}
			block, _ := pem.Decode(keyPEM)
			if block == nil || block.Type != "PRIVATE KEY" {
				t.Fatal("keyPEM is not a PKCS #8 PRIVATE KEY block")
			}
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				t.Errorf("parse key: %v", err)
			}
		})
	}
}

func TestIssueServerNames(t *testing.T) {
	ca, _ := mustCA(t, testCAName)
	dnsNames := []string{"node.example", "*.edge.example"}
	ips := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}

	certPEM, _, err := ca.IssueServer("node-1", dnsNames, ips)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	cert := mustCert(t, certPEM)

	if cert.Subject.CommonName != "node-1" {
		t.Errorf("subject = %q, want node-1", cert.Subject.CommonName)
	}
	if !slices.Equal(cert.DNSNames, dnsNames) {
		t.Errorf("DNS names = %v, want %v", cert.DNSNames, dnsNames)
	}
	if !slices.EqualFunc(cert.IPAddresses, ips, net.IP.Equal) {
		t.Errorf("IP addresses = %v, want %v", cert.IPAddresses, ips)
	}
	for _, name := range []string{"node.example", "a.edge.example", "192.0.2.10", "2001:db8::10"} {
		if err := cert.VerifyHostname(name); err != nil {
			t.Errorf("VerifyHostname(%q): %v", name, err)
		}
	}
	if err := cert.VerifyHostname("other.example"); err == nil {
		t.Error("VerifyHostname(other.example) succeeded, want an error")
	}

	// Names are optional: the panel never checks them.
	if _, _, err := ca.IssueServer("node-2", nil, nil); err != nil {
		t.Errorf("IssueServer without names: %v", err)
	}
}

func TestIssueRequiresCommonName(t *testing.T) {
	ca, _ := mustCA(t, testCAName)
	if _, _, err := ca.IssueServer("", []string{"node.example"}, nil); err == nil {
		t.Error("IssueServer with an empty common name succeeded")
	}
	if _, _, err := ca.IssueClient(""); err == nil {
		t.Error("IssueClient with an empty common name succeeded")
	}
}

func TestIssuedSerialsAreUnique(t *testing.T) {
	ca, _ := mustCA(t, testCAName)
	seen := make(map[string]bool)
	for range 50 {
		certPEM, _, err := ca.IssueClient("postern-panel")
		if err != nil {
			t.Fatal(err)
		}
		serial := mustCert(t, certPEM).SerialNumber
		if serial.Sign() <= 0 {
			t.Fatalf("serial number %v is not positive", serial)
		}
		if seen[serial.String()] {
			t.Fatalf("serial number %v was issued twice", serial)
		}
		seen[serial.String()] = true
	}
}

func TestIssueRespectsCAValidity(t *testing.T) {
	now := time.Now()

	t.Run("a certificate does not outlive its CA", func(t *testing.T) {
		ca, _, err := newCA(testCAName, now.Add(-time.Hour), now.AddDate(1, 0, 0))
		if err != nil {
			t.Fatal(err)
		}
		certPEM, _, err := ca.IssueServer("node-1", nil, nil)
		if err != nil {
			t.Fatalf("IssueServer: %v", err)
		}
		if cert := mustCert(t, certPEM); cert.NotAfter.After(ca.Cert.NotAfter) {
			t.Errorf("certificate expires %v, after its CA (%v)", cert.NotAfter, ca.Cert.NotAfter)
		}
	})

	t.Run("an expired CA issues nothing", func(t *testing.T) {
		ca, _, err := newCA(testCAName, now.AddDate(-2, 0, 0), now.AddDate(-1, 0, 0))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ca.IssueServer("node-1", nil, nil); err == nil {
			t.Error("IssueServer from an expired CA succeeded")
		}
		if _, _, err := ca.IssueClient("postern-panel"); err == nil {
			t.Error("IssueClient from an expired CA succeeded")
		}
	})
}

var fingerprintFormat = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestFingerprintStable(t *testing.T) {
	p := newTestPKI(t)

	got := mustFingerprint(t, p.node.certPEM)
	if !fingerprintFormat.MatchString(got) {
		t.Fatalf("fingerprint %q is not 64 lowercase hex digits", got)
	}

	// SHA-256 over the certificate DER, computed independently.
	block, _ := pem.Decode(p.node.certPEM)
	sum := sha256.Sum256(block.Bytes)
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("fingerprint = %s, want %s", got, want)
	}

	t.Run("repeated calls agree", func(t *testing.T) {
		for range 3 {
			if again := mustFingerprint(t, p.node.certPEM); again != got {
				t.Errorf("fingerprint changed from %s to %s", got, again)
			}
		}
	})

	t.Run("survives a reload of the CA", func(t *testing.T) {
		loaded, err := LoadCA(p.ca.CertPEM, p.caKeyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if a, b := mustFingerprint(t, p.ca.CertPEM), mustFingerprint(t, loaded.CertPEM); a != b {
			t.Errorf("CA fingerprint changed from %s to %s across LoadCA", a, b)
		}
	})

	t.Run("different certificates differ", func(t *testing.T) {
		other := mustServer(t, p.ca, "node-1") // same name, same CA, new key
		if mustFingerprint(t, other.certPEM) == got {
			t.Error("two certificates share a fingerprint")
		}
		if mustFingerprint(t, p.ca.CertPEM) == got {
			t.Error("the CA and a node share a fingerprint")
		}
	})

	t.Run("the first certificate is the leaf", func(t *testing.T) {
		chain := slices.Concat(p.node.certPEM, p.ca.CertPEM)
		if chained := mustFingerprint(t, chain); chained != got {
			t.Errorf("fingerprint of a chain = %s, want the leaf's %s", chained, got)
		}
	})

	t.Run("other PEM blocks are skipped", func(t *testing.T) {
		mixed := slices.Concat([]byte("# node credentials\n"), p.node.keyPEM, p.node.certPEM)
		if mixed := mustFingerprint(t, mixed); mixed != got {
			t.Errorf("fingerprint of a mixed file = %s, want %s", mixed, got)
		}
	})

	errTests := []struct {
		name string
		pem  []byte
	}{
		{"empty", nil},
		{"not PEM", []byte("not a certificate")},
		{"only a key", p.node.keyPEM},
		{"garbage DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})},
	}
	for _, tt := range errTests {
		t.Run("error/"+tt.name, func(t *testing.T) {
			if fp, err := Fingerprint(tt.pem); err == nil {
				t.Errorf("Fingerprint succeeded with %q, want an error", fp)
			}
		})
	}
}
