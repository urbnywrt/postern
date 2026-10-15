package nodes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
)

func openStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newKey(t *testing.T) seal.Key {
	t.Helper()
	var k seal.Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// rawSetting returns a stored setting as the JSON text that the database holds.
func rawSetting(t *testing.T, db *store.DB, key string) string {
	t.Helper()
	var raw jsonText
	ok, err := db.GetSetting(context.Background(), key, &raw)
	if err != nil {
		t.Fatalf("GetSetting(%q): %v", key, err)
	}
	if !ok {
		t.Fatalf("setting %q does not exist", key)
	}
	return string(raw)
}

// jsonText keeps the JSON of a value as it is.
type jsonText []byte

func (j *jsonText) UnmarshalJSON(b []byte) error {
	*j = append((*j)[:0], b...)
	return nil
}

func TestLoadOrCreateCAKeepsTheCA(t *testing.T) {
	db := openStore(t)
	key := newKey(t)
	ctx := context.Background()

	first, err := LoadOrCreateCA(ctx, db, key)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}
	if got := first.Cert.Subject.CommonName; got != "Internal CA" {
		t.Errorf("CA common name = %q, want %q", got, "Internal CA")
	}
	if !first.Cert.IsCA {
		t.Error("the CA certificate is not a CA certificate")
	}

	second, err := LoadOrCreateCA(ctx, db, key)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA: %v", err)
	}
	if !bytes.Equal(first.Cert.Raw, second.Cert.Raw) {
		t.Error("the second load returned another CA certificate")
	}
	if !first.Key.Equal(second.Key) {
		t.Error("the second load returned another CA key")
	}
	if !bytes.Equal(first.CertPEM, second.CertPEM) {
		t.Error("the second load returned another CA PEM")
	}

	// The key is sealed, bound to its place, and nowhere in the clear.
	raw := rawSetting(t, db, "pki.ca")
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Error("the stored CA holds a private key in the clear")
	}
	var stored sealedCert
	if _, err := db.GetSetting(ctx, "pki.ca", &stored); err != nil {
		t.Fatal(err)
	}
	if stored.CertPEM != string(first.CertPEM) {
		t.Error("the stored CA certificate is not the CA certificate")
	}
	keyPEM, err := seal.Open(key, stored.KeyEnc, []byte("pki.ca"))
	if err != nil {
		t.Fatalf("the stored CA key does not open with its additional data: %v", err)
	}
	if _, err := pki.LoadCA([]byte(stored.CertPEM), keyPEM); err != nil {
		t.Errorf("the stored CA does not load: %v", err)
	}
}

// A CA that is there but cannot be read is an error. It is never replaced:
// every node trusts it.
func TestLoadOrCreateCADoesNotReplaceAnUnreadableCA(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		spoil func(t *testing.T, db *store.DB, key seal.Key) seal.Key // returns the key to load with
	}{
		{
			name: "another master key",
			spoil: func(t *testing.T, _ *store.DB, _ seal.Key) seal.Key {
				return newKey(t)
			},
		},
		{
			name: "certificate is not PEM",
			spoil: func(t *testing.T, db *store.DB, key seal.Key) seal.Key {
				var s sealedCert
				if _, err := db.GetSetting(ctx, "pki.ca", &s); err != nil {
					t.Fatal(err)
				}
				s.CertPEM = "not a certificate"
				if err := db.PutSetting(ctx, "pki.ca", s); err != nil {
					t.Fatal(err)
				}
				return key
			},
		},
		{
			name: "key sealed for another place",
			spoil: func(t *testing.T, db *store.DB, key seal.Key) seal.Key {
				var s sealedCert
				if _, err := db.GetSetting(ctx, "pki.ca", &s); err != nil {
					t.Fatal(err)
				}
				plain, err := seal.Open(key, s.KeyEnc, []byte("pki.ca"))
				if err != nil {
					t.Fatal(err)
				}
				if s.KeyEnc, err = seal.Seal(key, plain, []byte("pki.panel_client")); err != nil {
					t.Fatal(err)
				}
				if err := db.PutSetting(ctx, "pki.ca", s); err != nil {
					t.Fatal(err)
				}
				return key
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openStore(t)
			key := newKey(t)
			if _, err := LoadOrCreateCA(ctx, db, key); err != nil {
				t.Fatal(err)
			}
			loadKey := tt.spoil(t, db, key)
			broken := rawSetting(t, db, "pki.ca")
			if _, err := LoadOrCreateCA(ctx, db, loadKey); err == nil {
				t.Fatal("LoadOrCreateCA succeeded with a CA it cannot read")
			}
			if after := rawSetting(t, db, "pki.ca"); after != broken {
				t.Error("LoadOrCreateCA replaced the stored CA")
			}
		})
	}
}

func TestLoadOrCreateCAConcurrentCallsAgree(t *testing.T) {
	db := openStore(t)
	key := newKey(t)
	const n = 8
	cas := make([]*pki.CA, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cas[i], errs[i] = LoadOrCreateCA(context.Background(), db, key)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if !bytes.Equal(cas[i].Cert.Raw, cas[0].Cert.Raw) {
			t.Fatalf("call %d returned another CA", i)
		}
	}
}

func TestPanelClientCertificateIsMadeOnce(t *testing.T) {
	db := openStore(t)
	key := newKey(t)
	ctx := context.Background()
	ca, err := LoadOrCreateCA(ctx, db, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := loadOrCreateClientCert(ctx, db, key, ca)
	if err != nil {
		t.Fatalf("first loadOrCreateClientCert: %v", err)
	}
	cert := parseCert(t, certPEM)
	if cert.Subject.CommonName != "client" {
		t.Errorf("client common name = %q, want %q", cert.Subject.CommonName, "client")
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("client extended key usage = %v, want clientAuth only", cert.ExtKeyUsage)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the client certificate does not verify against the CA: %v", err)
	}

	certPEM2, keyPEM2, err := loadOrCreateClientCert(ctx, db, key, ca)
	if err != nil {
		t.Fatalf("second loadOrCreateClientCert: %v", err)
	}
	if !bytes.Equal(certPEM, certPEM2) || !bytes.Equal(keyPEM, keyPEM2) {
		t.Error("the second call made another client certificate")
	}

	raw := rawSetting(t, db, "pki.panel_client")
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Error("the stored client certificate holds its private key in the clear")
	}
	var stored sealedCert
	if _, err := db.GetSetting(ctx, "pki.panel_client", &stored); err != nil {
		t.Fatal(err)
	}
	plain, err := seal.Open(key, stored.KeyEnc, []byte("pki.panel_client"))
	if err != nil {
		t.Fatalf("the stored client key does not open with its additional data: %v", err)
	}
	if !bytes.Equal(plain, keyPEM) {
		t.Error("the stored client key is not the key that was returned")
	}
}

// A client certificate that the CA did not issue is refused rather than used
// or replaced: the nodes would refuse it.
func TestPanelClientCertificateOfAnotherCAIsRefused(t *testing.T) {
	db := openStore(t)
	key := newKey(t)
	ctx := context.Background()
	ca, err := LoadOrCreateCA(ctx, db, key)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := pki.NewCA("Internal CA")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateClientCert(ctx, db, key, other); err != nil {
		t.Fatalf("loadOrCreateClientCert with another CA: %v", err)
	}
	before := rawSetting(t, db, "pki.panel_client")
	if _, _, err := loadOrCreateClientCert(ctx, db, key, ca); err == nil {
		t.Fatal("a client certificate of another CA was accepted")
	}
	if rawSetting(t, db, "pki.panel_client") != before {
		t.Error("the client certificate was replaced")
	}
}

func TestNodeNames(t *testing.T) {
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	if got, want := nodeCommonName(id), "01jabcdefghjkmnpqrstvwxyz0"; got != want {
		t.Errorf("nodeCommonName = %q, want %q", got, want)
	}
	if got, want := nodeDNSName(id), "01jabcdefghjkmnpqrstvwxyz0.internal"; got != want {
		t.Errorf("nodeDNSName = %q, want %q", got, want)
	}
}
