package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"slices"
	"testing"
	"time"
)

func mustCSR(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func mustECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestSignServerCSRMatchesIssueServer: the certificate made from a request
// says what IssueServer says for the same node, for the request's own key,
// whatever the request asks for.
func TestSignServerCSRMatchesIssueServer(t *testing.T) {
	ca, _ := mustCA(t, testCAName)
	key := mustECKey(t, elliptic.P256())
	csr := mustCSR(t, key, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "evil", Organization: []string{"x"}},
		DNSNames:    []string{"panel.example.com"},
		IPAddresses: []net.IP{net.IPv4(192, 0, 2, 1)},
	})
	names := []string{"01abc.internal"}
	gotPEM, err := ca.SignServerCSR(csr, "01abc", names)
	if err != nil {
		t.Fatalf("SignServerCSR: %v", err)
	}
	wantPEM, _, err := ca.IssueServer("01abc", names, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, want := mustCert(t, gotPEM), mustCert(t, wantPEM)

	if pub, ok := got.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Error("the certificate is not for the request's key")
	}
	if got.Subject.String() != want.Subject.String() {
		t.Errorf("subject %q, want %q", got.Subject, want.Subject)
	}
	if !slices.Equal(got.DNSNames, want.DNSNames) || len(got.IPAddresses) != 0 {
		t.Errorf("names %v %v, want %v and no IPs", got.DNSNames, got.IPAddresses, want.DNSNames)
	}
	if !slices.Equal(got.ExtKeyUsage, want.ExtKeyUsage) || got.KeyUsage != want.KeyUsage {
		t.Errorf("usage %v/%v, want %v/%v", got.ExtKeyUsage, got.KeyUsage, want.ExtKeyUsage, want.KeyUsage)
	}
	if got.IsCA || !got.BasicConstraintsValid {
		t.Error("the certificate is not an explicit CA:FALSE leaf")
	}
	if !bytes.Equal(got.RawIssuer, want.RawIssuer) {
		t.Error("issuer differs")
	}
	for _, d := range []struct {
		name      string
		got, want time.Time
	}{{"NotBefore", got.NotBefore, want.NotBefore}, {"NotAfter", got.NotAfter, want.NotAfter}} {
		if diff := d.got.Sub(d.want).Abs(); diff > 5*time.Second {
			t.Errorf("%s %v, want about %v", d.name, d.got, d.want)
		}
	}
	if len(got.Extensions) != len(want.Extensions) {
		t.Errorf("%d extensions, want %d", len(got.Extensions), len(want.Extensions))
	}
	if err := got.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("not signed by the CA: %v", err)
	}
}

func TestSignServerCSRRefuses(t *testing.T) {
	ca, _ := mustCA(t, testCAName)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	good := mustCSR(t, mustECKey(t, elliptic.P256()), nil)
	badSig := bytes.Clone(good)
	badSig[len(badSig)-3] ^= 0xff // inside the signature
	big := mustCSR(t, mustECKey(t, elliptic.P256()), &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "x"},
		DNSNames: []string{string(bytes.Repeat([]byte("a"), MaxCSRSize))},
	})

	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"P-384", mustCSR(t, mustECKey(t, elliptic.P384()), nil)},
		{"RSA", mustCSR(t, rsaKey, nil)},
		{"bad signature", badSig},
		{"oversize", big},
		{"garbage", []byte("not a certificate request")},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if certPEM, err := ca.SignServerCSR(tc.der, "01abc", []string{"01abc.internal"}); err == nil || certPEM != nil {
				t.Errorf("SignServerCSR = %d bytes, %v; want a refusal", len(certPEM), err)
			}
		})
	}
	if _, err := ca.SignServerCSR(good, "01abc", nil); err != nil {
		t.Errorf("the good request was refused: %v", err)
	}
	if _, err := ca.SignServerCSR(good, "", nil); err == nil {
		t.Error("an empty common name was accepted")
	}
}
