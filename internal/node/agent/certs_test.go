package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// selfSigned returns a self-signed certificate for domain and its key, PEM.
func selfSigned(t *testing.T, domain string, notBefore, notAfter time.Time) (chain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// PutCertificate stores the pair under data/certs/<domain>/ with the key
// private, answers the digest, is idempotent, kicks the reconciler when the
// files change, and refuses what cannot be served without touching the disk.
func TestPutCertificate(t *testing.T) {
	r := newRig(t)
	now := r.clock.Now()
	chain, key := selfSigned(t, "web.example.com", now.Add(-time.Hour), now.Add(60*24*time.Hour))
	sum := sha256.Sum256(chain)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := r.client.PutCertificate(ctx, connect.NewRequest(&nodev1.PutCertificateRequest{
		Domain: "web.example.com", FullchainPem: chain, KeyPem: key,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.GetStored() || resp.Msg.GetSha256() != hex.EncodeToString(sum[:]) || resp.Msg.GetNotAfter() == "" {
		t.Errorf("response = %v", resp.Msg)
	}
	dir := filepath.Join(r.paths.CertsDir(), "web.example.com")
	fi, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("privkey.pem: %v, mode %v; want 0600", err, fi)
	}
	if _, err := os.Stat(filepath.Join(dir, "fullchain.pem")); err != nil {
		t.Error(err)
	}
	if n := r.kicks.Load(); n != 1 {
		t.Errorf("reconcile triggered %d times, want 1", n)
	}

	again, err := r.client.PutCertificate(ctx, connect.NewRequest(&nodev1.PutCertificateRequest{
		Domain: "web.example.com", FullchainPem: chain, KeyPem: key,
	}))
	if err != nil || again.Msg.GetStored() || again.Msg.GetSha256() != resp.Msg.GetSha256() {
		t.Errorf("second put = %v, %v; want the same digest, not stored", again.Msg, err)
	}
	if n := r.kicks.Load(); n != 1 {
		t.Errorf("reconcile triggered %d times after an identical put, want still 1", n)
	}

	_, badKey := selfSigned(t, "web.example.com", now, now.Add(time.Hour))
	for _, tc := range []struct {
		name string
		req  *nodev1.PutCertificateRequest
		want string
	}{
		{"wrong key", &nodev1.PutCertificateRequest{Domain: "web.example.com", FullchainPem: chain, KeyPem: badKey}, "pair"},
		{"other domain", &nodev1.PutCertificateRequest{Domain: "other.example.com", FullchainPem: chain, KeyPem: key}, "not for"},
		{"bad domain", &nodev1.PutCertificateRequest{Domain: "Web.Example.com", FullchainPem: chain, KeyPem: key}, "lowercase"},
		{"empty", &nodev1.PutCertificateRequest{}, "lowercase"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.client.PutCertificate(ctx, connect.NewRequest(tc.req))
			var cerr *connect.Error
			if !errors.As(err, &cerr) || cerr.Code() != connect.CodeInvalidArgument || !strings.Contains(cerr.Message(), tc.want) {
				t.Errorf("err = %v, want InvalidArgument with %q", err, tc.want)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(r.paths.CertsDir(), "other.example.com")); !os.IsNotExist(err) {
		t.Error("a refused certificate left a directory")
	}
	for _, line := range r.bufferKinds() {
		if line == "" {
			t.Error("empty kind")
		}
	}
}

// A PEM larger than 64 KiB is refused before it is parsed.
func TestPutCertificateCapsThePEMs(t *testing.T) {
	r := newRig(t)
	now := r.clock.Now()
	chain, key := selfSigned(t, "web.example.com", now.Add(-time.Hour), now.Add(60*24*time.Hour))
	big := append(bytes.Repeat([]byte("# padding\n"), maxPEMBytes/10+1), chain...)
	ctx := context.Background()
	for _, req := range []*nodev1.PutCertificateRequest{
		{Domain: "web.example.com", FullchainPem: big, KeyPem: key},
		{Domain: "web.example.com", FullchainPem: chain, KeyPem: append(bytes.Repeat([]byte("\n"), maxPEMBytes+1), key...)},
	} {
		_, err := r.client.PutCertificate(ctx, connect.NewRequest(req))
		var cerr *connect.Error
		if !errors.As(err, &cerr) || cerr.Code() != connect.CodeInvalidArgument || !strings.Contains(cerr.Message(), "64 KiB") {
			t.Errorf("err = %v, want InvalidArgument naming the cap", err)
		}
	}
	if _, err := os.Stat(filepath.Join(r.paths.CertsDir(), "web.example.com")); !os.IsNotExist(err) {
		t.Error("a refused certificate left a directory")
	}
}
