package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/registration"

	"github.com/urbnywrt/postern/internal/node/state"
)

func TestTheAccountKeyIsMadeOnceAndKept(t *testing.T) {
	home := t.TempDir()
	m := &Manager{Paths: state.Paths{Home: home}}
	key, err := m.accountKey()
	if err != nil {
		t.Fatalf("accountKey: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("the key is a %T, want ECDSA", key)
	}
	path := filepath.Join(home, "data", "acme", "account.json")
	if got := mode(t, path); got != 0o600 {
		t.Errorf("account.json has mode %v, want 0600", got)
	}
	if got := mode(t, filepath.Dir(path)); got != 0o700 {
		t.Errorf("data/acme has mode %v, want 0700", got)
	}
	// Another manager of the node, after a restart, has the same key.
	again, err := (&Manager{Paths: state.Paths{Home: home}}).accountKey()
	if err != nil {
		t.Fatal(err)
	}
	if !key.Public().(*ecdsa.PublicKey).Equal(again.Public()) {
		t.Error("the key changed")
	}
}

func TestTheAccountIsNotedForEachDirectory(t *testing.T) {
	m := &Manager{Paths: state.Paths{Home: t.TempDir()}}
	if _, err := m.accountKey(); err != nil {
		t.Fatal(err)
	}
	reg := func(uri string, contact ...string) *registration.Resource {
		return &registration.Resource{URI: uri, Body: acme.Account{Contact: contact}}
	}
	for dir, r := range map[string]*registration.Resource{
		LetsEncrypt:        reg("https://acme-v02.api.letsencrypt.org/acme/acct/1", "mailto:admin@example.com"),
		LetsEncryptStaging: reg("https://acme-staging-v02.api.letsencrypt.org/acme/acct/2"),
	} {
		if err := m.noteAccount(dir, r); err != nil {
			t.Fatalf("noteAccount: %v", err)
		}
	}
	data, err := os.ReadFile(m.accountPath())
	if err != nil {
		t.Fatal(err)
	}
	var f accountFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	want := map[string]accountEntry{
		LetsEncrypt:        {URI: "https://acme-v02.api.letsencrypt.org/acme/acct/1", Contact: []string{"admin@example.com"}},
		LetsEncryptStaging: {URI: "https://acme-staging-v02.api.letsencrypt.org/acme/acct/2"},
	}
	if !reflect.DeepEqual(f.Accounts, want) {
		t.Errorf("accounts = %+v, want %+v", f.Accounts, want)
	}
	if _, err := parseAccountKey(f.Key); err != nil {
		t.Errorf("the key was lost: %v", err)
	}
}

func TestAnAccountFileThatCannotBeReadIsKept(t *testing.T) {
	m := &Manager{Paths: state.Paths{Home: t.TempDir()}}
	path := m.accountPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	junk := []byte(`{"key": "not a key"}`)
	if err := os.WriteFile(path, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.accountKey(); err == nil {
		t.Fatal("a key from a file that holds none")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, junk) {
		t.Error("the file was replaced: the account it may stand for would be lost")
	}
}

func TestParseAccountKey(t *testing.T) {
	enc := func(key any) string {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAccountKey(enc(rsaKey)); err != nil {
		t.Errorf("an RSA key: %v", err)
	}
	if _, err := parseAccountKey(enc(edKey)); err == nil {
		t.Error("an Ed25519 key, which lego does not sign with, was taken")
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	if _, err := parseAccountKey(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1}))); err == nil {
		t.Error("a key that is not PKCS #8 was taken")
	}
}
