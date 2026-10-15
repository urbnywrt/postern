package sshxtest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

// NewEd25519Key returns a new Ed25519 key for a server or a client.
func NewEd25519Key(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sshxtest: generate an Ed25519 key: %v", err)
	}
	return signer(t, priv)
}

// NewECDSAKey returns a new ECDSA P-256 key.
func NewECDSAKey(t testing.TB) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("sshxtest: generate an ECDSA key: %v", err)
	}
	return signer(t, priv)
}

// NewRSAKey returns a new 2048-bit RSA key. Making one takes a moment.
func NewRSAKey(t testing.TB) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("sshxtest: generate an RSA key: %v", err)
	}
	return signer(t, priv)
}

func signer(t testing.TB, priv any) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("sshxtest: %v", err)
	}
	return s
}

// NewClientKey returns a new Ed25519 private key in the OpenSSH PEM format, as
// ssh-keygen writes it, encrypted with passphrase unless that is "", and its
// public key, to put in Config.AuthorizedKeys.
func NewClientKey(t testing.TB, passphrase string) (pemBytes []byte, pub ssh.PublicKey) {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sshxtest: generate a client key: %v", err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "sshxtest")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "sshxtest", []byte(passphrase))
	}
	if err != nil {
		t.Fatalf("sshxtest: encode the client key: %v", err)
	}
	pub, err = ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("sshxtest: %v", err)
	}
	return pem.EncodeToMemory(block), pub
}
