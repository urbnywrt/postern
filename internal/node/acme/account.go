package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-acme/lego/v4/registration"

	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	accountDirMode  = 0o700
	accountFileMode = 0o600
	accountKeyPEM   = "PRIVATE KEY" // PKCS #8
)

// accountFile is data/acme/account.json: the key of the node's ACME account,
// one for every domain, and the account the key has at each ACME directory
// (Let's Encrypt and its staging directory are two). The key is made, and
// saved, before it is first used; the accounts are noted as the CA names
// them. The file is root's alone (0600).
type accountFile struct {
	// Key is the private key, PEM (PKCS #8).
	Key string `json:"key"`
	// Accounts are the accounts of the key by the URL of their directory.
	Accounts map[string]accountEntry `json:"accounts,omitempty"`
}

// accountEntry is the account of the key at a directory.
type accountEntry struct {
	URI     string   `json:"uri"`
	Contact []string `json:"contact,omitempty"`
}

// accountPath is data/acme/account.json.
func (m *Manager) accountPath() string {
	return filepath.Join(m.Paths.Home, "data", "acme", "account.json")
}

// accountKey returns the key of the node's account. The first call makes an
// ECDSA P-256 key and saves it.
func (m *Manager) accountKey() (crypto.Signer, error) {
	m.accountMu.Lock()
	defer m.accountMu.Unlock()
	f, err := m.readAccount()
	if errors.Is(err, fs.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("making the key of the ACME account: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("making the key of the ACME account: %w", err)
		}
		f := &accountFile{Key: string(pem.EncodeToMemory(&pem.Block{Type: accountKeyPEM, Bytes: der}))}
		if err := m.writeAccount(f); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	return parseAccountKey(f.Key)
}

// noteAccount notes the account of the key at a directory.
func (m *Manager) noteAccount(directory string, reg *registration.Resource) error {
	if reg == nil || reg.URI == "" {
		return nil
	}
	m.accountMu.Lock()
	defer m.accountMu.Unlock()
	f, err := m.readAccount()
	if err != nil {
		return err
	}
	entry := accountEntry{URI: reg.URI}
	for _, c := range reg.Body.Contact {
		entry.Contact = append(entry.Contact, strings.TrimPrefix(c, "mailto:"))
	}
	if old, ok := f.Accounts[directory]; ok && old.URI == entry.URI && slices.Equal(old.Contact, entry.Contact) {
		return nil
	}
	if f.Accounts == nil {
		f.Accounts = map[string]accountEntry{}
	}
	f.Accounts[directory] = entry
	return m.writeAccount(f)
}

// readAccount reads account.json. A file that is not there is an error that
// is fs.ErrNotExist.
func (m *Manager) readAccount() (*accountFile, error) {
	data, err := os.ReadFile(m.accountPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("reading the ACME account: %s", pathFree(err))
	}
	var f accountFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, errors.New("reading the ACME account: data/acme/account.json is not an account file")
	}
	if _, err := parseAccountKey(f.Key); err != nil {
		return nil, err
	}
	return &f, nil
}

// writeAccount replaces account.json, atomically.
func (m *Manager) writeAccount(f *accountFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("writing the ACME account: %w", err)
	}
	dir := filepath.Dir(m.accountPath())
	if err := os.MkdirAll(dir, accountDirMode); err != nil {
		return fmt.Errorf("writing the ACME account: %s", pathFree(err))
	}
	if err := state.WriteFileAtomic(m.accountPath(), append(data, '\n'), accountFileMode); err != nil {
		return fmt.Errorf("writing the ACME account: %s", pathFree(err))
	}
	return nil
}

// parseAccountKey parses the key of account.json: an ECDSA or an RSA key,
// PKCS #8, the kinds lego signs with.
func parseAccountKey(s string) (crypto.Signer, error) {
	bad := errors.New("reading the ACME account: the key in data/acme/account.json cannot be used")
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != accountKeyPEM {
		return nil, bad
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, bad
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case *rsa.PrivateKey:
		return k, nil
	}
	return nil, bad
}

// acmeUser is the node's account as lego sees it. The account is registered
// at every issuance: a key that has an account gets that one back (RFC 8555
// 7.3.1), so the node never depends on an account URL the CA may have
// forgotten.
type acmeUser struct {
	email string
	key   crypto.Signer
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return nil }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
