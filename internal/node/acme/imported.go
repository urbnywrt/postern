package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/urbnywrt/postern/internal/webrules"
)

// PutResult is what Put did.
type PutResult struct {
	// SHA256 is the lowercase hex digest of the fullchain.pem on disk.
	SHA256 string
	// Stored reports whether the files were written: false when the same
	// certificate and key were there already.
	Stored bool
	// NotAfter is when the certificate expires.
	NotAfter time.Time
}

// Put stores an imported certificate (Ruling S3-1) in data/certs/<domain>/ as
// the manager stores the ones it issues: fullchain.pem, privkey.pem (0600) and
// meta.json, written together (writeFiles). The chain and the key must be a
// pair, the certificate for domain (in lowercase ASCII) and valid now. It is
// idempotent: the same files are not written again. It takes the domain's
// turn like an issuance does: one that runs ends first (or ctx does), and no
// issuance starts meanwhile. The error never holds any part of the files.
func (m *Manager) Put(ctx context.Context, domain string, fullchain, key []byte) (PutResult, error) {
	m.init()
	if err := validDomain(domain); err != nil {
		return PutResult{}, fmt.Errorf("acme: %w", err)
	}
	leaf, err := certLeaf(fullchain, key, domain)
	if err != nil {
		return PutResult{}, fmt.Errorf("acme: %w", err)
	}
	now := m.now()
	switch {
	case now.Add(webrules.ClockTolerance).Before(leaf.NotBefore):
		return PutResult{}, fmt.Errorf("acme: the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return PutResult{}, fmt.Errorf("acme: the certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	m.touch(domain) // a certificate put resets the unused clock of its domain
	sum := sha256.Sum256(fullchain)
	res := PutResult{SHA256: hex.EncodeToString(sum[:]), NotAfter: leaf.NotAfter}

	// The domain's turn (see ensure): wait for an issuance that runs, then
	// hold the flight while the files are written.
	for {
		m.mu.Lock()
		if f := m.flights[domain]; f != nil {
			m.mu.Unlock()
			select {
			case <-f.done:
				continue
			case <-ctx.Done():
				return PutResult{}, ctx.Err()
			}
		}
		f := &flight{done: make(chan struct{})}
		m.flights[domain] = f
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			delete(m.flights, domain)
			m.mu.Unlock()
			close(f.done)
		}()
		break
	}

	dir := m.certDir(domain)
	oldChain, err1 := os.ReadFile(filepath.Join(dir, fullchainFile))
	oldKey, err2 := os.ReadFile(filepath.Join(dir, privkeyFile))
	if err1 == nil && err2 == nil && bytes.Equal(oldChain, fullchain) && bytes.Equal(oldKey, key) {
		return res, nil
	}
	if err := os.MkdirAll(dir, certDirMode); err != nil {
		return PutResult{}, errors.New("acme: writing the certificate: " + pathFree(err))
	}
	meta, err := json.MarshalIndent(certMeta{
		ExpiresAt: jsTime(leaf.NotAfter),
		IssuedAt:  jsTime(leaf.NotBefore),
		Staging:   false,
	}, "", "  ")
	if err != nil {
		return PutResult{}, fmt.Errorf("acme: writing the certificate: %w", err)
	}
	err = writeFiles(dir, []newFile{
		{privkeyFile, key, privkeyMode},
		{fullchainFile, fullchain, publicFileMode},
		{metaFile, append(meta, '\n'), publicFileMode},
	})
	if err != nil {
		return PutResult{}, errors.New("acme: writing the certificate: " + pathFree(err))
	}
	m.mu.Lock()
	delete(m.failures, domain) // whatever failed before, there is a certificate now
	m.mu.Unlock()
	res.Stored = true
	return res, nil
}
