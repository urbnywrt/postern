package acme

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/urbnywrt/postern/internal/webrules"
)

// The files of a certificate in data/certs/<domain>/.
const (
	fullchainFile = "fullchain.pem" // the chain as the CA returned it, leaf first
	privkeyFile   = "privkey.pem"   // the key of the certificate, 0600
	metaFile      = "meta.json"     // {expiresAt, issuedAt, staging[, reissueNonce]}

	certDirMode    = 0o700
	privkeyMode    = 0o600
	publicFileMode = 0o644
)

// certMeta is meta.json. Its times are as JavaScript's
// Date.prototype.toISOString writes them; the manager writes them that way and
// reads either.
type certMeta struct {
	ExpiresAt jsTime `json:"expiresAt"`
	IssuedAt  jsTime `json:"issuedAt"`
	Staging   bool   `json:"staging"`
	// ReissueNonce is the WebSettings.reissue_nonce the certificate was
	// issued for; left out when 0, so that the files stay as they are until a
	// reissue is asked for.
	ReissueNonce uint64 `json:"reissueNonce,omitempty"`
}

// jsTime is a time as toISOString writes it: UTC, milliseconds, "Z"
// (2026-01-02T03:04:05.678Z). Any RFC 3339 time is read.
type jsTime time.Time

const jsTimeLayout = "2006-01-02T15:04:05.000Z"

func (t jsTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Format(jsTimeLayout))
}

func (t *jsTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	*t = jsTime(parsed)
	return nil
}

// certDir is the directory of the certificate of domain, which must be valid
// (validDomain): its name is the domain.
func (m *Manager) certDir(domain string) string {
	return filepath.Join(m.Paths.CertsDir(), domain)
}

// inspect looks at the certificate of domain on disk: whether it can be served
// at now, until when, and whether it is due for renewal or for the reissue
// that SetReissueNonce asks for. LastError, Issuing and the like are left to
// Status.
func (m *Manager) inspect(domain string, now time.Time) Status {
	return m.inspectFor(domain, now, m.reissueNonce(domain))
}

// inspectFor is inspect with the reissue nonce that is wanted: a certificate
// that records another one is due. A wanted nonce of 0 asks for nothing, so a
// proxy deleted and made again for the same domain (its nonce back at 0)
// costs no issuance.
func (m *Manager) inspectFor(domain string, now time.Time, nonce uint64) Status {
	st := Status{Domain: domain, Due: true}
	if err := validDomain(domain); err != nil {
		st.Problem = err.Error()
		return st
	}
	dir := m.certDir(domain)
	chain, err := os.ReadFile(filepath.Join(dir, fullchainFile))
	if errors.Is(err, fs.ErrNotExist) {
		st.Problem = ProblemNoCertificate
		return st
	}
	if err != nil {
		st.Problem = "the certificate cannot be read: " + pathFree(err)
		return st
	}
	sum := sha256.Sum256(chain)
	st.FullchainSHA256 = hex.EncodeToString(sum[:])
	key, err := os.ReadFile(filepath.Join(dir, privkeyFile))
	if err != nil {
		st.Problem = "the key of the certificate cannot be read: " + pathFree(err)
		return st
	}
	leaf, err := certLeaf(chain, key, domain)
	if err != nil {
		st.Problem = err.Error()
		return st
	}
	st.NotAfter = leaf.NotAfter
	st.RenewAt = renewAt(leaf)
	st.Issuer = leaf.Issuer.CommonName
	if st.Issuer == "" {
		st.Issuer = leaf.Issuer.String()
	}
	if data, err := os.ReadFile(filepath.Join(dir, metaFile)); err == nil {
		var meta certMeta
		if json.Unmarshal(data, &meta) == nil {
			st.IssuedAt = time.Time(meta.IssuedAt)
			st.Staging = meta.Staging
			st.ReissueNonce = meta.ReissueNonce
		}
	}
	switch {
	case now.Add(webrules.ClockTolerance).Before(leaf.NotBefore):
		st.Problem = "the certificate is not valid before " + leaf.NotBefore.UTC().Format(time.RFC3339)
	case !now.Before(leaf.NotAfter):
		st.Problem = "the certificate expired at " + leaf.NotAfter.UTC().Format(time.RFC3339)
	default:
		st.Valid = true
	}
	st.Due = !st.Valid || !now.Before(st.RenewAt) || st.Staging != m.Staging || (nonce != 0 && st.ReissueNonce != nonce)
	return st
}

// certLeaf returns the certificate of a chain and its key, PEM, when they make
// a pair and the certificate is for domain.
func certLeaf(chain, key []byte, domain string) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, fmt.Errorf("the certificate and its key are not a pair: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, fmt.Errorf("the certificate cannot be parsed: %w", err)
		}
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("the certificate is not for %s", domain)
	}
	return leaf, nil
}

// renewAt is when a certificate is due for renewal (Ruling S3-3): once the
// validity it has left is at most min(RenewBefore, half its lifetime). That
// is 30 days before it expires for every lifetime of 60 days or more (Let's
// Encrypt's 90 days, and the 64 it has announced), and half its lifetime for
// a shorter one, which is thus not due again as soon as it is issued.
func renewAt(leaf *x509.Certificate) time.Time {
	ahead := RenewBefore
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life > 0 {
		ahead = min(ahead, life/2)
	}
	return leaf.NotAfter.Add(-ahead)
}

// store writes the certificate of domain, its key and meta.json into
// data/certs/<domain>/ (writeFiles): a reader sees the old files or the new
// ones, and the pair of the certificate and its key is the old or the new one
// but for the moment between two renames. The key is 0600 from the start, the
// directory 0700.
func (m *Manager) store(domain string, is *issued, leaf *x509.Certificate, now time.Time, nonce uint64) error {
	dir := m.certDir(domain)
	if err := os.MkdirAll(dir, certDirMode); err != nil {
		return fmt.Errorf("writing the certificate: %s", pathFree(err))
	}
	meta, err := json.MarshalIndent(certMeta{
		ExpiresAt:    jsTime(leaf.NotAfter),
		IssuedAt:     jsTime(now),
		Staging:      m.Staging,
		ReissueNonce: nonce,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("writing the certificate: %w", err)
	}
	err = writeFiles(dir, []newFile{
		{privkeyFile, is.key, privkeyMode},
		{fullchainFile, is.fullchain, publicFileMode},
		{metaFile, append(meta, '\n'), publicFileMode},
	})
	if err != nil {
		return fmt.Errorf("writing the certificate: %s", pathFree(err))
	}
	return nil
}

// newFile is a file for writeFiles.
type newFile struct {
	name string
	data []byte
	mode os.FileMode
}

// writeFiles replaces files of dir together: each is written to a temporary
// file in dir (mode 0600 until it is complete) and flushed, and only when all
// of them are, they are renamed over theirs, in order, and dir is flushed. A
// failure before the renames, such as a full disk, leaves the old files as
// they were: a renewal that cannot be written never breaks the certificate
// that is served.
func writeFiles(dir string, files []newFile) (err error) {
	var tmps []string
	defer func() {
		if err != nil {
			for _, t := range tmps {
				_ = os.Remove(t) // one that was renamed already is gone
			}
		}
	}()
	for _, f := range files {
		tmp, err := writeTemp(dir, f)
		if err != nil {
			return err
		}
		tmps = append(tmps, tmp)
	}
	for i, f := range files {
		if err := os.Rename(tmps[i], filepath.Join(dir, f.name)); err != nil {
			return err
		}
	}
	if d, err := os.Open(dir); err == nil { // best effort: the renames are atomic without it
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// writeTemp writes f to a new temporary file in dir and returns its name.
func writeTemp(dir string, f newFile) (name string, err error) {
	t, err := os.CreateTemp(dir, "."+f.name+".tmp-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = t.Close()
			_ = os.Remove(t.Name())
		}
	}()
	if _, err = t.Write(f.data); err != nil {
		return "", err
	}
	if err = t.Chmod(f.mode); err != nil { // not the umask's business
		return "", err
	}
	if err = t.Sync(); err != nil {
		return "", err
	}
	if err = t.Close(); err != nil {
		return "", err
	}
	return t.Name(), nil
}

// pathFree is the text of a file system error without the path, which a
// status names otherwise.
func pathFree(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}
