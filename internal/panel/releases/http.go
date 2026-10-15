package releases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// The timeouts and limits of release traffic (Global Constraints, HTTP).
const (
	dialTimeout     = 15 * time.Second
	headerTimeout   = 30 * time.Second
	downloadTimeout = 5 * time.Minute
	maxArchive      = 200 << 20 // an asset
	maxSumsFile     = 64 << 10  // a checksum file
)

// ErrInsecureURL is returned for a URL that is not https:// (http:// is taken
// for a loopback host only, for tests).
var ErrInsecureURL = errors.New("releases: release traffic is https only")

// ErrTooLarge is returned for a download that is larger than its limit.
var ErrTooLarge = errors.New("releases: the download is too large")

// checkURLScheme refuses a URL that is not https://, unless its host is a
// loopback address, where http:// is taken.
func checkURLScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("releases: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrInsecureURL, redact(raw))
}

// NewHTTPClient returns the client of release traffic: dial and TLS 15 s,
// headers 30 s, HTTPS_PROXY honoured, https only on redirects too, and Go's
// stripping of Authorization on a redirect to another host kept.
func NewHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: headerTimeout,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("releases: too many redirects")
			}
			return checkURLScheme(req.URL.String())
		},
	}
}

// get sends a GET for u with the User-Agent of the panel and the headers of
// src when the URL is on the API's host (the token stays on its host), and
// returns the response, which the caller closes. A status other than 200 is an
// error, and a 404 is errNotFound.
func (c *Catalog) get(ctx context.Context, u string, src *FeedSource) (*http.Response, error) {
	if err := checkURLScheme(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("releases: %w", err)
	}
	req.Header.Set("User-Agent", userAgent())
	if src != nil && src.Token != "" && req.URL.Host == src.host() {
		if src.Kind == SourceGitea {
			req.Header.Set("Authorization", "token "+src.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+src.Token)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("releases: fetch %s: %w", redact(u), redactErr(err))
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", errNotFound, redact(u))
	}
	_ = resp.Body.Close()
	return nil, fmt.Errorf("releases: fetch %s: HTTP %d", redact(u), resp.StatusCode)
}

// errNotFound is a 404 of a download: for a checksum file it means that the
// release has none.
var errNotFound = errors.New("releases: not found")

// getSmall downloads a small file (a checksum file) of at most max bytes.
func (c *Catalog) getSmall(ctx context.Context, u string, src *FeedSource, max int64) ([]byte, error) {
	resp, err := c.get(ctx, u, src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := readLimited(resp.Body, max, ErrTooLarge)
	if err != nil {
		return nil, fmt.Errorf("releases: fetch %s: %w", redact(u), err)
	}
	return b, nil
}

// downloadTo downloads u to a temporary file next to dst (dst + ".part"),
// hashing it, and returns the SHA-256 and the size. The temporary file is
// removed when the download fails; when it succeeds it is left for the caller
// to rename or remove. The whole download has downloadTimeout.
func (c *Catalog) downloadTo(ctx context.Context, u string, src *FeedSource, tmp string) (sha string, size int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	resp, err := c.get(ctx, u, src)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength > maxArchive {
		return "", 0, fmt.Errorf("%w: %s", ErrTooLarge, redact(u))
	}
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302: the archives are public files that the nodes get; the directory is the panel's
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return "", 0, fmt.Errorf("releases: download %s: %w", redact(u), redactErr(err))
	}
	if n > maxArchive {
		return "", 0, fmt.Errorf("%w: %s", ErrTooLarge, redact(u))
	}
	if err := f.Sync(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// fileSHA256 returns the SHA-256 and the size of the file at p.
func fileSHA256(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
