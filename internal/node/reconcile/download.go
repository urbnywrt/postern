package reconcile

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/netpolicy"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Downloads of artifacts by the node itself (NodeSettings.artifact_source
// "direct", R5-1). An artifact that the state names and the store does not
// have is downloaded from its url in the background, streamed into the store,
// which verifies the pinned SHA-256 before it keeps anything, and woken into
// a pass, whose check of the artifact tries it out as it tries an upload
// (checkArtifact). A download that fails leaves the artifact missing, is
// reported once with the event artifact_download_failed, and its url is not
// tried again for downloadRetryAfter; the panel uploads what the node still
// lacks at its next resync, as it does for any node.
//
// The rules of release traffic (Global Constraints, HTTP): https only, on
// redirects too; dial and TLS 15 s, headers 30 s, a whole download 5 min; at
// most 200 MiB; User-Agent postern-node/<version>. Every connection goes to
// an address that internal/netpolicy allows (no loopback, private,
// link-local or metadata address, whatever name or redirect led there), and
// so through no proxy: HTTPS_PROXY is not honoured. The node sends no
// credentials: a url with userinfo is refused, and no header but the
// User-Agent goes out. URLs are reported without their query and userinfo.

const (
	evArtifactDownloadFailed = "artifact_download_failed"

	// maxDownloadSize bounds a download, as an upload is bounded.
	maxDownloadSize = 200 << 20
	// downloadRetryAfter is how long a url whose download failed is left
	// alone.
	downloadRetryAfter = 10 * time.Minute
	// maxDownloads is how many downloads run at a time.
	maxDownloads = 2

	downloadDialTimeout   = 15 * time.Second
	downloadHeaderTimeout = 30 * time.Second
	downloadTimeout       = 5 * time.Minute
	downloadMaxRedirects  = 10
)

var (
	// errInsecureURL refuses a url that is not https, and one that carries
	// credentials.
	errInsecureURL = errors.New("artifact downloads are https only")
	// errDownloadTooLarge refuses a download over its bound.
	errDownloadTooLarge = errors.New("the download is too large")
)

// wantDownload starts the download of an artifact that the store does not
// have, when the node downloads for itself and the state gives a url; a ref
// whose download runs, or whose url failed within downloadRetryAfter, starts
// nothing.
func (p *pass) wantDownload(a *nodev1.ArtifactRef, ref artifacts.Ref) {
	if state.ArtifactSourceOf(p.st.GetSettings()) != state.ArtifactSourceDirect || a.GetUrl() == "" {
		return
	}
	p.r.startDownload(ref, a.GetUrl())
}

// startDownload downloads ref from raw in the background, with the context of
// Run (a download outlives the pass that asked for it), and wakes a pass when
// it stored the artifact.
func (r *Reconciler) startDownload(ref artifacts.Ref, raw string) {
	now := r.now()
	r.mu.Lock()
	if r.downloading[ref] {
		r.mu.Unlock()
		return
	}
	if at, ok := r.downloadFailed[raw]; ok && now.Sub(at) < downloadRetryAfter {
		r.mu.Unlock()
		return
	}
	if r.downloading == nil {
		r.downloading = map[artifacts.Ref]bool{}
		r.downloadFailed = map[string]time.Time{}
		r.downloadSlots = make(chan struct{}, maxDownloads)
	}
	r.downloading[ref] = true
	slots := r.downloadSlots
	ctx := r.bg
	if ctx == nil {
		ctx = context.Background()
	}
	r.downloads.Add(1)
	r.mu.Unlock()

	go func() {
		defer r.downloads.Done()
		var err error
		select {
		case slots <- struct{}{}:
			err = r.download(ctx, ref, raw)
			<-slots
		case <-ctx.Done():
			err = ctx.Err()
		}
		r.mu.Lock()
		delete(r.downloading, ref)
		switch {
		case err == nil:
			delete(r.downloadFailed, raw)
		case ctx.Err() == nil:
			r.downloadFailed[raw] = r.now()
		}
		r.mu.Unlock()
		if err != nil {
			if ctx.Err() == nil {
				shown := redactURL(raw)
				r.event(evArtifactDownloadFailed, sevWarning, "",
					fmt.Sprintf("artifact %s %s for %s: the download from %s failed: %v; the panel uploads it at its next resync",
						ref.Engine, ref.Version, ref.Arch, shown, err),
					map[string]string{
						"engine": ref.Engine, "version": ref.Version, "arch": ref.Arch,
						"url": shown, "reason": clip(err.Error(), 256),
					})
			}
			return
		}
		r.log().Info("artifact downloaded", "engine", ref.Engine, "version", ref.Version, "arch", ref.Arch, "url", redactURL(raw))
		r.wakeUp()
	}()
}

// download fetches raw into the store as ref.
func (r *Reconciler) download(ctx context.Context, ref artifacts.Ref, raw string) error {
	if err := r.checkDownloadURL(raw); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return errors.New("the url does not parse")
	}
	req.Header.Set("User-Agent", "postern-node/"+cmp.Or(r.Version, "dev"))
	resp, err := r.downloadClient().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // without the url, which may have a query
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	limit := cmp.Or(r.maxDownload, maxDownloadSize)
	if resp.ContentLength > limit {
		return fmt.Errorf("%w: %d bytes, at most %d", errDownloadTooLarge, resp.ContentLength, limit)
	}
	return r.Artifacts.Put(ref, &boundedReader{r: resp.Body, left: limit})
}

// downloadClient is the HTTP client of downloads: the timeouts of release
// traffic, names resolved with Resolver, no proxy, every connection checked
// against the destination policy (publicDialer) and every redirect
// checked as the url is.
//
// HTTPS_PROXY is not honoured here: through a proxy the node would not see
// the address it reaches, and the destination policy could not hold. A node
// that reaches the release only through a proxy gets the artifact from the
// upload of the panel at the next resync, as on any failure.
func (r *Reconciler) downloadClient() *http.Client {
	dialer := r.publicDialer(downloadDialTimeout, r.downloadAllowDial)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       r.downloadTLS,
			TLSHandshakeTimeout:   downloadDialTimeout,
			ResponseHeaderTimeout: downloadHeaderTimeout,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= downloadMaxRedirects {
				return errors.New("too many redirects")
			}
			return r.checkDownloadURL(req.URL.String())
		},
	}
}

// errDestination refuses a connection to an address that the destination
// policy refuses (internal/netpolicy).
var errDestination = errors.New("the agent's own connections go to public addresses only")

// publicDialer is the dialer of the agent's own connections to third parties
// (artifact downloads, subscription fetches, WARP registration): names
// resolved with Resolver and every connection checked against the destination
// policy (checkPublicDial). Control sees the address that is connected to,
// after the lookup: a name that resolves to an inner address, a redirect to
// one and a rebinding all meet it. allow is a test's loosening; nil in
// production.
func (r *Reconciler) publicDialer(timeout time.Duration, allow func(netip.AddrPort) bool) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout, KeepAlive: 30 * time.Second, Resolver: r.Resolver,
		Control: func(_, address string, _ syscall.RawConn) error { return checkPublicDial(address, allow) },
	}
}

// checkPublicDial refuses to connect to an address that netpolicy does not
// allow (loopback, private, link-local, metadata, the IPv4-embedding forms of
// them, ...), unless allow (a test's) passes it.
func checkPublicDial(address string, allow func(netip.AddrPort) bool) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q is not an address", errDestination, address)
	}
	if allow != nil && allow(ap) {
		return nil
	}
	if why := netpolicy.NonPublic(ap.Addr()); why != "" {
		return fmt.Errorf("%w: %s is %s", errDestination, ap.Addr(), why)
	}
	return nil
}

// checkDownloadURL refuses a url that is not https:// and a url with
// userinfo; http:// is taken only when a test allows it (downloadAllowHTTP).
func (r *Reconciler) checkDownloadURL(raw string) error {
	return checkURL(raw, r.downloadAllowHTTP, errInsecureURL)
}

// checkURL refuses, with refused, a url without a host, one with userinfo and
// one whose scheme is not https (or http, when allowHTTP).
func checkURL(raw string, allowHTTP bool, refused error) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("the url does not parse")
	}
	if u.User != nil {
		return fmt.Errorf("%w: the url carries credentials", refused)
	}
	switch {
	case u.Host == "":
	case u.Scheme == "https", u.Scheme == "http" && allowHTTP:
		return nil
	}
	return fmt.Errorf("%w: %s", refused, redactURL(raw))
}

// redactURL is a url as it may be shown: without userinfo, query and
// fragment.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(a url that does not parse)"
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	return u.String()
}

// boundedReader reads r and fails once more than left bytes came.
type boundedReader struct {
	r    io.Reader
	left int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n, errDownloadTooLarge
	}
	return n, err
}

// clip cuts s to at most n bytes.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
