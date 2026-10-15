package releases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

// The kinds of feed source.
const (
	SourceGitHub = "github"
	SourceGitea  = "gitea"
)

// The limits of a feed (Global Constraints, HTTP).
const (
	maxFeedPage   = 4 << 20  // a page of the release list
	maxNotes      = 64 << 10 // the release notes that are kept
	maxFullPages  = 5        // how many pages a full fetch reads at most
	githubPerPage = 100
	giteaLimit    = 50
)

// The page sizes that a list is read at, largest first: the default of the
// API, and the smaller ones that a list whose page is over maxFeedPage falls
// back to (Xray's release list is 13 MB at 100 releases a page and 2.7 MB at
// 20, measured 2026-10-05: its notes are long and its assets many).
var (
	githubPageSizes = []int{githubPerPage, 25, 10}
	giteaPageSizes  = []int{giteaLimit, 25, 10}
)

// ErrFeedTooLarge is returned when a page of a release list is more than 4 MiB.
var ErrFeedTooLarge = errors.New("releases: a page of the release list is too large")

// A FeedSource is a release list to fetch: a repository on GitHub or on a Gitea.
type FeedSource struct {
	Kind    string // SourceGitHub or SourceGitea
	APIBase string // https://api.github.com, or the base URL of the Gitea (no /api/v1)
	Repo    string // owner/name
	Token   string // "" for none; never logged
}

// A FeedAsset is a file of a release as the feed lists it.
type FeedAsset struct {
	Name    string
	URL     string // where to download it
	Digest  string // the SHA-256 that the API states, lower-case hex; "" when it states none (Gitea)
	Size    int64
	Created time.Time
}

// A FeedRelease is a release as the feed lists it.
type FeedRelease struct {
	Tag        string
	Prerelease bool
	Published  time.Time
	Notes      string // the release notes, clipped to 64 KiB of valid UTF-8
	URL        string // the page of the release
	Assets     []FeedAsset
}

// ListURL returns the URL of the first page of the release list of src at the
// default page size: the URL that the feed is stored under.
func (src FeedSource) ListURL() string {
	if src.Kind == SourceGitea {
		return src.listURL(giteaLimit)
	}
	return src.listURL(githubPerPage)
}

// listURL returns the URL of the first page of the release list at a page size.
func (src FeedSource) listURL(perPage int) string {
	base := strings.TrimRight(src.APIBase, "/")
	if src.Kind == SourceGitea {
		return base + "/api/v1/repos/" + src.Repo + "/releases?limit=" + strconv.Itoa(perPage)
	}
	return base + "/repos/" + src.Repo + "/releases?per_page=" + strconv.Itoa(perPage)
}

// pageSizes returns the page sizes to try for src, largest first, starting at
// the one that lim remembers for the list when it does.
func (src FeedSource) pageSizes(lim *Limiter) []int {
	sizes := githubPageSizes
	if src.Kind == SourceGitea {
		sizes = giteaPageSizes
	}
	if known := lim.pageSize(src.ListURL()); known != 0 {
		for i, n := range sizes {
			if n == known {
				return sizes[i:]
			}
		}
	}
	return sizes
}

// host returns the host of the API, to which alone the token is sent.
func (src FeedSource) host() string {
	u, err := url.Parse(src.APIBase)
	if err != nil {
		return ""
	}
	return u.Host
}

// addHeaders sets the headers of a request to the API of src, the token among
// them when the request goes to the API's host.
func (src FeedSource) addHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent())
	if src.Kind == SourceGitea {
		req.Header.Set("Accept", "application/json")
	} else {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	if src.Token != "" && req.URL.Host == src.host() && req.URL.Host != "" {
		if src.Kind == SourceGitea {
			req.Header.Set("Authorization", "token "+src.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+src.Token)
		}
	}
}

func userAgent() string { return "postern-panel/" + version.Version }

// FetchReleases reads the release list of src. etag is the ETag that the last
// answer for the first page carried ("" for none): it is sent as If-None-Match,
// and newETag is the one of this answer, as it was, to store for the next time.
// notModified says that the first page was a 304: there is nothing new, and
// rels is nil. A 403 or a 429 returns retryAt, the time to wait until (from
// Retry-After or X-RateLimit-Reset), and an error; lim is told of it too, so
// that no request goes out before.
//
// full reads page after page, following Link rel="next", until a release that
// is not a prerelease has been seen, at most maxFullPages pages: what a panel
// that has no ETag yet (and so nothing stored) needs so that the stable
// releases are not missed behind a page of prereleases (F8). Otherwise the
// first page alone is read: a later poll sees what is new there.
//
// Drafts are left out, as are releases whose tag release.ValidVersion refuses.
// Every request goes through lim.
//
// A page is read up to maxFeedPage bytes. A list whose page is larger at the
// default page size (100 releases for GitHub, 50 for Gitea) is read again from
// its first page at the next smaller size (25, then 10), and lim remembers the
// size that worked, so that later polls of that list start there. The ETag is
// the one of the first page at the size that worked, and is sent on the first
// page at every size: a 304 is an optimization, so the pairing is loose.
func FetchReleases(ctx context.Context, hc *http.Client, lim *Limiter, src FeedSource, etag string, full bool) (
	rels []FeedRelease, newETag string, notModified bool, retryAt time.Time, err error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if lim == nil {
		lim = NewLimiter(nil)
	}
	if src.Kind != SourceGitHub && src.Kind != SourceGitea {
		return nil, "", false, time.Time{}, fmt.Errorf("releases: unknown feed kind %q", src.Kind)
	}
	if err := checkURLScheme(src.APIBase); err != nil {
		return nil, "", false, time.Time{}, err
	}
	sizes := src.pageSizes(lim)
	for i, size := range sizes {
		rels, newETag, notModified, retryAt, err = fetchList(ctx, hc, lim, src, src.listURL(size), etag, full)
		if errors.Is(err, ErrFeedTooLarge) && i+1 < len(sizes) {
			continue
		}
		if err == nil {
			lim.setPageSize(src.ListURL(), size)
		}
		return rels, newETag, notModified, retryAt, err
	}
	return nil, "", false, time.Time{}, errors.New("releases: no page size to try")
}

// fetchList reads the release list from its first page at the URL first, as
// FetchReleases documents, at one page size.
func fetchList(ctx context.Context, hc *http.Client, lim *Limiter, src FeedSource, first, etag string, full bool) (
	rels []FeedRelease, newETag string, notModified bool, retryAt time.Time, err error) {
	next := first
	for page := 1; next != "" && page <= maxFullPages; page++ {
		var (
			body    []byte
			resp    *http.Response
			pageTag string
		)
		if page == 1 {
			pageTag = etag
		}
		body, resp, retryAt, err = fetchPage(ctx, hc, lim, src, next, pageTag)
		if err != nil {
			return nil, "", false, retryAt, err
		}
		if page == 1 {
			newETag = resp.Header.Get("ETag")
			if resp.StatusCode == http.StatusNotModified {
				return nil, newETag, true, time.Time{}, nil
			}
		}
		var (
			got      []FeedRelease
			sawFinal bool
		)
		if src.Kind == SourceGitea {
			got, sawFinal, err = parseGitea(body)
		} else {
			got, sawFinal, err = parseGitHub(body)
		}
		if err != nil {
			return nil, "", false, time.Time{}, fmt.Errorf("releases: page %d of %s: %w", page, redact(next), err)
		}
		rels = append(rels, got...)
		if !full || sawFinal {
			break
		}
		if next = nextLink(resp.Header); next != "" && !src.allowsNext(next) {
			slog.Warn("releases: a Link rel=next of a release list points off the API; paging stops",
				"api", redact(src.APIBase), "next", redact(next))
			next = ""
		}
	}
	return rels, newETag, false, time.Time{}, nil
}

// allowsNext reports whether a Link rel="next" URL may be followed: it has to
// pass checkURLScheme (https, or http to a loopback host) and be on the host of
// the API, where the token goes. Anything else (a downgrade to http on the
// same host, another host) stops paging.
func (src FeedSource) allowsNext(next string) bool {
	if checkURLScheme(next) != nil {
		return false
	}
	u, err := url.Parse(next)
	if err != nil {
		return false
	}
	return u.Host != "" && u.Host == src.host()
}

// fetchPage sends one request of the list, through lim, and returns the body
// (empty for a 304), the response, and for a 403 or a 429 the time to retry at.
func fetchPage(ctx context.Context, hc *http.Client, lim *Limiter, src FeedSource, u, etag string) ([]byte, *http.Response, time.Time, error) {
	if err := lim.Wait(ctx, src.Token != ""); err != nil {
		return nil, nil, time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("releases: %w", err)
	}
	src.addHeaders(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("releases: fetch %s: %w", redact(u), redactErr(err))
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		if etag != "" {
			return nil, resp, time.Time{}, nil
		}
		return nil, nil, time.Time{}, fmt.Errorf("releases: fetch %s: 304 without If-None-Match", redact(u))
	case http.StatusForbidden, http.StatusTooManyRequests:
		at := retryAfter(resp.Header, lim.now())
		lim.Defer(at)
		return nil, nil, at, fmt.Errorf("releases: fetch %s: HTTP %d, retry at %s", redact(u), resp.StatusCode, at.UTC().Format(time.RFC3339))
	case http.StatusNotFound:
		return nil, nil, time.Time{}, fmt.Errorf("%w: %s", errNotFound, redact(u))
	default:
		return nil, nil, time.Time{}, fmt.Errorf("releases: fetch %s: HTTP %d", redact(u), resp.StatusCode)
	}
	body, err := readLimited(resp.Body, maxFeedPage, ErrFeedTooLarge)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("releases: fetch %s: %w", redact(u), err)
	}
	return body, resp, time.Time{}, nil
}

// maxRetryAfter caps what a 403 or 429 may ask the panel to wait: the limiter
// is shared, so one feed's answer must not stall the others for good.
const maxRetryAfter = 24 * time.Hour

// retryAfter reads when a 403 or 429 lets the panel try again: Retry-After
// (seconds or an HTTP date), else X-RateLimit-Reset (Unix seconds), else a
// minute from now. It is never before now nor more than maxRetryAfter after.
func retryAfter(h http.Header, now time.Time) time.Time {
	at := retryAfterRaw(h, now)
	if max := now.Add(maxRetryAfter); at.After(max) {
		return max
	}
	return at
}

func retryAfterRaw(h http.Header, now time.Time) time.Time {
	at := now.Add(time.Minute)
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			at = now.Add(time.Duration(secs) * time.Second)
		} else if t, err := http.ParseTime(v); err == nil {
			at = t
		}
	} else if v := strings.TrimSpace(h.Get("X-RateLimit-Reset")); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			at = time.Unix(secs, 0)
		}
	}
	if at.Before(now) {
		return now
	}
	return at
}

// readLimited reads r up to max bytes; more is tooLarge.
func readLimited(r io.Reader, max int64, tooLarge error) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, tooLarge
	}
	return b, nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// nextLink returns the URL of rel="next" of the Link header, "" for none.
func nextLink(h http.Header) string {
	for _, v := range h.Values("Link") {
		for _, part := range strings.Split(v, ",") {
			if m := linkNext.FindStringSubmatch(part); m != nil {
				return m[1]
			}
		}
	}
	return ""
}

// redact returns u for a log or an error: no query, no userinfo.
func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "<url>"
	}
	p.RawQuery, p.Fragment, p.User = "", "", nil
	return p.String()
}

// redactErr drops the URL that a *url.Error carries (it may hold a query)
// and keeps the cause.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// The JSON shapes of the two APIs, with the fields that are read.

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt string        `json:"published_at"`
	Body        string        `json:"body"`
	HTMLURL     string        `json:"html_url"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name      string `json:"name"`
	URL       string `json:"browser_download_url"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

type giteaRelease struct {
	TagName     string       `json:"tag_name"`
	Draft       bool         `json:"draft"`
	Prerelease  bool         `json:"prerelease"`
	PublishedAt string       `json:"published_at"`
	Body        string       `json:"body"`
	HTMLURL     string       `json:"html_url"`
	Assets      []giteaAsset `json:"assets"`
}

type giteaAsset struct {
	Name      string `json:"name"`
	URL       string `json:"browser_download_url"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

// parseGitHub reads a page of the GitHub release list. sawFinal says whether a
// release that is not a prerelease was on the page (drafts and refused tags
// count too: the page reached that far down the list).
func parseGitHub(body []byte) (rels []FeedRelease, sawFinal bool, err error) {
	var in []githubRelease
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, false, fmt.Errorf("decode: %w", err)
	}
	for _, r := range in {
		if !r.Prerelease {
			sawFinal = true
		}
		if r.Draft || !release.ValidVersion(r.TagName) {
			continue
		}
		fr := FeedRelease{
			Tag: r.TagName, Prerelease: r.Prerelease, Published: parseTime(r.PublishedAt),
			Notes: clipNotes(r.Body), URL: r.HTMLURL,
		}
		for _, a := range r.Assets {
			if a.Name == "" || a.URL == "" {
				continue
			}
			fa := FeedAsset{Name: a.Name, URL: a.URL, Size: a.Size, Created: parseTime(a.CreatedAt)}
			if hex, ok := strings.CutPrefix(strings.ToLower(a.Digest), "sha256:"); ok && hex64.MatchString(hex) {
				fa.Digest = hex
			}
			fr.Assets = append(fr.Assets, fa)
		}
		rels = append(rels, fr)
	}
	return rels, sawFinal, nil
}

// parseGitea reads a page of the Gitea release list (F9): the attachments
// have no digest, and of two with one name the newest created_at is kept.
func parseGitea(body []byte) (rels []FeedRelease, sawFinal bool, err error) {
	var in []giteaRelease
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, false, fmt.Errorf("decode: %w", err)
	}
	for _, r := range in {
		if !r.Prerelease {
			sawFinal = true
		}
		if r.Draft || !release.ValidVersion(r.TagName) {
			continue
		}
		fr := FeedRelease{
			Tag: r.TagName, Prerelease: r.Prerelease, Published: parseTime(r.PublishedAt),
			Notes: clipNotes(r.Body), URL: r.HTMLURL,
		}
		byName := map[string]int{}
		for _, a := range r.Assets {
			if a.Name == "" || a.URL == "" {
				continue
			}
			fa := FeedAsset{Name: a.Name, URL: a.URL, Size: a.Size, Created: parseTime(a.CreatedAt)}
			if i, dup := byName[a.Name]; dup {
				if fa.Created.After(fr.Assets[i].Created) {
					fr.Assets[i] = fa
				}
				continue
			}
			byName[a.Name] = len(fr.Assets)
			fr.Assets = append(fr.Assets, fa)
		}
		sort.SliceStable(fr.Assets, func(i, j int) bool { return fr.Assets[i].Name < fr.Assets[j].Name })
		rels = append(rels, fr)
	}
	return rels, sawFinal, nil
}

// parseTime reads an RFC 3339 time, the zero time for none or a bad one.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// clipNotes returns the release notes as the panel keeps them: valid UTF-8, at
// most maxNotes bytes, cut at a rune boundary.
func clipNotes(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= maxNotes {
		return s
	}
	cut := maxNotes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
