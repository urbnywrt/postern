package releases

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchPaging(t *testing.T) {
	api := newFakeAPI(t)
	api.pages["1"] = apiPage{body: list(ghRelease("v2.0.0-rc1", true, false, "a.tar.gz"), ghRelease("v2.0.0-rc0", true, false)), next: true}
	api.pages["2"] = apiPage{body: list(ghRelease("v1.9.9-rc1", true, false), ghRelease("v1.9.8", false, false, "b.zip")), next: true}
	api.pages["3"] = apiPage{body: list(ghRelease("v1.9.7", false, false)), next: false}
	src := api.github("o/r")

	t.Run("full stops after the first final release", func(t *testing.T) {
		api.hits.Store(0)
		rels, _, notModified, _, err := FetchReleases(context.Background(), api.srv.Client(), NewLimiter(nil), src, "", true)
		if err != nil || notModified {
			t.Fatalf("FetchReleases: %v, notModified %v", err, notModified)
		}
		var tags []string
		for _, r := range rels {
			tags = append(tags, r.Tag)
		}
		if got, want := strings.Join(tags, " "), "v2.0.0-rc1 v2.0.0-rc0 v1.9.9-rc1 v1.9.8"; got != want {
			t.Errorf("tags = %q, want %q", got, want)
		}
		if api.hits.Load() != 2 {
			t.Errorf("requests = %d, want 2 (page 3 is behind a final release)", api.hits.Load())
		}
		if r := api.last.Load(); r.URL.Query().Get("per_page") != "100" || r.Header.Get("Accept") != "application/vnd.github+json" ||
			r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || !strings.HasPrefix(r.Header.Get("User-Agent"), "postern-panel/") {
			t.Errorf("request: %v %v", r.URL, r.Header)
		}
		if a := rels[3].Assets[0]; a.Name != "b.zip" || a.Digest != sum([]byte("b.zip")) || a.Size != 3 || a.URL == "" {
			t.Errorf("asset = %+v", a)
		}
		if rels[0].Notes != "notes of v2.0.0-rc1" || rels[0].Published.IsZero() || !rels[0].Prerelease || rels[3].Prerelease {
			t.Errorf("release fields: %+v", rels[0])
		}
	})

	t.Run("a later poll reads page 1 only", func(t *testing.T) {
		api.hits.Store(0)
		rels, _, _, _, err := FetchReleases(context.Background(), api.srv.Client(), NewLimiter(nil), src, "", false)
		if err != nil {
			t.Fatal(err)
		}
		if len(rels) != 2 || api.hits.Load() != 1 {
			t.Errorf("releases %d, requests %d; want 2, 1", len(rels), api.hits.Load())
		}
	})

	t.Run("at most 5 pages", func(t *testing.T) {
		deep := newFakeAPI(t)
		for i := 1; i <= 8; i++ {
			deep.pages[fmt.Sprint(i)] = apiPage{body: list(ghRelease(fmt.Sprintf("v0.%d.0-rc1", i), true, false)), next: true}
		}
		rels, _, _, _, err := FetchReleases(context.Background(), deep.srv.Client(), NewLimiter(nil), deep.github("o/r"), "", true)
		if err != nil {
			t.Fatal(err)
		}
		if len(rels) != 5 || deep.hits.Load() != 5 {
			t.Errorf("releases %d, requests %d; want 5, 5", len(rels), deep.hits.Load())
		}
	})
}

func TestFetchETag(t *testing.T) {
	api := newFakeAPI(t)
	api.etag = `W/"abc"`
	api.pages["1"] = apiPage{body: list(ghRelease("v1.0.0", false, false))}
	src := api.github("o/r")
	lim := NewLimiter(nil)

	rels, etag, notModified, _, err := FetchReleases(context.Background(), api.srv.Client(), lim, src, "", false)
	if err != nil || notModified || len(rels) != 1 {
		t.Fatalf("first: %v %v %d", err, notModified, len(rels))
	}
	if etag != `W/"abc"` {
		t.Fatalf("etag = %q, want the raw weak ETag", etag)
	}
	rels, etag2, notModified, _, err := FetchReleases(context.Background(), api.srv.Client(), lim, src, etag, false)
	if err != nil || !notModified || rels != nil || etag2 != etag {
		t.Fatalf("second: %v notModified=%v rels=%v etag=%q", err, notModified, rels, etag2)
	}
	if got := api.last.Load().Header.Get("If-None-Match"); got != `W/"abc"` {
		t.Errorf("If-None-Match = %q", got)
	}
	api.etag = `W/"def"`
	api.pages["1"] = apiPage{body: list(ghRelease("v1.0.1", false, false), ghRelease("v1.0.0", false, false))}
	rels, etag3, notModified, _, err := FetchReleases(context.Background(), api.srv.Client(), lim, src, etag, false)
	if err != nil || notModified || len(rels) != 2 || etag3 != `W/"def"` {
		t.Fatalf("third: %v notModified=%v rels=%d etag=%q", err, notModified, len(rels), etag3)
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	lim := NewLimiter(clock)
	for i := 0; i < limitAnonymous; i++ {
		if err := lim.Wait(context.Background(), false); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := lim.Wait(ctx, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the 51st unauthenticated request: %v, want to wait", err)
	}
	// With a token the cap is higher.
	if err := lim.Wait(context.Background(), true); err != nil {
		t.Fatalf("authenticated: %v", err)
	}
	now = now.Add(time.Hour + time.Second)
	if err := lim.Wait(context.Background(), false); err != nil {
		t.Fatalf("an hour later: %v", err)
	}
	// Defer holds everything back.
	lim.Defer(now.Add(time.Hour))
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := lim.Wait(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("after Defer: %v, want to wait", err)
	}
}

func TestFetchRateLimit(t *testing.T) {
	api := newFakeAPI(t)
	api.reset = time.Now().Add(time.Hour).Truncate(time.Second)
	lim := NewLimiter(nil)
	src := api.github("o/r")
	_, _, _, retryAt, err := FetchReleases(context.Background(), api.srv.Client(), lim, src, "", true)
	if err == nil {
		t.Fatal("a 403 is an error")
	}
	if !retryAt.Equal(api.reset) {
		t.Errorf("retryAt = %v, want %v", retryAt, api.reset)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, _, _, err := FetchReleases(ctx, api.srv.Client(), lim, src, "", true); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("before the reset: %v, want to wait", err)
	}
	if api.hits.Load() != 1 {
		t.Errorf("requests = %d, want 1: none before the reset", api.hits.Load())
	}
	// Retry-After in seconds is read too.
	h := http.Header{"Retry-After": {"30"}}
	if at := retryAfter(h, time.Unix(1000, 0)); !at.Equal(time.Unix(1030, 0)) {
		t.Errorf("Retry-After 30 = %v", at)
	}
}

func TestGiteaShape(t *testing.T) {
	var (
		last  *http.Request
		gitea *httptest.Server
	)
	gitea = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r.Clone(context.Background())
		if r.URL.Path != "/api/v1/repos/o/r/releases" || r.URL.Query().Get("limit") != "50" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprintf(w, `[{"tag_name":"v1.2.0","draft":false,"prerelease":false,"published_at":"2026-10-01T00:00:00Z","body":"b","html_url":"%s/o/r/releases/tag/v1.2.0",
		  "assets":[
		    {"id":1,"name":"x-linux-amd64","size":10,"created_at":"2026-10-01T00:00:00Z","uuid":"u1","browser_download_url":"%s/attachments/u1"},
		    {"id":2,"name":"x-linux-amd64","size":11,"created_at":"2026-10-02T00:00:00Z","uuid":"u2","browser_download_url":"%s/attachments/u2"},
		    {"id":3,"name":"x-linux-arm64","size":12,"created_at":"2026-10-01T00:00:00Z","uuid":"u3","browser_download_url":"%s/attachments/u3"}]}]`,
			gitea.URL, gitea.URL, gitea.URL, gitea.URL)
	}))
	t.Cleanup(gitea.Close)
	src := FeedSource{Kind: SourceGitea, APIBase: gitea.URL, Repo: "o/r", Token: "secret-token"}
	rels, _, _, _, err := FetchReleases(context.Background(), gitea.Client(), NewLimiter(nil), src, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := last.Header.Get("Authorization"); got != "token secret-token" {
		t.Errorf("Authorization = %q", got)
	}
	if len(rels) != 1 || len(rels[0].Assets) != 2 {
		t.Fatalf("releases = %+v", rels)
	}
	a := rels[0].Assets[0]
	if a.Name != "x-linux-amd64" || a.Size != 11 || !strings.HasSuffix(a.URL, "/attachments/u2") || a.Digest != "" {
		t.Errorf("duplicate name: got %+v, want the newest and no digest", a)
	}
	// The bytes of browser_download_url are fetched with the same token, on
	// the Gitea's host only.
	tc := newTestCatalog(t)
	tc.http = gitea.Client()
	resp, err := tc.get(context.Background(), a.URL, &src)
	if err == nil {
		_ = resp.Body.Close()
	}
	if got := last.Header.Get("Authorization"); got != "token secret-token" {
		t.Errorf("download Authorization = %q", got)
	}
	tc.host.put("/elsewhere", []byte("x"))
	resp, err = tc.get(context.Background(), tc.host.url("/elsewhere"), &src)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	tc.host.mu.Lock()
	defer tc.host.mu.Unlock()
	if got := tc.host.auth["/elsewhere"]; got != "" {
		t.Errorf("the token went to another host: %q", got)
	}
}

func TestFetchSkips(t *testing.T) {
	api := newFakeAPI(t)
	api.pages["1"] = apiPage{body: list(
		ghRelease("v1.1.0", false, true),     // a draft
		ghRelease("../x", false, false),      // not a version
		ghRelease("v1.0.1-rc1", true, false), // a prerelease by the flag
		ghRelease("v1.0.0", false, false),
	)}
	rels, _, _, _, err := FetchReleases(context.Background(), api.srv.Client(), NewLimiter(nil), api.github("o/r"), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 || rels[0].Tag != "v1.0.1-rc1" || !rels[0].Prerelease || rels[1].Tag != "v1.0.0" || rels[1].Prerelease {
		t.Errorf("releases = %+v", rels)
	}
	long := strings.Repeat("é", 40*1024) // 80 KiB
	if n := clipNotes(long); len(n) > maxNotes || len(n) < maxNotes-1 || !strings.HasSuffix(n, "é") {
		t.Errorf("clipNotes: %d bytes", len(n))
	}
	if n := clipNotes("ok\xffbad"); n != "ok�bad" {
		t.Errorf("clipNotes invalid UTF-8 = %q", n)
	}
}

func TestFetchPageSize(t *testing.T) {
	api := newFakeAPI(t)
	api.bigAbove = 25
	api.etag = `W/"big"`
	api.pages["1"] = apiPage{body: list(ghRelease("v1.0.0-rc1", true, false)), next: true}
	api.pages["2"] = apiPage{body: list(ghRelease("v1.0.0", false, false))}
	src := api.github("o/r")
	lim := NewLimiter(nil)
	rels, etag, _, _, err := FetchReleases(context.Background(), api.srv.Client(), lim, src, "", true)
	if err != nil || len(rels) != 2 || etag != `W/"big"` {
		t.Fatalf("FetchReleases: %v, %d releases, etag %q", err, len(rels), etag)
	}
	// 100 (too large), then 25: pages 1 and 2.
	if api.hits.Load() != 3 {
		t.Errorf("requests = %d, want 3", api.hits.Load())
	}
	if r := api.last.Load(); r.URL.Query().Get("per_page") != "25" || r.URL.Query().Get("page") != "2" {
		t.Errorf("last request: %v", r.URL)
	}
	// The next poll starts at 25, and the ETag is sent there.
	api.hits.Store(0)
	_, _, notModified, _, err := FetchReleases(context.Background(), api.srv.Client(), lim, src, etag, false)
	if err != nil || !notModified || api.hits.Load() != 1 {
		t.Errorf("second poll: %v notModified=%v requests=%d", err, notModified, api.hits.Load())
	}
	if r := api.last.Load(); r.URL.Query().Get("per_page") != "25" || r.Header.Get("If-None-Match") != `W/"big"` {
		t.Errorf("second poll request: %v %v", r.URL, r.Header)
	}
	// Too large at every size is the error.
	api.bigAbove = 5
	if _, _, _, _, err := FetchReleases(context.Background(), api.srv.Client(), NewLimiter(nil), src, "", false); !errors.Is(err, ErrFeedTooLarge) {
		t.Errorf("err = %v, want ErrFeedTooLarge", err)
	}
}

func TestFeedPageTooLarge(t *testing.T) {
	api := newFakeAPI(t)
	api.pages["1"] = apiPage{body: "[" + strings.Repeat(" ", maxFeedPage) + "]"}
	_, _, _, _, err := FetchReleases(context.Background(), api.srv.Client(), NewLimiter(nil), api.github("o/r"), "", false)
	if !errors.Is(err, ErrFeedTooLarge) {
		t.Errorf("err = %v, want ErrFeedTooLarge", err)
	}
}

func TestInsecureURL(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://api.github.com", true},
		{"http://127.0.0.1:1234/x", true},
		{"http://localhost:1234/x", true},
		{"http://198.51.100.7/x", false},
		{"http://example.com/x", false},
		{"ftp://example.com/x", false},
	} {
		if err := checkURLScheme(tc.url); (err == nil) != tc.ok {
			t.Errorf("checkURLScheme(%s) = %v, want ok=%v", tc.url, err, tc.ok)
		}
	}
	src := FeedSource{Kind: SourceGitHub, APIBase: "http://198.51.100.7", Repo: "o/r"}
	if _, _, _, _, err := FetchReleases(context.Background(), nil, nil, src, "", false); !errors.Is(err, ErrInsecureURL) {
		t.Errorf("FetchReleases over http: %v", err)
	}
}

func TestFetchNextLinkChecked(t *testing.T) {
	for _, tc := range []struct{ name, next string }{
		{"foreign host", "https://198.51.100.7/repos/o/r/releases?page=2"},
		{"http to another host", "http://198.51.100.7/repos/o/r/releases?page=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.nextLink = tc.next
			api.pages["1"] = apiPage{body: list(ghRelease("v1.0.0-rc1", true, false)), next: true}
			src := api.github("o/r")
			src.Token = "secret-token"
			rels, _, _, _, err := FetchReleases(context.Background(), api.srv.Client(), NewLimiter(nil), src, "", true)
			if err != nil || len(rels) != 1 || api.hits.Load() != 1 {
				t.Errorf("err %v, releases %d, requests %d; want paging to stop after page 1", err, len(rels), api.hits.Load())
			}
		})
	}
	src := FeedSource{Kind: SourceGitea, APIBase: "https://git.example.com", Repo: "o/r"}
	for next, want := range map[string]bool{
		"https://git.example.com/api/v1/repos/o/r/releases?page=2": true,
		"http://git.example.com/api/v1/repos/o/r/releases?page=2":  false, // a downgrade on the same host
		"https://git.example.com:8443/api/v1/repos/o/r/releases":   false, // another host:port
		"https://example.com/x":                                    false,
		"://bad":                                                   false,
	} {
		if got := src.allowsNext(next); got != want {
			t.Errorf("allowsNext(%s) = %v, want %v", next, got, want)
		}
	}
}

func TestRetryAfterCap(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	h := http.Header{"Retry-After": {"99999999"}}
	if at := retryAfter(h, now); !at.Equal(now.Add(maxRetryAfter)) {
		t.Errorf("Retry-After huge = %v, want the cap", at)
	}
	h = http.Header{}
	h.Set("X-RateLimit-Reset", "1")
	if at := retryAfter(h, now); !at.Equal(now) {
		t.Errorf("a reset in the past = %v, want now", at)
	}
	// The limiter's clock is the one that is read.
	api := newFakeAPI(t)
	api.reset = time.Unix(2_000_000, 0)
	lim := NewLimiter(func() time.Time { return now })
	_, _, _, retryAt, err := FetchReleases(context.Background(), api.srv.Client(), lim, api.github("o/r"), "", true)
	if err == nil || !retryAt.Equal(now.Add(maxRetryAfter)) {
		t.Errorf("retryAt = %v (%v), want now+24h by the injected clock", retryAt, err)
	}
}
