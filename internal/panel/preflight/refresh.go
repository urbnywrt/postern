package preflight

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// SettingCloudflareRanges is the key, in the settings store, of the last good
// list of the Cloudflare ranges.
const SettingCloudflareRanges = "preflight.cloudflare_ranges"

// The wait between refreshes, and after a refresh that failed.
const (
	DefaultRefreshEvery = 24 * time.Hour
	retryAfterFailure   = time.Hour
)

// SettingsStore is the part of the panel's settings store that the refresh
// uses (store.DB has it).
type SettingsStore interface {
	GetSetting(ctx context.Context, key string, dst any) (bool, error)
	PutSetting(ctx context.Context, key string, v any) error
}

type storedRanges struct {
	Ranges    []string  `json:"ranges"`
	FetchedAt time.Time `json:"fetched_at"`
}

// A Refresher keeps Ranges up to date: it starts from the last good list in the
// settings store (the embedded one when there is none, or it is unusable),
// fetches the published lists once a day, and stores a list only when the
// whole answer is good. A refresh that fails leaves the list as it was.
type Refresher struct {
	Ranges *CloudflareRanges
	// Client is the panel's HTTP client (releases.NewHTTPClient: HTTPS_PROXY
	// honoured); nil is http.DefaultClient.
	Client *http.Client
	Store  SettingsStore
	Log    *slog.Logger
	// URLs are the lists; none means CloudflareIPv4URL and CloudflareIPv6URL.
	URLs []string
	// Every is the wait between refreshes, DefaultRefreshEvery when zero.
	Every time.Duration
	// Now is time.Now when nil.
	Now func() time.Time
}

func (f *Refresher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Refresher) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Load takes the last good list from the settings store, and returns when it
// was fetched (zero when there is none that can be used).
func (f *Refresher) Load(ctx context.Context) time.Time {
	var s storedRanges
	ok, err := f.Store.GetSetting(ctx, SettingCloudflareRanges, &s)
	if err != nil {
		f.log().Warn("could not read the stored Cloudflare ranges; the built-in ones are used", "err", err)
		return time.Time{}
	}
	if !ok {
		return time.Time{}
	}
	ps, err := parsePrefixes(strings.NewReader(strings.Join(s.Ranges, "\n")))
	if err != nil || len(ps) < minRanges {
		f.log().Warn("the stored Cloudflare ranges are not usable; the built-in ones are used")
		return time.Time{}
	}
	f.Ranges.set(ps)
	return s.FetchedAt
}

// RefreshOnce fetches the lists and, when they are good, uses and stores them.
// On any error the ranges and the stored list stay as they were.
func (f *Refresher) RefreshOnce(ctx context.Context) error {
	if err := f.Ranges.Refresh(ctx, f.Client, f.URLs...); err != nil {
		return err
	}
	err := f.Store.PutSetting(ctx, SettingCloudflareRanges, storedRanges{Ranges: f.Ranges.strings(), FetchedAt: f.now().UTC()})
	if err != nil {
		f.log().Warn("could not store the refreshed Cloudflare ranges; they are used until the panel restarts", "err", err)
	}
	return nil
}

// Run loads the stored list, then refreshes it a day after it was fetched and
// every day after that, until ctx is done. A failure is logged and tried again
// an hour later.
func (f *Refresher) Run(ctx context.Context) {
	every := f.Every
	if every <= 0 {
		every = DefaultRefreshEvery
	}
	next := f.Load(ctx).Add(every)
	for {
		if wait := next.Sub(f.now()); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err := f.RefreshOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			f.log().Warn("could not refresh the Cloudflare ranges; the last good ones stay in use", "err", err)
			next = f.now().Add(retryAfterFailure)
			continue
		}
		f.log().Info("refreshed the Cloudflare ranges", "ranges", f.Ranges.Len())
		next = f.now().Add(every)
	}
}
