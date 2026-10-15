package releases

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// The schedule of the tracker.
const (
	pollEvery     = 6 * time.Hour // a release feed, ± pollJitter
	pollJitter    = 0.10
	refreshMinGap = time.Minute      // between two Refreshes of one component
	stableEvery   = 6 * time.Hour    // the stable list
	stableRetry   = 15 * time.Minute // the stable list after a failure
	gcEvery       = 24 * time.Hour
	// A tick of Run is never less than minTick nor more than maxTick apart
	// from the last: the feeds are due at times of their own, and a feed that
	// fails is tried again at its next time, not at once.
	minTick = time.Minute
	maxTick = time.Hour
)

// EventReleaseFound is recorded when a feed lists a version of a component
// above the version of a channel that the version is in.
const EventReleaseFound = "release_found"

// ErrTooSoon is returned by Refresh within a minute of the last Refresh of the
// component.
var ErrTooSoon = errors.New("releases: the release list was refreshed less than a minute ago")

// Run tracks the releases until ctx is done: it polls the feed of every
// component at start and then every 6 h ± 10 %, each at a time of its own,
// fetches the stable list at start and every 6 h, prepares in the background a
// version that a feed found above a channel version, and collects the
// archives daily. It returns once the background work has ended.
func (c *Catalog) Run(ctx context.Context) {
	c.mu.Lock()
	c.bgCtx = ctx
	c.mu.Unlock()
	defer c.bg.Wait()
	for ctx.Err() == nil {
		next := c.tick(ctx)
		wait := next.Sub(c.now())
		if wait < minTick {
			wait = minTick
		}
		if wait > maxTick {
			wait = maxTick
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// tick does what is due: the feeds whose time has come, the stable list and
// the archive GC. It returns when the next thing is due.
func (c *Catalog) tick(ctx context.Context) time.Time {
	now := c.now()
	next := now.Add(maxTick)
	earlier := func(t time.Time) {
		if !t.IsZero() && t.Before(next) {
			next = t
		}
	}
	for _, comp := range Components {
		if comp.Pinned {
			continue // no releases to poll
		}
		feed, err := c.db.Feed(ctx, c.Source(ctx, comp).ListURL())
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.log.Error("could not read a feed", "component", comp.Name, "err", err)
			continue
		}
		if feed.NextAt.After(now) {
			earlier(feed.NextAt)
			continue
		}
		at, err := c.poll(ctx, comp)
		if err != nil {
			c.log.Warn("the release list could not be read", "component", comp.Name, "err", err)
		}
		earlier(at)
	}
	if !c.stableNext.After(now) {
		c.stableNext = now.Add(stableEvery)
		if err := c.refreshStable(ctx); err != nil {
			c.log.Warn("the stable list could not be applied", "err", err)
			c.stableNext = now.Add(stableRetry)
		}
	}
	earlier(c.stableNext)
	if !c.gcNext.After(now) {
		if err := c.gc(ctx); err != nil {
			c.log.Warn("the archive GC failed", "err", err)
		}
		c.gcNext = now.Add(gcEvery)
	}
	earlier(c.gcNext)
	return next
}

// nextPoll returns when a feed polled now is due again: in 6 h ± 10 %, so that
// the feeds drift apart and the panels of the world do not poll together.
func nextPoll(now time.Time) time.Time {
	spread := float64(pollEvery) * pollJitter
	jitter := time.Duration((rand.Float64()*2 - 1) * spread) //nolint:gosec // G404: the jitter spreads the polls; it is not a secret
	return now.Add(pollEvery + jitter)
}

// Refresh polls the feed of the component now, whatever its schedule, at most
// once a minute per component (ErrTooSoon), and stores what it found.
func (c *Catalog) Refresh(ctx context.Context, component string) error {
	comp, ok := ComponentOf(component)
	if !ok {
		return fmt.Errorf("%w: component %q", ErrUnknown, component)
	}
	if comp.Pinned {
		return nil // it publishes no releases: there is nothing to poll
	}
	c.mu.Lock()
	now := c.now()
	if last, ok := c.refreshed[component]; ok && now.Sub(last) < refreshMinGap {
		c.mu.Unlock()
		return ErrTooSoon
	}
	c.refreshed[component] = now
	c.mu.Unlock()
	_, err := c.poll(ctx, comp)
	return err
}

// poll fetches the release list of the component, stores the releases and the
// feed (its ETag, when it was checked, when it is due, why it failed), and
// returns when it is due again. The first fetch, and one after a lost ETag,
// reads the list in full (see FetchReleases).
func (c *Catalog) poll(ctx context.Context, comp Component) (time.Time, error) {
	src := c.Source(ctx, comp)
	feed, err := c.db.Feed(ctx, src.ListURL())
	if errors.Is(err, store.ErrNotFound) {
		feed = store.Feed{URL: src.ListURL()}
	} else if err != nil {
		return time.Time{}, err
	}
	feed.Component = comp.Name
	rels, etag, notModified, retryAt, ferr := FetchReleases(ctx, c.http, c.lim, src, feed.ETag, feed.ETag == "")
	now := c.now()
	feed.CheckedAt = now
	feed.NextAt = nextPoll(now)
	if retryAt.After(feed.NextAt) {
		feed.NextAt = retryAt
	}
	if ferr != nil {
		feed.LastError = ferr.Error()
	} else {
		feed.LastError = ""
		if !notModified {
			feed.ETag = etag
			c.absorb(ctx, comp, rels)
		}
	}
	if err := c.db.PutFeed(ctx, feed); err != nil {
		return feed.NextAt, err
	}
	return feed.NextAt, ferr
}

// absorb stores the releases of a feed. A release that the feed shows for the
// first time (unknown, or known from the stable list alone) and that is above
// the version of a channel it is in raises release_found. Then, for each
// channel, the newest version above the channel version that is not ready for
// every architecture of the nodes is prepared in the background (one Prepare
// per version, not one per release of a long list), so that a Prepare that
// failed, or could not run for want of nodes, is tried again at the next poll.
func (c *Catalog) absorb(ctx context.Context, comp Component, rels []FeedRelease) {
	chans, err := c.db.ChannelVersions(ctx)
	if err != nil {
		c.log.Error("could not read the channel versions", "err", err)
		return
	}
	now := c.now()
	for _, fr := range rels {
		rel := &store.Release{Engine: comp.Name, Version: fr.Tag, Tag: fr.Tag, Source: store.SourceUpstream,
			Notes: fr.Notes, URL: fr.URL, Prerelease: fr.Prerelease, PublishedAt: fr.Published, FetchedAt: now,
			Assets: map[string]store.ReleaseAsset{}}
		old, err := c.db.ReleaseOf(ctx, comp.Name, fr.Tag)
		known := err == nil
		if known {
			// Where the panel learnt of the release first, and whether it is
			// stable, are not the feed's to say.
			rel.Source, rel.Stable = old.Source, old.Stable
		} else if !errors.Is(err, store.ErrNotFound) {
			c.log.Error("could not read a release", "component", comp.Name, "version", fr.Tag, "err", err)
			continue
		}
		for _, arch := range Archs {
			name := comp.AssetName(fr.Tag, arch)
			for _, fa := range fr.Assets {
				if name == "" || fa.Name != name {
					continue
				}
				a := store.ReleaseAsset{File: name, URL: fa.URL, Size: fa.Size}
				if fa.Digest != "" {
					a.SHA256, a.SHASource = fa.Digest, store.SHASourceDigest
				}
				rel.Assets[arch] = a
			}
		}
		if err := c.storeFeedRelease(ctx, comp, rel, old); err != nil {
			c.log.Error("could not store a release", "component", comp.Name, "version", fr.Tag, "err", err)
			continue
		}
		// Known from the stable list alone: the list has no notes and no
		// date, the feed gives both. Once it has, the release was seen.
		firstSeen := !known || (old.Source == store.SourceStable && old.PublishedAt.IsZero() && old.Notes == "")
		if !firstSeen {
			continue
		}
		var found []string
		for _, ch := range []string{store.ChannelStable, store.ChannelLatest} {
			cur := chans[comp.Name][ch]
			in, err := c.inChannel(ctx, rel, ch)
			if err != nil || !in || cur == "" || release.Compare(rel.Version, cur) <= 0 {
				continue
			}
			found = append(found, ch)
		}
		if len(found) > 0 {
			c.event(ctx, EventReleaseFound, "info",
				fmt.Sprintf("%s %s is out, above the %s version", comp.Name, rel.Version, strings.Join(found, " and ")),
				map[string]string{"component": comp.Name, "version": rel.Version, "channels": strings.Join(found, ",")})
		}
	}
	c.prepareNewest(ctx, comp, chans[comp.Name])
}

// prepareNewest prepares in the background, for the architectures of the
// nodes, the newest version of each channel that is above the channel version
// and not ready for every one of them. Newest leaves out an unusable version.
func (c *Catalog) prepareNewest(ctx context.Context, comp Component, chans map[string]string) {
	archs, err := c.NodeArchs(ctx)
	if err != nil {
		c.log.Error("could not read the nodes", "err", err)
		return
	}
	if len(archs) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, ch := range []string{store.ChannelStable, store.ChannelLatest} {
		cur := chans[ch]
		v, err := c.Newest(ctx, comp.Name, ch, archs)
		if err != nil {
			c.log.Error("could not find the newest release", "component", comp.Name, "channel", ch, "err", err)
			continue
		}
		if v == "" || cur == "" || release.Compare(v, cur) <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		rel, err := c.db.ReleaseOf(ctx, comp.Name, v)
		if err != nil {
			continue
		}
		ready := true
		for _, arch := range archs {
			if rel.Assets[arch].State != store.AssetReady {
				ready = false
			}
		}
		if ready {
			continue
		}
		c.spawn(func(ctx context.Context) {
			if err := c.Prepare(ctx, comp.Name, v, archs); err != nil {
				c.log.Warn("could not prepare a found release", "component", comp.Name, "version", v, "err", err)
			}
		})
	}
}

// storeFeedRelease upserts a release of a feed. A digest that disagrees with a
// pinned SHA-256 (ErrChecksumChanged) is not written (a pin never changes):
// the event release_checksum_mismatch says so, the rest of the release is
// stored, and an asset whose pin is not built in is made unusable (R5-4 keeps
// a built-in asset's state).
func (c *Catalog) storeFeedRelease(ctx context.Context, comp Component, rel, old *store.Release) error {
	err := c.db.UpsertRelease(ctx, rel)
	if !errors.Is(err, store.ErrChecksumChanged) || old == nil {
		return err
	}
	var unusable []string
	for arch, a := range rel.Assets {
		o, ok := old.Assets[arch]
		if !ok || a.SHA256 == "" || o.SHA256 == "" || a.SHA256 == o.SHA256 {
			continue
		}
		c.event(ctx, EventChecksumMismatch, "error",
			fmt.Sprintf("%s %s %s: the digest of the release API disagrees with the %s SHA-256", comp.Name, rel.Version, arch, o.SHASource),
			map[string]string{"component": comp.Name, "version": rel.Version, "arch": arch,
				"expected": o.SHA256, "got": a.SHA256, "source": o.SHASource, "from": "digest"})
		if o.SHASource != store.SHASourceBuiltin {
			unusable = append(unusable, arch)
		}
		a.SHA256, a.SHASource = "", ""
		rel.Assets[arch] = a
	}
	if err := c.db.UpsertRelease(ctx, rel); err != nil {
		return err
	}
	for _, arch := range unusable {
		c.setUnusable(ctx, comp, rel, arch, fmt.Sprintf("the digest of the release API disagrees with the %s SHA-256", old.Assets[arch].SHASource))
	}
	return nil
}

// spawn runs fn in the background, in the context of Run (or, before Run, in
// none), and Run waits for it before it returns.
func (c *Catalog) spawn(fn func(ctx context.Context)) {
	c.mu.Lock()
	ctx := c.bgCtx
	c.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	c.bg.Add(1)
	go func() {
		defer c.bg.Done()
		fn(ctx)
	}()
}
