package releases

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The archive GC keeps an archive that nothing names for gcKeepAge, and the
// gcKeepNewest newest versions of each component for good.
const (
	gcKeepAge    = 30 * 24 * time.Hour
	gcKeepNewest = 2
)

// gc removes the archives of versions that nothing names and that are older
// than 30 days. Named are: the versions in the desired state of any node (the
// pinned engine version of a proxy, the provider versions of a node), every
// channel version and the newest of every channel, the built-ins, and the 2
// newest versions of each component. The asset of a removed archive goes back
// to unchecked, so that a later Prepare downloads it again.
func (c *Catalog) gc(ctx context.Context) error {
	keep, err := c.named(ctx)
	if err != nil {
		return err
	}
	cut := c.now().Add(-gcKeepAge)
	comps, err := os.ReadDir(c.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, cd := range comps {
		if !cd.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(c.dir, cd.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, vd := range versions {
			if !vd.IsDir() || keep[cd.Name()][vd.Name()] {
				continue
			}
			dir := filepath.Join(c.dir, cd.Name(), vd.Name())
			if recent, err := anyNewer(dir, cut); err != nil || recent {
				if err != nil {
					errs = append(errs, err)
				}
				continue
			}
			if err := os.RemoveAll(dir); err != nil {
				errs = append(errs, err)
				continue
			}
			c.log.Info("removed the archives of a version that nothing names", "component", cd.Name(), "version", vd.Name())
			errs = append(errs, c.forget(ctx, cd.Name(), vd.Name()))
		}
	}
	return errors.Join(errs...)
}

// anyNewer reports whether any file of dir was modified after cut.
func anyNewer(dir string, cut time.Time) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return false, err
		}
		if info.ModTime().After(cut) {
			return true, nil
		}
	}
	return false, nil
}

// forget puts the ready assets of a version whose archives were removed back
// to unchecked; a version the catalog does not know needs nothing.
func (c *Catalog) forget(ctx context.Context, component, version string) error {
	rel, err := c.db.ReleaseOf(ctx, component, version)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for arch, a := range rel.Assets {
		if a.State != store.AssetReady {
			continue
		}
		if err := c.db.SetAssetState(ctx, component, version, arch, store.AssetUnchecked, "", ""); err != nil {
			return fmt.Errorf("releases: gc %s %s %s: %w", component, version, arch, err)
		}
	}
	return nil
}

// named returns the versions whose archives the GC keeps, by component.
func (c *Catalog) named(ctx context.Context) (map[string]map[string]bool, error) {
	keep := map[string]map[string]bool{}
	add := func(component, version string) {
		if component == "" || version == "" {
			return
		}
		if keep[component] == nil {
			keep[component] = map[string]bool{}
		}
		keep[component][version] = true
	}
	for _, b := range builtins {
		add(b.Component, b.Version)
	}
	chans, err := c.db.ChannelVersions(ctx)
	if err != nil {
		return nil, err
	}
	for comp, byChannel := range chans {
		for _, v := range byChannel {
			add(comp, v)
		}
	}
	archs, err := c.NodeArchs(ctx)
	if err != nil {
		return nil, err
	}
	for _, comp := range Components {
		for _, ch := range []string{store.ChannelStable, store.ChannelLatest} {
			v, err := c.Newest(ctx, comp.Name, ch, archs)
			if err != nil {
				return nil, err
			}
			add(comp.Name, v)
		}
		rels, err := c.db.ListReleases(ctx, comp.Name)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(rels) && i < gcKeepNewest; i++ {
			add(comp.Name, rels[i].Version)
		}
	}
	nodes, err := c.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		for comp, v := range n.ProviderVersions {
			add(comp, v)
		}
	}
	proxies, err := c.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, err
	}
	for _, p := range proxies {
		add(p.Engine, p.EngineVersion)
	}
	return keep, nil
}
