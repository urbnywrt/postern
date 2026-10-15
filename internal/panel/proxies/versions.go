package proxies

import (
	"cmp"
	"context"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The sources of the effective version of a proxy (Proxy.version_source).
const (
	SourcePinned  = "pinned"  // the proxy is pinned to the version
	SourceRollout = "rollout" // a rollout holds the proxy at the version
	SourceChannel = "channel" // the version of the engine on the channel of the node
)

// Effective is the engine and the version that a proxy is to run, and the
// rule that gives the version.
type Effective struct {
	Engine, Version, Source string
}

// EffectiveVersion returns what a proxy is to run (Global Constraints,
// Channels): a pinned proxy runs its engine_version, one under a rollout runs
// its engine_version while the rollout holds it, and one on policy channel
// runs the version of its engine on the channel of its node (nodeChannel, or
// defaultChannel when the node has none; a channel that the table does not
// know falls back to the default, so that the node always has a version). A
// pinned or rollout proxy without a version falls back to the channel too.
// channels is the table of versions by engine and channel
// (store.DB.ChannelVersions); "" is the answer when it has none.
func EffectiveVersion(p *store.Proxy, nodeChannel, defaultChannel string, channels map[string]map[string]string) Effective {
	engine := cmp.Or(p.Engine, store.EngineTelemt)
	switch p.EngineVersionPolicy {
	case store.EnginePolicyPinned:
		if p.EngineVersion != "" {
			return Effective{Engine: engine, Version: p.EngineVersion, Source: SourcePinned}
		}
	case store.EnginePolicyRollout:
		if p.EngineVersion != "" {
			return Effective{Engine: engine, Version: p.EngineVersion, Source: SourceRollout}
		}
	}
	return Effective{Engine: engine, Version: channelVersion(engine, nodeChannel, defaultChannel, channels), Source: SourceChannel}
}

// ProviderVersion returns the version of a provider (xray, psiphon-core) that a
// node runs: the override of the node for the component while one is set, else
// the version of the component on the channel of the node.
func ProviderVersion(n *store.Node, component, defaultChannel string, channels map[string]map[string]string) string {
	if v := n.ProviderVersions[component]; v != "" {
		return v
	}
	return channelVersion(component, n.EngineChannel, defaultChannel, channels)
}

// channelOf is the channel that a node follows: its own, or the default.
func channelOf(nodeChannel, defaultChannel string) string {
	return cmp.Or(nodeChannel, defaultChannel, store.ChannelStable)
}

// channelVersion is the version of a component on the channel of a node; a
// channel the table has no row for takes the default channel's.
func channelVersion(component, nodeChannel, defaultChannel string, channels map[string]map[string]string) string {
	def := cmp.Or(defaultChannel, store.ChannelStable)
	byChannel := channels[component]
	if v := byChannel[channelOf(nodeChannel, def)]; v != "" {
		return v
	}
	return byChannel[def]
}

// channelData is the part of the data of a node that the versions of its
// proxies and providers come from: the versions of the channels and the
// default channel of the panel.
type channelData struct {
	versions       map[string]map[string]string // engine → channel → version
	defaultChannel string
}

// loadChannelData reads the channel versions and the default channel.
func loadChannelData(ctx context.Context, db *store.DB) (*channelData, error) {
	versions, err := db.ChannelVersions(ctx)
	if err != nil {
		return nil, err
	}
	cd := &channelData{versions: versions, defaultChannel: store.ChannelStable}
	if _, err := db.GetSetting(ctx, store.SettingDefaultChannel, &cd.defaultChannel); err != nil {
		return nil, err
	}
	cd.defaultChannel = cmp.Or(cd.defaultChannel, store.ChannelStable)
	return cd, nil
}

// effective is the effective version of a proxy of a node.
func (cd *channelData) effective(n *store.Node, p *store.Proxy) Effective {
	return EffectiveVersion(p, n.EngineChannel, cd.defaultChannel, cd.versions)
}

// provider is the version of a provider on a node.
func (cd *channelData) provider(n *store.Node, component string) string {
	return ProviderVersion(n, component, cd.defaultChannel, cd.versions)
}

// channel is the channel that a node follows.
func (cd *channelData) channel(n *store.Node) string {
	return channelOf(n.EngineChannel, cd.defaultChannel)
}
