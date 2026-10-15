// Package releases is the release catalog of the panel: the components whose
// releases it tracks, the feeds they come from (the GitHub and Gitea release
// APIs), the rules that decide which SHA-256 an asset has to have, and Prepare,
// which downloads an asset, checks it and keeps it for the nodes.
package releases

import (
	"strings"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// The kinds of component.
const (
	KindEngine   = "engine"   // an MTProto engine that a proxy runs
	KindProvider = "provider" // an egress provider
)

// The architectures that the panel keeps assets for.
var Archs = []string{"amd64", "arm64"}

// A SumsSpec says where the checksums of a release's assets are published and
// how they are written.
type SumsSpec struct {
	// File is the name of the checksum file, with "{asset}" for the asset's
	// name and "{n}" for the version without its leading v.
	File   string
	Format release.SumsFormat
}

// A Component is a program whose releases the panel tracks.
type Component struct {
	Name   string // telemt, mtg, xray, psiphon-core
	Kind   string // KindEngine or KindProvider
	Repo   string // owner/name on GitHub
	Binary string // the name of the executable
	// Member is the cleaned path of the binary inside the archive, with "{n}"
	// for the version without its leading v and "{arch}" for the architecture.
	Member string
	// TagV says whether the tags of the component carry a leading v. The
	// version string is the tag as published, so {n} strips it where it is.
	TagV bool
	// Assets names the asset of each architecture, with "{n}" as in Member.
	Assets map[string]string
	Sums   SumsSpec
	// Pinned says that the component publishes no releases of its own: the
	// panel knows only the versions that it pins (built in, the stable list),
	// and polls no feed for it.
	Pinned bool
	// Postern says that Postern builds the component and ships it with its own
	// releases (Ruling S2-26): its files are served by the release source of
	// the panel, under the tag of a release of Postern, each with a .minisig
	// by a release key ("postern <name> <tag> linux/<arch>"), which Prepare
	// verifies. Repo is unused.
	Postern bool
}

// Components are the engines and providers that the panel tracks, as the plan
// of slice 5 lists them (Global Constraints, Components).
var Components = []Component{
	{
		Name: "telemt", Kind: KindEngine, Repo: "telemt/telemt", Binary: "telemt", Member: "telemt",
		Assets: map[string]string{"amd64": "telemt-x86_64-linux-musl.tar.gz", "arm64": "telemt-aarch64-linux-musl.tar.gz"},
		Sums:   SumsSpec{File: "{asset}.sha256", Format: release.SumsSHA256},
	},
	{
		Name: "mtg", Kind: KindEngine, Repo: "9seconds/mtg", Binary: "mtg", Member: "mtg-{n}-linux-{arch}/mtg", TagV: true,
		Assets: map[string]string{"amd64": "mtg-{n}-linux-amd64.tar.gz", "arm64": "mtg-{n}-linux-arm64.tar.gz"},
		Sums:   SumsSpec{File: "mtg-{n}-checksums.txt", Format: release.SumsSHA256},
	},
	{
		Name: "xray", Kind: KindProvider, Repo: "XTLS/Xray-core", Binary: "xray", Member: "xray", TagV: true,
		Assets: map[string]string{"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"},
		Sums:   SumsSpec{File: "{asset}.dgst", Format: release.SumsDgst},
	},
	{
		// Psiphon's own client (GPL-3.0, run as a separate program: see
		// docs/third-party/psiphon-tunnel-core.md), which a release of Postern
		// builds from a pinned upstream commit, statically, for both
		// architectures (scripts/psiphon-core.sh): the binary itself, signed.
		// Its versions are <date of the commit>-<revision>.
		Name: "psiphon-core", Kind: KindProvider,
		Binary: "psiphon-core", Member: "psiphon-core",
		Assets:  map[string]string{"amd64": "psiphon-core-linux-amd64", "arm64": "psiphon-core-linux-arm64"},
		Pinned:  true,
		Postern: true,
	},
}

// ComponentOf returns the component with this name.
func ComponentOf(name string) (Component, bool) {
	for _, c := range Components {
		if c.Name == name {
			return c, true
		}
	}
	return Component{}, false
}

// N returns the version without its leading v: what "{n}" expands to.
func (c Component) N(version string) string {
	return strings.TrimPrefix(version, "v")
}

// AssetName returns the name of the asset of this version for arch, "" when
// the component has none for that architecture.
func (c Component) AssetName(version, arch string) string {
	return strings.ReplaceAll(c.Assets[arch], "{n}", c.N(version))
}

// MemberPath returns the cleaned path of the binary inside the archive of
// this version for arch.
func (c Component) MemberPath(version, arch string) string {
	return strings.NewReplacer("{n}", c.N(version), "{arch}", arch).Replace(c.Member)
}

// SumsFile returns the name of the checksum file that covers asset.
func (c Component) SumsFile(version, asset string) string {
	return strings.NewReplacer("{asset}", asset, "{n}", c.N(version)).Replace(c.Sums.File)
}

// DownloadURL returns where GitHub serves file of the release with this tag.
// (For a Postern component, see PosternDownloadURL.)
func (c Component) DownloadURL(tag, file string) string {
	return "https://github.com/" + c.Repo + "/releases/download/" + tag + "/" + file
}

// ReleaseURL returns the page of the release with this tag.
func (c Component) ReleaseURL(tag string) string {
	return "https://github.com/" + c.Repo + "/releases/tag/" + tag
}

// PosternDownloadURL returns where the release source rs serves file of the
// release of Postern with this tag; "" for no tag.
func PosternDownloadURL(rs store.ReleaseSource, tag, file string) string {
	if tag == "" {
		return ""
	}
	return posternBase(rs) + "/releases/download/" + tag + "/" + file
}

// PosternReleaseURL returns the page of the release of Postern with this tag
// on the release source rs; "" for no tag.
func PosternReleaseURL(rs store.ReleaseSource, tag string) string {
	if tag == "" {
		return ""
	}
	return posternBase(rs) + "/releases/tag/" + tag
}

func posternBase(rs store.ReleaseSource) string {
	if rs.Kind == SourceGitea {
		return strings.TrimRight(rs.BaseURL, "/") + "/" + rs.Repo
	}
	return "https://github.com/" + rs.Repo
}

// PosternTag returns the tag of the release of Postern that a build of this
// version is, "" for a build that is not a release (dev, a commit).
func PosternTag(v string) string {
	if strings.HasPrefix(v, "v") && release.ValidVersion(v) {
		return v
	}
	return ""
}
