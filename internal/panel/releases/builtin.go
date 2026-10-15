package releases

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/urbnywrt/postern/internal/release"
)

// builtinJSON holds the built-in pins: for each component the releases that
// the panel trusts before any signed stable list, with the SHA-256 of each
// asset. Its shape is that of the components of engines-stable.json.
//
//go:embed builtin.json
var builtinJSON []byte

// A BuiltinRelease is a release whose assets are pinned in the panel.
type BuiltinRelease struct {
	Component string
	Version   string
	// Tag is the tag of the release on its repository: Version for an upstream
	// release, "" for a Postern component, whose files are in the release of
	// Postern that the panel is (Catalog.Seed).
	Tag    string
	Assets map[string]BuiltinAsset // by architecture
}

// A BuiltinAsset is the file and the SHA-256 of a built-in release for one
// architecture.
type BuiltinAsset struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

var builtins = mustLoadBuiltins()

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func mustLoadBuiltins() []BuiltinRelease {
	var in map[string][]struct {
		Version string                  `json:"version"`
		Assets  map[string]BuiltinAsset `json:"assets"`
	}
	if err := json.Unmarshal(builtinJSON, &in); err != nil {
		panic("releases: builtin.json: " + err.Error())
	}
	var out []BuiltinRelease
	for name, rels := range in {
		comp, ok := ComponentOf(name)
		if !ok {
			panic("releases: builtin.json names an unknown component " + name)
		}
		for _, r := range rels {
			for arch, a := range r.Assets {
				if !hex64.MatchString(a.SHA256) {
					panic(fmt.Sprintf("releases: builtin.json: %s %s %s: not a SHA-256", name, r.Version, arch))
				}
				if want := comp.AssetName(r.Version, arch); a.File != want {
					panic(fmt.Sprintf("releases: builtin.json: %s %s %s: file %q, the component names %q", name, r.Version, arch, a.File, want))
				}
			}
			tag := r.Version
			if comp.Postern {
				tag = ""
			}
			out = append(out, BuiltinRelease{Component: name, Version: r.Version, Tag: tag, Assets: r.Assets})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
		}
		if c := release.Compare(out[i].Version, out[j].Version); c != 0 {
			return c < 0
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// Builtins returns the built-in releases, by component and version.
func Builtins() []BuiltinRelease {
	return append([]BuiltinRelease(nil), builtins...)
}

// BuiltinSHA returns the built-in SHA-256 of the asset of this component,
// version and architecture, and whether there is one.
func BuiltinSHA(component, version, arch string) (string, bool) {
	for _, r := range builtins {
		if r.Component == component && r.Version == version {
			a, ok := r.Assets[arch]
			return a.SHA256, ok
		}
	}
	return "", false
}
