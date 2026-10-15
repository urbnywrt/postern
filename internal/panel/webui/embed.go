// Package webui holds the admin UI that the panel serves: the build of web/,
// embedded in the binary.
//
// The files are in dist/. Only a placeholder page, index.html, is committed
// there, so that the panel builds without Node. The Docker build runs the build
// of web/ and puts its output into dist/ before it compiles the panel, and a
// developer who wants the UI in a binary does the same by hand (see
// deploy/panel/README.md).
package webui

import (
	"embed"
	"io/fs"
)

// all: also embeds the files whose names start with a dot or an underscore. The
// server skips the hidden ones.
//
//go:embed all:dist
var dist embed.FS

// FS returns the files of the UI, with index.html at its root.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("webui: " + err.Error()) // dist is embedded above, so it exists
	}
	return sub
}
