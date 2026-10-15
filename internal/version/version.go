// Package version holds the build metadata of the Postern binaries.
//
// The variables are overridden at link time, for example:
//
//	go build -ldflags "\
//	  -X github.com/urbnywrt/postern/internal/version.Version=v1.2.3 \
//	  -X github.com/urbnywrt/postern/internal/version.Commit=abc1234 \
//	  -X github.com/urbnywrt/postern/internal/version.Date=2026-10-04T12:00:00Z" ./cmd/node
package version

import "fmt"

// The linker's -X flag can only set string variables that are initialised with
// a constant, so these must stay plain string vars.
var (
	// Version is the release version, or "dev" for a local build.
	Version = "dev"
	// Commit is the source revision the binary was built from.
	Commit = "none"
	// Date is the build time (RFC 3339, UTC).
	Date = "unknown"
	// NodeImage is the Docker image of the node that the panel installs nodes
	// from, as POSTERN_NODE_IMAGE gives it, when the environment does not set
	// it: a name with or without a tag, e.g. ghcr.io/<OWNER>/postern-node.
	// Empty for none. The panel only uses it.
	NodeImage = ""
)

// String returns the build metadata as "<Version> (<Commit>, <Date>)".
func String() string {
	return fmt.Sprintf("%s (%s, %s)", Version, Commit, Date)
}
