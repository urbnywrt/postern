package proxies

import "github.com/urbnywrt/postern/internal/panel/nodes"

// The types of this package are what the node manager takes, and the manager
// is what the services notify. This file does not compile if they drift apart.
var (
	_ nodes.StateBuilder    = (*StateBuilder)(nil)
	_ nodes.Ingestor        = (*Ingestor)(nil)
	_ nodes.ArtifactEnsurer = (*Catalog)(nil)
	_ Notifier              = (*nodes.Manager)(nil)
)
