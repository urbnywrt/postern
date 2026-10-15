package engines

import "regexp"

// Trial says how to try an engine binary out before it is used. The binary
// runs in the runner image with Args and nothing else (no config, no
// network), and passes when it exits with ExitCode and its output, stdout and
// stderr together, matches Output. A nil Output accepts any output.
//
// A trial tells a binary that runs on the node from one that does not (another
// architecture, a dynamically linked build, a broken download), and one that
// is the version it claims to be from one that is not.
type Trial struct {
	Args     []string
	ExitCode int
	Output   *regexp.Regexp
}

// Trialer is implemented by the drivers whose binaries can be tried out.
type Trialer interface {
	// Trial returns the trial of the engine's binary of the given version: the
	// upstream tag as published, for example "v2.2.8" for mtg.
	Trial(version string) Trial
}
