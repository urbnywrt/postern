// Command postern-node is the node-side binary of Postern.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/urbnywrt/postern/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches the subcommand named by args[0] and returns the process exit
// code. It is separate from main so that tests can call it.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version":
		_, _ = fmt.Fprintln(stdout, version.String())
		return 0
	case "bootstrap":
		return runBootstrap(args[1:], stdout, stderr)
	case "agent":
		return runAgent(args[1:], stdout, stderr)
	case "edge":
		return runEdge(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "postern-node: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: postern-node <command>

Commands:
  agent      run the node agent: management API, reconciler, statistics
  bootstrap  prepare the node in its container and start the launcher
  edge       run the edge: public listeners, egress chains, control socket
  version    print version information
`)
}
