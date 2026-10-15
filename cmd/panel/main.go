// Command postern-panel is the control panel binary of Postern.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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
	case "serve":
		// SIGTERM is what docker stop sends; SIGINT is Ctrl-C.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		// The first signal starts the shutdown. A second one, from somebody who
		// does not want to wait for it, gets the default behaviour back.
		go func() {
			<-ctx.Done()
			stop()
		}()
		return runServe(ctx, args[1:], os.Getenv, stdout, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, version.String())
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "postern-panel: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: postern-panel <command>

Commands:
  serve    run the panel; it is configured by the environment (below)
  version  print version information

Environment of serve:
  POSTERN_DATA             data directory: the database, backups, downloaded
                           engines (default /data)
  POSTERN_KEYS             directory of the master key, master.key; keep it apart
                           from the data directory (default /keys)
  POSTERN_LISTEN           address to listen on (default :8080)
  POSTERN_TRUSTED_PROXIES  comma-separated IP addresses or CIDR prefixes of the
                           reverse proxies whose X-Forwarded-For and
                           X-Forwarded-Proto are believed
                           (default 127.0.0.1/32,::1/128)
  POSTERN_HEALTHY_FILE     file to create once the panel is serving; the launcher
                           of the Docker image sets it (default none)
  POSTERN_NODE_KIT_DIR     directory of the node kit: the postern-node binaries
                           and the installer that the panel serves for manual
                           installs of nodes; the Docker image has it there
                           (default /usr/local/share/postern/node-kit)
  POSTERN_NODE_IMAGE       Docker image of the node that the one-command install
                           of a node runs, e.g. ghcr.io/<OWNER>/postern-node;
                           without a tag or digest the tag is the version of the
                           panel (a dev build then has none: give the tag)
                           (default the image of the build, if it has one)
  POSTERN_GEOIP_BASE_URL   http:// or https:// address of the directory that the
                           country database (dbip-country-lite-YYYY-MM.mmdb.gz)
                           is downloaded from; for a mirror, or a test
                           (default https://download.db-ip.com/free)
  POSTERN_PUBLIC_PAGE      off serves the admin on every host, the public page's
                           own included, and the page on none: the way back in
                           when the page was given the name the panel is
                           reached by (default on)
`)
}
