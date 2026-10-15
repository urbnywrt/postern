// Command badengine stands in for a telemt release that passes the trial run
// of a node and cannot serve: TestVersions serves it as telemt 3.5.91.
//
// The trial runs "telemt healthcheck --mode liveness <missing file>", which
// telemt answers with "[telemt] healthcheck failed: config load failed: …" and
// exit code 1 (Global Constraints, Trial runs); this program answers the same.
// Run as an engine, with anything else, it exits with 3 at once, so the new
// generation of the engine never serves and the step of the rollout fails.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		fmt.Println("[telemt] healthcheck failed: config load failed: e2e")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "badengine: the stand-in of TestVersions does not serve")
	os.Exit(3)
}
