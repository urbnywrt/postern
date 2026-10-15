//go:build !linux

package agent

// diskUsage is not measured off Linux, where the node does not run.
func diskUsage(string) (total, used uint64) { return 0, 0 }
