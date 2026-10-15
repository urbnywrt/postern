//go:build !linux

package diag

import "errors"

// diskSpace is not measured off Linux, where the node does not run.
func diskSpace(string) (total, avail uint64, err error) {
	return 0, 0, errors.New("diag: the disk is measured on Linux only")
}
