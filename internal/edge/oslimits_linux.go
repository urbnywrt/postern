package edge

import (
	"os"
	"syscall"
)

// openFileLimit returns the soft limit of open files of the process
// (RLIMIT_NOFILE), 0 when it cannot be read. Go raises the soft limit to the
// hard one when a program starts, so this is the hard limit unless something
// has lowered it since.
func openFileLimit() uint64 {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0
	}
	return lim.Cur
}

// systemMemory returns the memory limit of the process and where it comes
// from (see memoryLimit).
func systemMemory() (uint64, string) {
	return memoryLimit(os.ReadFile)
}
