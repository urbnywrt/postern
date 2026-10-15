package edge

import (
	"math"
	"strconv"
	"strings"
)

// The files the memory limit of the process is read from on Linux: the limit
// of its cgroup (v2), and the memory of the machine.
const (
	cgroupMemoryMax = "/sys/fs/cgroup/memory.max"
	procMeminfo     = "/proc/meminfo"
)

// Where the memory limit comes from, for the log.
const (
	memoryFromCgroup  = "cgroup"
	memoryFromMeminfo = "meminfo"
	memoryUnknown     = "unknown"
)

// memoryLimit returns the memory the process may use, in bytes, and where that
// comes from: the memory.max of its cgroup when that is a number (it is "max"
// for no limit), else MemTotal of /proc/meminfo; 0 and memoryUnknown when
// neither can be read. read reads a whole file, as os.ReadFile does.
func memoryLimit(read func(name string) ([]byte, error)) (uint64, string) {
	if b, err := read(cgroupMemoryMax); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			return n, memoryFromCgroup
		}
	}
	if b, err := read(procMeminfo); err == nil {
		if n := memTotal(string(b)); n > 0 {
			return n, memoryFromMeminfo
		}
	}
	return 0, memoryUnknown
}

// memTotal returns MemTotal of the content of /proc/meminfo, in bytes; 0 when
// it has none that can be read.
func memTotal(meminfo string) uint64 {
	for line := range strings.Lines(meminfo) {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return 0
		}
		if len(f) > 1 && f[1] == "kB" {
			n = min(n, math.MaxUint64/1024) * 1024
		}
		return n
	}
	return 0
}
