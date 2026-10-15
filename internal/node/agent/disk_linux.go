package agent

import "syscall"

// diskUsage returns the size of the file system that holds path and how much
// of it is used, in bytes; zeros when it cannot be read.
func diskUsage(path string) (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Bsize <= 0 {
		return 0, 0
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	if st.Bfree <= st.Blocks {
		used = (st.Blocks - st.Bfree) * bsize
	}
	return total, used
}
