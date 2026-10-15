//go:build !unix

package reconcile

// fileOwner is not available on this platform.
func fileOwner(string) (uid, gid int, ok bool) { return 0, 0, false }
