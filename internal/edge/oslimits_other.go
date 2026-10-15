//go:build !linux

package edge

// The edge runs on Linux. Elsewhere it builds, for tools and tests, and the
// limits of the process are not known: the caps are derived from the values
// taken for unknown limits (see deriveCaps).

// openFileLimit returns 0, a limit that is not known.
func openFileLimit() uint64 { return 0 }

// systemMemory returns 0, a limit that is not known.
func systemMemory() (uint64, string) { return 0, memoryUnknown }
