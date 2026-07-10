//go:build linux

package buildinfo

func runningExecutablePath() (string, error) {
	// Opening this procfs link refers to the executable inode of the current
	// process even if the original directory entry is replaced or removed.
	return "/proc/self/exe", nil
}
