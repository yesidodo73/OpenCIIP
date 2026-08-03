//go:build linux

package report

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validateReportDirectoryAccess(path string, info os.FileInfo) error {
	uid, err := reportDirectoryUID(path, info)
	if err != nil {
		return err
	}
	currentUID := uint32(os.Geteuid())
	private := uid == currentUID && info.Mode().Perm()&0o022 == 0
	trustedSticky := info.Mode()&os.ModeSticky != 0 && (uid == 0 || uid == currentUID)
	if private || trustedSticky {
		return nil
	}
	if uid != currentUID {
		return fmt.Errorf("report root must be owned by the current user or be a trusted sticky directory: %s", path)
	}
	return fmt.Errorf("report root must not be writable by group or other users unless it is a trusted sticky directory: %s", path)
}

func validatePrivateReportDirectory(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("report directory must be a real directory: %s", path)
	}
	uid, err := reportDirectoryUID(path, info)
	if err != nil {
		return err
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("report directory must be owned by the current user: %s", path)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("report directory must have mode 0700: %s", path)
	}
	return nil
}

func reportDirectoryUID(path string, info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("could not verify report directory owner: %s", path)
	}
	return stat.Uid, nil
}

func validateReportDirectoryPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(path) {
		if err == nil {
			err = fmt.Errorf("path contains a symbolic link")
		}
		return fmt.Errorf("resolve report root: %w", err)
	}
	return nil
}
