//go:build !linux

package stateroot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func preparePlatform(value string, create bool) (string, error) {
	if strings.TrimSpace(value) == "" || strings.IndexByte(value, 0) >= 0 {
		return "", invalid("path is empty or contains a NUL byte")
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", invalid(err.Error())
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Lstat(absolute)
	if err != nil {
		if !create || !os.IsNotExist(err) {
			return "", invalid(fmt.Sprintf("inspect %s: %v", absolute, err))
		}
		return "", invalid("automatic remediation state-root creation is supported only on Linux")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", invalid("path must be a private real directory")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != absolute {
		if err == nil {
			err = fmt.Errorf("path contains a symbolic link")
		}
		return "", invalid(err.Error())
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return "", invalid(err.Error())
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		if err == nil {
			err = fmt.Errorf("directory changed while it was opened")
		}
		return "", invalid(err.Error())
	}
	return absolute, nil
}
