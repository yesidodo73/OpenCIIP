//go:build linux

package stateroot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	if !filepath.IsAbs(absolute) {
		return "", invalid("path is not absolute")
	}

	current := string(filepath.Separator)
	if err := validateDirectory(current, false); err != nil {
		return "", err
	}
	relative := strings.TrimPrefix(absolute, current)
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		if component == "" {
			continue
		}
		if component == "." || component == ".." || strings.IndexByte(component, 0) >= 0 {
			return "", invalid("path has a non-canonical component")
		}
		parent := current
		current = filepath.Join(current, component)
		info, inspectErr := os.Lstat(current)
		if errors.Is(inspectErr, os.ErrNotExist) {
			if !create {
				return "", invalid(fmt.Sprintf("%s does not exist", current))
			}
			// A missing component is created on the filesystem that contains
			// its nearest existing parent. Prove that filesystem is a supported
			// durable local filesystem before making the directory.
			if err := validateStateFilesystem(parent); err != nil {
				return "", err
			}
			if err := os.Mkdir(current, 0o700); err != nil {
				return "", invalid(fmt.Sprintf("create %s: %v", current, err))
			}
			if err := os.Chmod(current, 0o700); err != nil {
				return "", invalid(fmt.Sprintf("secure %s: %v", current, err))
			}
			if err := syncDirectory(parent); err != nil {
				return "", invalid(fmt.Sprintf("sync parent of %s: %v", current, err))
			}
			info, inspectErr = os.Lstat(current)
		}
		if inspectErr != nil {
			return "", invalid(fmt.Sprintf("inspect %s: %v", current, inspectErr))
		}
		final := index == len(components)-1
		if err := validateDirectoryInfo(current, info, final); err != nil {
			return "", err
		}
	}
	if current != absolute {
		return "", invalid("path could not be resolved canonically")
	}
	if err := validateDirectory(absolute, true); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != absolute {
		if err == nil {
			err = fmt.Errorf("path contains a symbolic link")
		}
		return "", invalid(err.Error())
	}
	if err := verifyOpenedIdentity(absolute); err != nil {
		return "", err
	}
	// Re-check the final root after creation. This also catches a mount that
	// appeared below the parent that was checked before the first mkdir.
	if err := validateStateFilesystem(absolute); err != nil {
		return "", err
	}
	return absolute, nil
}

func validateDirectory(path string, final bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return invalid(fmt.Sprintf("inspect %s: %v", path, err))
	}
	return validateDirectoryInfo(path, info, final)
}

func validateDirectoryInfo(path string, info os.FileInfo, final bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return invalid(fmt.Sprintf("%s is not a real directory", path))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return invalid(fmt.Sprintf("ownership for %s is unavailable", path))
	}
	effectiveUID := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != effectiveUID {
		return invalid(fmt.Sprintf("%s is owned by untrusted uid %d", path, stat.Uid))
	}
	permissions := info.Mode().Perm()
	if permissions&0o022 != 0 {
		return invalid(fmt.Sprintf("%s is writable by group or other users", path))
	}
	if final && (stat.Uid != effectiveUID || permissions != 0o700) {
		return invalid(fmt.Sprintf("%s must be owned by uid %d with mode 0700", path, effectiveUID))
	}
	return nil
}

func verifyOpenedIdentity(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return invalid(fmt.Sprintf("inspect %s: %v", path, err))
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return invalid(fmt.Sprintf("open %s without following links: %v", path, err))
	}
	defer syscall.Close(fd)
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil {
		return invalid(fmt.Sprintf("inspect opened %s: %v", path, err))
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || opened.Mode&syscall.S_IFMT != syscall.S_IFDIR || opened.Dev != beforeStat.Dev || opened.Ino != beforeStat.Ino {
		return invalid(fmt.Sprintf("%s changed while it was opened", path))
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
