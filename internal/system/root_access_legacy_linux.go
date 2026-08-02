//go:build linux

package system

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const maximumLegacySymlinks = 40

// legacyLinuxRootAccess provides the same rooted traversal guarantee on kernels
// that predate openat2. os.Root resolves every component relative to an open
// directory descriptor; the additional resolver preserves Linux's root-relative
// interpretation of absolute symbolic links.
type legacyLinuxRootAccess struct {
	mu   sync.RWMutex
	root *os.Root
}

func newLegacyRootedAccess(rootPath string) (rootedAccess, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	return &legacyLinuxRootAccess{root: root}, nil
}

func (r *legacyLinuxRootAccess) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	root := r.root
	r.root = nil
	r.mu.Unlock()
	if root == nil {
		return nil
	}
	return root.Close()
}

func (r *legacyLinuxRootAccess) Open(name string) (*os.File, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, os.ErrClosed
	}
	resolved, err := resolveLegacyRootName(r.root, name, true)
	if err != nil {
		return nil, err
	}
	// O_NONBLOCK prevents a path race to a FIFO or device from blocking before
	// ReadFile verifies that the opened descriptor is a regular file.
	return r.root.OpenFile(resolved, os.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
}

func (r *legacyLinuxRootAccess) OpenNoFollow(name string) (*os.File, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, os.ErrClosed
	}
	resolved, err := resolveLegacyRootName(r.root, name, false)
	if err != nil {
		return nil, err
	}
	before, err := r.root.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, &os.PathError{Op: "openat", Path: resolved, Err: unix.ELOOP}
	}
	file, err := r.root.OpenFile(resolved, os.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	after, err := r.root.Lstat(resolved)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !sameFileSnapshot(before, opened) || !sameFileSnapshot(opened, after) {
		_ = file.Close()
		return nil, &os.PathError{Op: "openat", Path: resolved, Err: ErrFileChanged}
	}
	return file, nil
}

func (r *legacyLinuxRootAccess) OpenDir(name string) (*os.File, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, os.ErrClosed
	}
	resolved, err := resolveLegacyRootName(r.root, name, true)
	if err != nil {
		return nil, err
	}
	return r.root.OpenFile(resolved, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOCTTY, 0)
}

func (r *legacyLinuxRootAccess) Stat(name string) (os.FileInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, os.ErrClosed
	}
	resolved, err := resolveLegacyRootName(r.root, name, true)
	if err != nil {
		return nil, err
	}
	return r.root.Stat(resolved)
}

func (r *legacyLinuxRootAccess) Lstat(name string) (os.FileInfo, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, "", os.ErrClosed
	}
	resolved, err := resolveLegacyRootName(r.root, name, false)
	if err != nil {
		return nil, "", err
	}
	info, err := r.root.Lstat(resolved)
	if err != nil {
		return nil, "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return info, "", nil
	}
	target, err := readLegacyRootLink(r.root, resolved, false)
	if err != nil {
		return nil, "", err
	}
	return info, target, nil
}

func resolveLegacyRootName(root *os.Root, name string, followFinal bool) (string, error) {
	if name == "." {
		return name, nil
	}
	if name == "" || path.IsAbs(name) || name != path.Clean(name) || name == ".." || strings.HasPrefix(name, "../") {
		return "", fmt.Errorf("%w: %s", ErrPathOutsideRoot, name)
	}

	current := name
	for links := 0; ; {
		parts := strings.Split(current, "/")
		resolvedLink := false
		for index := range parts {
			if index == len(parts)-1 && !followFinal {
				return current, nil
			}
			prefix := strings.Join(parts[:index+1], "/")
			info, err := root.Lstat(prefix)
			if err != nil {
				return "", err
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			links++
			if links > maximumLegacySymlinks {
				return "", &os.PathError{Op: "openat", Path: name, Err: unix.ELOOP}
			}
			target, err := readLegacyRootLink(root, prefix, true)
			if err != nil {
				return "", err
			}
			current, err = replaceLegacyRootLink(parts, index, target)
			if err != nil {
				return "", err
			}
			resolvedLink = true
			break
		}
		if !resolvedLink {
			return current, nil
		}
	}
}

func replaceLegacyRootLink(parts []string, index int, target string) (string, error) {
	var combined strings.Builder
	if path.IsAbs(target) {
		combined.WriteString(strings.TrimLeft(target, "/"))
	} else {
		if index > 0 {
			combined.WriteString(strings.Join(parts[:index], "/"))
			combined.WriteByte('/')
		}
		combined.WriteString(target)
	}
	if index+1 < len(parts) {
		if combined.Len() > 0 && !strings.HasSuffix(combined.String(), "/") {
			combined.WriteByte('/')
		}
		combined.WriteString(strings.Join(parts[index+1:], "/"))
	}
	replaced := combined.String()
	replaced = clampLegacyRootParents(replaced)
	if replaced == "" {
		return ".", nil
	}
	return replaced, nil
}

func clampLegacyRootParents(name string) string {
	components := strings.Split(name, "/")
	depth := 0
	for index, component := range components {
		switch component {
		case "", ".":
			continue
		case "..":
			if depth == 0 {
				components[index] = "."
				continue
			}
			depth--
		default:
			depth++
		}
	}
	return strings.Join(components, "/")
}

func readLegacyRootLink(root *os.Root, name string, rejectMagic bool) (string, error) {
	file, err := root.OpenFile(name, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		return "", &os.PathError{Op: "fstatfs", Path: name, Err: err}
	}
	target, err := readlinkFile(file, name)
	if err != nil {
		return "", err
	}
	if rejectMagic && filesystem.Type == unix.PROC_SUPER_MAGIC && !ordinaryProcLinkTarget(target) {
		return "", &os.PathError{Op: "openat", Path: name, Err: unix.ELOOP}
	}
	return target, nil
}

func ordinaryProcLinkTarget(target string) bool {
	if target == "self/mounts" || target == "self/net" || target == "/sys/firmware/devicetree/base" {
		return true
	}
	parts := strings.Split(target, "/")
	if len(parts) == 1 {
		_, err := strconv.ParseUint(parts[0], 10, 64)
		return err == nil
	}
	if len(parts) == 3 && parts[1] == "task" {
		_, processErr := strconv.ParseUint(parts[0], 10, 64)
		_, threadErr := strconv.ParseUint(parts[2], 10, 64)
		return processErr == nil && threadErr == nil
	}
	return false
}
