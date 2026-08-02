//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	rootedResolveFlags = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS
	maximumLinkSize    = 64 << 10
)

type linuxRootAccess struct {
	mu   sync.RWMutex
	root *os.File
}

func newRootedAccess(path string) (rootedAccess, error) {
	supported, err := rootedOpenat2Supported()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRootedAccessUnsupported, err)
	}
	if !supported {
		return newLegacyRootedAccess(path)
	}

	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	root := os.NewFile(uintptr(fd), path)
	if root == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create system root handle")
	}
	access := &linuxRootAccess{root: root}
	probe, err := access.openWithFlags(".", uint64(unix.O_PATH|unix.O_DIRECTORY))
	if err != nil {
		_ = access.Close()
		return nil, fmt.Errorf("%w: %v", ErrRootedAccessUnsupported, err)
	}
	if err := probe.Close(); err != nil {
		_ = access.Close()
		return nil, fmt.Errorf("close rooted path probe: %w", err)
	}
	return access, nil
}

func rootedOpenat2Supported() (bool, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, ".", &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: rootedResolveFlags,
	})
	if errors.Is(err, unix.ENOSYS) {
		return false, nil
	}
	if err != nil {
		return false, &os.PathError{Op: "openat2", Path: ".", Err: err}
	}
	return true, unix.Close(fd)
}

func (r *linuxRootAccess) Close() error {
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

func (r *linuxRootAccess) Open(name string) (*os.File, error) {
	// O_NONBLOCK prevents a path race to a FIFO or device from blocking before
	// ReadFile can verify that the opened descriptor is a regular file.
	return r.openWithFlags(name, uint64(unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK))
}

func (r *linuxRootAccess) OpenNoFollow(name string) (*os.File, error) {
	return r.openWithFlags(name, uint64(unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_NOFOLLOW))
}

func (r *linuxRootAccess) OpenDir(name string) (*os.File, error) {
	return r.openWithFlags(name, uint64(unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOCTTY))
}

func (r *linuxRootAccess) Stat(name string) (os.FileInfo, error) {
	file, err := r.openWithFlags(name, uint64(unix.O_PATH))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

func (r *linuxRootAccess) Lstat(name string) (os.FileInfo, string, error) {
	file, err := r.openWithFlags(name, uint64(unix.O_PATH|unix.O_NOFOLLOW))
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return info, "", nil
	}
	target, err := readlinkFile(file, name)
	if err != nil {
		return nil, "", err
	}
	return info, target, nil
}

func (r *linuxRootAccess) openWithFlags(name string, flags uint64) (*os.File, error) {
	if r == nil {
		return nil, os.ErrClosed
	}
	r.mu.RLock()
	if r.root == nil {
		r.mu.RUnlock()
		return nil, os.ErrClosed
	}
	fd, err := unix.Openat2(int(r.root.Fd()), name, &unix.OpenHow{
		Flags:   flags | uint64(unix.O_CLOEXEC),
		Resolve: rootedResolveFlags,
	})
	r.mu.RUnlock()
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "openat2", Path: name, Err: os.ErrInvalid}
	}
	return file, nil
}

func readlinkFile(file *os.File, name string) (string, error) {
	for size := 128; size <= maximumLinkSize; size *= 2 {
		buffer := make([]byte, size)
		count, err := unix.Readlinkat(int(file.Fd()), "", buffer)
		if err != nil {
			return "", &os.PathError{Op: "readlinkat", Path: name, Err: err}
		}
		if count < len(buffer) {
			return string(buffer[:count]), nil
		}
	}
	return "", fmt.Errorf("%w: symbolic link target %s", ErrReadLimit, name)
}
