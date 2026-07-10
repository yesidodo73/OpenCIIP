//go:build linux

package runlock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func acquirePlatform(ctx context.Context, stateRoot, lockPath string, create bool) (func() error, error) {
	rootInfo, err := os.Lstat(stateRoot)
	if err != nil {
		return nil, &Error{Code: CodeInvalidRoot, Path: stateRoot, Err: err}
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		return nil, &Error{Code: CodeUnsafePath, Path: stateRoot, Err: fmt.Errorf("state root must be a private real directory")}
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != uint32(os.Geteuid()) || uint32(rootStat.Mode)&0o7777 != 0o700 {
		return nil, &Error{Code: CodeUnsafePath, Path: stateRoot, Err: fmt.Errorf("state root owner does not match effective user")}
	}
	resolved, err := filepathEvalNoSymlink(stateRoot)
	if err != nil || resolved != stateRoot {
		if err == nil {
			err = fmt.Errorf("state root contains a symbolic link")
		}
		return nil, &Error{Code: CodeUnsafePath, Path: stateRoot, Err: err}
	}

	rootFD, err := syscall.Open(stateRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &Error{Code: CodeUnsafePath, Path: stateRoot, Err: err}
	}
	var openedRoot syscall.Stat_t
	if err := syscall.Fstat(rootFD, &openedRoot); err != nil {
		_ = syscall.Close(rootFD)
		return nil, &Error{Code: CodeUnsafePath, Path: stateRoot, Err: err}
	}
	if openedRoot.Dev != rootStat.Dev || openedRoot.Ino != rootStat.Ino || openedRoot.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(rootFD)
		return nil, &Error{Code: CodeUnsafePath, Path: stateRoot, Err: fmt.Errorf("state root identity changed during lock acquisition")}
	}

	flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if create {
		flags |= syscall.O_CREAT
	}
	fd, err := syscall.Openat(rootFD, "remediation.lock", flags, 0o600)
	if err != nil {
		_ = syscall.Close(rootFD)
		return nil, &Error{Code: CodeUnsafePath, Path: lockPath, Err: err}
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = syscall.Close(fd)
		_ = syscall.Close(rootFD)
		return nil, &Error{Code: CodeUnsafePath, Path: lockPath, Err: fmt.Errorf("create lock file handle")}
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		_ = syscall.Close(rootFD)
		return nil, &Error{Code: CodeUnsafePath, Path: lockPath, Err: err}
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || uint32(stat.Mode)&0o7777 != 0o600 {
		_ = file.Close()
		_ = syscall.Close(rootFD)
		return nil, &Error{Code: CodeUnsafePath, Path: lockPath, Err: fmt.Errorf("lock must be a single-link 0600 regular file owned by the effective user")}
	}

	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			_ = syscall.Close(rootFD)
			return nil, &Error{Code: CodeLockUnavailable, Path: lockPath, Err: err}
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			_ = syscall.Close(rootFD)
			return nil, &Error{Code: CodeLockUnavailable, Path: lockPath, Err: ctx.Err()}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if create {
		if err := syscall.Fsync(rootFD); err != nil {
			_ = syscall.Flock(fd, syscall.LOCK_UN)
			_ = file.Close()
			_ = syscall.Close(rootFD)
			return nil, &Error{Code: CodeUnsafePath, Path: stateRoot, Err: err}
		}
	}

	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
				releaseErr = err
			}
			if err := file.Close(); err != nil && releaseErr == nil {
				releaseErr = err
			}
			if err := syscall.Close(rootFD); err != nil && releaseErr == nil {
				releaseErr = err
			}
		})
		return releaseErr
	}, nil
}

func filepathEvalNoSymlink(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}
