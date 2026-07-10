//go:build linux

package journal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

func acquireFileLock(ctx context.Context, path string) (func() error, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create lock file handle")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, fmt.Errorf("lock path must be a private regular file")
	}

	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	var once sync.Once
	var unlockErr error
	return func() error {
		once.Do(func() {
			if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
				unlockErr = err
			}
			if err := file.Close(); err != nil && unlockErr == nil {
				unlockErr = err
			}
		})
		return unlockErr
	}, nil
}
