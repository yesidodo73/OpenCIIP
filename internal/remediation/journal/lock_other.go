//go:build !linux

package journal

import (
	"context"
	"fmt"
	"os"
	"sync"
)

func acquireFileLock(ctx context.Context, path string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("lock path must be a private regular file")
		}
	case !os.IsNotExist(err):
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			closeErr = file.Close()
		})
		return closeErr
	}, nil
}
