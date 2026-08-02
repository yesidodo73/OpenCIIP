//go:build linux

package runlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAcquireProvidesOneExclusiveHostLock(t *testing.T) {
	root := privateStateRoot(t)

	first, err := Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("Acquire(first) error = %v", err)
	}
	t.Cleanup(func() {
		_ = first.Release()
	})
	wantPath := filepath.Join(root, "remediation.lock")
	if first.Path() != wantPath {
		t.Fatalf("Handle.Path() = %q, want %q", first.Path(), wantPath)
	}
	assertPrivateLockFile(t, wantPath)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	second, err := AcquireExisting(ctx, root)
	if second != nil {
		_ = second.Release()
		t.Fatal("AcquireExisting(second) acquired an already-held lock")
	}
	if code := CodeOf(err); code != CodeLockUnavailable {
		t.Fatalf("AcquireExisting(second) error = %v, code = %q, want %q", err, code, CodeLockUnavailable)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcquireExisting(second) error = %v, want context deadline", err)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("Release(first) error = %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("second Release(first) error = %v", err)
	}
	third, err := AcquireExisting(context.Background(), root)
	if err != nil {
		t.Fatalf("AcquireExisting(after release) error = %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("Close(third) error = %v", err)
	}
}

func TestAcquireExistingDoesNotCreatePersistentLockEntry(t *testing.T) {
	t.Parallel()

	root := privateStateRoot(t)
	lockPath := filepath.Join(root, "remediation.lock")
	handle, err := AcquireExisting(context.Background(), root)
	if handle != nil {
		_ = handle.Release()
		t.Fatal("AcquireExisting() created and acquired a missing lock entry")
	}
	if code := CodeOf(err); code != CodeUnsafePath {
		t.Fatalf("AcquireExisting() error = %v, code = %q, want %q", err, code, CodeUnsafePath)
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing lock path error = %v, want os.ErrNotExist", err)
	}
}

func TestAcquireRejectsUnsafeStateRootAndLockObjects(t *testing.T) {
	t.Run("state root mode", func(t *testing.T) {
		root := privateStateRoot(t)
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatalf("Chmod(root) error = %v", err)
		}
		t.Cleanup(func() {
			_ = os.Chmod(root, 0o700)
		})
		assertUnsafeAcquire(t, root)
	})

	t.Run("state root symlink", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatalf("Mkdir(target) error = %v", err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink(root) error = %v", err)
		}
		assertUnsafeAcquire(t, link)
	})

	t.Run("lock symlink", func(t *testing.T) {
		root := privateStateRoot(t)
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
			t.Fatalf("WriteFile(target) error = %v", err)
		}
		if err := os.Symlink(target, filepath.Join(root, "remediation.lock")); err != nil {
			t.Fatalf("Symlink(lock) error = %v", err)
		}
		assertUnsafeAcquire(t, root)
	})

	t.Run("lock hardlink", func(t *testing.T) {
		root := privateStateRoot(t)
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, []byte("lock"), 0o600); err != nil {
			t.Fatalf("WriteFile(target) error = %v", err)
		}
		if err := os.Link(target, filepath.Join(root, "remediation.lock")); err != nil {
			t.Fatalf("Link(lock) error = %v", err)
		}
		assertUnsafeAcquire(t, root)
	})

	t.Run("lock mode", func(t *testing.T) {
		root := privateStateRoot(t)
		lockPath := filepath.Join(root, "remediation.lock")
		if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
			t.Fatalf("WriteFile(lock) error = %v", err)
		}
		if err := os.Chmod(lockPath, 0o644); err != nil {
			t.Fatalf("Chmod(lock) error = %v", err)
		}
		assertUnsafeAcquire(t, root)
	})

	t.Run("lock directory", func(t *testing.T) {
		root := privateStateRoot(t)
		if err := os.Mkdir(filepath.Join(root, "remediation.lock"), 0o700); err != nil {
			t.Fatalf("Mkdir(lock) error = %v", err)
		}
		assertUnsafeAcquire(t, root)
	})
}

func privateStateRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod(root) error = %v", err)
	}
	return root
}

func assertUnsafeAcquire(t *testing.T, root string) {
	t.Helper()

	handle, err := Acquire(context.Background(), root)
	if handle != nil {
		_ = handle.Release()
		t.Fatalf("Acquire(%s) succeeded for an unsafe object", root)
	}
	if code := CodeOf(err); code != CodeUnsafePath {
		t.Fatalf("Acquire(%s) error = %v, code = %q, want %q", root, err, code, CodeUnsafePath)
	}
}

func assertPrivateLockFile(t *testing.T, path string) {
	t.Helper()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(lock) error = %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("lock ownership is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		t.Fatalf("lock mode=%v uid=%d nlink=%d, want regular 0600 uid=%d nlink=1", info.Mode(), stat.Uid, stat.Nlink, os.Geteuid())
	}
}
