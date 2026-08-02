//go:build !linux

package runlock

import (
	"context"
	"os"
	"testing"
)

func TestAcquireFailsClosedOnUnverifiedPlatform(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod(root) error = %v", err)
	}
	handle, err := Acquire(context.Background(), root)
	if handle != nil {
		_ = handle.Release()
		t.Fatal("Acquire() returned a lock handle on an unverified platform")
	}
	if code := CodeOf(err); code != CodeUnsupportedPlatform {
		t.Fatalf("Acquire() error = %v, code = %q, want %q", err, code, CodeUnsupportedPlatform)
	}
}
