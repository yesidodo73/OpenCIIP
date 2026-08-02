//go:build linux

package regularfile

import (
	"context"
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNormalizeRejectsUnsupportedExtendedAttribute(t *testing.T) {
	fixture := newReadOnlyLinuxFixture(t, 0o640)
	const name = "user.openciip-test"
	if err := unix.Setxattr(fixture.physicalPath, name, []byte("fixture"), 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EPERM) {
			t.Skipf("fixture filesystem does not permit user xattrs: %v", err)
		}
		t.Fatalf("set unsupported xattr: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Removexattr(fixture.physicalPath, name); err != nil && !errors.Is(err, syscall.ENODATA) {
			t.Errorf("remove unsupported xattr fixture: %v", err)
		}
	})

	_, err := fixture.handler.Normalize(context.Background(), fixture.reference)
	if got := CodeOf(err); got != CodeUnsupportedMetadata {
		t.Fatalf("Normalize() error code = %q, want %q (error: %v)", got, CodeUnsupportedMetadata, err)
	}
}

func TestNormalizeRejectsFileAboveConfiguredLimit(t *testing.T) {
	fixture := newReadOnlyLinuxFixture(t, 0o640)
	fixture.handler.maxFileSize = int64(len(fixture.content) - 1)

	_, err := fixture.handler.Normalize(context.Background(), fixture.reference)
	if got := CodeOf(err); got != CodeUnsupportedFileType {
		t.Fatalf("Normalize() error code = %q, want %q (error: %v)", got, CodeUnsupportedFileType, err)
	}
}
