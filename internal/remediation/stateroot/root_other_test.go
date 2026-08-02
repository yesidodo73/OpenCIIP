//go:build !linux

package stateroot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateExistingPrivateDirectoryOnNonLinux(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod(root) error = %v", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("Lstat(root) error = %v", err)
	}
	resolved, err := Validate(root)
	if info.Mode().Perm()&0o077 != 0 {
		if err == nil {
			t.Fatalf("Validate() resolved %q although the platform did not preserve private mode bits (%v)", resolved, info.Mode())
		}
		return
	}
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("Abs(root) error = %v", err)
	}
	if resolved != filepath.Clean(absolute) {
		t.Fatalf("Validate() = %q, want %q", resolved, filepath.Clean(absolute))
	}
}

func TestPrepareDoesNotCreateStateRootOnNonLinux(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing")
	if resolved, err := Prepare(missing); err == nil {
		t.Fatalf("Prepare() resolved %q on an unverified platform", resolved)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("Prepare() created missing root or returned unexpected Lstat error: %v", err)
	}
}

func TestValidateRejectsSymlinkedDirectoryOnNonLinux(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	if resolved, err := Validate(link); err == nil {
		t.Fatalf("Validate(symlink) resolved %q", resolved)
	}
}
