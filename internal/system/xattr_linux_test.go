//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOSReaderReadXAttrsCapturesPresentAndAbsentAttributes(t *testing.T) {
	root := t.TempDir()
	hostPath := filepath.Join(root, "target")
	if err := os.WriteFile(hostPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	const attribute = "user.openciip_test"
	if err := unix.Setxattr(hostPath, attribute, []byte("value"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skipf("test filesystem does not permit user xattrs: %v", err)
		}
		t.Fatal(err)
	}

	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	values, metadata, err := reader.ReadXAttrs(
		context.Background(),
		"/target",
		[]string{attribute, "user.openciip_absent"},
		1024,
		true,
	)
	if err != nil {
		t.Fatalf("ReadXAttrs() error = %v", err)
	}
	if got := string(values[attribute]); got != "value" {
		t.Fatalf("attribute value = %q, want value", got)
	}
	if _, exists := values["user.openciip_absent"]; exists {
		t.Fatal("absent attribute was returned as present")
	}
	if metadata.Path != "/target" || metadata.FileType != "regular" {
		t.Fatalf("metadata = %#v, want rooted target metadata", metadata)
	}
}

func TestOSReaderReadXAttrsEnforcesReadLimit(t *testing.T) {
	root := t.TempDir()
	hostPath := filepath.Join(root, "target")
	if err := os.WriteFile(hostPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	const attribute = "user.openciip_test"
	if err := unix.Setxattr(hostPath, attribute, []byte("too-large"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skipf("test filesystem does not permit user xattrs: %v", err)
		}
		t.Fatal(err)
	}

	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	_, _, err = reader.ReadXAttrs(context.Background(), "/target", []string{attribute}, 4, true)
	if !errors.Is(err, ErrReadLimit) {
		t.Fatalf("ReadXAttrs() error = %v, want ErrReadLimit", err)
	}
}

func TestOSReaderReadXAttrsDoesNotFollowFinalSymlinkWhenDisabled(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	const attribute = "user.openciip_test"
	if err := unix.Setxattr(target, attribute, []byte("value"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skipf("test filesystem does not permit user xattrs: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, _, err := reader.ReadXAttrs(
		context.Background(),
		"/link",
		[]string{attribute},
		1024,
		false,
	); err == nil {
		t.Fatal("ReadXAttrs() followed the final symlink despite followFinalSymlink=false")
	}
	values, _, err := reader.ReadXAttrs(
		context.Background(),
		"/link",
		[]string{attribute},
		1024,
		true,
	)
	if err != nil || string(values[attribute]) != "value" {
		t.Fatalf("ReadXAttrs(follow) = %q, %v", values[attribute], err)
	}
}

func TestLegacyOSReaderReadXAttrsDoesNotFollowFinalSymlinkWhenDisabled(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	const attribute = "user.openciip_test"
	if err := unix.Setxattr(target, attribute, []byte("value"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skipf("test filesystem does not permit user xattrs: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	access, err := newLegacyRootedAccess(root)
	if err != nil {
		t.Fatal(err)
	}
	reader := &OSReader{root: access}
	defer reader.Close()

	if _, _, err := reader.ReadXAttrs(
		context.Background(),
		"/link",
		[]string{attribute},
		1024,
		false,
	); err == nil {
		t.Fatal("legacy ReadXAttrs() followed the final symlink despite followFinalSymlink=false")
	}
	values, _, err := reader.ReadXAttrs(
		context.Background(),
		"/link",
		[]string{attribute},
		1024,
		true,
	)
	if err != nil || string(values[attribute]) != "value" {
		t.Fatalf("legacy ReadXAttrs(follow) = %q, %v", values[attribute], err)
	}
}
