//go:build !windows

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOSReaderReadsOnlyRootedRegularFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directory := filepath.Join(root, "etc")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "sample.conf"), []byte("value=1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("OSReader.Close() error = %v", err)
		}
	})
	data, metadata, err := reader.ReadFile(context.Background(), "/etc/sample.conf", 64)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "value=1\n" || metadata.Path != "/etc/sample.conf" || metadata.FileType != "regular" {
		t.Fatalf("ReadFile() = %q, %#v", data, metadata)
	}
	if _, err := reader.Stat("etc/sample.conf"); err == nil {
		t.Fatal("Stat() accepted a relative system path")
	}
}

func TestOSReaderEnforcesReadLimitAndFileType(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large"), []byte("12345"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("OSReader.Close() error = %v", err)
		}
	})
	if _, _, err := reader.ReadFile(context.Background(), "/large", 4); !errors.Is(err, ErrReadLimit) {
		t.Fatalf("ReadFile(limit) error = %v, want ErrReadLimit", err)
	}
	if _, _, err := reader.ReadFile(context.Background(), "/directory", 64); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("ReadFile(directory) error = %v, want ErrNotRegularFile", err)
	}
}

func TestOSReaderRejectsIntermediateSymlinkOutsideRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("OSReader.Close() error = %v", err)
		}
	})
	if _, err := reader.Lstat("/etc/secret"); err == nil {
		t.Fatal("Lstat() followed an intermediate symlink outside the configured root")
	}
	if _, _, err := reader.ReadFile(context.Background(), "/etc/secret", 64); err == nil {
		t.Fatal("ReadFile() followed an intermediate symlink outside the configured root")
	}
}

func TestOSReaderFollowsRelativeSymlinkWithinRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "lib"), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "etc"), 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "lib", "os-release"), []byte("ID=fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc", "os-release")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("OSReader.Close() error = %v", err)
		}
	})
	data, _, err := reader.ReadFile(context.Background(), "/etc/os-release", 64)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "ID=fixture\n" {
		t.Fatalf("ReadFile() = %q", data)
	}
}

func TestOSReaderRejectsNonCanonicalSystemPath(t *testing.T) {
	t.Parallel()
	reader, err := NewOSReader(t.TempDir())
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("OSReader.Close() error = %v", err)
		}
	})
	if _, err := reader.Lstat("/etc/../secret"); err == nil {
		t.Fatal("Lstat() accepted a non-canonical system path")
	}
}
