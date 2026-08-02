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

func TestOSReaderReadFilePrefixKeepsLargeFileBounded(t *testing.T) {
	t.Parallel()

	const fileSize = int64(100 << 20)
	root := t.TempDir()
	systemPath := filepath.Join(root, "large-executable")
	file, err := os.OpenFile(systemPath, os.O_CREATE|os.O_RDWR, 0o755)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	if _, err := file.Write([]byte("\x7fELF")); err != nil {
		_ = file.Close()
		t.Fatalf("Write() error = %v", err)
	}
	if err := file.Truncate(fileSize); err != nil {
		_ = file.Close()
		t.Fatalf("Truncate() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
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

	data, metadata, err := reader.ReadFilePrefix(
		context.Background(),
		"/large-executable",
		256,
	)
	if err != nil {
		t.Fatalf("ReadFilePrefix() error = %v", err)
	}
	if len(data) != 256 || string(data[:4]) != "\x7fELF" ||
		metadata.Size != fileSize || metadata.FileType != "regular" {
		t.Fatalf(
			"ReadFilePrefix() = bytes:%d prefix:%q metadata:%#v",
			len(data),
			data[:4],
			metadata,
		)
	}
}

func TestReadOpenedFilePrefixRejectsMetadataMutation(t *testing.T) {
	t.Parallel()

	systemPath := filepath.Join(t.TempDir(), "mutable-prefix")
	if err := os.WriteFile(systemPath, []byte("before\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	file, err := os.Open(systemPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer file.Close()

	_, _, err = readOpenedFilePrefix(
		context.Background(),
		"/mutable-prefix",
		4,
		file,
		func() error {
			return os.WriteFile(systemPath, []byte("changed-and-longer\n"), 0o600)
		},
	)
	if !errors.Is(err, ErrFileChanged) {
		t.Fatalf("readOpenedFilePrefix() error = %v, want ErrFileChanged", err)
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

func TestOSReaderReadDirBoundedDistinguishesExactLimitFromOverflow(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directory := filepath.Join(root, "logs")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
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

	entries, truncated, err := reader.ReadDirBounded("/logs", 2)
	if err != nil {
		t.Fatalf("ReadDirBounded(exact) error = %v", err)
	}
	if truncated || len(entries) != 2 {
		t.Fatalf("ReadDirBounded(exact) = %d entries, truncated=%t; want 2, false", len(entries), truncated)
	}

	if err := os.WriteFile(filepath.Join(directory, "three"), nil, 0o600); err != nil {
		t.Fatalf("WriteFile(three) error = %v", err)
	}
	entries, truncated, err = reader.ReadDirBounded("/logs", 2)
	if err != nil {
		t.Fatalf("ReadDirBounded(overflow) error = %v", err)
	}
	if !truncated || len(entries) != 2 {
		t.Fatalf("ReadDirBounded(overflow) = %d entries, truncated=%t; want 2, true", len(entries), truncated)
	}

	entries, truncated, err = reader.ReadDirBounded("/logs", 0)
	if err != nil {
		t.Fatalf("ReadDirBounded(zero) error = %v", err)
	}
	if !truncated || len(entries) != 0 {
		t.Fatalf("ReadDirBounded(zero) = %d entries, truncated=%t; want 0, true", len(entries), truncated)
	}
}
