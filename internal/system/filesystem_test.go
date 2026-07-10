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
	if _, _, err := reader.ReadFile(context.Background(), "/large", 4); !errors.Is(err, ErrReadLimit) {
		t.Fatalf("ReadFile(limit) error = %v, want ErrReadLimit", err)
	}
	if _, _, err := reader.ReadFile(context.Background(), "/directory", 64); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("ReadFile(directory) error = %v, want ErrNotRegularFile", err)
	}
}
