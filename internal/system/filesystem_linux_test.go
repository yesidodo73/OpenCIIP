//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOSReaderFollowsAbsoluteSymlinkInsideRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o700); err != nil {
		t.Fatalf("MkdirAll(pam.d) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "authselect"), 0o700); err != nil {
		t.Fatalf("MkdirAll(authselect) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "authselect", "system-auth"), []byte("auth required pam_env.so\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink("/etc/authselect/system-auth", filepath.Join(root, "etc", "pam.d", "system-auth")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	reader := newLinuxTestReader(t, root)

	data, _, err := reader.ReadFile(context.Background(), "/etc/pam.d/system-auth", 1024)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "auth required pam_env.so\n" {
		t.Fatalf("ReadFile() = %q", data)
	}
	link, err := reader.Lstat("/etc/pam.d/system-auth")
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if link.FileType != "symlink" || link.LinkTarget != "/etc/authselect/system-auth" {
		t.Fatalf("Lstat() = %#v", link)
	}
}

func TestOSReaderRejectsRelativeAndAbsoluteSymlinkEscape(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(root) error = %v", err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatalf("Mkdir(outside) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink("../outside", filepath.Join(root, "relative")); err != nil {
		t.Fatalf("Symlink(relative) error = %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "absolute")); err != nil {
		t.Fatalf("Symlink(absolute) error = %v", err)
	}
	reader := newLinuxTestReader(t, root)

	if _, _, err := reader.ReadFile(context.Background(), "/relative/secret", 64); err == nil {
		t.Fatal("ReadFile(relative escape) succeeded")
	}
	if _, _, err := reader.ReadFile(context.Background(), "/absolute", 64); err == nil {
		t.Fatal("ReadFile(absolute escape) succeeded")
	}
}

func TestOSReaderRejectsProcMagicLinkButCanInspectFinalNamespaceLink(t *testing.T) {
	reader := newLinuxTestReader(t, "/")
	probePath := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probePath, []byte("probe\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	file, err := os.Open(probePath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer file.Close()
	magicPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
	if _, _, err := reader.ReadFile(context.Background(), magicPath, 64); err == nil {
		t.Fatal("ReadFile(proc magic link) succeeded")
	}

	namespacePath := fmt.Sprintf("/proc/%d/ns/mnt", os.Getpid())
	metadata, err := reader.Lstat(namespacePath)
	if err != nil {
		t.Fatalf("Lstat(namespace) error = %v", err)
	}
	if metadata.FileType != "symlink" || !strings.HasPrefix(metadata.LinkTarget, "mnt:[") {
		t.Fatalf("Lstat(namespace) = %#v", metadata)
	}
}

func TestReadOpenedFileRejectsMutationBeforePostReadSnapshot(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mutable")
	if err := os.WriteFile(path, []byte("before\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	_, _, err = readOpenedFile(context.Background(), "/mutable", 64, file, func() error {
		time.Sleep(time.Millisecond)
		if err := os.WriteFile(path, []byte("after!\n"), 0o600); err != nil {
			return err
		}
		return os.Chtimes(path, before.ModTime(), before.ModTime())
	})
	if !errors.Is(err, ErrFileChanged) {
		t.Fatalf("readOpenedFile() error = %v, want ErrFileChanged", err)
	}
}

func TestOSReaderCloseIsIdempotentAndFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("value\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
	if _, _, err := reader.ReadFile(context.Background(), "/file", 64); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ReadFile(after Close) error = %v, want os.ErrClosed", err)
	}
}

func newLinuxTestReader(t *testing.T, root string) *OSReader {
	t.Helper()
	reader, err := NewOSReader(root)
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("OSReader.Close() error = %v", err)
		}
	})
	return reader
}
