//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"io"
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
		// Some supported filesystems expose ctime at one-second granularity.
		time.Sleep(1100 * time.Millisecond)
		if err := os.WriteFile(path, []byte("after!\n"), 0o600); err != nil {
			return err
		}
		return os.Chtimes(path, before.ModTime(), before.ModTime())
	})
	if !errors.Is(err, ErrFileChanged) {
		t.Fatalf("readOpenedFile() error = %v, want ErrFileChanged", err)
	}
}

func TestReadOpenedDirectoryBoundedSnapshotRejectsCTimeRace(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "watched")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer directory.Close()

	_, _, _, err = readOpenedDirectoryBoundedSnapshot(
		"/watched",
		8,
		directory,
		nil,
		func() error {
			// Restore the visible mode so only the Linux ctime snapshot exposes
			// the mutation. Some supported filesystems expose whole-second ctime.
			time.Sleep(1100 * time.Millisecond)
			if err := os.Chmod(path, 0o750); err != nil {
				return err
			}
			return os.Chmod(path, 0o700)
		},
	)
	if !errors.Is(err, ErrFileChanged) {
		t.Fatalf("readOpenedDirectoryBoundedSnapshot() error = %v, want ErrFileChanged", err)
	}
}

func TestOSReaderReadDirBoundedSnapshotRejectsExpectedIdentityChange(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directoryPath := filepath.Join(root, "watched")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	reader := newLinuxTestReader(t, root)

	expected, err := reader.Stat("/watched")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	entries, observed, truncated, err := reader.ReadDirBoundedSnapshot(
		"/watched",
		8,
		&expected,
	)
	if err != nil {
		t.Fatalf("ReadDirBoundedSnapshot(stable) error = %v", err)
	}
	if len(entries) != 0 || truncated || !sameMetadataSnapshot(expected, observed) {
		t.Fatalf(
			"ReadDirBoundedSnapshot(stable) = entries:%d metadata:%#v truncated:%t",
			len(entries),
			observed,
			truncated,
		)
	}

	t.Run("ctime before open", func(t *testing.T) {
		// Restore every portable metadata field before opening the snapshot.
		// The expected Linux ctime is the only remaining indication of change.
		time.Sleep(1100 * time.Millisecond)
		if err := os.Chmod(directoryPath, 0o750); err != nil {
			t.Fatalf("Chmod(temporary) error = %v", err)
		}
		if err := os.Chmod(directoryPath, 0o700); err != nil {
			t.Fatalf("Chmod(restore) error = %v", err)
		}
		_, _, _, err := reader.ReadDirBoundedSnapshot("/watched", 8, &expected)
		if !errors.Is(err, ErrFileChanged) {
			t.Fatalf("ReadDirBoundedSnapshot(ctime mismatch) error = %v, want ErrFileChanged", err)
		}
	})

	t.Run("inode replacement", func(t *testing.T) {
		original := filepath.Join(root, "original")
		if err := os.Rename(directoryPath, original); err != nil {
			t.Fatalf("Rename() error = %v", err)
		}
		if err := os.Mkdir(directoryPath, 0o700); err != nil {
			t.Fatalf("Mkdir(replacement) error = %v", err)
		}
		_, _, _, err := reader.ReadDirBoundedSnapshot("/watched", 8, &expected)
		if !errors.Is(err, ErrFileChanged) {
			t.Fatalf("ReadDirBoundedSnapshot(replaced inode) error = %v, want ErrFileChanged", err)
		}
	})

	current, err := reader.Stat("/watched")
	if err != nil {
		t.Fatalf("Stat(replacement) error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*FileMetadata)
	}{
		{
			name: "device",
			mutate: func(metadata *FileMetadata) {
				metadata.Device++
			},
		},
		{
			name: "type",
			mutate: func(metadata *FileMetadata) {
				metadata.FileType = "regular"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := current
			test.mutate(&changed)
			_, _, _, err := reader.ReadDirBoundedSnapshot("/watched", 8, &changed)
			if !errors.Is(err, ErrFileChanged) {
				t.Fatalf(
					"ReadDirBoundedSnapshot(%s mismatch) error = %v, want ErrFileChanged",
					test.name,
					err,
				)
			}
		})
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

func TestLegacyRootAccessMatchesRootedSymlinkSemantics(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "authselect"), 0o700); err != nil {
		t.Fatalf("MkdirAll(authselect) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o700); err != nil {
		t.Fatalf("MkdirAll(pam.d) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "authselect", "system-auth"), []byte("auth required pam_env.so\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink("/etc/authselect/system-auth", filepath.Join(root, "etc", "pam.d", "system-auth")); err != nil {
		t.Fatalf("Symlink(inside) error = %v", err)
	}
	if err := os.Symlink("../../outside", filepath.Join(root, "etc", "escape")); err != nil {
		t.Fatalf("Symlink(escape) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("clamped to root\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	if err := os.Symlink("../../target", filepath.Join(root, "etc", "clamped")); err != nil {
		t.Fatalf("Symlink(clamped) error = %v", err)
	}

	access, err := newLegacyRootedAccess(root)
	if err != nil {
		t.Fatalf("newLegacyRootedAccess() error = %v", err)
	}
	t.Cleanup(func() {
		if err := access.Close(); err != nil {
			t.Errorf("legacyRootAccess.Close() error = %v", err)
		}
	})

	file, err := access.Open("etc/pam.d/system-auth")
	if err != nil {
		t.Fatalf("Open(inside link) error = %v", err)
	}
	data, err := io.ReadAll(file)
	if closeErr := file.Close(); closeErr != nil {
		t.Errorf("Close(inside link) error = %v", closeErr)
	}
	if err != nil || string(data) != "auth required pam_env.so\n" {
		t.Fatalf("ReadAll(inside link) = %q, %v", data, err)
	}
	if _, err := access.Open("etc/escape"); err == nil {
		t.Fatal("Open(escape) succeeded")
	}
	clamped, err := access.Open("etc/clamped")
	if err != nil {
		t.Fatalf("Open(clamped) error = %v", err)
	}
	clampedData, err := io.ReadAll(clamped)
	if closeErr := clamped.Close(); closeErr != nil {
		t.Errorf("Close(clamped) error = %v", closeErr)
	}
	if err != nil || string(clampedData) != "clamped to root\n" {
		t.Fatalf("ReadAll(clamped) = %q, %v", clampedData, err)
	}
}

func TestLegacyRootAccessRejectsProcMagicLink(t *testing.T) {
	access, err := newLegacyRootedAccess("/")
	if err != nil {
		t.Fatalf("newLegacyRootedAccess() error = %v", err)
	}
	t.Cleanup(func() {
		if err := access.Close(); err != nil {
			t.Errorf("legacyRootAccess.Close() error = %v", err)
		}
	})

	probePath := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probePath, []byte("probe\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	file, err := os.Open(probePath)
	if err != nil {
		t.Fatalf("Open(probe) error = %v", err)
	}
	defer file.Close()

	magicPath := fmt.Sprintf("proc/%d/fd/%d", os.Getpid(), file.Fd())
	if _, err := access.Open(magicPath); err == nil {
		t.Fatal("Open(proc magic link) succeeded")
	}

	self, err := access.Stat("proc/self")
	if err != nil {
		t.Fatalf("Stat(proc/self) error = %v", err)
	}
	if !self.IsDir() {
		t.Fatalf("Stat(proc/self) mode = %v, want directory", self.Mode())
	}
	mounts, err := access.Open("proc/mounts")
	if err != nil {
		t.Fatalf("Open(proc/mounts) error = %v", err)
	}
	if closeErr := mounts.Close(); closeErr != nil {
		t.Errorf("Close(proc/mounts) error = %v", closeErr)
	}
}

func TestLegacyRootAccessDoesNotLexicallyCollapseSymlinkTargets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(regular) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte("must not be read\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	if err := os.Symlink("regular/../secret", filepath.Join(root, "dotdot-link")); err != nil {
		t.Fatalf("Symlink(dotdot-link) error = %v", err)
	}
	if err := os.Symlink("regular/", filepath.Join(root, "slash-link")); err != nil {
		t.Fatalf("Symlink(slash-link) error = %v", err)
	}

	access, err := newLegacyRootedAccess(root)
	if err != nil {
		t.Fatalf("newLegacyRootedAccess() error = %v", err)
	}
	t.Cleanup(func() {
		if err := access.Close(); err != nil {
			t.Errorf("legacyRootAccess.Close() error = %v", err)
		}
	})

	if _, err := access.Open("dotdot-link"); err == nil {
		t.Fatal("Open(dotdot-link) collapsed a non-directory path component")
	}
	if _, err := access.Open("slash-link"); err == nil {
		t.Fatal("Open(slash-link) ignored the target's directory requirement")
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
