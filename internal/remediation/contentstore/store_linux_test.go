//go:build linux

package contentstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStoreRejectsNonPrivatePayloadAndNamespaceModes(t *testing.T) {
	t.Run("payload content mode", func(t *testing.T) {
		store, root := newTestStore(t)
		if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
		contentPath := filepath.Join(root, "payloads", "run", "change", "operation", "content.bin")
		if err := os.Chmod(contentPath, 0o644); err != nil {
			t.Fatalf("Chmod(content) error = %v", err)
		}
		if _, err := store.Content(context.Background(), "run", "change", "operation"); err == nil {
			t.Fatal("Content() accepted group/other-readable payload content")
		}
	})

	t.Run("existing namespace mode", func(t *testing.T) {
		store, root := newTestStore(t)
		runPath := filepath.Join(root, "payloads", "run")
		if err := os.Mkdir(runPath, 0o755); err != nil {
			t.Fatalf("Mkdir(run) error = %v", err)
		}
		if err := os.Chmod(runPath, 0o755); err != nil {
			t.Fatalf("Chmod(run) error = %v", err)
		}
		if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err == nil {
			t.Fatal("Put() accepted an existing non-private run namespace")
		}
		if _, err := os.Lstat(filepath.Join(runPath, "change", "operation", "content.bin")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe namespace gained content with error %v, want os.ErrNotExist", err)
		}
	})

	t.Run("deletion namespace mode", func(t *testing.T) {
		store, root := newTestStore(t)
		if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
		runPath := filepath.Join(root, "payloads", "run")
		if err := os.Chmod(runPath, 0o755); err != nil {
			t.Fatalf("Chmod(run) error = %v", err)
		}
		if err := store.DeleteRunContent(context.Background(), "run"); err == nil {
			t.Fatal("DeleteRunContent() accepted a non-private run namespace")
		}
		if _, err := os.Lstat(runPath); err != nil {
			t.Fatalf("DeleteRunContent() removed unsafe namespace: %v", err)
		}
	})
}

func TestStorePayloadIsOwnedByEffectiveUserAndSingleLink(t *testing.T) {
	t.Parallel()

	store, root := newTestStore(t)
	if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	contentPath := filepath.Join(root, "payloads", "run", "change", "operation", "content.bin")
	info, err := os.Lstat(contentPath)
	if err != nil {
		t.Fatalf("Lstat(content) error = %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("payload ownership is unavailable")
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		t.Fatalf("payload uid=%d nlink=%d, want uid=%d nlink=1", stat.Uid, stat.Nlink, os.Geteuid())
	}
}

func TestStoreContentRejectsSymlinkReplacement(t *testing.T) {
	t.Parallel()

	store, root := newTestStore(t)
	if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	contentPath := filepath.Join(root, "payloads", "run", "change", "operation", "content.bin")
	if err := os.Remove(contentPath); err != nil {
		t.Fatalf("Remove(content) error = %v", err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside) error = %v", err)
	}
	if err := os.Symlink(outside, contentPath); err != nil {
		t.Fatalf("Symlink(content) error = %v", err)
	}
	if _, err := store.Content(context.Background(), "run", "change", "operation"); err == nil {
		t.Fatal("Content() followed a symlink replacement")
	}
}

func TestNewAndOpenExistingOnVerifiedStateRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("verified content-store integration requires the same root context as automatic remediation")
	}
	parent := os.Getenv("OPENCIIP_TEST_TRUSTED_STATE_PARENT")
	if parent == "" {
		t.Skip("set OPENCIIP_TEST_TRUSTED_STATE_PARENT to an existing trusted directory on a supported host filesystem")
	}
	root, err := os.MkdirTemp(filepath.Clean(parent), "openciip-contentstore-test-")
	if err != nil {
		t.Fatalf("MkdirTemp(trusted parent) error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("RemoveAll(test content store) error = %v", err)
		}
	})

	store, err := New(root)
	if err != nil {
		t.Fatalf("New(%s) error = %v", root, err)
	}
	if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	reopened, err := OpenExisting(root)
	if err != nil {
		t.Fatalf("OpenExisting(%s) error = %v", root, err)
	}
	got, err := reopened.Content(context.Background(), "run", "change", "operation")
	if err != nil || string(got) != "content" {
		t.Fatalf("Content() = %q, error = %v", got, err)
	}
	if err := reopened.DeleteRunContent(context.Background(), "run"); err != nil {
		t.Fatalf("DeleteRunContent() error = %v", err)
	}
}
