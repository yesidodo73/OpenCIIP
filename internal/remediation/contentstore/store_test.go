//go:build linux

package contentstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorePutReadAndDeleteLifecycle(t *testing.T) {
	t.Parallel()

	store, root := newTestStore(t)
	ctx := context.Background()
	content := []byte("planned\ncontent\x00with binary data")

	if err := store.Put(ctx, "run-1", "change-1", "operation-1", content); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	contentPath := filepath.Join(root, "payloads", "run-1", "change-1", "operation-1", "content.bin")
	assertPrivateRegularFile(t, contentPath)
	assertPrivateDirectories(t,
		filepath.Join(root, "payloads"),
		filepath.Join(root, "payloads", "run-1"),
		filepath.Join(root, "payloads", "run-1", "change-1"),
		filepath.Join(root, "payloads", "run-1", "change-1", "operation-1"),
	)
	assertNoTemporaryPayloads(t, filepath.Dir(contentPath))

	got, err := store.Content(ctx, "run-1", "change-1", "operation-1")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("Content() = %q, want %q", got, content)
	}

	if err := store.Put(ctx, "run-1", "change-1", "operation-1", []byte("replacement")); err == nil {
		t.Fatal("second Put() unexpectedly replaced immutable planned content")
	}
	afterDuplicate, err := store.Content(ctx, "run-1", "change-1", "operation-1")
	if err != nil {
		t.Fatalf("Content() after duplicate Put error = %v", err)
	}
	if !bytes.Equal(afterDuplicate, content) {
		t.Fatalf("duplicate Put changed content to %q, want %q", afterDuplicate, content)
	}
	assertNoTemporaryPayloads(t, filepath.Dir(contentPath))

	if err := store.Put(ctx, "run-2", "change-2", "operation-2", []byte("other run")); err != nil {
		t.Fatalf("Put(other run) error = %v", err)
	}
	if err := store.DeleteRunContent(ctx, "run-1"); err != nil {
		t.Fatalf("DeleteRunContent() error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "payloads", "run-1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted run path error = %v, want os.ErrNotExist", err)
	}
	if got, err := store.Content(ctx, "run-2", "change-2", "operation-2"); err != nil || string(got) != "other run" {
		t.Fatalf("other run Content() = %q, error = %v", got, err)
	}

	if err := store.DeleteRunContent(ctx, "run-1"); err != nil {
		t.Fatalf("idempotent DeleteRunContent() error = %v", err)
	}
}

func TestStoreRejectsInvalidIdentifiersWithoutCreatingNamespaces(t *testing.T) {
	t.Parallel()

	store, root := newTestStore(t)
	invalid := []string{
		"",
		".",
		"..",
		"../escape",
		"nested/path",
		`nested\path`,
		"-leading",
		".hidden",
		strings.Repeat("a", 129),
	}
	for _, identifier := range invalid {
		identifier := identifier
		t.Run(identifierName(identifier), func(t *testing.T) {
			t.Parallel()

			if err := store.Put(context.Background(), identifier, "change", "operation", []byte("x")); err == nil {
				t.Fatalf("Put(runID=%q) unexpectedly succeeded", identifier)
			}
			if _, err := store.Content(context.Background(), identifier, "change", "operation"); err == nil {
				t.Fatalf("Content(runID=%q) unexpectedly succeeded", identifier)
			}
			if err := store.DeleteRunContent(context.Background(), identifier); err == nil {
				t.Fatalf("DeleteRunContent(runID=%q) unexpectedly succeeded", identifier)
			}
		})
	}

	entries, err := os.ReadDir(filepath.Join(root, "payloads"))
	if err != nil {
		t.Fatalf("ReadDir(payloads) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid identifiers created payload entries: %v", entryNames(entries))
	}
}

func TestStoreCanceledOperationsHaveNoNewEffect(t *testing.T) {
	t.Parallel()

	store, root := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := store.Put(ctx, "run", "change", "operation", []byte("content")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put(canceled) error = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "payloads", "run")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Put(canceled) run path error = %v, want os.ErrNotExist", err)
	}

	if err := store.Put(context.Background(), "existing", "change", "operation", []byte("content")); err != nil {
		t.Fatalf("Put(existing) error = %v", err)
	}
	if _, err := store.Content(ctx, "existing", "change", "operation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Content(canceled) error = %v, want context.Canceled", err)
	}
	if err := store.DeleteRunContent(ctx, "existing"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DeleteRunContent(canceled) error = %v, want context.Canceled", err)
	}
	if got, err := store.Content(context.Background(), "existing", "change", "operation"); err != nil || string(got) != "content" {
		t.Fatalf("canceled delete changed content to %q, error = %v", got, err)
	}
}

func TestStoreDeleteResumesTombstoneAndRejectsConflictingNamespaces(t *testing.T) {
	t.Parallel()

	t.Run("resume tombstone", func(t *testing.T) {
		t.Parallel()

		store, root := newTestStore(t)
		if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
		payloadRoot := filepath.Join(root, "payloads")
		original := filepath.Join(payloadRoot, "run")
		tombstone := filepath.Join(payloadRoot, ".deleting-run")
		if err := os.Rename(original, tombstone); err != nil {
			t.Fatalf("Rename(tombstone) error = %v", err)
		}

		if err := store.DeleteRunContent(context.Background(), "run"); err != nil {
			t.Fatalf("DeleteRunContent(tombstone) error = %v", err)
		}
		for _, path := range []string{original, tombstone} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("deleted path %s error = %v, want os.ErrNotExist", path, err)
			}
		}
	})

	t.Run("conflicting original and tombstone", func(t *testing.T) {
		t.Parallel()

		store, root := newTestStore(t)
		if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
		payloadRoot := filepath.Join(root, "payloads")
		original := filepath.Join(payloadRoot, "run")
		tombstone := filepath.Join(payloadRoot, ".deleting-run")
		if err := os.Mkdir(tombstone, 0o700); err != nil {
			t.Fatalf("Mkdir(tombstone) error = %v", err)
		}

		if err := store.DeleteRunContent(context.Background(), "run"); err == nil {
			t.Fatal("DeleteRunContent() succeeded with conflicting original and tombstone namespaces")
		}
		for _, path := range []string{original, tombstone} {
			if info, err := os.Lstat(path); err != nil || !info.IsDir() {
				t.Fatalf("conflict path %s info = %v, error = %v; want preserved directory", path, info, err)
			}
		}
	})
}

func TestStoreDeleteDoesNotFollowNestedSymlink(t *testing.T) {
	store, root := newTestStore(t)
	if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile(sentinel) error = %v", err)
	}
	link := filepath.Join(root, "payloads", "run", "change", "operation", "outside")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}

	if err := store.DeleteRunContent(context.Background(), "run"); err != nil {
		t.Fatalf("DeleteRunContent() error = %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "keep" {
		t.Fatalf("outside sentinel = %q, error = %v; delete followed a nested symlink", data, err)
	}
}

func TestStoreRejectsUnsafePayloadObjects(t *testing.T) {
	t.Run("payload root symlink", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(root, "payloads")); err != nil {
			t.Skipf("symbolic links are unavailable: %v", err)
		}
		if store, err := openStore(root, false); err == nil {
			t.Fatalf("openStore() = %#v, want a symlink rejection", store)
		}
	})

	t.Run("content directory in place of file", func(t *testing.T) {
		store, root := newTestStore(t)
		contentPath := filepath.Join(root, "payloads", "run", "change", "operation", "content.bin")
		if err := os.MkdirAll(contentPath, 0o700); err != nil {
			t.Fatalf("MkdirAll(content path) error = %v", err)
		}
		if _, err := store.Content(context.Background(), "run", "change", "operation"); err == nil {
			t.Fatal("Content() accepted a directory in place of the payload file")
		}
		if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err == nil {
			t.Fatal("Put() replaced a directory in place of the payload file")
		}
	})

	t.Run("run deletion symlink", func(t *testing.T) {
		store, root := newTestStore(t)
		outside := t.TempDir()
		sentinel := filepath.Join(outside, "sentinel")
		if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
			t.Fatalf("WriteFile(sentinel) error = %v", err)
		}
		runPath := filepath.Join(root, "payloads", "run")
		if err := os.Symlink(outside, runPath); err != nil {
			t.Skipf("symbolic links are unavailable: %v", err)
		}

		if err := store.DeleteRunContent(context.Background(), "run"); err == nil {
			t.Fatal("DeleteRunContent() accepted a symlinked run namespace")
		}
		data, err := os.ReadFile(sentinel)
		if err != nil || string(data) != "keep" {
			t.Fatalf("outside sentinel = %q, error = %v; delete followed the run symlink", data, err)
		}
	})
}

func TestStoreNilReceiverFailsClosed(t *testing.T) {
	t.Parallel()

	var store *Store
	if err := store.Put(context.Background(), "run", "change", "operation", []byte("content")); err == nil {
		t.Fatal("nil Store.Put() succeeded")
	}
	if _, err := store.Content(context.Background(), "run", "change", "operation"); err == nil {
		t.Fatal("nil Store.Content() succeeded")
	}
	if err := store.DeleteRunContent(context.Background(), "run"); err == nil {
		t.Fatal("nil Store.DeleteRunContent() succeeded")
	}
}

func TestWriteContextStopsBetweenPartialWrites(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	writer := &cancelingWriter{cancel: cancel}
	err := writeContext(ctx, writer, []byte("abcdef"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("writeContext() error = %v, want context.Canceled", err)
	}
	if got := writer.buffer.String(); got != "abc" {
		t.Fatalf("writeContext() wrote %q after cancellation, want only first partial write", got)
	}
}

func TestContextReaderRejectsReadAfterCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &contextReader{ctx: ctx, reader: strings.NewReader("content")}
	buffer := make([]byte, 8)
	count, err := reader.Read(buffer)
	if count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("Read() = (%d, %v), want (0, context.Canceled)", count, err)
	}
}

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod(state root) error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "payloads"), 0o700); err != nil {
		t.Fatalf("Mkdir(payloads) error = %v", err)
	}
	store, err := openStore(root, false)
	if err != nil {
		t.Fatalf("openStore() error = %v", err)
	}
	return store, root
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %v, want single payload regular file mode 0600", path, info.Mode())
	}
}

func assertPrivateDirectories(t *testing.T, paths ...string) {
	t.Helper()

	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("Lstat(%s) error = %v", path, err)
		}
		if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode = %v, want a private directory", path, info.Mode())
		}
	}
}

func assertNoTemporaryPayloads(t *testing.T, directory string) {
	t.Helper()

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", directory, err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".content-") || strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary payload %q remained after operation", entry.Name())
		}
	}
}

func identifierName(value string) string {
	if value == "" {
		return "empty"
	}
	return strings.NewReplacer(
		"/", "_slash_",
		`\`, "_backslash_",
		".", "_dot_",
	).Replace(value)
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

type cancelingWriter struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
	writes int
}

func (w *cancelingWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writes > 1 {
		return 0, io.ErrClosedPipe
	}
	count := len(data) / 2
	if count == 0 {
		count = len(data)
	}
	written, err := w.buffer.Write(data[:count])
	w.cancel()
	return written, err
}
