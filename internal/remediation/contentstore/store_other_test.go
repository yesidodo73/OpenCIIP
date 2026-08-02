//go:build !linux

package contentstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestValidateIdentifiersRejectsTraversalAndNonCanonicalValues(t *testing.T) {
	t.Parallel()

	valid := []string{
		"a",
		"run-1",
		"change_set.1",
		strings.Repeat("a", 128),
	}
	for _, value := range valid {
		if err := validateIdentifiers(value); err != nil {
			t.Errorf("validateIdentifiers(%q) error = %v", value, err)
		}
	}
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
	for _, value := range invalid {
		if err := validateIdentifiers(value); err == nil {
			t.Errorf("validateIdentifiers(%q) unexpectedly succeeded", value)
		}
	}
}

func TestStoreNilReceiverFailsClosedOnNonLinux(t *testing.T) {
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

func TestWriteContextStopsBetweenPartialWritesOnNonLinux(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	writer := &nonLinuxCancelingWriter{cancel: cancel}
	err := writeContext(ctx, writer, []byte("abcdef"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("writeContext() error = %v, want context.Canceled", err)
	}
	if got := writer.buffer.String(); got != "abc" {
		t.Fatalf("writeContext() wrote %q after cancellation, want only first partial write", got)
	}
}

func TestContextReaderRejectsReadAfterCancellationOnNonLinux(t *testing.T) {
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

type nonLinuxCancelingWriter struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
	writes int
}

func (w *nonLinuxCancelingWriter) Write(data []byte) (int, error) {
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
