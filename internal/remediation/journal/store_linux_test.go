//go:build linux

package journal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLockedTruncatesOnlyAnIncompleteFinalWALRecord(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	approved := testApprovedJournal(t, initial)
	first, err := makeRecord(initial, "")
	if err != nil {
		t.Fatalf("makeRecord(initial) error = %v", err)
	}
	second, err := makeRecord(approved, first.Digest)
	if err != nil {
		t.Fatalf("makeRecord(approved) error = %v", err)
	}

	root := t.TempDir()
	runDirectory := filepath.Join(root, initial.RunID)
	if err := os.Mkdir(runDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir(run directory) error = %v", err)
	}
	walPath := filepath.Join(runDirectory, walFileName)
	if err := writeInitialWAL(walPath, first); err != nil {
		t.Fatalf("writeInitialWAL() error = %v", err)
	}
	if committed, err := appendWAL(walPath, second); err != nil || !committed {
		t.Fatalf("appendWAL() committed=%t error=%v, want committed record", committed, err)
	}
	validInfo, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat(valid WAL) error = %v", err)
	}

	file, err := openPrivateRegular(walPath, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatalf("openPrivateRegular() error = %v", err)
	}
	if _, err := file.Write([]byte(`{"schema_version":1,"revision":`)); err != nil {
		_ = file.Close()
		t.Fatalf("append incomplete record error = %v", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("sync incomplete record error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close incomplete record error = %v", err)
	}

	store := newStoreAt(root)
	incompleteInfo, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat(incomplete WAL) error = %v", err)
	}
	inspection, err := store.Inspect(context.Background(), initial.RunID)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !inspection.IncompleteWALTail || inspection.Journal == nil || inspection.Journal.Revision != approved.Revision {
		t.Fatalf("Inspect() = %#v, want latest complete revision plus incomplete-tail marker", inspection)
	}
	afterInspection, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat(WAL after inspection) error = %v", err)
	}
	if afterInspection.Size() != incompleteInfo.Size() {
		t.Fatalf("read-only inspection changed WAL size from %d to %d", incompleteInfo.Size(), afterInspection.Size())
	}

	loaded, err := store.loadLocked(context.Background(), initial.RunID)
	if err != nil {
		t.Fatalf("loadLocked() error = %v", err)
	}
	if loaded.journal.Revision != approved.Revision || loaded.digest != second.Digest {
		t.Fatalf("loaded revision=%d digest=%q, want revision=%d digest=%q", loaded.journal.Revision, loaded.digest, approved.Revision, second.Digest)
	}
	afterInfo, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat(recovered WAL) error = %v", err)
	}
	if afterInfo.Size() != validInfo.Size() {
		t.Fatalf("recovered WAL size = %d, want last valid boundary %d", afterInfo.Size(), validInfo.Size())
	}

	record, _, incomplete, err := readWAL(context.Background(), walPath, initial.RunID)
	if err != nil {
		t.Fatalf("readWAL(recovered) error = %v", err)
	}
	if incomplete || record.Revision != approved.Revision {
		t.Fatalf("recovered WAL incomplete=%t revision=%d, want complete revision %d", incomplete, record.Revision, approved.Revision)
	}
}

func TestLoadLockedRejectsCompleteTamperedRecordWithoutTruncation(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	approved := testApprovedJournal(t, initial)
	first, err := makeRecord(initial, "")
	if err != nil {
		t.Fatalf("makeRecord(initial) error = %v", err)
	}
	second, err := makeRecord(approved, first.Digest)
	if err != nil {
		t.Fatalf("makeRecord(approved) error = %v", err)
	}
	second.Journal.Warnings = []string{"tampered after digest creation"}

	root := t.TempDir()
	runDirectory := filepath.Join(root, initial.RunID)
	if err := os.Mkdir(runDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir(run directory) error = %v", err)
	}
	walPath := filepath.Join(runDirectory, walFileName)
	if err := writeInitialWAL(walPath, first); err != nil {
		t.Fatalf("writeInitialWAL() error = %v", err)
	}
	if committed, err := appendWAL(walPath, second); err != nil || !committed {
		t.Fatalf("appendWAL(tampered) committed=%t error=%v, want bytes durably written for recovery test", committed, err)
	}
	before, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat(tampered WAL) error = %v", err)
	}

	store := newStoreAt(root)
	_, err = store.loadLocked(context.Background(), initial.RunID)
	if CodeOf(err) != CodeCorruptWAL {
		t.Fatalf("loadLocked() error = %v, want %s", err, CodeCorruptWAL)
	}
	after, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Stat(WAL after rejection) error = %v", err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("corrupt complete record changed WAL size from %d to %d", before.Size(), after.Size())
	}
}
