//go:build linux && openciip_mutation_test

package regularfile

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

// This test mutates only a t.TempDir fixture. Run it explicitly with
// go test -tags=openciip_mutation_test ./internal/remediation/regularfile -run TestApplyAndRestoreMetadataInTempDir
func TestApplyAndRestoreMetadataInTempDir(t *testing.T) {
	fixture := setupMetadataMutationFixture(t)
	ctx := context.Background()
	resource, err := fixture.handler.Normalize(ctx, fixture.reference)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	before, err := fixture.handler.Capture(ctx, resource)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	desired, err := fixture.handler.BuildDesiredMetadata(ctx, resource, DesiredMetadata{
		UID:            before.File.UID,
		GID:            before.File.GID,
		Mode:           before.File.Mode &^ 0o077,
		SELinuxContext: before.File.SELinuxContext,
	})
	if err != nil {
		t.Fatalf("BuildDesiredMetadata() error = %v", err)
	}
	artifact, err := fixture.handler.Backup(ctx, "change-test", "operation-test", resource, before)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	applied, err := fixture.handler.ApplyMetadata(ctx, resource, before, desired)
	if err != nil {
		t.Fatalf("ApplyMetadata() error = %v", err)
	}
	assertMutationFixtureState(t, fixture, applied, before, desired.File.Mode)

	now := time.Now().UTC()
	operation := model.OperationRecord{
		ID:               "operation-test",
		Sequence:         1,
		RollbackSequence: 1,
		Kind:             model.OperationFileMetadata,
		RecoveryMode:     model.RecoveryStateInferable,
		State:            model.OperationApplied,
		Resource:         resource,
		ExpectedBefore:   before,
		Before:           before,
		Desired:          desired,
		ObservedAfter:    &applied,
		Backup:           &artifact,
		ApplyIntentAt:    &now,
		AppliedAt:        &now,
	}
	restored, err := fixture.handler.Restore(ctx, operation, artifact, false)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	assertMutationFixtureState(t, fixture, restored, before, before.File.Mode)
	if restored.Fingerprint != before.Fingerprint {
		t.Fatalf("restored fingerprint = %q, want %q", restored.Fingerprint, before.Fingerprint)
	}
}

type metadataMutationFixture struct {
	handler      *Handler
	reference    model.ResourceRef
	physicalPath string
	content      []byte
}

func setupMetadataMutationFixture(t *testing.T) metadataMutationFixture {
	t.Helper()
	systemRoot := t.TempDir()
	runDirectory := t.TempDir()
	if err := os.Chmod(runDirectory, 0o700); err != nil {
		t.Fatalf("protect run directory: %v", err)
	}
	parent := filepath.Join(systemRoot, "etc")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("create fixture parent: %v", err)
	}
	physicalPath := filepath.Join(parent, "target.conf")
	content := []byte("temporary metadata mutation fixture\n")
	originalMode := os.FileMode(0o640)
	if err := os.WriteFile(physicalPath, content, 0o600); err != nil {
		t.Fatalf("create mutation fixture: %v", err)
	}
	if err := os.Chmod(physicalPath, originalMode); err != nil {
		t.Fatalf("set mutation fixture mode: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(physicalPath, originalMode); err != nil {
			t.Errorf("restore mutation fixture mode during cleanup: %v", err)
		}
	})
	handler, err := New(systemRoot, runDirectory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return metadataMutationFixture{
		handler:      handler,
		reference:    model.ResourceRef{Kind: model.ResourceFile, ID: "/etc/target.conf"},
		physicalPath: physicalPath,
		content:      content,
	}
}

func assertMutationFixtureState(t *testing.T, fixture metadataMutationFixture, snapshot, expectedIdentity model.ResourceSnapshot, expectedMode uint32) {
	t.Helper()
	content, err := os.ReadFile(fixture.physicalPath)
	if err != nil {
		t.Fatalf("read mutation fixture: %v", err)
	}
	if string(content) != string(fixture.content) || snapshot.File.SHA256 == "" {
		t.Fatal("metadata mutation changed the fixture content")
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(fixture.physicalPath, &stat); err != nil {
		t.Fatalf("stat mutation fixture: %v", err)
	}
	if uint32(stat.Mode)&0o7777 != expectedMode || snapshot.File.Mode != expectedMode {
		t.Fatalf("fixture mode = %#o, snapshot mode = %#o, want %#o", uint32(stat.Mode)&0o7777, snapshot.File.Mode, expectedMode)
	}
	if snapshot.File.Device != expectedIdentity.File.Device || snapshot.File.Inode != expectedIdentity.File.Inode || snapshot.File.GID != expectedIdentity.File.GID {
		t.Fatal("metadata mutation changed the approved inode or GID")
	}
	if uint64(stat.Dev) != expectedIdentity.File.Device || stat.Ino != expectedIdentity.File.Inode || int(stat.Gid) != expectedIdentity.File.GID {
		t.Fatal("metadata mutation changed the fixture inode or GID")
	}
}
