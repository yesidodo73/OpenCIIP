//go:build linux && openciip_mutation_test

package regularfile

import (
	"context"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestRecipeMetadataTransitionsApplyAndRestoreInTempDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("owner transition validation requires root")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("nobody account is unavailable: %v", err)
	}
	nobodyUID, err := strconv.Atoi(nobody.Uid)
	if err != nil || nobodyUID == 0 {
		t.Fatalf("nobody UID = %q, want a non-root numeric UID", nobody.Uid)
	}

	tests := []struct {
		name        string
		beforeUID   int
		beforeMode  os.FileMode
		desiredMode uint32
	}{
		{name: "owner only", beforeUID: nobodyUID, beforeMode: 0o644, desiredMode: 0o644},
		{name: "mode only", beforeUID: 0, beforeMode: 0o664, desiredMode: 0o644},
		{name: "owner and mode", beforeUID: nobodyUID, beforeMode: 0o666, desiredMode: 0o600},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := setupMetadataMutationFixture(t)
			if err := os.Chown(fixture.physicalPath, test.beforeUID, -1); err != nil {
				t.Fatalf("set fixture owner: %v", err)
			}
			if err := os.Chmod(fixture.physicalPath, test.beforeMode); err != nil {
				t.Fatalf("set fixture mode: %v", err)
			}

			ctx := context.Background()
			resource, err := fixture.handler.Normalize(ctx, fixture.reference)
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			before, err := fixture.handler.Capture(ctx, resource)
			if err != nil {
				t.Fatalf("Capture() error = %v", err)
			}
			if before.File.UID != test.beforeUID || before.File.Mode != uint32(test.beforeMode) {
				t.Fatalf("before owner/mode = %d/%#o, want %d/%#o", before.File.UID, before.File.Mode, test.beforeUID, test.beforeMode)
			}
			desired, err := fixture.handler.BuildDesiredMetadata(ctx, resource, DesiredMetadata{
				UID:            0,
				GID:            before.File.GID,
				Mode:           test.desiredMode,
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
			assertRecipeMatrixState(t, fixture, applied, before, 0, test.desiredMode)

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
				RollbackIntentAt: &now,
			}
			restored, err := fixture.handler.Restore(ctx, operation, artifact)
			if err != nil {
				t.Fatalf("Restore() error = %v", err)
			}
			assertRecipeMatrixState(t, fixture, restored, before, test.beforeUID, uint32(test.beforeMode))
		})
	}
}

func assertRecipeMatrixState(
	t *testing.T,
	fixture metadataMutationFixture,
	snapshot model.ResourceSnapshot,
	identity model.ResourceSnapshot,
	wantUID int,
	wantMode uint32,
) {
	t.Helper()
	assertMutationFixtureState(t, fixture, snapshot, identity, wantMode)
	var stat syscall.Stat_t
	if err := syscall.Stat(fixture.physicalPath, &stat); err != nil {
		t.Fatalf("stat mutation fixture: %v", err)
	}
	if int(stat.Uid) != wantUID || snapshot.File.UID != wantUID {
		t.Fatalf("fixture UID = %d, snapshot UID = %d, want %d", stat.Uid, snapshot.File.UID, wantUID)
	}
}
