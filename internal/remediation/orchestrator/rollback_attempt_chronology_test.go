package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestBlockedRollbackAttemptCompletesAfterItsErrors(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	drift := faultCloneSnapshot(fixture.after)
	drift.Fingerprint = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	drift.File.Inode++
	fixture.live = drift

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRecoveryRequired)
	}
	assertRollbackAttemptChronology(t, fixture.harness.state.RollbackAttempts)
}

func TestFailedRollbackAttemptCompletesAfterItsErrors(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	restoreErr := errors.New("restore failed before changing the target")
	fixture.runtime.restore = func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
		return faultCloneSnapshot(fixture.after), restoreErr
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRollbackFailed {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRollbackFailed)
	}
	assertRollbackAttemptChronology(t, fixture.harness.state.RollbackAttempts)
}

func TestNoEffectRecoveryAttemptCompletesAfterItsError(t *testing.T) {
	value := faultNoEffectRollbackAttemptJournal(t)
	harness := newFaultStoreHarness(t, value)
	operation := value.ChangeSets[0].Operations[0]
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			return faultCloneSnapshot(operation.Before), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() restored a durable no-effect operation")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, nil)

	if _, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild()); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if harness.state.State != model.RunFailed {
		t.Fatalf("recovered run state = %s, want %s", harness.state.State, model.RunFailed)
	}
	assertRollbackAttemptChronology(t, harness.state.RollbackAttempts)
}

func TestResolvedCrashRollbackAttemptDoesNotOverlapHistory(t *testing.T) {
	value := faultResolvedCrashRollbackJournal(t)
	historical := value.RollbackAttempts[0]
	harness := newFaultStoreHarness(t, value)
	operation := value.ChangeSets[0].Operations[0]
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			return faultCloneSnapshot(operation.Before), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() repeated a resolved rollback")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"resolved"})

	if _, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild()); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if harness.state.State != model.RunRolledBack {
		t.Fatalf("recovered run state = %s, want %s", harness.state.State, model.RunRolledBack)
	}
	if len(harness.state.RollbackAttempts) != 2 {
		t.Fatalf("rollback attempts = %d, want immutable history and resolved crash attempt", len(harness.state.RollbackAttempts))
	}
	if !rollbackAttemptEqual(harness.state.RollbackAttempts[0], historical) {
		t.Fatal("Recover() changed completed historical rollback attempt")
	}
	assertRollbackAttemptChronology(t, harness.state.RollbackAttempts)
}

func assertRollbackAttemptChronology(t *testing.T, attempts []model.RollbackAttempt) {
	t.Helper()
	if len(attempts) == 0 {
		t.Fatal("rollback attempt history is empty")
	}
	for index, attempt := range attempts {
		if attempt.CompletedAt == nil {
			t.Fatalf("rollback attempt %s is incomplete", attempt.ID)
		}
		for _, journalError := range attempt.Errors {
			if journalError.OccurredAt.After(*attempt.CompletedAt) {
				t.Fatalf(
					"rollback attempt %s completed at %s before error at %s",
					attempt.ID,
					attempt.CompletedAt,
					journalError.OccurredAt,
				)
			}
		}
		if index > 0 {
			previous := attempts[index-1]
			if previous.CompletedAt == nil {
				t.Fatalf("rollback attempt %s follows incomplete attempt %s", attempt.ID, previous.ID)
			}
			if attempt.StartedAt.Before(*previous.CompletedAt) {
				t.Fatalf(
					"rollback attempt %s started at %s before previous attempt %s completed at %s",
					attempt.ID,
					attempt.StartedAt,
					previous.ID,
					previous.CompletedAt,
				)
			}
		}
	}
}

func faultNoEffectRollbackAttemptJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := recoverApplyIntentJournal(t)
	changeSet := &value.ChangeSets[0]
	operation := &changeSet.Operations[0]
	noEffectAt := faultBaseTime().Add(4 * time.Minute)
	observed := faultCloneSnapshot(operation.Before)
	observed.File.CapturedAt = noEffectAt
	operation.State = model.OperationFailed
	operation.ObservedAfter = &observed
	operationError := model.JournalError{
		Code:        model.JournalErrorApplyFailed,
		Phase:       "recover_no_effect",
		ChangeSetID: changeSet.ID,
		OperationID: operation.ID,
		Resource:    operationResource(*operation),
		Message:     "apply_failed during recover_no_effect",
		OccurredAt:  noEffectAt,
	}
	operation.Error = &operationError
	changeSet.State = model.ChangeApplyFailed
	changeSet.Error = &operationError
	attemptStartedAt := noEffectAt.Add(time.Minute)
	value.State = model.RunRollingBack
	value.RollbackAttempts = []model.RollbackAttempt{{
		ID:                  "rollback-no-effect",
		Scope:               model.RollbackItem,
		Trigger:             model.RollbackCrashRecovery,
		RequestedChangeSets: []string{changeSet.ID},
		ExpandedChangeSets:  []string{changeSet.ID},
		StartedAt:           attemptStartedAt,
	}}
	value.UpdatedAt = attemptStartedAt.Add(time.Minute)
	faultSealJournal(t, value)
	return value
}

func faultResolvedCrashRollbackJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	changeSet := &value.ChangeSets[0]
	operation := &changeSet.Operations[0]
	attemptStartedAt := faultBaseTime().Add(6 * time.Minute)
	rollbackIntentAt := attemptStartedAt.Add(time.Minute)
	rolledBackAt := rollbackIntentAt.Add(time.Minute)
	attemptCompletedAt := rolledBackAt.Add(time.Minute)
	operation.State = model.OperationRolledBack
	operation.RollbackIntentAt = &rollbackIntentAt
	observed := faultCloneSnapshot(operation.Before)
	observed.File.CapturedAt = rolledBackAt
	operation.ObservedRollback = &observed
	operation.RolledBackAt = &rolledBackAt
	changeSet.State = model.ChangeRolledBack
	changeSet.RolledBackAt = &rolledBackAt
	value.State = model.RunRollbackFailed
	value.UnresolvedChangeSets = nil
	value.RollbackAttempts = []model.RollbackAttempt{{
		ID:                  "rollback-failed-history",
		Scope:               model.RollbackItem,
		Trigger:             model.RollbackUserRequest,
		RequestedChangeSets: []string{changeSet.ID},
		ExpandedChangeSets:  []string{changeSet.ID},
		Outcome:             model.RollbackFailed,
		StartedAt:           attemptStartedAt,
		CompletedAt:         &attemptCompletedAt,
	}}
	value.UpdatedAt = attemptCompletedAt.Add(time.Minute)
	faultSealJournal(t, value)
	if err := value.Validate(); err != nil {
		t.Fatalf("resolved crash fixture Validate() error = %v", err)
	}
	return value
}
