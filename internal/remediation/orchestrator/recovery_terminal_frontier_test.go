package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestRecoverIncompleteRollbackRevalidatesEveryObservedResourceBeforeSuccess(t *testing.T) {
	value := faultInterruptedRollbackFrontierJournal(t, false)
	harness, manager, runtime := newRecoveryFrontierDriftFixture(t, value)

	assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("Recover() error = %v, want %s", err, CodeRecoveryRequired)
	}
	assertCommittedRecoveryError(t, err)
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a", "change-b/operation-b"}) {
		t.Fatalf("ConfirmedRolledBack = %v", assessment.ConfirmedRolledBack)
	}
	if !runtime.drifted {
		t.Fatal("second initial capture did not drift the first observed resource")
	}
	if harness.state.State != model.RunRollingBack {
		t.Fatalf("durable run state = %s, want %s", harness.state.State, model.RunRollingBack)
	}
	if len(harness.state.RollbackAttempts) != 1 ||
		harness.state.RollbackAttempts[0].CompletedAt != nil ||
		harness.state.RollbackAttempts[0].Outcome != "" {
		t.Fatalf("stale recovery success was persisted: %#v", harness.state.RollbackAttempts)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("incomplete recovery journal Validate() error = %v", err)
	}
}

func TestRecoverCompletedRollbackTransitionRevalidatesFrontierBeforeTerminalState(t *testing.T) {
	value := faultInterruptedRollbackFrontierJournal(t, true)
	historical := value.RollbackAttempts[0]
	harness, manager, runtime := newRecoveryFrontierDriftFixture(t, value)

	assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("Recover() error = %v, want %s", err, CodeRecoveryRequired)
	}
	assertCommittedRecoveryError(t, err)
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a", "change-b/operation-b"}) {
		t.Fatalf("ConfirmedRolledBack = %v", assessment.ConfirmedRolledBack)
	}
	if !runtime.drifted {
		t.Fatal("second initial capture did not drift the first observed resource")
	}
	if harness.state.State != model.RunRollingBack {
		t.Fatalf("durable run state = %s, want %s", harness.state.State, model.RunRollingBack)
	}
	if len(harness.state.RollbackAttempts) != 1 || !rollbackAttemptEqual(harness.state.RollbackAttempts[0], historical) {
		t.Fatalf("completed historical attempt changed: %#v", harness.state.RollbackAttempts)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("completed-transition recovery journal Validate() error = %v", err)
	}
}

func TestRecoverResolvedCrashRollbackRevalidatesFrontierBeforeRecordingSuccess(t *testing.T) {
	value := faultResolvedCrashRollbackJournal(t)
	historical := value.RollbackAttempts[0]
	harness := newFaultStoreHarness(t, value)
	operation := value.ChangeSets[0].Operations[0]
	live := faultCloneSnapshot(operation.Before)
	drifted := false
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			current := faultCloneSnapshot(live)
			if !drifted {
				drifted = true
				live.Fingerprint = strings.Repeat("f", 64)
				live.File.Inode++
			}
			return current, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() repeated a resolved rollback")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"must-not-be-consumed"})

	assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("Recover() error = %v, want %s", err, CodeRecoveryRequired)
	}
	assertCommittedRecoveryError(t, err)
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedRolledBack = %v", assessment.ConfirmedRolledBack)
	}
	if harness.state.State != model.RunRollbackFailed {
		t.Fatalf("durable run state = %s, want %s", harness.state.State, model.RunRollbackFailed)
	}
	if len(harness.state.RollbackAttempts) != 1 || !rollbackAttemptEqual(harness.state.RollbackAttempts[0], historical) {
		t.Fatalf("recovery recorded stale success history: %#v", harness.state.RollbackAttempts)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("resolved-crash recovery journal Validate() error = %v", err)
	}
}

func TestRecoverResolvedCrashRollbackRevalidatesAgainBeforeTerminalUpdate(t *testing.T) {
	value := faultResolvedCrashRollbackJournal(t)
	harness := newFaultStoreHarness(t, value)
	operation := value.ChangeSets[0].Operations[0]
	live := faultCloneSnapshot(operation.Before)
	injected := false
	harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if !injected &&
			len(harness.state.RollbackAttempts) == 1 &&
			len(candidate.RollbackAttempts) == 2 {
			injected = true
			live.Fingerprint = strings.Repeat("f", 64)
			live.File.Inode++
		}
		return nil
	}
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			return faultCloneSnapshot(live), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() repeated a resolved rollback")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"resolved-second-boundary"})

	assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("Recover() error = %v, want %s", err, CodeRecoveryRequired)
	}
	assertCommittedRecoveryError(t, err)
	if !injected {
		t.Fatal("test did not drift the resource after recording the resolved attempt")
	}
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedRolledBack = %v", assessment.ConfirmedRolledBack)
	}
	if harness.state.State != model.RunRollingBack {
		t.Fatalf("durable run state = %s, want %s", harness.state.State, model.RunRollingBack)
	}
	if len(harness.state.RollbackAttempts) != 2 {
		t.Fatalf("rollback attempts = %d, want historical and recorded recovery attempts", len(harness.state.RollbackAttempts))
	}
	recoveryAttempt := harness.state.RollbackAttempts[1]
	if recoveryAttempt.Outcome != model.RollbackSucceeded || recoveryAttempt.CompletedAt == nil {
		t.Fatalf("recorded recovery attempt = %#v", recoveryAttempt)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("pre-terminal resolved-crash journal Validate() error = %v", err)
	}
}

type recoveryFrontierDriftRuntime struct {
	*scriptedFileRuntime
	live          map[string]model.ResourceSnapshot
	firstObserved string
	drifted       bool
}

func newRecoveryFrontierDriftFixture(
	t *testing.T,
	value *model.RemediationJournal,
) (*faultStoreHarness, *Manager, *recoveryFrontierDriftRuntime) {
	t.Helper()
	harness := newFaultStoreHarness(t, value)
	fixture := &recoveryFrontierDriftRuntime{
		live: make(map[string]model.ResourceSnapshot, len(value.ChangeSets)),
	}
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		fixture.live[operation.Resource.Key] = faultCloneSnapshot(operation.Before)
	}
	fixture.scriptedFileRuntime = &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := fixture.live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			result := faultCloneSnapshot(current)
			if fixture.firstObserved == "" {
				fixture.firstObserved = resource.Key
			} else if !fixture.drifted && resource.Key != fixture.firstObserved {
				drift := faultCloneSnapshot(fixture.live[fixture.firstObserved])
				drift.Fingerprint = strings.Repeat("f", 64)
				drift.File.Inode++
				fixture.live[fixture.firstObserved] = drift
				fixture.drifted = true
			}
			return result, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() performed a live restore")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, fixture.scriptedFileRuntime, []string{"recovery-frontier"})
	return harness, manager, fixture
}

func assertCommittedRecoveryError(t *testing.T, err error) {
	t.Helper()
	var orchestrationError *Error
	if !errors.As(err, &orchestrationError) || !orchestrationError.Committed {
		t.Fatalf("recovery error = %#v, want Committed=true", orchestrationError)
	}
}

func faultInterruptedRollbackFrontierJournal(t *testing.T, completed bool) *model.RemediationJournal {
	t.Helper()
	value := faultVerifiedJournal(t, 2, false, model.FailureRollbackRun, model.RunRollingBack)
	attemptStartedAt := faultBaseTime().Add(6 * time.Minute)
	latest := attemptStartedAt
	for index := range value.ChangeSets {
		changeSet := &value.ChangeSets[index]
		operation := &changeSet.Operations[0]
		intentAt := attemptStartedAt.Add(time.Minute + time.Duration(index)*time.Nanosecond)
		operation.State = model.OperationRollbackIntentDurable
		operation.RollbackIntentAt = &intentAt
		changeSet.State = model.ChangeRollingBack
		latest = intentAt
		if completed {
			rolledBackAt := attemptStartedAt.Add(2*time.Minute + time.Duration(index)*time.Nanosecond)
			observed := faultCloneSnapshot(operation.Before)
			observed.File.CapturedAt = rolledBackAt
			operation.State = model.OperationRolledBack
			operation.ObservedRollback = &observed
			operation.RolledBackAt = &rolledBackAt
			changeSet.State = model.ChangeRolledBack
			changeSet.RolledBackAt = &rolledBackAt
			latest = rolledBackAt
		}
	}
	attempt := model.RollbackAttempt{
		ID:                 "rollback-frontier",
		Scope:              model.RollbackRun,
		Trigger:            model.RollbackUserRequest,
		ExpandedChangeSets: []string{"change-b", "change-a"},
		CascadeApproved:    true,
		StartedAt:          attemptStartedAt,
	}
	if completed {
		completedAt := latest.Add(time.Minute)
		attempt.Outcome = model.RollbackSucceeded
		attempt.CompletedAt = &completedAt
		latest = completedAt
	}
	value.RollbackAttempts = []model.RollbackAttempt{attempt}
	value.UnresolvedChangeSets = nil
	value.UpdatedAt = latest.Add(time.Minute)
	faultSealJournal(t, value)
	return value
}
