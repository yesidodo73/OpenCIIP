package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestApplyPreparationFailureRevalidatesRetainedWriterBeforeRunFailed(t *testing.T) {
	fixture := newRetainedWriterApplyFixture(t)
	capturesBeforeReject := 0
	terminalRejected := false
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if !terminalRejected &&
			fixture.harness.state.State == model.RunApplying &&
			candidate.State == model.RunFailed {
			capturesBeforeReject = fixture.retainedCaptures
			drift := faultCloneSnapshot(fixture.live[fixture.retainedKey])
			drift.Fingerprint = strings.Repeat("f", 64)
			drift.File.Inode++
			fixture.live[fixture.retainedKey] = drift
			terminalRejected = true
			return errors.New("injected RunFailed persistence rejection after frontier verification")
		}
		return nil
	}

	err := fixture.apply()
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf(
			"ApplyWithVerifier() error = %v, want %s; state=%s change states=%s/%s captures=%v retained=%s",
			err,
			CodeRecoveryRequired,
			fixture.harness.state.State,
			fixture.harness.state.ChangeSets[0].State,
			fixture.harness.state.ChangeSets[1].State,
			fixture.runtime.captureCalls,
			fixture.live[fixture.retainedKey].Fingerprint,
		)
	}
	if !terminalRejected || capturesBeforeReject == 0 || fixture.retainedCaptures <= capturesBeforeReject {
		t.Fatalf(
			"terminal rejection/captures = %t/%d/%d, want rejected terminal followed by retained-writer revalidation",
			terminalRejected,
			capturesBeforeReject,
			fixture.retainedCaptures,
		)
	}
	assertRetainedWriterRequiresRecovery(t, fixture.harness.state)
	if fixture.harness.state.ChangeSets[1].State != model.ChangeApplyFailed {
		t.Fatalf("failed change set state = %s, want %s", fixture.harness.state.ChangeSets[1].State, model.ChangeApplyFailed)
	}
}

func TestApplyPreparationFailureRecognizesCommittedRunFailedRevision(t *testing.T) {
	fixture := newRetainedWriterApplyFixture(t)
	commitErrors := 0
	capturesAtCommit := 0
	installCommitThenErrorUpdate(t, fixture.harness, func(previous, candidate *model.RemediationJournal) bool {
		committed := previous.State == model.RunApplying &&
			candidate.State == model.RunFailed &&
			candidate.ChangeSets[0].State == model.ChangeVerified &&
			candidate.ChangeSets[1].State == model.ChangeApplyFailed
		if committed {
			commitErrors++
			capturesAtCommit = fixture.retainedCaptures
		}
		return committed
	}, errors.New("injected RunFailed snapshot failure after WAL commit"))

	err := fixture.apply()
	if CodeOf(err) != CodePreconditionFailed {
		t.Fatalf("ApplyWithVerifier() error = %v, want original %s cause", err, CodePreconditionFailed)
	}
	if commitErrors != 1 {
		t.Fatalf("committed RunFailed errors = %d, want 1", commitErrors)
	}
	if fixture.retainedCaptures != capturesAtCommit {
		t.Fatalf(
			"retained captures after committed terminal = %d, want unchanged %d",
			fixture.retainedCaptures,
			capturesAtCommit,
		)
	}
	if fixture.harness.state.State != model.RunFailed {
		t.Fatalf("durable run state = %s, want %s", fixture.harness.state.State, model.RunFailed)
	}
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("committed RunFailed journal Validate() error = %v", err)
	}
}

type retainedWriterApplyFixture struct {
	value            *model.RemediationJournal
	harness          *faultStoreHarness
	live             map[string]model.ResourceSnapshot
	runtime          *scriptedFileRuntime
	manager          *Manager
	retainedKey      string
	failingKey       string
	retainedCaptures int
}

func newRetainedWriterApplyFixture(t *testing.T) *retainedWriterApplyFixture {
	t.Helper()

	value := faultJournalSkeleton(2, false)
	value.State = model.RunApproved
	value.FailurePolicy = model.FailureRollbackItem
	faultSealJournal(t, value)

	fixture := &retainedWriterApplyFixture{
		value:       value,
		harness:     newFaultStoreHarness(t, value),
		live:        make(map[string]model.ResourceSnapshot, len(value.ChangeSets)),
		retainedKey: value.ChangeSets[0].Operations[0].Resource.Key,
		failingKey:  value.ChangeSets[1].Operations[0].Resource.Key,
	}
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		fixture.live[operation.Resource.Key] = faultCloneSnapshot(operation.ExpectedBefore)
	}
	fixture.runtime = &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			if resource.Key == fixture.failingKey {
				failedPrecondition := faultCloneSnapshot(fixture.live[fixture.failingKey])
				failedPrecondition.Fingerprint = strings.Repeat("e", 64)
				failedPrecondition.File.Inode++
				return failedPrecondition, nil
			}
			if resource.Key == fixture.retainedKey {
				fixture.retainedCaptures++
			}
			current, exists := fixture.live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			return faultCloneSnapshot(current), nil
		},
		backup: func(
			_ context.Context,
			_ string,
			operationID string,
			_ model.CanonicalResource,
			_ model.ResourceSnapshot,
		) (model.BackupArtifact, error) {
			return faultBackup("backup-" + operationID), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		applyMetadata: func(
			_ context.Context,
			resource model.CanonicalResource,
			before model.ResourceSnapshot,
			desired model.ResourceSnapshot,
		) (model.ResourceSnapshot, error) {
			current := fixture.live[resource.Key]
			if !exactEqual(before, current) {
				return model.ResourceSnapshot{}, fmt.Errorf("resource %s changed before apply", resource.Key)
			}
			fixture.live[resource.Key] = faultCloneSnapshot(desired)
			return faultCloneSnapshot(desired), nil
		},
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("ApplyWithVerifier() restored a retained item-policy writer")
			return model.ResourceSnapshot{}, nil
		},
	}
	fixture.manager = newFaultManager(t, fixture.harness, fixture.runtime, nil)
	return fixture
}

func (f *retainedWriterApplyFixture) apply() error {
	return f.manager.ApplyWithVerifier(
		context.Background(),
		f.value.RunID,
		func(context.Context, *model.RemediationJournal) error { return nil },
		func(context.Context, *model.RemediationJournal, string, string) error { return nil },
		func(context.Context, *model.RemediationJournal, []string) ([]string, error) { return nil, nil },
	)
}

func TestRecoverStableInterruptedApplyRevalidatesRetainedWriterBeforeRunFailed(t *testing.T) {
	value := faultRetainedWriterNoEffectJournal(t, false)
	assertRecoverRetainedWriterDrift(t, value, false)
}

func TestRecoverNoEffectRollbackAttemptRevalidatesRetainedWriterBeforeRunFailed(t *testing.T) {
	value := faultRetainedWriterNoEffectJournal(t, true)
	assertRecoverRetainedWriterDrift(t, value, true)
}

func TestRecoverNoEffectAttemptRevalidatesRetainedRolledBackWriterBeforeRunFailed(t *testing.T) {
	assertRecoverRetainedRolledBackWriterDrift(t, false)
}

func TestRecoverNoEffectAttemptRevalidatesRetainedRolledBackWriterAfterRejectedTerminal(t *testing.T) {
	assertRecoverRetainedRolledBackWriterDrift(t, true)
}

func assertRecoverRetainedRolledBackWriterDrift(t *testing.T, driftAtTerminalBoundary bool) {
	t.Helper()

	value := faultRetainedRolledBackNoEffectJournal(t)
	historical := value.RollbackAttempts[0]
	harness := newFaultStoreHarness(t, value)
	retained := value.ChangeSets[0].Operations[0]
	noEffect := value.ChangeSets[1].Operations[0]
	live := map[string]model.ResourceSnapshot{
		retained.Resource.Key: faultCloneSnapshot(retained.Before),
		noEffect.Resource.Key: faultCloneSnapshot(noEffect.Before),
	}
	retainedCaptures := 0
	capturesBeforeReject := 0
	terminalRejected := false
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			if resource.Key == noEffect.Resource.Key {
				t.Fatal("Recover() captured a durable no-effect writer")
			}
			result := faultCloneSnapshot(current)
			retainedCaptures++
			if !driftAtTerminalBoundary && retainedCaptures == 1 {
				drift := faultCloneSnapshot(current)
				drift.Fingerprint = strings.Repeat("f", 64)
				drift.File.Inode++
				live[resource.Key] = drift
			}
			return result, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() restored a retained rolled-back writer")
			return model.ResourceSnapshot{}, nil
		},
	}
	if driftAtTerminalBoundary {
		harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
			if !terminalRejected && candidate.State == model.RunFailed {
				capturesBeforeReject = retainedCaptures
				drift := faultCloneSnapshot(live[retained.Resource.Key])
				drift.Fingerprint = strings.Repeat("f", 64)
				drift.File.Inode++
				live[retained.Resource.Key] = drift
				terminalRejected = true
				return errors.New("injected rolled-back frontier drift after rejected RunFailed persistence")
			}
			return nil
		}
	}
	manager := newFaultManager(t, harness, runtime, nil)

	_, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("Recover() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if driftAtTerminalBoundary {
		if !terminalRejected || capturesBeforeReject < 2 || retainedCaptures <= capturesBeforeReject {
			t.Fatalf(
				"terminal rejection/captures = %t/%d/%d, want rejected terminal followed by rolled-back frontier revalidation",
				terminalRejected,
				capturesBeforeReject,
				retainedCaptures,
			)
		}
	} else if retainedCaptures < 2 {
		t.Fatalf("retained rolled-back captures = %d, want initial observation and terminal precheck", retainedCaptures)
	}
	assertRetainedWriterRequiresRecovery(t, harness.state)
	if harness.state.ChangeSets[1].State != model.ChangeApplyFailed {
		t.Fatalf("no-effect change set state = %s, want %s", harness.state.ChangeSets[1].State, model.ChangeApplyFailed)
	}
	if len(harness.state.RollbackAttempts) != 2 ||
		!rollbackAttemptEqual(harness.state.RollbackAttempts[0], historical) ||
		harness.state.RollbackAttempts[1].CompletedAt != nil ||
		harness.state.RollbackAttempts[1].Outcome != "" {
		t.Fatalf("rollback attempt history changed after retained drift: %#v", harness.state.RollbackAttempts)
	}
}

func assertRecoverRetainedWriterDrift(
	t *testing.T,
	value *model.RemediationJournal,
	wantIncompleteAttempt bool,
) {
	t.Helper()

	harness := newFaultStoreHarness(t, value)
	retained := value.ChangeSets[0].Operations[0]
	noEffect := value.ChangeSets[1].Operations[0]
	live := map[string]model.ResourceSnapshot{
		retained.Resource.Key: faultCloneSnapshot(*retained.ObservedAfter),
		noEffect.Resource.Key: faultCloneSnapshot(noEffect.Before),
	}
	retainedCaptures := 0
	capturesBeforeReject := 0
	terminalRejected := false
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			if resource.Key == noEffect.Resource.Key {
				t.Fatal("Recover() captured a durable no-effect writer")
			}
			result := faultCloneSnapshot(current)
			retainedCaptures++
			return result, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() restored a retained item-policy writer")
			return model.ResourceSnapshot{}, nil
		},
	}
	harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if !terminalRejected && candidate.State == model.RunFailed {
			capturesBeforeReject = retainedCaptures
			drift := faultCloneSnapshot(live[retained.Resource.Key])
			drift.Fingerprint = strings.Repeat("f", 64)
			drift.File.Inode++
			live[retained.Resource.Key] = drift
			terminalRejected = true
			return errors.New("injected recovered RunFailed persistence rejection after frontier verification")
		}
		return nil
	}
	manager := newFaultManager(t, harness, runtime, nil)

	_, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("Recover() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if !terminalRejected || capturesBeforeReject < 2 || retainedCaptures <= capturesBeforeReject {
		t.Fatalf(
			"terminal rejection/captures = %t/%d/%d, want rejected terminal after final precheck and a later revalidation",
			terminalRejected,
			capturesBeforeReject,
			retainedCaptures,
		)
	}
	assertRetainedWriterRequiresRecovery(t, harness.state)
	if harness.state.ChangeSets[1].State != model.ChangeApplyFailed {
		t.Fatalf("no-effect change set state = %s, want %s", harness.state.ChangeSets[1].State, model.ChangeApplyFailed)
	}
	if wantIncompleteAttempt {
		if len(harness.state.RollbackAttempts) != 1 ||
			harness.state.RollbackAttempts[0].CompletedAt != nil ||
			harness.state.RollbackAttempts[0].Outcome != "" {
			t.Fatalf("stale no-effect attempt was finalized: %#v", harness.state.RollbackAttempts)
		}
	}
}

func assertRetainedWriterRequiresRecovery(t *testing.T, value *model.RemediationJournal) {
	t.Helper()
	if value.State != model.RunRecoveryRequired {
		t.Fatalf("durable run state = %s, want %s", value.State, model.RunRecoveryRequired)
	}
	if value.ChangeSets[0].State != model.ChangeRecoveryRequired {
		t.Fatalf("retained change set state = %s, want %s", value.ChangeSets[0].State, model.ChangeRecoveryRequired)
	}
	if value.State == model.RunFailed {
		t.Fatal("stale retained writer was accepted by normal RunFailed terminal")
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("recovery-required journal Validate() error = %v", err)
	}
}

func faultRetainedWriterNoEffectJournal(t *testing.T, withAttempt bool) *model.RemediationJournal {
	t.Helper()

	value := faultVerifiedJournal(t, 2, false, model.FailureRollbackItem, model.RunApplying)
	changeSet := &value.ChangeSets[1]
	operation := &changeSet.Operations[0]
	noEffectAt := faultBaseTime().Add(6 * time.Minute)
	observed := faultCloneSnapshot(operation.Before)
	observed.File.CapturedAt = noEffectAt
	journalError := model.JournalError{
		Code:        model.JournalErrorApplyFailed,
		Phase:       "recover_no_effect",
		ChangeSetID: changeSet.ID,
		OperationID: operation.ID,
		Resource:    operationResource(*operation),
		Message:     "apply_failed during recover_no_effect",
		OccurredAt:  noEffectAt,
	}
	operation.State = model.OperationFailed
	operation.ObservedAfter = &observed
	operation.AppliedAt = nil
	operation.Error = &journalError
	changeSet.State = model.ChangeApplyFailed
	changeSet.After = nil
	changeSet.AppliedAt = nil
	changeSet.VerifiedAt = nil
	changeSet.Error = &journalError
	value.Error = nil
	value.RollbackAttempts = nil
	if withAttempt {
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
	}
	faultSealJournal(t, value)
	return value
}

func faultRetainedRolledBackNoEffectJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()

	value := faultRetainedWriterNoEffectJournal(t, true)
	changeSet := &value.ChangeSets[0]
	operation := &changeSet.Operations[0]
	attemptStartedAt := faultBaseTime().Add(6*time.Minute + 10*time.Second)
	rollbackIntentAt := attemptStartedAt.Add(20 * time.Second)
	rolledBackAt := attemptStartedAt.Add(30 * time.Second)
	attemptCompletedAt := attemptStartedAt.Add(40 * time.Second)
	operation.State = model.OperationRolledBack
	operation.RollbackIntentAt = &rollbackIntentAt
	observedRollback := faultCloneSnapshot(operation.Before)
	observedRollback.File.CapturedAt = rolledBackAt
	operation.ObservedRollback = &observedRollback
	operation.RolledBackAt = &rolledBackAt
	changeSet.State = model.ChangeRolledBack
	changeSet.RolledBackAt = &rolledBackAt

	activeAttempt := value.RollbackAttempts[0]
	value.RollbackAttempts = []model.RollbackAttempt{
		{
			ID:                  "rollback-retained",
			Scope:               model.RollbackItem,
			Trigger:             model.RollbackUserRequest,
			RequestedChangeSets: []string{changeSet.ID},
			ExpandedChangeSets:  []string{changeSet.ID},
			CascadeApproved:     true,
			Outcome:             model.RollbackSucceeded,
			StartedAt:           attemptStartedAt,
			CompletedAt:         &attemptCompletedAt,
		},
		activeAttempt,
	}
	faultSealJournal(t, value)
	return value
}
