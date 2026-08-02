package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestApplyCompletionRetryRevalidatesLiveFrontier(t *testing.T) {
	fixture := newApplyCompletionRetryFixture(t)
	drift := faultCloneSnapshot(fixture.live)
	drift.Fingerprint = strings.Repeat("f", 64)
	drift.File.Inode++
	rejected := false
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if !rejected &&
			fixture.harness.state.State == model.RunVerifying &&
			candidate.State == model.RunCompleted {
			rejected = true
			fixture.live = faultCloneSnapshot(drift)
			return errors.New("injected run completion failure before commit")
		}
		return nil
	}

	err := fixture.apply(func(context.Context, *model.RemediationJournal, []string) ([]string, error) {
		return nil, nil
	})
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("ApplyWithVerifier() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if !rejected {
		t.Fatal("test did not reject the first run completion update")
	}
	if fixture.harness.state.State == model.RunCompleted {
		t.Fatal("apply retry durably completed after the live writer frontier changed")
	}
	if fixture.harness.state.State != model.RunRecoveryRequired {
		t.Fatalf("durable run state = %s, want %s", fixture.harness.state.State, model.RunRecoveryRequired)
	}
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovery-required journal Validate() error = %v", err)
	}
}

func TestApplyCompletionRetryRerunsPlatformEvaluator(t *testing.T) {
	fixture := newApplyCompletionRetryFixture(t)
	evaluatorHealthy := true
	finalCalls := 0
	rejected := false
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if !rejected &&
			fixture.harness.state.State == model.RunVerifying &&
			candidate.State == model.RunCompleted {
			rejected = true
			evaluatorHealthy = false
			return errors.New("injected run completion failure before commit")
		}
		return nil
	}

	err := fixture.apply(func(_ context.Context, journal *model.RemediationJournal, ids []string) ([]string, error) {
		if journal.State != model.RunVerifying {
			return nil, nil
		}
		finalCalls++
		if !evaluatorHealthy {
			return append([]string(nil), ids...), errors.New("platform evaluator changed after the rejected completion update")
		}
		return nil, nil
	})
	if CodeOf(err) != CodeVerificationFailed {
		t.Fatalf("ApplyWithVerifier() error = %v, want %s", err, CodeVerificationFailed)
	}
	if !rejected {
		t.Fatal("test did not reject the first run completion update")
	}
	if finalCalls != 2 {
		t.Fatalf("final evaluator calls = %d, want initial verification and retry revalidation", finalCalls)
	}
	if fixture.harness.state.State == model.RunCompleted {
		t.Fatal("apply retry durably completed after the platform evaluator changed")
	}
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("post-verification-failure journal Validate() error = %v", err)
	}
}

func TestApplyFirstCompletionRevalidatesAfterEvaluatorCallback(t *testing.T) {
	fixture := newApplyCompletionRetryFixture(t)
	drifted := false
	err := fixture.apply(func(_ context.Context, journal *model.RemediationJournal, _ []string) ([]string, error) {
		if journal.State == model.RunVerifying && !drifted {
			drifted = true
			drift := faultCloneSnapshot(fixture.live)
			drift.Fingerprint = strings.Repeat("f", 64)
			drift.File.Inode++
			fixture.live = drift
		}
		return nil, nil
	})
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("ApplyWithVerifier() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if !drifted {
		t.Fatal("final evaluator did not drift the live resource before returning success")
	}
	if fixture.harness.state.State != model.RunRecoveryRequired {
		t.Fatalf("durable run state = %s, want %s", fixture.harness.state.State, model.RunRecoveryRequired)
	}
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovery-required journal Validate() error = %v", err)
	}
}

func TestApplyCompletionRetryRevalidatesAfterEvaluatorCallback(t *testing.T) {
	fixture := newApplyCompletionRetryFixture(t)
	retryStarted := false
	finalCalls := 0
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if !retryStarted &&
			fixture.harness.state.State == model.RunVerifying &&
			candidate.State == model.RunCompleted {
			retryStarted = true
			return errors.New("injected run completion failure before commit")
		}
		return nil
	}

	err := fixture.apply(func(_ context.Context, journal *model.RemediationJournal, _ []string) ([]string, error) {
		if journal.State != model.RunVerifying {
			return nil, nil
		}
		finalCalls++
		if retryStarted && finalCalls == 2 {
			drift := faultCloneSnapshot(fixture.live)
			drift.Fingerprint = strings.Repeat("f", 64)
			drift.File.Inode++
			fixture.live = drift
		}
		return nil, nil
	})
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("ApplyWithVerifier() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if finalCalls != 2 {
		t.Fatalf("final evaluator calls = %d, want initial and retry calls", finalCalls)
	}
	if fixture.harness.state.State != model.RunRecoveryRequired {
		t.Fatalf("durable run state = %s, want %s", fixture.harness.state.State, model.RunRecoveryRequired)
	}
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("retry recovery-required journal Validate() error = %v", err)
	}
}

func TestRollbackOperationResultRetryRevalidatesObservedRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	drift := faultCloneSnapshot(fixture.before)
	drift.Fingerprint = strings.Repeat("f", 64)
	drift.File.Inode++
	rejected := false
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if !rejected &&
			durable.State == model.OperationRollbackIntentDurable &&
			next.State == model.OperationRolledBack {
			rejected = true
			fixture.live = faultCloneSnapshot(drift)
			return errors.New("injected rollback-result failure before commit")
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if !rejected {
		t.Fatal("test did not reject the first rollback-result update")
	}
	operation := rollbackCrashCutOperation(t, fixture.harness.state)
	if operation.State != model.OperationRollbackIntentDurable ||
		operation.ObservedRollback != nil ||
		operation.RolledBackAt != nil {
		t.Fatalf("stale rollback result was persisted after drift: %#v", operation)
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRollingBack, model.OperationRollbackIntentDurable)
}

func TestRollbackItemTerminalRetryRevalidatesLiveFrontier(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	drift := faultCloneSnapshot(fixture.before)
	drift.Fingerprint = strings.Repeat("f", 64)
	drift.File.Inode++
	rejected := false
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if rejected || len(fixture.harness.state.RollbackAttempts) != 1 || len(candidate.RollbackAttempts) != 1 {
			return nil
		}
		durableAttempt := fixture.harness.state.RollbackAttempts[0]
		nextAttempt := candidate.RollbackAttempts[0]
		if durableAttempt.CompletedAt == nil &&
			nextAttempt.CompletedAt != nil &&
			candidate.State == model.RunRolledBack {
			rejected = true
			fixture.live = faultCloneSnapshot(drift)
			return errors.New("injected item terminal failure before commit")
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if !rejected {
		t.Fatal("test did not reject the first item terminal update")
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRolledBack, model.OperationRolledBack)
}

func TestRollbackRunTerminalRetryRevalidatesLiveFrontier(t *testing.T) {
	value := faultVerifiedJournal(t, 2, false, model.FailureRollbackRun, model.RunCompleted)
	harness := newFaultStoreHarness(t, value)
	live := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	backups := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		live[operation.Resource.Key] = faultCloneSnapshot(*operation.ObservedAfter)
		backups[operation.Backup.ID] = faultCloneSnapshot(operation.Before)
	}
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			return faultCloneSnapshot(current), nil
		},
		verifyBackup: func(_ context.Context, artifact model.BackupArtifact) error {
			if _, exists := backups[artifact.ID]; !exists {
				return fmt.Errorf("unexpected backup %s", artifact.ID)
			}
			return nil
		},
		restore: func(_ context.Context, operation model.OperationRecord, artifact model.BackupArtifact) (model.ResourceSnapshot, error) {
			before, exists := backups[artifact.ID]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected backup %s", artifact.ID)
			}
			live[operation.Resource.Key] = faultCloneSnapshot(before)
			return faultCloneSnapshot(before), nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"run-terminal"})
	rejected := false
	harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if rejected || len(harness.state.RollbackAttempts) != 1 || len(candidate.RollbackAttempts) != 1 {
			return nil
		}
		durableAttempt := harness.state.RollbackAttempts[0]
		nextAttempt := candidate.RollbackAttempts[0]
		if durableAttempt.CompletedAt == nil &&
			nextAttempt.CompletedAt != nil &&
			nextAttempt.Scope == model.RollbackRun &&
			candidate.State == model.RunRolledBack {
			rejected = true
			operation := value.ChangeSets[0].Operations[0]
			drift := faultCloneSnapshot(operation.Before)
			drift.Fingerprint = strings.Repeat("f", 64)
			drift.File.Inode++
			live[operation.Resource.Key] = drift
			return errors.New("injected run terminal failure before commit")
		}
		return nil
	}

	preview, err := manager.PreviewRollbackRun(context.Background(), value.RunID)
	if err != nil {
		t.Fatalf("PreviewRollbackRun() error = %v", err)
	}
	_, err = manager.RollbackRun(context.Background(), value.RunID, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackRun() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if !rejected {
		t.Fatal("test did not reject the first run terminal update")
	}
	if harness.state.State != model.RunRollingBack {
		t.Fatalf("durable run state = %s, want %s", harness.state.State, model.RunRollingBack)
	}
	if len(harness.state.RollbackAttempts) != 1 ||
		harness.state.RollbackAttempts[0].CompletedAt != nil ||
		harness.state.RollbackAttempts[0].Outcome != "" {
		t.Fatalf("stale run terminal result was persisted: %#v", harness.state.RollbackAttempts)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("incomplete run rollback journal Validate() error = %v", err)
	}
}

func TestRollbackRunFirstTerminalUpdateRevalidatesAllRestoredResources(t *testing.T) {
	value := faultVerifiedJournal(t, 2, false, model.FailureRollbackRun, model.RunCompleted)
	harness := newFaultStoreHarness(t, value)
	live := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	backups := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		live[operation.Resource.Key] = faultCloneSnapshot(*operation.ObservedAfter)
		backups[operation.Backup.ID] = faultCloneSnapshot(operation.Before)
	}
	restoredResources := make([]string, 0, len(value.ChangeSets))
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			return faultCloneSnapshot(current), nil
		},
		verifyBackup: func(_ context.Context, artifact model.BackupArtifact) error {
			if _, exists := backups[artifact.ID]; !exists {
				return fmt.Errorf("unexpected backup %s", artifact.ID)
			}
			return nil
		},
		restore: func(_ context.Context, operation model.OperationRecord, artifact model.BackupArtifact) (model.ResourceSnapshot, error) {
			before, exists := backups[artifact.ID]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected backup %s", artifact.ID)
			}
			live[operation.Resource.Key] = faultCloneSnapshot(before)
			if len(restoredResources) > 0 {
				earlierKey := restoredResources[0]
				drift := faultCloneSnapshot(live[earlierKey])
				drift.Fingerprint = strings.Repeat("f", 64)
				drift.File.Inode++
				live[earlierKey] = drift
			}
			restoredResources = append(restoredResources, operation.Resource.Key)
			return faultCloneSnapshot(before), nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"run-first-terminal"})

	preview, err := manager.PreviewRollbackRun(context.Background(), value.RunID)
	if err != nil {
		t.Fatalf("PreviewRollbackRun() error = %v", err)
	}
	_, err = manager.RollbackRun(context.Background(), value.RunID, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackRun() error = %v, want %s", err, CodeRecoveryRequired)
	}
	var orchestrationError *Error
	if !errors.As(err, &orchestrationError) || !orchestrationError.Committed {
		t.Fatalf("RollbackRun() error = %#v, want Committed=true", orchestrationError)
	}
	if len(restoredResources) != 2 {
		t.Fatalf("restored resources = %v, want both disjoint resources", restoredResources)
	}
	if harness.state.State != model.RunRollingBack {
		t.Fatalf("durable run state = %s, want %s", harness.state.State, model.RunRollingBack)
	}
	if len(harness.state.RollbackAttempts) != 1 ||
		harness.state.RollbackAttempts[0].CompletedAt != nil ||
		harness.state.RollbackAttempts[0].Outcome != "" {
		t.Fatalf("stale run terminal result was persisted: %#v", harness.state.RollbackAttempts)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("incomplete run rollback journal Validate() error = %v", err)
	}
}

func TestRollbackItemFirstTerminalUpdateRevalidatesLiveFrontier(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	injected := false
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if injected {
			return nil
		}
		durable, _, err := findChangeSet(fixture.harness.state, "change-a")
		if err != nil {
			t.Fatalf("findChangeSet(durable) error = %v", err)
		}
		next, _, err := findChangeSet(candidate, "change-a")
		if err != nil {
			t.Fatalf("findChangeSet(candidate) error = %v", err)
		}
		if durable.State == model.ChangeRollingBack && next.State == model.ChangeRolledBack {
			injected = true
			drift := faultCloneSnapshot(fixture.before)
			drift.Fingerprint = strings.Repeat("f", 64)
			drift.File.Inode++
			fixture.live = drift
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRecoveryRequired)
	}
	var orchestrationError *Error
	if !errors.As(err, &orchestrationError) || !orchestrationError.Committed {
		t.Fatalf("RollbackItem() error = %#v, want Committed=true", orchestrationError)
	}
	if !injected {
		t.Fatal("test did not change the live resource before terminal completion")
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRolledBack, model.OperationRolledBack)
}

type applyCompletionRetryFixture struct {
	harness *faultStoreHarness
	manager *Manager
	runtime *scriptedFileRuntime
	live    model.ResourceSnapshot
}

func newApplyCompletionRetryFixture(t *testing.T) *applyCompletionRetryFixture {
	t.Helper()
	value := faultJournalSkeleton(1, false)
	value.State = model.RunApproved
	faultSealJournal(t, value)
	operation := value.ChangeSets[0].Operations[0]
	fixture := &applyCompletionRetryFixture{
		harness: newFaultStoreHarness(t, value),
		live:    faultCloneSnapshot(operation.ExpectedBefore),
	}
	var backup model.ResourceSnapshot
	fixture.runtime = &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			if resource.Key != operation.Resource.Key {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			return faultCloneSnapshot(fixture.live), nil
		},
		backup: func(
			_ context.Context,
			_, _ string,
			resource model.CanonicalResource,
			expected model.ResourceSnapshot,
		) (model.BackupArtifact, error) {
			if resource.Key != operation.Resource.Key {
				return model.BackupArtifact{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			backup = faultCloneSnapshot(expected)
			return faultBackup("apply-completion-retry"), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		applyMetadata: func(
			_ context.Context,
			resource model.CanonicalResource,
			before, desired model.ResourceSnapshot,
		) (model.ResourceSnapshot, error) {
			if resource.Key != operation.Resource.Key || !exactEqual(fixture.live, before) {
				return model.ResourceSnapshot{}, errors.New("apply precondition changed")
			}
			fixture.live = faultCloneSnapshot(desired)
			return faultCloneSnapshot(desired), nil
		},
		restore: func(_ context.Context, restored model.OperationRecord, _ model.BackupArtifact) (model.ResourceSnapshot, error) {
			if restored.Resource.Key != operation.Resource.Key || backup.IsZero() {
				return model.ResourceSnapshot{}, errors.New("unexpected restore")
			}
			fixture.live = faultCloneSnapshot(backup)
			return faultCloneSnapshot(backup), nil
		},
	}
	fixture.manager = newFaultManager(t, fixture.harness, fixture.runtime, []string{"apply-retry"})
	return fixture
}

func (fixture *applyCompletionRetryFixture) apply(verifier ApplyVerifier) error {
	return fixture.manager.ApplyWithVerifier(
		context.Background(),
		fixture.harness.state.RunID,
		func(context.Context, *model.RemediationJournal) error { return nil },
		func(context.Context, *model.RemediationJournal, string, string) error { return nil },
		verifier,
	)
}
