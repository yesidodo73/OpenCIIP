package orchestrator

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestAutomaticRollbackTriggerErrorsStayWithinAttemptScope(t *testing.T) {
	journalError := model.JournalError{
		Code:        model.JournalErrorApplyFailed,
		Phase:       "apply",
		ChangeSetID: "change-2",
		Message:     "apply failed",
		OccurredAt:  time.Date(2026, time.July, 31, 3, 0, 0, 0, time.UTC),
	}
	value := &model.RemediationJournal{
		ChangeSets: []model.ChangeSet{
			{ID: "change-1", State: model.ChangeVerified},
			{ID: "change-2", State: model.ChangeApplyFailed, Error: &journalError},
		},
	}

	got := automaticRollbackTriggerErrors(
		value,
		model.RollbackUserRequest,
		[]string{"change-1"},
		[]string{"change-1"},
	)
	if len(got) != 0 {
		t.Fatalf("automaticRollbackTriggerErrors() = %v, want no out-of-scope historical error", got)
	}

	got = automaticRollbackTriggerErrors(
		value,
		model.RollbackUserRequest,
		[]string{"change-1"},
		[]string{"change-1", "change-2"},
	)
	if len(got) != 1 || got[0].ChangeSetID != "change-2" {
		t.Fatalf("automaticRollbackTriggerErrors() = %v, want in-scope apply error", got)
	}
}

func TestApplyFailureRollbackDoesNotCopyRequestedErrorOutsideExpandedScope(t *testing.T) {
	value := faultJournalSkeleton(2, false)
	value.State = model.RunApproved
	value.FailurePolicy = model.FailureRollbackRun
	faultSealJournal(t, value)

	harness := newFaultStoreHarness(t, value)
	live := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	backups := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		live[operation.Resource.Key] = faultCloneSnapshot(operation.ExpectedBefore)
	}
	retainedChangeSet := value.ChangeSets[0]
	failingChangeSet := value.ChangeSets[1]
	retained := retainedChangeSet.Operations[0]
	failing := failingChangeSet.Operations[0]
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			if resource.Key == failing.Resource.Key {
				current.Fingerprint = strings.Repeat("f", 64)
				current.File.Inode++
			}
			return faultCloneSnapshot(current), nil
		},
		backup: func(
			_ context.Context,
			_ string,
			operationID string,
			resource model.CanonicalResource,
			before model.ResourceSnapshot,
		) (model.BackupArtifact, error) {
			backups[operationID] = faultCloneSnapshot(before)
			return faultBackup("backup-" + operationID), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		applyMetadata: func(
			_ context.Context,
			resource model.CanonicalResource,
			before model.ResourceSnapshot,
			desired model.ResourceSnapshot,
		) (model.ResourceSnapshot, error) {
			current := live[resource.Key]
			if !exactEqual(before, current) {
				return model.ResourceSnapshot{}, fmt.Errorf("resource %s changed before apply", resource.Key)
			}
			live[resource.Key] = faultCloneSnapshot(desired)
			return faultCloneSnapshot(desired), nil
		},
		restore: func(
			_ context.Context,
			operation model.OperationRecord,
			_ model.BackupArtifact,
		) (model.ResourceSnapshot, error) {
			before, exists := backups[operation.ID]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("missing backup for %s", operation.ID)
			}
			live[operation.Resource.Key] = faultCloneSnapshot(before)
			return faultCloneSnapshot(before), nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"rollback-run-policy"})

	err := manager.ApplyWithVerifier(
		context.Background(),
		value.RunID,
		func(context.Context, *model.RemediationJournal) error { return nil },
		func(context.Context, *model.RemediationJournal, string, string) error { return nil },
		func(context.Context, *model.RemediationJournal, []string) ([]string, error) { return nil, nil },
	)
	if CodeOf(err) != CodePreconditionFailed {
		t.Fatalf("ApplyWithVerifier() error = %v, want original %s cause", err, CodePreconditionFailed)
	}
	if harness.state.State != model.RunFailed {
		t.Fatalf("durable run state = %s, want %s", harness.state.State, model.RunFailed)
	}
	if harness.state.ChangeSets[0].State != model.ChangeRolledBack ||
		harness.state.ChangeSets[1].State != model.ChangeApplyFailed {
		t.Fatalf(
			"durable change states = %s/%s, want %s/%s",
			harness.state.ChangeSets[0].State,
			harness.state.ChangeSets[1].State,
			model.ChangeRolledBack,
			model.ChangeApplyFailed,
		)
	}
	if len(harness.state.RollbackAttempts) != 1 {
		t.Fatalf("rollback attempts = %d, want 1", len(harness.state.RollbackAttempts))
	}
	attempt := harness.state.RollbackAttempts[0]
	if attempt.Trigger != model.RollbackApplyFailure ||
		attempt.Scope != model.RollbackRun ||
		!slices.Equal(attempt.RequestedChangeSets, []string{failingChangeSet.ID}) ||
		!slices.Equal(attempt.ExpandedChangeSets, []string{retainedChangeSet.ID}) ||
		attempt.Outcome != model.RollbackSucceeded ||
		attempt.CompletedAt == nil {
		t.Fatalf("automatic rollback attempt = %#v", attempt)
	}
	for _, attemptError := range attempt.Errors {
		if attemptError.ChangeSetID != "" && !slices.Contains(attempt.ExpandedChangeSets, attemptError.ChangeSetID) {
			t.Fatalf("rollback attempt copied out-of-scope error: %#v", attemptError)
		}
	}
	wantRestore := "restore:" + retained.Resource.Key
	if !slices.Equal(runtime.mutationCalls, []string{"apply:" + retained.Resource.Key, wantRestore}) {
		t.Fatalf("runtime mutations = %v, want apply and one restore for retained target", runtime.mutationCalls)
	}
	if !exactEqual(retained.ExpectedBefore, live[retained.Resource.Key]) {
		t.Fatal("automatic run rollback did not restore the retained target")
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("durable automatic rollback journal Validate() error = %v", err)
	}
}
