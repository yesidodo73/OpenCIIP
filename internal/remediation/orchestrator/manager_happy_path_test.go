package orchestrator

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestManagerApplyThenItemAndRunRollbackHappyPath(t *testing.T) {
	value := faultJournalSkeleton(2, false)
	value.State = model.RunApproved
	faultSealJournal(t, value)

	harness := newFaultStoreHarness(t, value)
	live := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	backups := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		live[operation.Resource.Key] = faultCloneSnapshot(operation.ExpectedBefore)
	}

	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("resource %s is not in the live-state fixture", resource.Key)
			}
			return faultCloneSnapshot(current), nil
		},
		backup: func(
			_ context.Context,
			_ string,
			operationID string,
			_ model.CanonicalResource,
			expected model.ResourceSnapshot,
		) (model.BackupArtifact, error) {
			artifact := faultBackup("backup-" + operationID)
			backups[artifact.ID] = faultCloneSnapshot(expected)
			return artifact, nil
		},
		verifyBackup: func(_ context.Context, artifact model.BackupArtifact) error {
			if _, exists := backups[artifact.ID]; !exists {
				return fmt.Errorf("backup %s was not captured", artifact.ID)
			}
			return nil
		},
		applyMetadata: func(
			_ context.Context,
			resource model.CanonicalResource,
			before model.ResourceSnapshot,
			desired model.ResourceSnapshot,
		) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists || !exactEqual(before, current) {
				return model.ResourceSnapshot{}, fmt.Errorf("resource %s does not match its apply precondition", resource.Key)
			}
			live[resource.Key] = faultCloneSnapshot(desired)
			return faultCloneSnapshot(desired), nil
		},
		restore: func(
			_ context.Context,
			operation model.OperationRecord,
			artifact model.BackupArtifact,
		) (model.ResourceSnapshot, error) {
			before, exists := backups[artifact.ID]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("backup %s is missing", artifact.ID)
			}
			if !exactEqual(operation.Before, before) {
				return model.ResourceSnapshot{}, fmt.Errorf("backup %s does not match the durable before state", artifact.ID)
			}
			live[operation.Resource.Key] = faultCloneSnapshot(before)
			return faultCloneSnapshot(before), nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"001", "002"})

	runGuardCalls := 0
	var effectGuardCalls []string
	var verifierCalls [][]string
	err := manager.ApplyWithVerifier(
		context.Background(),
		value.RunID,
		func(_ context.Context, journal *model.RemediationJournal) error {
			runGuardCalls++
			if journal.State != model.RunApproved {
				return fmt.Errorf("run guard observed run state %s, want %s", journal.State, model.RunApproved)
			}
			return nil
		},
		func(_ context.Context, journal *model.RemediationJournal, changeSetID, operationID string) error {
			effectGuardCalls = append(effectGuardCalls, changeSetID+"/"+operationID)
			changeSet, _, findErr := findChangeSet(journal, changeSetID)
			if findErr != nil {
				return findErr
			}
			if journal.State != model.RunApplying || changeSet.State != model.ChangeApplying {
				return fmt.Errorf("effect guard observed run/change states %s/%s", journal.State, changeSet.State)
			}
			operation, _, _, findErr := findOperation(journal, changeSetID, operationID)
			if findErr != nil {
				return findErr
			}
			if operation.State != model.OperationPlanned || operation.ApplyIntentAt != nil ||
				operation.Before.IsZero() || operation.Backup == nil {
				return fmt.Errorf("effect guard did not observe the prepared pre-intent operation")
			}
			current, exists := live[operation.Resource.Key]
			if !exists || !exactEqual(operation.Before, current) {
				return fmt.Errorf("effect guard did not run before the metadata side effect")
			}
			if changeSetID == "change-b" {
				previous, _, previousErr := findChangeSet(journal, "change-a")
				if previousErr != nil {
					return previousErr
				}
				if previous.State != model.ChangeVerified {
					return fmt.Errorf("second effect guard observed previous change set in %s, want %s", previous.State, model.ChangeVerified)
				}
			}
			return nil
		},
		func(_ context.Context, journal *model.RemediationJournal, changeSetIDs []string) ([]string, error) {
			ids := append([]string(nil), changeSetIDs...)
			verifierCalls = append(verifierCalls, ids)
			if len(ids) == 1 && journal.State != model.RunApplying {
				return ids, fmt.Errorf("item evaluator observed run state %s, want %s", journal.State, model.RunApplying)
			}
			if len(ids) == len(journal.ChangeSets) && journal.State != model.RunVerifying {
				return ids, fmt.Errorf("final evaluator observed run state %s, want %s", journal.State, model.RunVerifying)
			}
			for _, changeSetID := range ids {
				changeSet, _, findErr := findChangeSet(journal, changeSetID)
				if findErr != nil {
					return ids, findErr
				}
				if len(ids) == 1 && changeSet.State != model.ChangeVerifying {
					return ids, fmt.Errorf("item evaluator observed change set %s in state %s, want %s", changeSetID, changeSet.State, model.ChangeVerifying)
				}
				if len(ids) == len(journal.ChangeSets) && changeSet.State != model.ChangeVerified {
					return ids, fmt.Errorf("final evaluator observed change set %s in state %s, want %s", changeSetID, changeSet.State, model.ChangeVerified)
				}
				for _, operation := range changeSet.Operations {
					current, exists := live[operation.Resource.Key]
					if !exists || !exactEqual(operation.Desired, current) {
						return []string{changeSetID}, fmt.Errorf("resource %s does not satisfy the evaluator postcondition", operation.Resource.Key)
					}
				}
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("ApplyWithVerifier() error = %v", err)
	}
	if runGuardCalls != 1 {
		t.Fatalf("run guard calls = %d, want 1", runGuardCalls)
	}
	wantEffectGuardCalls := []string{"change-a/operation-a", "change-b/operation-b"}
	if !reflect.DeepEqual(effectGuardCalls, wantEffectGuardCalls) {
		t.Fatalf("effect guard calls = %v, want one call per effect boundary %v", effectGuardCalls, wantEffectGuardCalls)
	}
	wantVerifierCalls := [][]string{
		{"change-a"},
		{"change-b"},
		{"change-a", "change-b"},
	}
	if !reflect.DeepEqual(verifierCalls, wantVerifierCalls) {
		t.Fatalf("verifier calls = %v, want %v", verifierCalls, wantVerifierCalls)
	}
	assertHappyPathJournal(t, harness.state, model.RunCompleted, nil, map[string]model.ChangeSetState{
		"change-a": model.ChangeVerified,
		"change-b": model.ChangeVerified,
	})

	itemPreview, err := manager.PreviewRollbackItem(context.Background(), value.RunID, "change-b")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	if itemPreview.CascadeRequired ||
		!reflect.DeepEqual(itemPreview.ExpandedChangeSets, []string{"change-b"}) ||
		!reflect.DeepEqual(itemPreview.ExecutionOrder, []string{"change-b"}) {
		t.Fatalf("item rollback preview = %#v", itemPreview)
	}
	itemAttempt, err := manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-b",
		false,
		itemPreview.PreviewDigest, faultUserRollbackBuild())

	if err != nil {
		t.Fatalf("RollbackItem() error = %v", err)
	}
	assertHappyPathAttempt(t, itemAttempt, model.RollbackItem, []string{"change-b"}, []string{"change-b"})
	assertHappyPathJournal(t, harness.state, model.RunCompletedWithRollbacks, nil, map[string]model.ChangeSetState{
		"change-a": model.ChangeVerified,
		"change-b": model.ChangeRolledBack,
	})

	runPreview, err := manager.PreviewRollbackRun(context.Background(), value.RunID)
	if err != nil {
		t.Fatalf("PreviewRollbackRun() error = %v", err)
	}
	if !reflect.DeepEqual(runPreview.ExpandedChangeSets, []string{"change-a"}) ||
		!reflect.DeepEqual(runPreview.ExecutionOrder, []string{"change-a"}) {
		t.Fatalf("remaining run rollback preview = %#v", runPreview)
	}
	runAttempt, err := manager.RollbackRun(context.Background(), value.RunID, runPreview.PreviewDigest, faultUserRollbackBuild())
	if err != nil {
		t.Fatalf("RollbackRun() error = %v", err)
	}
	assertHappyPathAttempt(t, runAttempt, model.RollbackRun, nil, []string{"change-a"})
	assertHappyPathJournal(t, harness.state, model.RunRolledBack, nil, map[string]model.ChangeSetState{
		"change-a": model.ChangeRolledBack,
		"change-b": model.ChangeRolledBack,
	})

	wantMutations := []string{
		"apply:file:/etc/open-ciip-a",
		"apply:file:/etc/open-ciip-b",
		"restore:file:/etc/open-ciip-b",
		"restore:file:/etc/open-ciip-a",
	}
	if !reflect.DeepEqual(runtime.mutationCalls, wantMutations) {
		t.Fatalf("mutation order = %v, want reverse rollback order %v", runtime.mutationCalls, wantMutations)
	}
	for _, changeSet := range harness.state.ChangeSets {
		operation := changeSet.Operations[0]
		current := live[operation.Resource.Key]
		if !exactEqual(operation.Before, current) {
			t.Fatalf("final live state for %s does not match its durable before state", operation.Resource.Key)
		}
	}
}

func assertHappyPathAttempt(
	t *testing.T,
	attempt model.RollbackAttempt,
	scope model.RollbackScope,
	requested []string,
	expanded []string,
) {
	t.Helper()
	if attempt.Scope != scope ||
		attempt.Trigger != model.RollbackUserRequest ||
		attempt.Outcome != model.RollbackSucceeded ||
		attempt.CompletedAt == nil ||
		!reflect.DeepEqual(attempt.RequestedChangeSets, requested) ||
		!reflect.DeepEqual(attempt.ExpandedChangeSets, expanded) {
		t.Fatalf("rollback attempt = %#v", attempt)
	}
}

func assertHappyPathJournal(
	t *testing.T,
	journal *model.RemediationJournal,
	wantRunState model.RunState,
	wantUnresolved []string,
	wantChangeStates map[string]model.ChangeSetState,
) {
	t.Helper()
	if journal == nil {
		t.Fatal("journal is nil")
	}
	if journal.State != wantRunState {
		t.Fatalf("run state = %s, want %s", journal.State, wantRunState)
	}
	if !reflect.DeepEqual(journal.UnresolvedChangeSets, wantUnresolved) {
		t.Fatalf("unresolved change sets = %v, want %v", journal.UnresolvedChangeSets, wantUnresolved)
	}
	for changeSetID, wantState := range wantChangeStates {
		changeSet, _, err := findChangeSet(journal, changeSetID)
		if err != nil {
			t.Fatalf("findChangeSet(%s) error = %v", changeSetID, err)
		}
		if changeSet.State != wantState {
			t.Fatalf("change set %s state = %s, want %s", changeSetID, changeSet.State, wantState)
		}
		switch wantState {
		case model.ChangeVerified:
			if changeSet.VerifiedAt == nil || changeSet.Operations[0].State != model.OperationVerified {
				t.Fatalf("verified change set %s lacks terminal verification evidence", changeSetID)
			}
		case model.ChangeRolledBack:
			operation := changeSet.Operations[0]
			if changeSet.RolledBackAt == nil ||
				operation.State != model.OperationRolledBack ||
				operation.ObservedRollback == nil ||
				operation.RolledBackAt == nil {
				t.Fatalf("rolled-back change set %s lacks terminal rollback evidence", changeSetID)
			}
		}
	}
	if err := journal.Validate(); err != nil {
		t.Fatalf("journal Validate() error = %v", err)
	}
}
