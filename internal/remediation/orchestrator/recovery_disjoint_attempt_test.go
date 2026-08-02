package orchestrator

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestRecoverSequentiallyReconcilesDisjointCompletedRollbackScopes(t *testing.T) {
	value := faultDisjointCompletedRollbackJournal(t)
	historicalAttempts := append([]model.RollbackAttempt(nil), value.RollbackAttempts...)
	harness := newFaultStoreHarness(t, value)
	live := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		live[operation.Resource.Key] = faultCloneSnapshot(operation.Before)
	}
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			current, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			return faultCloneSnapshot(current), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() performed a live restore")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"recovery-b", "recovery-a"})

	first, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(first scope) error = %v", err)
	}
	if !reflect.DeepEqual(first.ConfirmedRolledBack, []string{"change-b/operation-b"}) {
		t.Fatalf("first ConfirmedRolledBack = %v, want [change-b/operation-b]", first.ConfirmedRolledBack)
	}
	if harness.state.State != model.RunRecoveryRequired {
		t.Fatalf("first recovered run state = %s, want %s", harness.state.State, model.RunRecoveryRequired)
	}
	if len(harness.state.RollbackAttempts) != 3 {
		t.Fatalf("first recovery attempts = %d, want two historical and one crash-recovery attempt", len(harness.state.RollbackAttempts))
	}
	if !reflect.DeepEqual(harness.state.RollbackAttempts[:2], historicalAttempts) {
		t.Fatal("first recovery changed completed historical attempts")
	}
	firstRecovery := harness.state.RollbackAttempts[2]
	if firstRecovery.Trigger != model.RollbackCrashRecovery ||
		firstRecovery.CompletedAt == nil ||
		firstRecovery.Outcome != model.RollbackSucceeded ||
		!reflect.DeepEqual(firstRecovery.ExpandedChangeSets, []string{"change-b"}) {
		t.Fatalf("first crash-recovery attempt = %#v", firstRecovery)
	}

	second, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(second scope) error = %v", err)
	}
	if !reflect.DeepEqual(second.ConfirmedRolledBack, []string{"change-a/operation-a", "change-b/operation-b"}) {
		t.Fatalf("second ConfirmedRolledBack = %v, want both operations", second.ConfirmedRolledBack)
	}
	if harness.state.State != model.RunRolledBack {
		t.Fatalf("second recovered run state = %s, want %s", harness.state.State, model.RunRolledBack)
	}
	if len(harness.state.RollbackAttempts) != 4 {
		t.Fatalf("second recovery attempts = %d, want one new attempt per disjoint scope", len(harness.state.RollbackAttempts))
	}
	if !reflect.DeepEqual(harness.state.RollbackAttempts[:2], historicalAttempts) {
		t.Fatal("second recovery changed completed historical attempts")
	}
	secondRecovery := harness.state.RollbackAttempts[3]
	if secondRecovery.Trigger != model.RollbackCrashRecovery ||
		secondRecovery.CompletedAt == nil ||
		secondRecovery.Outcome != model.RollbackSucceeded ||
		!reflect.DeepEqual(secondRecovery.ExpandedChangeSets, []string{"change-a"}) {
		t.Fatalf("second crash-recovery attempt = %#v", secondRecovery)
	}
	if !firstRecovery.CompletedAt.Before(secondRecovery.StartedAt) {
		t.Fatalf("sequential recovery attempts overlap: first completed %s, second started %s", firstRecovery.CompletedAt, secondRecovery.StartedAt)
	}
	if len(runtime.mutationCalls) != 0 {
		t.Fatalf("Recover() mutated externally restored resources: %v", runtime.mutationCalls)
	}
	revision := harness.state.Revision
	if _, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild()); err != nil {
		t.Fatalf("Recover(terminal retry) error = %v", err)
	}
	if harness.state.Revision != revision || len(harness.state.RollbackAttempts) != 4 {
		t.Fatalf("terminal retry changed journal: revision=%d attempts=%d", harness.state.Revision, len(harness.state.RollbackAttempts))
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("final journal Validate() error = %v", err)
	}
	assertRollbackAttemptChronology(t, harness.state.RollbackAttempts)
}

func TestRecoverDefersSharedWriterScopeWithoutPoisoningActiveAttempt(t *testing.T) {
	value := faultSharedWriterDeferredRollbackJournal(t)
	historicalAttempt := value.RollbackAttempts[0]
	activeAttempt := value.RollbackAttempts[1]
	harness := newFaultStoreHarness(t, value)
	earliestBefore := faultCloneSnapshot(value.ChangeSets[0].Operations[0].Before)
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			if resource.Key != earliestBefore.Reference.Key {
				return model.ResourceSnapshot{}, fmt.Errorf("unexpected resource %s", resource.Key)
			}
			return faultCloneSnapshot(earliestBefore), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() performed a live restore")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"recovery-shared"})

	first, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(active shared-resource scope) error = %v", err)
	}
	if !reflect.DeepEqual(first.ConfirmedRolledBack, []string{"change-b/operation-b"}) {
		t.Fatalf("first ConfirmedRolledBack = %v, want only the active scope", first.ConfirmedRolledBack)
	}
	if len(first.Ambiguous) != 0 {
		t.Fatalf("deferred scope poisoned active rollback evidence: %v", first.Ambiguous)
	}
	if harness.state.State != model.RunRecoveryRequired {
		t.Fatalf("first recovered run state = %s, want %s", harness.state.State, model.RunRecoveryRequired)
	}
	if len(harness.state.RollbackAttempts) != 2 {
		t.Fatalf("first recovery attempts = %d, want no scope widening", len(harness.state.RollbackAttempts))
	}
	if !reflect.DeepEqual(harness.state.RollbackAttempts[0], historicalAttempt) {
		t.Fatal("first recovery changed completed historical attempt")
	}
	completedActive := harness.state.RollbackAttempts[1]
	if completedActive.ID != activeAttempt.ID ||
		completedActive.CompletedAt == nil ||
		completedActive.Outcome != model.RollbackSucceeded ||
		!reflect.DeepEqual(completedActive.ExpandedChangeSets, []string{"change-b"}) {
		t.Fatalf("completed active attempt = %#v", completedActive)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("first recovered journal Validate() error = %v", err)
	}
	assertRollbackAttemptChronology(t, harness.state.RollbackAttempts)

	firstRevision := harness.state.Revision
	second, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(deferred shared-resource scope) error = %v", err)
	}
	if !reflect.DeepEqual(second.ConfirmedRolledBack, []string{"change-a/operation-a", "change-b/operation-b"}) {
		t.Fatalf("second ConfirmedRolledBack = %v, want the complete writer chain", second.ConfirmedRolledBack)
	}
	if len(second.Ambiguous) != 0 {
		t.Fatalf("second recovery marked a proven writer chain ambiguous: %v", second.Ambiguous)
	}
	if harness.state.Revision <= firstRevision {
		t.Fatalf("second recovery made no durable progress: revision=%d, previous=%d", harness.state.Revision, firstRevision)
	}
	if harness.state.State != model.RunRolledBack {
		t.Fatalf("second recovered run state = %s, want %s", harness.state.State, model.RunRolledBack)
	}
	if len(harness.state.RollbackAttempts) != 3 {
		t.Fatalf("second recovery attempts = %d, want one fresh deferred-scope attempt", len(harness.state.RollbackAttempts))
	}
	recoveryAttempt := harness.state.RollbackAttempts[2]
	if recoveryAttempt.Trigger != model.RollbackCrashRecovery ||
		recoveryAttempt.CompletedAt == nil ||
		recoveryAttempt.Outcome != model.RollbackSucceeded ||
		!reflect.DeepEqual(recoveryAttempt.ExpandedChangeSets, []string{"change-a", "change-b"}) {
		t.Fatalf("deferred crash-recovery attempt = %#v", recoveryAttempt)
	}
	if !completedActive.CompletedAt.Before(recoveryAttempt.StartedAt) {
		t.Fatalf("shared-resource recovery attempts overlap: active completed %s, deferred started %s", completedActive.CompletedAt, recoveryAttempt.StartedAt)
	}
	if !reflect.DeepEqual(harness.state.RollbackAttempts[0], historicalAttempt) {
		t.Fatal("second recovery changed completed historical attempt")
	}
	if len(runtime.mutationCalls) != 0 {
		t.Fatalf("Recover() mutated externally restored resources: %v", runtime.mutationCalls)
	}
	if err := harness.state.Validate(); err != nil {
		t.Fatalf("second recovered journal Validate() error = %v", err)
	}
	assertRollbackAttemptChronology(t, harness.state.RollbackAttempts)

	revision := harness.state.Revision
	if _, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild()); err != nil {
		t.Fatalf("Recover(terminal retry) error = %v", err)
	}
	if harness.state.Revision != revision || len(harness.state.RollbackAttempts) != 3 {
		t.Fatalf("terminal retry changed journal: revision=%d attempts=%d", harness.state.Revision, len(harness.state.RollbackAttempts))
	}
}

func faultDisjointCompletedRollbackJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultVerifiedJournal(t, 2, false, model.FailureRollbackItem, model.RunCompleted)
	value.State = model.RunRollbackFailed
	value.UnresolvedChangeSets = []string{"change-a", "change-b"}
	for index := range value.ChangeSets {
		value.ChangeSets[index].State = model.ChangeRollbackFailed
	}
	firstStarted := faultBaseTime().Add(6 * time.Minute)
	firstCompleted := firstStarted.Add(time.Minute)
	secondStarted := firstCompleted.Add(time.Minute)
	secondCompleted := secondStarted.Add(time.Minute)
	value.RollbackAttempts = []model.RollbackAttempt{
		{
			ID:                  "rollback-a",
			Scope:               model.RollbackItem,
			Trigger:             model.RollbackUserRequest,
			RequestedChangeSets: []string{"change-a"},
			ExpandedChangeSets:  []string{"change-a"},
			Outcome:             model.RollbackFailed,
			StartedAt:           firstStarted,
			CompletedAt:         &firstCompleted,
		},
		{
			ID:                  "rollback-b",
			Scope:               model.RollbackItem,
			Trigger:             model.RollbackUserRequest,
			RequestedChangeSets: []string{"change-b"},
			ExpandedChangeSets:  []string{"change-b"},
			Outcome:             model.RollbackFailed,
			StartedAt:           secondStarted,
			CompletedAt:         &secondCompleted,
		},
	}
	faultSealJournal(t, value)
	return value
}

func faultSharedWriterDeferredRollbackJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultVerifiedJournal(t, 2, false, model.FailureRollbackItem, model.RunCompleted)
	first := &value.ChangeSets[0]
	second := &value.ChangeSets[1]
	firstOperation := &first.Operations[0]
	secondOperation := &second.Operations[0]

	sharedResource := firstOperation.Resource
	chainedBefore := faultCloneSnapshot(*firstOperation.ObservedAfter)
	chainedDesired := faultFileSnapshot(sharedResource, "d", 0o400, faultBaseTime().Add(time.Minute))
	chainedObserved := faultCloneSnapshot(chainedDesired)
	chainedObserved.File.CapturedAt = faultBaseTime().Add(4 * time.Minute)
	second.Resources = []model.CanonicalResource{sharedResource}
	second.Before = []model.ResourceSnapshot{chainedBefore}
	second.After = []model.ResourceSnapshot{chainedObserved}
	secondOperation.Resource = sharedResource
	secondOperation.ExpectedBefore = chainedBefore
	secondOperation.Before = chainedBefore
	secondOperation.Desired = chainedDesired
	secondOperation.ObservedAfter = &chainedObserved
	value.ConflictGraph.Edges = []model.ConflictEdge{{
		From:      first.ID,
		To:        second.ID,
		Reason:    model.ConflictSharedResource,
		Resources: []string{sharedResource.Key},
	}}

	value.State = model.RunRollingBack
	first.State = model.ChangeRollbackFailed
	second.State = model.ChangeRolledBack
	rollbackIntentAt := faultBaseTime().Add(9 * time.Minute)
	rolledBackAt := faultBaseTime().Add(10 * time.Minute)
	secondOperation.State = model.OperationRolledBack
	secondOperation.RollbackIntentAt = &rollbackIntentAt
	secondOperation.ObservedRollback = &chainedBefore
	secondOperation.RolledBackAt = &rolledBackAt
	second.RolledBackAt = &rolledBackAt
	value.UnresolvedChangeSets = []string{first.ID}

	historicalStarted := faultBaseTime().Add(6 * time.Minute)
	historicalCompleted := faultBaseTime().Add(7 * time.Minute)
	activeStarted := faultBaseTime().Add(8 * time.Minute)
	value.RollbackAttempts = []model.RollbackAttempt{
		{
			ID:                  "rollback-shared-all",
			Scope:               model.RollbackItem,
			Trigger:             model.RollbackUserRequest,
			RequestedChangeSets: []string{first.ID},
			ExpandedChangeSets:  []string{first.ID, second.ID},
			CascadeApproved:     true,
			Outcome:             model.RollbackFailed,
			StartedAt:           historicalStarted,
			CompletedAt:         &historicalCompleted,
		},
		{
			ID:                  "rollback-shared-active",
			Scope:               model.RollbackItem,
			Trigger:             model.RollbackCrashRecovery,
			RequestedChangeSets: []string{second.ID},
			ExpandedChangeSets:  []string{second.ID},
			StartedAt:           activeStarted,
		},
	}
	value.UpdatedAt = rolledBackAt.Add(time.Minute)
	faultSealJournal(t, value)
	return value
}
