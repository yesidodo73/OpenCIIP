package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	journalpkg "github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
)

func TestRollbackChangeSetTransitionPersistenceFailurePreventsIntentAndRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected change-set rollback-state WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable, _, err := findChangeSet(fixture.harness.state, "change-a")
		if err != nil {
			t.Fatalf("findChangeSet(durable) error = %v", err)
		}
		next, _, err := findChangeSet(candidate, "change-a")
		if err != nil {
			t.Fatalf("findChangeSet(candidate) error = %v", err)
		}
		if durable.State == model.ChangeVerified && next.State == model.ChangeRollingBack {
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodePersistFailed)
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("change-set transition persistence failure caused target mutations: %v", fixture.runtime.mutationCalls)
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeVerified, model.OperationVerified)
	assertRollbackCrashCutLiveState(t, fixture, fixture.after)

	fixture.harness.rejectUpdate = nil
	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedApplied, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedApplied = %v, want [change-a/operation-a]", assessment.ConfirmedApplied)
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("Recover() restored a target without durable change-set rollback state: %v", fixture.runtime.mutationCalls)
	}
	assertRollbackFailureJournal(t, fixture.harness.state, model.ChangeRollbackFailed, model.OperationVerified)
	assertRollbackCrashCutLiveState(t, fixture, fixture.after)
}

func TestRolledBackChangeSetPersistenceFailureRequiresRecoveryWithoutSecondRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rolled-back change-set WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable, _, err := findChangeSet(fixture.harness.state, "change-a")
		if err != nil {
			t.Fatalf("findChangeSet(durable) error = %v", err)
		}
		next, _, err := findChangeSet(candidate, "change-a")
		if err != nil {
			t.Fatalf("findChangeSet(candidate) error = %v", err)
		}
		if durable.State == model.ChangeRollingBack && next.State == model.ChangeRolledBack {
			return persistErr
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
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("mutation calls = %v, want one restore", fixture.runtime.mutationCalls)
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRollingBack, model.OperationRolledBack)
	assertRollbackCrashCutLiveState(t, fixture, fixture.before)

	fixture.harness.rejectUpdate = nil
	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedRolledBack = %v, want [change-a/operation-a]", assessment.ConfirmedRolledBack)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("Recover() repeated the restore: %v", fixture.runtime.mutationCalls)
	}
	assertRecoveredRollbackCrashCut(t, fixture)
}

func TestFailedRollbackResultPersistenceFailureKeepsDurableIntentAndLiveAfter(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	restoreErr := errors.New("injected restore failure before any metadata change")
	fixture.runtime.restore = func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
		return faultCloneSnapshot(fixture.after), restoreErr
	}
	persistErr := errors.New("injected failed rollback-result WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if durable.State == model.OperationRollbackIntentDurable && next.State == model.OperationFailed {
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodePersistFailed)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("mutation calls = %v, want one failed restore call", fixture.runtime.mutationCalls)
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRollingBack, model.OperationRollbackIntentDurable)
	assertRollbackCrashCutLiveState(t, fixture, fixture.after)

	fixture.harness.rejectUpdate = nil
	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedApplied, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedApplied = %v, want [change-a/operation-a]", assessment.ConfirmedApplied)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("Recover() retried a failed restore: %v", fixture.runtime.mutationCalls)
	}
	assertRollbackFailureJournal(t, fixture.harness.state, model.ChangeRollbackFailed, model.OperationRollbackIntentDurable)
	assertRollbackCrashCutLiveState(t, fixture, fixture.after)
}

func TestAmbiguousRollbackResultPersistenceFailureRemainsUnresolved(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	unknown := faultCloneSnapshot(fixture.before)
	unknown.Fingerprint = strings.Repeat("f", 64)
	unknown.File.Inode++
	fixture.runtime.restore = func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
		fixture.live = faultCloneSnapshot(unknown)
		return faultCloneSnapshot(unknown), nil
	}
	persistErr := errors.New("injected ambiguous rollback-result WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if durable.State == model.OperationRollbackIntentDurable && next.State == model.OperationAmbiguous {
			return persistErr
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
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("mutation calls = %v, want one ambiguous restore call", fixture.runtime.mutationCalls)
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRollingBack, model.OperationRollbackIntentDurable)
	assertRollbackCrashCutLiveState(t, fixture, unknown)

	fixture.harness.rejectUpdate = nil
	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !reflect.DeepEqual(assessment.Ambiguous, []string{"change-a/operation-a"}) {
		t.Fatalf("Ambiguous = %v, want [change-a/operation-a]", assessment.Ambiguous)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("Recover() mutated an ambiguous target: %v", fixture.runtime.mutationCalls)
	}
	operation := rollbackCrashCutOperation(t, fixture.harness.state)
	changeSet, _, findErr := findChangeSet(fixture.harness.state, "change-a")
	if findErr != nil {
		t.Fatalf("findChangeSet() error = %v", findErr)
	}
	if fixture.harness.state.State != model.RunRecoveryRequired ||
		changeSet.State != model.ChangeRecoveryRequired ||
		operation.State != model.OperationAmbiguous ||
		operation.RollbackIntentAt == nil ||
		operation.Error == nil ||
		operation.Error.Code != model.JournalErrorRecoveryAmbiguous {
		t.Fatalf("ambiguous rollback lost durable recovery evidence: run=%s change=%#v operation=%#v", fixture.harness.state.State, changeSet, operation)
	}
	if !reflect.DeepEqual(fixture.harness.state.UnresolvedChangeSets, []string{"change-a"}) {
		t.Fatalf("unresolved change sets = %v, want [change-a]", fixture.harness.state.UnresolvedChangeSets)
	}
	assertRollbackCrashCutLiveState(t, fixture, unknown)
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovery-required journal Validate() error = %v", err)
	}
}

func TestRollbackFailureBlocksEntirePredecessorChain(t *testing.T) {
	value := faultVerifiedRollbackChain(t)
	harness := newFaultStoreHarness(t, value)
	live := make(map[string]model.ResourceSnapshot, len(value.ChangeSets))
	backups := make(map[string]string, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		operation := changeSet.Operations[0]
		live[operation.Resource.Key] = faultCloneSnapshot(*operation.ObservedAfter)
		backups[operation.ID] = operation.Backup.ID
	}
	restoreErr := errors.New("injected terminal writer restore failure")
	runtime := &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			snapshot, exists := live[resource.Key]
			if !exists {
				return model.ResourceSnapshot{}, errors.New("unexpected resource capture")
			}
			return faultCloneSnapshot(snapshot), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(_ context.Context, operation model.OperationRecord, artifact model.BackupArtifact) (model.ResourceSnapshot, error) {
			if operation.ID != "operation-c" || artifact.ID != backups[operation.ID] {
				return model.ResourceSnapshot{}, errors.New("blocked predecessor was sent to Restore")
			}
			return faultCloneSnapshot(live[operation.Resource.Key]), restoreErr
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"001", "002"})

	preview, err := manager.PreviewRollbackRun(context.Background(), value.RunID)
	if err != nil {
		t.Fatalf("PreviewRollbackRun() error = %v", err)
	}
	attempt, err := manager.RollbackRun(context.Background(), value.RunID, preview.PreviewDigest, faultUserRollbackBuild())
	if CodeOf(err) != CodeRollbackFailed {
		t.Fatalf("RollbackRun() error = %v, want %s", err, CodeRollbackFailed)
	}
	if !reflect.DeepEqual(attempt.ExpandedChangeSets, []string{"change-c", "change-b", "change-a"}) {
		t.Fatalf("rollback order = %v, want [change-c change-b change-a]", attempt.ExpandedChangeSets)
	}
	if !reflect.DeepEqual(runtime.mutationCalls, []string{"restore:file:/etc/open-ciip-c"}) {
		t.Fatalf("mutation calls = %v, want only terminal writer restore", runtime.mutationCalls)
	}
	assertRollbackChainState(t, harness.state)

	assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedApplied, []string{
		"change-a/operation-a",
		"change-b/operation-b",
		"change-c/operation-c",
	}) {
		t.Fatalf("ConfirmedApplied = %v", assessment.ConfirmedApplied)
	}
	if !reflect.DeepEqual(runtime.mutationCalls, []string{"restore:file:/etc/open-ciip-c"}) {
		t.Fatalf("Recover() mutated blocked predecessor chain: %v", runtime.mutationCalls)
	}
	assertRollbackChainState(t, harness.state)
}

func TestCommittedRollbackResultErrorIsRecognizedWithoutSecondRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	committedErr := errors.New("injected snapshot write failure after WAL commit")
	installCommitThenErrorUpdate(t, fixture.harness, func(previous, candidate *model.RemediationJournal) bool {
		durable := rollbackCrashCutOperation(t, previous)
		next := rollbackCrashCutOperation(t, candidate)
		return durable.State == model.OperationRollbackIntentDurable && next.State == model.OperationRolledBack
	}, committedErr)

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if err != nil {
		t.Fatalf("RollbackItem() error = %v", err)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("mutation calls = %v, want one restore", fixture.runtime.mutationCalls)
	}
	assertRecoveredRollbackCrashCut(t, fixture)
}

func TestCommittedRollbackTerminalErrorIsRecognizedWithoutRecovery(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	committedErr := errors.New("injected terminal snapshot sync failure after WAL commit")
	installCommitThenErrorUpdate(t, fixture.harness, func(previous, candidate *model.RemediationJournal) bool {
		if len(previous.RollbackAttempts) != 1 || len(candidate.RollbackAttempts) != 1 {
			return false
		}
		previousAttempt := previous.RollbackAttempts[0]
		candidateAttempt := candidate.RollbackAttempts[0]
		return previous.State == model.RunRollingBack &&
			previousAttempt.CompletedAt == nil &&
			candidate.State == model.RunRolledBack &&
			candidateAttempt.CompletedAt != nil &&
			candidateAttempt.Outcome == model.RollbackSucceeded
	}, committedErr)

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	attempt, err := fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if err != nil {
		t.Fatalf("RollbackItem() error = %v", err)
	}
	if attempt.Outcome != model.RollbackSucceeded || attempt.CompletedAt == nil {
		t.Fatalf("RollbackItem() attempt = %#v, want durable terminal success", attempt)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("mutation calls = %v, want one restore", fixture.runtime.mutationCalls)
	}
	assertRecoveredRollbackCrashCut(t, fixture)
}

func TestRollbackTerminalPersistenceRetriesWithoutSecondRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected terminal WAL sync failure before commit")
	terminalPersistenceAttempts := 0
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if len(candidate.RollbackAttempts) != 1 || len(fixture.harness.state.RollbackAttempts) != 1 {
			return nil
		}
		durableAttempt := fixture.harness.state.RollbackAttempts[0]
		candidateAttempt := candidate.RollbackAttempts[0]
		if durableAttempt.CompletedAt == nil &&
			candidateAttempt.CompletedAt != nil &&
			candidate.State == model.RunRolledBack {
			terminalPersistenceAttempts++
			if terminalPersistenceAttempts == 1 {
				return persistErr
			}
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	attempt, err := fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
	if err != nil {
		t.Fatalf("RollbackItem() error = %v", err)
	}
	if terminalPersistenceAttempts != 2 {
		t.Fatalf("terminal persistence attempts = %d, want initial attempt and one retry", terminalPersistenceAttempts)
	}
	if attempt.Outcome != model.RollbackSucceeded || attempt.CompletedAt == nil {
		t.Fatalf("RollbackItem() attempt = %#v, want durable terminal success", attempt)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("mutation calls = %v, want one restore", fixture.runtime.mutationCalls)
	}
	assertRecoveredRollbackCrashCut(t, fixture)
}

func TestRecoverFinalizationPersistenceFailureIsReadOnlyAndRetryable(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected recovery finalization WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if len(candidate.RollbackAttempts) != 1 || len(fixture.harness.state.RollbackAttempts) != 1 {
			return nil
		}
		durableAttempt := fixture.harness.state.RollbackAttempts[0]
		nextAttempt := candidate.RollbackAttempts[0]
		if durableAttempt.CompletedAt == nil && nextAttempt.CompletedAt != nil {
			return persistErr
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
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRolledBack, model.OperationRolledBack)
	revisionBeforeRecovery := fixture.harness.state.Revision
	mutationsBeforeRecovery := append([]string(nil), fixture.runtime.mutationCalls...)

	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("Recover() error = %v, want %s", err, CodePersistFailed)
	}
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedRolledBack = %v, want [change-a/operation-a]", assessment.ConfirmedRolledBack)
	}
	if fixture.harness.state.Revision != revisionBeforeRecovery+1 {
		t.Fatalf("failed recovery finalization revision = %d, want one durable observer claim after %d", fixture.harness.state.Revision, revisionBeforeRecovery)
	}
	claimedAttempt := fixture.harness.state.RollbackAttempts[0]
	if claimedAttempt.ObservedByBuild == nil || *claimedAttempt.ObservedByBuild != faultRecoveryObserverBuild() {
		t.Fatalf("failed recovery finalization did not preserve its durable observer claim: %#v", claimedAttempt.ObservedByBuild)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, mutationsBeforeRecovery) {
		t.Fatalf("Recover() mutated the target while finalization persistence failed: before=%v after=%v", mutationsBeforeRecovery, fixture.runtime.mutationCalls)
	}
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRolledBack, model.OperationRolledBack)
	if len(fixture.harness.state.UnresolvedChangeSets) != 0 {
		t.Fatalf("failed finalization invented unresolved scope: %v", fixture.harness.state.UnresolvedChangeSets)
	}

	fixture.harness.rejectUpdate = nil
	assessment, err = fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(retry) error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("Recover(retry) ConfirmedRolledBack = %v", assessment.ConfirmedRolledBack)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, mutationsBeforeRecovery) {
		t.Fatalf("Recover(retry) repeated the restore: before=%v after=%v", mutationsBeforeRecovery, fixture.runtime.mutationCalls)
	}
	assertRecoveredRollbackCrashCut(t, fixture)
}

func TestRecoverRecognizesCommittedTerminalRevisionAfterSnapshotFailure(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if len(candidate.RollbackAttempts) != 1 || len(fixture.harness.state.RollbackAttempts) != 1 {
			return nil
		}
		durableAttempt := fixture.harness.state.RollbackAttempts[0]
		nextAttempt := candidate.RollbackAttempts[0]
		if durableAttempt.CompletedAt == nil && nextAttempt.CompletedAt != nil {
			return errors.New("injected rollback finalization failure before commit")
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
	assertIncompleteRollbackCrashCut(t, fixture.harness.state, model.ChangeRolledBack, model.OperationRolledBack)
	mutationsBeforeRecovery := append([]string(nil), fixture.runtime.mutationCalls...)

	terminalCommitErrors := 0
	installCommitThenErrorUpdate(t, fixture.harness, func(previous, candidate *model.RemediationJournal) bool {
		if len(previous.RollbackAttempts) != 1 || len(candidate.RollbackAttempts) != 1 {
			return false
		}
		previousAttempt := previous.RollbackAttempts[0]
		candidateAttempt := candidate.RollbackAttempts[0]
		committed := previousAttempt.CompletedAt == nil &&
			candidateAttempt.CompletedAt != nil &&
			candidateAttempt.Outcome == model.RollbackSucceeded &&
			candidate.State == model.RunRolledBack
		if committed {
			terminalCommitErrors++
		}
		return committed
	}, errors.New("injected terminal snapshot sync failure after WAL commit"))

	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if terminalCommitErrors != 1 {
		t.Fatalf("terminal commit errors = %d, want 1", terminalCommitErrors)
	}
	if assessment.LastValidRevision != fixture.harness.state.Revision {
		t.Fatalf("assessment revision = %d, want durable revision %d", assessment.LastValidRevision, fixture.harness.state.Revision)
	}
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedRolledBack = %v, want [change-a/operation-a]", assessment.ConfirmedRolledBack)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, mutationsBeforeRecovery) {
		t.Fatalf("Recover() repeated the restore: before=%v after=%v", mutationsBeforeRecovery, fixture.runtime.mutationCalls)
	}
	assertRecoveredRollbackCrashCut(t, fixture)
}

func TestRecoverIsNoOpAfterLoadRepairsTailToNormalTerminal(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	harness := newFaultStoreHarness(t, value)
	load := harness.store.load
	repairedIncompleteTail := false
	harness.store.load = func(ctx context.Context, runID string) (*model.RemediationJournal, error) {
		repairedIncompleteTail = true
		return load(ctx, runID)
	}
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			t.Fatal("Recover captured a target resource for a normal terminal journal")
			return model.ResourceSnapshot{}, errUnscriptedTestCall
		},
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover restored a target resource for a normal terminal journal")
			return model.ResourceSnapshot{}, errUnscriptedTestCall
		},
	}
	manager := newFaultManager(t, harness, runtime, nil)
	revision := harness.state.Revision

	assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if assessment.RunID != value.RunID || assessment.LastValidRevision != revision {
		t.Fatalf("assessment = %#v, want run %q revision %d", assessment, value.RunID, revision)
	}
	if !repairedIncompleteTail {
		t.Fatal("Recover did not use the repairing journal load path")
	}
	if assessment.AutomaticRollbackPossible ||
		len(assessment.ConfirmedApplied) != 0 ||
		len(assessment.ConfirmedRolledBack) != 0 ||
		len(assessment.NotApplied) != 0 ||
		len(assessment.Ambiguous) != 0 ||
		len(assessment.Reasons) != 0 {
		t.Fatalf("normal terminal recovery assessment was not a no-op: %#v", assessment)
	}
	if harness.state.Revision != revision || faultUpdateCallCount(harness.storeCalls) != 0 {
		t.Fatalf("normal terminal recovery changed the journal: revision=%d calls=%v", harness.state.Revision, harness.storeCalls)
	}
	if len(runtime.captureCalls) != 0 || len(runtime.mutationCalls) != 0 {
		t.Fatalf("normal terminal recovery touched target resources: captures=%v mutations=%v", runtime.captureCalls, runtime.mutationCalls)
	}
}

func assertRollbackFailureJournal(
	t *testing.T,
	value *model.RemediationJournal,
	wantChangeState model.ChangeSetState,
	wantOperationState model.OperationState,
) {
	t.Helper()
	if value.State != model.RunRollbackFailed {
		t.Fatalf("run state = %s, want %s", value.State, model.RunRollbackFailed)
	}
	if len(value.RollbackAttempts) != 1 {
		t.Fatalf("rollback attempts = %d, want 1", len(value.RollbackAttempts))
	}
	attempt := value.RollbackAttempts[0]
	if attempt.CompletedAt == nil || attempt.Outcome != model.RollbackFailed {
		t.Fatalf("rollback attempt = %#v, want completed failed attempt", attempt)
	}
	changeSet, _, err := findChangeSet(value, "change-a")
	if err != nil {
		t.Fatalf("findChangeSet() error = %v", err)
	}
	operation := rollbackCrashCutOperation(t, value)
	if changeSet.State != wantChangeState || operation.State != wantOperationState {
		t.Fatalf("rollback failure states = change:%s operation:%s, want change:%s operation:%s", changeSet.State, operation.State, wantChangeState, wantOperationState)
	}
	if !reflect.DeepEqual(value.UnresolvedChangeSets, []string{"change-a"}) {
		t.Fatalf("unresolved change sets = %v, want [change-a]", value.UnresolvedChangeSets)
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("rollback-failed journal Validate() error = %v", err)
	}
}

func faultVerifiedRollbackChain(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultJournalSkeleton(2, false)
	third := faultPlannedChangeSet(1)
	third.ID = "change-c"
	third.RuleID = "U-29"
	third.RuleIdentity.ID = "U-29"
	third.RuleIdentity.Reference.Item = "U-29"
	third.RecipeIdentity.ID = "rocky-u29-file-metadata"
	third.Sequence = 3
	resource := model.CanonicalResource{
		Reference: model.ResourceRef{Kind: model.ResourceFile, ID: "/etc/open-ciip-c"},
		Key:       "file:/etc/open-ciip-c",
	}
	third.Resources = []model.CanonicalResource{resource}
	third.Operations[0].ID = "operation-c"
	third.Operations[0].Resource = resource
	third.Operations[0].ExpectedBefore = faultFileSnapshot(resource, "e", 0o644, faultBaseTime())
	third.Operations[0].Desired = faultFileSnapshot(resource, "f", 0o600, faultBaseTime().Add(time.Minute))
	value.ChangeSets = append(value.ChangeSets, third)
	value.ChangeSets[1].DependsOn = []string{"change-a"}
	value.ChangeSets[2].DependsOn = []string{"change-b"}
	value.ConflictGraph = model.ConflictGraph{
		Nodes: []string{"change-a", "change-b", "change-c"},
		Edges: []model.ConflictEdge{
			{From: "change-a", To: "change-b", Reason: model.ConflictExplicitDependency},
			{From: "change-b", To: "change-c", Reason: model.ConflictExplicitDependency},
		},
	}
	value.State = model.RunCompleted
	value.FailurePolicy = model.FailureRollbackRun
	preparedAt := faultBaseTime().Add(2 * time.Minute)
	intentAt := faultBaseTime().Add(3 * time.Minute)
	appliedAt := faultBaseTime().Add(4 * time.Minute)
	verifiedAt := faultBaseTime().Add(5 * time.Minute)
	for index := range value.ChangeSets {
		changeSet := &value.ChangeSets[index]
		operation := &changeSet.Operations[0]
		observed := faultCloneSnapshot(operation.Desired)
		observed.File.CapturedAt = appliedAt
		changeSet.State = model.ChangeVerified
		changeSet.Before = []model.ResourceSnapshot{operation.ExpectedBefore}
		changeSet.After = []model.ResourceSnapshot{observed}
		changeSet.PreparedAt = &preparedAt
		changeSet.AppliedAt = &appliedAt
		changeSet.VerifiedAt = &verifiedAt
		operation.State = model.OperationVerified
		operation.Before = operation.ExpectedBefore
		operation.ObservedAfter = &observed
		backup := faultBackup([]string{"backup-a", "backup-b", "backup-c"}[index])
		operation.Backup = &backup
		operation.ApplyIntentAt = &intentAt
		operation.AppliedAt = &appliedAt
	}
	faultSealJournal(t, value)
	return value
}

func assertRollbackChainState(t *testing.T, value *model.RemediationJournal) {
	t.Helper()
	if value.State != model.RunRollbackFailed {
		t.Fatalf("run state = %s, want %s", value.State, model.RunRollbackFailed)
	}
	wantStates := map[string]model.ChangeSetState{
		"change-a": model.ChangeRollbackBlocked,
		"change-b": model.ChangeRollbackBlocked,
		"change-c": model.ChangeRollbackFailed,
	}
	for changeSetID, wantState := range wantStates {
		changeSet, _, err := findChangeSet(value, changeSetID)
		if err != nil {
			t.Fatalf("findChangeSet(%s) error = %v", changeSetID, err)
		}
		if changeSet.State != wantState {
			t.Fatalf("%s state = %s, want %s", changeSetID, changeSet.State, wantState)
		}
		if changeSet.Error == nil {
			t.Fatalf("%s has no durable rollback error", changeSetID)
		}
	}
	if !reflect.DeepEqual(value.UnresolvedChangeSets, []string{"change-a", "change-b", "change-c"}) {
		t.Fatalf("unresolved change sets = %v", value.UnresolvedChangeSets)
	}
	if len(value.RollbackAttempts) != 1 {
		t.Fatalf("rollback attempts = %d, want 1", len(value.RollbackAttempts))
	}
	attempt := value.RollbackAttempts[0]
	if attempt.CompletedAt == nil || attempt.Outcome != model.RollbackFailed {
		t.Fatalf("rollback attempt = %#v, want completed failed attempt", attempt)
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("blocked-chain journal Validate() error = %v", err)
	}
}

func installCommitThenErrorUpdate(
	t *testing.T,
	harness *faultStoreHarness,
	shouldFail func(previous, candidate *model.RemediationJournal) bool,
	injected error,
) {
	t.Helper()
	harness.store.update = func(
		_ context.Context,
		runID string,
		expectedRevision uint64,
		mutate func(*model.RemediationJournal) error,
	) (*model.RemediationJournal, error) {
		if runID != harness.state.RunID {
			t.Fatalf("scriptedJournalStore.Update() runID = %q, want %q", runID, harness.state.RunID)
		}
		if expectedRevision != harness.state.Revision {
			t.Fatalf("scriptedJournalStore.Update() revision = %d, want %d", expectedRevision, harness.state.Revision)
		}
		previous := faultCloneJournal(t, harness.state)
		candidate := faultCloneJournal(t, harness.state)
		if err := mutate(candidate); err != nil {
			return nil, err
		}
		candidate.Revision = harness.state.Revision + 1
		updatedAt := harness.state.UpdatedAt.Add(time.Second)
		latestEvent := candidate.LatestEventTime()
		if !updatedAt.After(latestEvent) {
			updatedAt = latestEvent.Add(time.Nanosecond)
		}
		candidate.UpdatedAt = updatedAt
		label := faultUpdateLabel(harness.state, candidate)
		harness.storeCalls = append(harness.storeCalls, "update:"+label)
		harness.events = append(harness.events, "store:update:"+label)
		if err := candidate.Validate(); err != nil {
			t.Fatalf("scriptedJournalStore candidate %q Validate() error = %v", label, err)
		}
		harness.lastCandidate = faultCloneJournal(t, candidate)
		harness.state = faultCloneJournal(t, candidate)
		if shouldFail(previous, candidate) {
			return nil, &journalpkg.Error{
				Code:      journalpkg.CodePersistFailed,
				Operation: "sync committed journal snapshot",
				RunID:     runID,
				Committed: true,
				Err:       injected,
			}
		}
		return faultCloneJournal(t, candidate), nil
	}
}
