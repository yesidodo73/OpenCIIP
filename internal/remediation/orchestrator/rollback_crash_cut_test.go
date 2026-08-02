package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestRollbackAttemptPersistenceFailurePreventsRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rollback-attempt WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		if len(candidate.RollbackAttempts) > len(fixture.harness.state.RollbackAttempts) {
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodePersistFailed)
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("rollback-attempt persistence failure caused target mutations: %v", fixture.runtime.mutationCalls)
	}
	if fixture.harness.state.State != model.RunCompleted || len(fixture.harness.state.RollbackAttempts) != 0 {
		t.Fatalf(
			"durable journal changed after rejected rollback attempt: state=%s attempts=%d",
			fixture.harness.state.State,
			len(fixture.harness.state.RollbackAttempts),
		)
	}
	assertRollbackCrashCutLiveState(t, fixture, fixture.after)
	if fixture.harness.rejectedCandidate == nil ||
		fixture.harness.rejectedCandidate.State != model.RunRollingBack ||
		len(fixture.harness.rejectedCandidate.RollbackAttempts) != 1 {
		t.Fatalf("rejected rollback-attempt candidate = %#v", fixture.harness.rejectedCandidate)
	}
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("durable journal Validate() error = %v", err)
	}
}

func TestRollbackIntentPersistenceFailureRecoversAsFailedWithoutRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rollback-intent WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if durable.State != model.OperationRollbackIntentDurable &&
			next.State == model.OperationRollbackIntentDurable {
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodePersistFailed)
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("rollback-intent persistence failure caused target mutations: %v", fixture.runtime.mutationCalls)
	}
	assertIncompleteRollbackCrashCut(
		t,
		fixture.harness.state,
		model.ChangeRollingBack,
		model.OperationVerified,
	)
	assertUserRollbackAttemptProvenance(t, fixture.harness.state.RollbackAttempts[0], false)
	assertRollbackCrashCutLiveState(t, fixture, fixture.after)

	fixture.harness.rejectUpdate = nil
	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedApplied, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedApplied = %v, want [change-a/operation-a]", assessment.ConfirmedApplied)
	}
	if len(assessment.ConfirmedRolledBack) != 0 {
		t.Fatalf("ConfirmedRolledBack = %v, want none", assessment.ConfirmedRolledBack)
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("Recover() restored a target after rejected rollback intent: %v", fixture.runtime.mutationCalls)
	}
	assertRollbackCrashCutLiveState(t, fixture, fixture.after)
	if fixture.harness.state.State != model.RunRollbackFailed {
		t.Fatalf("recovered run state = %s, want %s", fixture.harness.state.State, model.RunRollbackFailed)
	}
	changeSet, _, findErr := findChangeSet(fixture.harness.state, "change-a")
	if findErr != nil {
		t.Fatalf("findChangeSet() error = %v", findErr)
	}
	if changeSet.State != model.ChangeRollbackFailed {
		t.Fatalf("recovered change-set state = %s, want %s", changeSet.State, model.ChangeRollbackFailed)
	}
	attempt := fixture.harness.state.RollbackAttempts[0]
	if attempt.CompletedAt == nil || attempt.Outcome != model.RollbackFailed {
		t.Fatalf("recovered rollback attempt = %#v", attempt)
	}
	assertUserRollbackAttemptProvenance(t, attempt, true)
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovered journal Validate() error = %v", err)
	}
}

func TestRecoverStartsFreshAttemptAfterRejectedRollbackIntentAndLaterExternalRestore(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rollback-intent WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if durable.State != model.OperationRollbackIntentDurable &&
			next.State == model.OperationRollbackIntentDurable {
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodePersistFailed)
	}

	fixture.harness.rejectUpdate = nil
	if _, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild()); err != nil {
		t.Fatalf("Recover(after-state) error = %v", err)
	}
	assertRollbackFailureJournal(t, fixture.harness.state, model.ChangeRollbackFailed, model.OperationVerified)
	originalAttempt := fixture.harness.state.RollbackAttempts[0]
	if originalAttempt.CompletedAt == nil {
		t.Fatal("first recovery did not complete the failed rollback attempt")
	}

	fixture.live = faultCloneSnapshot(fixture.before)
	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(before-state) error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("ConfirmedRolledBack = %v, want [change-a/operation-a]", assessment.ConfirmedRolledBack)
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("Recover() mutated a target restored outside the process: %v", fixture.runtime.mutationCalls)
	}
	if len(fixture.harness.state.RollbackAttempts) != 2 {
		t.Fatalf("rollback attempts = %d, want immutable failed attempt and fresh recovery attempt", len(fixture.harness.state.RollbackAttempts))
	}
	if !reflect.DeepEqual(fixture.harness.state.RollbackAttempts[0], originalAttempt) {
		t.Fatal("second recovery changed the completed failed rollback attempt")
	}
	recoveryAttempt := fixture.harness.state.RollbackAttempts[1]
	if recoveryAttempt.Trigger != model.RollbackCrashRecovery ||
		recoveryAttempt.CompletedAt == nil ||
		recoveryAttempt.Outcome != model.RollbackSucceeded {
		t.Fatalf("fresh recovery attempt = %#v, want completed crash-recovery success", recoveryAttempt)
	}
	assertCrashRecoveryAttemptProvenance(t, recoveryAttempt)
	operation := rollbackCrashCutOperation(t, fixture.harness.state)
	if operation.RollbackIntentAt == nil ||
		operation.RollbackIntentAt.Before(recoveryAttempt.StartedAt) ||
		operation.RollbackIntentAt.After(*recoveryAttempt.CompletedAt) {
		t.Fatalf("rollback intent %v is outside fresh recovery attempt [%s, %v]", operation.RollbackIntentAt, recoveryAttempt.StartedAt, recoveryAttempt.CompletedAt)
	}
	assertRollbackCrashCutLiveState(t, fixture, fixture.before)
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovered journal Validate() error = %v", err)
	}
}

func TestRecoverReusesCommittedFreshAttemptAfterPersistenceError(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rollback-intent WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if durable.State != model.OperationRollbackIntentDurable &&
			next.State == model.OperationRollbackIntentDurable {
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodePersistFailed)
	}

	fixture.harness.rejectUpdate = nil
	if _, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild()); err != nil {
		t.Fatalf("Recover(after-state) error = %v", err)
	}
	assertRollbackFailureJournal(t, fixture.harness.state, model.ChangeRollbackFailed, model.OperationVerified)
	originalAttempt := fixture.harness.state.RollbackAttempts[0]
	fixture.live = faultCloneSnapshot(fixture.before)

	commitErrors := 0
	installCommitThenErrorUpdate(t, fixture.harness, func(previous, candidate *model.RemediationJournal) bool {
		committed := len(previous.RollbackAttempts) == 1 &&
			len(candidate.RollbackAttempts) == 2 &&
			candidate.RollbackAttempts[1].Trigger == model.RollbackCrashRecovery &&
			candidate.RollbackAttempts[1].CompletedAt == nil &&
			candidate.State == model.RunRollingBack
		if committed {
			commitErrors++
		}
		return committed
	}, errors.New("injected crash-recovery attempt snapshot failure after WAL commit"))

	_, err = fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("Recover(first before-state) error = %v, want %s", err, CodePersistFailed)
	}
	if commitErrors != 1 {
		t.Fatalf("committed fresh-attempt errors = %d, want 1", commitErrors)
	}
	if len(fixture.harness.state.RollbackAttempts) != 2 {
		t.Fatalf("durable rollback attempts = %d, want failed attempt and incomplete recovery attempt", len(fixture.harness.state.RollbackAttempts))
	}
	durableRecoveryAttempt := fixture.harness.state.RollbackAttempts[1]
	if durableRecoveryAttempt.CompletedAt != nil || durableRecoveryAttempt.Trigger != model.RollbackCrashRecovery {
		t.Fatalf("durable fresh recovery attempt = %#v", durableRecoveryAttempt)
	}
	assertCrashRecoveryAttemptProvenance(t, durableRecoveryAttempt)
	if rollbackCrashCutOperation(t, fixture.harness.state).RollbackIntentAt != nil {
		t.Fatal("rollback intent was recorded after fresh-attempt persistence returned an error")
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("Recover() mutated a target restored outside the process: %v", fixture.runtime.mutationCalls)
	}

	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(retry) error = %v", err)
	}
	if !reflect.DeepEqual(assessment.ConfirmedRolledBack, []string{"change-a/operation-a"}) {
		t.Fatalf("Recover(retry) ConfirmedRolledBack = %v, want [change-a/operation-a]", assessment.ConfirmedRolledBack)
	}
	if len(fixture.harness.state.RollbackAttempts) != 2 {
		t.Fatalf("Recover(retry) created a duplicate attempt: %d", len(fixture.harness.state.RollbackAttempts))
	}
	if !reflect.DeepEqual(fixture.harness.state.RollbackAttempts[0], originalAttempt) {
		t.Fatal("Recover(retry) changed the completed failed rollback attempt")
	}
	recoveryAttempt := fixture.harness.state.RollbackAttempts[1]
	if recoveryAttempt.ID != durableRecoveryAttempt.ID ||
		!recoveryAttempt.StartedAt.Equal(durableRecoveryAttempt.StartedAt) ||
		recoveryAttempt.CompletedAt == nil ||
		recoveryAttempt.Outcome != model.RollbackSucceeded {
		t.Fatalf("Recover(retry) recovery attempt = %#v, want same durable attempt completed successfully", recoveryAttempt)
	}
	assertCrashRecoveryAttemptProvenance(t, recoveryAttempt)
	revision := fixture.harness.state.Revision
	if _, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild()); err != nil {
		t.Fatalf("Recover(terminal retry) error = %v", err)
	}
	if fixture.harness.state.Revision != revision || len(fixture.harness.state.RollbackAttempts) != 2 {
		t.Fatalf("terminal retry changed the journal: revision=%d attempts=%d", fixture.harness.state.Revision, len(fixture.harness.state.RollbackAttempts))
	}
	if len(fixture.runtime.mutationCalls) != 0 {
		t.Fatalf("recovery retries mutated the target: %v", fixture.runtime.mutationCalls)
	}
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovered journal Validate() error = %v", err)
	}
}

func TestRollbackResultPersistenceFailureFailsClosedThenReconcilesFromLiveBeforeState(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rolled-back operation WAL sync failure")
	resultPersistenceAttempts := 0
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if durable.State == model.OperationRollbackIntentDurable &&
			next.State == model.OperationRolledBack {
			resultPersistenceAttempts++
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRecoveryRequired)
	}
	var orchestrationError *Error
	if !errors.As(err, &orchestrationError) || !orchestrationError.Committed {
		t.Fatalf("RollbackItem() error = %#v, want Committed=true", orchestrationError)
	}
	if resultPersistenceAttempts != 2 {
		t.Fatalf("rolled-back result persistence attempts = %d, want initial attempt and one retry", resultPersistenceAttempts)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("mutation calls = %v, want one restore", fixture.runtime.mutationCalls)
	}
	assertIncompleteRollbackCrashCut(
		t,
		fixture.harness.state,
		model.ChangeRollingBack,
		model.OperationRollbackIntentDurable,
	)
	assertUserRollbackAttemptProvenance(t, fixture.harness.state.RollbackAttempts[0], false)
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
	assertUserRollbackAttemptProvenance(t, fixture.harness.state.RollbackAttempts[0], true)
}

func TestRollbackResultPersistenceFailureWithUnknownLiveStateRequiresRecovery(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rolled-back operation WAL sync failure")
	fixture.harness.rejectUpdate = func(_ string, candidate *model.RemediationJournal) error {
		durable := rollbackCrashCutOperation(t, fixture.harness.state)
		next := rollbackCrashCutOperation(t, candidate)
		if durable.State == model.OperationRollbackIntentDurable &&
			next.State == model.OperationRolledBack {
			return persistErr
		}
		return nil
	}

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem() error = %v", err)
	}
	_, err = fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRecoveryRequired)
	}
	var orchestrationError *Error
	if !errors.As(err, &orchestrationError) || !orchestrationError.Committed {
		t.Fatalf("RollbackItem() error = %#v, want Committed=true", orchestrationError)
	}
	assertIncompleteRollbackCrashCut(
		t,
		fixture.harness.state,
		model.ChangeRollingBack,
		model.OperationRollbackIntentDurable,
	)
	assertUserRollbackAttemptProvenance(t, fixture.harness.state.RollbackAttempts[0], false)
	assertRollbackCrashCutLiveState(t, fixture, fixture.before)

	unknown := faultCloneSnapshot(fixture.before)
	unknown.Fingerprint = strings.Repeat("f", 64)
	unknown.File.Inode++
	fixture.live = unknown
	fixture.harness.rejectUpdate = nil
	assessment, err := fixture.manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !reflect.DeepEqual(assessment.Ambiguous, []string{"change-a/operation-a"}) {
		t.Fatalf("Ambiguous = %v, want [change-a/operation-a]", assessment.Ambiguous)
	}
	if len(assessment.ConfirmedRolledBack) != 0 {
		t.Fatalf("ConfirmedRolledBack = %v, want none", assessment.ConfirmedRolledBack)
	}
	if !reflect.DeepEqual(fixture.runtime.mutationCalls, []string{"restore:" + fixture.resource.Key}) {
		t.Fatalf("Recover() mutated an ambiguous target: %v", fixture.runtime.mutationCalls)
	}
	if fixture.harness.state.State != model.RunRecoveryRequired {
		t.Fatalf("recovered run state = %s, want %s", fixture.harness.state.State, model.RunRecoveryRequired)
	}
	changeSet, _, findErr := findChangeSet(fixture.harness.state, "change-a")
	if findErr != nil {
		t.Fatalf("findChangeSet() error = %v", findErr)
	}
	operation := rollbackCrashCutOperation(t, fixture.harness.state)
	if changeSet.State != model.ChangeRecoveryRequired ||
		operation.State != model.OperationAmbiguous ||
		operation.RollbackIntentAt == nil ||
		operation.Error == nil ||
		operation.Error.Code != model.JournalErrorRecoveryAmbiguous {
		t.Fatalf("ambiguous rollback was promoted or lost evidence: change=%#v operation=%#v", changeSet, operation)
	}
	if !reflect.DeepEqual(fixture.harness.state.UnresolvedChangeSets, []string{"change-a"}) {
		t.Fatalf("unresolved change sets = %v, want [change-a]", fixture.harness.state.UnresolvedChangeSets)
	}
	assertRollbackCrashCutLiveState(t, fixture, unknown)
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovery-required journal Validate() error = %v", err)
	}
}

func TestRollbackTerminalPersistenceFailureKeepsResultEvidenceForRecovery(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	persistErr := errors.New("injected rollback terminal WAL sync failure")
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
	_, err = fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

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
	assertIncompleteRollbackCrashCut(
		t,
		fixture.harness.state,
		model.ChangeRolledBack,
		model.OperationRolledBack,
	)
	assertUserRollbackAttemptProvenance(t, fixture.harness.state.RollbackAttempts[0], false)
	operation := rollbackCrashCutOperation(t, fixture.harness.state)
	if operation.ObservedRollback == nil || operation.RolledBackAt == nil ||
		!exactEqual(operation.Before, *operation.ObservedRollback) {
		t.Fatalf("durable rollback result evidence = %#v", operation)
	}
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
	assertUserRollbackAttemptProvenance(t, fixture.harness.state.RollbackAttempts[0], true)
}

type rollbackCrashCutFixture struct {
	harness  *faultStoreHarness
	runtime  *scriptedFileRuntime
	manager  *Manager
	resource model.CanonicalResource
	before   model.ResourceSnapshot
	after    model.ResourceSnapshot
	live     model.ResourceSnapshot
}

func newRollbackCrashCutFixture(t *testing.T, value *model.RemediationJournal) *rollbackCrashCutFixture {
	t.Helper()
	operation := value.ChangeSets[0].Operations[0]
	if operation.ObservedAfter == nil || operation.Backup == nil {
		t.Fatal("verified rollback crash-cut fixture lacks after observation or backup")
	}
	fixture := &rollbackCrashCutFixture{
		harness:  newFaultStoreHarness(t, value),
		resource: operation.Resource,
		before:   faultCloneSnapshot(operation.Before),
		after:    faultCloneSnapshot(*operation.ObservedAfter),
		live:     faultCloneSnapshot(*operation.ObservedAfter),
	}
	fixture.runtime = &scriptedFileRuntime{
		capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
			if resource.Key != fixture.resource.Key {
				return model.ResourceSnapshot{}, errors.New("unexpected resource capture")
			}
			return faultCloneSnapshot(fixture.live), nil
		},
		verifyBackup: func(_ context.Context, artifact model.BackupArtifact) error {
			if artifact.ID != operation.Backup.ID {
				return errors.New("unexpected backup artifact")
			}
			return nil
		},
		restore: func(_ context.Context, restoredOperation model.OperationRecord, artifact model.BackupArtifact) (model.ResourceSnapshot, error) {
			if restoredOperation.ID != operation.ID || artifact.ID != operation.Backup.ID {
				return model.ResourceSnapshot{}, errors.New("unexpected restore request")
			}
			fixture.live = faultCloneSnapshot(fixture.before)
			return faultCloneSnapshot(fixture.live), nil
		},
	}
	fixture.manager = newFaultManager(t, fixture.harness, fixture.runtime, []string{"001", "002"})
	return fixture
}

func rollbackCrashCutOperation(t *testing.T, value *model.RemediationJournal) *model.OperationRecord {
	t.Helper()
	operation, _, _, err := findOperation(value, "change-a", "operation-a")
	if err != nil {
		t.Fatalf("findOperation() error = %v", err)
	}
	return operation
}

func assertIncompleteRollbackCrashCut(
	t *testing.T,
	value *model.RemediationJournal,
	wantChangeState model.ChangeSetState,
	wantOperationState model.OperationState,
) {
	t.Helper()
	if value.State != model.RunRollingBack {
		t.Fatalf("run state at crash cut = %s, want %s", value.State, model.RunRollingBack)
	}
	if len(value.RollbackAttempts) != 1 {
		t.Fatalf("rollback attempts at crash cut = %d, want 1", len(value.RollbackAttempts))
	}
	attempt := value.RollbackAttempts[0]
	if attempt.CompletedAt != nil || attempt.Outcome != "" {
		t.Fatalf("rollback attempt was ambiguously promoted to terminal success: %#v", attempt)
	}
	changeSet, _, err := findChangeSet(value, "change-a")
	if err != nil {
		t.Fatalf("findChangeSet() error = %v", err)
	}
	if changeSet.State != wantChangeState {
		t.Fatalf("change-set state at crash cut = %s, want %s", changeSet.State, wantChangeState)
	}
	operation := rollbackCrashCutOperation(t, value)
	if operation.State != wantOperationState {
		t.Fatalf("operation state at crash cut = %s, want %s", operation.State, wantOperationState)
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("crash-cut journal Validate() error = %v", err)
	}
}

func assertRollbackCrashCutLiveState(
	t *testing.T,
	fixture *rollbackCrashCutFixture,
	want model.ResourceSnapshot,
) {
	t.Helper()
	if !exactEqual(want, fixture.live) {
		t.Fatalf("live resource state does not match the expected crash-cut observation")
	}
}

func assertRecoveredRollbackCrashCut(t *testing.T, fixture *rollbackCrashCutFixture) {
	t.Helper()
	if fixture.harness.state.State != model.RunRolledBack {
		t.Fatalf("recovered run state = %s, want %s", fixture.harness.state.State, model.RunRolledBack)
	}
	changeSet, _, err := findChangeSet(fixture.harness.state, "change-a")
	if err != nil {
		t.Fatalf("findChangeSet() error = %v", err)
	}
	if changeSet.State != model.ChangeRolledBack || changeSet.RolledBackAt == nil {
		t.Fatalf("recovered change set = %#v", changeSet)
	}
	operation := rollbackCrashCutOperation(t, fixture.harness.state)
	if operation.State != model.OperationRolledBack ||
		operation.ObservedRollback == nil ||
		operation.RolledBackAt == nil ||
		!exactEqual(operation.Before, *operation.ObservedRollback) {
		t.Fatalf("recovered operation = %#v", operation)
	}
	if len(fixture.harness.state.RollbackAttempts) != 1 {
		t.Fatalf("rollback attempts after recovery = %d, want 1", len(fixture.harness.state.RollbackAttempts))
	}
	attempt := fixture.harness.state.RollbackAttempts[0]
	if attempt.CompletedAt == nil || attempt.Outcome != model.RollbackSucceeded {
		t.Fatalf("recovered rollback attempt = %#v", attempt)
	}
	assertRollbackCrashCutLiveState(t, fixture, fixture.before)
	if err := fixture.harness.state.Validate(); err != nil {
		t.Fatalf("recovered journal Validate() error = %v", err)
	}
}

func assertUserRollbackAttemptProvenance(t *testing.T, attempt model.RollbackAttempt, recovered bool) {
	t.Helper()
	executor := faultUserRollbackBuild()
	if attempt.ExecutorBuild == nil || *attempt.ExecutorBuild != executor {
		t.Fatalf("user rollback executor provenance = %#v, want %#v", attempt.ExecutorBuild, executor)
	}
	observer := faultRecoveryObserverBuild()
	if recovered {
		if attempt.ObservedByBuild == nil || *attempt.ObservedByBuild != observer {
			t.Fatalf("recovered user rollback observer provenance = %#v, want %#v", attempt.ObservedByBuild, observer)
		}
		return
	}
	if attempt.ObservedByBuild != nil {
		t.Fatalf("unrecovered user rollback observer provenance = %#v, want nil", attempt.ObservedByBuild)
	}
}

func assertCrashRecoveryAttemptProvenance(t *testing.T, attempt model.RollbackAttempt) {
	t.Helper()
	observer := faultRecoveryObserverBuild()
	if attempt.ExecutorBuild != nil ||
		attempt.ObservedByBuild == nil ||
		*attempt.ObservedByBuild != observer {
		t.Fatalf(
			"crash recovery provenance = executor %#v observer %#v, want observer %#v only",
			attempt.ExecutorBuild,
			attempt.ObservedByBuild,
			observer,
		)
	}
}
