package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
)

const applyCleanupTimeout = 15 * time.Minute

func newApplyCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), applyCleanupTimeout)
}

func (m *Manager) reloadApplyJournal(parent context.Context, runID, stage string, stageErr error) (*model.RemediationJournal, error) {
	reloadContext, cancelReload := newApplyCleanupContext(parent)
	defer cancelReload()
	value, err := m.loadAndVerifyReadOnly(reloadContext, runID)
	if err != nil {
		return nil, &Error{Code: CodeRecoveryRequired, Operation: stage, RunID: runID, Committed: true, Err: fmt.Errorf("stage error: %v; durable journal reload failed: %w", stageErr, err)}
	}
	return value, nil
}

func applyJournalReloadRequired(err error) bool {
	switch CodeOf(err) {
	case CodePersistFailed, CodeRevisionConflict, CodeLockUnavailable, CodeInvalidState:
		return true
	default:
		return false
	}
}

func (m *Manager) updateBeforeAutomaticRollback(
	parent context.Context,
	current *model.RemediationJournal,
	operation string,
	mutate func(*model.RemediationJournal) error,
	persisted func(*model.RemediationJournal) bool,
) (*model.RemediationJournal, error) {
	if current == nil || mutate == nil || persisted == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: operation, Err: fmt.Errorf("current journal, mutation, and persistence predicate are required")}
	}
	next, err := m.update(parent, current, operation, mutate)
	if err == nil {
		return next, nil
	}
	firstErr := err
	latest, reloadErr := m.reloadApplyJournal(parent, current.RunID, "reload after "+operation, firstErr)
	if reloadErr != nil {
		return nil, reloadErr
	}
	if persisted(latest) {
		return latest, nil
	}

	retryContext, cancelRetry := newApplyCleanupContext(parent)
	next, retryErr := m.update(retryContext, latest, "retry "+operation, mutate)
	cancelRetry()
	if retryErr == nil {
		return next, nil
	}
	afterRetry, retryReloadErr := m.reloadApplyJournal(parent, current.RunID, "reload after retry "+operation, retryErr)
	if retryReloadErr != nil {
		return nil, retryReloadErr
	}
	if persisted(afterRetry) {
		return afterRetry, nil
	}
	return nil, &Error{
		Code:      CodeRecoveryRequired,
		Operation: operation,
		RunID:     current.RunID,
		Committed: true,
		Err:       fmt.Errorf("automatic rollback annotation was not durably confirmed: initial error: %v; retry error: %w", firstErr, retryErr),
	}
}

func journalErrorMatches(actual *model.JournalError, expected model.JournalError) bool {
	if actual == nil || actual.Code != expected.Code || actual.Phase != expected.Phase ||
		actual.ChangeSetID != expected.ChangeSetID || actual.OperationID != expected.OperationID ||
		actual.Message != expected.Message || actual.Retryable != expected.Retryable ||
		!actual.OccurredAt.Equal(expected.OccurredAt) || (actual.Resource == nil) != (expected.Resource == nil) {
		return false
	}
	return actual.Resource == nil || *actual.Resource == *expected.Resource
}

func (m *Manager) ApplyWithVerifier(ctx context.Context, runID string, guard ApplyGuard, verifier ApplyVerifier) error {
	if guard == nil || verifier == nil {
		return &Error{Code: CodeInvalidInput, Operation: "apply with verifier", RunID: runID, Err: fmt.Errorf("guard and verifier are required")}
	}
	return m.apply(ctx, runID, guard, verifier)
}

func (m *Manager) apply(ctx context.Context, runID string, guard ApplyGuard, verifier ApplyVerifier) error {
	lock, err := m.acquire(ctx, "apply")
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := m.ensureNoOtherRecoverable(ctx, runID); err != nil {
		return err
	}
	value, err := m.loadAndVerifyReadOnly(ctx, runID)
	if err != nil {
		return err
	}
	if value.State != model.RunApproved {
		return &Error{Code: CodeInvalidState, Operation: "apply", RunID: runID, Err: fmt.Errorf("run is %s, not approved", value.State)}
	}
	for _, changeSet := range value.ChangeSets {
		if changeSet.Approval == nil {
			return &Error{Code: CodeInvalidState, Operation: "apply", RunID: runID, ChangeSetID: changeSet.ID, Err: fmt.Errorf("change set has no approval")}
		}
		if err := changeSet.Approval.Validate(value.PlanDigest); err != nil {
			return &Error{Code: CodeInvalidState, Operation: "apply", RunID: runID, ChangeSetID: changeSet.ID, Err: err}
		}
		for _, operation := range changeSet.Operations {
			if operation.Kind != model.OperationFileMetadata {
				return &Error{Code: CodeUnsupportedOperation, Operation: "apply", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("only regular-file metadata remediation is supported")}
			}
		}
	}
	if err := guard(ctx, value); err != nil {
		return &Error{Code: CodePreconditionFailed, Operation: "apply execution gate", RunID: runID, Err: err}
	}
	handler, err := m.fileHandler(runID)
	if err != nil {
		return err
	}
	value, err = m.update(ctx, value, "start apply", func(next *model.RemediationJournal) error {
		next.State = model.RunApplying
		return nil
	})
	if err != nil {
		return err
	}
	changeSetIDs := make([]string, 0, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		changeSetIDs = append(changeSetIDs, changeSet.ID)
	}
	for _, changeSetID := range changeSetIDs {
		value, err = m.prepareChangeSet(ctx, value, handler, changeSetID)
		if err != nil {
			if CodeOf(err) == CodeRevisionConflict || CodeOf(err) == CodePersistFailed || CodeOf(err) == CodeInvalidState {
				return err
			}
			cleanupContext, cancelCleanup := newApplyCleanupContext(ctx)
			failureErr := m.failBeforeSideEffect(cleanupContext, value, changeSetID, err)
			cancelCleanup()
			return failureErr
		}
		prepared := value
		value, err = m.update(ctx, prepared, "start change set apply", func(next *model.RemediationJournal) error {
			changeSet, _, findErr := findChangeSet(next, changeSetID)
			if findErr != nil {
				return findErr
			}
			changeSet.State = model.ChangeApplying
			return nil
		})
		if err != nil {
			if CodeOf(err) == CodeLockUnavailable {
				cleanupContext, cancelCleanup := newApplyCleanupContext(ctx)
				failureErr := m.failBeforeSideEffect(cleanupContext, prepared, changeSetID, err)
				cancelCleanup()
				return failureErr
			}
			return err
		}
		operationIDs := orderedOperationIDs(value, changeSetID, false)
		for _, operationID := range operationIDs {
			var applyFailure error
			value, applyFailure = m.applyOperation(ctx, value, handler, changeSetID, operationID)
			if applyFailure != nil {
				if value == nil || applyJournalReloadRequired(applyFailure) {
					value, err = m.reloadApplyJournal(ctx, runID, "reload after apply operation failure", applyFailure)
					if err != nil {
						return err
					}
				}
				if value.State == model.RunRecoveryRequired || CodeOf(applyFailure) == CodeRecoveryRequired {
					return applyFailure
				}
				if !hasRollbackWork(value, changeSetID) {
					cleanupContext, cancelCleanup := newApplyCleanupContext(ctx)
					failureErr := m.failBeforeSideEffect(cleanupContext, value, changeSetID, applyFailure)
					cancelCleanup()
					return failureErr
				}
				cleanupContext, cancelCleanup := newApplyCleanupContext(ctx)
				rollbackErr := m.rollbackForFailure(cleanupContext, value, changeSetID, applyFailure, model.RollbackApplyFailure)
				cancelCleanup()
				if rollbackErr != nil {
					return rollbackErr
				}
				return applyFailure
			}
		}
		cleanupContext, cancelCleanup := newApplyCleanupContext(ctx)
		value, err = m.finishChangeSet(cleanupContext, value, handler, changeSetID)
		cancelCleanup()
		if err != nil {
			stageErr := err
			if value == nil || applyJournalReloadRequired(stageErr) {
				var reloadErr error
				value, reloadErr = m.reloadApplyJournal(ctx, runID, "reload after change-set verification failure", stageErr)
				if reloadErr != nil {
					return reloadErr
				}
			}
			if CodeOf(stageErr) == CodeRecoveryRequired || value.State == model.RunRecoveryRequired {
				return stageErr
			}
			rollbackContext, cancelRollback := newApplyCleanupContext(ctx)
			rollbackErr := m.rollbackForFailure(rollbackContext, value, changeSetID, stageErr, model.RollbackVerifyFailure)
			cancelRollback()
			if rollbackErr != nil {
				return rollbackErr
			}
			return stageErr
		}
		itemVerifierContext, cancelItemVerifier := newApplyCleanupContext(ctx)
		failedChangeSets, verificationErr := verifier(itemVerifierContext, value, []string{changeSetID})
		cancelItemVerifier()
		if verificationErr != nil {
			rollbackContext, cancelRollback := newApplyCleanupContext(ctx)
			rollbackErr := m.rollbackVerificationFailureLocked(rollbackContext, value, failedChangeSets, verificationErr, false)
			cancelRollback()
			if rollbackErr != nil {
				return &Error{Code: CodeVerificationFailed, Operation: "change-set evaluator verification and rollback", RunID: runID, ChangeSetID: changeSetID, Committed: true, Err: fmt.Errorf("verification error: %v; rollback error: %w", verificationErr, rollbackErr)}
			}
			return &Error{Code: CodeVerificationFailed, Operation: "change-set evaluator verification", RunID: runID, ChangeSetID: changeSetID, Committed: true, Err: fmt.Errorf("automatic rollback completed: %w", verificationErr)}
		}
		completionContext, cancelCompletion := newApplyCleanupContext(ctx)
		value, err = m.completeChangeSetVerification(completionContext, value, changeSetID)
		cancelCompletion()
		if err != nil {
			stageErr := err
			latest, reloadErr := m.reloadApplyJournal(ctx, runID, "reload after evaluator verification persistence failure", stageErr)
			if reloadErr != nil {
				return reloadErr
			}
			currentChangeSet, _, findErr := findChangeSet(latest, changeSetID)
			if findErr != nil {
				return &Error{Code: CodeRecoveryRequired, Operation: "resume evaluator verification persistence", RunID: runID, ChangeSetID: changeSetID, Err: findErr}
			}
			switch currentChangeSet.State {
			case model.ChangeVerified:
				value = latest
			case model.ChangeVerifying:
				retryContext, cancelRetry := newApplyCleanupContext(ctx)
				value, err = m.completeChangeSetVerification(retryContext, latest, changeSetID)
				cancelRetry()
				if err != nil {
					retryErr := err
					afterRetry, retryReloadErr := m.reloadApplyJournal(ctx, runID, "reload after evaluator verification persistence retry", retryErr)
					if retryReloadErr != nil {
						return retryReloadErr
					}
					afterRetryChangeSet, _, retryFindErr := findChangeSet(afterRetry, changeSetID)
					if retryFindErr != nil {
						return &Error{Code: CodeRecoveryRequired, Operation: "resume evaluator verification persistence", RunID: runID, ChangeSetID: changeSetID, Err: retryFindErr}
					}
					if afterRetryChangeSet.State == model.ChangeVerified {
						value = afterRetry
						break
					}
					rollbackContext, cancelRollback := newApplyCleanupContext(ctx)
					rollbackErr := m.rollbackForFailure(rollbackContext, afterRetry, changeSetID, retryErr, model.RollbackVerifyFailure)
					cancelRollback()
					if rollbackErr != nil {
						return rollbackErr
					}
					return stageErr
				}
			default:
				return &Error{Code: CodeRecoveryRequired, Operation: "resume evaluator verification persistence", RunID: runID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set is %s after persistence failure", currentChangeSet.State)}
			}
		}
	}
	runStateContext, cancelRunState := newApplyCleanupContext(ctx)
	beforeRunVerification := value
	value, err = m.update(runStateContext, beforeRunVerification, "start run verification", func(next *model.RemediationJournal) error {
		next.State = model.RunVerifying
		return nil
	})
	cancelRunState()
	if err != nil {
		stageErr := err
		latest, reloadErr := m.reloadApplyJournal(ctx, runID, "reload after run verification state failure", stageErr)
		if reloadErr != nil {
			return reloadErr
		}
		switch latest.State {
		case model.RunVerifying:
			value = latest
		case model.RunApplying:
			rollbackContext, cancelRollback := newApplyCleanupContext(ctx)
			rollbackErr := m.rollbackVerificationFailureLocked(rollbackContext, latest, changeSetIDs, stageErr, true)
			cancelRollback()
			if rollbackErr != nil {
				return rollbackErr
			}
			return stageErr
		default:
			return &Error{Code: CodeRecoveryRequired, Operation: "resume run verification state", RunID: runID, Err: fmt.Errorf("run is %s after persistence failure", latest.State)}
		}
	}
	runVerificationContext, cancelRunVerification := newApplyCleanupContext(ctx)
	beforeFinalVerification := value
	value, err = m.verifyRunFinal(runVerificationContext, beforeFinalVerification, handler)
	cancelRunVerification()
	if err != nil {
		stageErr := err
		if value == nil || applyJournalReloadRequired(stageErr) {
			var reloadErr error
			value, reloadErr = m.reloadApplyJournal(ctx, runID, "reload after final resource verification failure", stageErr)
			if reloadErr != nil {
				return reloadErr
			}
		}
		if CodeOf(stageErr) != CodeRecoveryRequired && value.State != model.RunRecoveryRequired {
			rollbackContext, cancelRollback := newApplyCleanupContext(ctx)
			rollbackErr := m.rollbackVerificationFailureLocked(rollbackContext, value, changeSetIDs, stageErr, true)
			cancelRollback()
			if rollbackErr != nil {
				return rollbackErr
			}
		}
		return stageErr
	}
	verifierContext, cancelVerifier := newApplyCleanupContext(ctx)
	failedChangeSets, verificationErr := verifier(verifierContext, value, changeSetIDs)
	cancelVerifier()
	if verificationErr != nil {
		rollbackContext, cancelRollback := newApplyCleanupContext(ctx)
		rollbackErr := m.rollbackVerificationFailureLocked(rollbackContext, value, failedChangeSets, verificationErr, false)
		cancelRollback()
		if rollbackErr != nil {
			return &Error{Code: CodeVerificationFailed, Operation: "platform evaluator verification and rollback", RunID: runID, Committed: true, Err: fmt.Errorf("verification error: %v; rollback error: %w", verificationErr, rollbackErr)}
		}
		return &Error{Code: CodeVerificationFailed, Operation: "platform evaluator verification", RunID: runID, Committed: true, Err: fmt.Errorf("automatic rollback completed: %w", verificationErr)}
	}
	completionContext, cancelCompletion := newApplyCleanupContext(ctx)
	_, err = m.update(completionContext, value, "complete run", func(next *model.RemediationJournal) error {
		for _, changeSet := range next.ChangeSets {
			if changeSet.State != model.ChangeVerified {
				return fmt.Errorf("change set %s is not verified", changeSet.ID)
			}
		}
		next.State = model.RunCompleted
		return nil
	})
	cancelCompletion()
	if err == nil {
		return nil
	}
	stageErr := err
	latest, reloadErr := m.reloadApplyJournal(ctx, runID, "reload after run completion persistence failure", stageErr)
	if reloadErr != nil {
		return reloadErr
	}
	if latest.State == model.RunCompleted {
		return nil
	}
	if latest.State != model.RunVerifying {
		return &Error{Code: CodeRecoveryRequired, Operation: "resume run completion", RunID: runID, Err: fmt.Errorf("run is %s after completion persistence failure", latest.State)}
	}
	retryContext, cancelRetry := newApplyCleanupContext(ctx)
	_, retryErr := m.update(retryContext, latest, "retry complete run", func(next *model.RemediationJournal) error {
		for _, changeSet := range next.ChangeSets {
			if changeSet.State != model.ChangeVerified {
				return fmt.Errorf("change set %s is not verified", changeSet.ID)
			}
		}
		next.State = model.RunCompleted
		return nil
	})
	cancelRetry()
	if retryErr != nil {
		afterRetry, retryReloadErr := m.reloadApplyJournal(ctx, runID, "reload after run completion persistence retry", retryErr)
		if retryReloadErr != nil {
			return retryReloadErr
		}
		if afterRetry.State == model.RunCompleted {
			return nil
		}
		return &Error{Code: CodeRecoveryRequired, Operation: "retry complete run", RunID: runID, Committed: true, Err: fmt.Errorf("initial completion error: %v; retry error: %v; durable run state is %s", stageErr, retryErr, afterRetry.State)}
	}
	return nil
}

func (m *Manager) verifyRunFinal(ctx context.Context, value *model.RemediationJournal, handler fileRuntime) (*model.RemediationJournal, error) {
	type writer struct {
		changeSetID string
		operationID string
		operation   model.OperationRecord
	}
	lastWriter := make(map[string]writer)
	for _, changeSet := range value.ChangeSets {
		if changeSet.State != model.ChangeVerified {
			continue
		}
		for _, operation := range changeSet.Operations {
			lastWriter[operation.Resource.Key] = writer{changeSetID: changeSet.ID, operationID: operation.ID, operation: operation}
		}
	}
	keys := make([]string, 0, len(lastWriter))
	for key := range lastWriter {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := lastWriter[key]
		current, err := handler.Capture(ctx, item.operation.Resource)
		if err == nil && exactEqual(item.operation.Desired, current) {
			continue
		}
		if err == nil {
			err = fmt.Errorf("final state differs from the last verified writer")
		}
		next, persistErr := m.persistRecoveryRequired(ctx, value, item.changeSetID, item.operationID, err)
		if persistErr != nil {
			return nil, persistErr
		}
		return next, &Error{Code: CodeRecoveryRequired, Operation: "verify run", RunID: value.RunID, ChangeSetID: item.changeSetID, OperationID: item.operationID, Err: err}
	}
	return value, nil
}

func (m *Manager) prepareChangeSet(ctx context.Context, value *model.RemediationJournal, handler fileRuntime, changeSetID string) (*model.RemediationJournal, error) {
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return value, &Error{Code: CodeInvalidState, Operation: "prepare change set", RunID: value.RunID, ChangeSetID: changeSetID, Err: err}
	}
	if changeSet.State != model.ChangePlanned {
		return value, &Error{Code: CodeInvalidState, Operation: "prepare change set", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set is %s", changeSet.State)}
	}
	type preparedOperation struct {
		id       string
		before   model.ResourceSnapshot
		artifact model.BackupArtifact
	}
	prepared := make([]preparedOperation, 0, len(changeSet.Operations))
	changeBefore := make(map[string]model.ResourceSnapshot, len(changeSet.Resources))
	for _, operation := range changeSet.Operations {
		if operation.Kind != model.OperationFileMetadata {
			return value, &Error{Code: CodeUnsupportedOperation, Operation: "prepare change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operation.ID, Err: fmt.Errorf("only regular-file metadata remediation is supported")}
		}
		current, captureErr := handler.Capture(ctx, operation.Resource)
		if captureErr != nil {
			return value, wrapDependency("capture before state", value.RunID, changeSetID, operation.ID, captureErr)
		}
		if !exactEqual(operation.ExpectedBefore, current) {
			return value, &Error{Code: CodePreconditionFailed, Operation: "prepare change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operation.ID, Err: fmt.Errorf("current state differs from the approved precondition")}
		}
		artifact, backupErr := handler.Backup(ctx, changeSetID, operation.ID, operation.Resource, current)
		if backupErr != nil {
			return value, wrapDependency("backup before state", value.RunID, changeSetID, operation.ID, backupErr)
		}
		if verifyErr := handler.VerifyBackup(ctx, artifact); verifyErr != nil {
			return value, wrapDependency("verify backup", value.RunID, changeSetID, operation.ID, verifyErr)
		}
		prepared = append(prepared, preparedOperation{id: operation.ID, before: current, artifact: artifact})
		changeBefore[operation.Resource.Key] = current
	}
	for _, item := range prepared {
		operation, _, _, findErr := findOperation(value, changeSetID, item.id)
		if findErr != nil {
			return value, &Error{Code: CodeInvalidState, Operation: "recheck prepared change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: item.id, Err: findErr}
		}
		current, captureErr := handler.Capture(ctx, operation.Resource)
		if captureErr != nil {
			return value, wrapDependency("recheck prepared state", value.RunID, changeSetID, item.id, captureErr)
		}
		if !exactEqual(item.before, current) {
			return value, &Error{Code: CodePreconditionFailed, Operation: "recheck prepared change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: item.id, Err: fmt.Errorf("resource changed while backups were prepared")}
		}
	}
	orderedBefore := make([]model.ResourceSnapshot, 0, len(changeSet.Resources))
	for _, resource := range changeSet.Resources {
		snapshot, exists := changeBefore[resource.Key]
		if !exists {
			return value, &Error{Code: CodeInvalidState, Operation: "prepare change set", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("resource %s has no before state", resource.Key)}
		}
		orderedBefore = append(orderedBefore, snapshot)
	}
	now := m.nowUTC()
	next, updateErr := m.update(ctx, value, "persist prepared change set", func(journal *model.RemediationJournal) error {
		target, _, findErr := findChangeSet(journal, changeSetID)
		if findErr != nil {
			return findErr
		}
		target.Before = orderedBefore
		target.PreparedAt = &now
		target.State = model.ChangePrepared
		for _, item := range prepared {
			operation, _, _, findErr := findOperation(journal, changeSetID, item.id)
			if findErr != nil {
				return findErr
			}
			operation.Before = item.before
			artifact := item.artifact
			operation.Backup = &artifact
		}
		return nil
	})
	if updateErr != nil {
		return value, updateErr
	}
	return next, nil
}

func (m *Manager) applyOperation(ctx context.Context, value *model.RemediationJournal, handler fileRuntime, changeSetID, operationID string) (*model.RemediationJournal, error) {
	operation, _, _, err := findOperation(value, changeSetID, operationID)
	if err != nil {
		return value, &Error{Code: CodeInvalidState, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: err}
	}
	if operation.Kind != model.OperationFileMetadata || operation.Before.IsZero() || operation.Backup == nil {
		return value, &Error{Code: CodeUnsupportedOperation, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("operation is not a prepared regular-file metadata change")}
	}
	current, err := handler.Capture(ctx, operation.Resource)
	if err != nil {
		return value, wrapDependency("capture apply precondition", value.RunID, changeSetID, operationID, err)
	}
	if !exactEqual(operation.Before, current) {
		return value, &Error{Code: CodePreconditionFailed, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("file changed after preparation")}
	}
	if err := handler.VerifyBackup(ctx, *operation.Backup); err != nil {
		return value, wrapDependency("verify backup before apply", value.RunID, changeSetID, operationID, err)
	}
	now := m.nowUTC()
	next, updateErr := m.update(ctx, value, "persist apply intent", func(next *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(next, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		target.State = model.OperationApplyIntentDurable
		target.ApplyIntentAt = &now
		return nil
	})
	if updateErr != nil {
		return value, updateErr
	}
	value = next
	operation, _, _, _ = findOperation(value, changeSetID, operationID)
	persistContext, cancelPersist := newApplyCleanupContext(ctx)
	defer cancelPersist()
	metadataObserved, applyErr := handler.ApplyMetadata(ctx, operation.Resource, operation.Before, operation.Desired)
	if applyErr != nil && !regularfile.Committed(applyErr) {
		observed, captureErr := handler.Capture(persistContext, operation.Resource)
		if captureErr != nil {
			return m.markOperationAmbiguous(persistContext, value, changeSetID, operationID, wrapDependency("capture failed apply result", value.RunID, changeSetID, operationID, captureErr))
		}
		if !exactEqual(operation.Before, observed) {
			return m.markOperationAmbiguous(persistContext, value, changeSetID, operationID, &Error{Code: CodeRecoveryRequired, Operation: "apply metadata", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("non-committed metadata failure did not leave the exact before state")})
		}
		return m.markOperationNoEffect(persistContext, value, changeSetID, operationID, observed, &Error{Code: CodeApplyFailed, Operation: "apply metadata", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: applyErr})
	}
	observed, captureErr := handler.Capture(persistContext, operation.Resource)
	if captureErr != nil {
		return m.markOperationAmbiguous(persistContext, value, changeSetID, operationID, wrapDependency("capture apply result", value.RunID, changeSetID, operationID, captureErr))
	}
	if !metadataObserved.IsZero() && !exactEqual(metadataObserved, observed) {
		return m.markOperationAmbiguous(persistContext, value, changeSetID, operationID, &Error{Code: CodeRecoveryRequired, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Committed: true, Err: fmt.Errorf("path no longer identifies the metadata-mutated inode")})
	}
	desired := exactEqual(operation.Desired, observed)
	before := exactEqual(operation.Before, observed)
	switch {
	case desired:
		appliedAt := m.nowUTC()
		next, updateErr := m.update(persistContext, value, "persist applied operation", func(next *model.RemediationJournal) error {
			target, _, _, findErr := findOperation(next, changeSetID, operationID)
			if findErr != nil {
				return findErr
			}
			target.ObservedAfter = &observed
			target.AppliedAt = &appliedAt
			target.State = model.OperationApplied
			if applyErr != nil {
				journalError := m.makeJournalError("apply", changeSetID, operationID, target, &Error{Code: CodeApplyFailed, Err: applyErr})
				target.Error = &journalError
			}
			return nil
		})
		if updateErr != nil {
			return value, updateErr
		}
		value = next
		if applyErr != nil {
			return value, &Error{Code: CodeApplyFailed, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Committed: true, Err: applyErr}
		}
		return value, nil
	case before:
		if applyErr == nil {
			applyErr = fmt.Errorf("metadata update returned success but the file remained in the before state")
		}
		return m.markOperationNoEffect(persistContext, value, changeSetID, operationID, observed, &Error{Code: CodeApplyFailed, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: applyErr})
	default:
		reason := applyErr
		if reason == nil {
			reason = fmt.Errorf("apply result matches neither before nor desired state")
		}
		return m.markOperationAmbiguous(persistContext, value, changeSetID, operationID, &Error{Code: CodeRecoveryRequired, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Committed: true, Err: reason})
	}
}

func (m *Manager) markOperationNoEffect(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, observed model.ResourceSnapshot, cause error) (*model.RemediationJournal, error) {
	next, err := m.update(ctx, value, "persist no-effect apply failure", func(journal *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		if target.RollbackIntentAt != nil || target.AppliedAt != nil || target.ObservedAfter != nil || !exactEqual(target.Before, observed) {
			return fmt.Errorf("failed apply result does not prove an unchanged target")
		}
		observedCopy := observed
		target.State = model.OperationFailed
		target.ObservedAfter = &observedCopy
		journalError := m.makeJournalError("apply", changeSetID, operationID, target, cause)
		target.Error = &journalError
		return nil
	})
	if err != nil {
		return value, err
	}
	return next, cause
}

func (m *Manager) markOperationAmbiguous(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, cause error) (*model.RemediationJournal, error) {
	next, err := m.update(ctx, value, "persist ambiguous apply result", func(journal *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		target.State = model.OperationAmbiguous
		journalError := m.makeJournalError("apply", changeSetID, operationID, target, cause)
		target.Error = &journalError
		changeSet, _, findErr := findChangeSet(journal, changeSetID)
		if findErr != nil {
			return findErr
		}
		changeSet.State = model.ChangeRecoveryRequired
		changeSet.Error = &journalError
		journal.State = model.RunRecoveryRequired
		journal.Error = &journalError
		journal.UnresolvedChangeSets = appendUnique(journal.UnresolvedChangeSets, changeSetID)
		return nil
	})
	if err != nil {
		return value, err
	}
	return next, &Error{Code: CodeRecoveryRequired, Operation: "apply operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Committed: true, Err: cause}
}

func (m *Manager) finishChangeSet(ctx context.Context, value *model.RemediationJournal, handler fileRuntime, changeSetID string) (*model.RemediationJournal, error) {
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return value, err
	}
	afterByResource := make(map[string]model.ResourceSnapshot, len(changeSet.Resources))
	for _, operation := range changeSet.Operations {
		if operation.ObservedAfter == nil || operation.State != model.OperationApplied {
			return value, &Error{Code: CodeApplyFailed, Operation: "finish change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operation.ID, Err: fmt.Errorf("operation is not applied")}
		}
		afterByResource[operation.Resource.Key] = *operation.ObservedAfter
	}
	orderedAfter := make([]model.ResourceSnapshot, 0, len(changeSet.Resources))
	for _, resource := range changeSet.Resources {
		orderedAfter = append(orderedAfter, afterByResource[resource.Key])
	}
	appliedAt := m.nowUTC()
	next, updateErr := m.update(ctx, value, "persist applied change set", func(next *model.RemediationJournal) error {
		target, _, findErr := findChangeSet(next, changeSetID)
		if findErr != nil {
			return findErr
		}
		target.After = orderedAfter
		target.AppliedAt = &appliedAt
		target.State = model.ChangeApplied
		return nil
	})
	if updateErr != nil {
		return value, updateErr
	}
	value = next
	next, updateErr = m.update(ctx, value, "start change set verification", func(next *model.RemediationJournal) error {
		target, _, findErr := findChangeSet(next, changeSetID)
		if findErr != nil {
			return findErr
		}
		target.State = model.ChangeVerifying
		return nil
	})
	if updateErr != nil {
		return value, updateErr
	}
	value = next
	changeSet, _, _ = findChangeSet(value, changeSetID)
	for _, operation := range changeSet.Operations {
		current, captureErr := handler.Capture(ctx, operation.Resource)
		if captureErr != nil {
			return m.markVerificationAmbiguous(ctx, value, changeSetID, operation.ID, captureErr)
		}
		if !exactEqual(operation.Desired, current) {
			reason := "verification result matches neither desired nor before state"
			if exactEqual(operation.Before, current) {
				reason = "file returned to its before state after apply"
			}
			return m.markVerificationAmbiguous(ctx, value, changeSetID, operation.ID, fmt.Errorf("%s", reason))
		}
	}
	return value, nil
}

func (m *Manager) completeChangeSetVerification(ctx context.Context, value *model.RemediationJournal, changeSetID string) (*model.RemediationJournal, error) {
	if value == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "complete change-set verification", ChangeSetID: changeSetID, Err: fmt.Errorf("journal is required")}
	}
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return value, &Error{Code: CodeInvalidState, Operation: "complete change-set verification", RunID: value.RunID, ChangeSetID: changeSetID, Err: err}
	}
	if changeSet.State != model.ChangeVerifying {
		return value, &Error{Code: CodeInvalidState, Operation: "complete change-set verification", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set is %s, not verifying", changeSet.State)}
	}
	for _, operation := range changeSet.Operations {
		if operation.State != model.OperationApplied || operation.ObservedAfter == nil {
			return value, &Error{Code: CodeInvalidState, Operation: "complete change-set verification", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operation.ID, Err: fmt.Errorf("operation has no verified resource-level after state")}
		}
	}
	verifiedAt := m.nowUTC()
	next, err := m.update(ctx, value, "persist evaluator-verified change set", func(journal *model.RemediationJournal) error {
		target, _, findErr := findChangeSet(journal, changeSetID)
		if findErr != nil {
			return findErr
		}
		target.State = model.ChangeVerified
		target.VerifiedAt = &verifiedAt
		for index := range target.Operations {
			target.Operations[index].State = model.OperationVerified
		}
		return nil
	})
	if err != nil {
		return value, err
	}
	return next, nil
}

func (m *Manager) markVerificationAmbiguous(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, cause error) (*model.RemediationJournal, error) {
	next, err := m.update(ctx, value, "persist ambiguous verification", func(journal *model.RemediationJournal) error {
		operation, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		journalError := m.makeJournalError("verification", changeSetID, operationID, operation, &Error{Code: CodeRecoveryRequired, Err: cause})
		changeSet, _, findErr := findChangeSet(journal, changeSetID)
		if findErr != nil {
			return findErr
		}
		changeSet.State = model.ChangeRecoveryRequired
		changeSet.Error = &journalError
		journal.State = model.RunRecoveryRequired
		journal.Error = &journalError
		journal.UnresolvedChangeSets = appendUnique(journal.UnresolvedChangeSets, changeSetID)
		return nil
	})
	if err != nil {
		return value, err
	}
	return next, &Error{Code: CodeRecoveryRequired, Operation: "verify change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Committed: true, Err: cause}
}

func orderedOperationIDs(value *model.RemediationJournal, changeSetID string, rollback bool) []string {
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return nil
	}
	operations := append([]model.OperationRecord(nil), changeSet.Operations...)
	sort.SliceStable(operations, func(i, j int) bool {
		if rollback {
			if operations[i].RollbackSequence == operations[j].RollbackSequence {
				return operations[i].ID < operations[j].ID
			}
			return operations[i].RollbackSequence < operations[j].RollbackSequence
		}
		if operations[i].Sequence == operations[j].Sequence {
			return operations[i].ID < operations[j].ID
		}
		return operations[i].Sequence < operations[j].Sequence
	})
	result := make([]string, 0, len(operations))
	for _, operation := range operations {
		result = append(result, operation.ID)
	}
	return result
}
