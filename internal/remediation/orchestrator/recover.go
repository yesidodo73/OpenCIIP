package orchestrator

import (
	"context"
	"fmt"
	"sort"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
)

func (m *Manager) Recover(ctx context.Context, runID string) (RecoveryAssessment, error) {
	lock, err := m.acquire(ctx, "recover")
	if err != nil {
		return RecoveryAssessment{}, err
	}
	defer lock.Release()
	// Recover is the only operation allowed to truncate an incomplete final WAL
	// record. Repair the explicitly selected run before listing recoverable runs;
	// otherwise ListRecoverable would reject that same incomplete tail and make
	// the documented recovery path unreachable.
	value, err := m.loadAndVerify(ctx, runID)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	if err := m.ensureNoOtherRecoverable(ctx, runID); err != nil {
		return RecoveryAssessment{}, err
	}
	assessment := RecoveryAssessment{RunID: runID, LastValidRevision: value.Revision}
	if value.State == model.RunCanceling || value.State == model.RunCancelFailed {
		for _, changeSet := range value.ChangeSets {
			for _, operation := range changeSet.Operations {
				assessment.NotApplied = append(assessment.NotApplied, changeSet.ID+"/"+operation.ID)
			}
		}
		assessment.NotApplied = uniqueSorted(assessment.NotApplied)
		if _, available := m.content.(RunContentDeleter); !available {
			assessment.Reasons = []string{"취소 복구에는 run-scoped desired content 삭제 기능이 필요합니다"}
			return assessment, &Error{Code: CodeRecoveryPending, Operation: "recover cancellation", RunID: runID, Err: fmt.Errorf("run-scoped desired content deletion is unavailable")}
		}
		next, cancelErr := m.cancelLoaded(ctx, value)
		if next != nil {
			assessment.LastValidRevision = next.Revision
		}
		return assessment, cancelErr
	}
	if value.State.Terminal() && !value.State.NeedsOperatorAction() {
		return assessment, &Error{Code: CodeInvalidState, Operation: "recover", RunID: runID, Err: fmt.Errorf("run %s does not require recovery", value.State)}
	}
	handler, err := m.fileHandler(runID)
	if err != nil {
		return assessment, err
	}
	value, err = m.recoverOperationChains(ctx, value, handler, &assessment)
	if err != nil {
		return assessment, err
	}
	for _, identifier := range assessment.ConfirmedApplied {
		changeSetID, operationID := splitAssessmentID(identifier)
		operation, _, _, findErr := findOperation(value, changeSetID, operationID)
		if findErr != nil {
			return assessment, &Error{Code: CodeInvalidState, Operation: "recover", RunID: runID, ChangeSetID: changeSetID, OperationID: operationID, Err: findErr}
		}
		if operation.Backup == nil {
			assessment.Ambiguous = append(assessment.Ambiguous, identifier)
			assessment.Reasons = append(assessment.Reasons, identifier+": durable backup is missing")
			value, err = m.persistRecoveryRequired(ctx, value, changeSetID, operationID, fmt.Errorf("durable backup is missing"))
			if err != nil {
				return assessment, err
			}
			continue
		}
		if verifyErr := handler.VerifyBackup(ctx, *operation.Backup); verifyErr != nil {
			assessment.Ambiguous = append(assessment.Ambiguous, identifier)
			assessment.Reasons = append(assessment.Reasons, identifier+": backup verification failed")
			value, err = m.persistRecoveryRequired(ctx, value, changeSetID, operationID, verifyErr)
			if err != nil {
				return assessment, err
			}
		}
	}
	assessment.ConfirmedApplied = uniqueSorted(assessment.ConfirmedApplied)
	assessment.ConfirmedRolledBack = uniqueSorted(assessment.ConfirmedRolledBack)
	assessment.NotApplied = uniqueSorted(assessment.NotApplied)
	assessment.Ambiguous = uniqueSorted(assessment.Ambiguous)
	assessment.ConfirmedApplied = removeAssessmentIDs(assessment.ConfirmedApplied, assessment.Ambiguous)
	assessment.Reasons = uniqueSorted(assessment.Reasons)
	assessment.AutomaticRollbackPossible = len(assessment.Ambiguous) == 0 && len(assessment.ConfirmedApplied) > 0
	value, err = m.finalizeRecoveredRun(ctx, value, assessment)
	if err != nil {
		return assessment, err
	}
	assessment.LastValidRevision = value.Revision
	return assessment, nil
}

type recoveryOperationRef struct {
	changeSetID       string
	operationID       string
	changeSetSequence int
	operationSequence int
}

type recoveredRollbackRef struct {
	changeSetID string
	operationID string
	operation   model.OperationRecord
}

func recoveryOperationOrder(value *model.RemediationJournal) []recoveryOperationRef {
	if value == nil {
		return nil
	}
	result := make([]recoveryOperationRef, 0)
	for _, changeSet := range value.ChangeSets {
		for _, operation := range changeSet.Operations {
			result = append(result, recoveryOperationRef{
				changeSetID:       changeSet.ID,
				operationID:       operation.ID,
				changeSetSequence: changeSet.Sequence,
				operationSequence: operation.Sequence,
			})
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].changeSetSequence != result[j].changeSetSequence {
			return result[i].changeSetSequence > result[j].changeSetSequence
		}
		if result[i].operationSequence != result[j].operationSequence {
			return result[i].operationSequence > result[j].operationSequence
		}
		if result[i].changeSetID != result[j].changeSetID {
			return result[i].changeSetID < result[j].changeSetID
		}
		return result[i].operationID < result[j].operationID
	})
	return result
}

func (m *Manager) recoverOperationChains(
	ctx context.Context,
	value *model.RemediationJournal,
	handler fileRuntime,
	assessment *RecoveryAssessment,
) (*model.RemediationJournal, error) {
	if value == nil || handler == nil || assessment == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "recover operation chains", Err: fmt.Errorf("journal, file handler, and assessment are required")}
	}
	logicalCurrent := make(map[string]model.ResourceSnapshot)
	blockedResources := make(map[string]error)
	rolledBackSuffixes := make(map[string][]recoveredRollbackRef)

	for _, reference := range recoveryOperationOrder(value) {
		operation, _, _, err := findOperation(value, reference.changeSetID, reference.operationID)
		if err != nil {
			return value, &Error{Code: CodeInvalidState, Operation: "recover", RunID: value.RunID, ChangeSetID: reference.changeSetID, OperationID: reference.operationID, Err: err}
		}
		operationCopy := *operation
		identifier := reference.changeSetID + "/" + reference.operationID
		if operationCopy.Kind != model.OperationFileMetadata {
			return value, &Error{Code: CodeUnsupportedOperation, Operation: "recover", RunID: value.RunID, ChangeSetID: reference.changeSetID, OperationID: reference.operationID, Err: fmt.Errorf("only regular-file metadata remediation is supported")}
		}
		if operationCopy.State == model.OperationPlanned {
			assessment.NotApplied = append(assessment.NotApplied, identifier)
			continue
		}
		if operationCopy.ProvesNoEffect() {
			// A durably proven no-effect apply never became a writer. It must
			// not consume the live frontier or block an earlier real writer.
			assessment.NotApplied = append(assessment.NotApplied, identifier)
			continue
		}

		resourceKey := operationCopy.Resource.Key
		if blockedCause, blocked := blockedResources[resourceKey]; blocked {
			assessment.Ambiguous = append(assessment.Ambiguous, identifier)
			assessment.Reasons = append(assessment.Reasons, identifier+": 후속 writer 상태를 확정할 수 없어 이전 상태 체인을 추론하지 않았습니다")
			value, err = m.persistRecoveryRequired(ctx, value, reference.changeSetID, reference.operationID, fmt.Errorf("resource writer chain is blocked by a later ambiguous operation: %w", blockedCause))
			if err != nil {
				return value, err
			}
			continue
		}
		if operationCopy.State == model.OperationRolledBack {
			if operationCopy.ObservedRollback == nil || !exactEqual(operationCopy.Before, *operationCopy.ObservedRollback) {
				cause := fmt.Errorf("recorded rollback state is inconsistent with the durable before state")
				assessment.Ambiguous = append(assessment.Ambiguous, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 기록된 롤백 상태가 durable before와 일치하지 않습니다")
				blockedResources[resourceKey] = cause
				value, err = m.persistRecoveryRequired(ctx, value, reference.changeSetID, reference.operationID, cause)
				if err != nil {
					return value, err
				}
				continue
			}
			rolledBackSuffixes[resourceKey] = append(rolledBackSuffixes[resourceKey], recoveredRollbackRef{
				changeSetID: reference.changeSetID,
				operationID: reference.operationID,
				operation:   operationCopy,
			})
			continue
		}

		current, exists := logicalCurrent[resourceKey]
		if !exists {
			current, err = handler.Capture(ctx, operationCopy.Resource)
			if err != nil {
				assessment.Ambiguous = append(assessment.Ambiguous, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 현재 파일 상태를 수집하지 못했습니다")
				blockedResources[resourceKey] = err
				value, err = m.persistRecoveryRequired(ctx, value, reference.changeSetID, reference.operationID, err)
				if err != nil {
					return value, err
				}
				continue
			}
			logicalCurrent[resourceKey] = current
		}
		before := exactEqual(operationCopy.Before, current)
		desiredMatches := exactEqual(operationCopy.Desired, current)
		durableAfterMatches := operationCopy.ObservedAfter != nil && exactEqual(*operationCopy.ObservedAfter, current)
		partialMetadata := !before && !durableAfterMatches && regularfile.MetadataTransitionCandidate(operationCopy.Before, operationCopy.Desired, current)
		deferSuffixValidation := before && (operationCanResolveToBefore(operationCopy) || rollbackRecoveryScopeCovers(value, reference.changeSetID))
		if suffix := rolledBackSuffixes[resourceKey]; len(suffix) > 0 && !deferSuffixValidation {
			suffixAnchor := current
			if partialMetadata {
				if operationCopy.ObservedAfter != nil {
					suffixAnchor = *operationCopy.ObservedAfter
				} else {
					suffixAnchor = operationCopy.Desired
				}
			}
			if chainErr := validateRecoveredRollbackSuffix(suffixAnchor, suffix); chainErr != nil {
				assessment.Ambiguous = append(assessment.Ambiguous, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 후속 롤백 writer 체인이 현재 상태와 일치하지 않습니다")
				blockedResources[resourceKey] = chainErr
				value, err = m.persistRecoveryRequired(ctx, value, reference.changeSetID, reference.operationID, chainErr)
				if err != nil {
					return value, err
				}
				value, err = m.markRecoveredRollbackSuffixAmbiguous(ctx, value, suffix, assessment, chainErr)
				if err != nil {
					return value, err
				}
				delete(rolledBackSuffixes, resourceKey)
				continue
			}
			for _, rolledBack := range suffix {
				assessment.ConfirmedRolledBack = append(assessment.ConfirmedRolledBack, rolledBack.changeSetID+"/"+rolledBack.operationID)
			}
			delete(rolledBackSuffixes, resourceKey)
		}

		activeEffect := false
		resolvedToBefore := false
		ambiguousCause := error(nil)
		ambiguousReason := ""

		switch operationCopy.State {
		case model.OperationApplyIntentDurable:
			switch {
			case before && canResolveNoEffect(operationCopy):
				value, err = m.resolveUnappliedOperation(ctx, value, reference.changeSetID, reference.operationID, current)
				assessment.NotApplied = append(assessment.NotApplied, identifier)
				logicalCurrent[resourceKey] = operationCopy.Before
				resolvedToBefore = true
			case desiredMatches && canInferInterruptedApply(operationCopy):
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationApplied, &current)
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				activeEffect = true
			case partialMetadata && canInferInterruptedApply(operationCopy):
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationApplied, &current)
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 원본 inode의 부분 메타데이터 변경을 안전한 롤백 후보로 확인했습니다")
				activeEffect = true
			default:
				ambiguousCause = fmt.Errorf("apply intent result is ambiguous")
				ambiguousReason = "apply intent 결과가 자원 writer 체인의 before 또는 desired와 일치하지 않습니다"
			}
		case model.OperationApplied, model.OperationVerified:
			if before && rollbackRecoveryScopeCovers(value, reference.changeSetID) {
				value, err = m.resolveRecoveredRollback(ctx, value, reference.changeSetID, reference.operationID, current)
				assessment.ConfirmedRolledBack = append(assessment.ConfirmedRolledBack, identifier)
				logicalCurrent[resourceKey] = operationCopy.Before
				resolvedToBefore = true
			} else if durableAfterMatches && !before {
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				activeEffect = true
			} else {
				ambiguousCause = fmt.Errorf("recorded applied state is inconsistent")
				ambiguousReason = "기록된 적용 상태가 자원 writer 체인의 기대 after 상태와 일치하지 않습니다"
			}
		case model.OperationRollbackIntentDurable:
			switch {
			case before:
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationRolledBack, &current)
				assessment.ConfirmedRolledBack = append(assessment.ConfirmedRolledBack, identifier)
				logicalCurrent[resourceKey] = operationCopy.Before
				resolvedToBefore = true
			case durableAfterMatches:
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				activeEffect = true
			case partialMetadata:
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 중단된 롤백의 부분 메타데이터 상태를 원본 inode에서 확인했습니다")
				activeEffect = true
			default:
				ambiguousCause = fmt.Errorf("rollback intent result is ambiguous")
				ambiguousReason = "rollback intent 결과가 자원 writer 체인의 before 또는 after와 일치하지 않습니다"
			}
		case model.OperationAmbiguous:
			switch {
			case before && operationCopy.RollbackIntentAt != nil:
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationRolledBack, &current)
				assessment.ConfirmedRolledBack = append(assessment.ConfirmedRolledBack, identifier)
				logicalCurrent[resourceKey] = operationCopy.Before
				resolvedToBefore = true
			case before && canResolveNoEffect(operationCopy):
				value, err = m.resolveUnappliedOperation(ctx, value, reference.changeSetID, reference.operationID, current)
				assessment.NotApplied = append(assessment.NotApplied, identifier)
				logicalCurrent[resourceKey] = operationCopy.Before
				resolvedToBefore = true
			case operationCopy.RollbackIntentAt == nil && durableAfterMatches && operationCopy.RecoveryMode != model.RecoveryManual:
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationApplied, &current)
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				activeEffect = true
			case desiredMatches && canInferInterruptedApply(operationCopy):
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationApplied, &current)
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				activeEffect = true
			case operationCopy.RollbackIntentAt != nil && durableAfterMatches && operationCopy.RecoveryMode != model.RecoveryManual:
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationApplied, &current)
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				activeEffect = true
			case partialMetadata && canInferInterruptedApply(operationCopy):
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationApplied, &current)
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 원본 inode의 부분 메타데이터 변경을 안전한 롤백 후보로 확인했습니다")
				activeEffect = true
			case partialMetadata && operationCopy.RollbackIntentAt != nil:
				value, err = m.resolveOperation(ctx, value, reference.changeSetID, reference.operationID, model.OperationApplied, &current)
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 중단된 롤백의 부분 메타데이터 상태를 원본 inode에서 확인했습니다")
				activeEffect = true
			default:
				ambiguousCause = fmt.Errorf("ambiguous operation cannot be inferred")
				ambiguousReason = "모호한 작업을 자원 writer 체인에서 안전하게 추론할 수 없습니다"
			}
		case model.OperationFailed:
			if before && operationCopy.RollbackIntentAt != nil {
				value, err = m.resolveRecoveredRollback(ctx, value, reference.changeSetID, reference.operationID, current)
				assessment.ConfirmedRolledBack = append(assessment.ConfirmedRolledBack, identifier)
				logicalCurrent[resourceKey] = operationCopy.Before
				resolvedToBefore = true
			} else if before && canResolveNoEffect(operationCopy) {
				value, err = m.resolveUnappliedOperation(ctx, value, reference.changeSetID, reference.operationID, current)
				assessment.NotApplied = append(assessment.NotApplied, identifier)
				logicalCurrent[resourceKey] = operationCopy.Before
				resolvedToBefore = true
			} else if durableAfterMatches && operationCopy.RollbackIntentAt != nil {
				// A rollback can fail before changing the file and leave the
				// original durable after state intact. This is an active,
				// retryable rollback candidate rather than an ambiguous file.
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				activeEffect = true
			} else if partialMetadata && operationCopy.RollbackIntentAt != nil {
				assessment.ConfirmedApplied = append(assessment.ConfirmedApplied, identifier)
				assessment.Reasons = append(assessment.Reasons, identifier+": 영속 롤백 의도 뒤 원본 inode의 부분 메타데이터 변경을 확인했습니다")
				activeEffect = true
			} else {
				ambiguousCause = fmt.Errorf("failed operation state is inconsistent")
				ambiguousReason = "실패로 기록된 작업이 자원 writer 체인의 before 상태와 일치하지 않습니다"
			}
		}
		if err != nil {
			return value, err
		}
		if ambiguousCause != nil {
			assessment.Ambiguous = append(assessment.Ambiguous, identifier)
			assessment.Reasons = append(assessment.Reasons, identifier+": "+ambiguousReason)
			blockedResources[resourceKey] = ambiguousCause
			value, err = m.persistRecoveryRequired(ctx, value, reference.changeSetID, reference.operationID, ambiguousCause)
			if err != nil {
				return value, err
			}
			if suffix := rolledBackSuffixes[resourceKey]; len(suffix) > 0 {
				value, err = m.markRecoveredRollbackSuffixAmbiguous(ctx, value, suffix, assessment, ambiguousCause)
				if err != nil {
					return value, err
				}
				delete(rolledBackSuffixes, resourceKey)
			}
			continue
		}
		if resolvedToBefore {
			if suffix := rolledBackSuffixes[resourceKey]; len(suffix) > 0 {
				resolved := operationCopy
				observedRollback := current
				resolved.ObservedRollback = &observedRollback
				combined := append(append([]recoveredRollbackRef(nil), suffix...), recoveredRollbackRef{
					changeSetID: reference.changeSetID,
					operationID: reference.operationID,
					operation:   resolved,
				})
				if chainErr := validateRecoveredRollbackSuffix(current, combined); chainErr != nil {
					blockedResources[resourceKey] = chainErr
					value, err = m.markRecoveredRollbackSuffixAmbiguous(ctx, value, suffix, assessment, chainErr)
					if err != nil {
						return value, err
					}
				} else {
					for _, rolledBack := range suffix {
						assessment.ConfirmedRolledBack = append(assessment.ConfirmedRolledBack, rolledBack.changeSetID+"/"+rolledBack.operationID)
					}
				}
				delete(rolledBackSuffixes, resourceKey)
			}
		}
		if activeEffect {
			// The next operation in this reverse traversal is an earlier writer.
			// Its expected current state is this operation's durable before state,
			// not the live file already modified by a later writer.
			logicalCurrent[resourceKey] = operationCopy.Before
		}
	}

	for resourceKey, suffix := range rolledBackSuffixes {
		if len(suffix) == 0 {
			continue
		}
		if blockedCause, blocked := blockedResources[resourceKey]; blocked {
			var err error
			value, err = m.markRecoveredRollbackSuffixAmbiguous(ctx, value, suffix, assessment, blockedCause)
			if err != nil {
				return value, err
			}
			continue
		}
		earliest := suffix[len(suffix)-1].operation
		live, captureErr := handler.Capture(ctx, earliest.Resource)
		if captureErr != nil || !exactEqual(earliest.Before, live) {
			if captureErr == nil {
				captureErr = fmt.Errorf("fully rolled-back writer chain does not match its earliest before state")
			}
			value, captureErr = m.markRecoveredRollbackSuffixAmbiguous(ctx, value, suffix, assessment, captureErr)
			if captureErr != nil {
				return value, captureErr
			}
			continue
		}
		if chainErr := validateRecoveredRollbackSuffix(earliest.Before, suffix); chainErr != nil {
			value, chainErr = m.markRecoveredRollbackSuffixAmbiguous(ctx, value, suffix, assessment, chainErr)
			if chainErr != nil {
				return value, chainErr
			}
			continue
		}
		for _, rolledBack := range suffix {
			assessment.ConfirmedRolledBack = append(assessment.ConfirmedRolledBack, rolledBack.changeSetID+"/"+rolledBack.operationID)
		}
	}

	for _, changeSet := range value.ChangeSets {
		if assessmentContainsChangeSet(assessment.Ambiguous, changeSet.ID) {
			continue
		}
		var err error
		value, err = m.reconcileRecoveredChangeSet(ctx, value, changeSet.ID)
		if err != nil {
			return value, err
		}
	}
	return value, nil
}

func operationCanResolveToBefore(operation model.OperationRecord) bool {
	switch operation.State {
	case model.OperationApplyIntentDurable,
		model.OperationRollbackIntentDurable,
		model.OperationAmbiguous,
		model.OperationFailed:
		return true
	default:
		return false
	}
}

func rollbackRecoveryScopeCovers(value *model.RemediationJournal, changeSetID string) bool {
	if value == nil {
		return false
	}
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil || !(changeSet.State.NeedsOperatorAction() || changeSet.State == model.ChangeRollingBack) {
		return false
	}
	for index := len(value.RollbackAttempts) - 1; index >= 0; index-- {
		attempt := value.RollbackAttempts[index]
		for _, target := range attempt.ExpandedChangeSets {
			if target == changeSetID {
				return true
			}
		}
	}
	return false
}

func validateRecoveredRollbackSuffix(anchor model.ResourceSnapshot, suffix []recoveredRollbackRef) error {
	expected := anchor
	for index := len(suffix) - 1; index >= 0; index-- {
		operation := suffix[index].operation
		if operation.ObservedRollback == nil || !exactEqual(operation.Before, *operation.ObservedRollback) || !exactEqual(operation.Before, expected) {
			return fmt.Errorf("rolled-back operation %s/%s breaks the durable writer chain", suffix[index].changeSetID, suffix[index].operationID)
		}
		if operation.ObservedAfter != nil {
			expected = *operation.ObservedAfter
		} else {
			expected = operation.Before
		}
	}
	return nil
}

func (m *Manager) markRecoveredRollbackSuffixAmbiguous(
	ctx context.Context,
	value *model.RemediationJournal,
	suffix []recoveredRollbackRef,
	assessment *RecoveryAssessment,
	cause error,
) (*model.RemediationJournal, error) {
	for _, rolledBack := range suffix {
		identifier := rolledBack.changeSetID + "/" + rolledBack.operationID
		assessment.Ambiguous = append(assessment.Ambiguous, identifier)
		assessment.Reasons = append(assessment.Reasons, identifier+": 롤백 writer 체인을 안전하게 검증하지 못했습니다")
		var err error
		value, err = m.persistRecoveryRequired(ctx, value, rolledBack.changeSetID, rolledBack.operationID, cause)
		if err != nil {
			return value, err
		}
	}
	return value, nil
}

func (m *Manager) resolveUnappliedOperation(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, observed model.ResourceSnapshot) (*model.RemediationJournal, error) {
	operation, _, _, err := findOperation(value, changeSetID, operationID)
	if err != nil {
		return nil, err
	}
	if operation.ProvesNoEffect() {
		return value, nil
	}
	if !canResolveNoEffect(*operation) || !exactEqual(operation.Before, observed) {
		return value, &Error{Code: CodeRecoveryRequired, Operation: "resolve unapplied operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("operation does not have exact no-effect evidence")}
	}
	journalError := m.makeJournalError("recover_no_effect", changeSetID, operationID, operation, &Error{Code: CodeApplyFailed, Err: fmt.Errorf("durable apply intent produced no observed target change")})
	return m.update(ctx, value, "persist recovered no-effect operation", func(journal *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		if !canResolveNoEffect(*target) || !exactEqual(target.Before, observed) {
			return fmt.Errorf("operation does not have exact no-effect evidence")
		}
		target.State = model.OperationFailed
		if target.ObservedAfter == nil {
			observedCopy := observed
			target.ObservedAfter = &observedCopy
		}
		target.Error = &journalError
		return nil
	})
}

func canResolveNoEffect(operation model.OperationRecord) bool {
	return operation.RollbackIntentAt == nil && operation.AppliedAt == nil &&
		(operation.ObservedAfter == nil || exactEqual(operation.Before, *operation.ObservedAfter))
}

func canInferInterruptedApply(operation model.OperationRecord) bool {
	return (operation.State == model.OperationApplyIntentDurable || operation.State == model.OperationAmbiguous) &&
		operation.ApplyIntentAt != nil && !operation.ApplyIntentAt.IsZero() && operation.Backup != nil &&
		operation.RollbackIntentAt == nil && operation.AppliedAt == nil && operation.ObservedAfter == nil &&
		operation.RecoveryMode == model.RecoveryStateInferable
}

func (m *Manager) resolveRecoveredRollback(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, observed model.ResourceSnapshot) (*model.RemediationJournal, error) {
	operation, _, _, err := findOperation(value, changeSetID, operationID)
	if err != nil {
		return nil, err
	}
	if operation.State != model.OperationRollbackIntentDurable {
		if !operation.State.CanTransitionTo(model.OperationRollbackIntentDurable) {
			return value, &Error{Code: CodeRecoveryRequired, Operation: "record recovered rollback intent", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("operation %s cannot enter rollback intent", operation.State)}
		}
		intentAt := m.nowUTC()
		value, err = m.update(ctx, value, "record recovered rollback intent", func(journal *model.RemediationJournal) error {
			target, _, _, findErr := findOperation(journal, changeSetID, operationID)
			if findErr != nil {
				return findErr
			}
			target.State = model.OperationRollbackIntentDurable
			if target.RollbackIntentAt == nil {
				target.RollbackIntentAt = &intentAt
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return m.resolveOperation(ctx, value, changeSetID, operationID, model.OperationRolledBack, &observed)
}

func (m *Manager) resolveOperation(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, state model.OperationState, observed *model.ResourceSnapshot) (*model.RemediationJournal, error) {
	resolvedAt := m.nowUTC()
	return m.update(ctx, value, "persist recovered operation", func(journal *model.RemediationJournal) error {
		operation, _, _, err := findOperation(journal, changeSetID, operationID)
		if err != nil {
			return err
		}
		operation.State = state
		switch state {
		case model.OperationApplied:
			if observed == nil {
				return fmt.Errorf("applied recovery state requires an observed snapshot")
			}
			if operation.ObservedAfter == nil {
				copy := *observed
				operation.ObservedAfter = &copy
			} else if !exactEqual(*operation.ObservedAfter, *observed) {
				if operation.Kind != model.OperationFileMetadata || !regularfile.MetadataTransitionCandidate(operation.Before, operation.Desired, *observed) {
					return fmt.Errorf("recovered observed state differs from the durable after state")
				}
				// A partial metadata state observed after an interrupted apply or
				// rollback is safe rollback input, but it must not replace the
				// immutable durable after snapshot recorded by the original apply.
			}
			operation.AppliedAt = &resolvedAt
		case model.OperationRolledBack:
			if observed == nil {
				return fmt.Errorf("rolled back recovery state requires an observed snapshot")
			}
			if operation.ObservedRollback == nil {
				copy := *observed
				operation.ObservedRollback = &copy
			} else if !exactEqual(*operation.ObservedRollback, *observed) {
				return fmt.Errorf("recovered rollback state differs from the durable observed rollback state")
			}
			operation.RolledBackAt = &resolvedAt
		}
		return nil
	})
}

func (m *Manager) persistRecoveryRequired(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, cause error) (*model.RemediationJournal, error) {
	operation, _, _, err := findOperation(value, changeSetID, operationID)
	if err != nil {
		return nil, err
	}
	journalError := m.makeJournalError("recovery", changeSetID, operationID, operation, &Error{Code: CodeRecoveryRequired, Err: cause})
	if operation.State.CanTransitionTo(model.OperationAmbiguous) {
		value, err = m.update(ctx, value, "persist ambiguous recovery operation", func(journal *model.RemediationJournal) error {
			target, _, _, findErr := findOperation(journal, changeSetID, operationID)
			if findErr != nil {
				return findErr
			}
			target.State = model.OperationAmbiguous
			target.Error = &journalError
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	changeSet, _, _ := findChangeSet(value, changeSetID)
	if changeSet.State != model.ChangeRecoveryRequired {
		if !changeSet.State.CanTransitionTo(model.ChangeRecoveryRequired) {
			if !changeSet.State.CanTransitionTo(model.ChangeRollingBack) {
				return nil, &Error{Code: CodeInvalidState, Operation: "persist recovery state", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("change set %s cannot enter recovery", changeSet.State)}
			}
			value, err = m.update(ctx, value, "enter recovery transition", func(journal *model.RemediationJournal) error {
				target, _, findErr := findChangeSet(journal, changeSetID)
				if findErr != nil {
					return findErr
				}
				target.State = model.ChangeRollingBack
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		value, err = m.update(ctx, value, "persist change set recovery state", func(journal *model.RemediationJournal) error {
			target, _, findErr := findChangeSet(journal, changeSetID)
			if findErr != nil {
				return findErr
			}
			target.State = model.ChangeRecoveryRequired
			target.Error = &journalError
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if value.State != model.RunRecoveryRequired {
		if !value.State.CanTransitionTo(model.RunRecoveryRequired) {
			if !value.State.CanTransitionTo(model.RunRollingBack) {
				return nil, &Error{Code: CodeInvalidState, Operation: "persist recovery state", RunID: value.RunID, Err: fmt.Errorf("run %s cannot enter recovery", value.State)}
			}
			value, err = m.update(ctx, value, "enter run recovery transition", func(journal *model.RemediationJournal) error {
				journal.State = model.RunRollingBack
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		value, err = m.update(ctx, value, "persist run recovery state", func(journal *model.RemediationJournal) error {
			journal.State = model.RunRecoveryRequired
			journal.Error = &journalError
			journal.UnresolvedChangeSets = appendUnique(journal.UnresolvedChangeSets, changeSetID)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	value, err = m.update(ctx, value, "persist unresolved recovery scope", func(journal *model.RemediationJournal) error {
		journal.UnresolvedChangeSets = appendUnique(journal.UnresolvedChangeSets, changeSetID)
		journal.Error = &journalError
		return nil
	})
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (m *Manager) reconcileRecoveredChangeSet(ctx context.Context, value *model.RemediationJournal, changeSetID string) (*model.RemediationJournal, error) {
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil || changeSet.State == model.ChangeRolledBack {
		return value, err
	}
	allRolledBack := true
	anyRolledBack := false
	allNotApplied := true
	allApplied := true
	for _, operation := range changeSet.Operations {
		allRolledBack = allRolledBack && (operation.State == model.OperationRolledBack || operation.State == model.OperationPlanned || operation.ProvesNoEffect())
		anyRolledBack = anyRolledBack || operation.State == model.OperationRolledBack
		allNotApplied = allNotApplied && (operation.State == model.OperationPlanned || operation.ProvesNoEffect())
		allApplied = allApplied && operation.State == model.OperationApplied
	}
	rollbackResolution := anyRolledBack || changeSet.State == model.ChangeRollingBack || changeSet.State.NeedsOperatorAction()
	if allRolledBack && anyRolledBack && rollbackResolution && changeSet.State != model.ChangeRolledBack {
		rolledBackAt := m.nowUTC()
		if changeSet.State != model.ChangeRollingBack {
			if !changeSet.State.CanTransitionTo(model.ChangeRollingBack) {
				return value, nil
			}
			value, err = m.update(ctx, value, "enter recovered rollback transition", func(journal *model.RemediationJournal) error {
				target, _, findErr := findChangeSet(journal, changeSetID)
				if findErr != nil {
					return findErr
				}
				target.State = model.ChangeRollingBack
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		return m.update(ctx, value, "reconcile recovered rollback", func(journal *model.RemediationJournal) error {
			target, _, findErr := findChangeSet(journal, changeSetID)
			if findErr != nil {
				return findErr
			}
			target.State = model.ChangeRolledBack
			target.RolledBackAt = &rolledBackAt
			target.Error = nil
			return nil
		})
	}
	if allNotApplied && (changeSet.State == model.ChangePrepared ||
		changeSet.State == model.ChangeApplying ||
		changeSet.State == model.ChangeRollingBack ||
		changeSet.State == model.ChangeRollbackBlocked ||
		changeSet.State == model.ChangeRollbackFailed ||
		changeSet.State == model.ChangePartiallyRolledBack ||
		changeSet.State == model.ChangeRecoveryRequired) {
		recoveryError := m.makeJournalError("recover_unapplied", changeSetID, "", nil, &Error{Code: CodeApplyFailed, Err: fmt.Errorf("interrupted change set has no observed applied effect")})
		return m.update(ctx, value, "reconcile unapplied change set", func(journal *model.RemediationJournal) error {
			target, _, findErr := findChangeSet(journal, changeSetID)
			if findErr != nil {
				return findErr
			}
			target.State = model.ChangeApplyFailed
			for _, operation := range target.Operations {
				if operation.ProvesNoEffect() && operation.Error != nil {
					errorCopy := *operation.Error
					target.Error = &errorCopy
					break
				}
			}
			if target.Error == nil {
				target.Error = &recoveryError
			}
			return nil
		})
	}
	if allApplied && changeSet.State == model.ChangeApplying {
		afterByResource := make(map[string]model.ResourceSnapshot, len(changeSet.Resources))
		for _, operation := range changeSet.Operations {
			if operation.ObservedAfter == nil {
				return value, &Error{Code: CodeRecoveryRequired, Operation: "reconcile applied change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operation.ID, Err: fmt.Errorf("applied operation has no durable after observation")}
			}
			afterByResource[operation.Resource.Key] = *operation.ObservedAfter
		}
		orderedAfter := make([]model.ResourceSnapshot, 0, len(changeSet.Resources))
		for _, resource := range changeSet.Resources {
			after, exists := afterByResource[resource.Key]
			if !exists {
				return value, &Error{Code: CodeRecoveryRequired, Operation: "reconcile applied change set", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("resource %s has no durable after observation", resource.Key)}
			}
			orderedAfter = append(orderedAfter, after)
		}
		appliedAt := m.nowUTC()
		return m.update(ctx, value, "reconcile applied change set", func(journal *model.RemediationJournal) error {
			target, _, findErr := findChangeSet(journal, changeSetID)
			if findErr != nil {
				return findErr
			}
			target.After = orderedAfter
			target.AppliedAt = &appliedAt
			target.State = model.ChangeApplied
			return nil
		})
	}
	return value, nil
}

func (m *Manager) finalizeIncompleteRollbackAttempt(ctx context.Context, value *model.RemediationJournal) (*model.RemediationJournal, bool, error) {
	attempt, incomplete := incompleteRollbackAttempt(value)
	if !incomplete {
		return value, false, nil
	}
	attemptID := attempt.ID
	targets := append([]string(nil), attempt.ExpandedChangeSets...)
	if len(targets) == 0 {
		return value, true, &Error{Code: CodeInvalidState, Operation: "recover incomplete rollback", RunID: value.RunID, Err: fmt.Errorf("rollback attempt %s has no expanded scope", attemptID)}
	}

	remaining := make([]string, 0, len(targets))
	for _, changeSetID := range targets {
		_, _, err := findChangeSet(value, changeSetID)
		if err != nil {
			return value, true, &Error{Code: CodeInvalidState, Operation: "recover incomplete rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: err}
		}
		if !hasRollbackWork(value, changeSetID) {
			continue
		}
		remaining = append(remaining, changeSetID)
	}
	anyRolledBack := hasRolledBackInTargets(value, targets)

	if len(remaining) > 0 {
		for _, changeSetID := range remaining {
			changeSet, _, err := findChangeSet(value, changeSetID)
			if err != nil {
				return value, true, err
			}
			journalError := m.makeJournalError("recover_interrupted_rollback", changeSetID, "", nil, &Error{Code: CodeRollbackFailed, Err: fmt.Errorf("rollback attempt %s ended before this change set was durably completed", attemptID)})
			if changeSet.State != model.ChangeRollbackFailed {
				if changeSet.State != model.ChangeRollingBack {
					if !changeSet.State.CanTransitionTo(model.ChangeRollingBack) {
						return value, true, &Error{Code: CodeRecoveryRequired, Operation: "recover incomplete rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set %s cannot re-enter rollback", changeSet.State)}
					}
					value, err = m.update(ctx, value, "re-enter interrupted rollback state", func(journal *model.RemediationJournal) error {
						target, _, findErr := findChangeSet(journal, changeSetID)
						if findErr != nil {
							return findErr
						}
						target.State = model.ChangeRollingBack
						return nil
					})
					if err != nil {
						return value, true, err
					}
				}
				value, err = m.update(ctx, value, "mark interrupted rollback retryable", func(journal *model.RemediationJournal) error {
					target, _, findErr := findChangeSet(journal, changeSetID)
					if findErr != nil {
						return findErr
					}
					target.State = model.ChangeRollbackFailed
					target.Error = &journalError
					return nil
				})
				if err != nil {
					return value, true, err
				}
			}
		}
	}

	if value.State != model.RunRollingBack {
		if !value.State.CanTransitionTo(model.RunRollingBack) {
			return value, true, &Error{Code: CodeRecoveryRequired, Operation: "recover incomplete rollback", RunID: value.RunID, Err: fmt.Errorf("run %s cannot re-enter rollback", value.State)}
		}
		var err error
		value, err = m.update(ctx, value, "re-enter interrupted run rollback", func(journal *model.RemediationJournal) error {
			journal.State = model.RunRollingBack
			return nil
		})
		if err != nil {
			return value, true, err
		}
	}

	completedAt := m.nowUTC()
	outcome := model.RollbackSucceeded
	targetUnresolved := rollbackTargetUnresolved(value, targets)
	unresolved := appendUnique(unresolvedRollbackChangeSets(value), targetUnresolved...)
	outsideViolation := false
	if len(remaining) > 0 {
		outcome = model.RollbackFailed
		if anyRolledBack {
			outcome = model.RollbackPartial
		}
	}
	if len(targetUnresolved) > 0 && outcome == model.RollbackSucceeded {
		outcome = model.RollbackFailed
		if anyRolledBack {
			outcome = model.RollbackPartial
		}
	}
	outsideUnresolved := rollbackOutsideUnresolved(value, targets, attempt.Scope)
	if len(outsideUnresolved) > 0 {
		unresolved = appendUnique(unresolved, outsideUnresolved...)
		outsideViolation = true
		if attempt.Scope == model.RollbackRun {
			outcome = model.RollbackFailed
		}
	}
	finalState := classifyRollbackRunState(value, targets, attempt.Scope)
	if outsideViolation {
		finalState = model.RunRecoveryRequired
	}

	errorCode := CodeRollbackFailed
	errorReason := fmt.Errorf("rollback attempt %s was interrupted", attemptID)
	if finalState == model.RunRecoveryRequired {
		errorCode = CodeRecoveryRequired
		errorReason = fmt.Errorf("rollback attempt %s requires recovery for unresolved or non-verified change state", attemptID)
	}
	journalError := m.makeJournalError("recover_interrupted_rollback", "", "", nil, &Error{Code: errorCode, Err: errorReason})
	applyFailureError := firstApplyFailureError(value)
	next, err := m.update(ctx, value, "complete interrupted rollback attempt", func(journal *model.RemediationJournal) error {
		last := &journal.RollbackAttempts[len(journal.RollbackAttempts)-1]
		if last.ID != attemptID || last.CompletedAt != nil {
			return fmt.Errorf("incomplete rollback attempt changed during recovery")
		}
		last.Outcome = outcome
		last.CompletedAt = &completedAt
		if outcome != model.RollbackSucceeded || outsideViolation {
			last.Errors = append(last.Errors, journalError)
			journal.Error = &journalError
		} else if finalState == model.RunFailed && applyFailureError != nil {
			errorCopy := *applyFailureError
			journal.Error = &errorCopy
		} else if !finalState.NeedsOperatorAction() {
			journal.Error = nil
		}
		journal.State = finalState
		journal.UnresolvedChangeSets = unresolved
		return nil
	})
	if err != nil {
		return value, true, err
	}
	return next, true, nil
}

func activeChangeSetsOutside(value *model.RemediationJournal, selected []string) []string {
	if value == nil {
		return nil
	}
	selectedSet := make(map[string]struct{}, len(selected))
	for _, changeSetID := range selected {
		selectedSet[changeSetID] = struct{}{}
	}
	active := activeMap(value)
	result := make([]string, 0)
	for _, changeSet := range value.ChangeSets {
		if _, included := selectedSet[changeSet.ID]; !included && active[changeSet.ID] {
			result = append(result, changeSet.ID)
		}
	}
	return result
}

func unresolvedRollbackChangeSets(value *model.RemediationJournal) []string {
	if value == nil {
		return nil
	}
	result := make([]string, 0)
	for _, changeSet := range value.ChangeSets {
		switch changeSet.State {
		case model.ChangeRollbackBlocked,
			model.ChangeRollbackFailed,
			model.ChangePartiallyRolledBack,
			model.ChangeRecoveryRequired:
			result = append(result, changeSet.ID)
		case model.ChangeRollingBack:
			if changeSet.Error != nil && changeSet.Error.Code == model.JournalErrorRecoveryAmbiguous {
				result = append(result, changeSet.ID)
			}
		}
	}
	return appendUnique(nil, result...)
}

func (m *Manager) finalizeCompletedRollbackTransition(ctx context.Context, value *model.RemediationJournal) (*model.RemediationJournal, bool, error) {
	if value == nil || value.State != model.RunRollingBack || len(value.RollbackAttempts) == 0 {
		return value, false, nil
	}
	attempt := value.RollbackAttempts[len(value.RollbackAttempts)-1]
	if attempt.CompletedAt == nil {
		return value, false, nil
	}
	if !attempt.Outcome.Valid() || attempt.Outcome == "" {
		return value, true, &Error{Code: CodeRecoveryRequired, Operation: "recover completed rollback transition", RunID: value.RunID, Err: fmt.Errorf("rollback attempt %s has no completed outcome", attempt.ID)}
	}
	if attempt.Outcome != model.RollbackSucceeded && rollbackScopeResolved(value, attempt.ExpandedChangeSets) {
		next, err := m.finalizeResolvedCrashRollback(ctx, value, attempt.Scope, attempt.RequestedChangeSets, attempt.ExpandedChangeSets, attempt.CascadeApproved)
		return next, true, err
	}
	finalState := classifyRollbackRunState(value, attempt.ExpandedChangeSets, attempt.Scope)
	targetUnresolved := rollbackTargetUnresolved(value, attempt.ExpandedChangeSets)
	unresolved := appendUnique(unresolvedRollbackChangeSets(value), targetUnresolved...)
	unresolved = appendUnique(unresolved, rollbackOutsideUnresolved(value, attempt.ExpandedChangeSets, attempt.Scope)...)
	if len(targetUnresolved) > 0 {
		finalState = model.RunRecoveryRequired
	}
	if len(rollbackOutsideUnresolved(value, attempt.ExpandedChangeSets, attempt.Scope)) > 0 {
		finalState = model.RunRecoveryRequired
	}
	stateError := m.rollbackRunStateError("recover_completed_rollback", finalState)
	applyFailureError := firstApplyFailureError(value)
	next, err := m.update(ctx, value, "complete recovered rollback run transition", func(journal *model.RemediationJournal) error {
		journal.State = finalState
		journal.UnresolvedChangeSets = unresolved
		if stateError != nil {
			errorCopy := *stateError
			journal.Error = &errorCopy
		} else if finalState == model.RunFailed && applyFailureError != nil {
			errorCopy := *applyFailureError
			journal.Error = &errorCopy
		} else {
			journal.Error = nil
		}
		return nil
	})
	if err != nil {
		return value, true, err
	}
	return next, true, nil
}

func rollbackScopeResolved(value *model.RemediationJournal, targets []string) bool {
	return value != nil && len(targets) > 0 && len(rollbackTargetUnresolved(value, targets)) == 0
}

func lastUnsuccessfulRollbackAttempt(value *model.RemediationJournal) (model.RollbackAttempt, bool) {
	if value == nil || len(value.RollbackAttempts) == 0 {
		return model.RollbackAttempt{}, false
	}
	attempt := value.RollbackAttempts[len(value.RollbackAttempts)-1]
	if attempt.CompletedAt == nil || attempt.Outcome == model.RollbackSucceeded {
		return model.RollbackAttempt{}, false
	}
	return attempt, true
}

func recoveredRollbackTargets(value *model.RemediationJournal) []string {
	if value == nil {
		return nil
	}
	result := make([]string, 0)
	for _, changeSet := range value.ChangeSets {
		if changeSet.State == model.ChangeRolledBack {
			result = append(result, changeSet.ID)
		}
	}
	return result
}

func completedRollbackAttemptCovers(value *model.RemediationJournal, changeSetID string) bool {
	if value == nil {
		return false
	}
	for _, attempt := range value.RollbackAttempts {
		if attempt.CompletedAt == nil || (attempt.Outcome != model.RollbackSucceeded && attempt.Outcome != model.RollbackPartial) {
			continue
		}
		for _, candidate := range attempt.ExpandedChangeSets {
			if candidate == changeSetID {
				return true
			}
		}
	}
	return false
}

func uncoveredRecoveredRollbackTargets(value *model.RemediationJournal) []string {
	if value == nil {
		return nil
	}
	result := make([]string, 0)
	for _, changeSet := range value.ChangeSets {
		if changeSet.State == model.ChangeRolledBack && !completedRollbackAttemptCovers(value, changeSet.ID) {
			result = append(result, changeSet.ID)
		}
	}
	return result
}

func (m *Manager) finalizeResolvedCrashRollback(
	ctx context.Context,
	value *model.RemediationJournal,
	scope model.RollbackScope,
	requested, targets []string,
	cascadeApproved bool,
) (*model.RemediationJournal, error) {
	// One recovery pass can reconcile effects from several historical failed
	// attempts. Cover every rolled-back change that still lacks immutable
	// successful/partial attempt history in this crash-recovery attempt; leaving
	// one outside would make a normal terminal state unverifiable and could
	// strand an otherwise safe item rollback when verified changes remain.
	uncovered := uncoveredRecoveredRollbackTargets(value)
	targets = appendUnique(targets, uncovered...)
	requested = appendUnique(requested, uncovered...)
	targets = appendUnique(nil, targets...)
	requested = appendUnique(nil, requested...)
	if len(targets) == 0 {
		return value, &Error{Code: CodeInvalidState, Operation: "finalize resolved crash rollback", RunID: value.RunID, Err: fmt.Errorf("resolved rollback scope is empty")}
	}
	attemptID, err := m.nextID("rollback-")
	if err != nil {
		return value, &Error{Code: CodePersistFailed, Operation: "generate crash recovery attempt ID", RunID: value.RunID, Err: err}
	}
	now := m.nowUTC()
	finalState := classifyRollbackRunState(value, targets, scope)
	outsideUnresolved := rollbackOutsideUnresolved(value, targets, scope)
	unresolved := appendUnique(unresolvedRollbackChangeSets(value), rollbackTargetUnresolved(value, targets)...)
	unresolved = appendUnique(unresolved, outsideUnresolved...)
	if len(outsideUnresolved) > 0 {
		finalState = model.RunRecoveryRequired
	}
	stateError := m.rollbackRunStateError("recover_resolved_crash_rollback", finalState)
	applyFailureError := firstApplyFailureError(value)
	attemptErrors := make([]model.JournalError, 0, 1)
	if stateError != nil {
		attemptErrors = append(attemptErrors, *stateError)
	}
	next, err := m.update(ctx, value, "record resolved crash rollback", func(journal *model.RemediationJournal) error {
		journal.State = model.RunRollingBack
		journal.RollbackAttempts = append(journal.RollbackAttempts, model.RollbackAttempt{
			ID:                  attemptID,
			Scope:               scope,
			Trigger:             model.RollbackCrashRecovery,
			RequestedChangeSets: append([]string(nil), requested...),
			ExpandedChangeSets:  append([]string(nil), targets...),
			CascadeApproved:     cascadeApproved,
			Outcome:             model.RollbackSucceeded,
			StartedAt:           now,
			CompletedAt:         &now,
			Errors:              append([]model.JournalError(nil), attemptErrors...),
		})
		return nil
	})
	if err != nil {
		return value, err
	}
	return m.update(ctx, next, "complete resolved crash rollback", func(journal *model.RemediationJournal) error {
		journal.State = finalState
		journal.UnresolvedChangeSets = unresolved
		if stateError != nil {
			errorCopy := *stateError
			journal.Error = &errorCopy
		} else if finalState == model.RunFailed && applyFailureError != nil {
			errorCopy := *applyFailureError
			journal.Error = &errorCopy
		} else {
			journal.Error = nil
		}
		return nil
	})
}

func (m *Manager) finalizeRecoveredRun(ctx context.Context, value *model.RemediationJournal, assessment RecoveryAssessment) (*model.RemediationJournal, error) {
	if len(assessment.Ambiguous) > 0 {
		return value, nil
	}
	if len(value.RollbackAttempts) > 0 {
		attempt := value.RollbackAttempts[len(value.RollbackAttempts)-1]
		if attemptTargetsOnlyNoEffect(value, attempt.ExpandedChangeSets) {
			return m.finalizeNoEffectRollbackAttempt(ctx, value, attempt)
		}
	}
	if next, handled, err := m.finalizeIncompleteRollbackAttempt(ctx, value); handled {
		return next, err
	}
	if next, handled, err := m.finalizeCompletedRollbackTransition(ctx, value); handled {
		return next, err
	}
	stableInterruptedApply := stableInterruptedApplyShape(value) && (value.State == model.RunApplying ||
		value.State == model.RunVerifying ||
		(value.State == model.RunRecoveryRequired && hasApplyFailedChangeSet(value)))
	if stableInterruptedApply {
		targets := rollbackTargets(value)
		journalError := firstApplyFailureError(value)
		if journalError == nil {
			generated := m.makeJournalError("recover_interrupted_apply", "", "", nil, &Error{Code: CodeApplyFailed, Err: fmt.Errorf("interrupted apply has no nonterminal target effect")})
			journalError = &generated
		}
		if value.FailurePolicy == model.FailureRollbackRun && len(targets) > 0 {
			if value.State == model.RunRecoveryRequired && sameIDs(value.UnresolvedChangeSets, targets) {
				return value, nil
			}
			return m.update(ctx, value, "require rollback for recovered run-policy failure", func(journal *model.RemediationJournal) error {
				journal.State = model.RunRecoveryRequired
				journal.UnresolvedChangeSets = appendUnique(nil, targets...)
				if journalError != nil {
					errorCopy := *journalError
					journal.Error = &errorCopy
				}
				return nil
			})
		}
		return m.update(ctx, value, "finalize recovered stable apply interruption", func(journal *model.RemediationJournal) error {
			journal.State = model.RunFailed
			journal.UnresolvedChangeSets = nil
			if journalError != nil {
				errorCopy := *journalError
				journal.Error = &errorCopy
			}
			return nil
		})
	}
	operatorActionState := value.State == model.RunRecoveryRequired || value.State == model.RunRollbackFailed || value.State == model.RunPartiallyRolledBack
	if operatorActionState {
		if prior, available := lastUnsuccessfulRollbackAttempt(value); available && rollbackScopeResolved(value, prior.ExpandedChangeSets) {
			return m.finalizeResolvedCrashRollback(ctx, value, prior.Scope, prior.RequestedChangeSets, prior.ExpandedChangeSets, prior.CascadeApproved)
		}
		if len(rollbackTargets(value)) == 0 && len(unresolvedRollbackChangeSets(value)) == 0 && !hasRecoveryRequiredEvidence(value) {
			targets := recoveredRollbackTargets(value)
			if len(targets) > 0 {
				return m.finalizeResolvedCrashRollback(ctx, value, model.RollbackRun, nil, targets, true)
			}
			if value.State != model.RunRecoveryRequired {
				return value, nil
			}
			applyFailureError := firstApplyFailureError(value)
			return m.update(ctx, value, "finalize resolved recovery", func(journal *model.RemediationJournal) error {
				journal.State = model.RunFailed
				journal.UnresolvedChangeSets = nil
				if applyFailureError != nil {
					errorCopy := *applyFailureError
					journal.Error = &errorCopy
				} else {
					journal.Error = nil
				}
				return nil
			})
		}
	}
	if value.State == model.RunRollingBack && len(rollbackTargets(value)) == 0 {
		return value, &Error{Code: CodeRecoveryRequired, Operation: "finalize recovered rollback", RunID: value.RunID, Err: fmt.Errorf("rolling-back run has no incomplete or completed attempt marker")}
	}
	targets := rollbackTargets(value)
	if (value.State == model.RunApplying || value.State == model.RunVerifying) && len(targets) > 0 {
		journalError := m.makeJournalError("recover_active_apply", "", "", nil, &Error{Code: CodeRecoveryRequired, Err: fmt.Errorf("recovered applied effects require an approved rollback")})
		return m.update(ctx, value, "require rollback for recovered active apply", func(journal *model.RemediationJournal) error {
			journal.State = model.RunRecoveryRequired
			journal.UnresolvedChangeSets = appendUnique(nil, targets...)
			journal.Error = &journalError
			return nil
		})
	}
	if (value.State == model.RunPlanned || value.State == model.RunApproved || value.State == model.RunApplying) && len(rollbackTargets(value)) == 0 {
		return m.update(ctx, value, "finalize recovered apply failure", func(journal *model.RemediationJournal) error {
			journal.State = model.RunFailed
			journal.UnresolvedChangeSets = nil
			return nil
		})
	}
	return value, nil
}

func attemptTargetsOnlyNoEffect(value *model.RemediationJournal, targets []string) bool {
	if value == nil || len(targets) == 0 || hasRolledBackInTargets(value, targets) {
		return false
	}
	foundNoEffect := false
	for _, changeSetID := range targets {
		changeSet, _, err := findChangeSet(value, changeSetID)
		if err != nil {
			return false
		}
		switch changeSet.State {
		case model.ChangePlanned,
			model.ChangePrepared,
			model.ChangeApplying,
			model.ChangeApplyFailed,
			model.ChangeRollingBack,
			model.ChangeRollbackBlocked,
			model.ChangeRollbackFailed,
			model.ChangePartiallyRolledBack,
			model.ChangeRecoveryRequired:
		default:
			return false
		}
		for _, operation := range changeSet.Operations {
			if operation.ProvesNoEffect() {
				foundNoEffect = true
				continue
			}
			if operation.State != model.OperationPlanned {
				return false
			}
		}
	}
	return foundNoEffect
}

func (m *Manager) finalizeNoEffectRollbackAttempt(ctx context.Context, value *model.RemediationJournal, attempt model.RollbackAttempt) (*model.RemediationJournal, error) {
	completedAt := m.nowUTC()
	rollbackError := m.makeJournalError("recover_no_effect_rollback", "", "", nil, &Error{Code: CodeRollbackFailed, Err: fmt.Errorf("rollback attempt had no live effect to restore")})
	applyError := firstNoEffectError(value)
	unresolved := unresolvedAfterNoEffectAttempt(value, attempt.ExpandedChangeSets)
	finalState := model.RunFailed
	if len(unresolved) > 0 {
		if value.State.CanTransitionTo(model.RunRecoveryRequired) {
			finalState = model.RunRecoveryRequired
		} else if value.State.NeedsOperatorAction() {
			finalState = value.State
		} else {
			return value, &Error{Code: CodeRecoveryRequired, Operation: "finalize no-effect rollback attempt", RunID: value.RunID, Err: fmt.Errorf("run %s cannot retain unresolved outside changes", value.State)}
		}
	}
	return m.update(ctx, value, "finalize no-effect rollback attempt", func(journal *model.RemediationJournal) error {
		if len(journal.RollbackAttempts) == 0 || journal.RollbackAttempts[len(journal.RollbackAttempts)-1].ID != attempt.ID {
			return fmt.Errorf("rollback attempt changed during no-effect recovery")
		}
		for _, changeSetID := range attempt.ExpandedChangeSets {
			changeSet, _, findErr := findChangeSet(journal, changeSetID)
			if findErr != nil {
				return findErr
			}
			hasNoEffect := false
			for _, operation := range changeSet.Operations {
				if operation.ProvesNoEffect() && operation.Error != nil {
					hasNoEffect = true
					errorCopy := *operation.Error
					changeSet.Error = &errorCopy
					break
				}
			}
			if changeSet.State != model.ChangePlanned || hasNoEffect {
				changeSet.State = model.ChangeApplyFailed
				changeSet.RolledBackAt = nil
			}
		}
		latest := &journal.RollbackAttempts[len(journal.RollbackAttempts)-1]
		if latest.CompletedAt == nil {
			latest.Outcome = model.RollbackBlocked
			latest.CompletedAt = &completedAt
			latest.Errors = append(latest.Errors, rollbackError)
		} else {
			journal.Warnings = appendUnique(journal.Warnings, "완료된 롤백 시도에 실제 복원 대상이 없었으며 무효과 적용 실패로 정합화했습니다.")
		}
		journal.State = finalState
		journal.UnresolvedChangeSets = appendUnique(nil, unresolved...)
		if finalState.NeedsOperatorAction() {
			journal.Error = &rollbackError
		} else if applyError != nil {
			errorCopy := *applyError
			journal.Error = &errorCopy
		} else {
			journal.Error = &rollbackError
		}
		return nil
	})
}

func unresolvedAfterNoEffectAttempt(value *model.RemediationJournal, targets []string) []string {
	if value == nil {
		return nil
	}
	selected := make(map[string]struct{}, len(targets))
	for _, changeSetID := range targets {
		selected[changeSetID] = struct{}{}
	}
	result := make([]string, 0)
	for _, changeSet := range value.ChangeSets {
		if _, resolved := selected[changeSet.ID]; resolved {
			continue
		}
		safe := false
		switch changeSet.State {
		case model.ChangePlanned:
			safe = true
			for _, operation := range changeSet.Operations {
				safe = safe && operation.State == model.OperationPlanned
			}
		case model.ChangeVerified:
			safe = value.FailurePolicy != model.FailureRollbackRun
			for _, operation := range changeSet.Operations {
				safe = safe && operation.State == model.OperationVerified
			}
		case model.ChangeApplyFailed:
			safe = terminalRollbackSafeChangeSet(changeSet)
		case model.ChangeRolledBack:
			safe = terminalRollbackSafeChangeSet(changeSet) && rolledBackChangeSetCovered(value, changeSet.ID)
		}
		if !safe {
			result = append(result, changeSet.ID)
		}
	}
	return appendUnique(nil, result...)
}

func rolledBackChangeSetCovered(value *model.RemediationJournal, changeSetID string) bool {
	hasSucceededAttempt := false
	for _, attempt := range value.RollbackAttempts {
		if attempt.CompletedAt == nil {
			continue
		}
		if attempt.Outcome == model.RollbackSucceeded {
			hasSucceededAttempt = true
		}
	}
	return hasSucceededAttempt && completedRollbackAttemptCovers(value, changeSetID)
}

func stableInterruptedApplyShape(value *model.RemediationJournal) bool {
	if value == nil {
		return false
	}
	for _, changeSet := range value.ChangeSets {
		switch changeSet.State {
		case model.ChangePlanned:
			for _, operation := range changeSet.Operations {
				if operation.State != model.OperationPlanned {
					return false
				}
			}
		case model.ChangeVerified:
			for _, operation := range changeSet.Operations {
				if operation.State != model.OperationVerified {
					return false
				}
			}
		case model.ChangeApplyFailed:
			for _, operation := range changeSet.Operations {
				if operation.ProvesNoEffect() {
					continue
				}
				if operation.State != model.OperationPlanned {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func firstApplyFailureError(value *model.RemediationJournal) *model.JournalError {
	if value == nil {
		return nil
	}
	for _, changeSet := range value.ChangeSets {
		if changeSet.State != model.ChangeApplyFailed {
			continue
		}
		if changeSet.Error != nil {
			return changeSet.Error
		}
		for _, operation := range changeSet.Operations {
			if operation.ProvesNoEffect() && operation.Error != nil {
				return operation.Error
			}
		}
	}
	if value.Error != nil && value.Error.Code == model.JournalErrorApplyFailed {
		return value.Error
	}
	for attemptIndex := range value.RollbackAttempts {
		for errorIndex := range value.RollbackAttempts[attemptIndex].Errors {
			candidate := &value.RollbackAttempts[attemptIndex].Errors[errorIndex]
			if candidate.Code == model.JournalErrorApplyFailed {
				return candidate
			}
		}
	}
	return nil
}

func firstNoEffectError(value *model.RemediationJournal) *model.JournalError {
	if value == nil {
		return nil
	}
	for _, changeSet := range value.ChangeSets {
		for _, operation := range changeSet.Operations {
			if operation.ProvesNoEffect() && operation.Error != nil {
				return operation.Error
			}
		}
	}
	return nil
}

func sameIDs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func splitAssessmentID(value string) (string, string) {
	for index, character := range value {
		if character == '/' {
			return value[:index], value[index+1:]
		}
	}
	return value, ""
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func removeAssessmentIDs(values, removals []string) []string {
	removed := make(map[string]struct{}, len(removals))
	for _, value := range removals {
		removed[value] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := removed[value]; !exists {
			result = append(result, value)
		}
	}
	return result
}

func assessmentContainsChangeSet(values []string, changeSetID string) bool {
	prefix := changeSetID + "/"
	for _, value := range values {
		if len(value) >= len(prefix) && value[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
