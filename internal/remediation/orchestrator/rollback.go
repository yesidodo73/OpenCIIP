package orchestrator

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/conflict"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
)

type rollbackFailure struct {
	err       error
	ambiguous bool
}

func (m *Manager) RollbackItem(ctx context.Context, runID, changeSetID string, cascadeApproved bool, previewDigest string, executorBuild model.RemediationBuildIdentity) (model.RollbackAttempt, error) {
	if err := executorBuild.ValidateRollbackExecutor(); err != nil {
		return model.RollbackAttempt{}, &Error{Code: CodeInvalidInput, Operation: "rollback item", RunID: runID, ChangeSetID: changeSetID, Err: fmt.Errorf("invalid rollback executor build: %w", err)}
	}
	lock, err := m.acquire(ctx, "rollback item")
	if err != nil {
		return model.RollbackAttempt{}, err
	}
	defer lock.Release()
	if err := m.ensureNoOtherRecoverable(ctx, runID); err != nil {
		return model.RollbackAttempt{}, err
	}
	value, err := m.loadAndVerifyReadOnly(ctx, runID)
	if err != nil {
		return model.RollbackAttempt{}, err
	}
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return model.RollbackAttempt{}, &Error{Code: CodeInvalidInput, Operation: "rollback item", RunID: runID, ChangeSetID: changeSetID, Err: err}
	}
	if !hasRollbackWork(value, changeSetID) || !itemRollbackState(changeSet.State) {
		return model.RollbackAttempt{}, &Error{Code: CodeInvalidState, Operation: "rollback item", RunID: runID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set %s is not rollback-eligible", changeSet.State)}
	}
	preview, previewErr := m.previewRollbackItem(value, changeSetID)
	if previewErr != nil {
		return model.RollbackAttempt{}, previewErr
	}
	if !rollbackPreviewDigestMatches(previewDigest, preview.PreviewDigest) {
		return model.RollbackAttempt{}, &Error{Code: CodeRollbackPreviewStale, Operation: "rollback item", RunID: runID, ChangeSetID: changeSetID, Err: fmt.Errorf("rollback scope changed or was not previewed at revision %d", value.Revision)}
	}
	if preview.CascadeRequired && !cascadeApproved {
		return model.RollbackAttempt{}, &Error{Code: CodeCascadeRequired, Operation: "rollback item", RunID: runID, ChangeSetID: changeSetID, Err: fmt.Errorf("the approved preview requires cascade rollback")}
	}
	return m.executeRollback(ctx, value, model.RollbackItem, model.RollbackUserRequest, []string{changeSetID}, preview.ExpandedChangeSets, cascadeApproved, executorBuild)
}

func itemRollbackState(state model.ChangeSetState) bool {
	switch state {
	case model.ChangeApplying,
		model.ChangeApplied,
		model.ChangeVerifying,
		model.ChangeVerified,
		model.ChangeApplyFailed,
		model.ChangeRollingBack,
		model.ChangeRollbackBlocked,
		model.ChangeRollbackFailed,
		model.ChangePartiallyRolledBack,
		model.ChangeRecoveryRequired:
		return true
	default:
		return false
	}
}

func (m *Manager) RollbackRun(ctx context.Context, runID, previewDigest string, executorBuild model.RemediationBuildIdentity) (model.RollbackAttempt, error) {
	if err := executorBuild.ValidateRollbackExecutor(); err != nil {
		return model.RollbackAttempt{}, &Error{Code: CodeInvalidInput, Operation: "rollback run", RunID: runID, Err: fmt.Errorf("invalid rollback executor build: %w", err)}
	}
	lock, err := m.acquire(ctx, "rollback run")
	if err != nil {
		return model.RollbackAttempt{}, err
	}
	defer lock.Release()
	if err := m.ensureNoOtherRecoverable(ctx, runID); err != nil {
		return model.RollbackAttempt{}, err
	}
	value, err := m.loadAndVerifyReadOnly(ctx, runID)
	if err != nil {
		return model.RollbackAttempt{}, err
	}
	preview, previewErr := m.previewRollbackRun(value)
	if previewErr != nil {
		return model.RollbackAttempt{}, previewErr
	}
	if !rollbackPreviewDigestMatches(previewDigest, preview.PreviewDigest) {
		return model.RollbackAttempt{}, &Error{Code: CodeRollbackPreviewStale, Operation: "rollback run", RunID: runID, Err: fmt.Errorf("rollback scope changed or was not previewed at revision %d", value.Revision)}
	}
	return m.executeRollback(ctx, value, model.RollbackRun, model.RollbackUserRequest, nil, preview.ExpandedChangeSets, true, executorBuild)
}

func rollbackPreviewDigestMatches(provided, expected string) bool {
	return provided != "" && len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (m *Manager) rollbackForFailure(ctx context.Context, value *model.RemediationJournal, failedChangeSet string, cause error, trigger model.RollbackTrigger) error {
	phase := "apply"
	if trigger == model.RollbackVerifyFailure {
		phase = "verification"
	}
	journalError := m.makeJournalError(value, phase, failedChangeSet, "", nil, cause)
	mutateFailure := func(journal *model.RemediationJournal) error {
		changeSet, _, findErr := findChangeSet(journal, failedChangeSet)
		if findErr != nil {
			return findErr
		}
		changeSet.Error = &journalError
		return nil
	}
	next, err := m.updateBeforeAutomaticRollback(ctx, value, "persist change set failure", mutateFailure, func(journal *model.RemediationJournal) bool {
		changeSet, _, findErr := findChangeSet(journal, failedChangeSet)
		return findErr == nil && journalErrorMatches(changeSet.Error, journalError)
	})
	if err != nil {
		return err
	}
	value = next
	active := activeMap(value)
	active[failedChangeSet] = hasRollbackWork(value, failedChangeSet)
	targets := make([]string, 0)
	scope := model.RollbackItem
	if value.FailurePolicy == model.FailureRollbackRun {
		scope = model.RollbackRun
		for _, changeSet := range value.ChangeSets {
			if active[changeSet.ID] {
				targets = append(targets, changeSet.ID)
			}
		}
	} else {
		closure, err := conflict.ItemRollbackClosure(value.ConflictGraph, failedChangeSet, active, true)
		if err != nil {
			return wrapDependency("compute failure rollback closure", value.RunID, failedChangeSet, "", err)
		}
		for _, id := range closure {
			if active[id] {
				targets = append(targets, id)
			}
		}
	}
	if len(targets) == 0 {
		return cause
	}
	_, err = m.executeRollback(ctx, value, scope, trigger, []string{failedChangeSet}, targets, true, value.RemediationBuild)
	return err
}

func (m *Manager) failBeforeSideEffect(
	ctx context.Context,
	value *model.RemediationJournal,
	handler fileRuntime,
	changeSetID string,
	cause error,
) error {
	if value == nil {
		return cause
	}
	journalError := m.makeJournalError(value, "prepare", changeSetID, "", nil, cause)
	mutateFailure := func(journal *model.RemediationJournal) error {
		changeSet, _, findErr := findChangeSet(journal, changeSetID)
		if findErr != nil {
			return findErr
		}
		changeSet.State = model.ChangeApplyFailed
		changeSet.Error = &journalError
		return nil
	}
	next, err := m.updateBeforeAutomaticRollback(ctx, value, "persist preparation failure", mutateFailure, func(journal *model.RemediationJournal) bool {
		changeSet, _, findErr := findChangeSet(journal, changeSetID)
		return findErr == nil && changeSet.State == model.ChangeApplyFailed && journalErrorMatches(changeSet.Error, journalError)
	})
	if err != nil {
		return err
	}
	priorTargets := rollbackTargets(next)
	filtered := priorTargets[:0]
	for _, id := range priorTargets {
		if id != changeSetID {
			filtered = append(filtered, id)
		}
	}
	priorTargets = filtered
	if next.FailurePolicy == model.FailureRollbackRun && len(priorTargets) > 0 {
		_, rollbackErr := m.executeRollback(ctx, next, model.RollbackRun, model.RollbackApplyFailure, []string{changeSetID}, priorTargets, true, next.RemediationBuild)
		if rollbackErr != nil {
			return rollbackErr
		}
		return cause
	}
	next, err = m.verifyRetainedWriterFrontier(ctx, next, handler)
	if err != nil {
		return err
	}
	terminalMutation := func(journal *model.RemediationJournal) error {
		journal.State = model.RunFailed
		journal.Error = &journalError
		return nil
	}
	expectedTerminal, err := cloneRecoveryJournal(next)
	if err != nil {
		return &Error{Code: CodeInvalidState, Operation: "build expected preparation-failure terminal", RunID: next.RunID, Err: err}
	}
	if err := terminalMutation(expectedTerminal); err != nil {
		return &Error{Code: CodeInvalidState, Operation: "build expected preparation-failure terminal", RunID: next.RunID, Err: err}
	}
	expectedTerminal.Revision = next.Revision + 1
	expectedTerminal.UpdatedAt = expectedTerminal.LatestEventTime()
	if err := expectedTerminal.Validate(); err != nil {
		return &Error{Code: CodeInvalidState, Operation: "build expected preparation-failure terminal", RunID: next.RunID, Err: err}
	}

	_, terminalErr := m.update(ctx, next, "fail run without item side effects", terminalMutation)
	if terminalErr == nil {
		return cause
	}
	terminal, err := m.reloadApplyJournal(ctx, next.RunID, "reload after fail run without item side effects", terminalErr)
	if err != nil {
		return err
	}
	if recoveryTerminalRevisionMatches(expectedTerminal, terminal) {
		return cause
	}
	if _, err = m.verifyRetainedWriterFrontier(ctx, terminal, handler); err != nil {
		return err
	}
	return terminalErr
}

func rollbackTargets(value *model.RemediationJournal) []string {
	result := make([]string, 0)
	for _, changeSet := range value.ChangeSets {
		if hasRollbackWork(value, changeSet.ID) {
			result = append(result, changeSet.ID)
		}
	}
	return result
}

func completeRollbackGroups(graph model.ConflictGraph, targets []string) []string {
	selected := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		selected[target] = struct{}{}
	}
	for _, group := range graph.Groups {
		include := false
		for _, member := range group.ChangeSets {
			if _, exists := selected[member]; exists {
				include = true
				break
			}
		}
		if include {
			for _, member := range group.ChangeSets {
				selected[member] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(selected))
	for _, node := range graph.Nodes {
		if _, exists := selected[node]; exists {
			result = append(result, node)
		}
	}
	return result
}

func completeRollbackContext(value *model.RemediationJournal, targets []string) []string {
	selected := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		selected[target] = struct{}{}
	}
	changed := true
	for changed {
		changed = false
		for _, edge := range value.ConflictGraph.Edges {
			if _, included := selected[edge.From]; !included {
				continue
			}
			if _, included := selected[edge.To]; included {
				continue
			}
			changeSet, _, err := findChangeSet(value, edge.To)
			if err != nil || !hasRollbackContext(*changeSet) {
				continue
			}
			selected[edge.To] = struct{}{}
			changed = true
		}
	}
	result := make([]string, 0, len(selected))
	for _, node := range value.ConflictGraph.Nodes {
		if _, included := selected[node]; included {
			result = append(result, node)
		}
	}
	return result
}

func hasRollbackContext(changeSet model.ChangeSet) bool {
	for _, operation := range changeSet.Operations {
		if operation.State == model.OperationRolledBack && operation.ObservedRollback != nil {
			return true
		}
	}
	return false
}

func hasRollbackWork(value *model.RemediationJournal, changeSetID string) bool {
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return false
	}
	for _, operation := range changeSet.Operations {
		if operation.ProvesNoEffect() {
			continue
		}
		switch operation.State {
		case model.OperationApplyIntentDurable,
			model.OperationApplied,
			model.OperationVerified,
			model.OperationFailed,
			model.OperationRollbackIntentDurable,
			model.OperationAmbiguous:
			return true
		}
	}
	return false
}

func automaticRollbackTriggerErrors(
	value *model.RemediationJournal,
	trigger model.RollbackTrigger,
	requested, expanded []string,
) []model.JournalError {
	if value == nil {
		return nil
	}
	result := make([]model.JournalError, 0, len(requested)+1)
	appendInScope := func(candidate model.JournalError) {
		if candidate.ChangeSetID != "" && !slices.Contains(expanded, candidate.ChangeSetID) {
			return
		}
		for index := range result {
			if journalErrorMatches(&result[index], candidate) {
				return
			}
		}
		result = append(result, candidate)
	}
	if trigger == model.RollbackApplyFailure || trigger == model.RollbackVerifyFailure {
		for _, changeSetID := range requested {
			changeSet, _, err := findChangeSet(value, changeSetID)
			if err == nil && changeSet.Error != nil {
				appendInScope(*changeSet.Error)
			}
		}
		if len(result) == 0 && value.Error != nil {
			appendInScope(*value.Error)
		}
	}
	if applyFailure := firstApplyFailureError(value); applyFailure != nil {
		appendInScope(*applyFailure)
	}
	return result
}

func rollbackAttemptExecutor(
	value *model.RemediationJournal,
	trigger model.RollbackTrigger,
	executorBuild model.RemediationBuildIdentity,
) (*model.RemediationBuildIdentity, error) {
	if value == nil {
		return nil, fmt.Errorf("journal is required")
	}
	switch trigger {
	case model.RollbackUserRequest:
		if err := executorBuild.ValidateRollbackExecutor(); err != nil {
			return nil, fmt.Errorf("invalid user rollback executor build: %w", err)
		}
	case model.RollbackApplyFailure, model.RollbackVerifyFailure:
		if executorBuild != value.RemediationBuild {
			return nil, fmt.Errorf("automatic rollback executor differs from the remediation build")
		}
	default:
		return nil, fmt.Errorf("rollback trigger %s cannot execute live rollback effects", trigger)
	}
	if value.SchemaVersion == 2 {
		return nil, nil
	}
	if value.SchemaVersion != model.RemediationSchemaVersion {
		return nil, fmt.Errorf("unsupported remediation schema version %d", value.SchemaVersion)
	}
	copy := executorBuild
	return &copy, nil
}

func cloneBuildIdentity(value *model.RemediationBuildIdentity) *model.RemediationBuildIdentity {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func buildIdentityPointerEqual(left, right *model.RemediationBuildIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (m *Manager) executeRollback(
	ctx context.Context,
	value *model.RemediationJournal,
	scope model.RollbackScope,
	trigger model.RollbackTrigger,
	requested, targets []string,
	cascadeApproved bool,
	executorBuild model.RemediationBuildIdentity,
) (model.RollbackAttempt, error) {
	if value == nil {
		return model.RollbackAttempt{}, &Error{Code: CodeInvalidInput, Operation: "rollback", Err: fmt.Errorf("journal is required")}
	}
	executorIdentity, err := rollbackAttemptExecutor(value, trigger, executorBuild)
	if err != nil {
		return model.RollbackAttempt{}, &Error{Code: CodeInvalidInput, Operation: "rollback", RunID: value.RunID, Err: err}
	}
	runID := value.RunID
	for {
		previousLength := len(targets)
		targets = completeRollbackGroups(value.ConflictGraph, targets)
		targets = completeRollbackContext(value, targets)
		if len(targets) == previousLength {
			break
		}
	}
	if len(targets) == 0 {
		return model.RollbackAttempt{}, &Error{Code: CodeInvalidState, Operation: "rollback", RunID: runID, Err: fmt.Errorf("rollback scope has no change set")}
	}
	if scope == model.RollbackItem && requiresRecoveredRunRollback(value) && !containsAllIDs(targets, value.UnresolvedChangeSets) {
		return model.RollbackAttempt{}, &Error{Code: CodeRecoveryRequired, Operation: "rollback", RunID: runID, Err: fmt.Errorf("the run failure policy requires rollback of the full unresolved scope")}
	}
	order, err := conflict.ReverseRollbackOrder(value.ConflictGraph, targets, sequenceMap(value))
	if err != nil {
		attempt, recordErr := m.recordBlockedAttempt(ctx, value, scope, trigger, requested, targets, cascadeApproved, executorIdentity, err)
		if recordErr != nil {
			return model.RollbackAttempt{}, recordErr
		}
		if trigger == model.RollbackApplyFailure || trigger == model.RollbackVerifyFailure || rollbackPreflightRequiresRecovery(err) {
			latest, loadErr := m.loadAndVerifyReadOnly(ctx, value.RunID)
			if loadErr != nil {
				return attempt, wrapDependency("reload blocked rollback order", value.RunID, "", "", loadErr)
			}
			if _, recoveryErr := m.markAutomaticRollbackBlocked(ctx, latest, targets, err); recoveryErr != nil {
				return attempt, recoveryErr
			}
			return attempt, &Error{Code: CodeRecoveryRequired, Operation: "rollback order", RunID: value.RunID, Err: err}
		}
		return attempt, wrapDependency("order rollback", value.RunID, "", "", err)
	}
	handler, err := m.fileHandler(value.RunID)
	if err != nil {
		return model.RollbackAttempt{}, err
	}
	if err := m.preflightRollback(ctx, value, handler, order); err != nil {
		attempt, recordErr := m.recordBlockedAttempt(ctx, value, scope, trigger, requested, order, cascadeApproved, executorIdentity, err)
		if recordErr != nil {
			return model.RollbackAttempt{}, recordErr
		}
		if trigger == model.RollbackApplyFailure || trigger == model.RollbackVerifyFailure || rollbackPreflightRequiresRecovery(err) {
			latest, loadErr := m.loadAndVerifyReadOnly(ctx, value.RunID)
			if loadErr != nil {
				return attempt, wrapDependency("reload blocked automatic rollback", value.RunID, "", "", loadErr)
			}
			if _, recoveryErr := m.markAutomaticRollbackBlocked(ctx, latest, order, err); recoveryErr != nil {
				return attempt, recoveryErr
			}
			return attempt, &Error{Code: CodeRecoveryRequired, Operation: "rollback preflight", RunID: value.RunID, Err: err}
		}
		return attempt, err
	}
	attemptID, err := m.nextID("rollback-")
	if err != nil {
		return model.RollbackAttempt{}, &Error{Code: CodePersistFailed, Operation: "generate rollback attempt ID", RunID: value.RunID, Err: err}
	}
	startedAt := m.nextEventTime(value)
	triggerErrors := automaticRollbackTriggerErrors(value, trigger, requested, order)
	value, err = m.update(ctx, value, "persist rollback attempt", func(journal *model.RemediationJournal) error {
		journal.State = model.RunRollingBack
		journal.RollbackAttempts = append(journal.RollbackAttempts, model.RollbackAttempt{
			ID:                  attemptID,
			Scope:               scope,
			Trigger:             trigger,
			ExecutorBuild:       cloneBuildIdentity(executorIdentity),
			RequestedChangeSets: append([]string(nil), requested...),
			ExpandedChangeSets:  append([]string(nil), order...),
			CascadeApproved:     cascadeApproved,
			StartedAt:           startedAt,
			Errors:              append([]model.JournalError(nil), triggerErrors...),
		})
		return nil
	})
	if err != nil {
		return model.RollbackAttempt{}, err
	}
	rollbackContext, cancelRollback := newApplyCleanupContext(ctx)
	defer cancelRollback()
	pending := make(map[string]bool, len(order))
	for _, id := range order {
		pending[id] = true
	}
	blocked := make(map[string]bool)
	resourceExpected := make(map[string]model.ResourceSnapshot)
	succeeded := 0
	failed := 0
	ambiguous := false
	rollbackEffects := 0
	for _, changeSetID := range order {
		if blocked[changeSetID] {
			pending[changeSetID] = false
			continue
		}
		changeSet, _, findErr := findChangeSet(value, changeSetID)
		if findErr != nil {
			stageErr := &Error{Code: CodeInvalidState, Operation: "rollback change set", RunID: value.RunID, ChangeSetID: changeSetID, Err: findErr}
			return model.RollbackAttempt{}, rollbackPostEffectError(runID, changeSetID, "", rollbackEffects, stageErr)
		}
		if !hasRollbackWork(value, changeSetID) {
			for _, operation := range changeSet.Operations {
				if operation.State == model.OperationRolledBack && operation.ObservedRollback != nil {
					resourceExpected[operation.Resource.Key] = *operation.ObservedRollback
				}
			}
			pending[changeSetID] = false
			continue
		}
		if changeSet.State != model.ChangeRollingBack {
			value, err = m.update(rollbackContext, value, "persist change set rollback state", func(journal *model.RemediationJournal) error {
				target, _, lookupErr := findChangeSet(journal, changeSetID)
				if lookupErr != nil {
					return lookupErr
				}
				target.State = model.ChangeRollingBack
				return nil
			})
			if err != nil {
				return model.RollbackAttempt{}, rollbackPostEffectError(runID, changeSetID, "", rollbackEffects, err)
			}
		}
		operationIDs := orderedOperationIDs(value, changeSetID, true)
		changeSucceeded := 0
		var changeFailure *rollbackFailure
		for _, operationID := range operationIDs {
			operation, _, _, _ := findOperation(value, changeSetID, operationID)
			if operation.State == model.OperationRolledBack {
				if operation.ObservedRollback == nil {
					changeFailure = &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("rolled back operation has no observed rollback state")}, ambiguous: true}
					break
				}
				resourceExpected[operation.Resource.Key] = *operation.ObservedRollback
				changeSucceeded++
				continue
			}
			if operation.State == model.OperationPlanned {
				continue
			}
			if operation.ProvesNoEffect() {
				continue
			}
			var expectedCurrent *model.ResourceSnapshot
			if snapshot, exists := resourceExpected[operation.Resource.Key]; exists {
				copy := snapshot
				expectedCurrent = &copy
			}
			var observedRollback *model.ResourceSnapshot
			value, observedRollback, changeFailure = m.rollbackOperation(rollbackContext, value, handler, changeSetID, operationID, expectedCurrent)
			if changeFailure != nil {
				var orchestrationError *Error
				if errors.As(changeFailure.err, &orchestrationError) && orchestrationError.Committed {
					rollbackEffects++
				}
				break
			}
			if observedRollback == nil {
				changeFailure = &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback change set", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("rollback completed without an observed state")}, ambiguous: true}
				break
			}
			resourceExpected[operation.Resource.Key] = *observedRollback
			changeSucceeded++
			rollbackEffects++
		}
		if value == nil {
			if changeFailure != nil {
				return model.RollbackAttempt{}, rollbackPostEffectError(runID, changeSetID, "", rollbackEffects, changeFailure.err)
			}
			stageErr := &Error{Code: CodePersistFailed, Operation: "rollback change set", RunID: runID}
			return model.RollbackAttempt{}, rollbackPostEffectError(runID, changeSetID, "", rollbackEffects, stageErr)
		}
		pending[changeSetID] = false
		if changeFailure == nil {
			currentChangeSet, _, _ := findChangeSet(value, changeSetID)
			for _, before := range currentChangeSet.Before {
				current, captureErr := handler.Capture(rollbackContext, before.Reference)
				if captureErr != nil {
					changeFailure = &rollbackFailure{err: wrapDependency("verify change set rollback", value.RunID, changeSetID, "", captureErr), ambiguous: true}
					break
				}
				if !exactEqual(before, current) {
					changeFailure = &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "verify change set rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("resource no longer matches the change-set before state")}, ambiguous: true}
					break
				}
			}
		}
		if changeFailure == nil {
			rolledBackAt := m.nextEventTime(value)
			value, err = m.update(rollbackContext, value, "persist rolled back change set", func(journal *model.RemediationJournal) error {
				target, _, lookupErr := findChangeSet(journal, changeSetID)
				if lookupErr != nil {
					return lookupErr
				}
				target.State = model.ChangeRolledBack
				target.RolledBackAt = &rolledBackAt
				target.Error = nil
				return nil
			})
			if err != nil {
				return model.RollbackAttempt{}, rollbackPostEffectError(runID, changeSetID, "", rollbackEffects, err)
			}
			succeeded++
			continue
		}
		failed++
		ambiguous = ambiguous || changeFailure.ambiguous
		failureState := model.ChangeRollbackFailed
		if changeFailure.ambiguous {
			failureState = model.ChangeRecoveryRequired
		} else if changeSucceeded > 0 {
			failureState = model.ChangePartiallyRolledBack
		}
		journalError := m.makeJournalError(value, "rollback", changeSetID, "", nil, changeFailure.err)
		value, err = m.update(rollbackContext, value, "persist rollback failure", func(journal *model.RemediationJournal) error {
			target, _, lookupErr := findChangeSet(journal, changeSetID)
			if lookupErr != nil {
				return lookupErr
			}
			target.State = failureState
			target.Error = &journalError
			attempt := &journal.RollbackAttempts[len(journal.RollbackAttempts)-1]
			attempt.Errors = append(attempt.Errors, journalError)
			return nil
		})
		if err != nil {
			return model.RollbackAttempt{}, rollbackPostEffectError(runID, changeSetID, "", rollbackEffects, err)
		}
		for _, predecessor := range conflict.BlockedPredecessors(value.ConflictGraph, changeSetID, pending) {
			if !pending[predecessor] || blocked[predecessor] {
				continue
			}
			blocked[predecessor] = true
			blockedError := m.makeJournalError(value, "rollback", predecessor, "", nil, &Error{Code: CodeCascadeRequired, Err: fmt.Errorf("rollback is blocked by failed dependent change set %s", changeSetID)})
			value, err = m.persistBlockedPredecessor(rollbackContext, value, predecessor, blockedError)
			if err != nil {
				return model.RollbackAttempt{}, rollbackPostEffectError(runID, predecessor, "", rollbackEffects, err)
			}
		}
	}
	outcome := model.RollbackSucceeded
	if ambiguous {
		outcome = model.RollbackFailed
	} else if failed > 0 || len(blocked) > 0 {
		if hasRolledBackInTargets(value, order) {
			outcome = model.RollbackPartial
		} else {
			outcome = model.RollbackFailed
		}
	}
	targetUnresolved := rollbackTargetUnresolved(value, order)
	if len(targetUnresolved) > 0 && outcome == model.RollbackSucceeded {
		outcome = model.RollbackFailed
		if hasRolledBackInTargets(value, order) {
			outcome = model.RollbackPartial
		}
	}
	unresolved := appendUnique(unresolvedRollbackChangeSets(value), targetUnresolved...)
	unresolved = appendUnique(unresolved, rollbackOutsideUnresolved(value, order, scope)...)
	finalState := classifyRollbackRunState(value, order, scope)
	stateError := m.rollbackRunStateError(value, "rollback_run_state", finalState)
	applyFailureError := firstApplyFailureError(value)
	if len(value.RollbackAttempts) == 0 {
		return model.RollbackAttempt{}, rollbackPostEffectError(
			runID,
			"",
			"",
			rollbackEffects,
			&Error{Code: CodeInvalidState, Operation: "complete rollback attempt", RunID: runID, Err: fmt.Errorf("rollback attempt is missing")},
		)
	}
	incompleteAttempt := value.RollbackAttempts[len(value.RollbackAttempts)-1]
	expectedAttempt := incompleteAttempt
	expectedAttempt.Outcome = outcome
	expectedAttempt.Errors = append([]model.JournalError(nil), incompleteAttempt.Errors...)
	var expectedJournalError *model.JournalError
	if stateError != nil {
		expectedAttempt.Errors = append(expectedAttempt.Errors, *stateError)
		errorCopy := *stateError
		expectedJournalError = &errorCopy
	} else if finalState == model.RunFailed && applyFailureError != nil {
		errorCopy := *applyFailureError
		expectedJournalError = &errorCopy
	}
	completedAt := m.rollbackAttemptCompletionTime(value, incompleteAttempt.StartedAt, expectedAttempt.Errors)
	expectedAttempt.CompletedAt = &completedAt
	completeAttempt := func(journal *model.RemediationJournal) error {
		if journal.State != model.RunRollingBack ||
			len(journal.RollbackAttempts) != len(value.RollbackAttempts) {
			return fmt.Errorf("rollback attempt completion precondition changed")
		}
		attempt := &journal.RollbackAttempts[len(journal.RollbackAttempts)-1]
		if !rollbackAttemptEqual(*attempt, incompleteAttempt) {
			return fmt.Errorf("rollback attempt changed before completion")
		}
		attempt.Outcome = expectedAttempt.Outcome
		attempt.CompletedAt = expectedAttempt.CompletedAt
		attempt.Errors = append([]model.JournalError(nil), expectedAttempt.Errors...)
		journal.State = finalState
		journal.UnresolvedChangeSets = append([]string(nil), unresolved...)
		if expectedJournalError == nil {
			journal.Error = nil
		} else {
			errorCopy := *expectedJournalError
			journal.Error = &errorCopy
		}
		return nil
	}
	completionPersisted := func(journal *model.RemediationJournal) bool {
		if journal == nil ||
			journal.State != finalState ||
			len(journal.RollbackAttempts) != len(value.RollbackAttempts) ||
			!slices.Equal(journal.UnresolvedChangeSets, unresolved) ||
			!journalErrorPointerEqual(journal.Error, expectedJournalError) {
			return false
		}
		return rollbackAttemptEqual(journal.RollbackAttempts[len(journal.RollbackAttempts)-1], expectedAttempt)
	}
	if outcome == model.RollbackSucceeded {
		frontierContext, cancelFrontier := newApplyCleanupContext(ctx)
		frontierErr := m.verifyRollbackLiveFrontier(frontierContext, value, handler)
		cancelFrontier()
		if frontierErr != nil {
			return model.RollbackAttempt{}, &Error{
				Code:      CodeRecoveryRequired,
				Operation: "verify rollback live frontier before completion",
				RunID:     runID,
				Committed: rollbackEffects > 0 || succeeded > 0,
				Err:       frontierErr,
			}
		}
	}
	completionContext, cancelCompletion := newApplyCleanupContext(ctx)
	defer cancelCompletion()
	value, err = m.updateAfterRollbackEffect(
		completionContext,
		value,
		"complete rollback attempt",
		"",
		"",
		completeAttempt,
		completionPersisted,
		func(ctx context.Context, latest *model.RemediationJournal) error {
			if outcome != model.RollbackSucceeded {
				return nil
			}
			return m.verifyRollbackLiveFrontier(ctx, latest, handler)
		},
	)
	if err != nil {
		return model.RollbackAttempt{}, err
	}
	attempt := value.RollbackAttempts[len(value.RollbackAttempts)-1]
	if outcome != model.RollbackSucceeded {
		code := CodeRollbackFailed
		if finalState == model.RunRecoveryRequired {
			code = CodeRecoveryRequired
		}
		return attempt, &Error{Code: code, Operation: "rollback", RunID: value.RunID, Committed: rollbackEffects > 0 || succeeded > 0, Err: fmt.Errorf("rollback outcome is %s", outcome)}
	}
	if finalState.NeedsOperatorAction() {
		code := CodeRollbackFailed
		if finalState == model.RunRecoveryRequired {
			code = CodeRecoveryRequired
		}
		return attempt, &Error{Code: code, Operation: "rollback", RunID: value.RunID, Committed: true, Err: fmt.Errorf("rollback attempt succeeded but run remains %s", finalState)}
	}
	return attempt, nil
}

func rollbackAttemptEqual(actual, expected model.RollbackAttempt) bool {
	if actual.ID != expected.ID ||
		actual.Scope != expected.Scope ||
		actual.Trigger != expected.Trigger ||
		!buildIdentityPointerEqual(actual.ExecutorBuild, expected.ExecutorBuild) ||
		!buildIdentityPointerEqual(actual.ObservedByBuild, expected.ObservedByBuild) ||
		actual.CascadeApproved != expected.CascadeApproved ||
		actual.Outcome != expected.Outcome ||
		!actual.StartedAt.Equal(expected.StartedAt) ||
		!slices.Equal(actual.RequestedChangeSets, expected.RequestedChangeSets) ||
		!slices.Equal(actual.ExpandedChangeSets, expected.ExpandedChangeSets) ||
		(actual.CompletedAt == nil) != (expected.CompletedAt == nil) ||
		len(actual.Errors) != len(expected.Errors) {
		return false
	}
	if actual.CompletedAt != nil && !actual.CompletedAt.Equal(*expected.CompletedAt) {
		return false
	}
	for index := range actual.Errors {
		if !journalErrorMatches(&actual.Errors[index], expected.Errors[index]) {
			return false
		}
	}
	return true
}

func journalErrorPointerEqual(actual, expected *model.JournalError) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	return journalErrorMatches(actual, *expected)
}

func rollbackPostEffectError(runID, changeSetID, operationID string, rollbackEffects int, err error) error {
	if err == nil || rollbackEffects == 0 {
		return err
	}
	return &Error{
		Code:        CodeRecoveryRequired,
		Operation:   "rollback after a persisted target result",
		RunID:       runID,
		ChangeSetID: changeSetID,
		OperationID: operationID,
		Committed:   true,
		Err:         err,
	}
}

func rollbackPreflightRequiresRecovery(err error) bool {
	switch CodeOf(err) {
	case CodeRecoveryRequired, CodeBackupFailed, CodePreconditionFailed, CodeInvalidState, CodeUnsupportedOperation, CodeHostMismatch, CodeBootChanged:
		return true
	default:
		return false
	}
}

func rollbackRecoveryEligibleChangeSets(value *model.RemediationJournal, targets []string) ([]string, error) {
	eligible := make([]string, 0, len(targets))
	for _, changeSetID := range targets {
		changeSet, _, err := findChangeSet(value, changeSetID)
		if err != nil {
			return nil, err
		}
		if hasRollbackWork(value, changeSetID) || changeSet.State == model.ChangeRolledBack || hasRollbackContext(*changeSet) || !terminalRollbackSafeChangeSet(*changeSet) {
			eligible = append(eligible, changeSetID)
		}
	}
	return appendUnique(nil, eligible...), nil
}

func enterBlockedRollbackRecovery(journal *model.RemediationJournal, eligible []string, journalError model.JournalError) error {
	if journal == nil {
		return fmt.Errorf("journal is required")
	}
	if journal.State != model.RunRecoveryRequired {
		if !journal.State.CanTransitionTo(model.RunRollingBack) {
			return fmt.Errorf("run %s cannot enter rollback recovery", journal.State)
		}
		journal.State = model.RunRollingBack
	}
	for _, changeSetID := range eligible {
		target, _, err := findChangeSet(journal, changeSetID)
		if err != nil {
			return err
		}
		if target.State != model.ChangeRecoveryRequired {
			noEffectFailure := *target
			noEffectFailure.State = model.ChangeApplyFailed
			if !hasRollbackWork(journal, changeSetID) && target.State.CanTransitionTo(model.ChangeApplyFailed) && terminalRollbackSafeChangeSet(noEffectFailure) {
				// Keep the in-flight state until Recover reconciles the no-effect
				// operation. The run-level recovery marker and unresolved scope are
				// written atomically below.
			} else if target.State.CanTransitionTo(model.ChangeRecoveryRequired) {
				target.State = model.ChangeRecoveryRequired
			} else if target.State.CanTransitionTo(model.ChangeRollingBack) {
				target.State = model.ChangeRollingBack
			}
		}
		errorCopy := journalError
		errorCopy.ChangeSetID = changeSetID
		target.Error = &errorCopy
		journal.UnresolvedChangeSets = appendUnique(journal.UnresolvedChangeSets, changeSetID)
	}
	journal.Error = &journalError
	return nil
}

func (m *Manager) markAutomaticRollbackBlocked(ctx context.Context, value *model.RemediationJournal, targets []string, cause error) (*model.RemediationJournal, error) {
	journalError := m.makeJournalError(value, "rollback_preflight", "", "", nil, &Error{Code: CodeRecoveryRequired, Err: cause})
	eligible, err := rollbackRecoveryEligibleChangeSets(value, targets)
	if err != nil {
		return nil, err
	}

	next, err := m.update(ctx, value, "enter blocked rollback recovery", func(journal *model.RemediationJournal) error {
		return enterBlockedRollbackRecovery(journal, eligible, journalError)
	})
	if err != nil {
		return nil, err
	}
	value = next

	for _, changeSetID := range eligible {
		changeSet, _, _ := findChangeSet(value, changeSetID)
		if changeSet.State != model.ChangeRollingBack {
			continue
		}
		value, err = m.update(ctx, value, "persist blocked change-set recovery", func(journal *model.RemediationJournal) error {
			target, _, lookupErr := findChangeSet(journal, changeSetID)
			if lookupErr != nil {
				return lookupErr
			}
			target.State = model.ChangeRecoveryRequired
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if value.State != model.RunRecoveryRequired {
		value, err = m.update(ctx, value, "persist blocked run recovery", func(journal *model.RemediationJournal) error {
			journal.State = model.RunRecoveryRequired
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return value, nil
}

func (m *Manager) persistBlockedPredecessor(ctx context.Context, value *model.RemediationJournal, changeSetID string, journalError model.JournalError) (*model.RemediationJournal, error) {
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return nil, err
	}
	if changeSet.State == model.ChangeRollbackBlocked {
		return value, nil
	}
	if !changeSet.State.CanTransitionTo(model.ChangeRollbackBlocked) {
		if !changeSet.State.CanTransitionTo(model.ChangeRollingBack) {
			return nil, &Error{Code: CodeInvalidState, Operation: "block rollback predecessor", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set %s cannot be blocked", changeSet.State)}
		}
		value, err = m.update(ctx, value, "enter blocked predecessor transition", func(journal *model.RemediationJournal) error {
			target, _, lookupErr := findChangeSet(journal, changeSetID)
			if lookupErr != nil {
				return lookupErr
			}
			target.State = model.ChangeRollingBack
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return m.update(ctx, value, "persist blocked predecessor", func(journal *model.RemediationJournal) error {
		target, _, lookupErr := findChangeSet(journal, changeSetID)
		if lookupErr != nil {
			return lookupErr
		}
		target.State = model.ChangeRollbackBlocked
		target.Error = &journalError
		attempt := &journal.RollbackAttempts[len(journal.RollbackAttempts)-1]
		attempt.Errors = append(attempt.Errors, journalError)
		return nil
	})
}

func advanceRolledBackWriterChain(expected map[string]model.ResourceSnapshot, operation model.OperationRecord) error {
	if operation.ObservedRollback == nil || !exactEqual(operation.Before, *operation.ObservedRollback) {
		return fmt.Errorf("rolled-back operation %s has no trustworthy before-state observation", operation.ID)
	}
	if later, exists := expected[operation.Resource.Key]; exists {
		after := operation.Before
		if operation.ObservedAfter != nil {
			after = *operation.ObservedAfter
		}
		if !exactEqual(later, after) {
			return fmt.Errorf("rolled-back operation %s breaks the durable writer chain", operation.ID)
		}
	}
	expected[operation.Resource.Key] = *operation.ObservedRollback
	return nil
}

func rollbackFrontierMatchesSuffix(operation model.OperationRecord, suffixAnchor, live model.ResourceSnapshot) bool {
	if exactEqual(suffixAnchor, live) {
		return true
	}
	if operation.RollbackIntentAt == nil || operation.ObservedAfter == nil || !exactEqual(suffixAnchor, *operation.ObservedAfter) {
		return false
	}
	return exactEqual(operation.Before, live) || regularfile.MetadataTransitionCandidate(operation.Before, operation.Desired, live)
}

func (m *Manager) preflightRollback(ctx context.Context, value *model.RemediationJournal, handler fileRuntime, order []string) error {
	simulated := make(map[string]model.ResourceSnapshot)
	rolledExpected := make(map[string]model.ResourceSnapshot)
	for _, changeSetID := range order {
		changeSet, _, err := findChangeSet(value, changeSetID)
		if err != nil {
			return &Error{Code: CodeInvalidState, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: err}
		}
		if !hasRollbackWork(value, changeSetID) && changeSet.State != model.ChangeRolledBack && changeSet.State != model.ChangePlanned && changeSet.State != model.ChangePrepared && changeSet.State != model.ChangeApplyFailed {
			return &Error{Code: CodeInvalidState, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set has no rollback-eligible operation")}
		}
		if !hasRollbackWork(value, changeSetID) && changeSet.State != model.ChangeRolledBack {
			continue
		}
		for _, operationID := range orderedOperationIDs(value, changeSetID, true) {
			operation, _, _, _ := findOperation(value, changeSetID, operationID)
			if operation.State == model.OperationPlanned {
				continue
			}
			if operation.ProvesNoEffect() {
				continue
			}
			if operation.State == model.OperationRolledBack {
				if chainErr := advanceRolledBackWriterChain(rolledExpected, *operation); chainErr != nil {
					return &Error{Code: CodeRecoveryRequired, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: chainErr}
				}
				simulated[operation.Resource.Key] = operation.Before
				continue
			}
			if operation.Kind != model.OperationFileMetadata {
				return &Error{Code: CodeUnsupportedOperation, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("only regular-file metadata rollback is supported")}
			}
			if operation.State == model.OperationAmbiguous {
				return &Error{Code: CodeRecoveryRequired, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("ambiguous operation must be recovered before rollback")}
			}
			if operation.State == model.OperationApplyIntentDurable || (operation.State == model.OperationFailed && operation.RollbackIntentAt == nil) {
				return &Error{Code: CodeRecoveryRequired, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("in-flight apply result must be recovered before rollback")}
			}
			if operation.Backup == nil {
				return &Error{Code: CodeBackupFailed, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("operation has no backup")}
			}
			if err := handler.VerifyBackup(ctx, *operation.Backup); err != nil {
				return wrapDependency("preflight backup verification", value.RunID, changeSetID, operationID, err)
			}
			current, exists := simulated[operation.Resource.Key]
			if expected, pending := rolledExpected[operation.Resource.Key]; pending {
				observed, captureErr := handler.Capture(ctx, operation.Resource)
				if captureErr != nil {
					return wrapDependency("preflight rolled back state", value.RunID, changeSetID, operationID, captureErr)
				}
				if !rollbackFrontierMatchesSuffix(*operation, expected, observed) {
					return &Error{Code: CodeRecoveryRequired, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("recorded rollback chain no longer matches its last observed state")}
				}
				delete(rolledExpected, operation.Resource.Key)
			}
			if !exists {
				current, err = handler.Capture(ctx, operation.Resource)
				if err != nil {
					return wrapDependency("preflight current state", value.RunID, changeSetID, operationID, err)
				}
			}
			if exactEqual(operation.Before, current) {
				simulated[operation.Resource.Key] = operation.Before
				continue
			}
			afterMatches := operation.ObservedAfter != nil && exactEqual(*operation.ObservedAfter, current)
			partialMetadata := operation.RollbackIntentAt != nil && regularfile.MetadataTransitionCandidate(operation.Before, operation.Desired, current)
			if !afterMatches && !partialMetadata {
				return &Error{Code: CodePreconditionFailed, Operation: "preflight rollback", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("rollback chain does not match the original inode's durable after or partial metadata state")}
			}
			simulated[operation.Resource.Key] = operation.Before
		}
	}
	rolledKeys := make([]string, 0, len(rolledExpected))
	for key := range rolledExpected {
		rolledKeys = append(rolledKeys, key)
	}
	sort.Strings(rolledKeys)
	for _, key := range rolledKeys {
		expected := rolledExpected[key]
		current, err := handler.Capture(ctx, expected.Reference)
		if err != nil {
			return wrapDependency("preflight final rolled back state", value.RunID, "", "", err)
		}
		if !exactEqual(expected, current) {
			return &Error{Code: CodeRecoveryRequired, Operation: "preflight rollback", RunID: value.RunID, Err: fmt.Errorf("rolled back resource %s no longer matches its last observed state", key)}
		}
	}
	return nil
}

func (m *Manager) rollbackOperation(
	ctx context.Context,
	value *model.RemediationJournal,
	handler fileRuntime,
	changeSetID, operationID string,
	expectedCurrent *model.ResourceSnapshot,
) (*model.RemediationJournal, *model.ResourceSnapshot, *rollbackFailure) {
	operation, _, _, err := findOperation(value, changeSetID, operationID)
	if err != nil {
		return value, nil, &rollbackFailure{err: err, ambiguous: true}
	}
	if operation.Backup == nil {
		return value, nil, &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("backup is missing")}, ambiguous: true}
	}
	if operation.ProvesNoEffect() {
		return value, nil, &rollbackFailure{err: &Error{Code: CodeInvalidState, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("operation has durable no-effect evidence and no rollback work")}}
	}
	if operation.State == model.OperationApplyIntentDurable || operation.State == model.OperationAmbiguous ||
		(operation.State == model.OperationFailed && operation.RollbackIntentAt == nil) {
		return value, nil, &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("in-flight apply result must be recovered before rollback")}, ambiguous: true}
	}
	if err := handler.VerifyBackup(ctx, *operation.Backup); err != nil {
		return value, nil, &rollbackFailure{err: wrapDependency("verify rollback backup", value.RunID, changeSetID, operationID, err), ambiguous: true}
	}
	current, err := handler.Capture(ctx, operation.Resource)
	if err != nil {
		return value, nil, &rollbackFailure{err: wrapDependency("capture rollback precondition", value.RunID, changeSetID, operationID, err), ambiguous: true}
	}
	if expectedCurrent != nil && !rollbackFrontierMatchesSuffix(*operation, *expectedCurrent, current) {
		return value, nil, &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("resource state changed after the preceding rollback step")}, ambiguous: true}
	}
	beforeMatches := exactEqual(operation.Before, current)
	afterMatches := operation.ObservedAfter != nil && exactEqual(*operation.ObservedAfter, current)
	partialMetadata := operation.RollbackIntentAt != nil && regularfile.MetadataTransitionCandidate(operation.Before, operation.Desired, current)
	if !beforeMatches && !afterMatches && !partialMetadata {
		return value, nil, &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("current state matches neither before nor a safe metadata transition on the original inode")}, ambiguous: true}
	}
	if operation.State == model.OperationAmbiguous {
		return value, nil, &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: fmt.Errorf("ambiguous operation must be assessed before rollback")}, ambiguous: true}
	}
	if operation.State != model.OperationRollbackIntentDurable {
		intentAt := m.nextEventTime(value)
		value, err = m.update(ctx, value, "persist rollback intent", func(journal *model.RemediationJournal) error {
			target, _, _, findErr := findOperation(journal, changeSetID, operationID)
			if findErr != nil {
				return findErr
			}
			target.State = model.OperationRollbackIntentDurable
			target.RollbackIntentAt = &intentAt
			return nil
		})
		if err != nil {
			return nil, nil, &rollbackFailure{err: err}
		}
		operation, _, _, _ = findOperation(value, changeSetID, operationID)
	}
	persistContext, cancelPersist := newApplyCleanupContext(ctx)
	defer cancelPersist()
	if beforeMatches {
		verified, verifyErr := handler.Capture(persistContext, operation.Resource)
		if verifyErr != nil || !exactEqual(current, verified) {
			if verifyErr == nil {
				verifyErr = fmt.Errorf("file changed after rollback intent")
			}
			next, failure := m.markRollbackAmbiguous(persistContext, value, changeSetID, operationID, verifyErr)
			return next, nil, failure
		}
		next, failure := m.markOperationRolledBack(persistContext, value, handler, changeSetID, operationID, verified, nil)
		return next, &verified, failure
	}
	operationCopy := *operation
	restoreObserved, restoreErr := handler.Restore(ctx, operationCopy, *operation.Backup)
	restored, captureErr := handler.Capture(persistContext, operation.Resource)
	if captureErr != nil {
		next, failure := m.markRollbackAmbiguous(persistContext, value, changeSetID, operationID, captureErr)
		return next, nil, failure
	}
	if !restoreObserved.IsZero() && !exactEqual(restoreObserved, restored) {
		next, failure := m.markRollbackAmbiguous(persistContext, value, changeSetID, operationID, fmt.Errorf("file identity changed after metadata restore"))
		return next, nil, failure
	}
	if exactEqual(operation.Before, restored) {
		next, failure := m.markOperationRolledBack(persistContext, value, handler, changeSetID, operationID, restored, restoreErr)
		return next, &restored, failure
	}
	if exactEqual(current, restored) {
		if restoreErr == nil {
			restoreErr = fmt.Errorf("restore returned success but the file remained in the after state")
		}
		next, failure := m.markRollbackFailed(persistContext, value, changeSetID, operationID, restoreErr)
		return next, nil, failure
	}
	if restoreErr == nil {
		restoreErr = fmt.Errorf("restore result matches neither before nor after state")
	}
	next, failure := m.markRollbackAmbiguous(persistContext, value, changeSetID, operationID, restoreErr)
	return next, nil, failure
}

func (m *Manager) markOperationRolledBack(ctx context.Context, value *model.RemediationJournal, handler fileRuntime, changeSetID, operationID string, observed model.ResourceSnapshot, diagnostic error) (*model.RemediationJournal, *rollbackFailure) {
	rolledBackAt := m.nextEventTime(value)
	operation, _, _, findErr := findOperation(value, changeSetID, operationID)
	if findErr != nil {
		return value, &rollbackFailure{err: findErr, ambiguous: true}
	}
	var expectedError *model.JournalError
	if diagnostic != nil && operation.Error == nil {
		journalError := m.makeJournalError(value, "rollback", changeSetID, operationID, operation, diagnostic)
		expectedError = &journalError
	}
	mutate := func(journal *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		target.State = model.OperationRolledBack
		observedCopy := observed
		target.ObservedRollback = &observedCopy
		target.RolledBackAt = &rolledBackAt
		if expectedError != nil && target.Error == nil {
			errorCopy := *expectedError
			target.Error = &errorCopy
		}
		return nil
	}
	persisted := func(journal *model.RemediationJournal) bool {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil || target.State != model.OperationRolledBack ||
			target.ObservedRollback == nil || target.RolledBackAt == nil ||
			!exactEqual(observed, *target.ObservedRollback) ||
			!target.RolledBackAt.Equal(rolledBackAt) {
			return false
		}
		return expectedError == nil || journalErrorMatches(target.Error, *expectedError)
	}
	revalidate := func(ctx context.Context, latest *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(latest, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		if target.State != model.OperationRollbackIntentDurable ||
			target.RollbackIntentAt == nil ||
			operation.RollbackIntentAt == nil ||
			!target.RollbackIntentAt.Equal(*operation.RollbackIntentAt) {
			return fmt.Errorf("rollback operation changed before result persistence retry")
		}
		current, captureErr := handler.Capture(ctx, target.Resource)
		if captureErr != nil {
			return fmt.Errorf("capture rollback result before persistence retry: %w", captureErr)
		}
		if !exactEqual(observed, current) {
			return fmt.Errorf("live rollback result changed before persistence retry")
		}
		return nil
	}
	next, err := m.updateAfterRollbackEffect(ctx, value, "persist rolled back operation", changeSetID, operationID, mutate, persisted, revalidate)
	if err != nil {
		return nil, &rollbackFailure{err: err, ambiguous: true}
	}
	return next, nil
}

func (m *Manager) markRollbackFailed(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, cause error) (*model.RemediationJournal, *rollbackFailure) {
	next, err := m.update(ctx, value, "persist failed rollback operation", func(journal *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		target.State = model.OperationFailed
		journalError := m.makeJournalError(journal, "rollback", changeSetID, operationID, target, &Error{Code: CodeRollbackFailed, Err: cause})
		target.Error = &journalError
		return nil
	})
	if err != nil {
		return nil, &rollbackFailure{err: err}
	}
	return next, &rollbackFailure{err: &Error{Code: CodeRollbackFailed, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Err: cause}}
}

func (m *Manager) markRollbackAmbiguous(ctx context.Context, value *model.RemediationJournal, changeSetID, operationID string, cause error) (*model.RemediationJournal, *rollbackFailure) {
	operation, _, _, findErr := findOperation(value, changeSetID, operationID)
	if findErr != nil {
		return value, &rollbackFailure{err: findErr, ambiguous: true}
	}
	journalError := m.makeJournalError(value, "rollback", changeSetID, operationID, operation, &Error{Code: CodeRecoveryRequired, Err: cause})
	mutate := func(journal *model.RemediationJournal) error {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		if findErr != nil {
			return findErr
		}
		target.State = model.OperationAmbiguous
		errorCopy := journalError
		target.Error = &errorCopy
		return nil
	}
	persisted := func(journal *model.RemediationJournal) bool {
		target, _, _, findErr := findOperation(journal, changeSetID, operationID)
		return findErr == nil &&
			target.State == model.OperationAmbiguous &&
			journalErrorMatches(target.Error, journalError)
	}
	next, err := m.updateAfterRollbackEffect(ctx, value, "persist ambiguous rollback operation", changeSetID, operationID, mutate, persisted, nil)
	if err != nil {
		return nil, &rollbackFailure{err: err, ambiguous: true}
	}
	return next, &rollbackFailure{err: &Error{Code: CodeRecoveryRequired, Operation: "rollback operation", RunID: value.RunID, ChangeSetID: changeSetID, OperationID: operationID, Committed: true, Err: cause}, ambiguous: true}
}

func (m *Manager) verifyRollbackLiveFrontier(ctx context.Context, value *model.RemediationJournal, handler fileRuntime) error {
	if value == nil || handler == nil {
		return fmt.Errorf("journal and file handler are required")
	}
	type writerRef struct {
		changeSetID       string
		operationID       string
		changeSetSequence int
		operationSequence int
	}
	writers := make([]writerRef, 0)
	for _, changeSet := range value.ChangeSets {
		for _, operation := range changeSet.Operations {
			writers = append(writers, writerRef{
				changeSetID:       changeSet.ID,
				operationID:       operation.ID,
				changeSetSequence: changeSet.Sequence,
				operationSequence: operation.Sequence,
			})
		}
	}
	sort.SliceStable(writers, func(i, j int) bool {
		if writers[i].changeSetSequence != writers[j].changeSetSequence {
			return writers[i].changeSetSequence < writers[j].changeSetSequence
		}
		if writers[i].operationSequence != writers[j].operationSequence {
			return writers[i].operationSequence < writers[j].operationSequence
		}
		if writers[i].changeSetID != writers[j].changeSetID {
			return writers[i].changeSetID < writers[j].changeSetID
		}
		return writers[i].operationID < writers[j].operationID
	})

	frontier := make(map[string]model.ResourceSnapshot)
	for _, reference := range writers {
		operation, _, _, err := findOperation(value, reference.changeSetID, reference.operationID)
		if err != nil {
			return err
		}
		if operation.State == model.OperationPlanned || operation.ProvesNoEffect() {
			continue
		}
		if operation.Before.IsZero() {
			return fmt.Errorf("operation %s/%s has no durable before state", reference.changeSetID, reference.operationID)
		}
		if _, exists := frontier[operation.Resource.Key]; !exists {
			frontier[operation.Resource.Key] = operation.Before
		}
		switch operation.State {
		case model.OperationRolledBack:
			// A rolled-back writer no longer contributes to the live
			// frontier. Earlier active writers remain authoritative.
		case model.OperationApplied, model.OperationVerified:
			if operation.ObservedAfter == nil {
				return fmt.Errorf("active operation %s/%s has no durable after state", reference.changeSetID, reference.operationID)
			}
			frontier[operation.Resource.Key] = *operation.ObservedAfter
		default:
			return fmt.Errorf("operation %s/%s remains %s at rollback completion", reference.changeSetID, reference.operationID, operation.State)
		}
	}

	return verifyLiveFrontierSnapshots(ctx, handler, frontier, "rollback live frontier")
}

func verifyLiveFrontierSnapshots(
	ctx context.Context,
	handler fileRuntime,
	frontier map[string]model.ResourceSnapshot,
	label string,
) error {
	if handler == nil {
		return fmt.Errorf("file handler is required")
	}
	keys := make([]string, 0, len(frontier))
	for key := range frontier {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		expected := frontier[key]
		current, err := handler.Capture(ctx, expected.Reference)
		if err != nil {
			return fmt.Errorf("capture %s %s: %w", label, key, err)
		}
		if !exactEqual(expected, current) {
			return fmt.Errorf("%s %s changed before terminal persistence", label, key)
		}
	}
	return nil
}

func (m *Manager) updateAfterRollbackEffect(
	parent context.Context,
	current *model.RemediationJournal,
	operation, changeSetID, operationID string,
	mutate func(*model.RemediationJournal) error,
	persisted func(*model.RemediationJournal) bool,
	revalidate func(context.Context, *model.RemediationJournal) error,
) (*model.RemediationJournal, error) {
	if current == nil || mutate == nil || persisted == nil {
		return nil, &Error{
			Code:        CodeRecoveryRequired,
			Operation:   operation,
			ChangeSetID: changeSetID,
			OperationID: operationID,
			Committed:   true,
			Err:         fmt.Errorf("current journal, mutation, and persistence predicate are required after a possible rollback effect"),
		}
	}
	next, firstErr := m.update(parent, current, operation, mutate)
	if firstErr == nil {
		return next, nil
	}
	latest, reloadErr := m.reloadApplyJournal(parent, current.RunID, "reload after "+operation, firstErr)
	if reloadErr != nil {
		return nil, &Error{
			Code:        CodeRecoveryRequired,
			Operation:   operation,
			RunID:       current.RunID,
			ChangeSetID: changeSetID,
			OperationID: operationID,
			Committed:   true,
			Err:         reloadErr,
		}
	}
	if persisted(latest) {
		return latest, nil
	}
	if revalidate != nil {
		revalidationContext, cancelRevalidation := newApplyCleanupContext(parent)
		revalidationErr := revalidate(revalidationContext, latest)
		cancelRevalidation()
		if revalidationErr != nil {
			return nil, &Error{
				Code:        CodeRecoveryRequired,
				Operation:   operation,
				RunID:       current.RunID,
				ChangeSetID: changeSetID,
				OperationID: operationID,
				Committed:   true,
				Err: fmt.Errorf(
					"live rollback state changed before persistence retry: initial error: %v; revalidation error: %w",
					firstErr,
					revalidationErr,
				),
			}
		}
	}

	retryContext, cancelRetry := newApplyCleanupContext(parent)
	next, retryErr := m.update(retryContext, latest, "retry "+operation, mutate)
	cancelRetry()
	if retryErr == nil {
		return next, nil
	}
	afterRetry, retryReloadErr := m.reloadApplyJournal(parent, current.RunID, "reload after retry "+operation, retryErr)
	if retryReloadErr != nil {
		return nil, &Error{
			Code:        CodeRecoveryRequired,
			Operation:   operation,
			RunID:       current.RunID,
			ChangeSetID: changeSetID,
			OperationID: operationID,
			Committed:   true,
			Err:         retryReloadErr,
		}
	}
	if persisted(afterRetry) {
		return afterRetry, nil
	}
	return nil, &Error{
		Code:        CodeRecoveryRequired,
		Operation:   operation,
		RunID:       current.RunID,
		ChangeSetID: changeSetID,
		OperationID: operationID,
		Committed:   true,
		Err: fmt.Errorf(
			"rollback result after a possible target change was not durably confirmed: initial error: %v; retry error: %w",
			firstErr,
			retryErr,
		),
	}
}

func (m *Manager) recordBlockedAttempt(
	ctx context.Context,
	value *model.RemediationJournal,
	scope model.RollbackScope,
	trigger model.RollbackTrigger,
	requested, expanded []string,
	cascadeApproved bool,
	executorBuild *model.RemediationBuildIdentity,
	cause error,
) (model.RollbackAttempt, error) {
	attemptID, err := m.nextID("rollback-")
	if err != nil {
		return model.RollbackAttempt{}, &Error{Code: CodePersistFailed, Operation: "generate blocked attempt ID", RunID: value.RunID, Err: err}
	}
	startedAt := m.nextEventTime(value)
	journalError := m.makeJournalError(value, "rollback_preflight", "", "", nil, cause)
	attemptErrors := automaticRollbackTriggerErrors(value, trigger, requested, expanded)
	attemptErrors = append(attemptErrors, journalError)
	recoveryRequired := trigger == model.RollbackApplyFailure || trigger == model.RollbackVerifyFailure || rollbackPreflightRequiresRecovery(cause)
	var recoveryError model.JournalError
	var eligible []string
	if recoveryRequired {
		recoveryError = m.makeJournalError(value, "rollback_preflight_recovery", "", "", nil, &Error{Code: CodeRecoveryRequired, Err: cause})
		eligible, err = rollbackRecoveryEligibleChangeSets(value, expanded)
		if err != nil {
			return model.RollbackAttempt{}, err
		}
	}
	completedAt := m.rollbackAttemptCompletionTime(value, startedAt, attemptErrors)
	attempt := model.RollbackAttempt{
		ID:                  attemptID,
		Scope:               scope,
		Trigger:             trigger,
		ExecutorBuild:       cloneBuildIdentity(executorBuild),
		RequestedChangeSets: append([]string(nil), requested...),
		ExpandedChangeSets:  append([]string(nil), expanded...),
		CascadeApproved:     cascadeApproved,
		Outcome:             model.RollbackBlocked,
		StartedAt:           startedAt,
		CompletedAt:         &completedAt,
		Errors:              append([]model.JournalError(nil), attemptErrors...),
	}
	_, err = m.update(ctx, value, "persist blocked rollback attempt", func(journal *model.RemediationJournal) error {
		journal.RollbackAttempts = append(journal.RollbackAttempts, attempt)
		if recoveryRequired {
			return enterBlockedRollbackRecovery(journal, eligible, recoveryError)
		}
		return nil
	})
	if err != nil {
		latest, reloadErr := m.reloadApplyJournal(ctx, value.RunID, "reload blocked rollback attempt", err)
		if reloadErr != nil {
			return model.RollbackAttempt{}, reloadErr
		}
		for _, recorded := range latest.RollbackAttempts {
			if recorded.ID == attempt.ID {
				return recorded, nil
			}
		}
		return model.RollbackAttempt{}, err
	}
	return attempt, nil
}

func hasAnyActiveOutside(value *model.RemediationJournal, rolledBack []string) bool {
	selected := make(map[string]struct{}, len(rolledBack))
	for _, id := range rolledBack {
		selected[id] = struct{}{}
	}
	for _, changeSet := range value.ChangeSets {
		if _, included := selected[changeSet.ID]; included {
			continue
		}
		if hasRollbackWork(value, changeSet.ID) {
			return true
		}
	}
	return false
}

func hasAnyRolledBack(value *model.RemediationJournal) bool {
	if value == nil {
		return false
	}
	for _, changeSet := range value.ChangeSets {
		if changeSet.State == model.ChangeRolledBack || changeSet.State == model.ChangePartiallyRolledBack {
			return true
		}
		for _, operation := range changeSet.Operations {
			if operation.State == model.OperationRolledBack {
				return true
			}
		}
	}
	return false
}

func hasRecoveryRequiredEvidence(value *model.RemediationJournal) bool {
	if value == nil {
		return false
	}
	for _, changeSet := range value.ChangeSets {
		if changeSet.State == model.ChangeRecoveryRequired || (changeSet.State == model.ChangeRollingBack && changeSet.Error != nil && changeSet.Error.Code == model.JournalErrorRecoveryAmbiguous) {
			return true
		}
		for _, operation := range changeSet.Operations {
			if operation.State == model.OperationAmbiguous {
				return true
			}
		}
	}
	return false
}

func rollbackOutsideScopes(value *model.RemediationJournal, targets []string) (all []string, unsafe []string) {
	if value == nil {
		return nil, nil
	}
	selected := make(map[string]struct{}, len(targets))
	for _, changeSetID := range targets {
		selected[changeSetID] = struct{}{}
	}
	for _, changeSet := range value.ChangeSets {
		if _, included := selected[changeSet.ID]; included {
			continue
		}
		hasWork := hasRollbackWork(value, changeSet.ID)
		stableVerified := hasWork && changeSet.State == model.ChangeVerified
		if stableVerified {
			for _, operation := range changeSet.Operations {
				if operation.State != model.OperationVerified {
					stableVerified = false
					break
				}
			}
		}
		safeNoEffect := !hasWork && terminalRollbackSafeChangeSet(changeSet)
		if safeNoEffect && changeSet.State == model.ChangeRolledBack {
			// A rolled-back change outside the current attempt is terminal-safe
			// only when immutable successful/partial attempt history already
			// covers it. The current attempt supplies the separate globally
			// required successful outcome if it reaches a normal terminal state.
			safeNoEffect = completedRollbackAttemptCovers(value, changeSet.ID)
		}
		if safeNoEffect {
			continue
		}
		all = append(all, changeSet.ID)
		if !stableVerified {
			unsafe = append(unsafe, changeSet.ID)
		}
	}
	return appendUnique(nil, all...), appendUnique(nil, unsafe...)
}

func terminalRollbackSafeChangeSet(changeSet model.ChangeSet) bool {
	allowed := func(states ...model.OperationState) bool {
		set := make(map[model.OperationState]struct{}, len(states))
		for _, state := range states {
			set[state] = struct{}{}
		}
		for _, operation := range changeSet.Operations {
			if _, ok := set[operation.State]; !ok {
				return false
			}
		}
		return true
	}
	switch changeSet.State {
	case model.ChangePlanned:
		return allowed(model.OperationPlanned)
	case model.ChangeApplyFailed:
		for _, operation := range changeSet.Operations {
			if operation.State != model.OperationPlanned && !operation.ProvesNoEffect() {
				return false
			}
		}
		return true
	case model.ChangeRolledBack:
		hasRolledBack := false
		for _, operation := range changeSet.Operations {
			if operation.State == model.OperationRolledBack {
				hasRolledBack = true
				continue
			}
			if operation.State != model.OperationPlanned && !operation.ProvesNoEffect() {
				return false
			}
		}
		return hasRolledBack
	default:
		return false
	}
}

func rollbackTargetUnresolved(value *model.RemediationJournal, targets []string) []string {
	if value == nil {
		return nil
	}
	result := make([]string, 0)
	for _, changeSetID := range targets {
		changeSet, _, err := findChangeSet(value, changeSetID)
		if err != nil || hasRollbackWork(value, changeSetID) || !terminalRollbackSafeChangeSet(*changeSet) {
			result = append(result, changeSetID)
		}
	}
	return appendUnique(nil, result...)
}

func rollbackOutsideUnresolved(value *model.RemediationJournal, targets []string, scope model.RollbackScope) []string {
	all, unsafe := rollbackOutsideScopes(value, targets)
	if scope == model.RollbackRun {
		return all
	}
	return unsafe
}

func (m *Manager) rollbackRunStateError(value *model.RemediationJournal, phase string, state model.RunState) *model.JournalError {
	if !state.NeedsOperatorAction() {
		return nil
	}
	code := CodeRollbackFailed
	if state == model.RunRecoveryRequired {
		code = CodeRecoveryRequired
	}
	journalError := m.makeJournalError(value, phase, "", "", nil, &Error{Code: code, Err: fmt.Errorf("rollback run remains %s", state)})
	return &journalError
}

func classifyRollbackRunState(value *model.RemediationJournal, targets []string, scope model.RollbackScope) model.RunState {
	if hasRecoveryRequiredEvidence(value) {
		return model.RunRecoveryRequired
	}
	if len(unresolvedRollbackChangeSets(value)) > 0 {
		if hasAnyRolledBack(value) {
			return model.RunPartiallyRolledBack
		}
		return model.RunRollbackFailed
	}
	if len(rollbackTargetUnresolved(value, targets)) > 0 {
		return model.RunRecoveryRequired
	}
	outside, unsafe := rollbackOutsideScopes(value, targets)
	if len(outside) > 0 {
		if scope == model.RollbackRun || len(unsafe) > 0 {
			return model.RunRecoveryRequired
		}
		if hasApplyFailureOutcome(value) {
			return model.RunFailed
		}
		return model.RunCompletedWithRollbacks
	}
	if hasApplyFailureOutcome(value) {
		return model.RunFailed
	}
	return model.RunRolledBack
}

func hasApplyFailedChangeSet(value *model.RemediationJournal) bool {
	if value == nil {
		return false
	}
	for _, changeSet := range value.ChangeSets {
		if changeSet.State == model.ChangeApplyFailed {
			return true
		}
	}
	return false
}

func hasApplyFailureOutcome(value *model.RemediationJournal) bool {
	if hasApplyFailedChangeSet(value) {
		return true
	}
	if value == nil {
		return false
	}
	if value.Error != nil && value.Error.Code == model.JournalErrorApplyFailed && value.Error.Phase == "recover_interrupted_apply" {
		return true
	}
	for _, attempt := range value.RollbackAttempts {
		for _, journalError := range attempt.Errors {
			if journalError.Code == model.JournalErrorApplyFailed && journalError.Phase == "recover_interrupted_apply" {
				return true
			}
		}
	}
	return false
}

func requiresRecoveredRunRollback(value *model.RemediationJournal) bool {
	return value != nil && value.FailurePolicy == model.FailureRollbackRun && value.State == model.RunRecoveryRequired && len(value.UnresolvedChangeSets) > 0
}

func containsAllIDs(candidates, required []string) bool {
	available := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		available[candidate] = struct{}{}
	}
	for _, requiredID := range required {
		if _, exists := available[requiredID]; !exists {
			return false
		}
	}
	return true
}

func hasRolledBackInTargets(value *model.RemediationJournal, targets []string) bool {
	for _, changeSetID := range targets {
		changeSet, _, err := findChangeSet(value, changeSetID)
		if err != nil {
			continue
		}
		if changeSet.State == model.ChangeRolledBack || changeSet.State == model.ChangePartiallyRolledBack {
			return true
		}
		for _, operation := range changeSet.Operations {
			if operation.State == model.OperationRolledBack {
				return true
			}
		}
	}
	return false
}
