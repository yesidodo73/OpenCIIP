package orchestrator

import (
	"context"
	"fmt"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/conflict"
)

func (m *Manager) rollbackVerificationFailureLocked(ctx context.Context, value *model.RemediationJournal, failedChangeSets []string, cause error, forceRun bool) error {
	if value == nil {
		return &Error{Code: CodeInvalidInput, Operation: "rollback evaluator verification failure", Err: fmt.Errorf("journal is required")}
	}
	runID := value.RunID
	if cause == nil {
		cause = fmt.Errorf("platform evaluator postcondition failed")
	}

	requested := make([]string, 0, len(failedChangeSets))
	seen := make(map[string]struct{}, len(failedChangeSets))
	for _, id := range failedChangeSets {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		if _, _, findErr := findChangeSet(value, id); findErr != nil {
			return &Error{Code: CodeInvalidInput, Operation: "rollback evaluator verification failure", RunID: runID, ChangeSetID: id, Err: findErr}
		}
		seen[id] = struct{}{}
		requested = append(requested, id)
	}
	if len(requested) == 0 {
		for _, changeSet := range value.ChangeSets {
			if hasRollbackWork(value, changeSet.ID) {
				requested = append(requested, changeSet.ID)
			}
		}
	}

	journalError := m.makeJournalError("evaluator_verification", "", "", nil, &Error{Code: CodeVerificationFailed, Err: cause})
	mutateFailure := func(journal *model.RemediationJournal) error {
		for _, id := range requested {
			changeSet, _, findErr := findChangeSet(journal, id)
			if findErr != nil {
				return findErr
			}
			copy := journalError
			copy.ChangeSetID = id
			changeSet.Error = &copy
		}
		journal.Error = &journalError
		return nil
	}
	updated, err := m.updateBeforeAutomaticRollback(ctx, value, "persist evaluator verification failure", mutateFailure, func(journal *model.RemediationJournal) bool {
		if !journalErrorMatches(journal.Error, journalError) {
			return false
		}
		for _, id := range requested {
			changeSet, _, findErr := findChangeSet(journal, id)
			if findErr != nil {
				return false
			}
			expected := journalError
			expected.ChangeSetID = id
			if !journalErrorMatches(changeSet.Error, expected) {
				return false
			}
		}
		return true
	})
	if err != nil {
		return err
	}
	value = updated

	scope := model.RollbackItem
	targets := make([]string, 0)
	if forceRun || value.FailurePolicy == model.FailureRollbackRun {
		scope = model.RollbackRun
		targets = rollbackTargets(value)
	} else {
		active := activeMap(value)
		selected := make(map[string]struct{})
		for _, id := range requested {
			if !hasRollbackWork(value, id) {
				continue
			}
			closure, closureErr := conflict.ItemRollbackClosure(value.ConflictGraph, id, active, true)
			if closureErr != nil {
				return wrapDependency("compute evaluator failure rollback closure", runID, id, "", closureErr)
			}
			for _, target := range closure {
				if active[target] {
					selected[target] = struct{}{}
				}
			}
		}
		for _, changeSet := range value.ChangeSets {
			if _, exists := selected[changeSet.ID]; exists {
				targets = append(targets, changeSet.ID)
			}
		}
	}
	if len(targets) == 0 {
		return &Error{Code: CodeInvalidState, Operation: "rollback evaluator verification failure", RunID: runID, Err: fmt.Errorf("no rollback-eligible changes remain: %w", cause)}
	}
	_, err = m.executeRollback(ctx, value, scope, model.RollbackVerifyFailure, requested, targets, true)
	return err
}
