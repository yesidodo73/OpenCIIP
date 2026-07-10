package orchestrator

import (
	"context"
	"fmt"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func (m *Manager) Cancel(ctx context.Context, runID string) error {
	lock, err := m.acquire(ctx, "cancel")
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
	_, err = m.cancelLoaded(ctx, value)
	return err
}

func (m *Manager) cancelLoaded(ctx context.Context, value *model.RemediationJournal) (*model.RemediationJournal, error) {
	if value == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "cancel", Err: fmt.Errorf("journal is required")}
	}
	if err := validateUnusedPlan(value); err != nil {
		return value, &Error{Code: CodeInvalidState, Operation: "cancel", RunID: value.RunID, Err: err}
	}
	deleter, ok := m.content.(RunContentDeleter)
	if !ok || deleter == nil {
		return value, &Error{Code: CodeUnsupportedOperation, Operation: "cancel", RunID: value.RunID, Err: fmt.Errorf("run-scoped desired content deletion is unavailable")}
	}
	var err error
	switch value.State {
	case model.RunPlanned, model.RunApproved, model.RunCancelFailed:
		value, err = m.update(ctx, value, "persist cancellation intent", func(journal *model.RemediationJournal) error {
			journal.State = model.RunCanceling
			journal.Error = nil
			return nil
		})
		if err != nil {
			return nil, err
		}
	case model.RunCanceling:
	default:
		return value, &Error{Code: CodeInvalidState, Operation: "cancel", RunID: value.RunID, Err: fmt.Errorf("run %s cannot be canceled after apply has started", value.State)}
	}
	if err := deleter.DeleteRunContent(ctx, value.RunID); err != nil {
		failure := &Error{Code: CodeCancelFailed, Operation: "delete unused desired content", RunID: value.RunID, Err: err}
		journalError := m.makeJournalError("cancel", "", "", nil, failure)
		persistContext, cancelPersist := newApplyCleanupContext(ctx)
		defer cancelPersist()
		next, persistErr := m.update(persistContext, value, "persist cancellation failure", func(journal *model.RemediationJournal) error {
			journal.State = model.RunCancelFailed
			journal.Error = &journalError
			return nil
		})
		if persistErr != nil {
			return nil, persistErr
		}
		return next, failure
	}
	completionContext, cancelCompletion := newApplyCleanupContext(ctx)
	defer cancelCompletion()
	next, err := m.update(completionContext, value, "complete cancellation", func(journal *model.RemediationJournal) error {
		journal.State = model.RunCanceled
		journal.Error = nil
		journal.UnresolvedChangeSets = nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	return next, nil
}

func validateUnusedPlan(value *model.RemediationJournal) error {
	for _, changeSet := range value.ChangeSets {
		if changeSet.State != model.ChangePlanned || len(changeSet.Before) != 0 || len(changeSet.After) != 0 || changeSet.PreparedAt != nil || changeSet.AppliedAt != nil || changeSet.VerifiedAt != nil || changeSet.RolledBackAt != nil {
			return fmt.Errorf("change set %s contains apply runtime state", changeSet.ID)
		}
		for _, operation := range changeSet.Operations {
			if operation.State != model.OperationPlanned || !operation.Before.IsZero() || operation.ObservedAfter != nil || operation.ObservedRollback != nil || operation.Backup != nil || operation.ApplyIntentAt != nil || operation.AppliedAt != nil || operation.RollbackIntentAt != nil || operation.RolledBackAt != nil {
				return fmt.Errorf("operation %s contains apply runtime state", operation.ID)
			}
		}
	}
	return nil
}
