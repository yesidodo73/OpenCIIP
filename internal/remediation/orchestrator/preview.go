package orchestrator

import (
	"context"
	"fmt"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/conflict"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
)

type rollbackPreviewDigestPayload struct {
	RunID               string              `json:"run_id"`
	Revision            uint64              `json:"revision"`
	PlanDigest          string              `json:"plan_digest"`
	Scope               model.RollbackScope `json:"scope"`
	RequestedChangeSets []string            `json:"requested_change_sets"`
	ExpandedChangeSets  []string            `json:"expanded_change_sets"`
	ExecutionOrder      []string            `json:"execution_order"`
	CascadeRequired     bool                `json:"cascade_required"`
}

func (m *Manager) PreviewRollbackItem(ctx context.Context, runID, changeSetID string) (RollbackPreview, error) {
	lock, err := m.acquireReadOnly(ctx, "preview item rollback")
	if err != nil {
		return RollbackPreview{}, err
	}
	defer lock.Release()
	value, err := m.loadAndVerifyReadOnly(ctx, runID)
	if err != nil {
		return RollbackPreview{}, err
	}
	return m.previewRollbackItem(value, changeSetID)
}

func (m *Manager) previewRollbackItem(value *model.RemediationJournal, changeSetID string) (RollbackPreview, error) {
	if attempt, incomplete := incompleteRollbackAttempt(value); incomplete {
		return RollbackPreview{}, &Error{Code: CodeRecoveryRequired, Operation: "preview item rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("rollback attempt %s is incomplete; recover it before creating a new preview", attempt.ID)}
	}
	changeSet, _, err := findChangeSet(value, changeSetID)
	if err != nil {
		return RollbackPreview{}, &Error{Code: CodeInvalidInput, Operation: "preview item rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: err}
	}
	if !hasRollbackWork(value, changeSetID) || !itemRollbackState(changeSet.State) {
		return RollbackPreview{}, &Error{Code: CodeInvalidState, Operation: "preview item rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("change set %s is not rollback-eligible", changeSet.State)}
	}
	active := activeMap(value)
	closure, err := conflict.ItemRollbackClosure(value.ConflictGraph, changeSetID, active, true)
	if err != nil {
		return RollbackPreview{}, wrapDependency("compute item rollback preview", value.RunID, changeSetID, "", err)
	}
	cascadeRequired := false
	if _, noCascadeErr := conflict.ItemRollbackClosure(value.ConflictGraph, changeSetID, active, false); noCascadeErr != nil {
		if conflict.CodeOf(noCascadeErr) != conflict.CodeRollbackConflict {
			return RollbackPreview{}, wrapDependency("compute non-cascade rollback preview", value.RunID, changeSetID, "", noCascadeErr)
		}
		cascadeRequired = true
	}
	expanded := expandRollbackTargets(value, closure)
	if requiresRecoveredRunRollback(value) && !containsAllIDs(expanded, value.UnresolvedChangeSets) {
		return RollbackPreview{}, &Error{Code: CodeRecoveryRequired, Operation: "preview item rollback", RunID: value.RunID, ChangeSetID: changeSetID, Err: fmt.Errorf("the run failure policy requires rollback of the full unresolved scope")}
	}
	if err := validatePreviewOperations(value, expanded, "preview item rollback"); err != nil {
		return RollbackPreview{}, err
	}
	order, err := conflict.ReverseRollbackOrder(value.ConflictGraph, expanded, sequenceMap(value))
	if err != nil {
		return RollbackPreview{}, wrapDependency("order item rollback preview", value.RunID, changeSetID, "", err)
	}
	requested := []string{changeSetID}
	digest, err := journal.Digest(rollbackPreviewDigestPayload{
		RunID:               value.RunID,
		Revision:            value.Revision,
		PlanDigest:          value.PlanDigest,
		Scope:               model.RollbackItem,
		RequestedChangeSets: requested,
		ExpandedChangeSets:  expanded,
		ExecutionOrder:      order,
		CascadeRequired:     cascadeRequired,
	})
	if err != nil {
		return RollbackPreview{}, &Error{Code: CodeInvalidState, Operation: "digest item rollback preview", RunID: value.RunID, ChangeSetID: changeSetID, Err: err}
	}
	return RollbackPreview{
		RunID:               value.RunID,
		Revision:            value.Revision,
		Scope:               model.RollbackItem,
		RequestedChangeSets: requested,
		ExpandedChangeSets:  expanded,
		ExecutionOrder:      order,
		CascadeRequired:     cascadeRequired,
		PreviewDigest:       digest,
	}, nil
}

func (m *Manager) PreviewRollbackRun(ctx context.Context, runID string) (RollbackPreview, error) {
	lock, err := m.acquireReadOnly(ctx, "preview run rollback")
	if err != nil {
		return RollbackPreview{}, err
	}
	defer lock.Release()
	value, err := m.loadAndVerifyReadOnly(ctx, runID)
	if err != nil {
		return RollbackPreview{}, err
	}
	return m.previewRollbackRun(value)
}

func (m *Manager) previewRollbackRun(value *model.RemediationJournal) (RollbackPreview, error) {
	if attempt, incomplete := incompleteRollbackAttempt(value); incomplete {
		return RollbackPreview{}, &Error{Code: CodeRecoveryRequired, Operation: "preview run rollback", RunID: value.RunID, Err: fmt.Errorf("rollback attempt %s is incomplete; recover it before creating a new preview", attempt.ID)}
	}
	targets := rollbackTargets(value)
	if len(targets) == 0 {
		return RollbackPreview{}, &Error{Code: CodeInvalidState, Operation: "preview run rollback", RunID: value.RunID, Err: fmt.Errorf("run has no rollback-eligible changes")}
	}
	expanded := expandRollbackTargets(value, targets)
	if err := validatePreviewOperations(value, expanded, "preview run rollback"); err != nil {
		return RollbackPreview{}, err
	}
	order, err := conflict.ReverseRollbackOrder(value.ConflictGraph, expanded, sequenceMap(value))
	if err != nil {
		return RollbackPreview{}, wrapDependency("order run rollback preview", value.RunID, "", "", err)
	}
	digest, err := journal.Digest(rollbackPreviewDigestPayload{
		RunID:               value.RunID,
		Revision:            value.Revision,
		PlanDigest:          value.PlanDigest,
		Scope:               model.RollbackRun,
		RequestedChangeSets: []string{},
		ExpandedChangeSets:  expanded,
		ExecutionOrder:      order,
		CascadeRequired:     false,
	})
	if err != nil {
		return RollbackPreview{}, &Error{Code: CodeInvalidState, Operation: "digest run rollback preview", RunID: value.RunID, Err: err}
	}
	return RollbackPreview{
		RunID:               value.RunID,
		Revision:            value.Revision,
		Scope:               model.RollbackRun,
		RequestedChangeSets: []string{},
		ExpandedChangeSets:  expanded,
		ExecutionOrder:      order,
		CascadeRequired:     false,
		PreviewDigest:       digest,
	}, nil
}

func expandRollbackTargets(value *model.RemediationJournal, targets []string) []string {
	expanded := append([]string(nil), targets...)
	for {
		previousLength := len(expanded)
		expanded = completeRollbackGroups(value.ConflictGraph, expanded)
		expanded = completeRollbackContext(value, expanded)
		if len(expanded) == previousLength {
			return expanded
		}
	}
}

func validatePreviewOperations(value *model.RemediationJournal, targets []string, phase string) error {
	for _, id := range targets {
		candidate, _, err := findChangeSet(value, id)
		if err != nil {
			return &Error{Code: CodeInvalidState, Operation: phase, RunID: value.RunID, ChangeSetID: id, Err: err}
		}
		for _, operation := range candidate.Operations {
			if operation.ProvesNoEffect() {
				continue
			}
			if operation.State == model.OperationApplyIntentDurable || operation.State == model.OperationAmbiguous ||
				(operation.State == model.OperationFailed && operation.RollbackIntentAt == nil) {
				return &Error{Code: CodeRecoveryRequired, Operation: phase, RunID: value.RunID, ChangeSetID: id, OperationID: operation.ID, Err: fmt.Errorf("in-flight apply result must be recovered before rollback")}
			}
			if operation.State != model.OperationPlanned && operation.Kind != model.OperationFileMetadata {
				return &Error{Code: CodeUnsupportedOperation, Operation: phase, RunID: value.RunID, ChangeSetID: id, OperationID: operation.ID, Err: fmt.Errorf("only regular-file metadata rollback is supported")}
			}
		}
	}
	return nil
}
