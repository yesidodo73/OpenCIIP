package journal

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func ValidateTransition(previous, next *model.RemediationJournal) error {
	if previous == nil || next == nil {
		return wrap(CodeInvalidInput, "validate transition", "", fmt.Errorf("previous and next journals are required"))
	}
	if err := previous.Validate(); err != nil {
		return wrap(CodeInvalidInput, "validate transition", previous.RunID, err)
	}
	if err := next.Validate(); err != nil {
		return wrap(CodeInvalidInput, "validate transition", next.RunID, err)
	}
	if previous.SchemaVersion != next.SchemaVersion {
		return transitionError(next.RunID, "schema version is immutable")
	}
	if previous.Revision == math.MaxUint64 {
		return transitionError(next.RunID, "revision is exhausted")
	}
	if next.Revision != previous.Revision+1 {
		return transitionError(next.RunID, fmt.Sprintf("revision must advance from %d to %d", previous.Revision, previous.Revision+1))
	}
	if previous.RunID != next.RunID || previous.ScanRunID != next.ScanRunID {
		return transitionError(next.RunID, "run identifiers are immutable")
	}
	if previous.ScanToolVersion != next.ScanToolVersion ||
		previous.ScanToolCommit != next.ScanToolCommit ||
		previous.ScanToolExecutableSHA256 != next.ScanToolExecutableSHA256 ||
		previous.RuleSetVersion != next.RuleSetVersion {
		return transitionError(next.RunID, "scan tool and rule set identities are immutable")
	}
	if !reflect.DeepEqual(previous.Platform, next.Platform) || !reflect.DeepEqual(previous.RemediationBuild, next.RemediationBuild) {
		return transitionError(next.RunID, "platform and remediation build identities are immutable")
	}
	if previous.FailurePolicy != next.FailurePolicy || previous.PlanDigest != next.PlanDigest {
		return transitionError(next.RunID, "failure policy and plan digest are immutable")
	}
	if !reflect.DeepEqual(previous.Host, next.Host) || !previous.StartedAt.Equal(next.StartedAt) {
		return transitionError(next.RunID, "host identity and start time are immutable")
	}
	if !next.UpdatedAt.After(previous.UpdatedAt) {
		return transitionError(next.RunID, "updated_at must move forwards")
	}
	if !previous.State.CanTransitionTo(next.State) {
		return transitionError(next.RunID, fmt.Sprintf("run state cannot transition from %s to %s", previous.State, next.State))
	}
	if !reflect.DeepEqual(previous.ConflictGraph, next.ConflictGraph) {
		return transitionError(next.RunID, "the approved conflict graph is immutable")
	}
	if len(previous.ChangeSets) != len(next.ChangeSets) {
		return transitionError(next.RunID, "change sets cannot be added or removed")
	}

	nextByID := make(map[string]*model.ChangeSet, len(next.ChangeSets))
	for index := range next.ChangeSets {
		changeSet := &next.ChangeSets[index]
		nextByID[changeSet.ID] = changeSet
	}
	for index := range previous.ChangeSets {
		before := &previous.ChangeSets[index]
		if next.ChangeSets[index].ID != before.ID {
			return transitionError(next.RunID, "change set order is immutable")
		}
		after, exists := nextByID[before.ID]
		if !exists {
			return transitionError(next.RunID, fmt.Sprintf("change set %s was removed", before.ID))
		}
		if before.Approval == nil && after.Approval != nil &&
			(previous.State != model.RunPlanned || next.State != model.RunApproved) {
			return transitionError(
				next.RunID,
				fmt.Sprintf("change set %s approval can only be initialized while the run transitions from planned to approved", before.ID),
			)
		}
		if err := validateChangeSetTransition(next.RunID, before, after); err != nil {
			return err
		}
	}
	if err := validateAttemptHistory(next.RunID, previous.LatestEventTime(), previous.RollbackAttempts, next.RollbackAttempts); err != nil {
		return err
	}
	if err := validateRecoveryObserverClaim(next.RunID, previous, next); err != nil {
		return err
	}
	if err := validateJournalErrorEvents(previous, next); err != nil {
		return err
	}
	return nil
}

func validateChangeSetTransition(runID string, previous, next *model.ChangeSet) error {
	if previous.RuleID != next.RuleID || previous.Sequence != next.Sequence || previous.Risk != next.Risk || previous.RollbackGroup != next.RollbackGroup {
		return transitionError(runID, fmt.Sprintf("change set %s plan identity is immutable", previous.ID))
	}
	if !reflect.DeepEqual(previous.RuleIdentity, next.RuleIdentity) || !reflect.DeepEqual(previous.RecipeIdentity, next.RecipeIdentity) {
		return transitionError(runID, fmt.Sprintf("change set %s rule or recipe identity changed", previous.ID))
	}
	if previous.DryRun != next.DryRun || previous.ExpectedImpact != next.ExpectedImpact {
		return transitionError(runID, fmt.Sprintf("change set %s approved presentation is immutable", previous.ID))
	}
	if !reflect.DeepEqual(previous.DependsOn, next.DependsOn) || !reflect.DeepEqual(previous.Resources, next.Resources) {
		return transitionError(runID, fmt.Sprintf("change set %s dependencies and resources are immutable", previous.ID))
	}
	if !previous.State.CanTransitionTo(next.State) {
		return transitionError(runID, fmt.Sprintf("change set %s cannot transition from %s to %s", previous.ID, previous.State, next.State))
	}
	if previous.Approval != nil && !reflect.DeepEqual(previous.Approval, next.Approval) {
		return transitionError(runID, fmt.Sprintf("change set %s approval is immutable", previous.ID))
	}
	for _, marker := range []struct {
		name     string
		previous *time.Time
		next     *time.Time
	}{
		{name: "prepared_at", previous: previous.PreparedAt, next: next.PreparedAt},
		{name: "applied_at", previous: previous.AppliedAt, next: next.AppliedAt},
		{name: "verified_at", previous: previous.VerifiedAt, next: next.VerifiedAt},
		{name: "rolled_back_at", previous: previous.RolledBackAt, next: next.RolledBackAt},
	} {
		if !immutableDurableTime(marker.previous, marker.next) {
			return transitionError(runID, fmt.Sprintf("change set %s %s is immutable", previous.ID, marker.name))
		}
	}
	if len(previous.Before) > 0 && !reflect.DeepEqual(previous.Before, next.Before) {
		return transitionError(runID, fmt.Sprintf("change set %s changed its durable before state", previous.ID))
	}
	if len(previous.After) > 0 && !reflect.DeepEqual(previous.After, next.After) {
		return transitionError(runID, fmt.Sprintf("change set %s changed its observed after state", previous.ID))
	}
	if len(previous.Operations) != len(next.Operations) {
		return transitionError(runID, fmt.Sprintf("change set %s operations cannot be added or removed", previous.ID))
	}
	nextOperations := make(map[string]*model.OperationRecord, len(next.Operations))
	for index := range next.Operations {
		operation := &next.Operations[index]
		nextOperations[operation.ID] = operation
	}
	for index := range previous.Operations {
		before := &previous.Operations[index]
		if next.Operations[index].ID != before.ID {
			return transitionError(runID, fmt.Sprintf("operation order changed in change set %s", previous.ID))
		}
		after, exists := nextOperations[before.ID]
		if !exists {
			return transitionError(runID, fmt.Sprintf("operation %s was removed from change set %s", before.ID, previous.ID))
		}
		if err := validateOperationTransition(runID, previous.ID, before, after); err != nil {
			return err
		}
	}
	return nil
}

func validateOperationTransition(runID, changeSetID string, previous, next *model.OperationRecord) error {
	if previous.Sequence != next.Sequence || previous.RollbackSequence != next.RollbackSequence || previous.Kind != next.Kind || previous.RecoveryMode != next.RecoveryMode {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s has an immutable plan", previous.ID, changeSetID))
	}
	if !reflect.DeepEqual(previous.Resource, next.Resource) || !reflect.DeepEqual(previous.ExpectedBefore, next.ExpectedBefore) || !reflect.DeepEqual(previous.Desired, next.Desired) {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s changed its resource, approved precondition, or desired state", previous.ID, changeSetID))
	}
	if !previous.Before.IsZero() && !reflect.DeepEqual(previous.Before, next.Before) {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s changed its durable before state", previous.ID, changeSetID))
	}
	if previous.ObservedAfter != nil && !reflect.DeepEqual(previous.ObservedAfter, next.ObservedAfter) {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s changed its observed state", previous.ID, changeSetID))
	}
	if previous.ObservedRollback != nil && !reflect.DeepEqual(previous.ObservedRollback, next.ObservedRollback) {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s changed its observed rollback state", previous.ID, changeSetID))
	}
	if previous.Backup != nil && !reflect.DeepEqual(previous.Backup, next.Backup) {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s changed its backup artifact", previous.ID, changeSetID))
	}
	for _, marker := range []struct {
		name     string
		previous *time.Time
		next     *time.Time
	}{
		{name: "apply_intent_at", previous: previous.ApplyIntentAt, next: next.ApplyIntentAt},
		{name: "applied_at", previous: previous.AppliedAt, next: next.AppliedAt},
		{name: "rollback_intent_at", previous: previous.RollbackIntentAt, next: next.RollbackIntentAt},
		{name: "rolled_back_at", previous: previous.RolledBackAt, next: next.RolledBackAt},
	} {
		if !immutableDurableTime(marker.previous, marker.next) {
			return transitionError(runID, fmt.Sprintf("operation %s in change set %s %s is immutable", previous.ID, changeSetID, marker.name))
		}
	}
	if previous.ProvesNoEffect() && !next.ProvesNoEffect() {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s changed its durable no-effect result", previous.ID, changeSetID))
	}
	if !previous.State.CanTransitionTo(next.State) {
		return transitionError(runID, fmt.Sprintf("operation %s in change set %s cannot transition from %s to %s", previous.ID, changeSetID, previous.State, next.State))
	}
	return nil
}

func validateAttemptHistory(runID string, latestPreviousEvent time.Time, previous, next []model.RollbackAttempt) error {
	if len(next) < len(previous) {
		return transitionError(runID, "rollback attempts cannot be removed")
	}
	if len(next) > len(previous)+1 {
		return transitionError(runID, "only one rollback attempt may be appended per revision")
	}
	for index := range previous {
		before := previous[index]
		after := next[index]
		if before.ID != after.ID || before.Scope != after.Scope || before.Trigger != after.Trigger || before.CascadeApproved != after.CascadeApproved {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s identity is immutable", before.ID))
		}
		if !reflect.DeepEqual(before.RequestedChangeSets, after.RequestedChangeSets) || !reflect.DeepEqual(before.ExpandedChangeSets, after.ExpandedChangeSets) || !before.StartedAt.Equal(after.StartedAt) {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s scope is immutable", before.ID))
		}
		if !buildIdentityPointerEqual(before.ExecutorBuild, after.ExecutorBuild) {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s executor build is immutable", before.ID))
		}
		if before.ObservedByBuild != nil {
			if !buildIdentityPointerEqual(before.ObservedByBuild, after.ObservedByBuild) {
				return transitionError(runID, fmt.Sprintf("rollback attempt %s observer build is immutable", before.ID))
			}
		}
		if !immutableDurableTime(before.CompletedAt, after.CompletedAt) {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s completed_at is immutable", before.ID))
		}
		if before.CompletedAt != nil && !before.CompletedAt.IsZero() && !reflect.DeepEqual(before, after) {
			return transitionError(runID, fmt.Sprintf("completed rollback attempt %s is immutable", before.ID))
		}
		if len(after.Errors) < len(before.Errors) {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s errors cannot be removed", before.ID))
		}
		for errorIndex := range before.Errors {
			if !reflect.DeepEqual(before.Errors[errorIndex], after.Errors[errorIndex]) {
				return transitionError(runID, fmt.Sprintf("rollback attempt %s changed a recorded error", before.ID))
			}
		}
	}
	if len(next) == len(previous)+1 {
		appended := next[len(previous)]
		if !appended.StartedAt.After(latestPreviousEvent) {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s must start after the previous durable event", appended.ID))
		}
		if appended.Trigger != model.RollbackCrashRecovery && appended.ObservedByBuild != nil {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s observer build can only be added by an isolated recovery claim", appended.ID))
		}
	}
	return nil
}

func validateRecoveryObserverClaim(runID string, previous, next *model.RemediationJournal) error {
	claimedIndex := -1
	for index := range previous.RollbackAttempts {
		before := previous.RollbackAttempts[index]
		after := next.RollbackAttempts[index]
		if before.ObservedByBuild != nil || after.ObservedByBuild == nil {
			continue
		}
		if claimedIndex >= 0 {
			return transitionError(runID, "only one recovery observer may be claimed per revision")
		}
		if before.CompletedAt != nil || after.CompletedAt != nil {
			return transitionError(runID, fmt.Sprintf("rollback attempt %s recovery observer must be claimed while the attempt is incomplete", before.ID))
		}
		claimedIndex = index
	}
	if claimedIndex < 0 {
		return nil
	}
	normalized := *next
	normalized.Revision = previous.Revision
	normalized.UpdatedAt = previous.UpdatedAt
	normalized.RollbackAttempts = append([]model.RollbackAttempt(nil), next.RollbackAttempts...)
	normalized.RollbackAttempts[claimedIndex].ObservedByBuild = nil
	if !reflect.DeepEqual(*previous, normalized) {
		return transitionError(runID, fmt.Sprintf("rollback attempt %s recovery observer claim must be the only durable state change", previous.RollbackAttempts[claimedIndex].ID))
	}
	return nil
}

func buildIdentityPointerEqual(left, right *model.RemediationBuildIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func immutableDurableTime(previous, next *time.Time) bool {
	return previous == nil || previous.IsZero() || (next != nil && previous.Equal(*next))
}

func validateJournalErrorEvents(previous, next *model.RemediationJournal) error {
	previousErrors := collectJournalErrors(previous)
	latestPreviousEvent := previous.LatestEventTime()
	for _, journalError := range collectJournalErrors(next) {
		if containsJournalError(previousErrors, journalError) {
			continue
		}
		if !journalError.OccurredAt.After(latestPreviousEvent) {
			return transitionError(
				next.RunID,
				fmt.Sprintf("new journal error %s must occur after the previous durable event", journalError.Phase),
			)
		}
	}
	return nil
}

func collectJournalErrors(journal *model.RemediationJournal) []model.JournalError {
	if journal == nil {
		return nil
	}
	result := make([]model.JournalError, 0)
	if journal.Error != nil {
		result = append(result, *journal.Error)
	}
	for _, changeSet := range journal.ChangeSets {
		if changeSet.Error != nil {
			result = append(result, *changeSet.Error)
		}
		for _, operation := range changeSet.Operations {
			if operation.Error != nil {
				result = append(result, *operation.Error)
			}
		}
	}
	for _, attempt := range journal.RollbackAttempts {
		result = append(result, attempt.Errors...)
	}
	return result
}

func containsJournalError(errors []model.JournalError, candidate model.JournalError) bool {
	for _, journalError := range errors {
		if reflect.DeepEqual(journalError, candidate) {
			return true
		}
	}
	return false
}

func transitionError(runID, message string) error {
	return wrap(CodeInvalidTransition, "validate transition", runID, fmt.Errorf("%s", message))
}
