package journal

import (
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestChangeSetTransitionPreservesDurableTimestamps(t *testing.T) {
	base := time.Date(2026, time.July, 31, 1, 0, 0, 0, time.UTC)
	markers := []struct {
		name string
		set  func(*model.ChangeSet, *time.Time)
	}{
		{name: "prepared_at", set: func(value *model.ChangeSet, marker *time.Time) { value.PreparedAt = marker }},
		{name: "applied_at", set: func(value *model.ChangeSet, marker *time.Time) { value.AppliedAt = marker }},
		{name: "verified_at", set: func(value *model.ChangeSet, marker *time.Time) { value.VerifiedAt = marker }},
		{name: "rolled_back_at", set: func(value *model.ChangeSet, marker *time.Time) { value.RolledBackAt = marker }},
	}

	for _, marker := range markers {
		t.Run(marker.name+" is immutable", func(t *testing.T) {
			previous := model.ChangeSet{ID: "change-a", State: model.ChangePrepared}
			next := previous
			changed := base.Add(time.Second)
			marker.set(&previous, &base)
			marker.set(&next, &changed)

			err := validateChangeSetTransition("run-a", &previous, &next)
			if err == nil || !strings.Contains(err.Error(), marker.name+" is immutable") {
				t.Fatalf("validateChangeSetTransition() error = %v", err)
			}
		})

		t.Run(marker.name+" can be initialized", func(t *testing.T) {
			previous := model.ChangeSet{ID: "change-a", State: model.ChangePrepared}
			next := previous
			marker.set(&next, &base)

			if err := validateChangeSetTransition("run-a", &previous, &next); err != nil {
				t.Fatalf("validateChangeSetTransition() error = %v", err)
			}
		})
	}
}

func TestChangeSetTransitionPreservesApprovalTimestamp(t *testing.T) {
	approvedAt := time.Date(2026, time.July, 31, 1, 0, 0, 0, time.UTC)
	changedAt := approvedAt.Add(time.Second)
	previous := model.ChangeSet{
		ID:       "change-a",
		State:    model.ChangePlanned,
		Approval: &model.Approval{Source: "test", PlanDigest: strings.Repeat("a", 64), ApprovedAt: approvedAt},
	}
	next := previous
	approval := *previous.Approval
	approval.ApprovedAt = changedAt
	next.Approval = &approval

	err := validateChangeSetTransition("run-a", &previous, &next)
	if err == nil || !strings.Contains(err.Error(), "approval is immutable") {
		t.Fatalf("validateChangeSetTransition() error = %v", err)
	}
}

func TestOperationTransitionPreservesDurableTimestamps(t *testing.T) {
	base := time.Date(2026, time.July, 31, 1, 0, 0, 0, time.UTC)
	markers := []struct {
		name string
		set  func(*model.OperationRecord, *time.Time)
	}{
		{name: "apply_intent_at", set: func(value *model.OperationRecord, marker *time.Time) { value.ApplyIntentAt = marker }},
		{name: "applied_at", set: func(value *model.OperationRecord, marker *time.Time) { value.AppliedAt = marker }},
		{name: "rollback_intent_at", set: func(value *model.OperationRecord, marker *time.Time) { value.RollbackIntentAt = marker }},
		{name: "rolled_back_at", set: func(value *model.OperationRecord, marker *time.Time) { value.RolledBackAt = marker }},
	}

	for _, marker := range markers {
		t.Run(marker.name+" is immutable", func(t *testing.T) {
			previous := model.OperationRecord{ID: "operation-a", State: model.OperationApplied}
			next := previous
			changed := base.Add(time.Second)
			marker.set(&previous, &base)
			marker.set(&next, &changed)

			err := validateOperationTransition("run-a", "change-a", &previous, &next)
			if err == nil || !strings.Contains(err.Error(), marker.name+" is immutable") {
				t.Fatalf("validateOperationTransition() error = %v", err)
			}
		})

		t.Run(marker.name+" can be initialized from zero", func(t *testing.T) {
			zero := time.Time{}
			previous := model.OperationRecord{ID: "operation-a", State: model.OperationApplied}
			next := previous
			marker.set(&previous, &zero)
			marker.set(&next, &base)

			if err := validateOperationTransition("run-a", "change-a", &previous, &next); err != nil {
				t.Fatalf("validateOperationTransition() error = %v", err)
			}
		})
	}
}

func TestRollbackAttemptTransitionPreservesCompletionTime(t *testing.T) {
	startedAt := time.Date(2026, time.July, 31, 1, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Second)
	changedAt := completedAt.Add(time.Second)
	previous := []model.RollbackAttempt{{
		ID:                 "attempt-a",
		Scope:              model.RollbackItem,
		Trigger:            model.RollbackUserRequest,
		ExpandedChangeSets: []string{"change-a"},
		Outcome:            model.RollbackSucceeded,
		StartedAt:          startedAt,
		CompletedAt:        &completedAt,
	}}
	next := append([]model.RollbackAttempt(nil), previous...)
	next[0].CompletedAt = &changedAt

	err := validateAttemptHistory("run-a", time.Time{}, previous, next)
	if err == nil || !strings.Contains(err.Error(), "completed_at is immutable") {
		t.Fatalf("validateAttemptHistory() error = %v", err)
	}
}

func TestRollbackAttemptTransitionAllowsCompletion(t *testing.T) {
	startedAt := time.Date(2026, time.July, 31, 1, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Second)
	previous := []model.RollbackAttempt{{
		ID:                 "attempt-a",
		Scope:              model.RollbackItem,
		Trigger:            model.RollbackUserRequest,
		ExpandedChangeSets: []string{"change-a"},
		StartedAt:          startedAt,
	}}
	next := append([]model.RollbackAttempt(nil), previous...)
	next[0].Outcome = model.RollbackSucceeded
	next[0].CompletedAt = &completedAt

	if err := validateAttemptHistory("run-a", time.Time{}, previous, next); err != nil {
		t.Fatalf("validateAttemptHistory() error = %v", err)
	}
}

func TestRunTransitionPreservesStartTime(t *testing.T) {
	previous := testApprovedJournal(t, testInitialJournal(t))
	next := previous
	next.Revision++
	next.StartedAt = previous.StartedAt.Add(-time.Nanosecond)
	next.UpdatedAt = previous.UpdatedAt.Add(time.Nanosecond)

	err := ValidateTransition(&previous, &next)
	if err == nil || !strings.Contains(err.Error(), "start time are immutable") {
		t.Fatalf("ValidateTransition() error = %v", err)
	}
}

func TestJournalErrorTransitionRequiresNewLogicalEvent(t *testing.T) {
	previous := testInitialJournal(t)
	next := previous
	next.Revision++
	occurredAt := previous.LatestEventTime()
	next.Error = &model.JournalError{
		Code:       model.JournalErrorApplyFailed,
		Phase:      "apply",
		Message:    "apply failed",
		OccurredAt: occurredAt,
	}
	next.UpdatedAt = occurredAt.Add(time.Nanosecond)

	err := ValidateTransition(&previous, &next)
	if err == nil || !strings.Contains(err.Error(), "must occur after the previous durable event") {
		t.Fatalf("ValidateTransition() error = %v", err)
	}
}

func TestJournalErrorTransitionAllowsReplacementAndHistoricalCopy(t *testing.T) {
	base := testInitialJournal(t)
	historical := model.JournalError{
		Code:       model.JournalErrorApplyFailed,
		Phase:      "apply",
		Message:    "apply failed",
		OccurredAt: base.UpdatedAt,
	}
	base.Error = &historical

	t.Run("replace current error with a later event", func(t *testing.T) {
		next := base
		next.Revision++
		replacement := historical
		replacement.Code = model.JournalErrorVerificationFailed
		replacement.Phase = "verification"
		replacement.Message = "verification failed"
		replacement.OccurredAt = base.LatestEventTime().Add(time.Nanosecond)
		next.Error = &replacement
		next.UpdatedAt = replacement.OccurredAt.Add(time.Nanosecond)

		if err := ValidateTransition(&base, &next); err != nil {
			t.Fatalf("ValidateTransition() error = %v", err)
		}
	})

	t.Run("copy historical error into scoped status", func(t *testing.T) {
		next := base
		next.Revision++
		next.Error = nil
		next.ChangeSets[0].Error = &historical
		next.UpdatedAt = base.UpdatedAt.Add(time.Nanosecond)

		if err := ValidateTransition(&base, &next); err != nil {
			t.Fatalf("ValidateTransition() error = %v", err)
		}
	})
}

func TestStoreUpdateAdvancesUpdatedAtPastMutationEvents(t *testing.T) {
	value := testInitialJournal(t)
	approvedAt := value.StartedAt.Add(12 * time.Hour)
	value.State = model.RunApproved
	for index := range value.ChangeSets {
		value.ChangeSets[index].Approval = &model.Approval{
			Source:     "timestamp-test",
			PlanDigest: value.PlanDigest,
			ApprovedAt: approvedAt,
		}
	}

	updatedAt, err := updatedAtAfterJournalEvents(value.StartedAt.Add(-time.Hour), &value)
	if err != nil {
		t.Fatalf("updatedAtAfterJournalEvents() error = %v", err)
	}
	if !updatedAt.After(approvedAt) {
		t.Fatalf("updatedAt = %s, want after mutation event %s", updatedAt, approvedAt)
	}
	value.UpdatedAt = updatedAt
	if err := value.Validate(); err != nil {
		t.Fatalf("journal Validate() error = %v", err)
	}
}
