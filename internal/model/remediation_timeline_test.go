package model

import (
	"strings"
	"testing"
	"time"
)

func TestRemediationTimelineRejectsCausalBypasses(t *testing.T) {
	tests := []struct {
		name      string
		journal   func() RemediationJournal
		wantError string
	}{
		{
			name: "approval before run start",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.ChangeSets[0].Approval.ApprovedAt = value.StartedAt.Add(-time.Second)
				return value
			},
			wantError: "approval precedes journal start",
		},
		{
			name: "preparation before approval",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.ChangeSets[0].Approval.ApprovedAt = value.ChangeSets[0].PreparedAt.Add(time.Second)
				return value
			},
			wantError: "preparation precedes approval",
		},
		{
			name: "operation intent before preparation",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				intentAt := value.ChangeSets[0].PreparedAt.Add(-time.Second)
				value.ChangeSets[0].Operations[0].ApplyIntentAt = &intentAt
				return value
			},
			wantError: "apply intent precedes preparation",
		},
		{
			name: "change set completion before operation completion",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				appliedAt := value.ChangeSets[0].AppliedAt.Add(time.Second)
				value.ChangeSets[0].Operations[0].AppliedAt = &appliedAt
				return value
			},
			wantError: "apply completion precedes operation",
		},
		{
			name: "verification before change set apply completion",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				verifiedAt := value.ChangeSets[0].AppliedAt.Add(-time.Second)
				value.ChangeSets[0].VerifiedAt = &verifiedAt
				return value
			},
			wantError: "verification completion precedes apply completion",
		},
		{
			name: "rollback intent before covering attempt",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				intentAt := *value.ChangeSets[0].Operations[0].RollbackIntentAt
				value.RollbackAttempts[0].StartedAt = intentAt.Add(time.Second)
				return value
			},
			wantError: "rollback intent is not within a covering rollback attempt",
		},
		{
			name: "rollback intent after covering attempt completion",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				intentAt := *value.ChangeSets[0].Operations[0].RollbackIntentAt
				startedAt := intentAt.Add(-2 * time.Second)
				completedAt := intentAt.Add(-time.Second)
				value.RollbackAttempts[0].StartedAt = startedAt
				value.RollbackAttempts[0].CompletedAt = &completedAt
				return value
			},
			wantError: "rollback intent is not within a covering rollback attempt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.journal().Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRemediationTimelineAllowsIncompleteRecoveryPrefix(t *testing.T) {
	value := journalContractRecoveryIntent()
	if err := value.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRollbackAttemptRejectsRegressedCompletionTime(t *testing.T) {
	attempt := journalContractIncompleteAttempt("attempt-regressed")
	completedAt := attempt.StartedAt.Add(-time.Nanosecond)
	attempt.CompletedAt = &completedAt
	attempt.Outcome = RollbackFailed

	err := attempt.Validate()
	if err == nil || !strings.Contains(err.Error(), "completion precedes start") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRollbackAttemptRejectsErrorAfterCompletion(t *testing.T) {
	attempt := journalContractIncompleteAttempt("attempt-late-error")
	completedAt := attempt.StartedAt.Add(time.Second)
	attempt.CompletedAt = &completedAt
	attempt.Outcome = RollbackFailed
	attempt.Errors = []JournalError{*journalContractError("rollback", completedAt.Add(time.Nanosecond))}

	err := attempt.Validate()
	if err == nil || !strings.Contains(err.Error(), "error occurs after completion") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRemediationTimelineRejectsOverlappingRollbackAttempts(t *testing.T) {
	value := journalContractRolledBack()
	first := value.RollbackAttempts[0]
	second := first
	second.ID = "attempt-overlap"
	second.StartedAt = first.CompletedAt.Add(-time.Nanosecond)
	secondCompletedAt := first.CompletedAt.Add(time.Nanosecond)
	second.CompletedAt = &secondCompletedAt
	value.RollbackAttempts = []RollbackAttempt{first, second}
	value.UpdatedAt = secondCompletedAt.Add(time.Nanosecond)

	err := value.Validate()
	if err == nil || !strings.Contains(err.Error(), "overlaps previous rollback attempt") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRemediationTimelineRejectsRegressedJournalErrors(t *testing.T) {
	tests := []struct {
		name      string
		journal   func() RemediationJournal
		wantError string
	}{
		{
			name: "top-level error before run start",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.Error = journalContractError("verification", value.StartedAt.Add(-time.Nanosecond))
				return value
			},
			wantError: "precedes journal start",
		},
		{
			name: "operation error before apply intent",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				operation := &value.ChangeSets[0].Operations[0]
				operation.Error = journalContractError("apply", operation.ApplyIntentAt.Add(-time.Nanosecond))
				return value
			},
			wantError: "precedes operation apply intent",
		},
		{
			name: "operation rollback error before rollback intent",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				operation := &value.ChangeSets[0].Operations[0]
				operation.Error = journalContractError("rollback", operation.RollbackIntentAt.Add(-time.Nanosecond))
				return value
			},
			wantError: "precedes operation rollback intent",
		},
		{
			name: "rollback error before attempt start",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				attempt := &value.RollbackAttempts[0]
				attempt.Errors = append(attempt.Errors, *journalContractError("rollback", attempt.StartedAt.Add(-time.Nanosecond)))
				return value
			},
			wantError: "precedes rollback attempt",
		},
		{
			name: "updated-at before nested error",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				occurredAt := value.UpdatedAt.Add(time.Nanosecond)
				value.Error = journalContractError("verification", occurredAt)
				return value
			},
			wantError: "updated_at precedes a durable event",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.journal().Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestJournalErrorReferencesMatchTheirScope(t *testing.T) {
	tests := []struct {
		name      string
		journal   func() RemediationJournal
		wantError string
	}{
		{
			name: "top-level error rejects unknown change set",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.Error = journalContractError("verification", value.UpdatedAt)
				value.Error.ChangeSetID = "missing-change"
				return value
			},
			wantError: "references unknown change set",
		},
		{
			name: "top-level error rejects operation without change set",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.Error = journalContractError("verification", value.UpdatedAt)
				value.Error.OperationID = value.ChangeSets[0].Operations[0].ID
				return value
			},
			wantError: "references an operation without a change set",
		},
		{
			name: "top-level error rejects unknown operation",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.Error = journalContractError("verification", value.UpdatedAt)
				value.Error.ChangeSetID = value.ChangeSets[0].ID
				value.Error.OperationID = "missing-operation"
				return value
			},
			wantError: "references unknown operation",
		},
		{
			name: "change-set error rejects different change set",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.ChangeSets[0].Error = journalContractError("verification", value.UpdatedAt)
				value.ChangeSets[0].Error.ChangeSetID = "different-change"
				return value
			},
			wantError: "references different change set",
		},
		{
			name: "change-set error rejects unknown operation",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.ChangeSets[0].Error = journalContractError("verification", value.UpdatedAt)
				value.ChangeSets[0].Error.OperationID = "missing-operation"
				return value
			},
			wantError: "references unknown operation",
		},
		{
			name: "operation error rejects different change set",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				operation := &value.ChangeSets[0].Operations[0]
				operation.Error = journalContractError("verification", value.UpdatedAt)
				operation.Error.ChangeSetID = "different-change"
				return value
			},
			wantError: "references different change set",
		},
		{
			name: "operation error rejects different operation",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				operation := &value.ChangeSets[0].Operations[0]
				operation.Error = journalContractError("verification", value.UpdatedAt)
				operation.Error.OperationID = "different-operation"
				return value
			},
			wantError: "references different operation",
		},
		{
			name: "rollback attempt error rejects unknown change set",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				journalError := journalContractError("rollback", value.RollbackAttempts[0].StartedAt)
				journalError.ChangeSetID = "missing-change"
				value.RollbackAttempts[0].Errors = append(value.RollbackAttempts[0].Errors, *journalError)
				return value
			},
			wantError: "references unknown change set",
		},
		{
			name: "rollback attempt error rejects change set outside attempt scope",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				second := journalContractBase().ChangeSets[0]
				second.ID = "change-2"
				second.Sequence = 2
				value.ChangeSets = append(value.ChangeSets, second)
				value.ConflictGraph.Nodes = append(value.ConflictGraph.Nodes, second.ID)
				journalError := journalContractError("apply", value.RollbackAttempts[0].StartedAt)
				journalError.ChangeSetID = second.ID
				value.RollbackAttempts[0].Errors = append(value.RollbackAttempts[0].Errors, *journalError)
				return value
			},
			wantError: "outside its scope",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.journal().Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestLatestEventTimeIncludesJournalErrors(t *testing.T) {
	value := journalContractCompleted()
	occurredAt := value.UpdatedAt.Add(time.Hour)
	value.RollbackAttempts = []RollbackAttempt{{
		ID:                 "attempt-errors",
		Scope:              RollbackItem,
		Trigger:            RollbackCrashRecovery,
		ExpandedChangeSets: []string{value.ChangeSets[0].ID},
		Outcome:            RollbackFailed,
		StartedAt:          value.UpdatedAt,
		CompletedAt:        &value.UpdatedAt,
		Errors:             []JournalError{*journalContractError("apply", occurredAt)},
	}}

	if got := value.LatestEventTime(); !got.Equal(occurredAt) {
		t.Fatalf("LatestEventTime() = %s, want %s", got, occurredAt)
	}
}
