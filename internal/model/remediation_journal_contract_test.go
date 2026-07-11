package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRunStateTransitionContract(t *testing.T) {
	states := []RunState{
		RunPlanned,
		RunApproved,
		RunApplying,
		RunVerifying,
		RunCompleted,
		RunRollingBack,
		RunRolledBack,
		RunCompletedWithRollbacks,
		RunCanceling,
		RunCanceled,
		RunCancelFailed,
		RunFailed,
		RunRollbackFailed,
		RunPartiallyRolledBack,
		RunRecoveryRequired,
	}
	allowed := map[RunState][]RunState{
		RunPlanned:                {RunApproved, RunCanceling, RunFailed},
		RunApproved:               {RunApplying, RunCanceling, RunFailed},
		RunApplying:               {RunVerifying, RunRollingBack, RunFailed, RunRecoveryRequired},
		RunVerifying:              {RunCompleted, RunRollingBack, RunFailed, RunRecoveryRequired},
		RunCompleted:              {RunRollingBack},
		RunRollingBack:            {RunRolledBack, RunCompletedWithRollbacks, RunFailed, RunRollbackFailed, RunPartiallyRolledBack, RunRecoveryRequired},
		RunCompletedWithRollbacks: {RunRollingBack},
		RunCanceling:              {RunCanceled, RunCancelFailed},
		RunCancelFailed:           {RunCanceling},
		RunFailed:                 {RunRollingBack},
		RunRollbackFailed:         {RunRollingBack, RunFailed},
		RunPartiallyRolledBack:    {RunRollingBack, RunFailed},
		RunRecoveryRequired:       {RunRollingBack, RunFailed},
	}
	terminal := map[RunState]bool{
		RunCompleted:              true,
		RunRolledBack:             true,
		RunCompletedWithRollbacks: true,
		RunCanceled:               true,
		RunCancelFailed:           true,
		RunFailed:                 true,
		RunRollbackFailed:         true,
		RunPartiallyRolledBack:    true,
		RunRecoveryRequired:       true,
	}
	operatorAction := map[RunState]bool{
		RunCancelFailed:        true,
		RunRollbackFailed:      true,
		RunPartiallyRolledBack: true,
		RunRecoveryRequired:    true,
	}

	for _, from := range states {
		if !from.Valid() {
			t.Fatalf("%q.Valid() = false", from)
		}
		for _, to := range states {
			want := from == to || slices.Contains(allowed[from], to)
			if got := from.CanTransitionTo(to); got != want {
				t.Errorf("%s.CanTransitionTo(%s) = %t, want %t", from, to, got, want)
			}
		}
		if got := from.Terminal(); got != terminal[from] {
			t.Errorf("%s.Terminal() = %t, want %t", from, got, terminal[from])
		}
		if got := from.NeedsOperatorAction(); got != operatorAction[from] {
			t.Errorf("%s.NeedsOperatorAction() = %t, want %t", from, got, operatorAction[from])
		}
	}

	invalid := RunState("invalid")
	if invalid.Valid() || invalid.CanTransitionTo(invalid) || invalid.Terminal() || invalid.NeedsOperatorAction() {
		t.Fatal("invalid run state was accepted")
	}
}

func TestChangeSetStateTransitionContract(t *testing.T) {
	states := []ChangeSetState{
		ChangePlanned,
		ChangePrepared,
		ChangeApplying,
		ChangeApplied,
		ChangeVerifying,
		ChangeVerified,
		ChangeApplyFailed,
		ChangeRollingBack,
		ChangeRolledBack,
		ChangeRollbackBlocked,
		ChangeRollbackFailed,
		ChangePartiallyRolledBack,
		ChangeRecoveryRequired,
	}
	allowed := map[ChangeSetState][]ChangeSetState{
		ChangePlanned:             {ChangePrepared, ChangeApplyFailed},
		ChangePrepared:            {ChangeApplying, ChangeApplyFailed},
		ChangeApplying:            {ChangeApplied, ChangeApplyFailed, ChangeRollingBack, ChangeRecoveryRequired},
		ChangeApplied:             {ChangeVerifying, ChangeRollingBack, ChangeRollbackBlocked, ChangeRecoveryRequired},
		ChangeVerifying:           {ChangeVerified, ChangeRollingBack, ChangeRecoveryRequired},
		ChangeVerified:            {ChangeRollingBack, ChangeRollbackBlocked, ChangeRecoveryRequired},
		ChangeApplyFailed:         {ChangeRollingBack, ChangeApplyFailed},
		ChangeRollingBack:         {ChangeApplyFailed, ChangeRolledBack, ChangeRollbackBlocked, ChangeRollbackFailed, ChangePartiallyRolledBack, ChangeRecoveryRequired},
		ChangeRolledBack:          {ChangeRecoveryRequired},
		ChangeRollbackBlocked:     {ChangeRollingBack, ChangeApplyFailed},
		ChangeRollbackFailed:      {ChangeRollingBack, ChangeApplyFailed},
		ChangePartiallyRolledBack: {ChangeRollingBack, ChangeApplyFailed},
		ChangeRecoveryRequired:    {ChangeRollingBack, ChangeApplyFailed},
	}
	operatorAction := map[ChangeSetState]bool{
		ChangeRollbackBlocked:     true,
		ChangeRollbackFailed:      true,
		ChangePartiallyRolledBack: true,
		ChangeRecoveryRequired:    true,
	}

	for _, from := range states {
		if !from.Valid() {
			t.Fatalf("%q.Valid() = false", from)
		}
		for _, to := range states {
			want := from == to || slices.Contains(allowed[from], to)
			if got := from.CanTransitionTo(to); got != want {
				t.Errorf("%s.CanTransitionTo(%s) = %t, want %t", from, to, got, want)
			}
		}
		if got := from.NeedsOperatorAction(); got != operatorAction[from] {
			t.Errorf("%s.NeedsOperatorAction() = %t, want %t", from, got, operatorAction[from])
		}
	}

	invalid := ChangeSetState("invalid")
	if invalid.Valid() || invalid.CanTransitionTo(invalid) || invalid.NeedsOperatorAction() {
		t.Fatal("invalid change-set state was accepted")
	}
}

func TestOperationStateTransitionContract(t *testing.T) {
	states := []OperationState{
		OperationPlanned,
		OperationApplyIntentDurable,
		OperationApplied,
		OperationVerified,
		OperationRollbackIntentDurable,
		OperationRolledBack,
		OperationFailed,
		OperationAmbiguous,
	}
	allowed := map[OperationState][]OperationState{
		OperationPlanned:               {OperationApplyIntentDurable, OperationFailed},
		OperationApplyIntentDurable:    {OperationApplied, OperationFailed, OperationAmbiguous, OperationRollbackIntentDurable},
		OperationApplied:               {OperationVerified, OperationRollbackIntentDurable, OperationAmbiguous},
		OperationVerified:              {OperationRollbackIntentDurable},
		OperationFailed:                {OperationRollbackIntentDurable},
		OperationAmbiguous:             {OperationApplied, OperationRolledBack, OperationFailed},
		OperationRollbackIntentDurable: {OperationRolledBack, OperationFailed, OperationAmbiguous},
	}

	for _, from := range states {
		if !from.Valid() {
			t.Fatalf("%q.Valid() = false", from)
		}
		for _, to := range states {
			want := from == to || slices.Contains(allowed[from], to)
			if got := from.CanTransitionTo(to); got != want {
				t.Errorf("%s.CanTransitionTo(%s) = %t, want %t", from, to, got, want)
			}
		}
	}

	invalid := OperationState("invalid")
	if invalid.Valid() || invalid.CanTransitionTo(invalid) {
		t.Fatal("invalid operation state was accepted")
	}
}

func TestRemediationJournalTerminalInvariantTable(t *testing.T) {
	tests := []struct {
		name      string
		journal   func() RemediationJournal
		wantError string
	}{
		{
			name:    "completed accepts only verified work",
			journal: journalContractCompleted,
		},
		{
			name: "completed rejects planned work",
			journal: func() RemediationJournal {
				journal := journalContractBase()
				journal.State = RunCompleted
				return journal
			},
			wantError: "cannot contain change set",
		},
		{
			name:    "rolled back accepts durable rollback and successful attempt",
			journal: journalContractRolledBack,
		},
		{
			name: "rolled back rejects verified work",
			journal: func() RemediationJournal {
				journal := journalContractCompleted()
				journal.State = RunRolledBack
				return journal
			},
			wantError: "cannot contain change set",
		},
		{
			name: "rolled back rejects missing successful attempt",
			journal: func() RemediationJournal {
				journal := journalContractRolledBack()
				journal.RollbackAttempts = nil
				return journal
			},
			wantError: "no completed successful rollback attempt",
		},
		{
			name: "canceled accepts untouched work",
			journal: func() RemediationJournal {
				journal := journalContractBase()
				journal.State = RunCanceled
				return journal
			},
		},
		{
			name: "canceled rejects verified work",
			journal: func() RemediationJournal {
				journal := journalContractCompleted()
				journal.State = RunCanceled
				return journal
			},
			wantError: "cannot contain change set",
		},
		{
			name: "failed accepts untouched work",
			journal: func() RemediationJournal {
				journal := journalContractBase()
				journal.State = RunFailed
				return journal
			},
		},
		{
			name:    "failed accepts exact durable no effect",
			journal: journalContractNoEffectFailure,
		},
		{
			name: "failed rejects recovery work",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				journal.State = RunFailed
				journal.UnresolvedChangeSets = nil
				return journal
			},
			wantError: "cannot contain change set",
		},
		{
			name:    "recovery required accepts durable intent and known unresolved work",
			journal: journalContractRecoveryIntent,
		},
		{
			name: "recovery required rejects unknown unresolved work",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				journal.UnresolvedChangeSets = []string{"missing-change"}
				return journal
			},
			wantError: "marks unknown change set",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.journal().Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() error = nil, want substring %q", test.wantError)
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %q, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRemediationJournalUnresolvedChangeSetContract(t *testing.T) {
	tests := []struct {
		name      string
		journal   func() RemediationJournal
		wantError string
	}{
		{
			name:    "known unresolved id is allowed for recovery",
			journal: journalContractRecoveryIntent,
		},
		{
			name: "unknown unresolved id is rejected",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				journal.UnresolvedChangeSets = append(journal.UnresolvedChangeSets, "missing-change")
				return journal
			},
			wantError: "marks unknown change set",
		},
		{
			name: "duplicate unresolved id is rejected",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				journal.UnresolvedChangeSets = []string{"change-1", "change-1"}
				return journal
			},
			wantError: "repeats unresolved change set",
		},
		{
			name: "normal completed state rejects known unresolved id",
			journal: func() RemediationJournal {
				journal := journalContractCompleted()
				journal.UnresolvedChangeSets = []string{"change-1"}
				return journal
			},
			wantError: "cannot contain unresolved changes",
		},
		{
			name: "normal failed state rejects known unresolved id",
			journal: func() RemediationJournal {
				journal := journalContractBase()
				journal.State = RunFailed
				journal.UnresolvedChangeSets = []string{"change-1"}
				return journal
			},
			wantError: "cannot contain unresolved changes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.journal().Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRemediationJournalIncompleteRollbackAttemptContract(t *testing.T) {
	tests := []struct {
		name      string
		journal   func() RemediationJournal
		wantError string
	}{
		{
			name: "recovery allows one final incomplete attempt",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				journal.RollbackAttempts = []RollbackAttempt{journalContractIncompleteAttempt("attempt-1")}
				return journal
			},
		},
		{
			name: "recovery allows completed attempts before final incomplete attempt",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				completed := journalContractCompletedAttempt("attempt-1", RollbackFailed)
				journal.RollbackAttempts = []RollbackAttempt{completed, journalContractIncompleteAttempt("attempt-2")}
				return journal
			},
		},
		{
			name: "recovery rejects a non-final incomplete attempt",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				completed := journalContractCompletedAttempt("attempt-2", RollbackFailed)
				journal.RollbackAttempts = []RollbackAttempt{journalContractIncompleteAttempt("attempt-1"), completed}
				return journal
			},
			wantError: "only the final rollback attempt may be incomplete",
		},
		{
			name: "completed rejects an incomplete attempt",
			journal: func() RemediationJournal {
				journal := journalContractCompleted()
				journal.RollbackAttempts = []RollbackAttempt{journalContractIncompleteAttempt("attempt-1")}
				return journal
			},
			wantError: "cannot contain incomplete rollback attempt",
		},
		{
			name: "failed rejects an incomplete attempt",
			journal: func() RemediationJournal {
				journal := journalContractBase()
				journal.State = RunFailed
				journal.RollbackAttempts = []RollbackAttempt{journalContractIncompleteAttempt("attempt-1")}
				return journal
			},
			wantError: "cannot contain incomplete rollback attempt",
		},
		{
			name: "outcome before completion is rejected",
			journal: func() RemediationJournal {
				journal := journalContractRecoveryIntent()
				attempt := journalContractIncompleteAttempt("attempt-1")
				attempt.Outcome = RollbackSucceeded
				journal.RollbackAttempts = []RollbackAttempt{attempt}
				return journal
			},
			wantError: "outcome before completion",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.journal().Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRollbackAttemptExpandedChangeSetContract(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*RollbackAttempt)
		wantError string
	}{
		{name: "one expanded change set is valid"},
		{
			name: "nil expanded change sets are rejected",
			mutate: func(attempt *RollbackAttempt) {
				attempt.ExpandedChangeSets = nil
			},
			wantError: "has no expanded change set",
		},
		{
			name: "empty expanded change sets are rejected",
			mutate: func(attempt *RollbackAttempt) {
				attempt.ExpandedChangeSets = []string{}
			},
			wantError: "has no expanded change set",
		},
		{
			name: "blank expanded id is rejected",
			mutate: func(attempt *RollbackAttempt) {
				attempt.ExpandedChangeSets = []string{" "}
			},
			wantError: "empty expanded change set",
		},
		{
			name: "duplicate expanded id is rejected",
			mutate: func(attempt *RollbackAttempt) {
				attempt.ExpandedChangeSets = []string{"change-1", "change-1"}
			},
			wantError: "repeats expanded change set",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attempt := journalContractIncompleteAttempt("attempt-1")
			if test.mutate != nil {
				test.mutate(&attempt)
			}
			err := attempt.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestOperationApplyIntentDurableMarkerContract(t *testing.T) {
	markerTime := journalContractTime().Add(4 * time.Minute)
	tests := []struct {
		name      string
		mutate    func(*OperationRecord)
		wantError string
	}{
		{name: "intent with before backup and timestamp is valid"},
		{
			name: "missing durable before is rejected",
			mutate: func(operation *OperationRecord) {
				operation.Before = ResourceSnapshot{}
			},
			wantError: "has no durable before state",
		},
		{
			name: "missing backup is rejected",
			mutate: func(operation *OperationRecord) {
				operation.Backup = nil
			},
			wantError: "has no durable apply intent or backup",
		},
		{
			name: "missing intent timestamp is rejected",
			mutate: func(operation *OperationRecord) {
				operation.ApplyIntentAt = nil
			},
			wantError: "has no durable apply intent or backup",
		},
		{
			name: "apply completion marker is rejected",
			mutate: func(operation *OperationRecord) {
				operation.AppliedAt = &markerTime
			},
			wantError: "apply intent contains completion",
		},
		{
			name: "after observation marker is rejected",
			mutate: func(operation *OperationRecord) {
				observed := operation.Desired
				operation.ObservedAfter = &observed
			},
			wantError: "apply intent contains completion",
		},
		{
			name: "rollback intent marker is rejected",
			mutate: func(operation *OperationRecord) {
				operation.RollbackIntentAt = &markerTime
			},
			wantError: "apply intent contains completion",
		},
		{
			name: "rollback observation marker is rejected",
			mutate: func(operation *OperationRecord) {
				observed := operation.Before
				operation.ObservedRollback = &observed
			},
			wantError: "apply intent contains completion",
		},
		{
			name: "rollback completion marker is rejected",
			mutate: func(operation *OperationRecord) {
				operation.RolledBackAt = &markerTime
			},
			wantError: "apply intent contains completion",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := journalContractIntentOperation()
			if test.mutate != nil {
				test.mutate(&operation)
			}
			err := operation.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestAppliedAndVerifiedOperationEvidenceContract(t *testing.T) {
	states := []OperationState{OperationApplied, OperationVerified}
	tests := []struct {
		name      string
		mutate    func(*OperationRecord)
		wantError string
	}{
		{name: "complete desired observation and apply time are valid"},
		{
			name: "missing observation is rejected",
			mutate: func(operation *OperationRecord) {
				operation.ObservedAfter = nil
			},
			wantError: "has no durable observed after state or apply completion time",
		},
		{
			name: "missing apply time is rejected",
			mutate: func(operation *OperationRecord) {
				operation.AppliedAt = nil
			},
			wantError: "has no durable observed after state or apply completion time",
		},
		{
			name: "zero apply time is rejected",
			mutate: func(operation *OperationRecord) {
				zero := time.Time{}
				operation.AppliedAt = &zero
			},
			wantError: "has no durable observed after state or apply completion time",
		},
		{
			name: "before observation is rejected even with desired fingerprint copied",
			mutate: func(operation *OperationRecord) {
				observed := operation.Before
				observed.Fingerprint = operation.Desired.Fingerprint
				operation.ObservedAfter = &observed
			},
			wantError: "does not exactly match its desired state",
		},
	}

	for _, state := range states {
		for _, test := range tests {
			t.Run(string(state)+"/"+test.name, func(t *testing.T) {
				operation := journalContractAppliedOperation(state)
				if test.mutate != nil {
					test.mutate(&operation)
				}
				err := operation.Validate()
				if test.wantError == "" {
					if err != nil {
						t.Fatalf("Validate() error = %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
				}
			})
		}
	}
}

func TestResourceSnapshotRequiresFullCanonicalIdentity(t *testing.T) {
	t.Run("exact snapshot compares every canonical field", func(t *testing.T) {
		left := journalContractBefore()
		right := journalContractBefore()
		right.Reference.AliasKeys = []string{"inode:11:22"}
		if exactResourceSnapshot(left, right) {
			t.Fatal("exactResourceSnapshot() accepted a different canonical alias set")
		}
	})

	t.Run("file path matches resource id", func(t *testing.T) {
		snapshot := journalContractBefore()
		snapshot.File.Path = "/etc/other"
		err := snapshot.Validate()
		if err == nil || !strings.Contains(err.Error(), "file snapshot path does not match its resource id") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("exact observation includes aliases", func(t *testing.T) {
		operation := journalContractAppliedOperation(OperationVerified)
		observed := *operation.ObservedAfter
		observed.Reference.AliasKeys = []string{"inode:11:22"}
		operation.ObservedAfter = &observed
		err := operation.Validate()
		if err == nil || !strings.Contains(err.Error(), "observed resource does not match its target") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("operation target includes aliases", func(t *testing.T) {
		operation := journalContractBase().ChangeSets[0].Operations[0]
		operation.Resource.AliasKeys = []string{"inode:11:22"}
		err := operation.Validate()
		if err == nil || !strings.Contains(err.Error(), "expected before resource does not match its target") {
			t.Fatalf("Validate() error = %v", err)
		}
	})
}

func TestOperationMarkerTimelineContract(t *testing.T) {
	t.Run("apply completion cannot precede intent", func(t *testing.T) {
		operation := journalContractAppliedOperation(OperationApplied)
		appliedAt := operation.ApplyIntentAt.Add(-time.Second)
		operation.AppliedAt = &appliedAt
		err := operation.Validate()
		if err == nil || !strings.Contains(err.Error(), "apply completion precedes its durable intent") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("rollback intent cannot precede apply intent", func(t *testing.T) {
		operation := journalContractAppliedOperation(OperationApplied)
		rollbackIntentAt := operation.ApplyIntentAt.Add(-time.Second)
		operation.RollbackIntentAt = &rollbackIntentAt
		err := operation.Validate()
		if err == nil || !strings.Contains(err.Error(), "rollback intent precedes the durable apply intent") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("rollback completion cannot precede intent", func(t *testing.T) {
		operation := journalContractRolledBack().ChangeSets[0].Operations[0]
		rolledBackAt := operation.RollbackIntentAt.Add(-time.Second)
		operation.RolledBackAt = &rolledBackAt
		err := operation.Validate()
		if err == nil || !strings.Contains(err.Error(), "rollback completion precedes its durable intent") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("completion marker requires its observation", func(t *testing.T) {
		operation := journalContractAppliedOperation(OperationAmbiguous)
		operation.ObservedAfter = nil
		err := operation.Validate()
		if err == nil || !strings.Contains(err.Error(), "apply completion requires its durable intent and observation") {
			t.Fatalf("Validate() error = %v", err)
		}
	})
}

func TestVerifiedChangeSetEvidenceContract(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*ChangeSet)
		wantError string
	}{
		{name: "complete desired after state and timestamps are valid"},
		{
			name: "missing prepared time is rejected",
			mutate: func(changeSet *ChangeSet) {
				changeSet.PreparedAt = nil
			},
			wantError: "has no preparation or apply completion time",
		},
		{
			name: "missing applied time is rejected",
			mutate: func(changeSet *ChangeSet) {
				changeSet.AppliedAt = nil
			},
			wantError: "has no preparation or apply completion time",
		},
		{
			name: "missing verified time is rejected",
			mutate: func(changeSet *ChangeSet) {
				changeSet.VerifiedAt = nil
			},
			wantError: "has no verification completion time",
		},
		{
			name: "missing after state is rejected",
			mutate: func(changeSet *ChangeSet) {
				changeSet.After = nil
			},
			wantError: "does not have a complete after state",
		},
		{
			name: "after state differing from desired is rejected",
			mutate: func(changeSet *ChangeSet) {
				after := changeSet.Before[0]
				after.Fingerprint = changeSet.After[0].Fingerprint
				changeSet.After = []ResourceSnapshot{after}
			},
			wantError: "does not match the final desired and observed state",
		},
		{
			name: "non-verified operation is rejected",
			mutate: func(changeSet *ChangeSet) {
				changeSet.Operations[0].State = OperationApplied
			},
			wantError: "contains non-verified operation",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := journalContractCompleted()
			changeSet := journal.ChangeSets[0]
			if test.mutate != nil {
				test.mutate(&changeSet)
			}
			err := changeSet.Validate(journal.PlanDigest)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRemediationJournalSchemaStateContract(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schemas", "remediation-journal.schema.json")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", schemaPath, err)
	}
	var schema any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("Unmarshal(schema) error = %v", err)
	}

	contractSubsets := []struct {
		name string
		want any
	}{
		{
			name: "normal terminals reject unresolved ids and incomplete attempts",
			want: map[string]any{
				"if": map[string]any{"properties": map[string]any{"state": map[string]any{"enum": []any{"completed", "rolled_back", "completed_with_rollbacks", "canceled", "failed"}}}},
				"then": map[string]any{"properties": map[string]any{
					"unresolved_change_sets": map[string]any{"maxItems": float64(0)},
					"rollback_attempts":      map[string]any{"items": map[string]any{"required": []any{"completed_at"}}},
				}},
			},
		},
		{
			name: "applied and verified operations require observation and apply time",
			want: map[string]any{
				"if":   map[string]any{"properties": map[string]any{"state": map[string]any{"enum": []any{"applied", "verified"}}}},
				"then": map[string]any{"required": []any{"observed_after", "applied_at"}},
			},
		},
		{
			name: "any apply completion marker requires intent and observation",
			want: map[string]any{
				"if":   map[string]any{"required": []any{"applied_at"}},
				"then": map[string]any{"required": []any{"apply_intent_at", "observed_after"}},
			},
		},
		{
			name: "any rollback completion marker requires observation",
			want: map[string]any{
				"if":   map[string]any{"required": []any{"rolled_back_at"}},
				"then": map[string]any{"required": []any{"observed_rollback"}},
			},
		},
		{
			name: "any rollback intent requires apply intent",
			want: map[string]any{
				"if":   map[string]any{"required": []any{"rollback_intent_at"}},
				"then": map[string]any{"required": []any{"apply_intent_at"}},
			},
		},
		{
			name: "durable apply intent excludes completion and rollback markers",
			want: map[string]any{
				"if": map[string]any{"properties": map[string]any{"state": map[string]any{"const": "apply_intent_durable"}}},
				"then": map[string]any{"not": map[string]any{"anyOf": []any{
					map[string]any{"required": []any{"applied_at"}},
					map[string]any{"required": []any{"observed_after"}},
					map[string]any{"required": []any{"rollback_intent_at"}},
					map[string]any{"required": []any{"observed_rollback"}},
					map[string]any{"required": []any{"rolled_back_at"}},
				}}},
			},
		},
		{
			name: "rolled back operation requires intent observation and completion time",
			want: map[string]any{
				"if":   map[string]any{"properties": map[string]any{"state": map[string]any{"const": "rolled_back"}}},
				"then": map[string]any{"required": []any{"observed_rollback", "rollback_intent_at", "rolled_back_at"}},
			},
		},
		{
			name: "rollback attempts require nonempty expanded change sets",
			want: map[string]any{
				"expanded_change_sets": map[string]any{"type": "array", "minItems": float64(1), "uniqueItems": true},
			},
		},
	}

	for _, contract := range contractSubsets {
		t.Run(contract.name, func(t *testing.T) {
			if !journalContractSchemaContains(schema, contract.want) {
				t.Fatalf("schema does not contain required contract subset: %#v", contract.want)
			}
		})
	}

	normalTerminalStates := journalContractSchemaNormalTerminals(t, schema)
	wantNormalTerminalStates := []string{"canceled", "completed", "completed_with_rollbacks", "failed", "rolled_back"}
	if !slices.Equal(normalTerminalStates, wantNormalTerminalStates) {
		t.Fatalf("normal terminal schema states = %v, want %v", normalTerminalStates, wantNormalTerminalStates)
	}
	if slices.Contains(normalTerminalStates, string(RunRecoveryRequired)) {
		t.Fatal("recovery_required must not receive normal-terminal constraints")
	}
}

func journalContractBase() RemediationJournal {
	startedAt := journalContractTime()
	resource := journalContractResource()
	before := journalContractBefore()
	desired := journalContractDesired()

	return RemediationJournal{
		SchemaVersion:   RemediationSchemaVersion,
		Revision:        1,
		RunID:           "run-contract-1",
		ScanRunID:       "scan-contract-1",
		ScanToolVersion: "1.0.0",
		ScanToolCommit:  "commit-1",
		RuleSetVersion:  "sha256:" + journalContractDigest("5"),
		Platform: PlatformInfo{
			OS:                 "linux",
			Family:             "rhel",
			ID:                 "rocky",
			VersionID:          "9.8",
			Architecture:       "amd64",
			ScanSupport:        ScanSupportTested,
			RemediationSupport: RemediationSupportVerified,
		},
		RemediationBuild: RemediationBuildIdentity{
			Version:          "1.0.0",
			Commit:           "commit-1",
			ExecutableSHA256: journalContractDigest("6"),
		},
		State:         RunPlanned,
		FailurePolicy: FailureRollbackItem,
		PlanDigest:    journalContractDigest("4"),
		Host: HostIdentity{
			MachineIDHash: journalContractDigest("7"),
			SystemRoot:    "/",
			RootDevice:    11,
			RootInode:     2,
			BootID:        "12345678-1234-1234-1234-123456789abc",
		},
		StartedAt: startedAt,
		UpdatedAt: startedAt,
		ChangeSets: []ChangeSet{
			{
				ID:     "change-1",
				RuleID: "U-19",
				RuleIdentity: RemediationRuleIdentity{
					ID:        "U-19",
					Title:     "hosts file permissions",
					Category:  CategoryFileDirectory,
					Severity:  SeverityHigh,
					Evaluator: "unix.file.hosts_permissions",
					Verification: Verification{
						State:        VerificationVerified,
						Environments: []string{"Rocky Linux 9.8 amd64"},
						VerifiedAt:   "2026-07-11T00:00:00Z",
					},
					BindingSources: []string{"rocky-linux-9.8-amd64"},
					Reference: Reference{
						Guide: "2026 test guide",
						Item:  "U-19",
						Pages: []int{1},
					},
				},
				RecipeIdentity: RemediationRecipeIdentity{
					ID:               "rocky-hosts-file-metadata",
					Selector:         PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
					DefinitionSHA256: journalContractDigest("8"),
				},
				Sequence:       1,
				Risk:           RiskSafe,
				State:          ChangePlanned,
				Resources:      []CanonicalResource{resource},
				DryRun:         "change file metadata",
				ExpectedImpact: "metadata only",
				Operations: []OperationRecord{
					{
						ID:               "operation-1",
						Sequence:         1,
						RollbackSequence: 1,
						Kind:             OperationFileMetadata,
						RecoveryMode:     RecoveryStateInferable,
						State:            OperationPlanned,
						Resource:         resource,
						ExpectedBefore:   before,
						Desired:          desired,
					},
				},
			},
		},
		ConflictGraph: ConflictGraph{
			Nodes: []string{"change-1"},
			Edges: []ConflictEdge{},
		},
	}
}

func journalContractCompleted() RemediationJournal {
	journal := journalContractBase()
	preparedAt := journal.StartedAt.Add(time.Minute)
	appliedAt := preparedAt.Add(time.Minute)
	verifiedAt := appliedAt.Add(time.Minute)
	changeSet := &journal.ChangeSets[0]
	changeSet.State = ChangeVerified
	changeSet.Before = []ResourceSnapshot{journalContractBefore()}
	changeSet.After = []ResourceSnapshot{journalContractDesired()}
	changeSet.PreparedAt = &preparedAt
	changeSet.AppliedAt = &appliedAt
	changeSet.VerifiedAt = &verifiedAt
	changeSet.Operations[0] = journalContractAppliedOperation(OperationVerified)
	journal.State = RunCompleted
	journal.UpdatedAt = verifiedAt
	return journal
}

func journalContractRolledBack() RemediationJournal {
	journal := journalContractBase()
	applyIntentAt := journal.StartedAt.Add(time.Minute)
	rollbackIntentAt := applyIntentAt.Add(time.Minute)
	rolledBackAt := rollbackIntentAt.Add(time.Minute)
	changeSet := &journal.ChangeSets[0]
	changeSet.State = ChangeRolledBack
	changeSet.Before = []ResourceSnapshot{journalContractBefore()}
	changeSet.RolledBackAt = &rolledBackAt
	operation := &changeSet.Operations[0]
	operation.State = OperationRolledBack
	operation.Before = journalContractBefore()
	operation.Backup = journalContractBackup()
	operation.ApplyIntentAt = &applyIntentAt
	operation.RollbackIntentAt = &rollbackIntentAt
	observedRollback := journalContractBefore()
	operation.ObservedRollback = &observedRollback
	operation.RolledBackAt = &rolledBackAt
	journal.State = RunRolledBack
	journal.UpdatedAt = rolledBackAt
	journal.RollbackAttempts = []RollbackAttempt{journalContractCompletedAttempt("attempt-1", RollbackSucceeded)}
	return journal
}

func journalContractNoEffectFailure() RemediationJournal {
	journal := journalContractBase()
	applyIntentAt := journal.StartedAt.Add(time.Minute)
	failedAt := applyIntentAt.Add(time.Minute)
	changeSet := &journal.ChangeSets[0]
	changeSet.State = ChangeApplyFailed
	operation := &changeSet.Operations[0]
	operation.State = OperationFailed
	operation.Before = journalContractBefore()
	operation.Backup = journalContractBackup()
	operation.ApplyIntentAt = &applyIntentAt
	observed := journalContractBefore()
	operation.ObservedAfter = &observed
	operation.Error = journalContractError("apply", failedAt)
	changeSet.Error = journalContractError("apply", failedAt)
	journal.Error = journalContractError("apply", failedAt)
	journal.State = RunFailed
	journal.UpdatedAt = failedAt
	return journal
}

func journalContractRecoveryIntent() RemediationJournal {
	journal := journalContractBase()
	intentAt := journal.StartedAt.Add(time.Minute)
	changeSet := &journal.ChangeSets[0]
	changeSet.State = ChangeRecoveryRequired
	changeSet.Before = []ResourceSnapshot{journalContractBefore()}
	changeSet.Operations[0] = journalContractIntentOperation()
	journal.State = RunRecoveryRequired
	journal.UpdatedAt = intentAt
	journal.UnresolvedChangeSets = []string{"change-1"}
	journal.Error = journalContractError("recover", intentAt)
	return journal
}

func journalContractIntentOperation() OperationRecord {
	operation := journalContractBase().ChangeSets[0].Operations[0]
	intentAt := journalContractTime().Add(time.Minute)
	operation.State = OperationApplyIntentDurable
	operation.Before = journalContractBefore()
	operation.Backup = journalContractBackup()
	operation.ApplyIntentAt = &intentAt
	return operation
}

func journalContractAppliedOperation(state OperationState) OperationRecord {
	operation := journalContractIntentOperation()
	appliedAt := journalContractTime().Add(2 * time.Minute)
	observed := journalContractDesired()
	operation.State = state
	operation.AppliedAt = &appliedAt
	operation.ObservedAfter = &observed
	return operation
}

func journalContractIncompleteAttempt(id string) RollbackAttempt {
	return RollbackAttempt{
		ID:                  id,
		Scope:               RollbackItem,
		Trigger:             RollbackCrashRecovery,
		RequestedChangeSets: []string{"change-1"},
		ExpandedChangeSets:  []string{"change-1"},
		CascadeApproved:     true,
		StartedAt:           journalContractTime().Add(2 * time.Minute),
	}
}

func journalContractCompletedAttempt(id string, outcome RollbackOutcome) RollbackAttempt {
	attempt := journalContractIncompleteAttempt(id)
	completedAt := attempt.StartedAt.Add(time.Minute)
	attempt.Outcome = outcome
	attempt.CompletedAt = &completedAt
	return attempt
}

func journalContractResource() CanonicalResource {
	return CanonicalResource{
		Reference: ResourceRef{Kind: ResourceFile, ID: "/etc/hosts"},
		Key:       "file:/etc/hosts",
	}
}

func journalContractBefore() ResourceSnapshot {
	return ResourceSnapshot{
		Reference:   journalContractResource(),
		Fingerprint: journalContractDigest("2"),
		File: &FileSnapshot{
			Path:         "/etc/hosts",
			Exists:       true,
			FileType:     "regular",
			Mode:         0o644,
			UID:          1000,
			GID:          1000,
			Size:         16,
			SHA256:       journalContractDigest("1"),
			Device:       11,
			Inode:        22,
			NLink:        1,
			ParentDevice: 11,
			ParentInode:  2,
			CapturedAt:   journalContractTime(),
		},
	}
}

func journalContractDesired() ResourceSnapshot {
	desired := journalContractBefore()
	desired.Fingerprint = journalContractDigest("3")
	desired.File.Mode = 0o600
	desired.File.UID = 0
	return desired
}

func journalContractBackup() *BackupArtifact {
	return &BackupArtifact{
		ID:             "backup-1",
		MetadataPath:   "backup/metadata.json",
		MetadataSHA256: journalContractDigest("9"),
		Durable:        true,
	}
}

func journalContractError(phase string, occurredAt time.Time) *JournalError {
	return &JournalError{
		Code:       JournalErrorRecoveryAmbiguous,
		Phase:      phase,
		Message:    "contract test error",
		OccurredAt: occurredAt,
	}
}

func journalContractDigest(character string) string {
	return strings.Repeat(character, 64)
}

func journalContractTime() time.Time {
	return time.Date(2026, time.July, 11, 0, 0, 0, 0, time.UTC)
}

func journalContractSchemaContains(node, want any) bool {
	if journalContractSchemaSubset(node, want) {
		return true
	}
	switch value := node.(type) {
	case map[string]any:
		for _, child := range value {
			if journalContractSchemaContains(child, want) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if journalContractSchemaContains(child, want) {
				return true
			}
		}
	}
	return false
}

func journalContractSchemaSubset(got, want any) bool {
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for key, expectedValue := range expected {
			actualValue, exists := actual[key]
			if !exists || !journalContractSchemaSubset(actualValue, expectedValue) {
				return false
			}
		}
		return true
	case []any:
		actual, ok := got.([]any)
		if !ok {
			return false
		}
		for _, expectedItem := range expected {
			found := false
			for _, actualItem := range actual {
				if journalContractSchemaSubset(actualItem, expectedItem) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(got, want)
	}
}

func journalContractSchemaNormalTerminals(t *testing.T, schema any) []string {
	t.Helper()
	var found []string
	var walk func(any)
	walk = func(node any) {
		if len(found) > 0 {
			return
		}
		switch value := node.(type) {
		case map[string]any:
			if rawEnum, ok := value["enum"].([]any); ok && len(rawEnum) == 5 {
				states := make([]string, 0, len(rawEnum))
				for _, entry := range rawEnum {
					state, ok := entry.(string)
					if !ok {
						states = nil
						break
					}
					states = append(states, state)
				}
				if slices.Contains(states, string(RunCompleted)) && slices.Contains(states, string(RunCanceled)) && slices.Contains(states, string(RunFailed)) {
					slices.Sort(states)
					found = states
					return
				}
			}
			for _, child := range value {
				walk(child)
			}
		case []any:
			for _, child := range value {
				walk(child)
			}
		}
	}
	walk(schema)
	if len(found) == 0 {
		t.Fatal("normal-terminal state enum not found in schema")
	}
	return found
}
