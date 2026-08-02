package journal

import (
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestRecoveryObserverClaimIsAnIsolatedDurableTransition(t *testing.T) {
	previous := testIncompleteUserRollbackJournal(t)
	next := cloneJournalValue(t, previous)
	observer := testRecoveryObserverBuild()
	next.RollbackAttempts[0].ObservedByBuild = &observer
	advanceJournalRevision(&next, previous)

	if err := ValidateTransition(&previous, &next); err != nil {
		t.Fatalf("ValidateTransition(observer claim) error = %v", err)
	}

	changed := cloneJournalValue(t, previous)
	changed.RollbackAttempts[0].ObservedByBuild = &observer
	advanceJournalRevision(&changed, previous)
	changed.Warnings = append(changed.Warnings, "unrelated mutation")
	if err := ValidateTransition(&previous, &changed); err == nil || !strings.Contains(err.Error(), "only durable state change") {
		t.Fatalf("ValidateTransition(observer plus unrelated change) error = %v", err)
	}
}

func TestNonCrashRollbackAttemptCannotStartWithRecoveryObserver(t *testing.T) {
	previous := testRollbackJournalWithoutAttempt(t)
	next := cloneJournalValue(t, previous)
	executor := testUserRollbackBuild()
	observer := testRecoveryObserverBuild()
	startedAt := previous.LatestEventTime().Add(time.Second)
	next.RollbackAttempts = []model.RollbackAttempt{{
		ID:                  "attempt-preclaimed",
		Scope:               model.RollbackItem,
		Trigger:             model.RollbackUserRequest,
		ExecutorBuild:       &executor,
		ObservedByBuild:     &observer,
		RequestedChangeSets: []string{"change-1"},
		ExpandedChangeSets:  []string{"change-1"},
		StartedAt:           startedAt,
	}}
	next.UpdatedAt = startedAt
	next.Revision++
	if err := next.Validate(); err != nil {
		t.Fatalf("next Validate() error = %v", err)
	}
	err := ValidateTransition(&previous, &next)
	if err == nil || !strings.Contains(err.Error(), "isolated recovery claim") {
		t.Fatalf("ValidateTransition(preclaimed observer) error = %v", err)
	}
}

func TestRollbackBuildProvenanceIsImmutable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.RollbackAttempt)
		want   string
	}{
		{
			name: "executor",
			mutate: func(attempt *model.RollbackAttempt) {
				attempt.ExecutorBuild.ExecutableSHA256 = strings.Repeat("e", 64)
			},
			want: "executor build is immutable",
		},
		{
			name: "observer",
			mutate: func(attempt *model.RollbackAttempt) {
				attempt.ObservedByBuild.ExecutableSHA256 = strings.Repeat("f", 64)
			},
			want: "observer build is immutable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			previous := testIncompleteUserRollbackJournal(t)
			observer := testRecoveryObserverBuild()
			previous.RollbackAttempts[0].ObservedByBuild = &observer
			if err := previous.Validate(); err != nil {
				t.Fatalf("previous Validate() error = %v", err)
			}
			next := cloneJournalValue(t, previous)
			test.mutate(&next.RollbackAttempts[0])
			advanceJournalRevision(&next, previous)
			err := ValidateTransition(&previous, &next)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRollbackAttemptAppendRequiresOneFreshAttempt(t *testing.T) {
	t.Run("two attempts in one revision", func(t *testing.T) {
		previous := testRollbackJournalWithoutAttempt(t)
		next := cloneJournalValue(t, previous)
		first := testCompletedCrashAttempt(previous.LatestEventTime().Add(time.Second), "attempt-first")
		second := testCompletedCrashAttempt(*first.CompletedAt, "attempt-second")
		next.RollbackAttempts = []model.RollbackAttempt{first, second}
		next.UpdatedAt = second.CompletedAt.Add(time.Second)
		next.Revision++
		if err := next.Validate(); err != nil {
			t.Fatalf("next Validate() error = %v", err)
		}
		err := ValidateTransition(&previous, &next)
		if err == nil || !strings.Contains(err.Error(), "only one rollback attempt") {
			t.Fatalf("ValidateTransition() error = %v", err)
		}
	})

	t.Run("attempt starts at previous durable event", func(t *testing.T) {
		previous := testRollbackJournalWithoutAttempt(t)
		next := cloneJournalValue(t, previous)
		observer := testRecoveryObserverBuild()
		next.RollbackAttempts = []model.RollbackAttempt{{
			ID:                  "attempt-stale-start",
			Scope:               model.RollbackItem,
			Trigger:             model.RollbackCrashRecovery,
			ObservedByBuild:     &observer,
			RequestedChangeSets: []string{"change-1"},
			ExpandedChangeSets:  []string{"change-1"},
			StartedAt:           previous.LatestEventTime(),
		}}
		advanceJournalRevision(&next, previous)
		if err := next.Validate(); err != nil {
			t.Fatalf("next Validate() error = %v", err)
		}
		err := ValidateTransition(&previous, &next)
		if err == nil || !strings.Contains(err.Error(), "previous durable event") {
			t.Fatalf("ValidateTransition() error = %v", err)
		}
	})
}

func testIncompleteUserRollbackJournal(t *testing.T) model.RemediationJournal {
	t.Helper()
	value := testRollbackJournalWithoutAttempt(t)
	executor := testUserRollbackBuild()
	startedAt := value.LatestEventTime().Add(time.Second)
	value.RollbackAttempts = []model.RollbackAttempt{{
		ID:                  "attempt-user",
		Scope:               model.RollbackItem,
		Trigger:             model.RollbackUserRequest,
		ExecutorBuild:       &executor,
		RequestedChangeSets: []string{"change-1"},
		ExpandedChangeSets:  []string{"change-1"},
		StartedAt:           startedAt,
	}}
	value.UpdatedAt = startedAt
	if err := value.Validate(); err != nil {
		t.Fatalf("rollback journal Validate() error = %v", err)
	}
	return value
}

func testRollbackJournalWithoutAttempt(t *testing.T) model.RemediationJournal {
	t.Helper()
	value := testApprovedJournal(t, testInitialJournal(t))
	value.State = model.RunRollingBack
	if err := value.Validate(); err != nil {
		t.Fatalf("rollback journal without attempt Validate() error = %v", err)
	}
	return value
}

func testCompletedCrashAttempt(startedAt time.Time, id string) model.RollbackAttempt {
	observer := testRecoveryObserverBuild()
	completedAt := startedAt.Add(time.Second)
	return model.RollbackAttempt{
		ID:                  id,
		Scope:               model.RollbackItem,
		Trigger:             model.RollbackCrashRecovery,
		ObservedByBuild:     &observer,
		RequestedChangeSets: []string{"change-1"},
		ExpandedChangeSets:  []string{"change-1"},
		Outcome:             model.RollbackBlocked,
		StartedAt:           startedAt,
		CompletedAt:         &completedAt,
	}
}

func testUserRollbackBuild() model.RemediationBuildIdentity {
	return model.RemediationBuildIdentity{
		Version:          "1.0.0",
		Commit:           strings.Repeat("a", 40),
		ExecutableSHA256: strings.Repeat("b", 64),
	}
}

func testRecoveryObserverBuild() model.RemediationBuildIdentity {
	return model.RemediationBuildIdentity{
		Version:          "0.1.0-alpha.39",
		Commit:           "recovery-observer",
		ExecutableSHA256: strings.Repeat("c", 64),
		Modified:         true,
	}
}

func cloneJournalValue(t *testing.T, value model.RemediationJournal) model.RemediationJournal {
	t.Helper()
	clone, err := cloneJournal(&value)
	if err != nil {
		t.Fatalf("cloneJournal() error = %v", err)
	}
	return *clone
}

func advanceJournalRevision(next *model.RemediationJournal, previous model.RemediationJournal) {
	next.Revision = previous.Revision + 1
	next.UpdatedAt = previous.UpdatedAt.Add(time.Second)
}
