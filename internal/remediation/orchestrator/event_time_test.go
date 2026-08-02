package orchestrator

import (
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestNextEventTimeAdvancesPastJournalMaximumWhenClockRegresses(t *testing.T) {
	base := time.Date(2026, time.July, 31, 2, 0, 0, 0, time.UTC)
	approvedAt := base.Add(time.Minute)
	preparedAt := approvedAt.Add(time.Minute)
	intentAt := preparedAt.Add(time.Minute)
	appliedAt := intentAt.Add(time.Minute)
	attemptStartedAt := appliedAt.Add(time.Minute)
	attemptCompletedAt := attemptStartedAt.Add(time.Minute)
	errorAt := attemptCompletedAt.Add(time.Minute)
	value := &model.RemediationJournal{
		StartedAt: base,
		UpdatedAt: base.Add(time.Second),
		ChangeSets: []model.ChangeSet{{
			Approval:   &model.Approval{ApprovedAt: approvedAt},
			PreparedAt: &preparedAt,
			Operations: []model.OperationRecord{{
				ApplyIntentAt: &intentAt,
				AppliedAt:     &appliedAt,
			}},
		}},
		RollbackAttempts: []model.RollbackAttempt{{
			StartedAt:   attemptStartedAt,
			CompletedAt: &attemptCompletedAt,
			Errors: []model.JournalError{{
				OccurredAt: errorAt,
			}},
		}},
	}
	manager := &Manager{now: func() time.Time { return base.Add(-time.Hour) }}

	got := manager.nextEventTime(value)
	want := errorAt.Add(time.Nanosecond)
	if !got.Equal(want) {
		t.Fatalf("nextEventTime() = %s, want %s", got, want)
	}

	value.RollbackAttempts[0].CompletedAt = &got
	got = manager.nextEventTime(value)
	want = want.Add(time.Nanosecond)
	if !got.Equal(want) {
		t.Fatalf("second nextEventTime() = %s, want %s", got, want)
	}
}

func TestNextEventTimeUsesLaterWallClock(t *testing.T) {
	base := time.Date(2026, time.July, 31, 2, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)
	value := &model.RemediationJournal{StartedAt: base, UpdatedAt: base.Add(time.Second)}
	manager := &Manager{now: func() time.Time { return now }}

	if got := manager.nextEventTime(value); !got.Equal(now) {
		t.Fatalf("nextEventTime() = %s, want %s", got, now)
	}
}

func TestMakeJournalErrorUsesLogicalEventTime(t *testing.T) {
	base := time.Date(2026, time.July, 31, 2, 0, 0, 0, time.UTC)
	value := &model.RemediationJournal{StartedAt: base, UpdatedAt: base.Add(time.Hour)}
	manager := &Manager{now: func() time.Time { return base.Add(-time.Hour) }}

	journalError := manager.makeJournalError(
		value,
		"apply",
		"",
		"",
		nil,
		&Error{Code: CodeApplyFailed},
	)
	want := value.UpdatedAt.Add(time.Nanosecond)
	if !journalError.OccurredAt.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", journalError.OccurredAt, want)
	}
}
