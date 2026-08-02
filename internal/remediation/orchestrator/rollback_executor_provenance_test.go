package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestUserRollbackAttemptsRecordCurrentExecutorBuild(t *testing.T) {
	t.Run("successful item rollback", func(t *testing.T) {
		value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
		fixture := newRollbackCrashCutFixture(t, value)
		preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
		if err != nil {
			t.Fatalf("PreviewRollbackItem() error = %v", err)
		}
		executor := faultUserRollbackBuild()
		attempt, err := fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, executor)
		if err != nil {
			t.Fatalf("RollbackItem() error = %v", err)
		}
		assertRollbackExecutor(t, attempt, executor)
	})

	t.Run("blocked preflight", func(t *testing.T) {
		value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
		fixture := newRollbackCrashCutFixture(t, value)
		drift := faultCloneSnapshot(fixture.after)
		drift.Fingerprint = strings.Repeat("f", 64)
		drift.File.Inode++
		fixture.live = drift
		preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
		if err != nil {
			t.Fatalf("PreviewRollbackItem() error = %v", err)
		}
		executor := faultUserRollbackBuild()
		attempt, err := fixture.manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, executor)
		if CodeOf(err) != CodeRecoveryRequired {
			t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRecoveryRequired)
		}
		assertRollbackExecutor(t, attempt, executor)
		if len(fixture.harness.state.RollbackAttempts) != 1 {
			t.Fatalf("blocked rollback attempts = %d, want 1", len(fixture.harness.state.RollbackAttempts))
		}
		assertRollbackExecutor(t, fixture.harness.state.RollbackAttempts[0], executor)
	})
}

func TestAutomaticRollbackAttemptsRecordOriginalRemediationBuild(t *testing.T) {
	for _, trigger := range []model.RollbackTrigger{model.RollbackApplyFailure, model.RollbackVerifyFailure} {
		t.Run(string(trigger), func(t *testing.T) {
			value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
			fixture := newRollbackCrashCutFixture(t, value)
			attempt, err := fixture.manager.executeRollback(
				context.Background(),
				value,
				model.RollbackItem,
				trigger,
				[]string{"change-a"},
				[]string{"change-a"},
				true,
				value.RemediationBuild,
			)
			if err != nil {
				t.Fatalf("executeRollback() error = %v", err)
			}
			assertRollbackExecutor(t, attempt, value.RemediationBuild)
		})
	}
}

func TestAutomaticRollbackRejectsDifferentExecutorBuild(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	different := value.RemediationBuild
	different.ExecutableSHA256 = strings.Repeat("f", 64)
	_, err := fixture.manager.executeRollback(
		context.Background(),
		value,
		model.RollbackItem,
		model.RollbackApplyFailure,
		[]string{"change-a"},
		[]string{"change-a"},
		true,
		different,
	)
	if CodeOf(err) != CodeInvalidInput {
		t.Fatalf("executeRollback() error = %v, want %s", err, CodeInvalidInput)
	}
	if len(fixture.runtime.mutationCalls) != 0 || len(fixture.harness.state.RollbackAttempts) != 0 {
		t.Fatalf("mismatched automatic executor changed state: mutations=%v attempts=%v", fixture.runtime.mutationCalls, fixture.harness.state.RollbackAttempts)
	}
}

func TestUserRollbackRejectsUnsafeExecutorBeforeStateAccess(t *testing.T) {
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	fixture := newRollbackCrashCutFixture(t, value)
	unsafe := faultUserRollbackBuild()
	unsafe.Version = "1.0.0-alpha.1"
	revision := fixture.harness.state.Revision

	_, err := fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		strings.Repeat("a", 64),
		unsafe,
	)
	if CodeOf(err) != CodeInvalidInput {
		t.Fatalf("RollbackItem() error = %v, want %s", err, CodeInvalidInput)
	}
	if len(fixture.harness.storeCalls) != 0 ||
		len(fixture.runtime.captureCalls) != 0 ||
		len(fixture.runtime.mutationCalls) != 0 ||
		fixture.harness.state.Revision != revision {
		t.Fatalf(
			"unsafe executor accessed rollback state: store=%v captures=%v mutations=%v revision=%d",
			fixture.harness.storeCalls,
			fixture.runtime.captureCalls,
			fixture.runtime.mutationCalls,
			fixture.harness.state.Revision,
		)
	}
}

func TestRecoverClaimsIncompleteAttemptBeforeResourceAccess(t *testing.T) {
	t.Run("claim persistence failure", func(t *testing.T) {
		value := faultIncompleteUserRollbackAttemptJournal(t, nil)
		harness := newFaultStoreHarness(t, value)
		persistErr := errors.New("injected recovery observer claim failure")
		harness.rejectUpdate = func(label string, _ *model.RemediationJournal) error {
			if label == "recovery_observer_claim" {
				return persistErr
			}
			return nil
		}
		runtime := failOnRecoveryResourceAccess(t)
		manager := newFaultManager(t, harness, runtime, nil)
		_, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
		if CodeOf(err) != CodePersistFailed {
			t.Fatalf("Recover() error = %v, want %s", err, CodePersistFailed)
		}
		if len(runtime.captureCalls) != 0 || len(runtime.mutationCalls) != 0 {
			t.Fatalf("failed observer claim touched resources: captures=%v mutations=%v", runtime.captureCalls, runtime.mutationCalls)
		}
		if harness.state.RollbackAttempts[0].ObservedByBuild != nil {
			t.Fatalf("failed observer claim changed durable attempt: %#v", harness.state.RollbackAttempts[0])
		}
	})

	t.Run("different recovery owner", func(t *testing.T) {
		first := faultRecoveryObserverBuild()
		value := faultIncompleteUserRollbackAttemptJournal(t, &first)
		harness := newFaultStoreHarness(t, value)
		runtime := failOnRecoveryResourceAccess(t)
		manager := newFaultManager(t, harness, runtime, nil)
		different := first
		different.ExecutableSHA256 = strings.Repeat("d", 64)
		_, err := manager.Recover(context.Background(), value.RunID, different)
		if CodeOf(err) != CodeRecoveryRequired {
			t.Fatalf("Recover() error = %v, want %s", err, CodeRecoveryRequired)
		}
		if len(runtime.captureCalls) != 0 || len(runtime.mutationCalls) != 0 {
			t.Fatalf("owner mismatch touched resources: captures=%v mutations=%v", runtime.captureCalls, runtime.mutationCalls)
		}
		if got := harness.state.RollbackAttempts[0].ObservedByBuild; got == nil || *got != first {
			t.Fatalf("owner mismatch changed durable observer: %#v", got)
		}
	})
}

func TestRecoveryObserverClaimRecognizesCommittedPersistenceError(t *testing.T) {
	value := faultIncompleteUserRollbackAttemptJournal(t, nil)
	harness := newFaultStoreHarness(t, value)
	commitErr := errors.New("injected observer claim error after commit")
	harness.rejectUpdate = func(label string, candidate *model.RemediationJournal) error {
		if label != "recovery_observer_claim" {
			return nil
		}
		harness.state = faultCloneJournal(t, candidate)
		return commitErr
	}
	manager := newFaultManager(t, harness, failOnRecoveryResourceAccess(t), nil)
	observer := faultRecoveryObserverBuild()
	next, err := manager.claimRecoveryAttempt(context.Background(), value, observer)
	if err != nil {
		t.Fatalf("claimRecoveryAttempt() error = %v", err)
	}
	if next.Revision != value.Revision+1 ||
		next.RollbackAttempts[0].ObservedByBuild == nil ||
		*next.RollbackAttempts[0].ObservedByBuild != observer {
		t.Fatalf("committed observer claim was not recognized: %#v", next.RollbackAttempts)
	}
}

func TestCrashRecoveryAttemptsRecordObserverWithoutExecutor(t *testing.T) {
	value := faultResolvedCrashRollbackJournal(t)
	harness := newFaultStoreHarness(t, value)
	operation := value.ChangeSets[0].Operations[0]
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			return faultCloneSnapshot(operation.Before), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() restored an already rolled-back operation")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"recovered"})
	observer := faultRecoveryObserverBuild()
	if _, err := manager.Recover(context.Background(), value.RunID, observer); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	attempt := harness.state.RollbackAttempts[len(harness.state.RollbackAttempts)-1]
	if attempt.Trigger != model.RollbackCrashRecovery ||
		attempt.ExecutorBuild != nil ||
		attempt.ObservedByBuild == nil ||
		*attempt.ObservedByBuild != observer {
		t.Fatalf("crash recovery provenance = %#v", attempt)
	}
}

func assertRollbackExecutor(t *testing.T, attempt model.RollbackAttempt, expected model.RemediationBuildIdentity) {
	t.Helper()
	if attempt.ExecutorBuild == nil || *attempt.ExecutorBuild != expected || attempt.ObservedByBuild != nil {
		t.Fatalf("rollback attempt build provenance = executor %#v observer %#v, want executor %#v only", attempt.ExecutorBuild, attempt.ObservedByBuild, expected)
	}
}

func faultIncompleteUserRollbackAttemptJournal(
	t *testing.T,
	observer *model.RemediationBuildIdentity,
) *model.RemediationJournal {
	t.Helper()
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
	startedAt := value.LatestEventTime().Add(time.Second)
	executor := faultUserRollbackBuild()
	value.State = model.RunRollingBack
	value.RollbackAttempts = []model.RollbackAttempt{{
		ID:                  "rollback-incomplete-user",
		Scope:               model.RollbackItem,
		Trigger:             model.RollbackUserRequest,
		ExecutorBuild:       &executor,
		ObservedByBuild:     cloneBuildIdentity(observer),
		RequestedChangeSets: []string{"change-a"},
		ExpandedChangeSets:  []string{"change-a"},
		StartedAt:           startedAt,
	}}
	value.UpdatedAt = startedAt
	faultSealJournal(t, value)
	return value
}

func failOnRecoveryResourceAccess(t *testing.T) *scriptedFileRuntime {
	t.Helper()
	return &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() accessed a resource before proving recovery ownership")
			return model.ResourceSnapshot{}, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error {
			t.Fatal("Recover() verified a backup before proving recovery ownership")
			return nil
		},
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover() restored a resource before proving recovery ownership")
			return model.ResourceSnapshot{}, nil
		},
	}
}
