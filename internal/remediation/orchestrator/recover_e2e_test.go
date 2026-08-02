package orchestrator

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestManagerRecoverEndToEndNeverRestoresTargetResources(t *testing.T) {
	tests := []struct {
		name                     string
		journal                  func(*testing.T) *model.RemediationJournal
		live                     func(*model.RemediationJournal) model.ResourceSnapshot
		wantRunState             model.RunState
		wantOperationState       model.OperationState
		wantConfirmedApplied     []string
		wantConfirmedRolledBack  []string
		wantNotApplied           []string
		wantAmbiguous            []string
		wantUnresolvedChangeSets []string
		wantAutomaticRollback    bool
		wantBackupVerifications  int
		assertFinal              func(*testing.T, *model.RemediationJournal)
	}{
		{
			name:    "durable apply intent with no effect",
			journal: recoverApplyIntentJournal,
			live: func(value *model.RemediationJournal) model.ResourceSnapshot {
				return faultCloneSnapshot(value.ChangeSets[0].Operations[0].Before)
			},
			wantRunState:          model.RunFailed,
			wantOperationState:    model.OperationFailed,
			wantNotApplied:        []string{"change-a/operation-a"},
			wantAutomaticRollback: false,
			assertFinal: func(t *testing.T, value *model.RemediationJournal) {
				t.Helper()
				changeSet := value.ChangeSets[0]
				operation := changeSet.Operations[0]
				if changeSet.State != model.ChangeApplyFailed {
					t.Fatalf("change set state = %s, want %s", changeSet.State, model.ChangeApplyFailed)
				}
				if !operation.ProvesNoEffect() {
					t.Fatal("recovered operation does not retain exact durable no-effect evidence")
				}
				if len(value.RollbackAttempts) != 0 || operation.RollbackIntentAt != nil || operation.ObservedRollback != nil {
					t.Fatalf("no-effect recovery invented rollback history: attempts=%d intent=%v observation=%v", len(value.RollbackAttempts), operation.RollbackIntentAt, operation.ObservedRollback)
				}
			},
		},
		{
			name:    "durably recorded applied effect",
			journal: recoverAppliedJournal,
			live: func(value *model.RemediationJournal) model.ResourceSnapshot {
				return faultCloneSnapshot(*value.ChangeSets[0].Operations[0].ObservedAfter)
			},
			wantRunState:             model.RunRecoveryRequired,
			wantOperationState:       model.OperationApplied,
			wantConfirmedApplied:     []string{"change-a/operation-a"},
			wantUnresolvedChangeSets: []string{"change-a"},
			wantAutomaticRollback:    true,
			wantBackupVerifications:  1,
			assertFinal: func(t *testing.T, value *model.RemediationJournal) {
				t.Helper()
				if value.ChangeSets[0].State != model.ChangeApplied {
					t.Fatalf("change set state = %s, want %s", value.ChangeSets[0].State, model.ChangeApplied)
				}
				if len(value.RollbackAttempts) != 0 {
					t.Fatalf("applied recovery invented %d rollback attempts", len(value.RollbackAttempts))
				}
			},
		},
		{
			name:    "interrupted rollback completed before crash",
			journal: recoverRollbackIntentJournal,
			live: func(value *model.RemediationJournal) model.ResourceSnapshot {
				return faultCloneSnapshot(value.ChangeSets[0].Operations[0].Before)
			},
			wantRunState:            model.RunRolledBack,
			wantOperationState:      model.OperationRolledBack,
			wantConfirmedRolledBack: []string{"change-a/operation-a"},
			wantAutomaticRollback:   false,
			assertFinal: func(t *testing.T, value *model.RemediationJournal) {
				t.Helper()
				if value.ChangeSets[0].State != model.ChangeRolledBack {
					t.Fatalf("change set state = %s, want %s", value.ChangeSets[0].State, model.ChangeRolledBack)
				}
				if len(value.RollbackAttempts) != 1 {
					t.Fatalf("rollback attempts = %d, want 1", len(value.RollbackAttempts))
				}
				attempt := value.RollbackAttempts[0]
				if attempt.CompletedAt == nil || attempt.Outcome != model.RollbackSucceeded {
					t.Fatalf("rollback attempt completion = %v/%s, want completed/%s", attempt.CompletedAt, attempt.Outcome, model.RollbackSucceeded)
				}
			},
		},
		{
			name:    "unrecognized live state remains ambiguous",
			journal: recoverApplyIntentJournal,
			live: func(value *model.RemediationJournal) model.ResourceSnapshot {
				snapshot := faultCloneSnapshot(value.ChangeSets[0].Operations[0].Before)
				snapshot.Fingerprint = strings.Repeat("f", 64)
				snapshot.File.Inode++
				snapshot.File.CapturedAt = faultBaseTime().Add(20 * time.Minute)
				return snapshot
			},
			wantRunState:             model.RunRecoveryRequired,
			wantOperationState:       model.OperationAmbiguous,
			wantAmbiguous:            []string{"change-a/operation-a"},
			wantUnresolvedChangeSets: []string{"change-a"},
			wantAutomaticRollback:    false,
			assertFinal: func(t *testing.T, value *model.RemediationJournal) {
				t.Helper()
				if value.ChangeSets[0].State != model.ChangeRecoveryRequired {
					t.Fatalf("change set state = %s, want %s", value.ChangeSets[0].State, model.ChangeRecoveryRequired)
				}
				if len(value.RollbackAttempts) != 0 {
					t.Fatalf("ambiguous recovery invented %d rollback attempts", len(value.RollbackAttempts))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := test.journal(t)
			harness := newFaultStoreHarness(t, value)
			backupVerifications := 0
			runtime := &scriptedFileRuntime{
				capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
					return test.live(value), nil
				},
				verifyBackup: func(context.Context, model.BackupArtifact) error {
					backupVerifications++
					return nil
				},
				restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
					t.Fatal("Recover called Restore and mutated a target resource")
					return model.ResourceSnapshot{}, nil
				},
			}
			manager := newFaultManager(t, harness, runtime, []string{"001"})

			assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
			if err != nil {
				t.Fatalf("Recover() error = %v", err)
			}

			if assessment.RunID != value.RunID {
				t.Fatalf("assessment run ID = %q, want %q", assessment.RunID, value.RunID)
			}
			if assessment.LastValidRevision != harness.state.Revision {
				t.Fatalf("assessment revision = %d, want final durable revision %d", assessment.LastValidRevision, harness.state.Revision)
			}
			if !slices.Equal(assessment.ConfirmedApplied, test.wantConfirmedApplied) {
				t.Fatalf("ConfirmedApplied = %v, want %v", assessment.ConfirmedApplied, test.wantConfirmedApplied)
			}
			if !slices.Equal(assessment.ConfirmedRolledBack, test.wantConfirmedRolledBack) {
				t.Fatalf("ConfirmedRolledBack = %v, want %v", assessment.ConfirmedRolledBack, test.wantConfirmedRolledBack)
			}
			if !slices.Equal(assessment.NotApplied, test.wantNotApplied) {
				t.Fatalf("NotApplied = %v, want %v", assessment.NotApplied, test.wantNotApplied)
			}
			if !slices.Equal(assessment.Ambiguous, test.wantAmbiguous) {
				t.Fatalf("Ambiguous = %v, want %v", assessment.Ambiguous, test.wantAmbiguous)
			}
			if assessment.AutomaticRollbackPossible != test.wantAutomaticRollback {
				t.Fatalf("AutomaticRollbackPossible = %t, want %t", assessment.AutomaticRollbackPossible, test.wantAutomaticRollback)
			}
			if harness.state.State != test.wantRunState {
				t.Fatalf("run state = %s, want %s", harness.state.State, test.wantRunState)
			}
			operation := harness.state.ChangeSets[0].Operations[0]
			if operation.State != test.wantOperationState {
				t.Fatalf("operation state = %s, want %s", operation.State, test.wantOperationState)
			}
			if !slices.Equal(harness.state.UnresolvedChangeSets, test.wantUnresolvedChangeSets) {
				t.Fatalf("unresolved change sets = %v, want %v", harness.state.UnresolvedChangeSets, test.wantUnresolvedChangeSets)
			}
			if backupVerifications != test.wantBackupVerifications {
				t.Fatalf("backup verification calls = %d, want %d", backupVerifications, test.wantBackupVerifications)
			}
			if len(runtime.mutationCalls) != 0 {
				t.Fatalf("Recover issued target mutation calls: %v", runtime.mutationCalls)
			}
			if err := harness.state.Validate(); err != nil {
				t.Fatalf("recovered journal Validate() error = %v", err)
			}
			test.assertFinal(t, harness.state)
		})
	}
}

func recoverApplyIntentJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultJournalSkeleton(1, false)
	value.State = model.RunApplying
	value.FailurePolicy = model.FailureRollbackItem
	preparedAt := faultBaseTime().Add(2 * time.Minute)
	intentAt := faultBaseTime().Add(3 * time.Minute)
	changeSet := &value.ChangeSets[0]
	operation := &changeSet.Operations[0]
	changeSet.State = model.ChangeApplying
	changeSet.Before = []model.ResourceSnapshot{faultCloneSnapshot(operation.ExpectedBefore)}
	changeSet.PreparedAt = &preparedAt
	operation.State = model.OperationApplyIntentDurable
	operation.Before = faultCloneSnapshot(operation.ExpectedBefore)
	backup := faultBackup("backup-a")
	operation.Backup = &backup
	operation.ApplyIntentAt = &intentAt
	faultSealJournal(t, value)
	return value
}

func recoverAppliedJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := recoverApplyIntentJournal(t)
	value.FailurePolicy = model.FailureRollbackRun
	appliedAt := faultBaseTime().Add(4 * time.Minute)
	operation := &value.ChangeSets[0].Operations[0]
	operation.State = model.OperationApplied
	observed := faultCloneSnapshot(operation.Desired)
	observed.File.CapturedAt = appliedAt
	operation.ObservedAfter = &observed
	operation.AppliedAt = &appliedAt
	faultSealJournal(t, value)
	return value
}

func recoverRollbackIntentJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultVerifiedJournal(t, 1, false, model.FailureRollbackRun, model.RunRollingBack)
	rollbackIntentAt := faultBaseTime().Add(6 * time.Minute)
	changeSet := &value.ChangeSets[0]
	changeSet.State = model.ChangeRollingBack
	operation := &changeSet.Operations[0]
	operation.State = model.OperationRollbackIntentDurable
	operation.RollbackIntentAt = &rollbackIntentAt
	value.RollbackAttempts = []model.RollbackAttempt{{
		ID:                 "rollback-interrupted",
		Scope:              model.RollbackRun,
		Trigger:            model.RollbackUserRequest,
		ExpandedChangeSets: []string{changeSet.ID},
		CascadeApproved:    true,
		StartedAt:          rollbackIntentAt,
	}}
	faultSealJournal(t, value)
	return value
}
