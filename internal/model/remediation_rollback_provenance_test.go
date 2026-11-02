package model

import (
	"strings"
	"testing"
	"time"
)

func TestRemediationJournalV4RollbackBuildProvenanceSchemaParity(t *testing.T) {
	schema := compileRemediationJournalV4Schema(t)
	valid := []struct {
		name    string
		attempt func(RemediationJournal) RollbackAttempt
	}{
		{
			name: "user item rollback",
			attempt: func(value RemediationJournal) RollbackAttempt {
				executor := journalContractRollbackExecutor()
				return rollbackProvenanceAttempt(value, RollbackItem, RollbackUserRequest, &executor, nil, []string{"change-1"})
			},
		},
		{
			name: "user run rollback",
			attempt: func(value RemediationJournal) RollbackAttempt {
				executor := journalContractRollbackExecutor()
				return rollbackProvenanceAttempt(value, RollbackRun, RollbackUserRequest, &executor, nil, nil)
			},
		},
		{
			name: "user item rollback with prerelease executor",
			attempt: func(value RemediationJournal) RollbackAttempt {
				executor := journalContractRollbackExecutor()
				executor.Version = "1.0.0-alpha.1"
				return rollbackProvenanceAttempt(value, RollbackItem, RollbackUserRequest, &executor, nil, []string{"change-1"})
			},
		},
		{
			name: "automatic apply failure rollback",
			attempt: func(value RemediationJournal) RollbackAttempt {
				executor := value.RemediationBuild
				return rollbackProvenanceAttempt(value, RollbackItem, RollbackApplyFailure, &executor, nil, []string{"change-1"})
			},
		},
		{
			name: "automatic verification failure rollback",
			attempt: func(value RemediationJournal) RollbackAttempt {
				executor := value.RemediationBuild
				return rollbackProvenanceAttempt(value, RollbackItem, RollbackVerifyFailure, &executor, nil, []string{"change-1"})
			},
		},
		{
			name: "crash recovery observation",
			attempt: func(value RemediationJournal) RollbackAttempt {
				observer := value.RemediationBuild
				return rollbackProvenanceAttempt(value, RollbackItem, RollbackCrashRecovery, nil, &observer, []string{"change-1"})
			},
		},
	}
	for _, test := range valid {
		t.Run("valid/"+test.name, func(t *testing.T) {
			value := journalContractRecoveryIntent()
			attempt := test.attempt(value)
			value.RollbackAttempts = []RollbackAttempt{attempt}
			value.UpdatedAt = attempt.StartedAt
			assertRemediationJournalParity(t, schema, value, true)
		})
	}

	invalid := []struct {
		name   string
		mutate func(*RollbackAttempt, RemediationJournal)
	}{
		{
			name: "user attempt missing executor",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.ExecutorBuild = nil
			},
		},
		{
			name: "user attempt has build metadata",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.ExecutorBuild.Version = "1.0.0-alpha.1+build.2"
			},
		},
		{
			name: "user attempt has modified executor",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.ExecutorBuild.Modified = true
			},
		},
		{
			name: "user attempt has null commit",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.ExecutorBuild.Commit = strings.Repeat("0", 40)
			},
		},
		{
			name: "user item attempt has no requested change set",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.RequestedChangeSets = nil
			},
		},
		{
			name: "user run attempt has requested change set",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.Scope = RollbackRun
			},
		},
	}
	for _, test := range invalid {
		t.Run("invalid/"+test.name, func(t *testing.T) {
			value := journalContractRecoveryIntent()
			executor := journalContractRollbackExecutor()
			attempt := rollbackProvenanceAttempt(value, RollbackItem, RollbackUserRequest, &executor, nil, []string{"change-1"})
			test.mutate(&attempt, value)
			value.RollbackAttempts = []RollbackAttempt{attempt}
			value.UpdatedAt = attempt.StartedAt
			assertRemediationJournalParity(t, schema, value, false)
		})
	}

	t.Run("invalid/crash recovery missing observer", func(t *testing.T) {
		value := journalContractRecoveryIntent()
		attempt := rollbackProvenanceAttempt(value, RollbackItem, RollbackCrashRecovery, nil, nil, []string{"change-1"})
		value.RollbackAttempts = []RollbackAttempt{attempt}
		value.UpdatedAt = attempt.StartedAt
		assertRemediationJournalParity(t, schema, value, false)
	})
	t.Run("invalid/crash recovery has executor", func(t *testing.T) {
		value := journalContractRecoveryIntent()
		executor := value.RemediationBuild
		observer := value.RemediationBuild
		attempt := rollbackProvenanceAttempt(value, RollbackItem, RollbackCrashRecovery, &executor, &observer, []string{"change-1"})
		value.RollbackAttempts = []RollbackAttempt{attempt}
		value.UpdatedAt = attempt.StartedAt
		assertRemediationJournalParity(t, schema, value, false)
	})
}

func TestRemediationJournalV3KeepsStableRollbackContract(t *testing.T) {
	schema := compileRemediationJournalSchema(t, "remediation-journal-v3.schema.json", "https://raw.githubusercontent.com/yesidodo73/OpenCIIP/main/schemas/remediation-journal-v3.schema.json")
	value := journalContractRecoveryIntent()
	value.SchemaVersion = 3
	executor := journalContractRollbackExecutor()
	attempt := rollbackProvenanceAttempt(value, RollbackItem, RollbackUserRequest, &executor, nil, []string{"change-1"})
	value.RollbackAttempts = []RollbackAttempt{attempt}
	value.UpdatedAt = attempt.StartedAt
	assertRemediationJournalParity(t, schema, value, true)

	value.RollbackAttempts[0].ExecutorBuild.Version = "1.0.0-alpha.1"
	assertRemediationJournalParity(t, schema, value, false)
}

func TestRemediationJournalRejectsRuntimeOnlyRollbackProvenanceViolations(t *testing.T) {
	schema := compileRemediationJournalV4Schema(t)
	tests := []struct {
		name   string
		mutate func(*RollbackAttempt, RemediationJournal)
	}{
		{
			name: "automatic executor differs from remediation build",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.ExecutorBuild.ExecutableSHA256 = journalContractDigest("f")
			},
		},
		{
			name: "user item request is outside expanded scope",
			mutate: func(attempt *RollbackAttempt, _ RemediationJournal) {
				attempt.RequestedChangeSets = []string{"change-outside"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := journalContractRecoveryIntent()
			executor := value.RemediationBuild
			trigger := RollbackApplyFailure
			if strings.Contains(test.name, "user item") {
				executor = journalContractRollbackExecutor()
				trigger = RollbackUserRequest
			}
			attempt := rollbackProvenanceAttempt(value, RollbackItem, trigger, &executor, nil, []string{"change-1"})
			test.mutate(&attempt, value)
			value.RollbackAttempts = []RollbackAttempt{attempt}
			value.UpdatedAt = attempt.StartedAt
			if err := value.Validate(); err == nil {
				t.Fatal("runtime accepted invalid rollback provenance")
			}
			if err := validateRemediationJournalSchema(schema, value); err != nil {
				t.Fatalf("JSON Schema rejected a structurally valid runtime-only corpus: %v", err)
			}
		})
	}
}

func TestLegacyRollbackAttemptRejectsV3BuildProvenance(t *testing.T) {
	_, value := readLegacyV2RemediationJournalFixture(t, "rolled-back.json")
	executor := journalContractRollbackExecutor()
	value.RollbackAttempts[0].ExecutorBuild = &executor
	if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "legacy rollback attempt") {
		t.Fatalf("Validate() error = %v, want legacy provenance rejection", err)
	}
}

func TestRolledBackOperationMustCompleteWithinCoveringAttempt(t *testing.T) {
	value := journalContractRolledBack()
	attempt := &value.RollbackAttempts[0]
	rolledBackAt := attempt.CompletedAt.Add(time.Nanosecond)
	value.ChangeSets[0].RolledBackAt = &rolledBackAt
	value.ChangeSets[0].Operations[0].RolledBackAt = &rolledBackAt
	value.UpdatedAt = rolledBackAt
	if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "covering rollback attempt") {
		t.Fatalf("Validate() error = %v, want attempt completion coverage rejection", err)
	}
}

func rollbackProvenanceAttempt(
	value RemediationJournal,
	scope RollbackScope,
	trigger RollbackTrigger,
	executor, observer *RemediationBuildIdentity,
	requested []string,
) RollbackAttempt {
	startedAt := value.LatestEventTime().Add(time.Second)
	return RollbackAttempt{
		ID:                  "attempt-provenance",
		Scope:               scope,
		Trigger:             trigger,
		ExecutorBuild:       executor,
		ObservedByBuild:     observer,
		RequestedChangeSets: append([]string(nil), requested...),
		ExpandedChangeSets:  []string{"change-1"},
		CascadeApproved:     true,
		StartedAt:           startedAt,
	}
}
