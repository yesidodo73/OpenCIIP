package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	modeltestdata "github.com/yesidodo73/OpenCIIP/internal/model/testdata"
)

const remediationJournalSchemaResource = "https://raw.githubusercontent.com/yesidodo73/OpenCIIP/main/schemas/remediation-journal.schema.json"

func TestRemediationJournalV4SchemaRuntimeParity(t *testing.T) {
	schema := compileRemediationJournalV4Schema(t)

	valid := []struct {
		name    string
		journal func() RemediationJournal
	}{
		{name: "planned run", journal: journalContractBase},
		{name: "approved run", journal: remediationJournalApprovedCorpus},
		{name: "completed run", journal: journalContractCompleted},
		{name: "failed run with durable no-effect evidence", journal: journalContractNoEffectFailure},
		{name: "rolled-back run", journal: journalContractRolledBack},
		{name: "recovery-required run with durable apply intent", journal: journalContractRecoveryIntent},
		{name: "applying run with prepared change set", journal: remediationJournalPreparedCorpus},
		{
			name: "applying run with active change set",
			journal: func() RemediationJournal {
				value := remediationJournalPreparedCorpus()
				value.ChangeSets[0].State = ChangeApplying
				return value
			},
		},
		{
			name: "canceled run",
			journal: func() RemediationJournal {
				value := journalContractBase()
				value.State = RunCanceled
				return value
			},
		},
	}
	for _, test := range valid {
		test := test
		t.Run("valid/"+test.name, func(t *testing.T) {
			value := test.journal()
			assertRemediationJournalParity(t, schema, value, true)
		})
	}

	invalid := []struct {
		name    string
		journal func() RemediationJournal
	}{
		{
			name: "approved run has change set without approval",
			journal: func() RemediationJournal {
				value := remediationJournalApprovedCorpus()
				value.ChangeSets[0].Approval = nil
				return value
			},
		},
		{
			name: "completed run contains planned change set",
			journal: func() RemediationJournal {
				value := journalContractBase()
				value.State = RunCompleted
				return value
			},
		},
		{
			name: "canceled run contains verified change set",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.State = RunCanceled
				return value
			},
		},
		{
			name: "failed run contains unresolved change set",
			journal: func() RemediationJournal {
				value := journalContractBase()
				value.State = RunFailed
				value.UnresolvedChangeSets = []string{value.ChangeSets[0].ID}
				return value
			},
		},
		{
			name: "rolled-back run has no successful attempt",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				value.RollbackAttempts = nil
				return value
			},
		},
		{
			name: "normal terminal run has incomplete rollback attempt",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.RollbackAttempts = []RollbackAttempt{journalContractIncompleteAttempt("attempt-incomplete")}
				return value
			},
		},
		{
			name: "verified change set has no verification marker",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.ChangeSets[0].VerifiedAt = nil
				return value
			},
		},
		{
			name: "prepared change set has no preparation marker",
			journal: func() RemediationJournal {
				value := remediationJournalPreparedCorpus()
				value.ChangeSets[0].PreparedAt = nil
				return value
			},
		},
		{
			name: "applying change set has no preparation marker",
			journal: func() RemediationJournal {
				value := remediationJournalPreparedCorpus()
				value.ChangeSets[0].State = ChangeApplying
				value.ChangeSets[0].PreparedAt = nil
				return value
			},
		},
		{
			name: "preparation marker has no approval",
			journal: func() RemediationJournal {
				value := remediationJournalPreparedCorpus()
				value.ChangeSets[0].Approval = nil
				return value
			},
		},
		{
			name: "operation apply intent has no change-set preparation marker",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				value.ChangeSets[0].PreparedAt = nil
				return value
			},
		},
		{
			name: "change-set apply marker has no preparation marker",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.State = RunRecoveryRequired
				value.ChangeSets[0].State = ChangeRecoveryRequired
				value.ChangeSets[0].PreparedAt = nil
				return value
			},
		},
		{
			name: "change-set apply marker has operation without apply marker",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				appliedAt := value.UpdatedAt.Add(time.Minute)
				value.ChangeSets[0].AppliedAt = &appliedAt
				return value
			},
		},
		{
			name: "change-set verification marker has no apply marker",
			journal: func() RemediationJournal {
				value := journalContractCompleted()
				value.State = RunRecoveryRequired
				value.ChangeSets[0].State = ChangeRecoveryRequired
				value.ChangeSets[0].AppliedAt = nil
				return value
			},
		},
		{
			name: "rolled-back change set has no rolled-back operation",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				value.ChangeSets[0].Operations[0] = journalContractBase().ChangeSets[0].Operations[0]
				return value
			},
		},
		{
			name: "apply intent has no backup",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				value.ChangeSets[0].Operations[0].Backup = nil
				return value
			},
		},
		{
			name: "apply intent contains completion artifacts",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				appliedAt := value.UpdatedAt.Add(time.Minute)
				observed := journalContractDesired()
				value.ChangeSets[0].Operations[0].AppliedAt = &appliedAt
				value.ChangeSets[0].Operations[0].ObservedAfter = &observed
				return value
			},
		},
		{
			name: "applied operation has no after observation",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				appliedAt := value.UpdatedAt.Add(time.Minute)
				value.ChangeSets[0].Operations[0].State = OperationApplied
				value.ChangeSets[0].Operations[0].AppliedAt = &appliedAt
				return value
			},
		},
		{
			name: "rolled-back operation has no rollback markers",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				value.ChangeSets[0].Operations[0].State = OperationRolledBack
				return value
			},
		},
		{
			name: "failed no-effect operation has no error",
			journal: func() RemediationJournal {
				value := journalContractNoEffectFailure()
				value.ChangeSets[0].Operations[0].Error = nil
				return value
			},
		},
		{
			name: "rollback attempt has outcome before completion",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				attempt := journalContractIncompleteAttempt("attempt-outcome-only")
				attempt.Outcome = RollbackSucceeded
				value.RollbackAttempts = []RollbackAttempt{attempt}
				return value
			},
		},
		{
			name: "rollback attempt completes without outcome",
			journal: func() RemediationJournal {
				value := journalContractRecoveryIntent()
				attempt := journalContractIncompleteAttempt("attempt-completion-only")
				completedAt := attempt.StartedAt.Add(time.Minute)
				attempt.CompletedAt = &completedAt
				value.RollbackAttempts = []RollbackAttempt{attempt}
				return value
			},
		},
	}
	for _, test := range invalid {
		test := test
		t.Run("invalid/"+test.name, func(t *testing.T) {
			value := test.journal()
			assertRemediationJournalParity(t, schema, value, false)
		})
	}
}

func remediationJournalApprovedCorpus() RemediationJournal {
	value := journalContractBase()
	approvedAt := value.StartedAt.Add(30 * time.Second)
	value.State = RunApproved
	value.UpdatedAt = approvedAt
	for index := range value.ChangeSets {
		value.ChangeSets[index].Approval = &Approval{
			Source:     "schema-parity",
			PlanDigest: value.PlanDigest,
			ApprovedAt: approvedAt,
		}
	}
	return value
}

func remediationJournalPreparedCorpus() RemediationJournal {
	value := journalContractBase()
	approvedAt := value.StartedAt.Add(30 * time.Second)
	preparedAt := value.StartedAt.Add(time.Minute)
	changeSet := &value.ChangeSets[0]
	changeSet.State = ChangePrepared
	changeSet.Before = []ResourceSnapshot{journalContractBefore()}
	changeSet.Approval = &Approval{
		Source:     "schema-parity",
		PlanDigest: value.PlanDigest,
		ApprovedAt: approvedAt,
	}
	changeSet.PreparedAt = &preparedAt
	changeSet.Operations[0].Before = journalContractBefore()
	value.State = RunApplying
	value.UpdatedAt = preparedAt
	return value
}

func TestRemediationJournalChronologyRemainsRuntimeOnly(t *testing.T) {
	schema := compileRemediationJournalV4Schema(t)
	tests := []struct {
		name    string
		journal func() RemediationJournal
	}{
		{
			name: "preparation precedes approval",
			journal: func() RemediationJournal {
				value := remediationJournalPreparedCorpus()
				preparedAt := value.ChangeSets[0].Approval.ApprovedAt.Add(-time.Second)
				value.ChangeSets[0].PreparedAt = &preparedAt
				return value
			},
		},
		{
			name: "attempt error follows completion",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				attempt := &value.RollbackAttempts[0]
				attempt.Errors = append(attempt.Errors, *journalContractError("rollback", attempt.CompletedAt.Add(time.Nanosecond)))
				value.UpdatedAt = attempt.Errors[len(attempt.Errors)-1].OccurredAt.Add(time.Nanosecond)
				return value
			},
		},
		{
			name: "rollback attempts overlap",
			journal: func() RemediationJournal {
				value := journalContractRolledBack()
				first := value.RollbackAttempts[0]
				second := first
				second.ID = "attempt-overlap"
				second.StartedAt = first.CompletedAt.Add(-time.Nanosecond)
				secondCompletedAt := first.CompletedAt.Add(time.Nanosecond)
				second.CompletedAt = &secondCompletedAt
				value.RollbackAttempts = []RollbackAttempt{first, second}
				value.UpdatedAt = secondCompletedAt.Add(time.Nanosecond)
				return value
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := test.journal()
			if err := value.Validate(); err == nil {
				t.Fatal("runtime accepted impossible rollback chronology")
			}
			if err := validateRemediationJournalSchema(schema, value); err != nil {
				t.Fatalf("JSON Schema rejected structurally valid chronology-only corpus: %v", err)
			}
		})
	}
}

func TestRemediationJournalCrossReferencesRemainRuntimeOnly(t *testing.T) {
	schema := compileRemediationJournalV4Schema(t)
	value := journalContractCompleted()
	value.Error = journalContractError("verification", value.UpdatedAt)
	value.Error.ChangeSetID = "missing-change"

	runtimeErr := value.Validate()
	if runtimeErr == nil || !strings.Contains(runtimeErr.Error(), "references unknown change set") {
		t.Fatalf("runtime cross-reference error = %v, want unknown change-set rejection", runtimeErr)
	}
	if err := validateRemediationJournalSchema(schema, value); err != nil {
		t.Fatalf("JSON Schema rejected structurally valid cross-reference-only corpus: %v", err)
	}
}

func TestLegacyRemediationJournalRuntimeCompatibilityAndPublicSchemaBoundary(t *testing.T) {
	schema := compileRemediationJournalV4Schema(t)

	tests := []struct {
		name            string
		fixture         string
		wantRunState    RunState
		wantChangeState ChangeSetState
		wantOperation   OperationState
	}{
		{
			name:            "planned status and cancellation input",
			fixture:         "planned.json",
			wantRunState:    RunPlanned,
			wantChangeState: ChangePlanned,
			wantOperation:   OperationPlanned,
		},
		{
			name:            "applied rollback input",
			fixture:         "applied.json",
			wantRunState:    RunApplying,
			wantChangeState: ChangeApplied,
			wantOperation:   OperationApplied,
		},
		{
			name:            "completed rollback history",
			fixture:         "rolled-back.json",
			wantRunState:    RunRolledBack,
			wantChangeState: ChangeRolledBack,
			wantOperation:   OperationRolledBack,
		},
		{
			name:            "interrupted apply recovery input",
			fixture:         "recovery.json",
			wantRunState:    RunApplying,
			wantChangeState: ChangeApplying,
			wantOperation:   OperationApplyIntentDurable,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			data, value := readLegacyV2RemediationJournalFixture(t, test.fixture)
			if err := value.Validate(); err != nil {
				t.Fatalf("legacy v2 runtime Validate() error = %v", err)
			}
			if value.SchemaVersion != legacyRemediationSchemaVersion || value.ScanToolExecutableSHA256 != "" {
				t.Fatalf("legacy fixture schema/digest = %d/%q", value.SchemaVersion, value.ScanToolExecutableSHA256)
			}
			if value.State != test.wantRunState ||
				value.ChangeSets[0].State != test.wantChangeState ||
				value.ChangeSets[0].Operations[0].State != test.wantOperation {
				t.Fatalf(
					"legacy fixture states = %s/%s/%s, want %s/%s/%s",
					value.State,
					value.ChangeSets[0].State,
					value.ChangeSets[0].Operations[0].State,
					test.wantRunState,
					test.wantChangeState,
					test.wantOperation,
				)
			}
			document, err := decodeRemediationJournalJSON(data)
			if err != nil {
				t.Fatalf("decode legacy fixture for public schema error = %v", err)
			}
			if err := schema.Validate(document); err == nil {
				t.Fatal("public v4 schema accepted a legacy v2 journal")
			}
		})
	}
}

func readLegacyV2RemediationJournalFixture(t *testing.T, name string) ([]byte, RemediationJournal) {
	t.Helper()

	data, err := modeltestdata.ReadLegacyV2Journal(name)
	if err != nil {
		t.Fatalf("ReadLegacyV2Journal(%q) error = %v", name, err)
	}
	if bytes.Contains(data, []byte(`"scan_tool_executable_sha256"`)) {
		t.Fatalf("legacy v2 fixture %q contains a v3-only field", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value RemediationJournal
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("Decode(%q) error = %v", name, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("Decode(%q) trailing data error = %v", name, err)
	}
	return data, value
}

func compileRemediationJournalV4Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	return compileRemediationJournalSchema(t, "remediation-journal.schema.json", remediationJournalSchemaResource)
}

func compileRemediationJournalSchema(t *testing.T, name, resource string) *jsonschema.Schema {
	t.Helper()
	schemaPath := filepath.Join("..", "..", "schemas", name)
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", schemaPath, err)
	}
	document, err := decodeRemediationJournalJSON(data)
	if err != nil {
		t.Fatalf("decode remediation journal schema error = %v", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseRegexpEngine(compileRemediationJournalECMARegexp)
	compiler.AssertFormat()
	if err := compiler.AddResource(resource, document); err != nil {
		t.Fatalf("AddResource(remediation journal schema) error = %v", err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatalf("Compile(remediation journal schema) error = %v", err)
	}
	if schema.DraftVersion != 2020 {
		t.Fatalf("compiled remediation journal schema draft = %d, want 2020-12", schema.DraftVersion)
	}
	return schema
}

func assertRemediationJournalParity(t *testing.T, schema *jsonschema.Schema, value RemediationJournal, wantValid bool) {
	t.Helper()

	runtimeErr := value.Validate()
	schemaErr := validateRemediationJournalSchema(schema, value)
	if wantValid {
		if runtimeErr != nil || schemaErr != nil {
			t.Fatalf("valid corpus mismatch: runtime error = %v; schema error = %v", runtimeErr, schemaErr)
		}
		return
	}
	if runtimeErr == nil || schemaErr == nil {
		t.Fatalf("invalid corpus mismatch: runtime error = %v; schema error = %v", runtimeErr, schemaErr)
	}
}

func validateRemediationJournalSchema(schema *jsonschema.Schema, value RemediationJournal) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	document, err := decodeRemediationJournalJSON(data)
	if err != nil {
		return err
	}
	return schema.Validate(document)
}

func decodeRemediationJournalJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

type remediationJournalECMARegexp regexp2.Regexp

func (regexp *remediationJournalECMARegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(regexp).MatchString(value)
	return err == nil && matched
}

func (regexp *remediationJournalECMARegexp) String() string {
	return (*regexp2.Regexp)(regexp).String()
}

func compileRemediationJournalECMARegexp(pattern string) (jsonschema.Regexp, error) {
	regexp, err := regexp2.Compile(pattern, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return (*remediationJournalECMARegexp)(regexp), nil
}
