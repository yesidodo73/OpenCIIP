package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	modeltestdata "github.com/yesidodo73/OpenCIIP/internal/model/testdata"
)

func TestLegacyV2JournalSupportsRollbackExecution(t *testing.T) {
	value := readFrozenLegacyV2Journal(t, "applied.json")
	fixture := newRollbackCrashCutFixture(t, value)

	preview, err := fixture.manager.PreviewRollbackItem(context.Background(), value.RunID, "change-a")
	if err != nil {
		t.Fatalf("PreviewRollbackItem(legacy v2) error = %v", err)
	}
	attempt, err := fixture.manager.RollbackItem(
		context.Background(),
		value.RunID,
		"change-a",
		false,
		preview.PreviewDigest, faultUserRollbackBuild())

	if err != nil {
		t.Fatalf("RollbackItem(legacy v2) error = %v", err)
	}
	if attempt.Outcome != model.RollbackSucceeded || fixture.harness.state.State != model.RunRolledBack {
		t.Fatalf("legacy v2 rollback outcome/state = %s/%s, want %s/%s", attempt.Outcome, fixture.harness.state.State, model.RollbackSucceeded, model.RunRolledBack)
	}
	if fixture.harness.state.SchemaVersion != 2 {
		t.Fatalf("legacy rollback changed schema version to %d", fixture.harness.state.SchemaVersion)
	}
	if attempt.ExecutorBuild != nil || attempt.ObservedByBuild != nil {
		t.Fatalf("legacy rollback persisted v3 provenance: executor=%#v observer=%#v", attempt.ExecutorBuild, attempt.ObservedByBuild)
	}
	assertLegacyV2RollbackProvenanceEmpty(t, fixture.harness.state)
	assertRollbackCrashCutLiveState(t, fixture, fixture.before)
}

func TestLegacyV2JournalSupportsReadOnlyRecovery(t *testing.T) {
	value := readFrozenLegacyV2Journal(t, "recovery.json")
	harness := newFaultStoreHarness(t, value)
	before := faultCloneSnapshot(value.ChangeSets[0].Operations[0].Before)
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			return faultCloneSnapshot(before), nil
		},
		restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
			t.Fatal("Recover(legacy v2) attempted a target restore")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, []string{"legacy-recovery"})

	assessment, err := manager.Recover(context.Background(), value.RunID, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("Recover(legacy v2) error = %v", err)
	}
	if assessment.AutomaticRollbackPossible {
		t.Fatal("legacy no-effect recovery reported automatic rollback work")
	}
	if harness.state.State != model.RunFailed || harness.state.ChangeSets[0].Operations[0].State != model.OperationFailed {
		t.Fatalf("legacy no-effect recovery state = %s/%s, want %s/%s", harness.state.State, harness.state.ChangeSets[0].Operations[0].State, model.RunFailed, model.OperationFailed)
	}
	if harness.state.SchemaVersion != 2 {
		t.Fatalf("legacy recovery changed schema version to %d", harness.state.SchemaVersion)
	}
	assertLegacyV2RollbackProvenanceEmpty(t, harness.state)
	if len(runtime.mutationCalls) != 0 {
		t.Fatalf("Recover(legacy v2) mutated target resources: %v", runtime.mutationCalls)
	}
}

func TestLegacyV2PlannedJournalSupportsStatusAndCancellation(t *testing.T) {
	value := readFrozenLegacyV2Journal(t, "planned.json")
	harness := newFaultStoreHarness(t, value)
	content := &faultContentStore{}
	manager := newFaultManagerWithContent(t, harness, nil, content, nil)

	loaded, err := manager.loadAndVerifyReadOnly(context.Background(), value.RunID)
	if err != nil {
		t.Fatalf("loadAndVerifyReadOnly(frozen legacy v2 plan) error = %v", err)
	}
	if loaded.SchemaVersion != 2 || loaded.State != model.RunPlanned {
		t.Fatalf("legacy status schema/state = %d/%s, want 2/%s", loaded.SchemaVersion, loaded.State, model.RunPlanned)
	}

	approval := model.Approval{
		Source:     "legacy-compatibility-test",
		PlanDigest: value.PlanDigest,
		ApprovedAt: value.UpdatedAt.Add(time.Minute),
	}
	if err := manager.Approve(context.Background(), value.RunID, approval); CodeOf(err) != CodeUnsupportedOperation {
		t.Fatalf("Approve(frozen legacy v2 plan) error = %v, want %s", err, CodeUnsupportedOperation)
	}
	if err := manager.Cancel(context.Background(), value.RunID); err != nil {
		t.Fatalf("Cancel(frozen legacy v2 plan) error = %v", err)
	}
	if harness.state.SchemaVersion != 2 || harness.state.State != model.RunCanceled {
		t.Fatalf("legacy cancellation schema/state = %d/%s, want 2/%s", harness.state.SchemaVersion, harness.state.State, model.RunCanceled)
	}
	if len(content.deleted) != 1 || content.deleted[0] != value.RunID {
		t.Fatalf("legacy cancellation deleted runs = %v, want [%s]", content.deleted, value.RunID)
	}
}

func TestLegacyV2RolledBackJournalSupportsStatus(t *testing.T) {
	value := readFrozenLegacyV2Journal(t, "rolled-back.json")
	harness := newFaultStoreHarness(t, value)
	manager := newFaultManager(t, harness, nil, nil)

	loaded, err := manager.loadAndVerifyReadOnly(context.Background(), value.RunID)
	if err != nil {
		t.Fatalf("loadAndVerifyReadOnly(frozen legacy v2 rolled-back journal) error = %v", err)
	}
	if loaded.SchemaVersion != 2 || loaded.State != model.RunRolledBack {
		t.Fatalf("legacy status schema/state = %d/%s, want 2/%s", loaded.SchemaVersion, loaded.State, model.RunRolledBack)
	}
}

func readFrozenLegacyV2Journal(t *testing.T, name string) *model.RemediationJournal {
	t.Helper()
	data, err := modeltestdata.ReadLegacyV2Journal(name)
	if err != nil {
		t.Fatalf("ReadLegacyV2Journal(%s) error = %v", name, err)
	}
	if bytes.Contains(data, []byte(`"scan_tool_executable_sha256"`)) {
		t.Fatalf("legacy v2 fixture %s contains a v3-only field", name)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value model.RemediationJournal
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("Decode(%s) error = %v", name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("Decode(%s) trailing data error = %v", name, err)
	}
	if value.SchemaVersion != 2 {
		t.Fatalf("legacy fixture %s schema_version = %d, want 2", name, value.SchemaVersion)
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("legacy fixture %s Validate() error = %v", name, err)
	}
	assertLegacyV2RollbackProvenanceEmpty(t, &value)
	return &value
}

func assertLegacyV2RollbackProvenanceEmpty(t *testing.T, value *model.RemediationJournal) {
	t.Helper()
	for _, attempt := range value.RollbackAttempts {
		if attempt.ExecutorBuild != nil || attempt.ObservedByBuild != nil {
			t.Fatalf(
				"legacy v2 rollback attempt %s contains v3 provenance: executor=%#v observer=%#v",
				attempt.ID,
				attempt.ExecutorBuild,
				attempt.ObservedByBuild,
			)
		}
	}
}
