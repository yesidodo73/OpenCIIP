package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	journalpkg "github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
)

func TestValidatePlanRequestRequiresMatchingScanExecutableIdentity(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("6", 64)
	base := PlanRequest{
		ScanRunID:                "scan-plan-contract",
		ScanToolVersion:          "0.1.0-alpha.36",
		ScanToolCommit:           "commit-plan-contract",
		ScanToolExecutableSHA256: digest,
		RuleSetVersion:           "sha256:" + strings.Repeat("5", 64),
		Platform: model.PlatformInfo{
			ScanSupport:        model.ScanSupportTested,
			RemediationSupport: model.RemediationSupportVerified,
		},
		RemediationBuild: model.RemediationBuildIdentity{
			Version:          "0.1.0-alpha.36",
			Commit:           "commit-plan-contract",
			ExecutableSHA256: digest,
		},
		FailurePolicy: model.FailureRollbackItem,
		ChangeSets:    []model.ChangeSet{{ID: "change-plan-contract"}},
	}
	if err := validatePlanRequest(base); err != nil {
		t.Fatalf("validatePlanRequest() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PlanRequest)
	}{
		{
			name: "legacy schema",
			mutate: func(request *PlanRequest) {
				request.SchemaVersion = 2
			},
		},
		{
			name: "missing digest",
			mutate: func(request *PlanRequest) {
				request.ScanToolExecutableSHA256 = ""
			},
		},
		{
			name: "different digest",
			mutate: func(request *PlanRequest) {
				request.ScanToolExecutableSHA256 = strings.Repeat("9", 64)
			},
		},
		{
			name: "different version",
			mutate: func(request *PlanRequest) {
				request.ScanToolVersion = "0.1.0-alpha.35"
			},
		},
		{
			name: "different commit",
			mutate: func(request *PlanRequest) {
				request.ScanToolCommit = "different-commit"
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := base
			test.mutate(&request)
			if err := validatePlanRequest(request); err == nil {
				t.Fatal("validatePlanRequest() error = nil, want rejection")
			}
		})
	}
}

func TestPlanDigestBindsScanExecutableIdentityAndPreservesLegacyShape(t *testing.T) {
	t.Parallel()

	value := faultJournalSkeleton(1, false)
	request := PlanRequest{
		ScanRunID:                value.ScanRunID,
		ScanToolVersion:          value.ScanToolVersion,
		ScanToolCommit:           value.ScanToolCommit,
		ScanToolExecutableSHA256: value.ScanToolExecutableSHA256,
		RuleSetVersion:           value.RuleSetVersion,
		Platform:                 value.Platform,
		RemediationBuild:         value.RemediationBuild,
		FailurePolicy:            value.FailurePolicy,
	}
	first, err := digestPlan(value.RunID, request, value.Host, value.ChangeSets, value.ConflictGraph)
	if err != nil {
		t.Fatalf("digestPlan() error = %v", err)
	}
	request.ScanToolExecutableSHA256 = strings.Repeat("9", 64)
	request.RemediationBuild.ExecutableSHA256 = strings.Repeat("9", 64)
	second, err := digestPlan(value.RunID, request, value.Host, value.ChangeSets, value.ConflictGraph)
	if err != nil {
		t.Fatalf("digestPlan(changed identity) error = %v", err)
	}
	if first == second {
		t.Fatal("plan digest did not bind the scan executable identity")
	}

	legacyRequest := PlanRequest{
		SchemaVersion:    2,
		ScanRunID:        value.ScanRunID,
		ScanToolVersion:  value.ScanToolVersion,
		ScanToolCommit:   value.ScanToolCommit,
		RuleSetVersion:   value.RuleSetVersion,
		Platform:         value.Platform,
		RemediationBuild: value.RemediationBuild,
		FailurePolicy:    value.FailurePolicy,
	}
	legacyDigest, err := digestPlan(value.RunID, legacyRequest, value.Host, nil, model.ConflictGraph{})
	if err != nil {
		t.Fatalf("digestPlan(legacy) error = %v", err)
	}
	legacyExpected, err := journalpkg.Digest(struct {
		SchemaVersion    int                            `json:"schema_version"`
		RunID            string                         `json:"run_id"`
		ScanRunID        string                         `json:"scan_run_id"`
		ScanToolVersion  string                         `json:"scan_tool_version"`
		ScanToolCommit   string                         `json:"scan_tool_commit"`
		RuleSetVersion   string                         `json:"rule_set_version"`
		Platform         model.PlatformInfo             `json:"platform"`
		RemediationBuild model.RemediationBuildIdentity `json:"remediation_build"`
		FailurePolicy    model.FailurePolicy            `json:"failure_policy"`
		Host             model.HostIdentity             `json:"host"`
		ChangeSets       []planChangeSet                `json:"change_sets"`
		ConflictGraph    model.ConflictGraph            `json:"conflict_graph"`
	}{
		SchemaVersion:    2,
		RunID:            value.RunID,
		ScanRunID:        value.ScanRunID,
		ScanToolVersion:  value.ScanToolVersion,
		ScanToolCommit:   value.ScanToolCommit,
		RuleSetVersion:   value.RuleSetVersion,
		Platform:         value.Platform,
		RemediationBuild: value.RemediationBuild,
		FailurePolicy:    value.FailurePolicy,
		Host:             value.Host,
		ChangeSets:       []planChangeSet{},
		ConflictGraph:    model.ConflictGraph{},
	})
	if err != nil {
		t.Fatalf("Digest(legacy shape) error = %v", err)
	}
	if legacyDigest != legacyExpected {
		t.Fatalf("legacy digest = %q, want old-shape digest %q", legacyDigest, legacyExpected)
	}

	legacyPayload, err := journalpkg.CanonicalJSON(planPayload{
		SchemaVersion:   2,
		RunID:           value.RunID,
		ScanRunID:       value.ScanRunID,
		ScanToolVersion: value.ScanToolVersion,
		ScanToolCommit:  value.ScanToolCommit,
	})
	if err != nil {
		t.Fatalf("CanonicalJSON(legacy payload) error = %v", err)
	}
	if bytes.Contains(legacyPayload, []byte("scan_tool_executable_sha256")) {
		t.Fatalf("legacy payload unexpectedly contains the v3 field: %s", legacyPayload)
	}
}

func TestLegacyPlanCanLoadAndCancelButCannotBeApproved(t *testing.T) {
	value := faultJournalSkeleton(1, false)
	value.SchemaVersion = 2
	value.ScanToolExecutableSHA256 = ""
	faultSealJournal(t, value)
	harness := newFaultStoreHarness(t, value)
	content := &faultContentStore{}
	manager := newFaultManagerWithContent(t, harness, nil, content, nil)

	if _, err := manager.loadAndVerifyReadOnly(context.Background(), value.RunID); err != nil {
		t.Fatalf("loadAndVerifyReadOnly(legacy) error = %v", err)
	}
	approval := model.Approval{
		Source:     "legacy-contract-test",
		PlanDigest: value.PlanDigest,
		ApprovedAt: faultBaseTime().Add(time.Minute),
	}
	if err := manager.Approve(context.Background(), value.RunID, approval); CodeOf(err) != CodeUnsupportedOperation {
		t.Fatalf("Approve(legacy) error = %v, want %s", err, CodeUnsupportedOperation)
	}
	if err := manager.Cancel(context.Background(), value.RunID); err != nil {
		t.Fatalf("Cancel(legacy) error = %v", err)
	}
	if harness.state.State != model.RunCanceled || harness.state.SchemaVersion != 2 {
		t.Fatalf("legacy cancellation state = %s schema=%d, want canceled schema 2", harness.state.State, harness.state.SchemaVersion)
	}
	if !reflect.DeepEqual(content.deleted, []string{value.RunID}) {
		t.Fatalf("deleted content runs = %v, want [%s]", content.deleted, value.RunID)
	}
}

func TestLegacyApprovedPlanCannotBypassApplyGuard(t *testing.T) {
	value := faultJournalSkeleton(1, false)
	value.SchemaVersion = 2
	value.ScanToolExecutableSHA256 = ""
	faultSealJournal(t, value)
	value.State = model.RunApproved
	approval := model.Approval{
		Source:     "legacy-contract-test",
		PlanDigest: value.PlanDigest,
		ApprovedAt: faultBaseTime().Add(time.Minute),
	}
	for index := range value.ChangeSets {
		copy := approval
		value.ChangeSets[index].Approval = &copy
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("legacy approved journal Validate() error = %v", err)
	}
	harness := newFaultStoreHarness(t, value)
	manager := newFaultManager(t, harness, nil, nil)
	runGuardCalled := false
	effectGuardCalled := false
	err := manager.ApplyWithVerifier(
		context.Background(),
		value.RunID,
		func(context.Context, *model.RemediationJournal) error {
			runGuardCalled = true
			return nil
		},
		func(context.Context, *model.RemediationJournal, string, string) error {
			effectGuardCalled = true
			return nil
		},
		func(context.Context, *model.RemediationJournal, []string) ([]string, error) {
			t.Fatal("verifier was called for a legacy plan")
			return nil, nil
		},
	)
	if CodeOf(err) != CodeUnsupportedOperation {
		t.Fatalf("ApplyWithVerifier(legacy) error = %v, want %s", err, CodeUnsupportedOperation)
	}
	if runGuardCalled || effectGuardCalled {
		t.Fatal("caller guards were invoked before the manager rejected a legacy plan")
	}
	if faultUpdateCallCount(harness.storeCalls) != 0 {
		t.Fatalf("legacy apply wrote journal state: %v", harness.storeCalls)
	}
}

func TestApplyWithVerifierRequiresRunEffectAndVerificationCallbacks(t *testing.T) {
	t.Parallel()

	runGuard := func(context.Context, *model.RemediationJournal) error { return nil }
	effectGuard := func(context.Context, *model.RemediationJournal, string, string) error { return nil }
	verifier := func(context.Context, *model.RemediationJournal, []string) ([]string, error) { return nil, nil }
	tests := []struct {
		name        string
		runGuard    ApplyRunGuard
		effectGuard ApplyEffectGuard
		verifier    ApplyVerifier
	}{
		{name: "missing run guard", effectGuard: effectGuard, verifier: verifier},
		{name: "missing effect guard", runGuard: runGuard, verifier: verifier},
		{name: "missing verifier", runGuard: runGuard, effectGuard: effectGuard},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := (&Manager{}).ApplyWithVerifier(
				context.Background(),
				"run-callback-contract",
				test.runGuard,
				test.effectGuard,
				test.verifier,
			)
			if CodeOf(err) != CodeInvalidInput {
				t.Fatalf("ApplyWithVerifier() error = %v, want %s", err, CodeInvalidInput)
			}
		})
	}
}

func TestApplyOperationPersistsVerifiedBackupAndIntentBeforeSideEffect(t *testing.T) {
	value := faultPlannedJournal(t)
	harness := newFaultStoreHarness(t, value)
	before := value.ChangeSets[0].Operations[0].ExpectedBefore
	desired := value.ChangeSets[0].Operations[0].Desired
	captureCount := 0
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			harness.events = append(harness.events, "runtime:capture")
			captureCount++
			if captureCount == 4 {
				return desired, nil
			}
			return before, nil
		},
		backup: func(context.Context, string, string, model.CanonicalResource, model.ResourceSnapshot) (model.BackupArtifact, error) {
			harness.events = append(harness.events, "runtime:backup")
			return faultBackup("backup-a"), nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error {
			harness.events = append(harness.events, "runtime:verify_backup")
			return nil
		},
		applyMetadata: func(context.Context, model.CanonicalResource, model.ResourceSnapshot, model.ResourceSnapshot) (model.ResourceSnapshot, error) {
			harness.events = append(harness.events, "runtime:apply")
			return desired, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, nil)

	prepared, err := manager.prepareChangeSet(context.Background(), harness.state, runtime, "change-a")
	if err != nil {
		t.Fatalf("prepareChangeSet() error = %v", err)
	}
	applying, err := manager.update(context.Background(), prepared, "start fault-fixture change set apply", func(next *model.RemediationJournal) error {
		next.ChangeSets[0].State = model.ChangeApplying
		return nil
	})
	if err != nil {
		t.Fatalf("start change-set apply Update() error = %v", err)
	}
	applied, err := manager.applyOperation(
		context.Background(),
		applying,
		runtime,
		func(_ context.Context, _ *model.RemediationJournal, changeSetID, operationID string) error {
			harness.events = append(harness.events, "guard:"+changeSetID+"/"+operationID)
			return nil
		},
		"change-a",
		"operation-a",
	)
	if err != nil {
		t.Fatalf("applyOperation() error = %v", err)
	}
	if err := applied.Validate(); err != nil {
		t.Fatalf("applied fixture Validate() error = %v", err)
	}
	operation, _, _, err := findOperation(applied, "change-a", "operation-a")
	if err != nil {
		t.Fatalf("findOperation() error = %v", err)
	}
	if operation.State != model.OperationApplied || operation.ApplyIntentAt == nil || operation.Backup == nil {
		t.Fatalf("applied operation lost durable intent or backup: %#v", operation)
	}

	wantEvents := []string{
		"runtime:capture",
		"runtime:backup",
		"runtime:verify_backup",
		"runtime:capture",
		"store:update:prepared",
		"store:update:change_applying",
		"runtime:capture",
		"runtime:verify_backup",
		"guard:change-a/operation-a",
		"store:update:apply_intent",
		"runtime:apply",
		"runtime:capture",
		"store:update:applied",
	}
	if !reflect.DeepEqual(harness.events, wantEvents) {
		t.Fatalf("effect-boundary events = %v, want %v", harness.events, wantEvents)
	}
	if wantStoreCalls := []string{"update:prepared", "update:change_applying", "update:apply_intent", "update:applied"}; !reflect.DeepEqual(harness.storeCalls, wantStoreCalls) {
		t.Fatalf("scriptedJournalStore calls = %v, want %v", harness.storeCalls, wantStoreCalls)
	}
}

func TestApplyOperationDoesNotMutateWhenIntentUpdateFails(t *testing.T) {
	value := faultPreparedJournal(t)
	harness := newFaultStoreHarness(t, value)
	persistErr := errors.New("injected apply-intent WAL sync failure")
	harness.rejectUpdate = func(label string, _ *model.RemediationJournal) error {
		if label == "apply_intent" {
			return persistErr
		}
		return nil
	}
	before := value.ChangeSets[0].Operations[0].Before
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			harness.events = append(harness.events, "runtime:capture")
			return before, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error {
			harness.events = append(harness.events, "runtime:verify_backup")
			return nil
		},
		applyMetadata: func(context.Context, model.CanonicalResource, model.ResourceSnapshot, model.ResourceSnapshot) (model.ResourceSnapshot, error) {
			t.Fatal("ApplyMetadata() was called after apply-intent persistence failed")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, nil)

	current := harness.state
	next, err := manager.applyOperation(
		context.Background(),
		current,
		runtime,
		func(context.Context, *model.RemediationJournal, string, string) error {
			harness.events = append(harness.events, "guard:effect")
			return nil
		},
		"change-a",
		"operation-a",
	)
	if CodeOf(err) != CodePersistFailed {
		t.Fatalf("applyOperation() error = %v, want %s", err, CodePersistFailed)
	}
	if next != current {
		t.Fatal("applyOperation() replaced the caller's journal after a failed intent update")
	}
	if len(runtime.mutationCalls) != 0 {
		t.Fatalf("mutation calls = %v, want none", runtime.mutationCalls)
	}
	operation, _, _, findErr := findOperation(harness.state, "change-a", "operation-a")
	if findErr != nil {
		t.Fatalf("findOperation() error = %v", findErr)
	}
	if operation.State != model.OperationPlanned || operation.ApplyIntentAt != nil {
		t.Fatalf("durable state changed after rejected intent update: %#v", operation)
	}
	if want := []string{"runtime:capture", "runtime:verify_backup", "guard:effect", "store:update:apply_intent"}; !reflect.DeepEqual(harness.events, want) {
		t.Fatalf("events = %v, want %v", harness.events, want)
	}
}

func TestApplyOperationDoesNotPersistIntentOrMutateWhenEffectGuardFails(t *testing.T) {
	value := faultPreparedJournal(t)
	harness := newFaultStoreHarness(t, value)
	before := value.ChangeSets[0].Operations[0].Before
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			harness.events = append(harness.events, "runtime:capture")
			return before, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error {
			harness.events = append(harness.events, "runtime:verify_backup")
			return nil
		},
		applyMetadata: func(context.Context, model.CanonicalResource, model.ResourceSnapshot, model.ResourceSnapshot) (model.ResourceSnapshot, error) {
			t.Fatal("ApplyMetadata() was called after the fresh effect guard failed")
			return model.ResourceSnapshot{}, nil
		},
	}
	manager := newFaultManager(t, harness, runtime, nil)
	guardErr := errors.New("fresh evaluator is no longer FAIL")

	current := harness.state
	next, err := manager.applyOperation(
		context.Background(),
		current,
		runtime,
		func(_ context.Context, journal *model.RemediationJournal, changeSetID, operationID string) error {
			harness.events = append(harness.events, "guard:"+changeSetID+"/"+operationID)
			operation, _, _, findErr := findOperation(journal, changeSetID, operationID)
			if findErr != nil {
				return findErr
			}
			if operation.ApplyIntentAt != nil || operation.Backup == nil || operation.Before.IsZero() {
				return fmt.Errorf("effect guard did not observe a prepared pre-intent operation")
			}
			return guardErr
		},
		"change-a",
		"operation-a",
	)
	if CodeOf(err) != CodePreconditionFailed || !errors.Is(err, guardErr) {
		t.Fatalf("applyOperation() error = %v, want %s wrapping guard failure", err, CodePreconditionFailed)
	}
	if next != current {
		t.Fatal("applyOperation() replaced the caller's journal after a rejected effect gate")
	}
	if len(runtime.mutationCalls) != 0 {
		t.Fatalf("mutation calls = %v, want none", runtime.mutationCalls)
	}
	if len(harness.storeCalls) != 0 {
		t.Fatalf("journal writes = %v, want none after effect guard failure", harness.storeCalls)
	}
	if want := []string{"runtime:capture", "runtime:verify_backup", "guard:change-a/operation-a"}; !reflect.DeepEqual(harness.events, want) {
		t.Fatalf("events = %v, want %v", harness.events, want)
	}
}

func TestCommittedApplyErrorWithAmbiguousObservationRequiresRecovery(t *testing.T) {
	value := faultPreparedJournal(t)
	harness := newFaultStoreHarness(t, value)
	before := value.ChangeSets[0].Operations[0].Before
	desired := value.ChangeSets[0].Operations[0].Desired
	partial := faultCloneSnapshot(desired)
	partial.Fingerprint = strings.Repeat("f", 64)
	captureCount := 0
	committedErr := &regularfile.Error{
		Code:      regularfile.CodePostconditionFailed,
		Operation: "apply metadata",
		Path:      "/etc/open-ciip-a",
		Committed: true,
		Err:       errors.New("injected ambiguous metadata result"),
	}
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			harness.events = append(harness.events, "runtime:capture")
			captureCount++
			if captureCount == 1 {
				return before, nil
			}
			return partial, nil
		},
		verifyBackup: func(context.Context, model.BackupArtifact) error {
			harness.events = append(harness.events, "runtime:verify_backup")
			return nil
		},
		applyMetadata: func(context.Context, model.CanonicalResource, model.ResourceSnapshot, model.ResourceSnapshot) (model.ResourceSnapshot, error) {
			harness.events = append(harness.events, "runtime:apply")
			return model.ResourceSnapshot{}, committedErr
		},
	}
	manager := newFaultManager(t, harness, runtime, nil)

	next, err := manager.applyOperation(
		context.Background(),
		harness.state,
		runtime,
		func(context.Context, *model.RemediationJournal, string, string) error {
			harness.events = append(harness.events, "guard:effect")
			return nil
		},
		"change-a",
		"operation-a",
	)
	if CodeOf(err) != CodeRecoveryRequired {
		t.Fatalf("applyOperation() error = %v, want %s", err, CodeRecoveryRequired)
	}
	if next == nil || next.State != model.RunRecoveryRequired {
		t.Fatalf("journal state = %#v, want recovery required", next)
	}
	if err := next.Validate(); err != nil {
		t.Fatalf("recovery fixture Validate() error = %v", err)
	}
	changeSet, _, findErr := findChangeSet(next, "change-a")
	if findErr != nil {
		t.Fatalf("findChangeSet() error = %v", findErr)
	}
	operation, _, _, findErr := findOperation(next, "change-a", "operation-a")
	if findErr != nil {
		t.Fatalf("findOperation() error = %v", findErr)
	}
	if changeSet.State != model.ChangeRecoveryRequired || operation.State != model.OperationAmbiguous {
		t.Fatalf("ambiguous effect was promoted: change=%s operation=%s", changeSet.State, operation.State)
	}
	if operation.ApplyIntentAt == nil || operation.Backup == nil || operation.Error == nil || operation.Error.Code != model.JournalErrorRecoveryAmbiguous {
		t.Fatalf("ambiguous operation lost intent, backup, or error evidence: %#v", operation)
	}
	if len(next.UnresolvedChangeSets) != 1 || next.UnresolvedChangeSets[0] != "change-a" {
		t.Fatalf("unresolved change sets = %v", next.UnresolvedChangeSets)
	}
	if want := []string{
		"runtime:capture",
		"runtime:verify_backup",
		"guard:effect",
		"store:update:apply_intent",
		"runtime:apply",
		"runtime:capture",
		"store:update:ambiguous",
	}; !reflect.DeepEqual(harness.events, want) {
		t.Fatalf("events = %v, want %v", harness.events, want)
	}
}

func TestEvaluatorFailureSelectsRollbackScopeFromFailurePolicy(t *testing.T) {
	tests := []struct {
		name         string
		policy       model.FailurePolicy
		wantScope    model.RollbackScope
		wantExpanded []string
		wantCaptures int
	}{
		{
			name:         "item policy",
			policy:       model.FailureRollbackItem,
			wantScope:    model.RollbackItem,
			wantExpanded: []string{"change-b"},
			wantCaptures: 1,
		},
		{
			name:         "run policy",
			policy:       model.FailureRollbackRun,
			wantScope:    model.RollbackRun,
			wantExpanded: []string{"change-b", "change-a"},
			wantCaptures: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := faultVerifiedJournal(t, 2, false, test.policy, model.RunVerifying)
			harness := newFaultStoreHarness(t, value)
			stopErr := errors.New("stop after durable rollback scope capture")
			harness.rejectUpdate = func(label string, _ *model.RemediationJournal) error {
				if label == "rollback_attempt" {
					return stopErr
				}
				return nil
			}
			desired := make(map[string]model.ResourceSnapshot)
			for _, changeSet := range value.ChangeSets {
				for _, operation := range changeSet.Operations {
					desired[operation.Resource.Key] = operation.Desired
				}
			}
			runtime := &scriptedFileRuntime{
				capture: func(_ context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
					return desired[resource.Key], nil
				},
				verifyBackup: func(context.Context, model.BackupArtifact) error { return nil },
				restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
					t.Fatal("Restore() was called before rollback scope persistence completed")
					return model.ResourceSnapshot{}, nil
				},
			}
			manager := newFaultManager(t, harness, runtime, []string{"001"})

			err := manager.rollbackVerificationFailureLocked(
				context.Background(),
				harness.state,
				[]string{"change-b"},
				errors.New("injected evaluator postcondition failure"),
				false,
			)
			if err == nil {
				t.Fatal("rollbackVerificationFailureLocked() unexpectedly succeeded after injected journal failure")
			}
			if harness.rejectedCandidate == nil || len(harness.rejectedCandidate.RollbackAttempts) != 1 {
				t.Fatalf("rejected durable scope candidate = %#v", harness.rejectedCandidate)
			}
			attempt := harness.rejectedCandidate.RollbackAttempts[0]
			if attempt.Scope != test.wantScope || !reflect.DeepEqual(attempt.ExpandedChangeSets, test.wantExpanded) {
				t.Fatalf("rollback attempt scope=%s expanded=%v, want scope=%s expanded=%v", attempt.Scope, attempt.ExpandedChangeSets, test.wantScope, test.wantExpanded)
			}
			if attempt.Trigger != model.RollbackVerifyFailure || !reflect.DeepEqual(attempt.RequestedChangeSets, []string{"change-b"}) {
				t.Fatalf("rollback trigger/request = %s/%v", attempt.Trigger, attempt.RequestedChangeSets)
			}
			if err := harness.rejectedCandidate.Validate(); err != nil {
				t.Fatalf("rollback scope candidate Validate() error = %v", err)
			}
			if len(runtime.captureCalls) != test.wantCaptures {
				t.Fatalf("preflight capture calls = %v, want %d", runtime.captureCalls, test.wantCaptures)
			}
			if len(runtime.mutationCalls) != 0 {
				t.Fatalf("mutation calls = %v, want none", runtime.mutationCalls)
			}
			if wantCalls := []string{"update:verification_failure", "update:rollback_attempt"}; !reflect.DeepEqual(harness.storeCalls, wantCalls) {
				t.Fatalf("scriptedJournalStore calls = %v, want %v", harness.storeCalls, wantCalls)
			}
		})
	}
}

func TestRollbackItemRejectsStaleDigestAndUnapprovedCascadeBeforeRestore(t *testing.T) {
	t.Run("stale preview digest", func(t *testing.T) {
		value := faultVerifiedJournal(t, 1, false, model.FailureRollbackItem, model.RunCompleted)
		harness := newFaultStoreHarness(t, value)
		runtime := &scriptedFileRuntime{
			restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
				t.Fatal("Restore() was called with a stale rollback preview digest")
				return model.ResourceSnapshot{}, nil
			},
		}
		manager := newFaultManager(t, harness, runtime, nil)

		_, err := manager.RollbackItem(context.Background(), value.RunID, "change-a", false, strings.Repeat("0", 64), faultUserRollbackBuild())
		if CodeOf(err) != CodeRollbackPreviewStale {
			t.Fatalf("RollbackItem() error = %v, want %s", err, CodeRollbackPreviewStale)
		}
		if len(runtime.mutationCalls) != 0 || faultUpdateCallCount(harness.storeCalls) != 0 {
			t.Fatalf("stale preview caused effects: mutations=%v storeCalls=%v", runtime.mutationCalls, harness.storeCalls)
		}
	})

	t.Run("cascade not approved", func(t *testing.T) {
		value := faultVerifiedJournal(t, 2, true, model.FailureRollbackItem, model.RunCompleted)
		harness := newFaultStoreHarness(t, value)
		runtime := &scriptedFileRuntime{
			restore: func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error) {
				t.Fatal("Restore() was called without cascade approval")
				return model.ResourceSnapshot{}, nil
			},
		}
		manager := newFaultManager(t, harness, runtime, nil)
		preview, err := manager.previewRollbackItem(value, "change-a")
		if err != nil {
			t.Fatalf("previewRollbackItem() error = %v", err)
		}
		if !preview.CascadeRequired || !reflect.DeepEqual(preview.ExpandedChangeSets, []string{"change-a", "change-b"}) {
			t.Fatalf("cascade preview = required:%t expanded:%v", preview.CascadeRequired, preview.ExpandedChangeSets)
		}

		_, err = manager.RollbackItem(context.Background(), value.RunID, "change-a", false, preview.PreviewDigest, faultUserRollbackBuild())
		if CodeOf(err) != CodeCascadeRequired {
			t.Fatalf("RollbackItem() error = %v, want %s", err, CodeCascadeRequired)
		}
		if len(runtime.mutationCalls) != 0 || faultUpdateCallCount(harness.storeCalls) != 0 {
			t.Fatalf("unapproved cascade caused effects: mutations=%v storeCalls=%v", runtime.mutationCalls, harness.storeCalls)
		}
	})
}

type faultStoreHarness struct {
	testing           *testing.T
	store             *scriptedJournalStore
	state             *model.RemediationJournal
	events            []string
	storeCalls        []string
	rejectUpdate      func(string, *model.RemediationJournal) error
	lastCandidate     *model.RemediationJournal
	rejectedCandidate *model.RemediationJournal
}

type faultContentStore struct {
	deleted []string
}

func (*faultContentStore) Content(context.Context, string, string, string) ([]byte, error) {
	return nil, nil
}

func (store *faultContentStore) DeleteRunContent(_ context.Context, runID string) error {
	store.deleted = append(store.deleted, runID)
	return nil
}

func newFaultStoreHarness(t *testing.T, value *model.RemediationJournal) *faultStoreHarness {
	t.Helper()
	if value == nil {
		t.Fatal("fault journal fixture is nil")
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("fault journal fixture Validate() error = %v", err)
	}
	harness := &faultStoreHarness{testing: t, state: faultCloneJournal(t, value)}
	store := &scriptedJournalStore{root: t.TempDir()}
	harness.store = store
	store.load = func(context.Context, string) (*model.RemediationJournal, error) {
		harness.storeCalls = append(harness.storeCalls, "load")
		return faultCloneJournal(t, harness.state), nil
	}
	store.inspect = func(context.Context, string) (journalpkg.Inspection, error) {
		harness.storeCalls = append(harness.storeCalls, "inspect")
		return journalpkg.Inspection{Journal: faultCloneJournal(t, harness.state)}, nil
	}
	store.recoverable = func(context.Context) ([]model.RemediationJournal, error) {
		harness.storeCalls = append(harness.storeCalls, "list_recoverable")
		return nil, nil
	}
	store.update = func(
		_ context.Context,
		runID string,
		expectedRevision uint64,
		mutate func(*model.RemediationJournal) error,
	) (*model.RemediationJournal, error) {
		if runID != harness.state.RunID {
			t.Fatalf("scriptedJournalStore.Update() runID = %q, want %q", runID, harness.state.RunID)
		}
		if expectedRevision != harness.state.Revision {
			t.Fatalf("scriptedJournalStore.Update() revision = %d, want %d", expectedRevision, harness.state.Revision)
		}
		candidate := faultCloneJournal(t, harness.state)
		if err := mutate(candidate); err != nil {
			return nil, err
		}
		candidate.Revision = harness.state.Revision + 1
		updatedAt := harness.state.UpdatedAt.Add(time.Second)
		latestEvent := candidate.LatestEventTime()
		if !updatedAt.After(latestEvent) {
			updatedAt = latestEvent.Add(time.Nanosecond)
		}
		candidate.UpdatedAt = updatedAt
		label := faultUpdateLabel(harness.state, candidate)
		harness.storeCalls = append(harness.storeCalls, "update:"+label)
		harness.events = append(harness.events, "store:update:"+label)
		if err := candidate.Validate(); err != nil {
			t.Fatalf("scriptedJournalStore candidate %q Validate() error = %v", label, err)
		}
		harness.lastCandidate = faultCloneJournal(t, candidate)
		if harness.rejectUpdate != nil {
			if err := harness.rejectUpdate(label, candidate); err != nil {
				harness.rejectedCandidate = faultCloneJournal(t, candidate)
				return nil, err
			}
		}
		harness.state = faultCloneJournal(t, candidate)
		return faultCloneJournal(t, candidate), nil
	}
	return harness
}

func newFaultManager(t *testing.T, harness *faultStoreHarness, runtime fileRuntime, idValues []string) *Manager {
	return newFaultManagerWithContent(t, harness, runtime, nil, idValues)
}

func newFaultManagerWithContent(
	t *testing.T,
	harness *faultStoreHarness,
	runtime fileRuntime,
	content FileContentSource,
	idValues []string,
) *Manager {
	t.Helper()
	if len(idValues) == 0 {
		idValues = []string{"unused"}
	}
	ids := &sequenceIDSource{values: append([]string(nil), idValues...)}
	manager, err := newWithDependencies(
		harness.store,
		t.TempDir(),
		content,
		managerDependencies{
			fileFactory: func(string, string) (fileRuntime, error) { return runtime, nil },
			host:        scriptedHostCollector{identity: harness.state.Host},
			locks:       &scriptedLockProvider{handle: &scriptedLockHandle{}},
			newID:       ids.Next,
			now:         func() time.Time { return faultBaseTime().Add(30 * time.Minute) },
		},
	)
	if err != nil {
		t.Fatalf("newWithDependencies() error = %v", err)
	}
	return manager
}

func faultUpdateLabel(previous, next *model.RemediationJournal) string {
	if len(next.RollbackAttempts) > len(previous.RollbackAttempts) {
		return "rollback_attempt"
	}
	if len(next.RollbackAttempts) > 0 &&
		len(next.RollbackAttempts) == len(previous.RollbackAttempts) {
		previousAttempt := previous.RollbackAttempts[len(previous.RollbackAttempts)-1]
		nextAttempt := next.RollbackAttempts[len(next.RollbackAttempts)-1]
		if previousAttempt.ID == nextAttempt.ID &&
			previousAttempt.ObservedByBuild == nil &&
			nextAttempt.ObservedByBuild != nil {
			return "recovery_observer_claim"
		}
	}
	for _, nextChangeSet := range next.ChangeSets {
		previousChangeSet, _, err := findChangeSet(previous, nextChangeSet.ID)
		if err != nil {
			continue
		}
		for _, nextOperation := range nextChangeSet.Operations {
			previousOperation, _, _, err := findOperation(previous, nextChangeSet.ID, nextOperation.ID)
			if err != nil {
				continue
			}
			if previousOperation.Backup == nil && nextOperation.Backup != nil {
				return "prepared"
			}
			if previousOperation.State != nextOperation.State {
				switch nextOperation.State {
				case model.OperationApplyIntentDurable:
					return "apply_intent"
				case model.OperationApplied:
					return "applied"
				case model.OperationAmbiguous:
					return "ambiguous"
				}
			}
		}
		if previousChangeSet.Error == nil && nextChangeSet.Error != nil {
			return "verification_failure"
		}
		if previousChangeSet.State != nextChangeSet.State && nextChangeSet.State == model.ChangeApplying {
			return "change_applying"
		}
	}
	if previous.Error == nil && next.Error != nil {
		return "verification_failure"
	}
	return "other"
}

func faultPlannedJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultJournalSkeleton(1, false)
	value.State = model.RunApplying
	faultSealJournal(t, value)
	return value
}

func faultPreparedJournal(t *testing.T) *model.RemediationJournal {
	t.Helper()
	value := faultJournalSkeleton(1, false)
	value.State = model.RunApplying
	preparedAt := faultBaseTime().Add(2 * time.Minute)
	changeSet := &value.ChangeSets[0]
	operation := &changeSet.Operations[0]
	changeSet.State = model.ChangeApplying
	changeSet.Before = []model.ResourceSnapshot{operation.ExpectedBefore}
	changeSet.PreparedAt = &preparedAt
	operation.Before = operation.ExpectedBefore
	backup := faultBackup("backup-a")
	operation.Backup = &backup
	faultSealJournal(t, value)
	return value
}

func faultVerifiedJournal(t *testing.T, count int, cascade bool, policy model.FailurePolicy, runState model.RunState) *model.RemediationJournal {
	t.Helper()
	value := faultJournalSkeleton(count, cascade)
	value.State = runState
	value.FailurePolicy = policy
	preparedAt := faultBaseTime().Add(2 * time.Minute)
	intentAt := faultBaseTime().Add(3 * time.Minute)
	appliedAt := faultBaseTime().Add(4 * time.Minute)
	verifiedAt := faultBaseTime().Add(5 * time.Minute)
	for index := range value.ChangeSets {
		changeSet := &value.ChangeSets[index]
		operation := &changeSet.Operations[0]
		observed := faultCloneSnapshot(operation.Desired)
		observed.File.CapturedAt = appliedAt
		changeSet.State = model.ChangeVerified
		changeSet.Before = []model.ResourceSnapshot{operation.ExpectedBefore}
		changeSet.After = []model.ResourceSnapshot{observed}
		changeSet.PreparedAt = &preparedAt
		changeSet.AppliedAt = &appliedAt
		changeSet.VerifiedAt = &verifiedAt
		operation.State = model.OperationVerified
		operation.Before = operation.ExpectedBefore
		operation.ObservedAfter = &observed
		backup := faultBackup([]string{"backup-a", "backup-b"}[index])
		operation.Backup = &backup
		operation.ApplyIntentAt = &intentAt
		operation.AppliedAt = &appliedAt
	}
	faultSealJournal(t, value)
	return value
}

func faultJournalSkeleton(count int, cascade bool) *model.RemediationJournal {
	startedAt := faultBaseTime()
	value := &model.RemediationJournal{
		SchemaVersion:            model.RemediationSchemaVersion,
		Revision:                 7,
		RunID:                    "run-fault-injection",
		ScanRunID:                "scan-fault-injection",
		ScanToolVersion:          "1.0.0",
		ScanToolCommit:           "commit-fault-injection",
		ScanToolExecutableSHA256: strings.Repeat("6", 64),
		RuleSetVersion:           "sha256:" + strings.Repeat("5", 64),
		Platform: model.PlatformInfo{
			OS:                 "linux",
			Family:             "rhel",
			ID:                 "rocky",
			VersionID:          "9.8",
			Architecture:       "amd64",
			ScanSupport:        model.ScanSupportTested,
			RemediationSupport: model.RemediationSupportVerified,
		},
		RemediationBuild: model.RemediationBuildIdentity{
			Version:          "1.0.0",
			Commit:           "commit-fault-injection",
			ExecutableSHA256: strings.Repeat("6", 64),
		},
		State:         model.RunPlanned,
		FailurePolicy: model.FailureRollbackItem,
		PlanDigest:    strings.Repeat("4", 64),
		Host: model.HostIdentity{
			MachineIDHash: strings.Repeat("7", 64),
			SystemRoot:    "/",
			RootDevice:    11,
			RootInode:     2,
			BootID:        "12345678-1234-1234-1234-123456789abc",
		},
		StartedAt: startedAt,
		UpdatedAt: startedAt.Add(10 * time.Minute),
	}
	for index := 0; index < count; index++ {
		value.ChangeSets = append(value.ChangeSets, faultPlannedChangeSet(index))
	}
	value.ConflictGraph.Nodes = make([]string, 0, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		value.ConflictGraph.Nodes = append(value.ConflictGraph.Nodes, changeSet.ID)
	}
	if cascade && count == 2 {
		value.ChangeSets[1].DependsOn = []string{"change-a"}
		value.ConflictGraph.Edges = []model.ConflictEdge{{
			From:   "change-a",
			To:     "change-b",
			Reason: model.ConflictExplicitDependency,
		}}
	}
	return value
}

func faultPlannedChangeSet(index int) model.ChangeSet {
	changeSetIDs := []string{"change-a", "change-b"}
	operationIDs := []string{"operation-a", "operation-b"}
	ruleIDs := []string{"U-19", "U-22"}
	recipeIDs := []string{"rocky-u19-file-metadata", "rocky-u22-file-metadata"}
	paths := []string{"/etc/open-ciip-a", "/etc/open-ciip-b"}
	beforeSeeds := []string{"a", "c"}
	desiredSeeds := []string{"b", "d"}
	resource := model.CanonicalResource{
		Reference: model.ResourceRef{Kind: model.ResourceFile, ID: paths[index]},
		Key:       "file:" + paths[index],
	}
	before := faultFileSnapshot(resource, beforeSeeds[index], 0o644, faultBaseTime())
	desired := faultFileSnapshot(resource, desiredSeeds[index], 0o600, faultBaseTime().Add(time.Minute))
	ruleID := ruleIDs[index]
	return model.ChangeSet{
		ID:     changeSetIDs[index],
		RuleID: ruleID,
		RuleIdentity: model.RemediationRuleIdentity{
			ID:        ruleID,
			Title:     "fault injection file metadata rule",
			Category:  model.CategoryFileDirectory,
			Severity:  model.SeverityHigh,
			Evaluator: "unix.file.metadata_fault_fixture",
			Verification: model.Verification{
				State:        model.VerificationVerified,
				Environments: []string{"Rocky Linux 9.8 amd64 fault fixture"},
				VerifiedAt:   "2026-07-11T00:00:00Z",
			},
			BindingSources: []string{"linux-common", "rocky-linux-9.8-amd64"},
			Reference: model.Reference{
				Guide: "2026 Unix fault fixture",
				Item:  ruleID,
				Pages: []int{1},
			},
		},
		RecipeIdentity: model.RemediationRecipeIdentity{
			ID:               recipeIDs[index],
			Selector:         model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
			DefinitionSHA256: strings.Repeat("8", 64),
		},
		Sequence:       index + 1,
		Risk:           model.RiskSafe,
		State:          model.ChangePlanned,
		Resources:      []model.CanonicalResource{resource},
		DryRun:         "regular-file metadata would be changed",
		ExpectedImpact: "only approved metadata fields change",
		Operations: []model.OperationRecord{{
			ID:               operationIDs[index],
			Sequence:         1,
			RollbackSequence: 1,
			Kind:             model.OperationFileMetadata,
			RecoveryMode:     model.RecoveryStateInferable,
			State:            model.OperationPlanned,
			Resource:         resource,
			ExpectedBefore:   before,
			Desired:          desired,
		}},
	}
}

func faultSealJournal(t *testing.T, value *model.RemediationJournal) {
	t.Helper()
	if value.SchemaVersion == model.RemediationSchemaVersion {
		for index := range value.RollbackAttempts {
			attempt := &value.RollbackAttempts[index]
			if attempt.Trigger == model.RollbackCrashRecovery {
				if attempt.ObservedByBuild == nil {
					observer := faultRecoveryObserverBuild()
					attempt.ObservedByBuild = &observer
				}
				continue
			}
			if attempt.ExecutorBuild == nil {
				executor := value.RemediationBuild
				if attempt.Trigger == model.RollbackUserRequest {
					executor = faultUserRollbackBuild()
				}
				attempt.ExecutorBuild = &executor
			}
		}
	}
	digest, err := digestPlan(value.RunID, PlanRequest{
		SchemaVersion:            value.SchemaVersion,
		ScanRunID:                value.ScanRunID,
		ScanToolVersion:          value.ScanToolVersion,
		ScanToolCommit:           value.ScanToolCommit,
		ScanToolExecutableSHA256: value.ScanToolExecutableSHA256,
		RuleSetVersion:           value.RuleSetVersion,
		Platform:                 value.Platform,
		RemediationBuild:         value.RemediationBuild,
		FailurePolicy:            value.FailurePolicy,
	}, value.Host, value.ChangeSets, value.ConflictGraph)
	if err != nil {
		t.Fatalf("digestPlan() error = %v", err)
	}
	value.PlanDigest = digest
	approvedAt := faultBaseTime().Add(time.Minute)
	for index := range value.ChangeSets {
		value.ChangeSets[index].Approval = &model.Approval{
			Source:     "fault-injection-test",
			PlanDigest: digest,
			ApprovedAt: approvedAt,
		}
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("sealed fault journal Validate() error = %v", err)
	}
}

func faultFileSnapshot(resource model.CanonicalResource, fingerprintSeed string, mode uint32, capturedAt time.Time) model.ResourceSnapshot {
	return model.ResourceSnapshot{
		Reference:   resource,
		Fingerprint: strings.Repeat(fingerprintSeed, 64),
		File: &model.FileSnapshot{
			Path:         resource.Reference.ID,
			Exists:       true,
			FileType:     "regular",
			Mode:         mode,
			UID:          0,
			GID:          0,
			Size:         16,
			SHA256:       strings.Repeat("1", 64),
			Device:       11,
			Inode:        uint64(22 + len(resource.Reference.ID)),
			NLink:        1,
			ParentDevice: 11,
			ParentInode:  2,
			CapturedAt:   capturedAt,
		},
	}
}

func faultBackup(id string) model.BackupArtifact {
	return model.BackupArtifact{
		ID:             id,
		MetadataPath:   "backups/" + id + ".json",
		MetadataSHA256: strings.Repeat("e", 64),
		Durable:        true,
	}
}

func faultCloneSnapshot(value model.ResourceSnapshot) model.ResourceSnapshot {
	clone := value
	if value.File != nil {
		file := *value.File
		clone.File = &file
	}
	if value.Service != nil {
		service := *value.Service
		clone.Service = &service
	}
	return clone
}

func faultCloneJournal(t *testing.T, value *model.RemediationJournal) *model.RemediationJournal {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(fault journal) error = %v", err)
	}
	var clone model.RemediationJournal
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatalf("json.Unmarshal(fault journal) error = %v", err)
	}
	return &clone
}

func faultUpdateCallCount(calls []string) int {
	count := 0
	for _, call := range calls {
		if strings.HasPrefix(call, "update:") {
			count++
		}
	}
	return count
}

func faultBaseTime() time.Time {
	return time.Date(2026, time.July, 11, 10, 0, 0, 0, time.UTC)
}

func faultUserRollbackBuild() model.RemediationBuildIdentity {
	return model.RemediationBuildIdentity{
		Version:          "1.0.0",
		Commit:           strings.Repeat("a", 40),
		ExecutableSHA256: strings.Repeat("b", 64),
	}
}

func faultRecoveryObserverBuild() model.RemediationBuildIdentity {
	return model.RemediationBuildIdentity{
		Version:          "0.1.0-alpha.39",
		Commit:           "recovery-observer-fixture",
		ExecutableSHA256: strings.Repeat("c", 64),
		Modified:         true,
	}
}
