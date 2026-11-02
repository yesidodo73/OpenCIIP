package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/conflict"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/hostidentity"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
)

type planOperation struct {
	ID               string                  `json:"id"`
	Sequence         int                     `json:"sequence"`
	RollbackSequence int                     `json:"rollback_sequence"`
	Kind             model.OperationKind     `json:"kind"`
	RecoveryMode     model.RecoveryMode      `json:"recovery_mode"`
	Resource         model.CanonicalResource `json:"resource"`
	ExpectedBefore   model.ResourceSnapshot  `json:"expected_before"`
	Desired          model.ResourceSnapshot  `json:"desired"`
}

type planChangeSet struct {
	ID             string                          `json:"id"`
	RuleID         string                          `json:"rule_id"`
	RuleIdentity   model.RemediationRuleIdentity   `json:"rule_identity"`
	RecipeIdentity model.RemediationRecipeIdentity `json:"recipe_identity"`
	Sequence       int                             `json:"sequence"`
	Risk           model.RemediationRisk           `json:"risk"`
	RollbackGroup  string                          `json:"rollback_group,omitempty"`
	DependsOn      []string                        `json:"depends_on,omitempty"`
	Resources      []model.CanonicalResource       `json:"resources"`
	Operations     []planOperation                 `json:"operations"`
	DryRun         string                          `json:"dry_run"`
	ExpectedImpact string                          `json:"expected_impact"`
}

type planPayload struct {
	SchemaVersion            int                            `json:"schema_version"`
	RunID                    string                         `json:"run_id"`
	ScanRunID                string                         `json:"scan_run_id"`
	ScanToolVersion          string                         `json:"scan_tool_version"`
	ScanToolCommit           string                         `json:"scan_tool_commit"`
	ScanToolExecutableSHA256 string                         `json:"scan_tool_executable_sha256,omitempty"`
	RuleSetVersion           string                         `json:"rule_set_version"`
	Platform                 model.PlatformInfo             `json:"platform"`
	RemediationBuild         model.RemediationBuildIdentity `json:"remediation_build"`
	FailurePolicy            model.FailurePolicy            `json:"failure_policy"`
	Host                     model.HostIdentity             `json:"host"`
	ChangeSets               []planChangeSet                `json:"change_sets"`
	ConflictGraph            model.ConflictGraph            `json:"conflict_graph"`
}

func (m *Manager) Plan(ctx context.Context, request PlanRequest) (*model.RemediationJournal, error) {
	lock, err := m.acquire(ctx, "plan")
	if err != nil {
		return nil, err
	}
	defer lock.Release()
	if err := m.ensureNoOtherRecoverable(ctx, ""); err != nil {
		return nil, err
	}
	if err := validatePlanRequest(request); err != nil {
		return nil, err
	}
	actualHost, err := m.collectHost(ctx)
	if err != nil {
		return nil, err
	}
	if err := hostidentity.VerifyHost(request.Host, actualHost); err != nil {
		return nil, wrapDependency("verify requested host", "", "", "", err)
	}
	runID := strings.TrimSpace(request.RunID)
	if runID == "" {
		runID, err = m.nextID("run-")
		if err != nil {
			return nil, &Error{Code: CodePersistFailed, Operation: "generate run ID", Err: err}
		}
	}
	if !safeIdentifier(runID) {
		return nil, &Error{Code: CodeInvalidInput, Operation: "plan", RunID: runID, Err: fmt.Errorf("run ID contains unsupported characters or length")}
	}
	if runID == "payloads" {
		return nil, &Error{Code: CodeInvalidInput, Operation: "plan", RunID: runID, Err: fmt.Errorf("run ID uses a reserved state namespace")}
	}
	changeSets, err := cloneChangeSets(request.ChangeSets)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "clone plan", RunID: runID, Err: err}
	}
	sort.SliceStable(changeSets, func(i, j int) bool {
		if changeSets[i].Sequence == changeSets[j].Sequence {
			return changeSets[i].ID < changeSets[j].ID
		}
		return changeSets[i].Sequence < changeSets[j].Sequence
	})
	handler, err := m.fileHandler("")
	if err != nil {
		return nil, err
	}
	predicted := make(map[string]model.ResourceSnapshot)
	for changeSetIndex := range changeSets {
		if err := m.normalizePlanChangeSet(ctx, runID, &changeSets[changeSetIndex], handler, predicted); err != nil {
			return nil, err
		}
	}
	if err := verifyPlanBaselines(ctx, runID, handler, changeSets); err != nil {
		return nil, err
	}
	graph, err := conflict.Build(changeSets)
	if err != nil {
		return nil, wrapDependency("build conflict graph", runID, "", "", err)
	}
	digest, err := digestPlan(runID, request, actualHost, changeSets, graph)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "digest plan", RunID: runID, Err: err}
	}
	value := &model.RemediationJournal{
		SchemaVersion:            effectivePlanSchemaVersion(request.SchemaVersion),
		RunID:                    runID,
		ScanRunID:                request.ScanRunID,
		ScanToolVersion:          request.ScanToolVersion,
		ScanToolCommit:           request.ScanToolCommit,
		ScanToolExecutableSHA256: request.ScanToolExecutableSHA256,
		RuleSetVersion:           request.RuleSetVersion,
		Platform:                 request.Platform,
		RemediationBuild:         request.RemediationBuild,
		State:                    model.RunPlanned,
		FailurePolicy:            request.FailurePolicy,
		PlanDigest:               digest,
		Host:                     actualHost,
		ChangeSets:               changeSets,
		ConflictGraph:            graph,
	}
	if createErr := m.store.Create(ctx, value); createErr != nil {
		cleanupContext, cancelCleanup := newApplyCleanupContext(ctx)
		defer cancelCleanup()
		created, loadErr := m.store.Load(cleanupContext, runID)
		if loadErr != nil {
			return nil, wrapDependency("create planned journal", runID, "", "", createErr)
		}
		canceled, cancelErr := m.cancelLoaded(cleanupContext, created)
		if cancelErr != nil {
			return created, &Error{Code: CodePersistFailed, Operation: "cancel committed plan after create failure", RunID: runID, Committed: true, Err: fmt.Errorf("create error: %v; cancellation error: %w", createErr, cancelErr)}
		}
		return canceled, wrapDependency("create planned journal", runID, "", "", createErr)
	}
	loadContext, cancelLoad := newApplyCleanupContext(ctx)
	created, err := m.store.Load(loadContext, runID)
	cancelLoad()
	if err != nil {
		return nil, wrapDependency("load planned journal", runID, "", "", err)
	}
	if cancellationErr := ctx.Err(); cancellationErr != nil {
		cleanupContext, cancelCleanup := newApplyCleanupContext(ctx)
		defer cancelCleanup()
		canceled, cancelErr := m.cancelLoaded(cleanupContext, created)
		if cancelErr != nil {
			return created, &Error{Code: CodePersistFailed, Operation: "cancel plan after request cancellation", RunID: runID, Committed: true, Err: fmt.Errorf("request cancellation: %v; durable cancellation failed: %w", cancellationErr, cancelErr)}
		}
		return canceled, &Error{Code: CodeLockUnavailable, Operation: "plan request canceled after journal creation", RunID: runID, Committed: true, Err: cancellationErr}
	}
	return created, nil
}

func verifyPlanBaselines(ctx context.Context, runID string, handler fileRuntime, changeSets []model.ChangeSet) error {
	first := make(map[string]model.OperationRecord)
	for _, changeSet := range changeSets {
		for _, operation := range changeSet.Operations {
			if _, exists := first[operation.Resource.Key]; !exists {
				first[operation.Resource.Key] = operation
			}
		}
	}
	keys := make([]string, 0, len(first))
	for key := range first {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		operation := first[key]
		current, err := handler.Capture(ctx, operation.Resource)
		if err != nil {
			return wrapDependency("final plan precondition capture", runID, "", operation.ID, err)
		}
		if !exactEqual(operation.ExpectedBefore, current) {
			return &Error{Code: CodePreconditionFailed, Operation: "final plan precondition capture", RunID: runID, OperationID: operation.ID, Err: fmt.Errorf("resource changed before the plan was persisted")}
		}
	}
	return nil
}

func (m *Manager) normalizePlanChangeSet(
	ctx context.Context,
	runID string,
	changeSet *model.ChangeSet,
	handler fileRuntime,
	predicted map[string]model.ResourceSnapshot,
) error {
	if changeSet == nil || changeSet.State != model.ChangePlanned || changeSet.Approval != nil || len(changeSet.Before) != 0 || len(changeSet.After) != 0 || changeSet.PreparedAt != nil || changeSet.AppliedAt != nil || changeSet.VerifiedAt != nil || changeSet.RolledBackAt != nil || changeSet.Error != nil {
		return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, Err: fmt.Errorf("change set contains runtime state")}
	}
	if !safeIdentifier(changeSet.ID) {
		return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, Err: fmt.Errorf("change-set ID contains unsupported characters or length")}
	}
	canonicalByID := make(map[string]model.CanonicalResource, len(changeSet.Resources))
	canonicalByKey := make(map[string]model.CanonicalResource, len(changeSet.Resources))
	for index := range changeSet.Resources {
		resource, err := handler.Normalize(ctx, changeSet.Resources[index].Reference)
		if err != nil {
			return wrapDependency("normalize resource", runID, changeSet.ID, "", err)
		}
		if _, exists := canonicalByKey[resource.Key]; exists {
			return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, Err: fmt.Errorf("change set repeats resource %s", resource.Key)}
		}
		changeSet.Resources[index] = resource
		canonicalByID[resource.Reference.ID] = resource
		canonicalByKey[resource.Key] = resource
	}
	used := make(map[string]struct{}, len(changeSet.Operations))
	for operationIndex := range changeSet.Operations {
		operation := &changeSet.Operations[operationIndex]
		if !safeIdentifier(operation.ID) {
			return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("operation ID contains unsupported characters or length")}
		}
		if operation.State != model.OperationPlanned || !operation.Before.IsZero() || operation.ObservedAfter != nil || operation.ObservedRollback != nil || operation.Backup != nil || operation.ApplyIntentAt != nil || operation.AppliedAt != nil || operation.RollbackIntentAt != nil || operation.RolledBackAt != nil || operation.Error != nil {
			return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("operation contains runtime state")}
		}
		if operation.Kind != model.OperationFileMetadata {
			return &Error{Code: CodeUnsupportedOperation, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("only regular-file metadata remediation is supported")}
		}
		canonical, exists := canonicalByID[operation.Resource.Reference.ID]
		if !exists {
			candidate, normalizeErr := handler.Normalize(ctx, operation.Resource.Reference)
			if normalizeErr != nil {
				return wrapDependency("normalize operation resource", runID, changeSet.ID, operation.ID, normalizeErr)
			}
			canonical, exists = canonicalByKey[candidate.Key]
		}
		if !exists {
			return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("operation resource is not declared by its change set")}
		}
		if _, duplicate := used[canonical.Key]; duplicate {
			return &Error{Code: CodeUnsupportedOperation, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("multiple metadata operations on one file must be combined into one operation")}
		}
		used[canonical.Key] = struct{}{}
		operation.Resource = canonical
		if operation.Desired.File == nil || !operation.Desired.File.Exists || operation.Desired.File.FileType != "regular" {
			return &Error{Code: CodeUnsupportedOperation, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("desired state must describe an existing regular file")}
		}
		approvedCurrent, err := handler.Capture(ctx, canonical)
		if err != nil {
			return wrapDependency("capture approved precondition", runID, changeSet.ID, operation.ID, err)
		}
		expected, predictedExists := predicted[canonical.Key]
		if !predictedExists {
			expected = approvedCurrent
		} else if expected.File == nil || approvedCurrent.File == nil || expected.File.ParentDevice != approvedCurrent.File.ParentDevice || expected.File.ParentInode != approvedCurrent.File.ParentInode {
			return &Error{Code: CodePreconditionFailed, Operation: "capture approved precondition", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("predicted predecessor uses a different parent directory")}
		}
		builtDesired, err := handler.BuildDesiredMetadata(ctx, canonical, regularfile.DesiredMetadata{
			UID:            operation.Desired.File.UID,
			GID:            operation.Desired.File.GID,
			Mode:           operation.Desired.File.Mode,
			SELinuxContext: operation.Desired.File.SELinuxContext,
		})
		if err != nil {
			return wrapDependency("validate desired file", runID, changeSet.ID, operation.ID, err)
		}
		if builtDesired.File == nil || builtDesired.File.ParentDevice != approvedCurrent.File.ParentDevice || builtDesired.File.ParentInode != approvedCurrent.File.ParentInode {
			return &Error{Code: CodePreconditionFailed, Operation: "validate desired file", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("target parent changed while the desired state was built")}
		}
		if operation.Desired.File.SHA256 != "" && operation.Desired.File.SHA256 != builtDesired.File.SHA256 {
			return &Error{Code: CodeInvalidInput, Operation: "validate desired file", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("provided desired content digest does not match the content source")}
		}
		if (operation.Desired.File.SHA256 != "" || operation.Desired.File.Size != 0) && operation.Desired.File.Size != builtDesired.File.Size {
			return &Error{Code: CodeInvalidInput, Operation: "validate desired file", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("provided desired content size does not match the content source")}
		}
		if operation.Desired.Fingerprint != "" && operation.Desired.Fingerprint != builtDesired.Fingerprint {
			return &Error{Code: CodeInvalidInput, Operation: "validate desired file", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("provided desired snapshot does not match content and metadata")}
		}
		middle, err := handler.Capture(ctx, canonical)
		if err != nil {
			return wrapDependency("recheck approved precondition", runID, changeSet.ID, operation.ID, err)
		}
		if !exactEqual(approvedCurrent, middle) {
			return &Error{Code: CodePreconditionFailed, Operation: "recheck approved precondition", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("file changed while the plan was built")}
		}
		stableCanonical, err := handler.Normalize(ctx, canonical.Reference)
		if err != nil {
			return wrapDependency("recheck canonical resource", runID, changeSet.ID, operation.ID, err)
		}
		finalCurrent, err := handler.Capture(ctx, canonical)
		if err != nil {
			return wrapDependency("finalize approved precondition", runID, changeSet.ID, operation.ID, err)
		}
		if !canonicalResourceEqual(canonical, stableCanonical) || !exactEqual(approvedCurrent, finalCurrent) {
			return &Error{Code: CodePreconditionFailed, Operation: "finalize approved precondition", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("canonical resource or file identity changed while the plan was built")}
		}
		operation.Desired = builtDesired
		operation.ExpectedBefore = expected
		if operation.RecoveryMode == model.RecoveryStateInferable && semanticEqual(operation.ExpectedBefore, operation.Desired) {
			return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, OperationID: operation.ID, Err: fmt.Errorf("state-inferable operation has equivalent before and desired states")}
		}
		predicted[canonical.Key] = operation.Desired
	}
	if len(used) != len(changeSet.Resources) {
		return &Error{Code: CodeInvalidInput, Operation: "normalize plan", RunID: runID, ChangeSetID: changeSet.ID, Err: fmt.Errorf("every declared resource must have exactly one operation")}
	}
	if err := changeSet.Validate(strings.Repeat("0", 64)); err != nil {
		return &Error{Code: CodeInvalidInput, Operation: "validate planned change set", RunID: runID, ChangeSetID: changeSet.ID, Err: err}
	}
	return nil
}

func digestPlan(runID string, request PlanRequest, host model.HostIdentity, changeSets []model.ChangeSet, graph model.ConflictGraph) (string, error) {
	planned := make([]planChangeSet, 0, len(changeSets))
	for _, changeSet := range changeSets {
		operations := make([]planOperation, 0, len(changeSet.Operations))
		for _, operation := range changeSet.Operations {
			operations = append(operations, planOperation{
				ID:               operation.ID,
				Sequence:         operation.Sequence,
				RollbackSequence: operation.RollbackSequence,
				Kind:             operation.Kind,
				RecoveryMode:     operation.RecoveryMode,
				Resource:         operation.Resource,
				ExpectedBefore:   operation.ExpectedBefore,
				Desired:          operation.Desired,
			})
		}
		planned = append(planned, planChangeSet{
			ID:             changeSet.ID,
			RuleID:         changeSet.RuleID,
			RuleIdentity:   changeSet.RuleIdentity,
			RecipeIdentity: changeSet.RecipeIdentity,
			Sequence:       changeSet.Sequence,
			Risk:           changeSet.Risk,
			RollbackGroup:  changeSet.RollbackGroup,
			DependsOn:      append([]string(nil), changeSet.DependsOn...),
			Resources:      append([]model.CanonicalResource(nil), changeSet.Resources...),
			Operations:     operations,
			DryRun:         changeSet.DryRun,
			ExpectedImpact: changeSet.ExpectedImpact,
		})
	}
	return journal.Digest(planPayload{
		SchemaVersion:            effectivePlanSchemaVersion(request.SchemaVersion),
		RunID:                    runID,
		ScanRunID:                request.ScanRunID,
		ScanToolVersion:          request.ScanToolVersion,
		ScanToolCommit:           request.ScanToolCommit,
		ScanToolExecutableSHA256: request.ScanToolExecutableSHA256,
		RuleSetVersion:           request.RuleSetVersion,
		Platform:                 request.Platform,
		RemediationBuild:         request.RemediationBuild,
		FailurePolicy:            request.FailurePolicy,
		Host:                     host,
		ChangeSets:               planned,
		ConflictGraph:            graph,
	})
}

func effectivePlanSchemaVersion(version int) int {
	if version == 0 {
		return model.RemediationSchemaVersion
	}
	return version
}

func validatePlanRequest(request PlanRequest) error {
	if effectivePlanSchemaVersion(request.SchemaVersion) != model.RemediationSchemaVersion {
		return &Error{Code: CodeUnsupportedOperation, Operation: "plan", Err: fmt.Errorf("new plans require remediation schema version %d", model.RemediationSchemaVersion)}
	}
	if strings.TrimSpace(request.ScanRunID) == "" ||
		strings.TrimSpace(request.ScanToolVersion) == "" ||
		strings.TrimSpace(request.ScanToolCommit) == "" ||
		strings.TrimSpace(request.ScanToolExecutableSHA256) == "" ||
		strings.TrimSpace(request.RuleSetVersion) == "" ||
		!request.FailurePolicy.Valid() ||
		len(request.ChangeSets) == 0 {
		return &Error{Code: CodeInvalidInput, Operation: "plan", Err: fmt.Errorf("scan identity, versions, failure policy, and change sets are required")}
	}
	if request.Platform.ScanSupport != model.ScanSupportTested ||
		request.Platform.RemediationSupport != model.RemediationSupportVerified {
		return &Error{Code: CodeUnsupportedOperation, Operation: "plan", Err: fmt.Errorf("only a verified platform can be bound to a remediation plan")}
	}
	if err := request.RemediationBuild.Validate(); err != nil {
		return &Error{Code: CodeInvalidInput, Operation: "plan", Err: err}
	}
	if request.ScanToolVersion != request.RemediationBuild.Version ||
		request.ScanToolCommit != request.RemediationBuild.Commit ||
		request.ScanToolExecutableSHA256 != request.RemediationBuild.ExecutableSHA256 {
		return &Error{Code: CodeInvalidInput, Operation: "plan", Err: fmt.Errorf("scan and remediation build identities must match")}
	}
	return nil
}

func requireCurrentExecutableBoundPlan(value *model.RemediationJournal, operation string) error {
	if value == nil {
		return &Error{Code: CodeInvalidState, Operation: operation, Err: fmt.Errorf("remediation journal is missing")}
	}
	if !model.HasRemediationBuildProvenance(value.SchemaVersion) ||
		value.ScanToolExecutableSHA256 == "" {
		return &Error{
			Code:      CodeUnsupportedOperation,
			Operation: operation,
			RunID:     value.RunID,
			Err:       fmt.Errorf("legacy remediation plans cannot be approved or applied; create a new plan from a current scan"),
		}
	}
	return nil
}

func (m *Manager) Approve(ctx context.Context, runID string, approval model.Approval) error {
	lock, err := m.acquire(ctx, "approve")
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := m.ensureNoOtherRecoverable(ctx, runID); err != nil {
		return err
	}
	value, err := m.loadAndVerifyReadOnly(ctx, runID)
	if err != nil {
		return err
	}
	if err := requireCurrentExecutableBoundPlan(value, "approve"); err != nil {
		return err
	}
	if value.State != model.RunPlanned {
		return &Error{Code: CodeInvalidState, Operation: "approve", RunID: runID, Err: fmt.Errorf("run is %s, not planned", value.State)}
	}
	approval.ApprovedAt = approval.ApprovedAt.UTC()
	if err := approval.Validate(value.PlanDigest); err != nil {
		return &Error{Code: CodeInvalidInput, Operation: "approve", RunID: runID, Err: err}
	}
	approval.ApprovedAt = m.nextEventTime(value)
	_, err = m.update(ctx, value, "persist approval", func(next *model.RemediationJournal) error {
		next.State = model.RunApproved
		for index := range next.ChangeSets {
			copy := approval
			next.ChangeSets[index].Approval = &copy
		}
		return nil
	})
	return err
}
