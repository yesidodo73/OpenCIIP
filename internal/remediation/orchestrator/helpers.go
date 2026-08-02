package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/conflict"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/hostidentity"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/runlock"
)

func (m *Manager) acquire(ctx context.Context, operation string) (lockHandle, error) {
	if m == nil || m.locks == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: operation, Err: fmt.Errorf("manager is nil")}
	}
	handle, err := m.locks.Acquire(ctx, m.stateRoot)
	if err != nil {
		return nil, wrapDependency(operation, "", "", "", err)
	}
	return handle, nil
}

func (m *Manager) acquireReadOnly(ctx context.Context, operation string) (lockHandle, error) {
	if m == nil || m.locks == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: operation, Err: fmt.Errorf("manager is nil")}
	}
	handle, err := m.locks.AcquireExisting(ctx, m.stateRoot)
	if err != nil {
		return nil, wrapDependency(operation, "", "", "", err)
	}
	return handle, nil
}

func (m *Manager) collectHost(ctx context.Context) (model.HostIdentity, error) {
	identity, err := m.host.Collect(ctx)
	if err != nil {
		return model.HostIdentity{}, wrapDependency("collect host identity", "", "", "", err)
	}
	return identity, nil
}

func (m *Manager) loadAndVerify(ctx context.Context, runID string) (*model.RemediationJournal, error) {
	value, err := m.store.Load(ctx, runID)
	if err != nil {
		return nil, wrapDependency("load journal", runID, "", "", err)
	}
	return m.verifyLoadedJournal(ctx, runID, value)
}

func (m *Manager) loadAndVerifyReadOnly(ctx context.Context, runID string) (*model.RemediationJournal, error) {
	inspection, err := m.store.Inspect(ctx, runID)
	if err != nil {
		return nil, wrapDependency("inspect journal", runID, "", "", err)
	}
	if inspection.IncompleteWALTail {
		return nil, &Error{Code: CodeRecoveryRequired, Operation: "inspect journal", RunID: runID, Err: fmt.Errorf("journal has an incomplete WAL tail; run recover before preview")}
	}
	return m.verifyLoadedJournal(ctx, runID, inspection.Journal)
}

func (m *Manager) verifyLoadedJournal(ctx context.Context, runID string, value *model.RemediationJournal) (*model.RemediationJournal, error) {
	if value == nil {
		return nil, &Error{Code: CodeInvalidState, Operation: "verify journal", RunID: runID, Err: fmt.Errorf("journal is missing")}
	}
	actual, err := m.collectHost(ctx)
	if err != nil {
		return nil, err
	}
	if requiresSameBoot(*value) {
		err = hostidentity.VerifySameBoot(value.Host, actual)
	} else {
		err = hostidentity.VerifyHost(value.Host, actual)
	}
	if err != nil {
		return nil, wrapDependency("verify host identity", runID, "", "", err)
	}
	calculated, err := digestPlan(value.RunID, PlanRequest{
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
		return nil, &Error{Code: CodeInvalidState, Operation: "verify plan digest", RunID: runID, Err: err}
	}
	if calculated != value.PlanDigest {
		return nil, &Error{Code: CodeInvalidState, Operation: "verify plan digest", RunID: runID, Err: fmt.Errorf("stored plan digest does not match immutable plan fields")}
	}
	return value, nil
}

func requiresSameBoot(value model.RemediationJournal) bool {
	for _, changeSet := range value.ChangeSets {
		for _, operation := range changeSet.Operations {
			switch operation.Kind {
			case model.OperationServiceStart,
				model.OperationServiceStop,
				model.OperationServiceReload,
				model.OperationServiceRestart,
				model.OperationDaemonReload:
				return true
			}
		}
	}
	return false
}

func (m *Manager) ensureNoOtherRecoverable(ctx context.Context, currentRunID string) error {
	values, err := m.store.ListRecoverable(ctx)
	if err != nil {
		return wrapDependency("list recoverable journals", currentRunID, "", "", err)
	}
	for _, value := range values {
		if value.RunID != currentRunID {
			return &Error{Code: CodeRecoveryPending, Operation: "check recoverable journals", RunID: currentRunID, Err: fmt.Errorf("run %s requires recovery first", value.RunID)}
		}
	}
	return nil
}

func (m *Manager) update(
	ctx context.Context,
	current *model.RemediationJournal,
	operation string,
	mutate func(*model.RemediationJournal) error,
) (*model.RemediationJournal, error) {
	if current == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: operation, Err: fmt.Errorf("current journal is required")}
	}
	next, err := m.store.Update(ctx, current.RunID, current.Revision, mutate)
	if err != nil {
		return nil, wrapDependency(operation, current.RunID, "", "", err)
	}
	return next, nil
}

func (m *Manager) fileHandler(runID string) (fileRuntime, error) {
	if m == nil || m.fileFactory == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "initialize regular-file handler", RunID: runID, Err: fmt.Errorf("file runtime factory is required")}
	}
	runDirectory := m.stateRoot
	if runID != "" {
		runDirectory = filepath.Join(m.stateRoot, runID)
	}
	handler, err := m.fileFactory(m.systemRoot, runDirectory)
	if err != nil {
		return nil, wrapDependency("initialize regular-file handler", runID, "", "", err)
	}
	return handler, nil
}

func (m *Manager) nextID(prefix string) (string, error) {
	if m == nil || m.newID == nil {
		return "", fmt.Errorf("ID source is required")
	}
	return m.newID(prefix)
}

func findChangeSet(value *model.RemediationJournal, id string) (*model.ChangeSet, int, error) {
	if value == nil {
		return nil, -1, fmt.Errorf("journal is nil")
	}
	for index := range value.ChangeSets {
		if value.ChangeSets[index].ID == id {
			return &value.ChangeSets[index], index, nil
		}
	}
	return nil, -1, fmt.Errorf("change set %s does not exist", id)
}

func findOperation(value *model.RemediationJournal, changeSetID, operationID string) (*model.OperationRecord, int, int, error) {
	changeSet, changeSetIndex, err := findChangeSet(value, changeSetID)
	if err != nil {
		return nil, -1, -1, err
	}
	for index := range changeSet.Operations {
		if changeSet.Operations[index].ID == operationID {
			return &changeSet.Operations[index], changeSetIndex, index, nil
		}
	}
	return nil, -1, -1, fmt.Errorf("operation %s does not exist in change set %s", operationID, changeSetID)
}

func cloneChangeSets(values []model.ChangeSet) ([]model.ChangeSet, error) {
	encoded, err := journal.CanonicalJSON(values)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var clone []model.ChangeSet
	if err := decoder.Decode(&clone); err != nil {
		return nil, err
	}
	return clone, nil
}

func randomID(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func semanticEqual(expected, observed model.ResourceSnapshot) bool {
	return expected.Reference.Key == observed.Reference.Key && expected.Fingerprint == observed.Fingerprint
}

func exactEqual(expected, observed model.ResourceSnapshot) bool {
	if !semanticEqual(expected, observed) || expected.File == nil || observed.File == nil {
		return false
	}
	return expected.File.Device == observed.File.Device && expected.File.Inode == observed.File.Inode && expected.File.ParentDevice == observed.File.ParentDevice && expected.File.ParentInode == observed.File.ParentInode
}

func canonicalResourceEqual(left, right model.CanonicalResource) bool {
	if left.Reference != right.Reference || left.Key != right.Key || len(left.AliasKeys) != len(right.AliasKeys) {
		return false
	}
	for index := range left.AliasKeys {
		if left.AliasKeys[index] != right.AliasKeys[index] {
			return false
		}
	}
	return true
}

func activeChangeSet(state model.ChangeSetState) bool {
	switch state {
	case model.ChangeApplying,
		model.ChangeApplied,
		model.ChangeVerifying,
		model.ChangeVerified,
		model.ChangeApplyFailed,
		model.ChangeRollingBack,
		model.ChangeRollbackBlocked,
		model.ChangeRollbackFailed,
		model.ChangePartiallyRolledBack,
		model.ChangeRecoveryRequired:
		return true
	default:
		return false
	}
}

func activeMap(value *model.RemediationJournal) map[string]bool {
	result := make(map[string]bool, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		result[changeSet.ID] = activeChangeSet(changeSet.State) && hasRollbackWork(value, changeSet.ID)
	}
	return result
}

func sequenceMap(value *model.RemediationJournal) map[string]int {
	result := make(map[string]int, len(value.ChangeSets))
	for _, changeSet := range value.ChangeSets {
		result[changeSet.ID] = changeSet.Sequence
	}
	return result
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	result := make([]string, 0, len(values)+len(additions))
	for _, value := range append(append([]string(nil), values...), additions...) {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (m *Manager) rollbackAttemptCompletionTime(
	value *model.RemediationJournal,
	startedAt time.Time,
	errors []model.JournalError,
) time.Time {
	completedAt := m.nextEventTime(value)
	if startedAt.After(completedAt) {
		completedAt = startedAt
	}
	for _, journalError := range errors {
		if journalError.OccurredAt.After(completedAt) {
			completedAt = journalError.OccurredAt
		}
	}
	return completedAt
}

func incompleteRollbackAttempt(value *model.RemediationJournal) (*model.RollbackAttempt, bool) {
	if value == nil || len(value.RollbackAttempts) == 0 {
		return nil, false
	}
	attempt := &value.RollbackAttempts[len(value.RollbackAttempts)-1]
	if attempt.CompletedAt != nil {
		return nil, false
	}
	return attempt, true
}

func operationResource(operation model.OperationRecord) *model.ResourceRef {
	reference := operation.Resource.Reference
	return &reference
}

func (m *Manager) makeJournalError(
	value *model.RemediationJournal,
	phase, changeSetID, operationID string,
	operation *model.OperationRecord,
	err error,
) model.JournalError {
	code := model.JournalErrorRecoveryAmbiguous
	if regularfile.CodeOf(err) == regularfile.CodeFileChanged {
		code = model.JournalErrorExternalChange
	}
	switch CodeOf(wrapDependency(phase, "", changeSetID, operationID, err)) {
	case CodeHostMismatch:
		code = model.JournalErrorHostMismatch
	case CodeBootChanged:
		code = model.JournalErrorBootChanged
	case CodeLockUnavailable:
		code = model.JournalErrorLockUnavailable
	case CodeRevisionConflict:
		code = model.JournalErrorRevisionConflict
	case CodePreconditionFailed:
		if code != model.JournalErrorExternalChange {
			code = model.JournalErrorPreconditionFailed
		}
	case CodeBackupFailed:
		if regularfile.CodeOf(err) == regularfile.CodeBackupHashMismatch {
			code = model.JournalErrorBackupHashMismatch
		} else {
			code = model.JournalErrorBackupMissing
		}
	case CodeUnsupportedOperation:
		code = model.JournalErrorUnsupportedResource
	case CodeApplyFailed:
		code = model.JournalErrorApplyFailed
	case CodeVerificationFailed:
		code = model.JournalErrorVerificationFailed
	case CodeRollbackFailed:
		code = model.JournalErrorRollbackFailed
	case CodePersistFailed:
		code = model.JournalErrorPersistFailed
	case CodeCancelFailed:
		code = model.JournalErrorCancelFailed
	case CodeCascadeRequired:
		code = model.JournalErrorRollbackDependency
	case CodeRecoveryRequired:
		code = model.JournalErrorRecoveryAmbiguous
	}
	var resource *model.ResourceRef
	if operation != nil {
		resource = operationResource(*operation)
	}
	message := string(code) + " during " + phase
	return model.JournalError{
		Code:        code,
		Phase:       phase,
		ChangeSetID: changeSetID,
		OperationID: operationID,
		Resource:    resource,
		Message:     message,
		Retryable:   false,
		OccurredAt:  m.nextEventTime(value),
	}
}

func wrapDependency(operation, runID, changeSetID, operationID string, err error) error {
	if err == nil {
		return nil
	}
	code := CodeOf(err)
	if code == "" {
		code = CodePersistFailed
	}
	switch {
	case CodeOf(err) != "":
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		code = CodeLockUnavailable
	case journal.CodeOf(err) == journal.CodeRevisionConflict:
		code = CodeRevisionConflict
	case journal.CodeOf(err) == journal.CodeCorruptWAL:
		code = CodeRecoveryRequired
	case journal.CodeOf(err) == journal.CodeInvalidInput, journal.CodeOf(err) == journal.CodeInvalidTransition:
		code = CodeInvalidState
	case hostidentity.CodeOf(err) == hostidentity.CodeHostMismatch:
		code = CodeHostMismatch
	case hostidentity.CodeOf(err) == hostidentity.CodeBootChanged:
		code = CodeBootChanged
	case runlock.CodeOf(err) == runlock.CodeLockUnavailable:
		code = CodeLockUnavailable
	case regularfile.CodeOf(err) == regularfile.CodePreconditionFailed, regularfile.CodeOf(err) == regularfile.CodeFileChanged:
		code = CodePreconditionFailed
	case regularfile.CodeOf(err) == regularfile.CodeBackupMissing,
		regularfile.CodeOf(err) == regularfile.CodeBackupHashMismatch,
		regularfile.CodeOf(err) == regularfile.CodeBackupWriteFailed:
		code = CodeBackupFailed
	case regularfile.CodeOf(err) == regularfile.CodeUnsupportedPlatform,
		regularfile.CodeOf(err) == regularfile.CodeUnsupportedFileType,
		regularfile.CodeOf(err) == regularfile.CodeSymlinkNotAllowed,
		regularfile.CodeOf(err) == regularfile.CodeHardLinkNotSupported,
		regularfile.CodeOf(err) == regularfile.CodeUnsupportedMetadata,
		regularfile.CodeOf(err) == regularfile.CodeSELinuxUnknown:
		code = CodeUnsupportedOperation
	case regularfile.CodeOf(err) == regularfile.CodeInvalidInput,
		regularfile.CodeOf(err) == regularfile.CodeUnsafePath:
		code = CodeInvalidInput
	case conflict.CodeOf(err) == conflict.CodeRollbackConflict, conflict.CodeOf(err) == conflict.CodeIncompleteGroup:
		code = CodeCascadeRequired
	case conflict.CodeOf(err) != "":
		code = CodeInvalidInput
	}
	committed := false
	var journalError *journal.Error
	if errors.As(err, &journalError) {
		committed = journalError.Committed
	}
	var fileError *regularfile.Error
	if errors.As(err, &fileError) {
		committed = committed || fileError.Committed
	}
	return &Error{
		Code:        code,
		Operation:   operation,
		RunID:       runID,
		ChangeSetID: changeSetID,
		OperationID: operationID,
		Committed:   committed,
		Err:         err,
	}
}
