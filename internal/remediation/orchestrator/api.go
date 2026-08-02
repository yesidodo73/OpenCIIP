package orchestrator

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/hostidentity"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
)

type ErrorCode string

const (
	CodeInvalidInput         ErrorCode = "invalid_input"
	CodeInvalidState         ErrorCode = "invalid_state"
	CodeUnsupportedOperation ErrorCode = "unsupported_operation"
	CodeHostMismatch         ErrorCode = "host_mismatch"
	CodeBootChanged          ErrorCode = "boot_changed"
	CodeLockUnavailable      ErrorCode = "lock_unavailable"
	CodeRevisionConflict     ErrorCode = "journal_revision_conflict"
	CodePreconditionFailed   ErrorCode = "precondition_failed"
	CodeBackupFailed         ErrorCode = "backup_failed"
	CodeApplyFailed          ErrorCode = "apply_failed"
	CodeVerificationFailed   ErrorCode = "verification_failed"
	CodeRollbackFailed       ErrorCode = "rollback_failed"
	CodeRecoveryRequired     ErrorCode = "recovery_required"
	CodeRecoveryPending      ErrorCode = "recovery_pending"
	CodeCascadeRequired      ErrorCode = "rollback_dependency_conflict"
	CodeRollbackPreviewStale ErrorCode = "rollback_preview_stale"
	CodeCancelFailed         ErrorCode = "cancel_failed"
	CodePersistFailed        ErrorCode = "persist_failed"
)

type Error struct {
	Code        ErrorCode
	Operation   string
	RunID       string
	ChangeSetID string
	OperationID string
	Committed   bool
	Err         error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	message := string(e.Code)
	if e.Operation != "" {
		message += " during " + e.Operation
	}
	if e.RunID != "" {
		message += " for run " + e.RunID
	}
	if e.ChangeSetID != "" {
		message += " change set " + e.ChangeSetID
	}
	if e.OperationID != "" {
		message += " operation " + e.OperationID
	}
	if e.Committed {
		message += " after a durable state change"
	}
	if e.Err != nil {
		message += ": " + e.Err.Error()
	}
	return message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func CodeOf(err error) ErrorCode {
	for err != nil {
		if structured, ok := err.(*Error); ok {
			return structured.Code
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = unwrapper.Unwrap()
	}
	return ""
}

type PlanRequest struct {
	SchemaVersion            int
	RunID                    string
	ScanRunID                string
	ScanToolVersion          string
	ScanToolCommit           string
	ScanToolExecutableSHA256 string
	RuleSetVersion           string
	Platform                 model.PlatformInfo
	RemediationBuild         model.RemediationBuildIdentity
	FailurePolicy            model.FailurePolicy
	Host                     model.HostIdentity
	ChangeSets               []model.ChangeSet
}

type RecoveryAssessment struct {
	RunID                     string
	LastValidRevision         uint64
	ConfirmedApplied          []string
	ConfirmedRolledBack       []string
	NotApplied                []string
	Ambiguous                 []string
	AutomaticRollbackPossible bool
	Reasons                   []string
}

type RollbackPreview struct {
	RunID               string
	Revision            uint64
	Scope               model.RollbackScope
	RequestedChangeSets []string
	ExpandedChangeSets  []string
	ExecutionOrder      []string
	CascadeRequired     bool
	PreviewDigest       string
}

type ApplyRunGuard func(ctx context.Context, journal *model.RemediationJournal) error
type ApplyEffectGuard func(ctx context.Context, journal *model.RemediationJournal, changeSetID, operationID string) error
type ApplyVerifier func(ctx context.Context, journal *model.RemediationJournal, changeSetIDs []string) (failedChangeSets []string, err error)

type FileContentSource interface {
	Content(ctx context.Context, runID, changeSetID, operationID string) ([]byte, error)
}

type FileContentStore interface {
	FileContentSource
	DeleteRunContent(ctx context.Context, runID string) error
}

type RunContentDeleter interface {
	DeleteRunContent(ctx context.Context, runID string) error
}

type JournalStore interface {
	Root() string
	Create(ctx context.Context, value *model.RemediationJournal) error
	Load(ctx context.Context, runID string) (*model.RemediationJournal, error)
	Inspect(ctx context.Context, runID string) (journal.Inspection, error)
	Update(
		ctx context.Context,
		runID string,
		expectedRevision uint64,
		mutate func(*model.RemediationJournal) error,
	) (*model.RemediationJournal, error)
	ListRecoverable(ctx context.Context) ([]model.RemediationJournal, error)
}

type RemediationManager interface {
	Plan(ctx context.Context, request PlanRequest) (*model.RemediationJournal, error)
	Approve(ctx context.Context, runID string, approval model.Approval) error
	Cancel(ctx context.Context, runID string) error
	ApplyWithVerifier(ctx context.Context, runID string, runGuard ApplyRunGuard, effectGuard ApplyEffectGuard, verifier ApplyVerifier) error
	PreviewRollbackItem(ctx context.Context, runID, changeSetID string) (RollbackPreview, error)
	RollbackItem(ctx context.Context, runID, changeSetID string, cascadeApproved bool, previewDigest string, executorBuild model.RemediationBuildIdentity) (model.RollbackAttempt, error)
	PreviewRollbackRun(ctx context.Context, runID string) (RollbackPreview, error)
	RollbackRun(ctx context.Context, runID, previewDigest string, executorBuild model.RemediationBuildIdentity) (model.RollbackAttempt, error)
	Recover(ctx context.Context, runID string, observedByBuild model.RemediationBuildIdentity) (RecoveryAssessment, error)
}

type Manager struct {
	store       JournalStore
	stateRoot   string
	systemRoot  string
	host        hostCollector
	content     FileContentSource
	fileFactory fileRuntimeFactory
	locks       lockProvider
	newID       func(string) (string, error)
	now         func() time.Time
}

var _ RemediationManager = (*Manager)(nil)

func New(stateRoot, systemRoot string, content FileContentSource) (*Manager, error) {
	store, err := journal.New(stateRoot)
	if err != nil {
		return nil, wrapDependency("initialize", "", "", "", err)
	}
	return NewWithStore(store, systemRoot, content)
}

// NewWithStore accepts only the durable on-disk journal implementation used by
// production workflows. Tests in this package may use newWithStore directly.
func NewWithStore(store *journal.Store, systemRoot string, content FileContentSource) (*Manager, error) {
	return newWithStore(store, systemRoot, content)
}

func newWithStore(store JournalStore, systemRoot string, content FileContentSource) (*Manager, error) {
	collector, err := hostidentity.New(systemRoot)
	if err != nil {
		return nil, wrapDependency("initialize", "", "", "", err)
	}
	return newWithDependencies(store, systemRoot, content, managerDependencies{
		fileFactory: newRegularFileRuntime,
		host:        collector,
		locks:       systemLockProvider{},
		newID:       randomID,
		now:         time.Now,
	})
}

func newWithDependencies(store JournalStore, systemRoot string, content FileContentSource, dependencies managerDependencies) (*Manager, error) {
	if store == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: fmt.Errorf("journal store is required")}
	}
	if dependencies.fileFactory == nil || dependencies.host == nil || dependencies.locks == nil || dependencies.newID == nil || dependencies.now == nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: fmt.Errorf("internal remediation dependencies are required")}
	}
	stateRoot := strings.TrimSpace(store.Root())
	if stateRoot == "" || strings.IndexByte(stateRoot, 0) >= 0 {
		return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: fmt.Errorf("journal store root is invalid")}
	}
	absoluteStateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: err}
	}
	absoluteSystemRoot, err := filepath.Abs(systemRoot)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: err}
	}
	return &Manager{
		store:       store,
		stateRoot:   filepath.Clean(absoluteStateRoot),
		systemRoot:  filepath.Clean(absoluteSystemRoot),
		host:        dependencies.host,
		content:     content,
		fileFactory: dependencies.fileFactory,
		locks:       dependencies.locks,
		newID:       dependencies.newID,
		now:         dependencies.now,
	}, nil
}

func (m *Manager) nowUTC() time.Time {
	return m.now().UTC()
}

func (m *Manager) nextEventTime(value *model.RemediationJournal) time.Time {
	now := m.nowUTC()
	if value == nil {
		return now
	}
	latest := value.LatestEventTime()
	if now.After(latest) {
		return now
	}
	return latest.Add(time.Nanosecond)
}
