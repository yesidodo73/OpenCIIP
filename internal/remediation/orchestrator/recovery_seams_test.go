package orchestrator

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
)

var errUnscriptedTestCall = errors.New("unscripted test dependency call")

var _ func(*journal.Store, string, FileContentSource) (*Manager, error) = NewWithStore

type scriptedJournalStore struct {
	root        string
	create      func(context.Context, *model.RemediationJournal) error
	load        func(context.Context, string) (*model.RemediationJournal, error)
	inspect     func(context.Context, string) (journal.Inspection, error)
	update      func(context.Context, string, uint64, func(*model.RemediationJournal) error) (*model.RemediationJournal, error)
	recoverable func(context.Context) ([]model.RemediationJournal, error)
}

func (s *scriptedJournalStore) Root() string {
	return s.root
}

func (s *scriptedJournalStore) Create(ctx context.Context, value *model.RemediationJournal) error {
	if s.create == nil {
		return errUnscriptedTestCall
	}
	return s.create(ctx, value)
}

func (s *scriptedJournalStore) Load(ctx context.Context, runID string) (*model.RemediationJournal, error) {
	if s.load == nil {
		return nil, errUnscriptedTestCall
	}
	return s.load(ctx, runID)
}

func (s *scriptedJournalStore) Inspect(ctx context.Context, runID string) (journal.Inspection, error) {
	if s.inspect == nil {
		return journal.Inspection{}, errUnscriptedTestCall
	}
	return s.inspect(ctx, runID)
}

func (s *scriptedJournalStore) Update(
	ctx context.Context,
	runID string,
	expectedRevision uint64,
	mutate func(*model.RemediationJournal) error,
) (*model.RemediationJournal, error) {
	if s.update == nil {
		return nil, errUnscriptedTestCall
	}
	return s.update(ctx, runID, expectedRevision, mutate)
}

func (s *scriptedJournalStore) ListRecoverable(ctx context.Context) ([]model.RemediationJournal, error) {
	if s.recoverable == nil {
		return nil, errUnscriptedTestCall
	}
	return s.recoverable(ctx)
}

type scriptedFileRuntime struct {
	normalize            func(context.Context, model.ResourceRef) (model.CanonicalResource, error)
	capture              func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error)
	buildDesiredMetadata func(context.Context, model.CanonicalResource, regularfile.DesiredMetadata) (model.ResourceSnapshot, error)
	backup               func(context.Context, string, string, model.CanonicalResource, model.ResourceSnapshot) (model.BackupArtifact, error)
	verifyBackup         func(context.Context, model.BackupArtifact) error
	applyMetadata        func(context.Context, model.CanonicalResource, model.ResourceSnapshot, model.ResourceSnapshot) (model.ResourceSnapshot, error)
	restore              func(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error)
	captureCalls         []string
	mutationCalls        []string
}

func (s *scriptedFileRuntime) Normalize(ctx context.Context, ref model.ResourceRef) (model.CanonicalResource, error) {
	if s.normalize == nil {
		return model.CanonicalResource{}, errUnscriptedTestCall
	}
	return s.normalize(ctx, ref)
}

func (s *scriptedFileRuntime) Capture(ctx context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
	s.captureCalls = append(s.captureCalls, resource.Key)
	if s.capture == nil {
		return model.ResourceSnapshot{}, errUnscriptedTestCall
	}
	return s.capture(ctx, resource)
}

func (s *scriptedFileRuntime) BuildDesiredMetadata(ctx context.Context, resource model.CanonicalResource, desired regularfile.DesiredMetadata) (model.ResourceSnapshot, error) {
	if s.buildDesiredMetadata == nil {
		return model.ResourceSnapshot{}, errUnscriptedTestCall
	}
	return s.buildDesiredMetadata(ctx, resource, desired)
}

func (s *scriptedFileRuntime) Backup(ctx context.Context, changeSetID, operationID string, resource model.CanonicalResource, expected model.ResourceSnapshot) (model.BackupArtifact, error) {
	if s.backup == nil {
		return model.BackupArtifact{}, errUnscriptedTestCall
	}
	return s.backup(ctx, changeSetID, operationID, resource, expected)
}

func (s *scriptedFileRuntime) VerifyBackup(ctx context.Context, artifact model.BackupArtifact) error {
	if s.verifyBackup == nil {
		return errUnscriptedTestCall
	}
	return s.verifyBackup(ctx, artifact)
}

func (s *scriptedFileRuntime) ApplyMetadata(ctx context.Context, resource model.CanonicalResource, before, desired model.ResourceSnapshot) (model.ResourceSnapshot, error) {
	s.mutationCalls = append(s.mutationCalls, "apply:"+resource.Key)
	if s.applyMetadata == nil {
		return model.ResourceSnapshot{}, errUnscriptedTestCall
	}
	return s.applyMetadata(ctx, resource, before, desired)
}

func (s *scriptedFileRuntime) Restore(ctx context.Context, operation model.OperationRecord, artifact model.BackupArtifact) (model.ResourceSnapshot, error) {
	s.mutationCalls = append(s.mutationCalls, "restore:"+operation.Resource.Key)
	if s.restore == nil {
		return model.ResourceSnapshot{}, errUnscriptedTestCall
	}
	return s.restore(ctx, operation, artifact)
}

type scriptedHostCollector struct {
	identity model.HostIdentity
	err      error
}

func (s scriptedHostCollector) Collect(context.Context) (model.HostIdentity, error) {
	return s.identity, s.err
}

type scriptedLockHandle struct {
	releases int
}

func (s *scriptedLockHandle) Release() error {
	s.releases++
	return nil
}

type scriptedLockProvider struct {
	handle        *scriptedLockHandle
	err           error
	acquireModes  []string
	acquiredRoots []string
}

func (s *scriptedLockProvider) Acquire(_ context.Context, root string) (lockHandle, error) {
	s.acquireModes = append(s.acquireModes, "create")
	s.acquiredRoots = append(s.acquiredRoots, root)
	return s.handle, s.err
}

func (s *scriptedLockProvider) AcquireExisting(_ context.Context, root string) (lockHandle, error) {
	s.acquireModes = append(s.acquireModes, "existing")
	s.acquiredRoots = append(s.acquiredRoots, root)
	return s.handle, s.err
}

type sequenceIDSource struct {
	values []string
	index  int
}

func (s *sequenceIDSource) Next(prefix string) (string, error) {
	if s.index >= len(s.values) {
		return "", errUnscriptedTestCall
	}
	value := prefix + s.values[s.index]
	s.index++
	return value, nil
}

func TestPackagePrivateDependenciesAreDeterministic(t *testing.T) {
	stateRoot := t.TempDir()
	systemRoot := t.TempDir()
	runtime := &scriptedFileRuntime{}
	locks := &scriptedLockProvider{handle: &scriptedLockHandle{}}
	ids := &sequenceIDSource{values: []string{"001"}}
	host := model.HostIdentity{BootID: "12345678-1234-1234-1234-123456789abc"}
	fixedNow := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	factoryCalls := 0

	manager, err := newWithDependencies(
		&scriptedJournalStore{root: stateRoot},
		systemRoot,
		nil,
		managerDependencies{
			fileFactory: func(gotSystemRoot, runDirectory string) (fileRuntime, error) {
				factoryCalls++
				if gotSystemRoot != filepath.Clean(systemRoot) {
					t.Fatalf("system root = %q, want %q", gotSystemRoot, filepath.Clean(systemRoot))
				}
				if runDirectory != filepath.Join(filepath.Clean(stateRoot), "run-a") {
					t.Fatalf("run directory = %q", runDirectory)
				}
				return runtime, nil
			},
			host:  scriptedHostCollector{identity: host},
			locks: locks,
			newID: ids.Next,
			now:   func() time.Time { return fixedNow },
		},
	)
	if err != nil {
		t.Fatalf("newWithDependencies() error = %v", err)
	}
	if _, err := manager.fileHandler("run-a"); err != nil {
		t.Fatalf("fileHandler() error = %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("file factory calls = %d, want 1", factoryCalls)
	}
	if got, err := manager.nextID("rollback-"); err != nil || got != "rollback-001" {
		t.Fatalf("nextID() = %q, %v", got, err)
	}
	if got := manager.nowUTC(); !got.Equal(fixedNow) {
		t.Fatalf("nowUTC() = %s, want %s", got, fixedNow)
	}
	if got, err := manager.collectHost(context.Background()); err != nil || got != host {
		t.Fatalf("collectHost() = %#v, %v", got, err)
	}
	handle, err := manager.acquire(context.Background(), "test")
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}
	if err := handle.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	readOnlyHandle, err := manager.acquireReadOnly(context.Background(), "test read-only")
	if err != nil {
		t.Fatalf("acquireReadOnly() error = %v", err)
	}
	if err := readOnlyHandle.Release(); err != nil {
		t.Fatalf("read-only Release() error = %v", err)
	}
	if len(locks.acquireModes) != 2 || locks.acquireModes[0] != "create" || locks.acquireModes[1] != "existing" || locks.handle.releases != 2 {
		t.Fatalf("unexpected lock calls: modes=%v releases=%d", locks.acquireModes, locks.handle.releases)
	}
}

func TestCanResolveNoEffectRequiresUncommittedForwardHistory(t *testing.T) {
	base := testInterruptedOperation(model.OperationApplyIntentDurable)
	desired := testFileSnapshot("b", 0o600, testTime().Add(3*time.Second))
	appliedAt := testTime().Add(4 * time.Second)
	rollbackIntentAt := testTime().Add(5 * time.Second)

	tests := []struct {
		name      string
		operation model.OperationRecord
		want      bool
	}{
		{name: "apply intent", operation: base, want: true},
		{name: "ambiguous without completion markers", operation: func() model.OperationRecord { value := base; value.State = model.OperationAmbiguous; return value }(), want: true},
		{name: "applied timestamp", operation: func() model.OperationRecord { value := base; value.AppliedAt = &appliedAt; return value }(), want: false},
		{name: "rollback intent", operation: func() model.OperationRecord { value := base; value.RollbackIntentAt = &rollbackIntentAt; return value }(), want: false},
		{name: "different durable after", operation: func() model.OperationRecord { value := base; value.ObservedAfter = &desired; return value }(), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := canResolveNoEffect(test.operation); got != test.want {
				t.Fatalf("canResolveNoEffect() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestCanInferInterruptedApplyRequiresMarkerlessStateInferableIntent(t *testing.T) {
	base := testInterruptedOperation(model.OperationApplyIntentDurable)
	desired := testFileSnapshot("b", 0o600, testTime().Add(3*time.Second))
	appliedAt := testTime().Add(4 * time.Second)
	rollbackIntentAt := testTime().Add(5 * time.Second)

	tests := []struct {
		name      string
		operation model.OperationRecord
		want      bool
	}{
		{name: "apply intent", operation: base, want: true},
		{name: "ambiguous interrupted apply", operation: func() model.OperationRecord { value := base; value.State = model.OperationAmbiguous; return value }(), want: true},
		{name: "manual recovery", operation: func() model.OperationRecord { value := base; value.RecoveryMode = model.RecoveryManual; return value }(), want: false},
		{name: "applied timestamp", operation: func() model.OperationRecord { value := base; value.AppliedAt = &appliedAt; return value }(), want: false},
		{name: "durable after", operation: func() model.OperationRecord { value := base; value.ObservedAfter = &desired; return value }(), want: false},
		{name: "rollback intent", operation: func() model.OperationRecord { value := base; value.RollbackIntentAt = &rollbackIntentAt; return value }(), want: false},
		{name: "already applied state", operation: func() model.OperationRecord { value := base; value.State = model.OperationApplied; return value }(), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := canInferInterruptedApply(test.operation); got != test.want {
				t.Fatalf("canInferInterruptedApply() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestResolveOperationPreservesExistingAppliedAt(t *testing.T) {
	operation := testInterruptedOperation(model.OperationAmbiguous)
	observed := operation.Desired
	originalAppliedAt := testTime().Add(3 * time.Second)
	operation.ObservedAfter = &observed
	operation.AppliedAt = &originalAppliedAt
	value := &model.RemediationJournal{
		Revision: 1,
		RunID:    "run-a",
		ChangeSets: []model.ChangeSet{{
			ID:         "change-a",
			Operations: []model.OperationRecord{operation},
		}},
	}
	store := &scriptedJournalStore{
		update: func(_ context.Context, runID string, expectedRevision uint64, mutate func(*model.RemediationJournal) error) (*model.RemediationJournal, error) {
			if runID != value.RunID || expectedRevision != value.Revision {
				t.Fatalf("Update(%q, %d), want (%q, %d)", runID, expectedRevision, value.RunID, value.Revision)
			}
			if err := mutate(value); err != nil {
				return nil, err
			}
			value.Revision++
			return value, nil
		},
	}
	manager := &Manager{store: store, now: func() time.Time { return testTime().Add(time.Hour) }}

	got, err := manager.resolveOperation(context.Background(), value, "change-a", operation.ID, model.OperationApplied, &observed)
	if err != nil {
		t.Fatalf("resolveOperation() error = %v", err)
	}
	resolved, _, _, err := findOperation(got, "change-a", operation.ID)
	if err != nil {
		t.Fatalf("findOperation() error = %v", err)
	}
	if resolved.AppliedAt == nil || !resolved.AppliedAt.Equal(originalAppliedAt) {
		t.Fatalf("AppliedAt = %v, want preserved %s", resolved.AppliedAt, originalAppliedAt)
	}
}

func TestRecoverOperationChainsSkipsDurableNoEffectWriter(t *testing.T) {
	operation := testNoEffectOperation("operation-a")
	value := &model.RemediationJournal{
		RunID: "run-a",
		State: model.RunApplying,
		ChangeSets: []model.ChangeSet{{
			ID:         "change-a",
			Sequence:   1,
			State:      model.ChangeApplyFailed,
			Operations: []model.OperationRecord{operation},
		}},
	}
	runtime := &scriptedFileRuntime{
		capture: func(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
			return model.ResourceSnapshot{}, errors.New("durable no-effect writer must not be captured")
		},
	}
	assessment := RecoveryAssessment{}

	got, err := (&Manager{}).recoverOperationChains(context.Background(), value, runtime, &assessment, nil, faultRecoveryObserverBuild())
	if err != nil {
		t.Fatalf("recoverOperationChains() error = %v", err)
	}
	if got != value {
		t.Fatal("recoverOperationChains() replaced an unchanged journal")
	}
	if len(runtime.captureCalls) != 0 || len(runtime.mutationCalls) != 0 {
		t.Fatalf("no-effect writer touched runtime: captures=%v mutations=%v", runtime.captureCalls, runtime.mutationCalls)
	}
	if len(assessment.NotApplied) != 1 || assessment.NotApplied[0] != "change-a/operation-a" {
		t.Fatalf("NotApplied = %v", assessment.NotApplied)
	}
}

func TestClassifyRollbackRunStatePreservesApplyFailure(t *testing.T) {
	rolledBack := model.ChangeSet{
		ID:    "change-a",
		State: model.ChangeRolledBack,
		Operations: []model.OperationRecord{{
			ID:    "operation-a",
			State: model.OperationRolledBack,
		}},
	}
	applyFailed := model.ChangeSet{
		ID:         "change-b",
		State:      model.ChangeApplyFailed,
		Operations: []model.OperationRecord{testNoEffectOperation("operation-b")},
		Error:      testApplyError("change-b", "operation-b"),
	}
	value := &model.RemediationJournal{ChangeSets: []model.ChangeSet{rolledBack, applyFailed}}

	if got := classifyRollbackRunState(value, []string{"change-a"}, model.RollbackItem); got != model.RunFailed {
		t.Fatalf("classifyRollbackRunState() = %s, want %s", got, model.RunFailed)
	}
}

func testInterruptedOperation(state model.OperationState) model.OperationRecord {
	before := testFileSnapshot("a", 0o644, testTime())
	desired := testFileSnapshot("b", 0o600, testTime().Add(time.Second))
	intentAt := testTime().Add(2 * time.Second)
	backup := testBackup("backup-a")
	return model.OperationRecord{
		ID:            "operation-a",
		Kind:          model.OperationFileMetadata,
		RecoveryMode:  model.RecoveryStateInferable,
		State:         state,
		Resource:      before.Reference,
		Before:        before,
		Desired:       desired,
		Backup:        &backup,
		ApplyIntentAt: &intentAt,
	}
}

func testNoEffectOperation(id string) model.OperationRecord {
	operation := testInterruptedOperation(model.OperationFailed)
	operation.ID = id
	observed := testFileSnapshot("a", 0o644, testTime().Add(3*time.Second))
	operation.ObservedAfter = &observed
	operation.Error = testApplyError("change-a", id)
	return operation
}

func testFileSnapshot(fingerprintSeed string, mode uint32, capturedAt time.Time) model.ResourceSnapshot {
	return model.ResourceSnapshot{
		Reference: model.CanonicalResource{
			Reference: model.ResourceRef{Kind: model.ResourceFile, ID: "/etc/open-ciip-test"},
			Key:       "file:/etc/open-ciip-test",
		},
		Fingerprint: strings.Repeat(fingerprintSeed, 64),
		File: &model.FileSnapshot{
			Path:         "/etc/open-ciip-test",
			Exists:       true,
			FileType:     "regular",
			Mode:         mode,
			UID:          0,
			GID:          0,
			SHA256:       strings.Repeat("c", 64),
			Device:       1,
			Inode:        2,
			NLink:        1,
			ParentDevice: 1,
			ParentInode:  3,
			CapturedAt:   capturedAt,
		},
	}
}

func testBackup(id string) model.BackupArtifact {
	return model.BackupArtifact{
		ID:             id,
		MetadataPath:   "backups/" + id + ".json",
		MetadataSHA256: strings.Repeat("d", 64),
		Durable:        true,
	}
}

func testApplyError(changeSetID, operationID string) *model.JournalError {
	return &model.JournalError{
		Code:        model.JournalErrorApplyFailed,
		Phase:       "apply",
		ChangeSetID: changeSetID,
		OperationID: operationID,
		Message:     "apply failed during deterministic test",
		OccurredAt:  testTime().Add(4 * time.Second),
	}
}

func testTime() time.Time {
	return time.Date(2026, time.July, 11, 10, 0, 0, 0, time.UTC)
}
