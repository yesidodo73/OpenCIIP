package orchestrator

import (
	"context"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/runlock"
)

type fileRuntime interface {
	Normalize(context.Context, model.ResourceRef) (model.CanonicalResource, error)
	Capture(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error)
	BuildDesiredMetadata(context.Context, model.CanonicalResource, regularfile.DesiredMetadata) (model.ResourceSnapshot, error)
	Backup(context.Context, string, string, model.CanonicalResource, model.ResourceSnapshot) (model.BackupArtifact, error)
	VerifyBackup(context.Context, model.BackupArtifact) error
	ApplyMetadata(context.Context, model.CanonicalResource, model.ResourceSnapshot, model.ResourceSnapshot) (model.ResourceSnapshot, error)
	Restore(context.Context, model.OperationRecord, model.BackupArtifact) (model.ResourceSnapshot, error)
}

type fileRuntimeFactory func(systemRoot, runDirectory string) (fileRuntime, error)

type hostCollector interface {
	Collect(context.Context) (model.HostIdentity, error)
}

type lockHandle interface {
	Release() error
}

type lockProvider interface {
	Acquire(context.Context, string) (lockHandle, error)
	AcquireExisting(context.Context, string) (lockHandle, error)
}

type systemLockProvider struct{}

func (systemLockProvider) Acquire(ctx context.Context, stateRoot string) (lockHandle, error) {
	return runlock.Acquire(ctx, stateRoot)
}

func (systemLockProvider) AcquireExisting(ctx context.Context, stateRoot string) (lockHandle, error) {
	return runlock.AcquireExisting(ctx, stateRoot)
}

func newRegularFileRuntime(systemRoot, runDirectory string) (fileRuntime, error) {
	return regularfile.New(systemRoot, runDirectory)
}

type managerDependencies struct {
	fileFactory fileRuntimeFactory
	host        hostCollector
	locks       lockProvider
	newID       func(string) (string, error)
	now         func() time.Time
}
