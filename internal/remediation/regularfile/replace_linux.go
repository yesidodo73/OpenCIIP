//go:build linux

package regularfile

import (
	"context"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
)

const metadataCleanupTimeout = 2 * time.Minute

func newMetadataCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), metadataCleanupTimeout)
}

func (h *Handler) applyMetadataPlatform(ctx context.Context, resource model.CanonicalResource, expectedBefore, desired model.ResourceSnapshot) (model.ResourceSnapshot, error) {
	if h == nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "apply metadata", Err: fmt.Errorf("handler is nil")}
	}
	target, err := h.validateResource(resource, "apply metadata")
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	if err := h.validateMetadataInputs(resource, expectedBefore, desired); err != nil {
		return model.ResourceSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return model.ResourceSnapshot{}, err
	}
	opened, err := h.openCurrentWritable(target, "apply metadata")
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	defer opened.close()
	current, _, err := h.snapshotOpened(ctx, resource, target, opened)
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	if !exactSnapshotEqual(expectedBefore, current) {
		return model.ResourceSnapshot{}, &Error{Code: CodePreconditionFailed, Operation: "apply metadata", Path: target, Err: fmt.Errorf("current file does not match the approved inode and fingerprint")}
	}
	if exactSnapshotEqual(desired, current) {
		return current, nil
	}
	if err := ctx.Err(); err != nil {
		return model.ResourceSnapshot{}, err
	}
	ownershipChange := current.File.UID != desired.File.UID || current.File.GID != desired.File.GID
	modeChange := current.File.Mode != desired.File.Mode
	modeWriteRequired := modeChange || ownershipChange
	if ownershipChange {
		if err := syscall.Fchown(opened.fd, desired.File.UID, desired.File.GID); err != nil {
			return h.metadataMutationFailure(ctx, resource, target, opened, "change ownership", err)
		}
		if modeWriteRequired {
			if err := ctx.Err(); err != nil {
				return h.metadataMutationFailure(ctx, resource, target, opened, "change ownership", err)
			}
		}
	}
	if modeWriteRequired {
		if err := syscall.Fchmod(opened.fd, desired.File.Mode); err != nil {
			return h.metadataMutationFailure(ctx, resource, target, opened, "change mode", err)
		}
	}
	if err := opened.file.Sync(); err != nil {
		return h.metadataMutationFailure(ctx, resource, target, opened, "sync metadata", err)
	}
	cleanupContext, cancelCleanup := newMetadataCleanupContext(ctx)
	defer cancelCleanup()
	observed, err := h.snapshotOpenedAfterMutation(cleanupContext, resource, target, opened)
	if err != nil {
		return model.ResourceSnapshot{}, committedMetadataError(target, "verify metadata", err)
	}
	if !exactSnapshotEqual(desired, observed) {
		return observed, &Error{Code: CodePostconditionFailed, Operation: "verify metadata", Path: target, Committed: true, Err: fmt.Errorf("file metadata does not match the approved desired state")}
	}
	return observed, nil
}

func (h *Handler) validateMetadataInputs(resource model.CanonicalResource, expectedBefore, desired model.ResourceSnapshot) error {
	target := resource.Reference.ID
	for label, snapshot := range map[string]model.ResourceSnapshot{"expected before": expectedBefore, "desired": desired} {
		if err := snapshot.Validate(); err != nil {
			return &Error{Code: CodeInvalidInput, Operation: "apply metadata", Path: target, Err: fmt.Errorf("%s snapshot: %w", label, err)}
		}
		if snapshot.Reference.Key != resource.Key || snapshot.File == nil || !snapshot.File.Exists || snapshot.File.FileType != "regular" || snapshot.File.Path != target {
			return &Error{Code: CodeInvalidInput, Operation: "apply metadata", Path: target, Err: fmt.Errorf("%s snapshot does not describe the target regular file", label)}
		}
		metadataDigest, err := digestFileMetadata(*snapshot.File)
		if err != nil || metadataDigest != snapshot.File.MetadataDigest {
			if err == nil {
				err = fmt.Errorf("metadata digest is inconsistent")
			}
			return &Error{Code: CodeInvalidInput, Operation: "apply metadata", Path: target, Err: fmt.Errorf("%s snapshot: %w", label, err)}
		}
		fingerprint, err := fingerprintFile(*snapshot.File)
		if err != nil || fingerprint != snapshot.Fingerprint {
			if err == nil {
				err = fmt.Errorf("fingerprint is inconsistent")
			}
			return &Error{Code: CodeInvalidInput, Operation: "apply metadata", Path: target, Err: fmt.Errorf("%s snapshot: %w", label, err)}
		}
	}
	if expectedBefore.File.NLink != 1 || desired.File.NLink != 1 {
		return &Error{Code: CodeHardLinkNotSupported, Operation: "apply metadata", Path: target, Err: fmt.Errorf("metadata remediation requires a single-link file")}
	}
	if !metadataImmutableEqual(*expectedBefore.File, *desired.File) {
		return &Error{Code: CodeUnsupportedMetadata, Operation: "apply metadata", Path: target, Err: fmt.Errorf("file metadata remediation must preserve inode, parent, content, links, xattrs, ACL, and SELinux context")}
	}
	if desired.File.Mode&^expectedBefore.File.Mode != 0 {
		return &Error{Code: CodeUnsupportedMetadata, Operation: "apply metadata", Path: target, Err: fmt.Errorf("file metadata remediation must not add permission or special-mode bits")}
	}
	if desired.File.UID < 0 || desired.File.GID < 0 || desired.File.Mode&^uint32(0o7777) != 0 {
		return &Error{Code: CodeUnsupportedMetadata, Operation: "apply metadata", Path: target, Err: fmt.Errorf("desired ownership or mode is unsupported")}
	}
	if h.selinuxActive && desired.File.SELinuxContext == "" {
		return &Error{Code: CodeSELinuxUnknown, Operation: "apply metadata", Path: target, Err: fmt.Errorf("SELinux is active but the preserved context is unknown")}
	}
	return nil
}

func (h *Handler) metadataMutationFailure(ctx context.Context, resource model.CanonicalResource, target string, opened *openedTarget, stage string, cause error) (model.ResourceSnapshot, error) {
	cleanupContext, cancelCleanup := newMetadataCleanupContext(ctx)
	defer cancelCleanup()
	if syncErr := opened.file.Sync(); syncErr != nil {
		cause = fmt.Errorf("%v; sync partial metadata: %w", cause, syncErr)
	}
	observed, observeErr := h.snapshotOpenedAfterMutation(cleanupContext, resource, target, opened)
	if observeErr != nil {
		return model.ResourceSnapshot{}, committedMetadataError(target, stage, fmt.Errorf("%v; post-mutation observation failed: %w", cause, observeErr))
	}
	return observed, &Error{Code: CodePostconditionFailed, Operation: stage, Path: target, Committed: true, Err: cause}
}

func (h *Handler) snapshotOpenedAfterMutation(ctx context.Context, resource model.CanonicalResource, target string, opened *openedTarget) (model.ResourceSnapshot, error) {
	if _, err := opened.file.Seek(0, io.SeekStart); err != nil {
		return model.ResourceSnapshot{}, &Error{Code: CodePostconditionFailed, Operation: "observe metadata", Path: target, Committed: true, Err: err}
	}
	if err := syscall.Fstat(opened.fd, &opened.stat); err != nil {
		return model.ResourceSnapshot{}, &Error{Code: CodePostconditionFailed, Operation: "observe metadata", Path: target, Committed: true, Err: err}
	}
	observed, _, err := h.snapshotOpened(ctx, resource, target, opened)
	return observed, err
}

func committedMetadataError(target, operation string, err error) error {
	code := CodePostconditionFailed
	if CodeOf(err) == CodeFileChanged || CodeOf(err) == CodeSymlinkNotAllowed || CodeOf(err) == CodeUnsupportedFileType {
		code = CodeFileChanged
	}
	return &Error{Code: code, Operation: operation, Path: target, Committed: true, Err: err}
}

func (h *Handler) restorePlatform(ctx context.Context, operation model.OperationRecord, artifact model.BackupArtifact, allowPartialResume bool) (model.ResourceSnapshot, error) {
	if h == nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "restore metadata", Err: fmt.Errorf("handler is nil")}
	}
	if err := ctx.Err(); err != nil {
		return model.ResourceSnapshot{}, err
	}
	if err := operation.Validate(); err != nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "restore metadata", Err: err}
	}
	if operation.Kind != model.OperationFileMetadata {
		return model.ResourceSnapshot{}, &Error{Code: CodeUnsupportedFileType, Operation: "restore metadata", Path: operation.Resource.Reference.ID, Err: fmt.Errorf("only regular-file metadata rollback is implemented")}
	}
	if operation.Backup == nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeBackupMissing, Operation: "restore metadata", Path: operation.Resource.Reference.ID, Err: fmt.Errorf("operation has no durable backup reference")}
	}
	recordedArtifact, err := journal.CanonicalJSON(*operation.Backup)
	if err != nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "restore metadata", Err: err}
	}
	providedArtifact, err := journal.CanonicalJSON(artifact)
	if err != nil || string(recordedArtifact) != string(providedArtifact) {
		if err == nil {
			err = fmt.Errorf("provided artifact differs from the operation backup reference")
		}
		return model.ResourceSnapshot{}, &Error{Code: CodeBackupHashMismatch, Operation: "restore metadata", Path: artifact.ID, Err: err}
	}
	metadata, _, err := h.readVerifiedArtifact(ctx, artifact)
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	if metadata.Resource.Key != operation.Resource.Key || !recordedSnapshotEqual(metadata.Snapshot, operation.Before) {
		return model.ResourceSnapshot{}, &Error{Code: CodeBackupHashMismatch, Operation: "restore metadata", Path: artifact.ID, Err: fmt.Errorf("backup metadata does not match the operation before state")}
	}
	target, err := h.validateResource(operation.Resource, "restore metadata")
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	current, _, err := h.captureCurrent(ctx, operation.Resource)
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	if exactSnapshotEqual(operation.Before, current) {
		return current, nil
	}
	observedAfter := operation.ObservedAfter != nil && exactSnapshotEqual(*operation.ObservedAfter, current)
	partial := allowPartialResume && MetadataTransitionCandidate(operation.Before, operation.Desired, current)
	if !observedAfter && !partial {
		return model.ResourceSnapshot{}, &Error{Code: CodeFileChanged, Operation: "restore metadata", Path: target, Err: fmt.Errorf("current file is neither the durable after state nor a safe metadata transition on the original inode")}
	}
	restored, err := h.applyMetadataPlatform(ctx, operation.Resource, current, operation.Before)
	if err != nil {
		return restored, err
	}
	if !exactSnapshotEqual(operation.Before, restored) {
		return restored, &Error{Code: CodePostconditionFailed, Operation: "restore metadata", Path: target, Committed: true, Err: fmt.Errorf("restored metadata does not match the durable before state")}
	}
	return restored, nil
}
