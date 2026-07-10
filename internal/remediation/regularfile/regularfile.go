package regularfile

import (
	"context"
	"fmt"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const defaultMaxFileSize int64 = 64 << 20

type ErrorCode string

const (
	CodeInvalidInput         ErrorCode = "invalid_input"
	CodeUnsafePath           ErrorCode = "unsafe_path"
	CodeUnsupportedFileType  ErrorCode = "unsupported_file_type"
	CodeSymlinkNotAllowed    ErrorCode = "symlink_not_allowed"
	CodeHardLinkNotSupported ErrorCode = "hard_link_not_supported"
	CodeFileChanged          ErrorCode = "external_change_detected"
	CodePreconditionFailed   ErrorCode = "precondition_failed"
	CodePostconditionFailed  ErrorCode = "postcondition_failed"
	CodeUnsupportedMetadata  ErrorCode = "unsupported_metadata"
	CodeSELinuxUnknown       ErrorCode = "selinux_restore_unknown"
	CodeBackupWriteFailed    ErrorCode = "backup_write_failed"
	CodeBackupMissing        ErrorCode = "backup_missing"
	CodeBackupHashMismatch   ErrorCode = "backup_hash_mismatch"
	CodeUnsupportedPlatform  ErrorCode = "unsupported_platform"
)

type Error struct {
	Code      ErrorCode
	Operation string
	Path      string
	Committed bool
	Err       error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	message := string(e.Code)
	if e.Operation != "" {
		message += " during " + e.Operation
	}
	if e.Path != "" {
		message += " for " + e.Path
	}
	if e.Committed {
		message += " after a possible metadata change"
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

func Committed(err error) bool {
	for err != nil {
		if structured, ok := err.(*Error); ok && structured.Committed {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = unwrapper.Unwrap()
	}
	return false
}

type DesiredMetadata struct {
	UID            int
	GID            int
	Mode           uint32
	SELinuxContext string
}

type config struct {
	maxFileSize int64
}

type Option func(*config) error

func WithMaxFileSize(limit int64) Option {
	return func(configuration *config) error {
		if limit <= 0 {
			return fmt.Errorf("maximum file size must be positive")
		}
		configuration.maxFileSize = limit
		return nil
	}
}

type Handler struct {
	systemRoot    string
	runDirectory  string
	maxFileSize   int64
	rootDevice    uint64
	rootInode     uint64
	runDevice     uint64
	runInode      uint64
	selinuxActive bool
}

func MetadataTransitionCandidate(before, desired, observed model.ResourceSnapshot) bool {
	if before.File == nil || desired.File == nil || observed.File == nil {
		return false
	}
	if before.Reference.Key == "" || before.Reference.Key != desired.Reference.Key || before.Reference.Key != observed.Reference.Key {
		return false
	}
	if !metadataImmutableEqual(*before.File, *desired.File) || !metadataImmutableEqual(*before.File, *observed.File) {
		return false
	}
	ownershipBefore := observed.File.UID == before.File.UID && observed.File.GID == before.File.GID
	ownershipDesired := observed.File.UID == desired.File.UID && observed.File.GID == desired.File.GID
	return (ownershipBefore || ownershipDesired) &&
		oneOfUint32(observed.File.Mode, before.File.Mode, desired.File.Mode)
}

func metadataImmutableEqual(left, right model.FileSnapshot) bool {
	return left.Path == right.Path &&
		left.Exists == right.Exists &&
		left.FileType == right.FileType &&
		left.Size == right.Size &&
		left.SHA256 == right.SHA256 &&
		left.LinkTarget == right.LinkTarget &&
		left.Device == right.Device &&
		left.Inode == right.Inode &&
		left.NLink == right.NLink &&
		left.ParentDevice == right.ParentDevice &&
		left.ParentInode == right.ParentInode &&
		left.XAttrDigest == right.XAttrDigest &&
		left.ACLDigest == right.ACLDigest &&
		left.SELinuxContext == right.SELinuxContext
}

func oneOfUint32(value, first, second uint32) bool {
	return value == first || value == second
}

func New(systemRoot, runDirectory string, options ...Option) (*Handler, error) {
	if strings.TrimSpace(systemRoot) == "" || strings.TrimSpace(runDirectory) == "" || strings.IndexByte(systemRoot, 0) >= 0 || strings.IndexByte(runDirectory, 0) >= 0 {
		return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: fmt.Errorf("system root and run directory are required and must not contain NUL bytes")}
	}
	configuration := config{maxFileSize: defaultMaxFileSize}
	for _, option := range options {
		if option == nil {
			return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: fmt.Errorf("option is nil")}
		}
		if err := option(&configuration); err != nil {
			return nil, &Error{Code: CodeInvalidInput, Operation: "initialize", Err: err}
		}
	}
	return newPlatform(systemRoot, runDirectory, configuration)
}

func (h *Handler) Kind() model.ResourceKind {
	return model.ResourceFile
}

func (h *Handler) Normalize(ctx context.Context, ref model.ResourceRef) (model.CanonicalResource, error) {
	return h.normalizePlatform(ctx, ref)
}

func (h *Handler) Capture(ctx context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
	return h.capturePlatform(ctx, resource)
}

func (h *Handler) BuildDesiredMetadata(ctx context.Context, resource model.CanonicalResource, metadata DesiredMetadata) (model.ResourceSnapshot, error) {
	return h.buildDesiredMetadataPlatform(ctx, resource, metadata)
}

func (h *Handler) Backup(ctx context.Context, changeSetID, operationID string, resource model.CanonicalResource, expected model.ResourceSnapshot) (model.BackupArtifact, error) {
	return h.backupPlatform(ctx, changeSetID, operationID, resource, expected)
}

func (h *Handler) VerifyBackup(ctx context.Context, artifact model.BackupArtifact) error {
	return h.verifyBackupPlatform(ctx, artifact)
}

func (h *Handler) ApplyMetadata(ctx context.Context, resource model.CanonicalResource, expectedBefore, desired model.ResourceSnapshot) (model.ResourceSnapshot, error) {
	return h.applyMetadataPlatform(ctx, resource, expectedBefore, desired)
}

func (h *Handler) Restore(ctx context.Context, operation model.OperationRecord, artifact model.BackupArtifact, allowPartialResume bool) (model.ResourceSnapshot, error) {
	return h.restorePlatform(ctx, operation, artifact, allowPartialResume)
}
