//go:build linux

package regularfile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
)

const (
	backupSchemaVersion = 1
	maxMetadataSize     = 1 << 20
)

type backupMetadata struct {
	SchemaVersion int                     `json:"schema_version"`
	Resource      model.CanonicalResource `json:"resource"`
	Snapshot      model.ResourceSnapshot  `json:"snapshot"`
}

func (m backupMetadata) validate() error {
	if m.SchemaVersion != backupSchemaVersion {
		return fmt.Errorf("unsupported backup metadata schema %d", m.SchemaVersion)
	}
	if err := m.Resource.Validate(); err != nil {
		return err
	}
	if err := m.Snapshot.Validate(); err != nil {
		return err
	}
	if m.Resource.Key != m.Snapshot.Reference.Key {
		return fmt.Errorf("backup metadata resource and snapshot differ")
	}
	if m.Snapshot.File == nil || !m.Snapshot.File.Exists || m.Snapshot.File.FileType != "regular" {
		return fmt.Errorf("backup metadata does not describe an existing regular file")
	}
	return nil
}

func (h *Handler) backupPlatform(ctx context.Context, changeSetID, operationID string, resource model.CanonicalResource, expected model.ResourceSnapshot) (model.BackupArtifact, error) {
	if h == nil {
		return model.BackupArtifact{}, &Error{Code: CodeInvalidInput, Operation: "backup", Err: fmt.Errorf("handler is nil")}
	}
	if err := ctx.Err(); err != nil {
		return model.BackupArtifact{}, err
	}
	target, err := h.validateResource(resource, "backup")
	if err != nil {
		return model.BackupArtifact{}, err
	}
	if !safeArtifactIdentifier(changeSetID) || !safeArtifactIdentifier(operationID) {
		return model.BackupArtifact{}, &Error{Code: CodeInvalidInput, Operation: "backup", Path: target, Err: fmt.Errorf("change-set and operation IDs must use only ASCII letters, digits, dot, underscore, or hyphen")}
	}
	if err := expected.Validate(); err != nil || expected.Reference.Key != resource.Key || expected.File == nil || !expected.File.Exists || expected.File.FileType != "regular" {
		if err == nil {
			err = fmt.Errorf("expected snapshot does not describe the target regular file")
		}
		return model.BackupArtifact{}, &Error{Code: CodeInvalidInput, Operation: "backup", Path: target, Err: err}
	}
	current, content, err := h.captureCurrent(ctx, resource)
	if err != nil {
		return model.BackupArtifact{}, err
	}
	if !exactSnapshotEqual(expected, current) {
		return model.BackupArtifact{}, &Error{Code: CodePreconditionFailed, Operation: "backup", Path: target, Err: fmt.Errorf("current file does not match the prepared snapshot")}
	}
	if current.File.NLink != 1 {
		return model.BackupArtifact{}, &Error{Code: CodeHardLinkNotSupported, Operation: "backup", Path: target, Err: fmt.Errorf("content backup is not sufficient to restore a hard-link relationship")}
	}
	contentDigest := sha256.Sum256(content)
	contentDigestText := hex.EncodeToString(contentDigest[:])
	if contentDigestText != expected.File.SHA256 || int64(len(content)) != expected.File.Size {
		return model.BackupArtifact{}, &Error{Code: CodeFileChanged, Operation: "backup", Path: target, Err: fmt.Errorf("captured content does not match the expected snapshot")}
	}
	metadata := backupMetadata{SchemaVersion: backupSchemaVersion, Resource: resource, Snapshot: expected}
	metadataBytes, err := journal.CanonicalJSON(metadata)
	if err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: target, Err: err}
	}
	metadataDigest := sha256.Sum256(metadataBytes)

	runFD, err := h.openRunRoot()
	if err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeUnsafePath, Operation: "backup", Path: h.runDirectory, Err: err}
	}
	defer syscall.Close(runFD)
	backupsFD, err := ensurePrivateDirectoryAt(runFD, "backups")
	if err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: h.runDirectory, Err: err}
	}
	defer syscall.Close(backupsFD)
	changeSetFD, err := ensurePrivateDirectoryAt(backupsFD, changeSetID)
	if err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: h.runDirectory, Err: err}
	}
	defer syscall.Close(changeSetFD)

	artifactName, artifactFD, err := createArtifactDirectory(changeSetFD, operationID)
	if err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: h.runDirectory, Err: err}
	}
	defer syscall.Close(artifactFD)
	if err := createPrivateFileAt(ctx, artifactFD, "content", content); err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: target, Err: err}
	}
	if err := createPrivateFileAt(ctx, artifactFD, "metadata.json", metadataBytes); err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: target, Err: err}
	}
	if err := syscall.Fsync(artifactFD); err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: target, Err: err}
	}

	storedContent, err := readPrivateRegularAt(ctx, artifactFD, "content", h.maxFileSize)
	if err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupHashMismatch, Operation: "backup", Path: target, Err: err}
	}
	storedMetadata, err := readPrivateRegularAt(ctx, artifactFD, "metadata.json", maxMetadataSize)
	if err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupHashMismatch, Operation: "backup", Path: target, Err: err}
	}
	if !bytes.Equal(storedContent, content) || !bytes.Equal(storedMetadata, metadataBytes) {
		return model.BackupArtifact{}, &Error{Code: CodeBackupHashMismatch, Operation: "backup", Path: target, Err: fmt.Errorf("backup readback differs from the captured bytes")}
	}
	for _, directoryFD := range []int{artifactFD, changeSetFD, backupsFD, runFD} {
		if err := syscall.Fsync(directoryFD); err != nil {
			return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: h.runDirectory, Err: err}
		}
	}

	artifactID := path.Join("backups", changeSetID, artifactName)
	artifact := model.BackupArtifact{
		ID:             artifactID,
		ContentPath:    path.Join(artifactID, "content"),
		MetadataPath:   path.Join(artifactID, "metadata.json"),
		ContentSize:    int64(len(content)),
		ContentSHA256:  contentDigestText,
		MetadataSHA256: hex.EncodeToString(metadataDigest[:]),
		Durable:        true,
	}
	if err := artifact.Validate(); err != nil {
		return model.BackupArtifact{}, &Error{Code: CodeBackupWriteFailed, Operation: "backup", Path: target, Err: err}
	}
	if err := h.verifyBackupPlatform(ctx, artifact); err != nil {
		return model.BackupArtifact{}, err
	}
	return artifact, nil
}

func (h *Handler) verifyBackupPlatform(ctx context.Context, artifact model.BackupArtifact) error {
	_, _, err := h.readVerifiedArtifact(ctx, artifact)
	return err
}

func (h *Handler) readVerifiedArtifact(ctx context.Context, artifact model.BackupArtifact) (backupMetadata, []byte, error) {
	if h == nil {
		return backupMetadata{}, nil, &Error{Code: CodeInvalidInput, Operation: "verify backup", Err: fmt.Errorf("handler is nil")}
	}
	if err := ctx.Err(); err != nil {
		return backupMetadata{}, nil, err
	}
	if err := artifact.Validate(); err != nil {
		return backupMetadata{}, nil, &Error{Code: CodeInvalidInput, Operation: "verify backup", Err: err}
	}
	components := strings.Split(artifact.ID, "/")
	if len(components) != 3 || components[0] != "backups" || !safeArtifactIdentifier(components[1]) || !safeArtifactDirectoryName(components[2]) || path.Clean(artifact.ID) != artifact.ID {
		return backupMetadata{}, nil, &Error{Code: CodeUnsafePath, Operation: "verify backup", Path: artifact.ID, Err: fmt.Errorf("artifact ID is not a canonical backup path")}
	}
	if artifact.ContentPath != path.Join(artifact.ID, "content") || artifact.MetadataPath != path.Join(artifact.ID, "metadata.json") {
		return backupMetadata{}, nil, &Error{Code: CodeUnsafePath, Operation: "verify backup", Path: artifact.ID, Err: fmt.Errorf("artifact file paths do not belong to the artifact directory")}
	}
	runFD, err := h.openRunRoot()
	if err != nil {
		return backupMetadata{}, nil, &Error{Code: CodeUnsafePath, Operation: "verify backup", Path: h.runDirectory, Err: err}
	}
	defer syscall.Close(runFD)
	currentFD := runFD
	opened := make([]int, 0, len(components))
	defer func() {
		for index := len(opened) - 1; index >= 0; index-- {
			_ = syscall.Close(opened[index])
		}
	}()
	for _, component := range components {
		nextFD, openErr := openPrivateDirectoryAt(currentFD, component)
		if openErr != nil {
			return backupMetadata{}, nil, &Error{Code: CodeBackupMissing, Operation: "verify backup", Path: artifact.ID, Err: openErr}
		}
		opened = append(opened, nextFD)
		currentFD = nextFD
	}
	content, err := readPrivateRegularAt(ctx, currentFD, "content", h.maxFileSize)
	if err != nil {
		return backupMetadata{}, nil, &Error{Code: CodeBackupMissing, Operation: "verify backup", Path: artifact.ContentPath, Err: err}
	}
	metadataBytes, err := readPrivateRegularAt(ctx, currentFD, "metadata.json", maxMetadataSize)
	if err != nil {
		return backupMetadata{}, nil, &Error{Code: CodeBackupMissing, Operation: "verify backup", Path: artifact.MetadataPath, Err: err}
	}
	contentDigest := sha256.Sum256(content)
	metadataDigest := sha256.Sum256(metadataBytes)
	if int64(len(content)) != artifact.ContentSize || hex.EncodeToString(contentDigest[:]) != artifact.ContentSHA256 || hex.EncodeToString(metadataDigest[:]) != artifact.MetadataSHA256 {
		return backupMetadata{}, nil, &Error{Code: CodeBackupHashMismatch, Operation: "verify backup", Path: artifact.ID, Err: fmt.Errorf("backup size or digest does not match the journal reference")}
	}
	var metadata backupMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return backupMetadata{}, nil, &Error{Code: CodeBackupHashMismatch, Operation: "verify backup", Path: artifact.MetadataPath, Err: err}
	}
	if err := metadata.validate(); err != nil {
		return backupMetadata{}, nil, &Error{Code: CodeBackupHashMismatch, Operation: "verify backup", Path: artifact.MetadataPath, Err: err}
	}
	canonical, err := journal.CanonicalJSON(metadata)
	if err != nil || !bytes.Equal(canonical, metadataBytes) {
		if err == nil {
			err = fmt.Errorf("backup metadata is not canonical JSON")
		}
		return backupMetadata{}, nil, &Error{Code: CodeBackupHashMismatch, Operation: "verify backup", Path: artifact.MetadataPath, Err: err}
	}
	return metadata, content, nil
}

func safeArtifactIdentifier(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
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

func safeArtifactDirectoryName(value string) bool {
	separator := strings.LastIndexByte(value, '-')
	if separator <= 0 || !safeArtifactIdentifier(value[:separator]) || len(value[separator+1:]) != 32 {
		return false
	}
	_, err := hex.DecodeString(value[separator+1:])
	return err == nil
}

func ensurePrivateDirectoryAt(parentFD int, name string) (int, error) {
	if !safeArtifactIdentifier(name) {
		return -1, fmt.Errorf("unsafe backup directory name")
	}
	err := syscall.Mkdirat(parentFD, name, 0o700)
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return -1, err
	}
	return openPrivateDirectoryAt(parentFD, name)
}

func openPrivateDirectoryAt(parentFD int, name string) (int, error) {
	if !safeArtifactIdentifier(name) && !safeArtifactDirectoryName(name) {
		return -1, fmt.Errorf("unsafe backup directory name")
	}
	fd, err := syscall.Openat(parentFD, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode)&0o7777 != 0o700 {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("backup path must be a private directory owned by the effective user")
	}
	return fd, nil
}

func createArtifactDirectory(parentFD int, operationID string) (string, int, error) {
	for attempt := 0; attempt < 8; attempt++ {
		randomBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
			return "", -1, err
		}
		name := operationID + "-" + hex.EncodeToString(randomBytes)
		if err := syscall.Mkdirat(parentFD, name, 0o700); errors.Is(err, syscall.EEXIST) {
			continue
		} else if err != nil {
			return "", -1, err
		}
		fd, err := openPrivateDirectoryAt(parentFD, name)
		if err != nil {
			return "", -1, err
		}
		return name, fd, nil
	}
	return "", -1, fmt.Errorf("could not allocate a unique backup artifact directory")
}

func createPrivateFileAt(ctx context.Context, directoryFD int, name string, data []byte) error {
	fd, err := syscall.Openat(directoryFD, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("create backup file handle")
	}
	closeNeeded := true
	defer func() {
		if closeNeeded {
			_ = file.Close()
		}
	}()
	if err := writeAllContext(ctx, file, data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closeNeeded = false
	return nil
}

func writeAllContext(ctx context.Context, writer io.Writer, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func readPrivateRegularAt(ctx context.Context, directoryFD int, name string, limit int64) ([]byte, error) {
	fd, err := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create backup file handle")
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Uid != uint32(os.Geteuid()) || uint32(before.Mode)&0o7777 != 0o600 || before.Nlink != 1 || before.Size < 0 || before.Size > limit {
		return nil, fmt.Errorf("backup file protection or size is invalid")
	}
	data, err := readExactContext(ctx, file, before.Size)
	if err != nil {
		return nil, err
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if !sameStableTarget(before, after) {
		return nil, fmt.Errorf("backup file changed while it was read")
	}
	return data, nil
}
