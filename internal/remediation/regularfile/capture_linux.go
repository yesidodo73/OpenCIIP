//go:build linux

package regularfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
)

const maxXAttrListSize = 64 << 10

func (h *Handler) capturePlatform(ctx context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error) {
	snapshot, _, err := h.captureCurrent(ctx, resource)
	return snapshot, err
}

func (h *Handler) captureCurrent(ctx context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, []byte, error) {
	if h == nil {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeInvalidInput, Operation: "capture", Err: fmt.Errorf("handler is nil")}
	}
	if err := ctx.Err(); err != nil {
		return model.ResourceSnapshot{}, nil, err
	}
	target, err := h.validateResource(resource, "capture")
	if err != nil {
		return model.ResourceSnapshot{}, nil, err
	}
	opened, err := h.openCurrent(target, "capture")
	if err != nil {
		return model.ResourceSnapshot{}, nil, err
	}
	defer opened.close()
	return h.snapshotOpened(ctx, resource, target, opened)
}

func (h *Handler) snapshotOpened(ctx context.Context, resource model.CanonicalResource, target string, opened *openedTarget) (model.ResourceSnapshot, []byte, error) {
	before := opened.stat
	if before.Size < 0 || before.Size > h.maxFileSize {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeUnsupportedFileType, Operation: "capture", Path: target, Err: fmt.Errorf("file size is outside the configured safe range")}
	}
	content, err := readExactContext(ctx, opened.file, before.Size)
	if err != nil {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeFileChanged, Operation: "capture", Path: target, Err: err}
	}
	xattrs, err := h.readSupportedXAttrs(opened.fd, target, "capture")
	if err != nil {
		return model.ResourceSnapshot{}, nil, err
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(opened.fd, &after); err != nil {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeUnsafePath, Operation: "capture", Path: target, Err: err}
	}
	if !sameStableTarget(before, after) {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeFileChanged, Operation: "capture", Path: target, Err: fmt.Errorf("file changed while its snapshot was captured")}
	}
	pathStat, err := statTargetAt(opened.parentFD, opened.name)
	if err != nil {
		return model.ResourceSnapshot{}, nil, classifyTargetError("capture", target, err)
	}
	if !sameStableTarget(after, pathStat) {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeFileChanged, Operation: "capture", Path: target, Err: fmt.Errorf("path no longer names the captured file")}
	}
	var parentAfter syscall.Stat_t
	if err := syscall.Fstat(opened.parentFD, &parentAfter); err != nil {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeUnsafePath, Operation: "capture", Path: target, Err: err}
	}
	if opened.parentStat.Dev != parentAfter.Dev || opened.parentStat.Ino != parentAfter.Ino {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeFileChanged, Operation: "capture", Path: target, Err: fmt.Errorf("target parent changed while the snapshot was captured")}
	}
	if err := h.validateOpenedPathIdentity(opened, "capture", target); err != nil {
		return model.ResourceSnapshot{}, nil, err
	}

	contentDigest := sha256.Sum256(content)
	xattrDigest := digestXAttrs(xattrs)
	selinuxContext := string(xattrs["security.selinux"])
	fileSnapshot := model.FileSnapshot{
		Path:           target,
		Exists:         true,
		FileType:       "regular",
		Mode:           uint32(after.Mode) & 0o7777,
		UID:            int(after.Uid),
		GID:            int(after.Gid),
		Size:           after.Size,
		SHA256:         hex.EncodeToString(contentDigest[:]),
		Device:         uint64(after.Dev),
		Inode:          after.Ino,
		NLink:          uint64(after.Nlink),
		ParentDevice:   uint64(parentAfter.Dev),
		ParentInode:    parentAfter.Ino,
		XAttrDigest:    xattrDigest,
		SELinuxContext: selinuxContext,
		CapturedAt:     time.Now().UTC(),
	}
	metadataDigest, err := digestFileMetadata(fileSnapshot)
	if err != nil {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeUnsupportedMetadata, Operation: "capture", Path: target, Err: err}
	}
	fileSnapshot.MetadataDigest = metadataDigest
	fingerprint, err := fingerprintFile(fileSnapshot)
	if err != nil {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeInvalidInput, Operation: "capture", Path: target, Err: err}
	}
	snapshot := model.ResourceSnapshot{Reference: resource, Fingerprint: fingerprint, File: &fileSnapshot}
	if err := snapshot.Validate(); err != nil {
		return model.ResourceSnapshot{}, nil, &Error{Code: CodeInvalidInput, Operation: "capture", Path: target, Err: err}
	}
	return snapshot, content, nil
}

func (h *Handler) buildDesiredMetadataPlatform(ctx context.Context, resource model.CanonicalResource, metadata DesiredMetadata) (model.ResourceSnapshot, error) {
	if h == nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "build desired state", Err: fmt.Errorf("handler is nil")}
	}
	if err := ctx.Err(); err != nil {
		return model.ResourceSnapshot{}, err
	}
	target, err := h.validateResource(resource, "build desired state")
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	if metadata.UID < 0 || metadata.GID < 0 || metadata.Mode&^uint32(0o7777) != 0 {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "build desired state", Path: target, Err: fmt.Errorf("ownership or mode is invalid")}
	}
	if h.selinuxActive && metadata.SELinuxContext == "" {
		return model.ResourceSnapshot{}, &Error{Code: CodeSELinuxUnknown, Operation: "build desired state", Path: target, Err: fmt.Errorf("SELinux is active but no restorable context was provided")}
	}
	current, _, err := h.captureCurrent(ctx, resource)
	if err != nil {
		return model.ResourceSnapshot{}, err
	}
	if current.File.NLink != 1 {
		return model.ResourceSnapshot{}, &Error{Code: CodeHardLinkNotSupported, Operation: "build desired state", Path: target, Err: fmt.Errorf("metadata remediation does not modify files with multiple hard links")}
	}
	if metadata.Mode&^current.File.Mode != 0 {
		return model.ResourceSnapshot{}, &Error{Code: CodeUnsupportedMetadata, Operation: "build desired state", Path: target, Err: fmt.Errorf("metadata remediation must not add permission or special-mode bits")}
	}
	if metadata.SELinuxContext != current.File.SELinuxContext {
		return model.ResourceSnapshot{}, &Error{Code: CodeUnsupportedMetadata, Operation: "build desired state", Path: target, Err: fmt.Errorf("metadata remediation must preserve the current SELinux context exactly")}
	}
	fileSnapshot := *current.File
	fileSnapshot.Mode = metadata.Mode
	fileSnapshot.UID = metadata.UID
	fileSnapshot.GID = metadata.GID
	fileSnapshot.SELinuxContext = metadata.SELinuxContext
	fileSnapshot.CapturedAt = time.Now().UTC()
	metadataDigest, err := digestFileMetadata(fileSnapshot)
	if err != nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "build desired state", Path: target, Err: err}
	}
	fileSnapshot.MetadataDigest = metadataDigest
	fingerprint, err := fingerprintFile(fileSnapshot)
	if err != nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "build desired state", Path: target, Err: err}
	}
	snapshot := model.ResourceSnapshot{Reference: resource, Fingerprint: fingerprint, File: &fileSnapshot}
	if err := snapshot.Validate(); err != nil {
		return model.ResourceSnapshot{}, &Error{Code: CodeInvalidInput, Operation: "build desired state", Path: target, Err: err}
	}
	return snapshot, nil
}

func readExactContext(ctx context.Context, reader io.Reader, size int64) ([]byte, error) {
	data := make([]byte, size)
	for offset := 0; offset < len(data); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count, err := reader.Read(data[offset:])
		offset += count
		if err != nil {
			return nil, err
		}
		if count == 0 {
			return nil, io.ErrUnexpectedEOF
		}
	}
	return data, nil
}

func sameStableTarget(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Nlink == right.Nlink && left.Uid == right.Uid && left.Gid == right.Gid && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func (h *Handler) readSupportedXAttrs(fd int, target, operation string) (map[string][]byte, error) {
	names, err := listXAttrNames(fd)
	if errors.Is(err, syscall.ENOTSUP) {
		if h.selinuxActive {
			return nil, &Error{Code: CodeSELinuxUnknown, Operation: operation, Path: target, Err: fmt.Errorf("filesystem does not expose SELinux metadata: %w", err)}
		}
		return map[string][]byte{}, nil
	}
	if err != nil {
		code := CodeUnsupportedMetadata
		if h.selinuxActive {
			code = CodeSELinuxUnknown
		}
		return nil, &Error{Code: code, Operation: operation, Path: target, Err: err}
	}
	values := make(map[string][]byte, len(names))
	for _, name := range names {
		if name != "security.selinux" {
			return nil, &Error{Code: CodeUnsupportedMetadata, Operation: operation, Path: target, Err: fmt.Errorf("extended attribute %q has no verified restore implementation", name)}
		}
		value, err := getXAttr(fd, name)
		if err != nil {
			return nil, &Error{Code: CodeUnsupportedMetadata, Operation: operation, Path: target, Err: err}
		}
		values[name] = value
	}
	if h.selinuxActive {
		contextValue, exists := values["security.selinux"]
		if !exists || len(contextValue) == 0 {
			return nil, &Error{Code: CodeSELinuxUnknown, Operation: operation, Path: target, Err: fmt.Errorf("SELinux is active but the target context cannot be captured")}
		}
	}
	return values, nil
}

func listXAttrNames(fd int) ([]string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := flistxattr(fd, nil)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		if size < 0 || size > maxXAttrListSize {
			return nil, fmt.Errorf("extended attribute list exceeds safe limit")
		}
		buffer := make([]byte, size)
		read, err := flistxattr(fd, buffer)
		if errors.Is(err, syscall.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if read < 0 || read > len(buffer) {
			return nil, fmt.Errorf("extended attribute list returned an invalid size")
		}
		buffer = buffer[:read]
		names := make([]string, 0)
		for len(buffer) > 0 {
			terminator := bytes.IndexByte(buffer, 0)
			if terminator <= 0 {
				return nil, fmt.Errorf("malformed extended attribute list")
			}
			names = append(names, string(buffer[:terminator]))
			buffer = buffer[terminator+1:]
		}
		sort.Strings(names)
		return names, nil
	}
	return nil, fmt.Errorf("extended attribute list changed repeatedly")
}

func getXAttr(fd int, name string) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		if size < 0 || size > maxXAttrListSize {
			return nil, fmt.Errorf("extended attribute exceeds safe limit")
		}
		if size == 0 {
			return []byte{}, nil
		}
		buffer := make([]byte, size)
		read, err := fgetxattr(fd, name, buffer)
		if errors.Is(err, syscall.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if read < 0 || read > len(buffer) {
			return nil, fmt.Errorf("extended attribute returned an invalid size")
		}
		return append([]byte(nil), buffer[:read]...), nil
	}
	return nil, fmt.Errorf("extended attribute changed repeatedly")
}

func flistxattr(fd int, destination []byte) (int, error) {
	var destinationPointer unsafe.Pointer
	if len(destination) > 0 {
		destinationPointer = unsafe.Pointer(&destination[0])
	}
	result, _, callErr := syscall.Syscall(
		syscall.SYS_FLISTXATTR,
		uintptr(fd),
		uintptr(destinationPointer),
		uintptr(len(destination)),
	)
	if callErr != 0 {
		return int(result), callErr
	}
	return int(result), nil
}

func fgetxattr(fd int, name string, destination []byte) (int, error) {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	var destinationPointer unsafe.Pointer
	if len(destination) > 0 {
		destinationPointer = unsafe.Pointer(&destination[0])
	}
	result, _, callErr := syscall.Syscall6(
		syscall.SYS_FGETXATTR,
		uintptr(fd),
		uintptr(unsafe.Pointer(namePointer)),
		uintptr(destinationPointer),
		uintptr(len(destination)),
		0,
		0,
	)
	if callErr != 0 {
		return int(result), callErr
	}
	return int(result), nil
}

func fsetxattr(fd int, name string, value []byte, flags int) error {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	var valuePointer unsafe.Pointer
	if len(value) > 0 {
		valuePointer = unsafe.Pointer(&value[0])
	}
	_, _, callErr := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		uintptr(fd),
		uintptr(unsafe.Pointer(namePointer)),
		uintptr(valuePointer),
		uintptr(len(value)),
		uintptr(flags),
		0,
	)
	if callErr != 0 {
		return callErr
	}
	return nil
}

func digestXAttrs(values map[string][]byte) string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	var length [8]byte
	for _, name := range names {
		binary.BigEndian.PutUint64(length[:], uint64(len(name)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(name))
		binary.BigEndian.PutUint64(length[:], uint64(len(values[name])))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(values[name])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digestFileMetadata(snapshot model.FileSnapshot) (string, error) {
	return journal.Digest(struct {
		Mode           uint32 `json:"mode"`
		UID            int    `json:"uid"`
		GID            int    `json:"gid"`
		NLink          uint64 `json:"nlink"`
		XAttrDigest    string `json:"xattr_digest"`
		ACLDigest      string `json:"acl_digest"`
		SELinuxContext string `json:"selinux_context"`
	}{
		Mode:           snapshot.Mode,
		UID:            snapshot.UID,
		GID:            snapshot.GID,
		NLink:          snapshot.NLink,
		XAttrDigest:    snapshot.XAttrDigest,
		ACLDigest:      snapshot.ACLDigest,
		SELinuxContext: snapshot.SELinuxContext,
	})
}

func fingerprintFile(snapshot model.FileSnapshot) (string, error) {
	return journal.Digest(struct {
		Path           string `json:"path"`
		Exists         bool   `json:"exists"`
		FileType       string `json:"file_type"`
		Mode           uint32 `json:"mode"`
		UID            int    `json:"uid"`
		GID            int    `json:"gid"`
		Size           int64  `json:"size"`
		SHA256         string `json:"sha256"`
		NLink          uint64 `json:"nlink"`
		ParentDevice   uint64 `json:"parent_device"`
		ParentInode    uint64 `json:"parent_inode"`
		XAttrDigest    string `json:"xattr_digest"`
		ACLDigest      string `json:"acl_digest"`
		SELinuxContext string `json:"selinux_context"`
		MetadataDigest string `json:"metadata_digest"`
	}{
		Path:           snapshot.Path,
		Exists:         snapshot.Exists,
		FileType:       snapshot.FileType,
		Mode:           snapshot.Mode,
		UID:            snapshot.UID,
		GID:            snapshot.GID,
		Size:           snapshot.Size,
		SHA256:         snapshot.SHA256,
		NLink:          snapshot.NLink,
		ParentDevice:   snapshot.ParentDevice,
		ParentInode:    snapshot.ParentInode,
		XAttrDigest:    snapshot.XAttrDigest,
		ACLDigest:      snapshot.ACLDigest,
		SELinuxContext: snapshot.SELinuxContext,
		MetadataDigest: snapshot.MetadataDigest,
	})
}

func semanticSnapshotEqual(expected, observed model.ResourceSnapshot) bool {
	return expected.Reference.Key == observed.Reference.Key && expected.Fingerprint == observed.Fingerprint
}

func exactSnapshotEqual(expected, observed model.ResourceSnapshot) bool {
	if !semanticSnapshotEqual(expected, observed) || expected.File == nil || observed.File == nil {
		return false
	}
	return expected.File.Device == observed.File.Device && expected.File.Inode == observed.File.Inode && expected.File.ParentDevice == observed.File.ParentDevice && expected.File.ParentInode == observed.File.ParentInode
}

func recordedSnapshotEqual(expected, observed model.ResourceSnapshot) bool {
	left, leftErr := journal.CanonicalJSON(expected)
	right, rightErr := journal.CanonicalJSON(observed)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
