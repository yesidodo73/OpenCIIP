package support

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	ACLInspectionUnavailableReason = "POSIX ACL을 확인할 수 있는 수집 방법이 없음"

	posixACLAccessXAttr  = "system.posix_acl_access"
	posixACLDefaultXAttr = "system.posix_acl_default"
	posixACLXAttrVersion = uint32(2)
	posixACLUndefinedID  = uint32(0xffffffff)
	posixACLReadLimit    = int64(1 << 20)

	posixACLTagUserObject  = uint16(0x01)
	posixACLTagUser        = uint16(0x02)
	posixACLTagGroupObject = uint16(0x04)
	posixACLTagGroup       = uint16(0x08)
	posixACLTagMask        = uint16(0x10)
	posixACLTagOther       = uint16(0x20)
)

type ACLInspection struct {
	Content  string
	Evidence model.Evidence
	Metadata *system.FileMetadata
}

type ACLInspectionUnavailableError struct {
	Target string
}

func (err *ACLInspectionUnavailableError) Error() string {
	target := strings.TrimSpace(err.Target)
	if target == "" {
		return "POSIX ACL inspection is unavailable"
	}
	return fmt.Sprintf("POSIX ACL inspection is unavailable for %s", target)
}

// ACLToolUnavailableError is retained for callers that classify the earlier
// getfacl-only error. The condition now means that neither the native reader nor
// getfacl can provide trustworthy ACL evidence.
type ACLToolUnavailableError = ACLInspectionUnavailableError

func IsACLToolUnavailable(err error) bool {
	var unavailable *ACLInspectionUnavailableError
	return errors.As(err, &unavailable)
}

// InspectPOSIXACL prefers a rooted native xattr snapshot. getfacl remains a
// compatibility fallback only when the caller does not require the ACL result
// to be bound to expectedMetadata.
func InspectPOSIXACL(
	ctx context.Context,
	files system.Reader,
	commands executor.CommandRunner,
	target string,
	followFinalSymlink bool,
	includeDefault bool,
	expectedMetadata *system.FileMetadata,
) (ACLInspection, error) {
	if err := ctx.Err(); err != nil {
		return ACLInspection{}, err
	}
	nativeAttempted := false
	nativeUnsupported := false
	if reader, ok := files.(system.XAttrReader); ok {
		nativeAttempted = true
		var noFollowMetadata *system.FileMetadata
		if !followFinalSymlink {
			metadata, err := files.Lstat(target)
			if err != nil {
				return ACLInspection{}, err
			}
			if metadata.FileType == "symlink" {
				return unavailableACLInspection(target, true, false), &ACLInspectionUnavailableError{Target: target}
			}
			noFollowMetadata = &metadata
		}
		names := []string{posixACLAccessXAttr}
		if includeDefault {
			names = append(names, posixACLDefaultXAttr)
		}
		values, metadata, err := reader.ReadXAttrs(
			ctx,
			target,
			names,
			posixACLReadLimit,
			followFinalSymlink,
		)
		if err == nil {
			if noFollowMetadata != nil && !sameACLTarget(*noFollowMetadata, metadata) {
				return changedACLInspection(target, metadata), fmt.Errorf("%w: %s", system.ErrFileChanged, target)
			}
			if expectedMetadata != nil && !sameACLTarget(*expectedMetadata, metadata) {
				return changedACLInspection(target, metadata), fmt.Errorf("%w: %s", system.ErrFileChanged, target)
			}
			return inspectNativePOSIXACL(target, metadata, values, includeDefault)
		}
		if !errors.Is(err, system.ErrXAttrUnsupported) {
			return ACLInspection{}, fmt.Errorf("inspect POSIX ACL xattrs for %s: %w", target, err)
		}
		nativeUnsupported = true
	}

	getfaclAvailable := commands != nil && commands.Available("getfacl")
	if expectedMetadata != nil {
		return unavailableBoundACLInspection(
				target,
				nativeAttempted,
				nativeUnsupported,
				getfaclAvailable,
			),
			&ACLInspectionUnavailableError{Target: target}
	}

	if getfaclAvailable {
		linkMode := "-P"
		if followFinalSymlink {
			linkMode = "-L"
		}
		spec := executor.Spec{
			Name:      "getfacl",
			Arguments: []string{"-c", "-p", "-n", linkMode, "--absolute-names", "--", target},
			Timeout:   15 * time.Second,
			MaxOutput: 1 << 20,
		}
		result, err := commands.Run(ctx, spec)
		if err != nil {
			return ACLInspection{}, err
		}
		inspection := ACLInspection{
			Content:  string(result.Stdout),
			Evidence: CommandEvidence(spec, result),
		}
		if result.ExitCode != 0 || result.Truncated {
			return inspection, fmt.Errorf("getfacl %s exit=%d truncated=%t", target, result.ExitCode, result.Truncated)
		}
		return inspection, nil
	}

	return unavailableACLInspection(target, nativeAttempted, nativeUnsupported), &ACLInspectionUnavailableError{Target: target}
}

func changedACLInspection(target string, metadata system.FileMetadata) ACLInspection {
	snapshot := metadata
	return ACLInspection{
		Evidence: FactEvidence("posix_acl_xattr", map[string]any{
			"path":              target,
			"backend":           "linux_xattr",
			"snapshot_mismatch": true,
			"device":            metadata.Device,
			"inode":             metadata.Inode,
		}),
		Metadata: &snapshot,
	}
}

func sameACLTarget(before, after system.FileMetadata) bool {
	return before.Path == after.Path &&
		before.FileType == after.FileType &&
		before.Mode == after.Mode &&
		before.Size == after.Size &&
		before.UID == after.UID &&
		before.GID == after.GID &&
		before.Device == after.Device &&
		before.Inode == after.Inode &&
		before.ModTime.Equal(after.ModTime) &&
		before.ChangeTime.Equal(after.ChangeTime) &&
		before.LinkTarget == after.LinkTarget
}

func unavailableACLInspection(target string, nativeAttempted, nativeUnsupported bool) ACLInspection {
	return ACLInspection{Evidence: FactEvidence("posix_acl", map[string]any{
		"target":             target,
		"native_attempted":   nativeAttempted,
		"native_unsupported": nativeUnsupported,
		"getfacl_available":  false,
	})}
}

func unavailableBoundACLInspection(
	target string,
	nativeAttempted bool,
	nativeUnsupported bool,
	getfaclAvailable bool,
) ACLInspection {
	return ACLInspection{Evidence: FactEvidence("posix_acl", map[string]any{
		"target":                   target,
		"native_attempted":         nativeAttempted,
		"native_unsupported":       nativeUnsupported,
		"getfacl_available":        getfaclAvailable,
		"getfacl_fallback_blocked": true,
		"expected_metadata_bound":  true,
	})}
}

func inspectNativePOSIXACL(
	target string,
	metadata system.FileMetadata,
	values map[string][]byte,
	includeDefault bool,
) (ACLInspection, error) {
	access, accessPresent := values[posixACLAccessXAttr]
	accessLines, err := decodePOSIXACLXAttr(access, false, accessPresent)
	if err != nil {
		return ACLInspection{}, fmt.Errorf("parse %s for %s: %w", posixACLAccessXAttr, target, err)
	}
	defaultLines := []string(nil)
	defaultPresent := false
	if includeDefault {
		defaultACL, exists := values[posixACLDefaultXAttr]
		defaultPresent = exists
		defaultLines, err = decodePOSIXACLXAttr(defaultACL, true, exists)
		if err != nil {
			return ACLInspection{}, fmt.Errorf("parse %s for %s: %w", posixACLDefaultXAttr, target, err)
		}
	}
	lines := append(append([]string(nil), accessLines...), defaultLines...)
	facts := map[string]any{
		"path":               target,
		"backend":            "linux_xattr",
		"device":             metadata.Device,
		"inode":              metadata.Inode,
		"access_acl_present": accessPresent,
		"access_entries":     append([]string(nil), accessLines...),
	}
	if includeDefault {
		facts["default_acl_present"] = defaultPresent
		facts["default_entries"] = append([]string(nil), defaultLines...)
	}
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	snapshot := metadata
	return ACLInspection{
		Content:  content,
		Evidence: FactEvidence("posix_acl_xattr", facts),
		Metadata: &snapshot,
	}, nil
}

func decodePOSIXACLXAttr(value []byte, defaultEntries, present bool) ([]string, error) {
	if !present {
		return nil, nil
	}
	if len(value) < 4 || (len(value)-4)%8 != 0 {
		return nil, fmt.Errorf("invalid payload length %d", len(value))
	}
	if version := binary.LittleEndian.Uint32(value[:4]); version != posixACLXAttrVersion {
		return nil, fmt.Errorf("unsupported xattr version %d", version)
	}

	lines := make([]string, 0, (len(value)-4)/8)
	baseTags := make(map[uint16]bool, 4)
	namedEntries := make(map[string]bool)
	hasNamed := false
	hasMask := false
	for offset := 4; offset < len(value); offset += 8 {
		tag := binary.LittleEndian.Uint16(value[offset : offset+2])
		permissions := binary.LittleEndian.Uint16(value[offset+2 : offset+4])
		identifier := binary.LittleEndian.Uint32(value[offset+4 : offset+8])
		if permissions&^uint16(0o7) != 0 {
			return nil, fmt.Errorf("ACL tag %#x has invalid permissions %#x", tag, permissions)
		}

		label := ""
		qualifier := ""
		switch tag {
		case posixACLTagUserObject:
			label = "user"
			if identifier != posixACLUndefinedID {
				return nil, fmt.Errorf("owner entry has an unexpected identifier")
			}
		case posixACLTagUser:
			label = "user"
			hasNamed = true
			if identifier == posixACLUndefinedID {
				return nil, fmt.Errorf("named user entry has no identifier")
			}
			qualifier = strconv.FormatUint(uint64(identifier), 10)
		case posixACLTagGroupObject:
			label = "group"
			if identifier != posixACLUndefinedID {
				return nil, fmt.Errorf("owning group entry has an unexpected identifier")
			}
		case posixACLTagGroup:
			label = "group"
			hasNamed = true
			if identifier == posixACLUndefinedID {
				return nil, fmt.Errorf("named group entry has no identifier")
			}
			qualifier = strconv.FormatUint(uint64(identifier), 10)
		case posixACLTagMask:
			label = "mask"
			hasMask = true
			if identifier != posixACLUndefinedID {
				return nil, fmt.Errorf("mask entry has an unexpected identifier")
			}
		case posixACLTagOther:
			label = "other"
			if identifier != posixACLUndefinedID {
				return nil, fmt.Errorf("other entry has an unexpected identifier")
			}
		default:
			return nil, fmt.Errorf("unsupported ACL tag %#x", tag)
		}

		if tag == posixACLTagUser || tag == posixACLTagGroup {
			key := fmt.Sprintf("%d:%s", tag, qualifier)
			if namedEntries[key] {
				return nil, fmt.Errorf("duplicate %s:%s entry", label, qualifier)
			}
			namedEntries[key] = true
		} else {
			if baseTags[tag] {
				return nil, fmt.Errorf("duplicate %s entry", label)
			}
			baseTags[tag] = true
		}

		prefix := ""
		if defaultEntries {
			prefix = "default:"
		}
		lines = append(lines, prefix+label+":"+qualifier+":"+formatACLPermissions(permissions))
	}

	for _, required := range []uint16{posixACLTagUserObject, posixACLTagGroupObject, posixACLTagOther} {
		if !baseTags[required] {
			return nil, fmt.Errorf("required ACL entry %#x is missing", required)
		}
	}
	if hasNamed && !hasMask {
		return nil, fmt.Errorf("extended ACL has no mask entry")
	}
	return lines, nil
}

func formatACLPermissions(value uint16) string {
	permissions := [3]byte{'-', '-', '-'}
	if value&0o4 != 0 {
		permissions[0] = 'r'
	}
	if value&0o2 != 0 {
		permissions[1] = 'w'
	}
	if value&0o1 != 0 {
		permissions[2] = 'x'
	}
	return string(permissions[:])
}

// RequireACLTool remains available for older call sites. New ACL checks should
// use InspectPOSIXACL so Linux xattr evidence is considered before this fallback.
func RequireACLTool(commands executor.CommandRunner, target string) (model.Evidence, error) {
	if commands == nil {
		return model.Evidence{}, fmt.Errorf("command runner is required for ACL inspection")
	}
	if commands.Available("getfacl") {
		return model.Evidence{}, nil
	}
	return FactEvidence("getfacl", map[string]any{
		"available": false,
		"purpose":   "posix_acl_inspection",
		"target":    target,
	}), &ACLInspectionUnavailableError{Target: target}
}
