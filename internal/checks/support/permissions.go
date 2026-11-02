package support

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type PermissionPolicy struct {
	AllowedUIDs        map[int]struct{}
	AllowedMode        os.FileMode
	AllowedTypes       map[string]struct{}
	AllowedSpecialBits os.FileMode
	FollowFinalSymlink bool
	SkipACL            bool
	CheckDefaultACL    bool
}

type PermissionAssessment struct {
	Path           string
	Exists         bool
	Metadata       system.FileMetadata
	NamedAccessACL bool
	ExtraModeBits  os.FileMode
	Violations     []string
	Unknowns       []string
	Evidence       []model.Evidence
}

func InspectPermissions(
	ctx context.Context,
	files system.Reader,
	commands executor.CommandRunner,
	path string,
	policy PermissionPolicy,
) (PermissionAssessment, error) {
	assessment := PermissionAssessment{Path: path}
	metadata, err := files.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return assessment, nil
		}
		return assessment, err
	}
	assessment.Exists = true
	assessment.Metadata = metadata
	assessment.Evidence = append(assessment.Evidence, FileMetadataEvidence(metadata))
	if metadata.FileType == "symlink" {
		if !policy.FollowFinalSymlink {
			assessment.Unknowns = append(assessment.Unknowns, "최종 경로가 심볼릭 링크임")
			return assessment, nil
		}
		resolved, statErr := files.Stat(path)
		if statErr != nil {
			return assessment, statErr
		}
		metadata = resolved
		assessment.Metadata = metadata
		assessment.Evidence = append(assessment.Evidence, FileMetadataEvidence(metadata))
	}
	if len(policy.AllowedTypes) > 0 {
		if _, allowed := policy.AllowedTypes[metadata.FileType]; !allowed {
			assessment.Violations = append(assessment.Violations, "허용되지 않은 파일 유형 "+metadata.FileType)
		}
	}
	if metadata.UID < 0 {
		assessment.Unknowns = append(assessment.Unknowns, "소유자 UID를 확인할 수 없음")
	} else if len(policy.AllowedUIDs) > 0 {
		if _, allowed := policy.AllowedUIDs[metadata.UID]; !allowed {
			assessment.Violations = append(assessment.Violations, fmt.Sprintf("허용되지 않은 소유자 UID %d", metadata.UID))
		}
	}
	if extra := metadata.Mode.Perm() &^ policy.AllowedMode.Perm(); extra != 0 {
		assessment.ExtraModeBits = extra
		assessment.Violations = append(assessment.Violations, fmt.Sprintf("허용되지 않은 권한 비트 %04o", extra))
	}
	if metadata.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)&^policy.AllowedSpecialBits != 0 {
		assessment.Violations = append(assessment.Violations, "특수 권한 비트가 설정됨")
	}
	if policy.SkipACL {
		sort.Strings(assessment.Violations)
		sort.Strings(assessment.Unknowns)
		return assessment, nil
	}
	aclInspection, aclErr := InspectPOSIXACL(
		ctx,
		files,
		commands,
		path,
		policy.FollowFinalSymlink,
		policy.CheckDefaultACL,
		&metadata,
	)
	if aclInspection.Evidence.Source != "" {
		assessment.Evidence = append(assessment.Evidence, aclInspection.Evidence)
	}
	if aclErr != nil {
		if IsACLToolUnavailable(aclErr) {
			assessment.Unknowns = append(assessment.Unknowns, ACLInspectionUnavailableReason)
			sort.Strings(assessment.Violations)
			sort.Strings(assessment.Unknowns)
			return assessment, nil
		}
		return assessment, aclErr
	}
	violations, namedAccessACL, err := permissionACLViolations(aclInspection.Content, metadata.UID, policy.AllowedMode, policy.CheckDefaultACL)
	if err != nil {
		return assessment, err
	}
	assessment.NamedAccessACL = namedAccessACL
	assessment.Violations = append(assessment.Violations, violations...)
	sort.Strings(assessment.Violations)
	sort.Strings(assessment.Unknowns)
	return assessment, nil
}

func permissionACLViolations(content string, ownerUID int, allowedMode os.FileMode, checkDefaults bool) ([]string, bool, error) {
	type aclEntry struct {
		defaultEntry bool
		tag          string
		qualifier    string
		permissions  os.FileMode
		effective    *os.FileMode
	}
	entries := make([]aclEntry, 0, 12)
	masks := map[bool]os.FileMode{false: 0o7, true: 0o7}
	namedAccessACL := false
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		defaultEntry := false
		if strings.HasPrefix(line, "default:") {
			defaultEntry = true
			line = strings.TrimPrefix(line, "default:")
			if !checkDefaults {
				continue
			}
		}
		mainPart, comment, _ := strings.Cut(line, "#")
		fields := strings.Split(strings.TrimSpace(mainPart), ":")
		if len(fields) != 3 {
			return nil, false, fmt.Errorf("ACL line %d is invalid", lineNumber+1)
		}
		permissions, err := parsePermissionBits(fields[2])
		if err != nil {
			return nil, false, fmt.Errorf("ACL line %d: %w", lineNumber+1, err)
		}
		item := aclEntry{defaultEntry: defaultEntry, tag: strings.TrimSpace(fields[0]), qualifier: strings.TrimSpace(fields[1]), permissions: permissions}
		if !item.defaultEntry && item.qualifier != "" && (item.tag == "user" || item.tag == "group") {
			namedAccessACL = true
		}
		if effectiveText := strings.TrimSpace(comment); strings.HasPrefix(effectiveText, "effective:") {
			effective, parseErr := parsePermissionBits(strings.TrimSpace(strings.TrimPrefix(effectiveText, "effective:")))
			if parseErr != nil {
				return nil, false, fmt.Errorf("ACL line %d effective permissions: %w", lineNumber+1, parseErr)
			}
			item.effective = &effective
		}
		if item.tag == "mask" && item.qualifier == "" {
			masks[item.defaultEntry] = item.permissions
		}
		entries = append(entries, item)
	}
	ownerAllowed := os.FileMode((allowedMode.Perm() >> 6) & 0o7)
	groupAllowed := os.FileMode((allowedMode.Perm() >> 3) & 0o7)
	otherAllowed := os.FileMode(allowedMode.Perm() & 0o7)
	violations := make([]string, 0)
	for _, item := range entries {
		actual := item.permissions
		if item.effective != nil {
			actual = *item.effective
		} else if (item.tag == "user" && item.qualifier != "") || item.tag == "group" {
			actual &= masks[item.defaultEntry]
		}
		allowed := groupAllowed
		switch {
		case item.tag == "user" && item.qualifier == "":
			allowed = ownerAllowed
		case item.tag == "user" && item.qualifier != "":
			uid, err := strconv.Atoi(item.qualifier)
			if err != nil || uid < 0 {
				return nil, false, fmt.Errorf("ACL user qualifier %q is not numeric", item.qualifier)
			}
			if uid == ownerUID {
				allowed = ownerAllowed
			}
		case item.tag == "group":
			allowed = groupAllowed
		case item.tag == "mask" && item.qualifier == "":
			if !item.defaultEntry {
				// The access ACL mask is represented by the inode's group mode bits,
				// which InspectPermissions validates before inspecting the ACL.
				continue
			}
			allowed = groupAllowed
		case item.tag == "other" && item.qualifier == "":
			allowed = otherAllowed
		default:
			return nil, false, fmt.Errorf("unsupported ACL tag %q", item.tag)
		}
		if extra := actual &^ allowed; extra != 0 {
			prefix := "ACL"
			if item.defaultEntry {
				prefix = "default ACL"
			}
			violations = append(violations, fmt.Sprintf("%s %s:%s에 허용되지 않은 권한 %03o", prefix, item.tag, item.qualifier, extra))
		}
	}
	return violations, namedAccessACL, nil
}

func parsePermissionBits(value string) (os.FileMode, error) {
	value = strings.TrimSpace(value)
	if len(value) != 3 {
		return 0, fmt.Errorf("invalid permissions %q", value)
	}
	var permissions os.FileMode
	for index, expected := range []byte{'r', 'w', 'x'} {
		if value[index] == '-' {
			continue
		}
		if value[index] != expected {
			return 0, fmt.Errorf("invalid permissions %q", value)
		}
		permissions |= 1 << (2 - index)
	}
	return permissions, nil
}
