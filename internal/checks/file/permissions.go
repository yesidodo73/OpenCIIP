package filecheck

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorPasswdPermissions   = "unix.file.passwd_permissions"
	EvaluatorShadowPermissions   = "unix.file.shadow_permissions"
	EvaluatorHostsPermissions    = "unix.file.hosts_permissions"
	EvaluatorServicesPermissions = "unix.file.services_permissions"
	EvaluatorHostsLPDPermissions = "unix.file.hosts_lpd_permissions"
)

type permissionPolicy struct {
	path              string
	allowedMode       os.FileMode
	allowedOwnerNames []string
	missingPass       bool
}

func Implementations() map[string]evaluator.Func {
	implementations := map[string]evaluator.Func{
		EvaluatorStartupPermissions:  evaluateStartupPermissions,
		EvaluatorInetdPermissions:    evaluateInetdPermissions,
		EvaluatorSyslogPermissions:   evaluateSyslogPermissions,
		EvaluatorPasswdPermissions:   staticPermissionEvaluator(permissionPolicy{path: "/etc/passwd", allowedMode: 0o644}),
		EvaluatorShadowPermissions:   staticPermissionEvaluator(permissionPolicy{path: "/etc/shadow", allowedMode: 0o400}),
		EvaluatorHostsPermissions:    staticPermissionEvaluator(permissionPolicy{path: "/etc/hosts", allowedMode: 0o644}),
		EvaluatorServicesPermissions: staticPermissionEvaluator(permissionPolicy{path: "/etc/services", allowedMode: 0o644, allowedOwnerNames: []string{"bin", "sys"}}),
		EvaluatorHostsLPDPermissions: staticPermissionEvaluator(permissionPolicy{path: "/etc/hosts.lpd", allowedMode: 0o600, missingPass: true}),
	}
	for id, implementation := range filesystemImplementations() {
		implementations[id] = implementation
	}
	return implementations
}

func staticPermissionEvaluator(policy permissionPolicy) evaluator.Func {
	return func(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
		allowedUIDs := map[int]struct{}{0: {}}
		var ownerEvidence *model.Evidence
		if len(policy.allowedOwnerNames) > 0 {
			accounts, evidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
			if err != nil {
				return permissionError("allowed_owner_lookup_failed", policy.path, err)
			}
			wanted := make(map[string]struct{}, len(policy.allowedOwnerNames))
			for _, name := range policy.allowedOwnerNames {
				wanted[name] = struct{}{}
			}
			for _, account := range accounts {
				if _, allowed := wanted[account.Name]; allowed {
					allowedUIDs[int(account.UID)] = struct{}{}
				}
			}
			ownerEvidence = &evidence
		}
		assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, policy.path, support.PermissionPolicy{
			AllowedUIDs: allowedUIDs, AllowedMode: policy.allowedMode,
			AllowedTypes: map[string]struct{}{"regular": {}},
		})
		if err != nil {
			return permissionError("file_permission_inspection_failed", policy.path, err)
		}
		if ownerEvidence != nil {
			assessment.Evidence = append([]model.Evidence{*ownerEvidence}, assessment.Evidence...)
		}
		ownerLabel := "root"
		if len(policy.allowedOwnerNames) > 0 {
			ownerLabel += "/" + strings.Join(policy.allowedOwnerNames, "/")
		}
		if !assessment.Exists {
			if policy.missingPass {
				return evaluator.Outcome{
					Status:   model.StatusPass,
					Summary:  fmt.Sprintf("%s 파일이 없어 가이드의 양호 기준을 충족합니다.", policy.path),
					Expected: fmt.Sprintf("파일이 없거나 %s 소유이고 권한이 %04o 허용 비트 이내여야 합니다.", ownerLabel, policy.allowedMode.Perm()),
					Observed: "파일 없음",
					Evidence: []model.Evidence{support.FactEvidence(policy.path, map[string]any{"exists": false})},
				}
			}
			return permissionError("file_not_found", policy.path, os.ErrNotExist)
		}
		expected := fmt.Sprintf("%s 소유 일반 파일이며 권한과 ACL이 %04o 허용 비트 이내여야 합니다.", ownerLabel, policy.allowedMode.Perm())
		if len(assessment.Violations) > 0 {
			return evaluator.Outcome{
				Status:   model.StatusFail,
				Summary:  fmt.Sprintf("%s 파일의 소유자, 유형, 권한 또는 ACL이 기준을 충족하지 않습니다.", policy.path),
				Expected: expected,
				Observed: strings.Join(assessment.Violations, "; "),
				Evidence: assessment.Evidence,
			}
		}
		if len(assessment.Unknowns) > 0 {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       fmt.Sprintf("%s 파일의 소유자, 유형 또는 ACL을 확정할 수 없습니다.", policy.path),
				Expected:      expected,
				Observed:      strings.Join(assessment.Unknowns, "; "),
				Evidence:      assessment.Evidence,
			}
		}
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  fmt.Sprintf("%s 파일의 소유자와 권한이 기준을 충족합니다.", policy.path),
			Expected: expected,
			Observed: fmt.Sprintf("uid=%d mode=%04o", assessment.Metadata.UID, assessment.Metadata.Mode.Perm()),
			Evidence: assessment.Evidence,
		}
	}
}

func checkACL(content string, allowedMode os.FileMode) ([]string, error) {
	type entry struct {
		tag       string
		qualifier string
		perms     os.FileMode
		effective *os.FileMode
	}
	entries := make([]entry, 0, 8)
	mask := os.FileMode(0o7)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		mainPart, comment, _ := strings.Cut(line, "#")
		fields := strings.Split(strings.TrimSpace(mainPart), ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d has an invalid ACL entry", lineNumber+1)
		}
		permissions, err := parseACLPermissions(strings.TrimSpace(fields[2]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		item := entry{tag: strings.TrimSpace(fields[0]), qualifier: strings.TrimSpace(fields[1]), perms: permissions}
		if effectiveText := strings.TrimSpace(comment); strings.HasPrefix(effectiveText, "effective:") {
			effective, parseErr := parseACLPermissions(strings.TrimSpace(strings.TrimPrefix(effectiveText, "effective:")))
			if parseErr != nil {
				return nil, fmt.Errorf("line %d effective permissions: %w", lineNumber+1, parseErr)
			}
			item.effective = &effective
		}
		if item.tag == "mask" && item.qualifier == "" {
			mask = item.perms
		}
		entries = append(entries, item)
	}
	violations := make([]string, 0)
	ownerAllowed := os.FileMode((allowedMode.Perm() >> 6) & 0o7)
	groupAllowed := os.FileMode((allowedMode.Perm() >> 3) & 0o7)
	otherAllowed := os.FileMode(allowedMode.Perm() & 0o7)
	for _, item := range entries {
		actual := item.perms
		if item.effective != nil {
			actual = *item.effective
		} else if item.qualifier != "" || item.tag == "group" {
			actual &= mask
		}
		allowed := groupAllowed
		switch {
		case item.tag == "user" && item.qualifier == "":
			allowed = ownerAllowed
		case item.tag == "other" && item.qualifier == "":
			allowed = otherAllowed
		case item.tag == "mask" && item.qualifier == "":
			allowed = groupAllowed
		case item.tag == "user" || item.tag == "group":
			allowed = groupAllowed
		default:
			return nil, fmt.Errorf("unsupported ACL tag %q", item.tag)
		}
		if extra := actual &^ allowed; extra != 0 {
			violations = append(violations, fmt.Sprintf("ACL %s:%s에 허용되지 않은 권한 %03o", item.tag, item.qualifier, extra))
		}
	}
	return violations, nil
}

func parseACLPermissions(value string) (os.FileMode, error) {
	if len(value) != 3 {
		return 0, fmt.Errorf("invalid ACL permission %q", value)
	}
	var permissions os.FileMode
	for index, expected := range []byte{'r', 'w', 'x'} {
		if value[index] == '-' {
			continue
		}
		if value[index] != expected {
			return 0, fmt.Errorf("invalid ACL permission %q", value)
		}
		permissions |= 1 << (2 - index)
	}
	return permissions, nil
}

func permissionError(code, path string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      fmt.Sprintf("%s 파일의 소유자 또는 권한을 확인하지 못했습니다.", path),
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
