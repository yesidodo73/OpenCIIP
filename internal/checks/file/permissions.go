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
		EvaluatorHostsLPDPermissions: evaluateHostsLPDPermissions,
	}
	for id, implementation := range filesystemImplementations() {
		implementations[id] = implementation
	}
	return implementations
}

func evaluateHostsLPDPermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	exists, err := environment.Files.Exists("/etc/hosts.lpd")
	if err != nil {
		return permissionError("hosts_lpd_stat_failed", "/etc/hosts.lpd", err)
	}
	if exists {
		return staticPermissionEvaluator(permissionPolicy{path: "/etc/hosts.lpd", allowedMode: 0o600})(ctx, rule, environment)
	}
	evidence := []model.Evidence{support.FactEvidence("/etc/hosts.lpd", map[string]any{"exists": false})}
	activeSignals := make([]string, 0)
	if environment.Platform.InitSystem == "systemd" {
		units, unitEvidence, inspectErr := support.InspectUnits(ctx, environment, []string{"lpd.service", "lpd.socket", "cups-lpd.socket", "cups-lpd@.service"})
		if inspectErr != nil {
			return permissionError("lpd_unit_inspection_failed", "/etc/hosts.lpd", inspectErr)
		}
		evidence = append(evidence, unitEvidence...)
		for _, unit := range units {
			if support.UnitActive(unit) || support.UnitEnabled(unit) {
				activeSignals = append(activeSignals, unit.Name)
			}
		}
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"lpd", "in.lpd", "cups-lpd"})
	if err != nil {
		return permissionError("lpd_process_inspection_failed", "/etc/hosts.lpd", err)
	}
	evidence = append(evidence, processEvidence)
	activeSignals = append(activeSignals, processes...)
	listeners, listenerEvidence, err := support.InspectListeningPorts(ctx, environment, []int{515})
	if err != nil {
		return permissionError("lpd_listener_inspection_failed", "/etc/hosts.lpd", err)
	}
	evidence = append(evidence, listenerEvidence)
	if len(listeners[515]) > 0 {
		activeSignals = append(activeSignals, "port 515 listening")
	}
	return hostsLPDMissingConclusion(environment.Platform.InitSystem, activeSignals, evidence)
}

func hostsLPDMissingConclusion(initSystem string, activeSignals []string, evidence []model.Evidence) evaluator.Outcome {
	activeSignals = uniqueSortedPaths(activeSignals)
	if len(activeSignals) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "활성 LPD 경로가 있으나 실제 접근 통제 파일을 확정할 수 없습니다.", Expected: "LPD가 비활성이거나 실제 hosts.lpd가 root 소유 0600 허용 비트 이내여야 합니다.", Observed: strings.Join(activeSignals, "; "), Evidence: evidence}
	}
	if initSystem != "systemd" {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "hosts.lpd가 없고 LPD 서비스의 부팅 활성 여부를 확인할 수 없습니다.", Expected: "LPD가 비활성이거나 실제 접근 통제 파일의 권한이 안전해야 합니다.", Observed: initSystem, Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "/etc/hosts.lpd가 없고 활성 LPD 서비스 경로도 확인되지 않았습니다.", Expected: "파일이 없거나 root 소유이고 권한이 0600 허용 비트 이내여야 합니다.", Observed: "파일 및 활성 LPD 경로 없음", Evidence: evidence}
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
