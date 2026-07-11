package filecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorStartupPermissions = "unix.file.startup_permissions"
	EvaluatorInetdPermissions   = "unix.file.inetd_permissions"
	EvaluatorSyslogPermissions  = "unix.file.syslog_permissions"
)

func evaluateStartupPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "시작 파일 권한을 지원하는 방식으로 확인할 수 없습니다.", Expected: "systemd 기반 Linux 환경이 필요합니다.", Observed: "init=" + environment.Platform.InitSystem}
	}
	specs := []executor.Spec{
		{Name: "systemctl", Arguments: []string{"list-unit-files", "--no-pager", "--no-legend", "--plain", "--state=enabled,enabled-runtime,linked,linked-runtime"}, Timeout: 30 * time.Second, MaxOutput: 4 << 20},
		{Name: "systemctl", Arguments: []string{"list-units", "--all", "--no-pager", "--no-legend", "--plain", "--state=active,activating,reloading", "--type=service", "--type=socket", "--type=timer", "--type=path", "--type=mount", "--type=automount", "--type=target", "--type=swap", "--type=slice"}, Timeout: 30 * time.Second, MaxOutput: 4 << 20},
	}
	units := make(map[string]struct{})
	evidence := make([]model.Evidence, 0)
	unsupportedUnitCount := 0
	for _, spec := range specs {
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return fileError("systemd_unit_listing_failed", "systemd 시작 대상을 열거하지 못했습니다.", err)
		}
		evidence = append(evidence, support.CommandEvidence(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return fileError("systemd_unit_listing_failed", "systemd 시작 대상을 열거하지 못했습니다.", fmt.Errorf("exit=%d truncated=%t", result.ExitCode, result.Truncated))
		}
		for _, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
			fields := strings.Fields(raw)
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			if name == "●" && len(fields) > 1 {
				name = fields[1]
			} else {
				name = strings.TrimPrefix(name, "●")
			}
			if !validSystemdUnitToken(name) {
				unsupportedUnitCount++
				continue
			}
			units[name] = struct{}{}
		}
	}
	unitNames := make([]string, 0, len(units))
	for name := range units {
		unitNames = append(unitNames, name)
	}
	sort.Strings(unitNames)
	unitNames, dependencyEvidence, dependencyUnknowns, err := expandStartupUnitDependencies(ctx, environment, unitNames)
	if err != nil {
		return fileError("systemd_dependency_inspection_failed", "systemd 시작 의존 관계를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, dependencyEvidence...)
	seenPaths := make(map[string]struct{})
	violations := make([]string, 0)
	unknowns := append([]string(nil), dependencyUnknowns...)
	if unsupportedUnitCount > 0 {
		unknowns = append(unknowns, fmt.Sprintf("이스케이프되거나 비표준인 unit 이름 %d개", unsupportedUnitCount))
	}
	for _, unitName := range unitNames {
		states, stateEvidence, err := support.InspectUnits(ctx, environment, []string{unitName})
		if err != nil {
			return fileError("systemd_unit_inspection_failed", "systemd unit 경로를 확인하지 못했습니다.", err)
		}
		evidence = append(evidence, stateEvidence...)
		if len(states) != 1 {
			return fileError("systemd_unit_inspection_failed", "systemd unit 경로를 확인하지 못했습니다.", fmt.Errorf("unexpected state count for %s", unitName))
		}
		state := states[0]
		unitPaths, reason := startupUnitPaths(state)
		if reason != "" {
			unknowns = append(unknowns, unitName+": "+reason)
		}
		if strings.HasSuffix(unitName, ".service") {
			inspectionName := state.InspectionName
			if inspectionName == "" {
				inspectionName = unitName
			}
			executablePaths, complete, executableEvidence, inspectErr := startupExecutablePaths(ctx, environment, inspectionName)
			if inspectErr != nil {
				return fileError("systemd_execstart_inspection_failed", "systemd unit의 실제 시작 실행 파일을 확인하지 못했습니다.", inspectErr)
			}
			evidence = append(evidence, executableEvidence)
			unitPaths = append(unitPaths, executablePaths...)
			if !complete {
				unknowns = append(unknowns, unitName+": ExecCondition/ExecStart 계열의 실제 스크립트 경로를 결정적으로 해석할 수 없음")
			}
		}
		for _, unitPath := range uniqueSortedPaths(unitPaths) {
			if _, exists := seenPaths[unitPath]; exists {
				continue
			}
			seenPaths[unitPath] = struct{}{}
			assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, unitPath, support.PermissionPolicy{
				AllowedUIDs: map[int]struct{}{0: {}}, AllowedMode: 0o755,
				AllowedTypes: map[string]struct{}{"regular": {}}, FollowFinalSymlink: true,
			})
			if err != nil {
				return fileError("startup_permission_inspection_failed", "시작 파일 권한을 확인하지 못했습니다.", err)
			}
			evidence = append(evidence, assessment.Evidence...)
			for _, violation := range assessment.Violations {
				violations = append(violations, unitPath+": "+violation)
			}
			for _, unknown := range assessment.Unknowns {
				unknowns = append(unknowns, unitPath+": "+unknown)
			}
			if !assessment.Exists {
				unknowns = append(unknowns, unitPath+": 파일 없음")
			}
		}
	}
	for _, legacyPath := range []string{"/etc/rc.d/rc.local", "/etc/rc.local"} {
		metadata, inspectErr := environment.Files.Lstat(legacyPath)
		if inspectErr != nil {
			if errors.Is(inspectErr, os.ErrNotExist) {
				continue
			}
			return fileError("legacy_startup_inspection_failed", "legacy 시작 스크립트를 확인하지 못했습니다.", inspectErr)
		}
		if metadata.Mode.Perm()&0o111 == 0 {
			continue
		}
		if _, exists := seenPaths[legacyPath]; exists {
			continue
		}
		seenPaths[legacyPath] = struct{}{}
		assessment, inspectErr := support.InspectPermissions(ctx, environment.Files, environment.Commands, legacyPath, support.PermissionPolicy{
			AllowedUIDs: map[int]struct{}{0: {}}, AllowedMode: 0o755,
			AllowedTypes: map[string]struct{}{"regular": {}}, FollowFinalSymlink: true,
		})
		if inspectErr != nil {
			return fileError("legacy_startup_permission_failed", "legacy 시작 스크립트 권한을 확인하지 못했습니다.", inspectErr)
		}
		evidence = append(evidence, assessment.Evidence...)
		for _, violation := range assessment.Violations {
			violations = append(violations, legacyPath+": "+violation)
		}
		for _, unknown := range assessment.Unknowns {
			unknowns = append(unknowns, legacyPath+": "+unknown)
		}
	}
	sort.Strings(violations)
	sort.Strings(unknowns)
	summaryEvidence := support.FactEvidence("systemd 시작 파일 권한 파생 정보", map[string]any{
		"unit_count": len(unitNames), "unique_path_count": len(seenPaths),
		"violation_count": len(violations), "unknown_count": len(unknowns), "unsupported_unit_count": unsupportedUnitCount,
		"violation_sample": limitedStrings(violations, 20), "unknown_sample": limitedStrings(unknowns, 20),
	})
	evidence = append(evidence, summaryEvidence)
	if len(violations) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "활성 또는 부팅 활성 시작 파일에 비-root 소유나 비소유자 쓰기 권한이 있습니다.", Expected: "모든 fragment, drop-in 및 실제 시작 실행 파일이 root 소유이고 group/other 쓰기가 없어야 합니다.", Observed: fmt.Sprintf("위반 %d건", len(violations)), Evidence: evidence}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "일부 generated/transient/custom 시작 경로의 권한을 확정할 수 없습니다.", Expected: "모든 활성 또는 부팅 활성 unit의 실제 시작 파일을 확인할 수 있어야 합니다.", Observed: fmt.Sprintf("확정 불가 %d건", len(unknowns)), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "활성 및 부팅 활성 systemd 시작 파일과 실제 실행 파일의 소유자·권한이 안전합니다.", Expected: "모든 fragment, drop-in 및 실제 시작 실행 파일이 root 소유이고 group/other 쓰기가 없어야 합니다.", Observed: fmt.Sprintf("unit %d개, 경로 %d개 확인", len(unitNames), len(seenPaths)), Evidence: evidence}
}

func evaluateInetdPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"xinetd.service", "inetd.service"})
	if err != nil {
		return fileError("inetd_unit_inspection_failed", "inetd/xinetd 상태를 확인하지 못했습니다.", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"xinetd", "inetd"})
	if err != nil {
		return fileError("inetd_process_inspection_failed", "inetd/xinetd 상태를 확인하지 못했습니다.", err)
	}
	evidence := append(unitEvidence, processEvidence)
	installed := false
	active := len(processes) > 0
	xinetdManaged := false
	inetdManaged := false
	for _, unit := range units {
		installed = installed || support.UnitInstalled(unit)
		active = active || support.UnitActive(unit) || support.UnitEnabled(unit)
	}
	for _, unit := range units {
		if !support.UnitInstalled(unit) || (!support.UnitActive(unit) && !support.UnitEnabled(unit)) {
			continue
		}
		if unit.Name == "xinetd.service" {
			xinetdManaged = true
		} else if unit.Name == "inetd.service" {
			inetdManaged = true
		}
		spec := executor.Spec{Name: "systemctl", Arguments: []string{"show", "--no-pager", "--property=ExecStart", "--", unit.Name}, Timeout: 15 * time.Second, MaxOutput: 1 << 20}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return fileError("inetd_execstart_failed", "inetd/xinetd 실행 경로를 확인하지 못했습니다.", runErr)
		}
		evidence = append(evidence, privateCommandSummary("inetd-execstart-summary", spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return fileError("inetd_execstart_failed", "inetd/xinetd 실행 경로를 확인하지 못했습니다.", fmt.Errorf("unit=%s exit=%d truncated=%t", unit.Name, result.ExitCode, result.Truncated))
		}
		if unit.Name == "xinetd.service" && xinetdUsesCustomConfig(string(result.Stdout)) {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "inetd/xinetd가 사용자 지정 설정 경로로 실행되고 있습니다.", Expected: "실제로 로드되는 모든 설정 경로를 확인할 수 있어야 합니다.", Observed: "ExecStart에 custom config option이 있습니다.", Evidence: evidence}
		}
		if unit.Name == "inetd.service" {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "활성 inetd 구현의 positional 설정 파일 및 디렉터리 의미를 확정할 수 없습니다.", Expected: "실제로 로드되는 모든 설정 경로를 확인할 수 있어야 합니다.", Observed: "inetd.service의 제품별 실행 인자 검증이 필요합니다.", Evidence: evidence}
		}
	}
	for _, processName := range processes {
		if (processName == "xinetd" && !xinetdManaged) || (processName == "inetd" && !inetdManaged) {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "systemd unit 밖에서 실행 중인 inetd/xinetd의 설정 경로를 확정할 수 없습니다.", Expected: "실제로 로드되는 모든 설정 경로를 확인할 수 있어야 합니다.", Observed: "process active, managed unit 없음", Evidence: evidence}
		}
	}
	paths, complete, pathEvidence, err := inetdConfigPaths(ctx, environment, xinetdManaged)
	if err != nil {
		return fileError("inetd_config_listing_failed", "inetd/xinetd 설정 파일을 열거하지 못했습니다.", err)
	}
	evidence = append(evidence, pathEvidence...)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	if !complete {
		unknowns = append(unknowns, "xinetd include/includedir 그래프를 완전히 해석할 수 없음")
	}
	existing := 0
	for _, configPath := range paths {
		assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, configPath, support.PermissionPolicy{
			AllowedUIDs: map[int]struct{}{0: {}}, AllowedMode: 0o600, AllowedTypes: map[string]struct{}{"regular": {}},
		})
		if err != nil {
			return fileError("inetd_permission_inspection_failed", "inetd/xinetd 설정 권한을 확인하지 못했습니다.", err)
		}
		if !assessment.Exists {
			continue
		}
		existing++
		evidence = append(evidence, assessment.Evidence...)
		for _, violation := range assessment.Violations {
			violations = append(violations, configPath+": "+violation)
		}
		for _, unknown := range assessment.Unknowns {
			unknowns = append(unknowns, configPath+": "+unknown)
		}
	}
	evidence = append(evidence, support.FactEvidence("inetd 설정 권한 파생 정보", map[string]any{"file_count": existing, "violation_count": len(violations), "unknown_count": len(unknowns)}))
	if !installed && !active && existing == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "inetd/xinetd와 설정 파일이 없습니다.", Expected: "사용되는 inetd/xinetd 설정에만 권한 기준을 적용합니다.", Observed: "unit, process, config 없음", Evidence: evidence}
	}
	if len(violations) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "inetd/xinetd 설정 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.", Expected: "사용되는 모든 설정 파일이 root 소유이고 0600 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("위반 %d건", len(violations)), Evidence: evidence}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "일부 inetd/xinetd 설정 파일의 실효 대상이나 권한을 확정할 수 없습니다.", Expected: "모든 설정 파일 유형과 ACL을 확인할 수 있어야 합니다.", Observed: fmt.Sprintf("확정 불가 %d건", len(unknowns)), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "inetd/xinetd 설정 파일의 소유자와 권한이 안전합니다.", Expected: "사용되는 모든 설정 파일이 root 소유이고 0600 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("설정 파일 %d개 확인, active=%t", existing, active), Evidence: evidence}
}

func evaluateSyslogPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"rsyslog.service"})
	if err != nil {
		return fileError("rsyslog_unit_inspection_failed", "rsyslog 상태를 확인하지 못했습니다.", err)
	}
	evidence := append([]model.Evidence(nil), unitEvidence...)
	if len(units) != 1 || !support.UnitInstalled(units[0]) || (!support.UnitActive(units[0]) && !support.UnitEnabled(units[0])) {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "활성 또는 부팅 활성 rsyslog 서비스가 없습니다.", Expected: "사용되는 rsyslog 설정에만 권한 기준을 적용합니다.", Observed: "journald-only 또는 rsyslog 비활성", Evidence: evidence}
	}
	unit := units[0]
	if unit.FragmentPath == "" || strings.TrimSpace(unit.DropInPaths) != "" || (!strings.HasPrefix(unit.FragmentPath, "/usr/lib/systemd/system/") && !strings.HasPrefix(unit.FragmentPath, "/lib/systemd/system/")) {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "비표준 rsyslog unit 또는 drop-in으로 설정 경로가 변경될 수 있습니다.", Expected: "실제로 로드되는 rsyslog 설정 경로를 확인할 수 있어야 합니다.", Observed: "custom unit or drop-in", Evidence: evidence}
	}
	rootConfig, startupPaths, startupEvidence, startupComplete, err := inspectRsyslogStartupPath(ctx, environment.Files)
	if err != nil {
		return fileError("rsyslog_startup_config_failed", "rsyslog 시작 설정을 해석하지 못했습니다.", err)
	}
	evidence = append(evidence, startupEvidence...)
	if !startupComplete {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "rsyslog 시작 옵션의 실효 설정 경로를 결정적으로 해석할 수 없습니다.", Expected: "EnvironmentFile과 -f 옵션에서 실제 설정 경로를 확정할 수 있어야 합니다.", Observed: "dynamic or conflicting rsyslog startup option", Evidence: evidence}
	}
	validationSpec := executor.Spec{Name: "rsyslogd", Arguments: []string{"-N1", "-f", rootConfig}, Timeout: 30 * time.Second, MaxOutput: 2 << 20}
	validation, err := environment.Commands.Run(ctx, validationSpec)
	if err != nil {
		return fileError("rsyslog_validation_failed", "rsyslog 설정 구문을 검증하지 못했습니다.", err)
	}
	evidence = append(evidence, support.CommandEvidence(validationSpec, validation))
	if validation.ExitCode != 0 || validation.Truncated {
		return fileError("rsyslog_validation_failed", "rsyslog 설정 구문을 검증하지 못했습니다.", fmt.Errorf("exit=%d truncated=%t", validation.ExitCode, validation.Truncated))
	}
	paths, complete, pathEvidence, err := collectRsyslogConfigPaths(ctx, environment, rootConfig)
	if err != nil {
		return fileError("rsyslog_include_failed", "rsyslog include 경로를 해석하지 못했습니다.", err)
	}
	evidence = append(evidence, pathEvidence...)
	paths = uniqueSortedPaths(append(paths, startupPaths...))
	if !complete {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "동적 또는 비표준 rsyslog include 경로를 완전히 해석할 수 없습니다.", Expected: "로드되는 모든 rsyslog 설정 파일을 열거할 수 있어야 합니다.", Observed: "unsupported include pattern", Evidence: evidence}
	}
	allowedOwners, ownerEvidence, err := allowedRsyslogOwners(ctx, environment)
	if err != nil {
		return fileError("rsyslog_owner_lookup_failed", "rsyslog 허용 소유자를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, ownerEvidence)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	for _, configPath := range paths {
		assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, configPath, support.PermissionPolicy{
			AllowedUIDs: allowedOwners, AllowedMode: 0o640, AllowedTypes: map[string]struct{}{"regular": {}},
		})
		if err != nil {
			return fileError("rsyslog_permission_inspection_failed", "rsyslog 설정 권한을 확인하지 못했습니다.", err)
		}
		if !assessment.Exists {
			return fileError("rsyslog_config_missing", "로드되는 rsyslog 설정 파일이 없습니다.", fmt.Errorf("%s", configPath))
		}
		evidence = append(evidence, assessment.Evidence...)
		for _, violation := range assessment.Violations {
			violations = append(violations, configPath+": "+violation)
		}
		for _, unknown := range assessment.Unknowns {
			unknowns = append(unknowns, configPath+": "+unknown)
		}
	}
	evidence = append(evidence, support.FactEvidence("rsyslog 설정 권한 파생 정보", map[string]any{"file_count": len(paths), "violation_count": len(violations), "unknown_count": len(unknowns)}))
	if len(violations) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "로드되는 rsyslog 설정 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.", Expected: "모든 설정 파일이 root/bin/sys 소유이고 0640 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("위반 %d건", len(violations)), Evidence: evidence}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "일부 rsyslog 설정 파일의 유형 또는 ACL을 확정할 수 없습니다.", Expected: "모든 로드 파일의 소유자·권한·ACL을 확인할 수 있어야 합니다.", Observed: fmt.Sprintf("확정 불가 %d건", len(unknowns)), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "로드되는 rsyslog 설정 파일의 소유자와 권한이 안전합니다.", Expected: "모든 설정 파일이 root/bin/sys 소유이고 0640 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("설정 파일 %d개 확인", len(paths)), Evidence: evidence}
}

func validSystemdUnitToken(value string) bool {
	if value == "" || (strings.HasPrefix(value, "-") && value != "-.mount") || !strings.Contains(value, ".") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("@_.:-", character) {
			return false
		}
	}
	return true
}

func startupUnitPaths(unit support.UnitState) ([]string, string) {
	fragment := strings.TrimSpace(unit.FragmentPath)
	if fragment == "" {
		return nil, "transient unit 또는 fragment 없음"
	}
	if !path.IsAbs(fragment) || path.Clean(fragment) != fragment || strings.ContainsAny(fragment, "\x00\r\n\"'") {
		return nil, "잘못된 fragment 경로"
	}
	normalized := path.Clean(fragment)
	if strings.HasPrefix(normalized, "/run/systemd/generator") || strings.HasPrefix(normalized, "/run/systemd/transient/") {
		return nil, "generated/transient unit"
	}
	paths := []string{normalized}
	for _, dropIn := range strings.Fields(unit.DropInPaths) {
		if !path.IsAbs(dropIn) || path.Clean(dropIn) != dropIn || strings.ContainsAny(dropIn, "\x00\r\n\"'") {
			return nil, "drop-in 경로를 결정적으로 해석할 수 없음"
		}
		paths = append(paths, dropIn)
	}
	sort.Strings(paths)
	return paths, ""
}

func startupExecutablePaths(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
) ([]string, bool, model.Evidence, error) {
	spec := executor.Spec{
		Name: "systemctl",
		Arguments: []string{
			"show", "--no-pager",
			"--property=ExecCondition,ExecStartPre,ExecStart,ExecStartPost",
			"--", unitName,
		},
		Timeout: 15 * time.Second, MaxOutput: 2 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := privateCommandSummary("systemd-start-command-summary", spec, result)
	if err != nil {
		return nil, false, evidence, err
	}
	if result.ExitCode != 0 || result.Truncated {
		return nil, false, evidence, fmt.Errorf("systemctl show %s exit=%d truncated=%t", unitName, result.ExitCode, result.Truncated)
	}
	properties, err := support.ParseKeyValueOutput(string(result.Stdout))
	if err != nil {
		return nil, false, evidence, err
	}
	complete := true
	paths := make([]string, 0)
	for _, property := range []string{"ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost"} {
		value, exists := properties[property]
		if !exists {
			complete = false
			continue
		}
		if strings.TrimSpace(value) == "" {
			if property == "ExecStart" {
				complete = false
			}
			continue
		}
		extracted, parsed := parseSystemdCommandPaths(value)
		paths = append(paths, extracted...)
		complete = complete && parsed
	}
	return uniqueSortedPaths(paths), complete, evidence, nil
}

func expandStartupUnitDependencies(
	ctx context.Context,
	environment evaluator.Environment,
	initial []string,
) ([]string, []model.Evidence, []string, error) {
	const maximumUnits = 4096
	seen := make(map[string]struct{}, len(initial))
	queue := append([]string(nil), initial...)
	for _, unitName := range initial {
		seen[unitName] = struct{}{}
	}
	evidence := make([]model.Evidence, 0)
	unknowns := make([]string, 0)
	for index := 0; index < len(queue); index++ {
		unitName := queue[index]
		properties := ""
		switch {
		case strings.HasSuffix(unitName, ".socket"), strings.HasSuffix(unitName, ".timer"), strings.HasSuffix(unitName, ".path"):
			properties = "Triggers"
		case strings.HasSuffix(unitName, ".target"):
			properties = "Wants,Requires"
		default:
			continue
		}
		spec := executor.Spec{
			Name: "systemctl", Arguments: []string{"show", "--no-pager", "--property=" + properties, "--", unitName},
			Timeout: 15 * time.Second, MaxOutput: 1 << 20,
		}
		result, err := environment.Commands.Run(ctx, spec)
		evidence = append(evidence, privateCommandSummary("systemd-start-dependency-summary", spec, result))
		if err != nil {
			return nil, evidence, unknowns, err
		}
		if result.ExitCode != 0 || result.Truncated {
			return nil, evidence, unknowns, fmt.Errorf("systemctl dependency query %s exit=%d truncated=%t", unitName, result.ExitCode, result.Truncated)
		}
		values, err := support.ParseKeyValueOutput(string(result.Stdout))
		if err != nil {
			return nil, evidence, unknowns, err
		}
		resolved := 0
		for _, property := range strings.Split(properties, ",") {
			value, exists := values[property]
			if !exists {
				unknowns = append(unknowns, unitName+": "+property+" 속성 누락")
				continue
			}
			for _, dependency := range strings.Fields(value) {
				if !startupRelevantUnitType(dependency) {
					continue
				}
				if !validSystemdUnitToken(dependency) {
					unknowns = append(unknowns, unitName+": 이스케이프되거나 비표준인 시작 의존 unit")
					continue
				}
				resolved++
				if _, exists := seen[dependency]; exists {
					continue
				}
				if len(seen) >= maximumUnits {
					unknowns = append(unknowns, "systemd 시작 의존 unit 수가 안전 한도를 초과함")
					continue
				}
				seen[dependency] = struct{}{}
				queue = append(queue, dependency)
			}
		}
		if properties == "Triggers" && resolved == 0 {
			unknowns = append(unknowns, unitName+": 활성화 대상 unit을 확인할 수 없음")
		}
	}
	result := make([]string, 0, len(seen))
	for unitName := range seen {
		result = append(result, unitName)
	}
	sort.Strings(result)
	return result, evidence, uniqueSortedPaths(unknowns), nil
}

func startupRelevantUnitType(unitName string) bool {
	for _, suffix := range []string{".service", ".socket", ".timer", ".path", ".mount", ".automount", ".target", ".swap", ".slice"} {
		if strings.HasSuffix(unitName, suffix) {
			return true
		}
	}
	return false
}

func parseSystemdCommandPaths(value string) ([]string, bool) {
	paths := make([]string, 0)
	pathMarkers := 0
	complete := true
	for _, rawField := range strings.Fields(value) {
		field := strings.Trim(rawField, "{};")
		if !strings.HasPrefix(field, "path=") {
			continue
		}
		pathMarkers++
		executable := strings.TrimPrefix(field, "path=")
		if !path.IsAbs(executable) || path.Clean(executable) != executable || strings.ContainsAny(executable, "\\\x00\r\n\"'`$%") {
			complete = false
			continue
		}
		paths = append(paths, executable)
		switch strings.ToLower(path.Base(executable)) {
		case "sh", "bash", "dash", "ksh", "zsh", "csh", "tcsh", "env", "busybox", "nice", "nohup", "setsid", "chroot", "su", "runuser", "sudo", "python", "python3", "perl", "ruby", "node":
			// The executable itself can be checked, but a secondary script or
			// dynamically selected program may be present in argv[].
			complete = false
		}
	}
	if pathMarkers == 0 || pathMarkers != strings.Count(value, "path=") {
		complete = false
	}
	return uniqueSortedPaths(paths), complete
}

func xinetdUsesCustomConfig(output string) bool {
	paths, complete := parseSystemdCommandPaths(output)
	if !complete || len(paths) != 1 || strings.ToLower(path.Base(paths[0])) != "xinetd" {
		return true
	}
	for _, rawField := range strings.Fields(strings.ToLower(output)) {
		field := strings.Trim(rawField, "{};\"'")
		if field == "-f" || strings.HasPrefix(field, "-f=") || strings.HasPrefix(field, "-f/") ||
			strings.HasPrefix(field, "--file") || strings.HasPrefix(field, "--config") {
			return true
		}
	}
	return false
}

func inetdConfigPaths(
	ctx context.Context,
	environment evaluator.Environment,
	xinetdManaged bool,
) ([]string, bool, []model.Evidence, error) {
	const maximumXinetdObjects = 4096
	result := make([]string, 0)
	evidence := make([]model.Evidence, 0)
	complete := true

	if !xinetdManaged {
		if _, err := environment.Files.Lstat("/etc/inetd.conf"); err == nil {
			result = append(result, "/etc/inetd.conf")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, false, evidence, err
		}
	}

	if _, err := environment.Files.Lstat("/etc/xinetd.conf"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, evidence, err
		}
		if xinetdManaged {
			complete = false
		}
		return uniqueSortedPaths(result), complete, evidence, nil
	}

	fileQueue := []string{"/etc/xinetd.conf"}
	directoryQueue := make([]string, 0)
	seenFiles := make(map[string]struct{})
	seenDirectories := make(map[string]struct{})
	for len(fileQueue) > 0 || len(directoryQueue) > 0 {
		if len(seenFiles)+len(seenDirectories) >= maximumXinetdObjects {
			complete = false
			break
		}
		if len(directoryQueue) > 0 {
			directory := directoryQueue[0]
			directoryQueue = directoryQueue[1:]
			if _, seen := seenDirectories[directory]; seen {
				continue
			}
			seenDirectories[directory] = struct{}{}
			entries, err := environment.Files.ReadDir(directory)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					complete = false
					continue
				}
				return nil, false, evidence, err
			}
			names := make([]string, 0)
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || path.Base(name) != name || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
					continue
				}
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				fileQueue = append(fileQueue, path.Join(directory, name))
			}
			evidence = append(evidence, support.FactEvidence(directory, map[string]any{
				"included_file_count": len(names), "names_redacted": true,
			}))
			continue
		}

		current := fileQueue[0]
		fileQueue = fileQueue[1:]
		if _, seen := seenFiles[current]; seen {
			continue
		}
		seenFiles[current] = struct{}{}
		data, metadata, err := environment.Files.ReadFile(ctx, current, 2<<20)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				complete = false
				continue
			}
			return nil, false, evidence, err
		}
		result = append(result, current)
		files, directories, parsed := parseXinetdIncludes(string(data))
		complete = complete && parsed
		fileQueue = append(fileQueue, files...)
		directoryQueue = append(directoryQueue, directories...)
		evidence = append(evidence, support.FactEvidence(current, map[string]any{
			"size": metadata.Size, "include_count": len(files), "includedir_count": len(directories),
			"include_scan_complete": parsed, "content_redacted": true,
		}))
	}
	return uniqueSortedPaths(result), complete, evidence, nil
}

func parseXinetdIncludes(content string) (files, directories []string, complete bool) {
	complete = true
	depth := 0
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line, commentComplete := stripXinetdComment(raw)
		if !commentComplete {
			complete = false
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && (strings.EqualFold(fields[0], "include") || strings.EqualFold(fields[0], "includedir")) {
			if depth != 0 || len(fields) != 2 || !safeXinetdIncludePath(fields[1]) {
				complete = false
			} else if strings.EqualFold(fields[0], "includedir") {
				directories = append(directories, fields[1])
			} else {
				files = append(files, fields[1])
			}
		}
		delta, balanced := xinetdBraceDelta(line)
		if !balanced || depth+delta < 0 {
			complete = false
			continue
		}
		depth += delta
	}
	if depth != 0 {
		complete = false
	}
	return uniqueSortedPaths(files), uniqueSortedPaths(directories), complete
}

func safeXinetdIncludePath(value string) bool {
	return value != "" && path.IsAbs(value) && path.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\\\"'`$%*?[")
}

func stripXinetdComment(value string) (string, bool) {
	quote := rune(0)
	escaped := false
	for index, character := range value {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == '#' {
			return value[:index], true
		}
	}
	return value, quote == 0 && !escaped
}

func xinetdBraceDelta(value string) (int, bool) {
	delta := 0
	quote := rune(0)
	escaped := false
	for _, character := range value {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		switch character {
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta, quote == 0 && !escaped
}

func collectRsyslogConfigPaths(ctx context.Context, environment evaluator.Environment, rootConfig string) ([]string, bool, []model.Evidence, error) {
	queue := []string{rootConfig}
	seen := make(map[string]struct{})
	result := make([]string, 0)
	evidence := make([]model.Evidence, 0)
	complete := true
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		data, _, err := environment.Files.ReadFile(ctx, current, 2<<20)
		if err != nil {
			if current != "/etc/rsyslog.conf" && errors.Is(err, os.ErrNotExist) {
				complete = false
				evidence = append(evidence, support.FactEvidence(current, map[string]any{"missing": true, "content_redacted": true}))
				continue
			}
			return nil, false, evidence, err
		}
		result = append(result, current)
		includes := make([]string, 0)
		for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lower := strings.ToLower(line)
			var pattern string
			switch {
			case strings.HasPrefix(lower, "$includeconfig"):
				fields := strings.Fields(line)
				if len(fields) != 2 {
					complete = false
					continue
				}
				pattern = strings.Trim(fields[1], "\"'")
			case strings.HasPrefix(lower, "include("):
				marker := strings.Index(lower, "file=")
				if marker < 0 {
					complete = false
					continue
				}
				remainder := strings.TrimSpace(line[marker+len("file="):])
				if len(remainder) < 2 || (remainder[0] != '"' && remainder[0] != '\'') {
					complete = false
					continue
				}
				quote := remainder[0]
				end := strings.IndexByte(remainder[1:], quote)
				if end < 0 {
					complete = false
					continue
				}
				pattern = remainder[1 : end+1]
			default:
				continue
			}
			matches, ok, err := expandFixedConfigPattern(environment, pattern)
			if err != nil {
				return nil, false, evidence, err
			}
			if !ok {
				complete = false
				continue
			}
			includes = append(includes, matches...)
		}
		sort.Strings(includes)
		queue = append(queue, includes...)
		evidence = append(evidence, support.FactEvidence(current, map[string]any{"include_count": len(includes), "content_redacted": true}))
	}
	sort.Strings(result)
	return result, complete, evidence, nil
}

func inspectRsyslogStartupPath(ctx context.Context, files system.Reader) (string, []string, []model.Evidence, bool, error) {
	const sysconfigPath = "/etc/sysconfig/rsyslog"
	exists, err := files.Exists(sysconfigPath)
	if err != nil {
		return "", nil, nil, false, err
	}
	if !exists {
		return "/etc/rsyslog.conf", nil, nil, true, nil
	}
	data, metadata, err := files.ReadFile(ctx, sysconfigPath, 256<<10)
	if err != nil {
		return "", nil, nil, false, err
	}
	configPath, complete, err := rsyslogConfigPathFromSysconfig(string(data))
	evidence := []model.Evidence{
		support.FileMetadataEvidence(metadata),
		support.FactEvidence("rsyslog startup configuration", map[string]any{"custom_config_path": configPath != "/etc/rsyslog.conf", "content_redacted": true}),
	}
	return configPath, []string{sysconfigPath}, evidence, complete, err
}

func rsyslogConfigPathFromSysconfig(content string) (string, bool, error) {
	selected := "/etc/rsyslog.conf"
	explicit := false
	setPath := func(candidate string) bool {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "=")
		if !path.IsAbs(candidate) || path.Clean(candidate) != candidate || strings.ContainsAny(candidate, "\\\x00\r\n\"'`$%") {
			return false
		}
		if explicit && selected != candidate {
			return false
		}
		selected = candidate
		explicit = true
		return true
	}
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		tokens, err := sysconfigTokens(raw)
		if err != nil {
			return "", false, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if len(tokens) > 1 {
			values, valueErr := sysconfigTokens(strings.Join(tokens[1:], " "))
			if valueErr != nil {
				return "", false, fmt.Errorf("line %d value: %w", lineNumber+1, valueErr)
			}
			tokens = append([]string{tokens[0]}, values...)
		}
		for index, token := range tokens {
			switch {
			case token == "RSYSLOG_CONFIG_FILE":
				if index+1 >= len(tokens) || !setPath(tokens[index+1]) {
					return selected, false, nil
				}
			case token == "-f":
				if index+1 >= len(tokens) || !setPath(tokens[index+1]) {
					return selected, false, nil
				}
			case strings.HasPrefix(token, "-f") && len(token) > 2:
				if !setPath(strings.TrimPrefix(token, "-f")) {
					return selected, false, nil
				}
			}
		}
	}
	return selected, true, nil
}

func sysconfigTokens(line string) ([]string, error) {
	result := make([]string, 0)
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			result = append(result, current.String())
			current.Reset()
		}
	}
	for _, character := range line {
		if escaped {
			current.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
		case '#':
			flush()
			return result, nil
		case ' ', '\t', '=':
			flush()
		default:
			current.WriteRune(character)
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unterminated quoted or escaped value")
	}
	flush()
	return result, nil
}

func expandFixedConfigPattern(environment evaluator.Environment, pattern string) ([]string, bool, error) {
	if pattern == "" || !path.IsAbs(pattern) || strings.ContainsAny(pattern, "\x00\r\n") {
		return nil, false, nil
	}
	directory, filePattern := path.Split(pattern)
	if strings.ContainsAny(strings.TrimSuffix(directory, "/"), "*?[") || filePattern == "" {
		return nil, false, nil
	}
	if !strings.ContainsAny(filePattern, "*?[") {
		return []string{path.Clean(pattern)}, true, nil
	}
	entries, err := environment.Files.ReadDir(strings.TrimSuffix(directory, "/"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, err
	}
	matches := make([]string, 0)
	for _, entry := range entries {
		matched, err := path.Match(filePattern, entry.Name())
		if err != nil {
			return nil, false, err
		}
		if matched && !entry.IsDir() {
			matches = append(matches, path.Join(directory, entry.Name()))
		}
	}
	sort.Strings(matches)
	return matches, true, nil
}

func allowedRsyslogOwners(ctx context.Context, environment evaluator.Environment) (map[int]struct{}, model.Evidence, error) {
	accounts, evidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return nil, model.Evidence{}, err
	}
	allowed := map[int]struct{}{0: {}}
	for _, account := range accounts {
		if account.Name == "root" || account.Name == "bin" || account.Name == "sys" {
			allowed[int(account.UID)] = struct{}{}
		}
	}
	return allowed, evidence, nil
}
