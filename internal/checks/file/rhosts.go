package filecheck

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorRHostsTrust = "unix.file.rhosts_trust"

var (
	rServiceUnits = []string{
		"rexec.service", "rexec.socket", "rexec@.service",
		"rlogin.service", "rlogin.socket", "rlogin@.service",
		"rsh.service", "rsh.socket", "rsh@.service",
		"xinetd.service",
	}
	rServiceProcesses   = []string{"in.rexecd", "in.rlogind", "in.rshd", "rexecd", "rlogind", "rshd"}
	rServiceConfigPaths = []string{"/etc/xinetd.d/rexec", "/etc/xinetd.d/rlogin", "/etc/xinetd.d/rsh"}
)

type trustInspection struct {
	Checked    int
	Violations []pathFinding
	Unknowns   []pathFinding
	Evidence   []model.Evidence
}

func evaluateRHostsTrust(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "r 계열 서비스 상태를 지원하는 방식으로 확인할 수 없습니다.",
			Expected:      "systemd 기반 Rocky Linux 9.8에서 r 계열 활성 경로를 확인할 수 있어야 합니다.",
			Observed:      environment.Platform.InitSystem,
		}
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, rServiceUnits)
	if err != nil {
		return fileError("r_service_units_failed", "r 계열 systemd unit 상태를 확인하지 못했습니다.", err)
	}
	listeners, listenerEvidence, err := support.InspectTCPListeningPorts(ctx, environment, []int{512, 513, 514})
	if err != nil {
		return fileError("r_service_listeners_failed", "r 계열 리스닝 포트를 확인하지 못했습니다.", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, rServiceProcesses)
	if err != nil {
		return fileError("r_service_processes_failed", "r 계열 프로세스를 확인하지 못했습니다.", err)
	}
	evidence := append([]model.Evidence(nil), unitEvidence...)
	evidence = append(evidence, listenerEvidence, processEvidence)
	installed := false
	activeIndicators := make([]string, 0)
	activationUnknowns := make([]pathFinding, 0)
	xinetdActive := false
	for _, unit := range units {
		if unit.Name == "xinetd.service" {
			xinetdActive = support.UnitActive(unit) || support.UnitEnabled(unit)
			continue
		}
		if support.UnitInstalled(unit) {
			installed = true
		}
		if support.UnitActive(unit) {
			activeIndicators = append(activeIndicators, unit.Name+" active")
		}
		if support.UnitEnabled(unit) {
			activeIndicators = append(activeIndicators, unit.Name+" enabled")
		}
	}
	for port, lines := range listeners {
		for range lines {
			activeIndicators = append(activeIndicators, fmt.Sprintf("port %d listening", port))
		}
	}
	for _, process := range processes {
		activeIndicators = append(activeIndicators, process+" process running")
	}
	for _, configPath := range rServiceConfigPaths {
		inspected, inspectErr := inspectPathWithoutSymlinks(environment.Files, configPath)
		if inspectErr != nil {
			return fileError("r_service_config_stat_failed", "r 계열 xinetd 설정의 존재 여부를 확인하지 못했습니다.", fmt.Errorf("%s: %w", configPath, inspectErr))
		}
		if !inspected.Exists {
			continue
		}
		installed = true
		evidence = append(evidence, inspected.Evidence...)
		if !xinetdActive {
			continue
		}
		if inspected.Unknown != "" {
			activationUnknowns = append(activationUnknowns, pathFinding{Path: configPath, Reason: inspected.Unknown})
			continue
		}
		if inspected.Metadata.FileType != "regular" {
			activationUnknowns = append(activationUnknowns, pathFinding{Path: configPath, Reason: "xinetd 설정이 일반 파일이 아님"})
			continue
		}
		data, readMetadata, readErr := environment.Files.ReadFile(ctx, configPath, 1<<20)
		if readErr != nil {
			return fileError("r_service_config_read_failed", "r 계열 xinetd 설정을 확인하지 못했습니다.", fmt.Errorf("%s: %w", configPath, readErr))
		}
		if readMetadata.Device != inspected.Metadata.Device || readMetadata.Inode != inspected.Metadata.Inode {
			activationUnknowns = append(activationUnknowns, pathFinding{Path: configPath, Reason: "검사 중 xinetd 설정 대상이 변경됨"})
			continue
		}
		disabled, known := parseXinetdDisable(data)
		if !known {
			activationUnknowns = append(activationUnknowns, pathFinding{Path: configPath, Reason: "실효 disable 값을 확정할 수 없음"})
			continue
		}
		if !disabled {
			activeIndicators = append(activeIndicators, configPath+" enabled by xinetd")
		}
	}
	sort.Strings(activeIndicators)
	evidence = append(evidence, support.FactEvidence("r-service-state", map[string]any{
		"installed":          installed,
		"active_indicators":  activeIndicators,
		"unknown_activation": findingFacts(activationUnknowns, 32),
	}))
	expected := "r 서비스가 비활성화되어 있거나, 활성 시 hosts.equiv와 .rhosts가 올바른 소유자·0600 이하 권한을 사용하고 + 신뢰 설정이 없어야 합니다."
	if len(activeIndicators) == 0 {
		if len(activationUnknowns) > 0 {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownAmbiguousResult,
				Summary:       "xinetd의 r 계열 서비스 활성 상태를 확정할 수 없습니다.",
				Expected:      expected,
				Observed:      findingsObserved(nil, activationUnknowns),
				Evidence:      evidence,
			}
		}
		if !installed {
			return evaluator.Outcome{
				Status:   model.StatusNotApplicable,
				Summary:  "r 계열 서버 구성요소와 활성 경로가 없습니다.",
				Expected: expected,
				Observed: "관련 unit, process, listener 없음",
				Evidence: evidence,
			}
		}
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "설치된 r 계열 서비스가 비활성화되어 있습니다.",
			Expected: expected,
			Observed: "관련 unit이 inactive이고 enabled 상태가 아니며 listener가 없습니다.",
			Evidence: evidence,
		}
	}

	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return fileError("effective_passwd_failed", "실효 계정 목록을 확인하지 못했습니다.", err)
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		return fileError("home_mounts_failed", "홈 디렉터리의 파일 시스템 유형을 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, accountEvidence, mountEvidence)
	violations := make([]pathFinding, 0)
	unknowns := make([]pathFinding, 0)
	checked := 0

	inspection, err := inspectTrustPath(ctx, environment, "/etc/hosts.equiv", "system", []uint32{0})
	if err != nil {
		return fileError("hosts_equiv_inspection_failed", "hosts.equiv 파일을 안전하게 확인하지 못했습니다.", err)
	}
	checked += inspection.Checked
	violations = append(violations, inspection.Violations...)
	unknowns = append(unknowns, inspection.Unknowns...)
	evidence = append(evidence, inspection.Evidence...)

	grouped := groupAccountsByHome(accounts)
	for _, home := range sortedHomes(grouped) {
		homeAccounts := grouped[home]
		if err := validateAbsoluteSystemPath(home); err != nil {
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "절대 홈 경로가 아님"})
			continue
		}
		kind, mount, found := mounts.classify(home)
		if !found {
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "포함 마운트를 확인할 수 없음"})
			continue
		}
		if kind != homeMountLocal {
			reason := fmt.Sprintf("%s 홈의 .rhosts 확인 정책 없음(%s:%s)", kind, mount.Target, mount.FSType)
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: reason})
			continue
		}
		candidate, err := fixedChildPath(home, ".rhosts")
		if err != nil {
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "절대 .rhosts 경로 생성 실패"})
			continue
		}
		if len(homeAccounts) != 1 {
			inspected, inspectErr := inspectPathWithoutSymlinks(environment.Files, candidate)
			if inspectErr != nil {
				return fileError("rhosts_stat_failed", ".rhosts 파일의 존재 여부를 확인하지 못했습니다.", fmt.Errorf("%s: %w", candidate, inspectErr))
			}
			if !inspected.Exists {
				continue
			}
			evidence = append(evidence, inspected.Evidence...)
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: candidate, Reason: "여러 계정이 같은 홈을 사용하며 .rhosts 소유 정책이 없음"})
			continue
		}
		account := homeAccounts[0]
		inspection, err := inspectTrustPath(ctx, environment, candidate, account.Name, []uint32{0, account.UID})
		if err != nil {
			return fileError("rhosts_inspection_failed", ".rhosts 파일을 안전하게 확인하지 못했습니다.", fmt.Errorf("%s: %w", candidate, err))
		}
		checked += inspection.Checked
		violations = append(violations, inspection.Violations...)
		unknowns = append(unknowns, inspection.Unknowns...)
		evidence = append(evidence, inspection.Evidence...)
	}

	evidence = append(evidence, findingEvidence("rhosts-trust-summary", checked, violations, unknowns))
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "활성 r 계열 서비스의 신뢰 파일이 소유자·권한 또는 + 설정 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: findingsObserved(violations, unknowns),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "활성 r 계열 서비스가 있으나 공유·원격 홈 또는 심볼릭 링크 때문에 신뢰 파일을 완전히 확인할 수 없습니다.",
			Expected:      expected,
			Observed:      findingsObserved(nil, unknowns),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "활성 r 계열 서비스의 신뢰 파일이 기준을 충족합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("활성 경로 %d건, 신뢰 파일 %d개 확인", len(activeIndicators), checked),
		Evidence: evidence,
	}
}

func parseXinetdDisable(data []byte) (bool, bool) {
	known := false
	disabled := false
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line, _, _ := strings.Cut(raw, "#")
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "disable" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "yes":
			disabled = true
			known = true
		case "no":
			disabled = false
			known = true
		default:
			return false, false
		}
	}
	return disabled, known
}

func inspectTrustPath(ctx context.Context, environment evaluator.Environment, systemPath, account string, allowedUIDs []uint32) (trustInspection, error) {
	inspected, err := inspectPathWithoutSymlinks(environment.Files, systemPath)
	if err != nil {
		return trustInspection{}, err
	}
	if !inspected.Exists {
		return trustInspection{}, nil
	}
	result := trustInspection{Evidence: append([]model.Evidence(nil), inspected.Evidence...)}
	if inspected.Unknown != "" {
		result.Unknowns = append(result.Unknowns, pathFinding{Account: account, Path: systemPath, Reason: inspected.Unknown})
		return result, nil
	}
	metadata := inspected.Metadata
	if metadata.FileType != "regular" {
		result.Unknowns = append(result.Unknowns, pathFinding{Account: account, Path: systemPath, Reason: "일반 파일이 아님"})
		return result, nil
	}
	if metadata.UID < 0 {
		result.Unknowns = append(result.Unknowns, pathFinding{Account: account, Path: systemPath, Reason: "소유자 UID 확인 불가"})
		return result, nil
	}
	reasons := make([]string, 0, 4)
	ownerAllowed := false
	for _, uid := range allowedUIDs {
		if uint64(metadata.UID) == uint64(uid) {
			ownerAllowed = true
			break
		}
	}
	if !ownerAllowed {
		reasons = append(reasons, fmt.Sprintf("허용되지 않은 소유자 UID %d", metadata.UID))
	}
	if extra := metadata.Mode.Perm() &^ os.FileMode(0o600); extra != 0 {
		reasons = append(reasons, fmt.Sprintf("허용되지 않은 권한 비트 %04o", extra))
	}
	if metadata.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		reasons = append(reasons, "특수 권한 비트 설정")
	}
	aclViolations, aclEvidence, err := inspectNonOwnerACL(ctx, environment, metadata, os.FileMode(0o7))
	if err != nil {
		return trustInspection{}, err
	}
	result.Evidence = append(result.Evidence, aclEvidence)
	reasons = append(reasons, aclViolations...)

	data, readMetadata, err := environment.Files.ReadFile(ctx, systemPath, 1<<20)
	if err != nil {
		return trustInspection{}, err
	}
	if readMetadata.Device != metadata.Device || readMetadata.Inode != metadata.Inode || readMetadata.FileType != metadata.FileType {
		result.Unknowns = append(result.Unknowns, pathFinding{Account: account, Path: systemPath, Reason: "검사 중 파일 대상이 변경됨"})
		return result, nil
	}
	entryCount, hasPositiveTrust, parseErr := inspectTrustEntries(data)
	if parseErr != nil {
		result.Unknowns = append(result.Unknowns, pathFinding{Account: account, Path: systemPath, Reason: "신뢰 설정 문법을 확정할 수 없음"})
		return result, nil
	}
	result.Evidence = append(result.Evidence, support.FactEvidence(systemPath, map[string]any{
		"entry_count":        entryCount,
		"positive_trust_set": hasPositiveTrust,
		"content_redacted":   true,
	}))
	if hasPositiveTrust {
		reasons = append(reasons, "+ 신뢰 설정 존재")
	}
	result.Checked = 1
	if len(reasons) > 0 {
		result.Violations = append(result.Violations, pathFinding{Account: account, Path: systemPath, Reason: strings.Join(reasons, ", ")})
	}
	return result, nil
}

func inspectTrustEntries(data []byte) (int, bool, error) {
	entryCount := 0
	hasPositiveTrust := false
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line, _, _ := strings.Cut(raw, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) > 2 {
			return entryCount, hasPositiveTrust, fmt.Errorf("line %d has more than two fields", lineNumber+1)
		}
		entryCount++
		for _, field := range fields {
			if strings.HasPrefix(field, "+") {
				hasPositiveTrust = true
			}
		}
	}
	return entryCount, hasPositiveTrust, nil
}
