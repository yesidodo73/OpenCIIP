package patchcheck

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorDNSPatchLevel = "unix.service.dns_patch_level"

func evaluateDNSPatchLevel(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 DNS 서비스와 수신 포트를 함께 확인할 수 없습니다.",
			Expected:      "systemd 기반 Linux의 활성 BIND와 배포판 보안 권고를 확인해야 합니다.",
			Observed:      "init=" + environment.Platform.InitSystem,
		}
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"named.service", "named-chroot.service"})
	if err != nil {
		return patchError("dns_unit_inspection_failed", err, nil)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"named"})
	if err != nil {
		return patchError("dns_process_inspection_failed", err, unitEvidence)
	}
	tcp, tcpEvidence, err := support.InspectTCPListeningPorts(ctx, environment, []int{53})
	if err != nil {
		return patchError("dns_listener_inspection_failed", err, append(unitEvidence, processEvidence))
	}
	udp, udpEvidence, err := support.InspectUDPListeningPorts(ctx, environment, []int{53})
	if err != nil {
		return patchError("dns_listener_inspection_failed", err, append(unitEvidence, processEvidence, tcpEvidence))
	}
	evidence := append(unitEvidence, processEvidence, tcpEvidence, udpEvidence)
	unitActive := false
	unitInstalled := false
	customUnit := false
	for _, unit := range units {
		unitInstalled = unitInstalled || support.UnitInstalled(unit)
		unitActive = unitActive || support.UnitActive(unit)
		if support.UnitActive(unit) && (strings.TrimSpace(unit.DropInPaths) != "" ||
			(!strings.HasPrefix(unit.FragmentPath, "/usr/lib/systemd/system/") && !strings.HasPrefix(unit.FragmentPath, "/lib/systemd/system/"))) {
			customUnit = true
		}
	}
	listenerActive := len(tcp[53]) > 0 || len(udp[53]) > 0
	processActive := len(processes) > 0
	resolvedStubOnly := false
	if !unitActive && !processActive && listenerActive {
		listenerLines := append(append([]string(nil), tcp[53]...), udp[53]...)
		assessment, inspectErr := support.InspectSystemdResolvedStub(ctx, environment, listenerLines)
		evidence = append(evidence, assessment.Evidence...)
		if inspectErr != nil {
			return patchError("systemd_resolved_stub_inspection_failed", inspectErr, evidence)
		}
		if assessment.Confirmed {
			listenerActive = false
			resolvedStubOnly = true
		}
	}
	if !unitActive && !listenerActive && !processActive {
		observed := "BIND unit, named 프로세스 및 53번 포트 리스너가 없습니다."
		if unitInstalled {
			observed = "BIND unit은 설치되어 있으나 비활성이고 named 프로세스 및 리스너가 없습니다."
		} else if resolvedStubOnly {
			observed = "BIND unit과 named 프로세스는 없고 systemd-resolved 로컬 stub 리스너만 있습니다."
		}
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "활성 BIND DNS 서비스가 없습니다.",
			Expected: "활성 authoritative DNS 서비스에만 패치 수준 점검을 적용합니다.",
			Observed: observed,
			Evidence: evidence,
		}
	}
	if customUnit || (!unitActive && listenerActive) || (!processActive && listenerActive) {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 DNS 리스너를 표준 BIND 실행 경로와 연결해 확인할 수 없습니다.",
			Expected:      "배포판에서 제공하는 표준 BIND unit과 실행 파일의 패키지 정보 및 보안 권고를 확인할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("unit_active=%t process_active=%t listener_active=%t custom_unit=%t", unitActive, processActive, listenerActive, customUnit),
			Evidence:      evidence,
		}
	}
	if environment.Platform.Family == "debian" {
		return evaluateDebianDNSPatchLevel(ctx, environment, evidence)
	}
	if !environment.Commands.Available("named") || !environment.Commands.Available("rpm") || !environment.Commands.Available("dnf") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "BIND 버전과 vendor 보안 권고를 수집할 도구가 없습니다.",
			Expected:      "named, rpm, dnf를 사용해 로컬 버전과 최신 배포판 보안 메타데이터를 대조해야 합니다.",
			Observed:      "필수 수집 명령 중 하나 이상 없음",
			Evidence:      evidence,
		}
	}
	specs := []executor.Spec{
		{Name: "named", Arguments: []string{"-v"}, Timeout: 15 * time.Second, MaxOutput: 1 << 20},
		{Name: "rpm", Arguments: []string{"-qf", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", "/usr/sbin/named"}, Timeout: 30 * time.Second, MaxOutput: 1 << 20},
		{Name: "dnf", Arguments: []string{"--cacheonly", "--setopt=metadata_expire=never", "-q", "updateinfo", "list", "--security"}, Timeout: 2 * time.Minute, MaxOutput: 8 << 20},
	}
	for _, spec := range specs {
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return patchError("dns_patch_evidence_failed", runErr, evidence)
		}
		evidence = append(evidence, summarizedCommandEvidence(spec, result, 100))
		if result.ExitCode != 0 || result.Truncated {
			if spec.Name == "dnf" && support.DNFCacheUnavailable(result) {
				return evaluator.Outcome{
					Status:        model.StatusUnknown,
					UnknownReason: model.UnknownInsufficientEvidence,
					Summary:       "캐시된 저장소 메타데이터가 없어 BIND 보안 패치 상태를 확인할 수 없습니다.",
					Expected:      "신뢰 가능한 최신 벤더 저장소 메타데이터와 로컬 BIND 패키지를 대조해야 합니다.",
					Observed:      "오프라인 DNF 캐시에 필요한 저장소 메타데이터가 없습니다.",
					Evidence:      evidence,
				}
			}
			return patchError("dns_patch_evidence_failed", fmt.Errorf("%s exit=%d truncated=%t", spec.Name, result.ExitCode, result.Truncated), evidence)
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "활성 BIND의 로컬 버전과 캐시된 보안 권고를 수집했으며 최신 패치 여부는 수동 확인이 필요합니다.",
		Expected:      "신뢰 가능한 최신 배포판 저장소 메타데이터와 기관 패치 절차를 기준으로 BIND 보안 권고가 모두 반영되어야 합니다.",
		Observed:      "upstream 버전 문자열은 backport 여부를 나타내지 않으므로 자동 비교하지 않았습니다.",
		Evidence:      evidence,
	}
}

func evaluateDebianDNSPatchLevel(
	ctx context.Context,
	environment evaluator.Environment,
	evidence []model.Evidence,
) evaluator.Outcome {
	if !environment.Commands.Available("named") ||
		!environment.Commands.Available("dpkg-query") ||
		!environment.Commands.Available("apt-get") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 BIND의 패키지 버전과 캐시된 업그레이드 후보를 DPKG/APT로 확인할 수 없습니다.",
			Expected:      "named 실행 버전, BIND 패키지 및 신뢰 가능한 최신 배포판 보안 메타데이터를 대조해야 합니다.",
			Observed: fmt.Sprintf(
				"named=%t dpkg-query=%t apt-get=%t",
				environment.Commands.Available("named"),
				environment.Commands.Available("dpkg-query"),
				environment.Commands.Available("apt-get"),
			),
			Evidence: evidence,
		}
	}

	versionSpec := executor.Spec{Name: "named", Arguments: []string{"-v"}, Timeout: 15 * time.Second, MaxOutput: 1 << 20}
	versionResult, err := environment.Commands.Run(ctx, versionSpec)
	if err != nil {
		return patchError("dns_patch_evidence_failed", err, evidence)
	}
	evidence = append(evidence, summarizedCommandEvidence(versionSpec, versionResult, 20))
	if versionResult.ExitCode != 0 || versionResult.Truncated {
		return patchError(
			"dns_patch_evidence_failed",
			fmt.Errorf("named exit=%d truncated=%t", versionResult.ExitCode, versionResult.Truncated),
			evidence,
		)
	}

	packages, packageEvidence, err := support.InspectDPKGInventory(ctx, environment)
	evidence = append(evidence, packageEvidence)
	if err != nil {
		return patchError("dns_patch_evidence_failed", err, evidence)
	}
	bindPackages := make([]support.DPKGPackage, 0, 1)
	for _, item := range packages {
		name := item.Name
		if index := strings.LastIndexByte(name, ':'); index > 0 {
			name = name[:index]
		}
		if name == "bind9" {
			bindPackages = append(bindPackages, item)
		}
	}
	if len(bindPackages) != 1 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 named 프로세스를 단일 배포판 BIND 패키지와 연결할 수 없습니다.",
			Expected:      "배포판 BIND 패키지의 설치 버전과 실행 중인 named를 연결할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("설치된 bind9 패키지 레코드 %d개", len(bindPackages)),
			Evidence:      evidence,
		}
	}
	evidence = append(evidence, support.FactEvidence("BIND DPKG package", map[string]any{
		"name": bindPackages[0].Name, "version": bindPackages[0].Version,
		"architecture": bindPackages[0].Architecture,
	}))

	aptSpec := aptUpgradeSimulationSpec()
	aptResult, err := environment.Commands.Run(ctx, aptSpec)
	if err != nil {
		return patchError("dns_patch_evidence_failed", err, evidence)
	}
	evidence = append(evidence, summarizedCommandEvidence(aptSpec, aptResult, 100))
	if aptResult.ExitCode != 0 || aptResult.Truncated {
		return patchError(
			"dns_patch_evidence_failed",
			fmt.Errorf("apt-get exit=%d truncated=%t", aptResult.ExitCode, aptResult.Truncated),
			evidence,
		)
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "활성 BIND의 실행 버전, DPKG 패키지와 APT 업그레이드 계획을 수집했으며 최신 보안 패치 여부는 수동 확인이 필요합니다.",
		Expected:      "신뢰 가능한 최신 배포판 보안 메타데이터와 기관 패치 절차를 기준으로 BIND 보안 권고가 모두 반영되어야 합니다.",
		Observed: fmt.Sprintf(
			"bind9=%s; 캐시 기반 전체 업그레이드 후보 %d개; APT 목록 최신성과 배포판 백포트 반영 여부는 자동 확정하지 않습니다.",
			bindPackages[0].Version,
			countAPTActionLines(aptResult.Stdout, "Inst "),
		),
		Evidence: evidence,
	}
}
