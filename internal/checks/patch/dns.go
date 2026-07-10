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
			Summary:       "DNS 서비스 대상을 지원하는 방식으로 확인할 수 없습니다.",
			Expected:      "systemd 기반 Rocky Linux 9.8의 활성 BIND와 vendor 보안 권고를 확인해야 합니다.",
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
	if !unitActive && !listenerActive && !processActive {
		observed := "BIND unit, named 프로세스 및 53번 포트 리스너가 없습니다."
		if unitInstalled {
			observed = "BIND unit은 설치되어 있으나 비활성이고 named 프로세스 및 리스너가 없습니다."
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
			Summary:       "활성 DNS 리스너와 지원되는 표준 BIND 실행 구성을 연결할 수 없습니다.",
			Expected:      "표준 Rocky BIND unit과 실행 파일의 RPM 및 vendor 권고를 확인할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("unit_active=%t process_active=%t listener_active=%t custom_unit=%t", unitActive, processActive, listenerActive, customUnit),
			Evidence:      evidence,
		}
	}
	if !environment.Commands.Available("named") || !environment.Commands.Available("rpm") || !environment.Commands.Available("dnf") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "BIND 버전과 vendor 보안 권고를 수집할 도구가 없습니다.",
			Expected:      "named, rpm, dnf를 사용해 로컬 버전과 최신 Rocky 보안 metadata를 대조해야 합니다.",
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
			return patchError("dns_patch_evidence_failed", fmt.Errorf("%s exit=%d truncated=%t", spec.Name, result.ExitCode, result.Truncated), evidence)
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "활성 BIND의 로컬 버전과 캐시된 보안 권고를 수집했으며 최신 패치 여부는 수동 확인이 필요합니다.",
		Expected:      "신뢰 가능한 최신 Rocky 9.8 저장소 metadata와 기관 패치 절차를 기준으로 BIND 보안 권고가 모두 반영되어야 합니다.",
		Observed:      "upstream 버전 문자열은 backport 여부를 나타내지 않으므로 자동 비교하지 않았습니다.",
		Evidence:      evidence,
	}
}
