package patchcheck

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorPatchPolicy = "unix.patch.policy_and_currency"

func Implementations() map[string]evaluator.Func {
	return map[string]evaluator.Func{
		EvaluatorPatchPolicy:   evaluatePatchPolicy,
		EvaluatorDNSPatchLevel: evaluateDNSPatchLevel,
	}
}

func evaluatePatchPolicy(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	evidence := []model.Evidence{support.FactEvidence("platform", map[string]any{
		"id": environment.Platform.ID, "version_id": environment.Platform.VersionID,
		"kernel_release": environment.Platform.KernelRelease, "package_manager": environment.Platform.PackageManager,
	})}
	if environment.Platform.Family == "debian" {
		return evaluateAPTPatchPolicy(ctx, environment, evidence)
	}
	if environment.Platform.Family != "rhel" || !environment.Commands.Available("rpm") || !environment.Commands.Available("dnf") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "설치 패키지와 사용 가능한 보안 업데이트를 RPM/DNF로 확인할 수 없습니다.",
			Expected:      "RPM과 오프라인 DNF metadata를 기관 패치 정책 및 벤더 권고와 대조해야 합니다.",
			Observed:      fmt.Sprintf("family=%s rpm=%t dnf=%t", environment.Platform.Family, environment.Commands.Available("rpm"), environment.Commands.Available("dnf")),
			Evidence:      evidence,
		}
	}

	specs := []executor.Spec{
		{
			Name: "rpm", Arguments: []string{"-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"},
			Timeout: 2 * time.Minute, MaxOutput: 8 << 20,
		},
		{
			Name: "dnf", Arguments: []string{"--cacheonly", "--setopt=metadata_expire=never", "-q", "repolist", "--enabled"},
			Timeout: 1 * time.Minute, MaxOutput: 4 << 20,
		},
		{
			Name: "dnf", Arguments: []string{"--cacheonly", "--setopt=metadata_expire=never", "-q", "updateinfo", "list", "--security"},
			Timeout: 2 * time.Minute, MaxOutput: 8 << 20,
		},
		{
			Name: "dnf", Arguments: []string{"--cacheonly", "-q", "history", "list", "--reverse"},
			Timeout: 1 * time.Minute, MaxOutput: 4 << 20,
		},
	}
	observed := make([]string, 0, len(specs))
	for _, spec := range specs {
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return patchError("patch_evidence_command_failed", err, evidence)
		}
		if result.ExitCode != 0 || result.Truncated {
			evidence = append(evidence, summarizedCommandEvidence(spec, result, 40))
			if spec.Name == "dnf" && support.DNFCacheUnavailable(result) {
				return patchCacheUnavailable(evidence)
			}
			return patchError("patch_evidence_command_failed", fmt.Errorf("%s exit=%d truncated=%t", spec.Name, result.ExitCode, result.Truncated), evidence)
		}
		evidence = append(evidence, summarizedCommandEvidence(spec, result, 100))
		observed = append(observed, fmt.Sprintf("%s %s: %d개 비어 있지 않은 출력 행", spec.Name, strings.Join(spec.Arguments[3:min(len(spec.Arguments), 6)], " "), nonEmptyLineCount(result.Stdout)))
	}

	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "로컬 패키지와 캐시된 보안 권고 증적을 수집했으며 패치 정책의 적정성은 수동 확인이 필요합니다.",
		Expected:      "승인된 패치 주기와 신뢰 가능한 최신 배포판 보안 메타데이터를 기준으로 모든 보안 권고 반영 여부를 확인해야 합니다.",
		Observed:      strings.Join(observed, "; ") + "; 캐시 최신성과 기관 정책 attestation이 없어 자동 확정하지 않습니다.",
		Evidence:      evidence,
	}
}

func evaluateAPTPatchPolicy(
	ctx context.Context,
	environment evaluator.Environment,
	evidence []model.Evidence,
) evaluator.Outcome {
	if !environment.Commands.Available("dpkg-query") || !environment.Commands.Available("apt-get") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "설치 패키지와 캐시된 업그레이드 후보를 DPKG/APT로 확인할 수 없습니다.",
			Expected:      "DPKG 설치 목록과 APT 캐시를 기관 패치 정책 및 벤더 권고와 대조해야 합니다.",
			Observed: fmt.Sprintf(
				"family=%s dpkg-query=%t apt-get=%t",
				environment.Platform.Family,
				environment.Commands.Available("dpkg-query"),
				environment.Commands.Available("apt-get"),
			),
			Evidence: evidence,
		}
	}

	packages, packageEvidence, err := support.InspectDPKGInventory(ctx, environment)
	evidence = append(evidence, packageEvidence)
	if err != nil {
		return patchError("patch_dpkg_inventory_failed", err, evidence)
	}
	sample := make([]string, 0, min(len(packages), 100))
	for _, item := range packages[:min(len(packages), 100)] {
		sample = append(sample, item.Name+"\t"+item.Version+"\t"+item.Architecture)
	}
	evidence = append(evidence, support.FactEvidence("dpkg-package-inventory-sample", map[string]any{
		"installed_package_count": len(packages),
		"sample":                  sample,
		"sample_truncated":        len(packages) > len(sample),
	}))

	spec := aptUpgradeSimulationSpec()
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return patchError("patch_apt_simulation_failed", err, evidence)
	}
	evidence = append(evidence, summarizedCommandEvidence(spec, result, 100))
	if result.ExitCode != 0 || result.Truncated {
		return patchError(
			"patch_apt_simulation_failed",
			fmt.Errorf("apt-get exit=%d truncated=%t", result.ExitCode, result.Truncated),
			evidence,
		)
	}
	upgradeCandidates := countAPTActionLines(result.Stdout, "Inst ")
	removalCandidates := countAPTActionLines(result.Stdout, "Remv ")
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "DPKG 설치 목록과 APT의 읽기 전용 업그레이드 계획을 수집했으며 패치 정책의 적정성은 수동 확인이 필요합니다.",
		Expected:      "승인된 패치 주기와 신뢰 가능한 최신 Debian 계열 보안 메타데이터를 기준으로 모든 보안 권고 반영 여부를 확인해야 합니다.",
		Observed: fmt.Sprintf(
			"설치 패키지 %d개; 캐시 기반 업그레이드 후보 %d개; 제거 후보 %d개; APT 목록 최신성과 기관의 실제 패치 이행 여부는 자동 확정하지 않습니다.",
			len(packages),
			upgradeCandidates,
			removalCandidates,
		),
		Evidence: evidence,
	}
}

func aptUpgradeSimulationSpec() executor.Spec {
	return executor.Spec{
		Name: "apt-get",
		Arguments: []string{
			"--simulate",
			"--quiet=2",
			"-o", "Debug::NoLocking=1",
			"-o", "APT::Get::List-Cleanup=0",
			"upgrade",
		},
		Timeout:   2 * time.Minute,
		MaxOutput: 8 << 20,
	}
}

func countAPTActionLines(output []byte, prefix string) int {
	count := 0
	for _, raw := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(raw, prefix) {
			count++
		}
	}
	return count
}

func patchCacheUnavailable(evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownInsufficientEvidence,
		Summary:       "캐시된 저장소 메타데이터가 없어 보안 패치 상태를 확인할 수 없습니다.",
		Expected:      "신뢰 가능한 최신 벤더 저장소 메타데이터와 기관 패치 정책을 기준으로 보안 권고 반영 여부를 확인해야 합니다.",
		Observed:      "오프라인 DNF 캐시에 필요한 저장소 메타데이터가 없습니다.",
		Evidence:      evidence,
	}
}

func summarizedCommandEvidence(spec executor.Spec, result executor.Result, sampleLimit int) model.Evidence {
	lines := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			line = "[UTF-8이 아닌 출력 행]"
		}
		if len(line) > 512 {
			line = line[:512] + "…"
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	sample := lines
	if len(sample) > sampleLimit {
		sample = sample[:sampleLimit]
	}
	stdoutDigest := sha256.Sum256(result.Stdout)
	stderrDigest := sha256.Sum256(result.Stderr)
	return support.FactEvidence(spec.Name, map[string]any{
		"executable": result.Executable, "arguments": spec.EvidenceArguments(), "exit_code": result.ExitCode,
		"duration_ms": result.Duration.Milliseconds(), "stdout_sha256": fmt.Sprintf("%x", stdoutDigest),
		"stderr_sha256": fmt.Sprintf("%x", stderrDigest), "line_count": len(lines), "sample": append([]string(nil), sample...),
		"sample_truncated": len(lines) > len(sample),
	})
}

func nonEmptyLineCount(data []byte) int {
	count := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func patchError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "패치 관리 증적을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
		Evidence:     evidence,
	}
}
