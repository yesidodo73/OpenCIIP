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
	if environment.Platform.Family != "rhel" || !environment.Commands.Available("rpm") || !environment.Commands.Available("dnf") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "지원되는 Rocky/RHEL 패키지 관리 증적을 수집할 수 없습니다.",
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
			return patchError("patch_evidence_command_failed", fmt.Errorf("%s exit=%d truncated=%t", spec.Name, result.ExitCode, result.Truncated), evidence)
		}
		evidence = append(evidence, summarizedCommandEvidence(spec, result, 100))
		observed = append(observed, fmt.Sprintf("%s %s: %d개 비어 있지 않은 출력 행", spec.Name, strings.Join(spec.Arguments[3:min(len(spec.Arguments), 6)], " "), nonEmptyLineCount(result.Stdout)))
	}

	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "로컬 패키지와 캐시된 보안 권고 증적을 수집했으며 패치 정책의 적정성은 수동 확인이 필요합니다.",
		Expected:      "승인된 패치 주기와 신뢰 가능한 최신 Rocky 벤더 metadata를 기준으로 모든 보안 권고 반영 여부를 확인해야 합니다.",
		Observed:      strings.Join(observed, "; ") + "; 캐시 최신성과 기관 정책 attestation이 없어 자동 확정하지 않습니다.",
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
