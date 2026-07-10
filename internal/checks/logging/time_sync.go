package logging

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorTimeSync = "unix.log.time_sync"

func Implementations() map[string]evaluator.Func {
	return map[string]evaluator.Func{
		EvaluatorTimeSync:           evaluateTimeSync,
		EvaluatorLogPolicy:          evaluateLogPolicy,
		EvaluatorLogFilePermissions: evaluateLogFilePermissions,
	}
}

func evaluateTimeSync(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "지원되는 방식으로 시각 동기화 서비스 상태를 확인할 수 없습니다.",
			Expected:      "Rocky Linux 9.8 systemd 환경에서 chronyd를 사용해야 합니다.",
			Observed:      environment.Platform.InitSystem,
		}
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"chronyd.service"})
	if err != nil {
		return logError("chronyd_service_failed", err)
	}
	evidence := append([]model.Evidence(nil), unitEvidence...)
	if len(units) != 1 || !support.UnitInstalled(units[0]) {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "시각 동기화 서비스가 설치되어 있지 않습니다.",
			Expected: "chronyd가 설치되어 활성화되고 승인된 시간원과 동기화되어야 합니다.",
			Observed: "chronyd.service not found",
			Evidence: evidence,
		}
	}
	if !support.UnitActive(units[0]) || !support.UnitEnabled(units[0]) {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "시각 동기화 서비스가 활성화되어 있지 않습니다.",
			Expected: "chronyd가 실행 중이며 부팅 시 활성화되어야 합니다.",
			Observed: fmt.Sprintf("active=%s unit_file=%s", units[0].ActiveState, units[0].UnitFileState),
			Evidence: evidence,
		}
	}

	configuredSources, hasDynamicIncludes, configEvidence, err := readChronySources(ctx, environment)
	if err != nil {
		return logError("chrony_config_failed", err)
	}
	evidence = append(evidence, configEvidence)
	if len(configuredSources) == 0 && !hasDynamicIncludes {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "chrony 설정에 시간원이 지정되어 있지 않습니다.",
			Expected: "하나 이상의 승인된 server 또는 pool 시간원이 설정되어야 합니다.",
			Observed: "server/pool 없음",
			Evidence: evidence,
		}
	}

	trackingSpec := executor.Spec{Name: "chronyc", Arguments: []string{"tracking"}, Timeout: 10 * time.Second}
	tracking, err := environment.Commands.Run(ctx, trackingSpec)
	if err != nil {
		return logError("chronyc_tracking_failed", err)
	}
	evidence = append(evidence, support.CommandEvidence(trackingSpec, tracking))
	if tracking.ExitCode != 0 || tracking.Truncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "현재 시각 동기화 상태를 확인하지 못했습니다.",
			Expected:      "chronyc tracking이 정상 상태를 반환해야 합니다.",
			Observed:      fmt.Sprintf("exit=%d truncated=%t", tracking.ExitCode, tracking.Truncated),
			Evidence:      evidence,
		}
	}
	leapStatus := trackingValue(string(tracking.Stdout), "Leap status")
	if !strings.EqualFold(leapStatus, "Normal") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "chronyd가 실행 중이지만 정상 동기화 상태를 확인하지 못했습니다.",
			Expected:      "Leap status가 Normal이어야 합니다.",
			Observed:      firstNonEmpty(leapStatus, "Leap status 없음"),
			Evidence:      evidence,
		}
	}

	approved, hasApproved, err := support.StringSliceParameter(rule.Parameters, "approved_sources")
	if err != nil {
		return logError("invalid_rule_parameter", err)
	}
	if hasDynamicIncludes {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "동적으로 포함되는 chrony 설정을 모두 해석하지 못했습니다.",
			Expected:      "모든 실효 시간원과 include 경로를 확인할 수 있어야 합니다.",
			Observed:      strings.Join(configuredSources, ", "),
			Evidence:      evidence,
		}
	}
	if !hasApproved || len(approved) == 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "현재 동기화는 정상이나 승인된 시간원 목록이 없어 정책 적합성을 확정할 수 없습니다.",
			Expected:      "구성된 모든 시간원이 기관의 승인 목록에 포함되어야 합니다.",
			Observed:      strings.Join(configuredSources, ", "),
			Evidence:      evidence,
		}
	}
	unapproved := differenceFold(configuredSources, approved)
	if len(unapproved) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "승인 목록에 없는 시간원이 구성되어 있습니다.",
			Expected: "구성된 모든 시간원이 기관의 승인 목록에 포함되어야 합니다.",
			Observed: strings.Join(unapproved, ", "),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "시각 동기화 서비스와 시간원이 정책 기준을 충족합니다.",
		Expected: "chronyd가 활성화되고 승인된 시간원과 정상 동기화되어야 합니다.",
		Observed: strings.Join(configuredSources, ", "),
		Evidence: evidence,
	}
}

func readChronySources(ctx context.Context, environment evaluator.Environment) ([]string, bool, model.Evidence, error) {
	data, _, err := environment.Files.ReadFile(ctx, "/etc/chrony.conf", 2<<20)
	if err != nil {
		return nil, false, model.Evidence{}, err
	}
	sources := make([]string, 0)
	dynamic := false
	facts := make([]map[string]any, 0)
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		switch directive {
		case "server", "pool", "peer":
			sources = append(sources, fields[1])
			facts = append(facts, map[string]any{"line": index + 1, "directive": directive, "source": fields[1]})
		case "include", "confdir", "sourcedir":
			dynamic = true
			facts = append(facts, map[string]any{"line": index + 1, "directive": directive, "path": fields[1]})
		}
	}
	sort.Strings(sources)
	return uniqueStrings(sources), dynamic, support.FactEvidence("/etc/chrony.conf", map[string]any{
		"directives":       facts,
		"dynamic_includes": dynamic,
	}), nil
}

func trackingValue(output, key string) string {
	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		left, right, found := strings.Cut(raw, ":")
		if found && strings.EqualFold(strings.TrimSpace(left), key) {
			return strings.TrimSpace(right)
		}
	}
	return ""
}

func differenceFold(values, allowed []string) []string {
	result := make([]string, 0)
	for _, value := range values {
		found := false
		for _, candidate := range allowed {
			if strings.EqualFold(value, candidate) {
				found = true
				break
			}
		}
		if !found {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "unknown"
}

func logError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "시각 동기화 설정을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
