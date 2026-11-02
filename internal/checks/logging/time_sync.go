package logging

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
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
			Summary:       "시각 동기화 서비스의 현재 상태와 부팅 시 활성 상태를 함께 확인할 수 없습니다.",
			Expected:      "systemd 환경에서 chronyd 상태를 확인할 수 있어야 합니다.",
			Observed:      environment.Platform.InitSystem,
		}
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"chronyd.service", "ntp.service", "systemd-timesyncd.service"})
	if err != nil {
		return logError("time_sync_service_failed", err, unitEvidence...)
	}
	evidence := append([]model.Evidence(nil), unitEvidence...)
	if len(units) != 3 {
		return logError("time_sync_service_failed", fmt.Errorf("time synchronization unit inventory is incomplete"), evidence...)
	}
	active := make([]int, 0, 3)
	for index, unit := range units {
		if support.UnitInstalled(unit) && support.UnitActive(unit) {
			active = append(active, index)
		}
	}
	if len(active) > 1 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "둘 이상의 시각 동기화 서비스가 동시에 실행 중입니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("활성 시각 동기화 서비스 %d개", len(active)),
			Evidence:      evidence,
		}
	}
	if len(active) == 1 && active[0] == 1 {
		return evaluateNTPD(ctx, rule, environment, evidence)
	}
	if len(active) == 1 && active[0] == 2 {
		return evaluator.Outcome{
			Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:  "가이드의 Linux 점검 사례에 없는 systemd-timesyncd가 사용 중입니다.",
			Expected: rule.Criteria.Pass, Observed: "systemd-timesyncd.service=active", Evidence: evidence,
		}
	}
	if len(active) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "시각 동기화 서비스가 활성화되어 있지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: "chronyd.service 및 ntp.service 비활성",
			Evidence: evidence,
		}
	}

	configuredSources, hasDynamicIncludes, configEvidence, err := readChronySources(ctx, environment)
	if err != nil {
		return logError("chrony_config_failed", err, evidence...)
	}
	evidence = append(evidence, configEvidence)
	if len(configuredSources) == 0 && !hasDynamicIncludes {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "chrony 설정에 시간원이 지정되어 있지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: "server/pool 없음",
			Evidence: evidence,
		}
	}

	sourcesSpec := executor.Spec{Name: "chronyc", Arguments: []string{"-N", "-c", "sources"}, Timeout: 10 * time.Second, MaxOutput: 1 << 20}
	runtimeResult, err := environment.Commands.Run(ctx, sourcesSpec)
	if err != nil {
		return logError("chronyc_sources_failed", err, evidence...)
	}
	evidence = append(evidence, support.CommandEvidence(sourcesSpec, runtimeResult))
	if runtimeResult.ExitCode != 0 || runtimeResult.Truncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "현재 chronyd 시간원 목록을 확인하지 못했습니다.",
			Expected:      "chronyc가 원래 이름을 보존한 전체 runtime source 목록을 반환해야 합니다.",
			Observed:      fmt.Sprintf("exit=%d truncated=%t", runtimeResult.ExitCode, runtimeResult.Truncated),
			Evidence:      evidence,
		}
	}
	runtimeSources, selectedSources, err := parseChronySourcesCSV(runtimeResult.Stdout)
	if err != nil {
		return logError("chronyc_sources_parse_failed", err, evidence...)
	}
	evidence = append(evidence, support.FactEvidence("chronyc runtime sources", map[string]any{
		"runtime_source_count": len(runtimeSources), "selected_source_count": len(selectedSources), "source_names": runtimeSources,
	}))
	if len(runtimeSources) == 0 || len(selectedSources) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "동기화된 Chrony 서버가 없습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("runtime=%d selected=%d", len(runtimeSources), len(selectedSources)),
			Evidence: evidence,
		}
	}
	if len(selectedSources) > 1 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownAmbiguousResult, Summary: "동기화된 Chrony 서버 상태를 해석할 수 없습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("selected=%d", len(selectedSources)), Evidence: evidence}
	}

	observed := fmt.Sprintf("configured=%s; runtime=%s; selected=%s", strings.Join(configuredSources, ", "), strings.Join(runtimeSources, ", "), strings.Join(selectedSources, ", "))
	if hasDynamicIncludes {
		observed += "; 동적 include 사용"
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "NTP 및 시각 동기화 설정이 적용되어 있습니다.",
		Expected: rule.Criteria.Pass,
		Observed: observed,
		Evidence: evidence,
	}
}

func evaluateNTPD(
	ctx context.Context,
	rule model.ResolvedRule,
	environment evaluator.Environment,
	evidence []model.Evidence,
) evaluator.Outcome {
	data, metadata, err := environment.Files.ReadFile(ctx, "/etc/ntp.conf", 1<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return evaluator.Outcome{Status: model.StatusFail, Summary: "/etc/ntp.conf에 NTP 서버가 설정되어 있지 않습니다.", Expected: rule.Criteria.Pass, Observed: "/etc/ntp.conf 없음", Evidence: evidence}
		}
		return logError("ntp_config_failed", err, evidence...)
	}
	evidence = append(evidence, support.FileMetadataEvidence(metadata))
	configured := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "server" {
			configured = append(configured, fields[1])
		}
	}
	sort.Strings(configured)
	configured = uniqueStrings(configured)
	evidence = append(evidence, support.FactEvidence("/etc/ntp.conf", map[string]any{"configured_servers": configured}))
	if len(configured) == 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "/etc/ntp.conf에 NTP 서버가 설정되어 있지 않습니다.", Expected: rule.Criteria.Pass, Observed: "server 설정 없음", Evidence: evidence}
	}
	spec := executor.Spec{Name: "ntpq", Arguments: []string{"-pn"}, Timeout: 10 * time.Second, MaxOutput: 1 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return logError("ntpq_failed", err, evidence...)
	}
	evidence = append(evidence, support.CommandEvidence(spec, result))
	if result.ExitCode != 0 || result.Truncated {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownInsufficientEvidence, Summary: "동기화된 NTP 서버를 확인하지 못했습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("ntpq exit=%d truncated=%t", result.ExitCode, result.Truncated), Evidence: evidence}
	}
	selected := make([]string, 0, 1)
	for _, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "*") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "*"))
		if len(fields) > 0 {
			selected = append(selected, fields[0])
		}
	}
	if len(selected) == 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "동기화된 NTP 서버가 없습니다.", Expected: rule.Criteria.Pass, Observed: "ntpq -pn에서 선택된 서버 없음", Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "NTP 서비스가 활성화되어 있고 서버와 동기화되어 있습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("configured=%s; selected=%s", strings.Join(configured, ", "), strings.Join(selected, ", ")), Evidence: evidence}
}

func evaluateSystemdTimesyncd(
	ctx context.Context,
	rule model.ResolvedRule,
	environment evaluator.Environment,
	unit support.UnitState,
	evidence []model.Evidence,
) evaluator.Outcome {
	if !support.UnitActive(unit) {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "시각 동기화 서비스가 활성화되어 있지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("active=%s unit_file=%s", unit.ActiveState, unit.UnitFileState),
			Evidence: evidence,
		}
	}

	statusSpec := executor.Spec{Name: "timedatectl", Arguments: []string{"status"}, Timeout: 10 * time.Second}
	statusResult, err := environment.Commands.Run(ctx, statusSpec)
	if err != nil {
		return logError("timedatectl_status_failed", err, evidence...)
	}
	evidence = append(evidence, support.CommandEvidence(statusSpec, statusResult))
	if statusResult.ExitCode != 0 || statusResult.Truncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "현재 시스템 시계의 동기화 상태를 확인하지 못했습니다.",
			Expected:      "systemd가 시스템 시계 동기화 완료 상태를 보고해야 합니다.",
			Observed:      fmt.Sprintf("exit=%d truncated=%t", statusResult.ExitCode, statusResult.Truncated),
			Evidence:      evidence,
		}
	}
	statusValues, err := parseTimedatectlStatus(statusResult.Stdout)
	if err != nil {
		return logError("timedatectl_status_parse_failed", err, evidence...)
	}
	synchronized := strings.ToLower(statusValues["system clock synchronized"])
	if synchronized == "" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "현재 시스템 시계의 동기화 완료 여부를 확인하지 못했습니다.",
			Expected:      "timedatectl이 시스템 시계 동기화 여부를 보고해야 합니다.",
			Observed:      "System clock synchronized 항목 없음",
			Evidence:      evidence,
		}
	}
	if synchronized != "yes" {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "systemd-timesyncd가 실행 중이지만 현재 동기화 완료 상태가 아닙니다.",
			Expected: rule.Criteria.Pass,
			Observed: "System clock synchronized=" + synchronized,
			Evidence: evidence,
		}
	}

	showSpec := executor.Spec{Name: "timedatectl", Arguments: []string{"show-timesync", "--all"}, Timeout: 10 * time.Second}
	showResult, err := environment.Commands.Run(ctx, showSpec)
	if err != nil {
		return logError("timedatectl_timesync_failed", err, evidence...)
	}
	evidence = append(evidence, support.CommandEvidence(showSpec, showResult))
	sourcesSupported := showResult.ExitCode == 0 && !showResult.Truncated
	configuredSources := make([]string, 0)
	runtimeSource := ""
	if sourcesSupported {
		properties, parseErr := support.ParseKeyValueOutput(string(showResult.Stdout))
		if parseErr != nil {
			return logError("timedatectl_timesync_parse_failed", parseErr, evidence...)
		}
		activeTierSources := make([]string, 0)
		for _, key := range []string{"LinkNTPServers", "SystemNTPServers", "RuntimeNTPServers"} {
			activeTierSources = append(activeTierSources, strings.Fields(properties[key])...)
		}
		sort.Strings(activeTierSources)
		activeTierSources = uniqueStrings(activeTierSources)
		fallbackSources := strings.Fields(properties["FallbackNTPServers"])
		sort.Strings(fallbackSources)
		fallbackSources = uniqueStrings(fallbackSources)
		sourceTier := "active"
		configuredSources = append(configuredSources, activeTierSources...)
		if len(activeTierSources) == 0 {
			sourceTier = "fallback"
			configuredSources = append(configuredSources, fallbackSources...)
		}
		runtimeSource = strings.TrimSpace(properties["ServerName"])
		if runtimeSource != "" {
			configuredSources = append(configuredSources, runtimeSource)
		}
		sort.Strings(configuredSources)
		configuredSources = uniqueStrings(configuredSources)
		evidence = append(evidence, support.FactEvidence("systemd-timesyncd sources", map[string]any{
			"active_tier_sources":  activeTierSources,
			"fallback_sources":     fallbackSources,
			"approval_source_tier": sourceTier,
			"configured_sources":   configuredSources,
			"runtime_source":       runtimeSource,
		}))
	} else if showResult.Truncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "systemd-timesyncd 시간원 정보를 완전히 수집하지 못했습니다.",
			Expected:      "실효 시간원 목록과 현재 사용 중인 시간원을 확인할 수 있어야 합니다.",
			Observed:      "timedatectl show-timesync output truncated",
			Evidence:      evidence,
		}
	} else if !timedatectlTimesyncUnsupported(showResult) {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "systemd-timesyncd 시간원 정보를 확인하지 못했습니다.",
			Expected:      "실효 시간원 목록과 현재 사용 중인 시간원을 확인할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("timedatectl show-timesync exit=%d", showResult.ExitCode),
			Evidence:      evidence,
		}
	}

	observed := "System clock synchronized=yes"
	if runtimeSource != "" {
		observed += "; runtime source=" + runtimeSource
	}
	if !sourcesSupported || runtimeSource == "" || len(configuredSources) == 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "현재 동기화는 정상이나 동기화된 시간원을 확인하지 못했습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      observed,
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "NTP 및 시각 동기화 설정이 적용되어 있습니다.",
		Expected: rule.Criteria.Pass,
		Observed: observed,
		Evidence: evidence,
	}
}

func parseTimedatectlStatus(data []byte) (map[string]string, error) {
	const synchronizedKey = "system clock synchronized"

	values := make(map[string]string)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		key = strings.ToLower(strings.TrimSpace(key))
		if !found || key != synchronizedKey {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("timedatectl status line %d repeats %s", lineNumber+1, key)
		}
		values[key] = strings.TrimSpace(value)
	}
	return values, nil
}

func timedatectlTimesyncUnsupported(result executor.Result) bool {
	if result.ExitCode == 0 {
		return false
	}
	message := strings.ToLower(string(result.Stderr) + "\n" + string(result.Stdout))
	return strings.Contains(message, "unknown operation") ||
		strings.Contains(message, "unrecognized option") ||
		strings.Contains(message, "unknown command")
}

func parseChronySourcesCSV(data []byte) ([]string, []string, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	sources := make([]string, 0)
	selected := make([]string, 0, 1)
	for line := 1; ; line++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("chronyc sources CSV line %d: %w", line, err)
		}
		if len(record) < 3 {
			return nil, nil, fmt.Errorf("chronyc sources CSV line %d has too few fields", line)
		}
		mode := strings.TrimSpace(record[0])
		state := strings.TrimSpace(record[1])
		source := strings.TrimSpace(record[2])
		if (mode != "^" && mode != "=" && mode != "#") || len(state) != 1 || !strings.Contains("*+-?x~", state) || source == "" || strings.ContainsAny(source, "\r\n\x00") {
			return nil, nil, fmt.Errorf("chronyc sources CSV line %d has invalid source fields", line)
		}
		sources = append(sources, source)
		if state == "*" {
			selected = append(selected, source)
		}
		if len(sources) > 1024 {
			return nil, nil, fmt.Errorf("chronyc sources output exceeds 1024 entries")
		}
	}
	sort.Strings(sources)
	sort.Strings(selected)
	return uniqueStrings(sources), uniqueStrings(selected), nil
}

func readChronySources(ctx context.Context, environment evaluator.Environment) ([]string, bool, model.Evidence, error) {
	configPath := chronyConfigurationPath(environment.Platform)
	data, _, err := environment.Files.ReadFile(ctx, configPath, 2<<20)
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
		case "include":
			dynamic = true
			facts = append(facts, map[string]any{"line": index + 1, "directive": directive, "path": fields[1], "resolved": false})
		case "confdir", "sourcedir":
			suffix := ".conf"
			if directive == "sourcedir" {
				suffix = ".sources"
			}
			for _, directory := range fields[1:] {
				count, unresolved, inspectErr := inspectChronyIncludeDirectory(environment, directory, suffix)
				if inspectErr != nil {
					return nil, false, model.Evidence{}, inspectErr
				}
				dynamic = dynamic || unresolved
				facts = append(facts, map[string]any{
					"line": index + 1, "directive": directive, "path": directory,
					"matching_files": count, "resolved_empty": !unresolved,
				})
			}
		}
	}
	sort.Strings(sources)
	return uniqueStrings(sources), dynamic, support.FactEvidence(configPath, map[string]any{
		"directives":       facts,
		"dynamic_includes": dynamic,
	}), nil
}

func chronyConfigurationPath(platform model.PlatformInfo) string {
	if platform.Family == "debian" {
		return "/etc/chrony/chrony.conf"
	}
	return "/etc/chrony.conf"
}

func inspectChronyIncludeDirectory(environment evaluator.Environment, directory, suffix string) (int, bool, error) {
	if !path.IsAbs(directory) || path.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n") {
		return 0, true, nil
	}
	entries, err := environment.Files.ReadDir(directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, true, fmt.Errorf("inspect chrony include directory %s: %w", directory, err)
	}
	count := 0
	for _, entry := range entries {
		if entry.Type().IsRegular() && path.Base(entry.Name()) == entry.Name() && strings.HasSuffix(entry.Name(), suffix) {
			count++
		}
	}
	return count, count > 0, nil
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

func chronyDynamicIncludeObservation(configuredSources, runtimeSources, selectedSources []string) string {
	return strings.Join([]string{
		"동적 include: 있음",
		"정적으로 확인한 시간원: " + chronySourceList(configuredSources),
		"runtime 시간원: " + chronySourceList(runtimeSources),
		"선택 시간원: " + chronySourceList(selectedSources),
	}, "\n")
}

func chronySourceList(sources []string) string {
	if len(sources) == 0 {
		return "없음"
	}
	return strings.Join(sources, ", ")
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

func logError(code string, err error, evidence ...model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "시각 동기화 설정을 수집하거나 해석하지 못했습니다.",
		Evidence:     append([]model.Evidence(nil), evidence...),
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
