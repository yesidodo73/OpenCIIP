package logging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const EvaluatorLogPolicy = "unix.log.policy"

var (
	rsyslogIncludeFilePattern  = regexp.MustCompile(`(?i)\bfile\s*=\s*["']([^"']+)["']`)
	rsyslogOptionalModePattern = regexp.MustCompile(`(?i)\bmode\s*=\s*["']optional["']`)
	rsyslogLocalPathPattern    = regexp.MustCompile(`(/var/log/[A-Za-z0-9_./-]+)`)
)

type rsyslogInspection struct {
	complete          bool
	files             []string
	localDestinations map[string]struct{}
	actionCount       int
}

func evaluateLogPolicy(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	expected := strings.TrimSpace(rule.Criteria.Pass)
	if expected == "" {
		expected = "승인된 로그 정책과 실효 설정이 일치하고 실제 로그가 기록되어야 합니다."
	}
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "시스템 로깅 서비스의 현재 상태를 확인할 수 없습니다.",
			Expected:      expected,
			Observed:      environment.Platform.InitSystem,
		}
	}

	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"rsyslog.service", "systemd-journald.service"})
	if err != nil {
		return logPolicyError("logging_service_inspection_failed", err)
	}
	evidence := append([]model.Evidence(nil), unitEvidence...)
	states := make(map[string]support.UnitState, len(units))
	for _, unit := range units {
		states[unit.Name] = unit
	}
	rsyslogActive := support.UnitActive(states["rsyslog.service"])
	journalActive := support.UnitActive(states["systemd-journald.service"])
	if !rsyslogActive && !journalActive {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "활성화된 시스템 로깅 백엔드가 없습니다.",
			Expected: expected,
			Observed: "rsyslog.service와 systemd-journald.service가 모두 비활성 상태입니다.",
			Evidence: evidence,
		}
	}
	for _, unitName := range []string{"rsyslog.service", "systemd-journald.service"} {
		unit := states[unitName]
		if support.UnitActive(unit) && !standardLoggingUnit(unit) {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "로깅 서비스 unit의 사용자 지정 실행 구성을 완전히 해석할 수 없습니다.",
				Expected:      expected,
				Observed:      unitName + "에 비표준 fragment 또는 drop-in이 있습니다.",
				Evidence:      evidence,
			}
		}
	}

	journalSettings := map[string]string{"storage": "auto"}
	journalComplete := true
	if journalActive {
		journalSettings, journalComplete, err = inspectJournaldEffectiveConfig(ctx, environment, &evidence)
		if err != nil {
			outcome := logPolicyError("journald_config_inspection_failed", err)
			outcome.Evidence = evidence
			return outcome
		}
	}

	rsyslogState := rsyslogInspection{localDestinations: make(map[string]struct{})}
	if rsyslogActive {
		customConfig, configEvidence, configErr := inspectRsyslogStartupConfig(ctx, environment.Files)
		if configErr != nil {
			return logPolicyError("rsyslog_startup_config_failed", configErr)
		}
		if configEvidence != nil {
			evidence = append(evidence, *configEvidence)
		}
		if customConfig {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "rsyslog가 사용자 지정 기본 설정 파일로 실행되고 있습니다.",
				Expected:      expected,
				Observed:      "시작 옵션에 사용자 지정 설정 경로가 있습니다.",
				Evidence:      evidence,
			}
		}
		spec := executor.Spec{Name: "rsyslogd", Arguments: []string{"-N1"}, Timeout: 30 * time.Second, MaxOutput: 2 << 20}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return logPolicyError("rsyslog_validation_failed", runErr)
		}
		evidence = append(evidence, support.CommandEvidence(spec, result))
		if result.Truncated {
			return logPolicyError("rsyslog_validation_truncated", fmt.Errorf("rsyslogd validation output was truncated"))
		}
		if result.ExitCode != 0 {
			return evaluator.Outcome{
				Status:   model.StatusFail,
				Summary:  "rsyslog 실효 설정의 구문 검증이 실패했습니다.",
				Expected: expected,
				Observed: fmt.Sprintf("rsyslogd -N1 exit=%d", result.ExitCode),
				Evidence: evidence,
			}
		}

		rsyslogState, err = inspectRsyslogConfig(ctx, environment.Files)
		if err != nil {
			return logPolicyError("rsyslog_config_inspection_failed", err)
		}
		localDestinations := make([]string, 0, len(rsyslogState.localDestinations))
		for destination := range rsyslogState.localDestinations {
			localDestinations = append(localDestinations, destination)
		}
		sort.Strings(localDestinations)
		evidence = append(evidence, support.FactEvidence("/etc/rsyslog.conf", map[string]any{
			"files_inspected":    rsyslogState.files,
			"fully_interpreted":  rsyslogState.complete,
			"action_count":       rsyslogState.actionCount,
			"local_destinations": localDestinations,
		}))
	}

	logFacts, presentCount, err := inspectExpectedLogPaths(environment.Files)
	if err != nil {
		return logPolicyError("log_path_inspection_failed", err)
	}
	evidence = append(evidence, support.FactEvidence("/var/log", map[string]any{
		"paths":         logFacts,
		"present_count": presentCount,
	}))

	storage := strings.ToLower(strings.TrimSpace(journalSettings["storage"]))
	if journalActive && journalComplete && storage == "none" && !rsyslogActive {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "journald가 로그를 저장하지 않도록 설정되었고 대체 rsyslog 백엔드도 활성화되어 있지 않습니다.",
			Expected: expected,
			Observed: "Storage=none; rsyslog inactive",
			Evidence: evidence,
		}
	}
	if rsyslogActive && rsyslogState.complete && rsyslogState.actionCount == 0 && (!journalActive || (journalComplete && storage == "none")) {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "활성 로깅 백엔드에서 기록 또는 전달 동작을 찾지 못했습니다.",
			Expected: expected,
			Observed: "rsyslog action 없음; journald 영속 저장 없음",
			Evidence: evidence,
		}
	}

	observed := fmt.Sprintf(
		"rsyslog_active=%t; journald_active=%t; journald_storage=%s; rsyslog_config_complete=%t; observed_log_paths=%d",
		rsyslogActive,
		journalActive,
		firstNonEmpty(storage, "unknown"),
		rsyslogState.complete,
		presentCount,
	)
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "로깅 백엔드와 설정은 수집했으나 기관 정책 및 실제 기록 동작을 확인하지 못했습니다.",
		Expected:      expected,
		Observed:      observed,
		Evidence:      evidence,
	}
}

func standardLoggingUnit(unit support.UnitState) bool {
	if !vendorSystemdUnitPath(unit.FragmentPath) {
		return false
	}
	for _, dropInPath := range strings.Fields(unit.DropInPaths) {
		if !vendorSystemdUnitPath(dropInPath) {
			return false
		}
	}
	return true
}

func vendorSystemdUnitPath(rawPath string) bool {
	unitPath := strings.ReplaceAll(strings.TrimSpace(rawPath), "\\", "/")
	if unitPath == "" || !path.IsAbs(unitPath) || path.Clean(unitPath) != unitPath {
		return false
	}
	return strings.HasPrefix(unitPath, "/usr/lib/systemd/system/") ||
		strings.HasPrefix(unitPath, "/lib/systemd/system/")
}

func inspectRsyslogStartupConfig(ctx context.Context, files system.Reader) (bool, *model.Evidence, error) {
	const filePath = "/etc/sysconfig/rsyslog"
	exists, err := files.Exists(filePath)
	if err != nil {
		return false, nil, err
	}
	if !exists {
		return false, nil, nil
	}
	data, _, err := files.ReadFile(ctx, filePath, 256<<10)
	if err != nil {
		return false, nil, err
	}
	custom, err := rsyslogCustomConfigOption(string(data))
	if err != nil {
		return false, nil, err
	}
	evidence := support.FactEvidence(filePath, map[string]any{"custom_config_path": custom})
	return custom, &evidence, nil
}

func rsyslogCustomConfigOption(content string) (bool, error) {
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		tokens, err := configAssignmentTokens(raw)
		if err != nil {
			return false, fmt.Errorf("line %d has invalid quoting", lineNumber+1)
		}
		for index, token := range tokens {
			switch {
			case token == "RSYSLOG_CONFIG_FILE":
				if index+1 >= len(tokens) || tokens[index+1] != "/etc/rsyslog.conf" {
					return true, nil
				}
			case token == "-f":
				if index+1 >= len(tokens) || tokens[index+1] != "/etc/rsyslog.conf" {
					return true, nil
				}
			case strings.HasPrefix(token, "-f") && len(token) > 2:
				if strings.TrimPrefix(token, "-f") != "/etc/rsyslog.conf" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func configAssignmentTokens(line string) ([]string, error) {
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
		return nil, fmt.Errorf("unterminated quoted value")
	}
	flush()
	return result, nil
}

func inspectJournaldEffectiveConfig(
	ctx context.Context,
	environment evaluator.Environment,
	evidence *[]model.Evidence,
) (map[string]string, bool, error) {
	spec := executor.Spec{
		Name:      "systemd-analyze",
		Arguments: []string{"cat-config", "systemd/journald.conf"},
		Timeout:   15 * time.Second,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return nil, false, err
	}
	*evidence = append(*evidence, support.CommandEvidence(spec, result))
	if result.Truncated {
		return nil, false, fmt.Errorf("systemd-analyze cat-config exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	if result.ExitCode != 0 {
		if systemdAnalyzeCatConfigUnsupported(result) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("systemd-analyze cat-config exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	settings, complete := parseJournaldConfig(string(result.Stdout))
	if _, exists := settings["storage"]; !exists {
		settings["storage"] = "auto"
	}
	return settings, complete, nil
}

func systemdAnalyzeCatConfigUnsupported(result executor.Result) bool {
	diagnostic := strings.ToLower(strings.TrimSpace(string(result.Stderr)))
	return strings.Contains(diagnostic, "unknown operation cat-config") ||
		strings.Contains(diagnostic, "unknown operation 'cat-config'") ||
		strings.Contains(diagnostic, `unknown operation "cat-config"`)
}

func parseJournaldConfig(content string) (map[string]string, bool) {
	settings := make(map[string]string)
	section := ""
	complete := true
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Journal" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) == "" {
			complete = false
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			complete = false
			continue
		}
		if key == "storage" || key == "forwardtosyslog" {
			settings[key] = value
		}
	}
	return settings, complete
}

func inspectRsyslogConfig(ctx context.Context, files system.Reader) (rsyslogInspection, error) {
	result := rsyslogInspection{
		complete:          true,
		localDestinations: make(map[string]struct{}),
	}
	visited := make(map[string]struct{})
	if err := inspectRsyslogFile(ctx, files, "/etc/rsyslog.conf", false, visited, &result); err != nil {
		return rsyslogInspection{}, err
	}
	sort.Strings(result.files)
	return result, nil
}

func inspectRsyslogFile(
	ctx context.Context,
	files system.Reader,
	filePath string,
	optional bool,
	visited map[string]struct{},
	result *rsyslogInspection,
) error {
	if len(visited) >= 128 {
		return fmt.Errorf("rsyslog include count exceeds the supported limit")
	}
	if _, exists := visited[filePath]; exists {
		return nil
	}
	visited[filePath] = struct{}{}
	data, _, err := files.ReadFile(ctx, filePath, 2<<20)
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	result.files = append(result.files, filePath)

	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "$includeconfig") {
			includeValue := strings.TrimSpace(line[len("$IncludeConfig"):])
			includeValue = strings.Trim(includeValue, "\"'")
			if includeValue == "" {
				result.complete = false
				continue
			}
			if err := inspectRsyslogInclude(ctx, files, includeValue, true, visited, result); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(lower, "include(") {
			match := rsyslogIncludeFilePattern.FindStringSubmatch(line)
			if len(match) != 2 || !strings.Contains(line, ")") {
				result.complete = false
				continue
			}
			optionalInclude := rsyslogOptionalModePattern.MatchString(line)
			if err := inspectRsyslogInclude(ctx, files, match[1], optionalInclude, visited, result); err != nil {
				return err
			}
			continue
		}

		lineHasAction := false
		paths := rsyslogLocalPathPattern.FindAllStringSubmatch(line, -1)
		for _, match := range paths {
			if len(match) == 2 {
				result.localDestinations[match[1]] = struct{}{}
				result.actionCount++
				lineHasAction = true
			}
		}
		if strings.Contains(lower, "type=\"omfwd\"") || strings.Contains(lower, "type='omfwd'") {
			result.actionCount++
			lineHasAction = true
		}
		if strings.Contains(lower, "type=\"omfile\"") || strings.Contains(lower, "type='omfile'") {
			if !lineHasAction {
				result.actionCount++
			}
			lineHasAction = true
			if len(paths) == 0 || strings.Contains(lower, "dynafile") {
				result.complete = false
			}
		}
		if strings.Contains(line, "@@") || (strings.Contains(line, "@") && !strings.Contains(line, "@cee:")) {
			result.actionCount++
			lineHasAction = true
		}
		fields := strings.Fields(line)
		if len(fields) > 1 {
			destination := fields[len(fields)-1]
			if strings.HasPrefix(destination, "|") || strings.HasPrefix(destination, "?") || strings.HasPrefix(destination, ":omusrmsg:") {
				result.actionCount++
				lineHasAction = true
				if strings.HasPrefix(destination, "?") {
					result.complete = false
				}
			}
		}
		if strings.Contains(lower, "action(") && !strings.Contains(line, ")") {
			result.complete = false
		}
		if strings.Contains(lower, "action(") && !lineHasAction {
			result.actionCount++
			result.complete = false
		}
	}
	return nil
}

func inspectRsyslogInclude(
	ctx context.Context,
	files system.Reader,
	pattern string,
	optional bool,
	visited map[string]struct{},
	result *rsyslogInspection,
) error {
	if !path.IsAbs(pattern) || strings.Contains(pattern, "$") || strings.ContainsAny(pattern, "`\r\n") {
		result.complete = false
		return nil
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return inspectRsyslogFile(ctx, files, pattern, optional, visited, result)
	}
	directory, filePattern := path.Split(pattern)
	if strings.ContainsAny(strings.TrimSuffix(directory, "/"), "*?[") || filePattern == "" {
		result.complete = false
		return nil
	}
	entries, err := files.ReadDir(strings.TrimSuffix(directory, "/"))
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	matches := make([]string, 0)
	for _, entry := range entries {
		matched, matchErr := path.Match(filePattern, entry.Name())
		if matchErr != nil {
			result.complete = false
			return nil
		}
		if matched && !entry.IsDir() {
			matches = append(matches, path.Join(directory, entry.Name()))
		}
	}
	sort.Strings(matches)
	for _, matchedPath := range matches {
		if err := inspectRsyslogFile(ctx, files, matchedPath, optional, visited, result); err != nil {
			return err
		}
	}
	return nil
}

func inspectExpectedLogPaths(files system.Reader) ([]map[string]any, int, error) {
	paths := []string{"/var/log/messages", "/var/log/secure", "/var/log/maillog", "/var/log/cron"}
	facts := make([]map[string]any, 0, len(paths))
	present := 0
	for _, filePath := range paths {
		metadata, err := files.Lstat(filePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				facts = append(facts, map[string]any{"path": filePath, "exists": false})
				continue
			}
			return nil, 0, err
		}
		present++
		facts = append(facts, map[string]any{
			"path":      filePath,
			"exists":    true,
			"file_type": metadata.FileType,
			"size":      metadata.Size,
			"mode":      fmt.Sprintf("%04o", metadata.Mode.Perm()),
			"uid":       metadata.UID,
		})
	}
	return facts, present, nil
}

func logPolicyError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "시스템 로깅 정책 설정을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
