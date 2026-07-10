package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorSessionTimeout = "unix.account.session_timeout"

type timeoutAnalysis struct {
	Path       string
	Exists     bool
	Value      *int
	Line       int
	Exported   bool
	Readonly   bool
	Ambiguous  bool
	Reasons    []string
	Directives []map[string]any
}

func evaluateSessionTimeout(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	maximum, found, err := support.IntParameter(rule.Parameters, "max_session_timeout_seconds")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	if !found {
		maximum = 600
	}
	if maximum < 1 || maximum > 86400 {
		return checkError("invalid_rule_parameter", fmt.Errorf("max_session_timeout_seconds must be between 1 and 86400"))
	}
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("account_inventory_failed", err)
	}
	interactive := make([]string, 0)
	unsupportedShells := make([]string, 0)
	for _, account := range accounts {
		if isNonLoginShell(account.Shell) {
			continue
		}
		interactive = append(interactive, account.Name)
		if !supportedTimeoutShell(account.Shell) {
			unsupportedShells = append(unsupportedShells, account.Name+"="+account.Shell)
		}
	}
	if len(interactive) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "세션 종료 시간을 적용할 대화형 계정이 없습니다.",
			Expected: fmt.Sprintf("대화형 shell의 실효 TMOUT이 1~%d초여야 합니다.", maximum),
			Observed: "대화형 계정 없음",
			Evidence: []model.Evidence{accountEvidence},
		}
	}

	analyses := make([]timeoutAnalysis, 0, 2)
	evidence := []model.Evidence{accountEvidence}
	for _, path := range []string{"/etc/profile", "/etc/bashrc"} {
		analysis, analysisEvidence, analysisErr := analyzeTimeoutFile(ctx, environment, path)
		if analysisErr != nil {
			return checkError("session_timeout_config_failed", analysisErr)
		}
		analyses = append(analyses, analysis)
		evidence = append(evidence, analysisEvidence)
	}

	violations := make([]string, 0)
	unknowns := append([]string(nil), unsupportedShells...)
	for _, analysis := range analyses {
		if !analysis.Exists {
			unknowns = append(unknowns, analysis.Path+" 없음")
			continue
		}
		if analysis.Ambiguous {
			unknowns = append(unknowns, analysis.Path+"의 조건부 또는 동적 TMOUT 설정")
			continue
		}
		if analysis.Value == nil || !analysis.Readonly || !analysis.Exported {
			unknowns = append(unknowns, analysis.Path+"에서 export·readonly가 적용된 최종 TMOUT을 확인할 수 없음")
			continue
		}
		if *analysis.Value < 1 || *analysis.Value > maximum {
			violations = append(violations, fmt.Sprintf("%s:%d TMOUT=%d", analysis.Path, analysis.Line, *analysis.Value))
		}
	}
	sort.Strings(violations)
	sort.Strings(unknowns)
	expected := fmt.Sprintf("지원되는 모든 대화형 shell에서 export·readonly TMOUT이 1~%d초여야 합니다.", maximum)
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "잠금된 세션 종료 시간이 가이드 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: strings.Join(violations, "; "),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "모든 대화형 shell의 최종 세션 종료 시간을 정적으로 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      strings.Join(uniqueSorted(unknowns), "; "),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "지원되는 로그인 및 비로그인 대화형 shell에 세션 종료 시간이 강제됩니다.",
		Expected: expected,
		Observed: fmt.Sprintf("/etc/profile 및 /etc/bashrc의 TMOUT이 1~%d초이고 export·readonly입니다.", maximum),
		Evidence: evidence,
	}
}

func analyzeTimeoutFile(ctx context.Context, environment evaluator.Environment, path string) (timeoutAnalysis, model.Evidence, error) {
	analysis := timeoutAnalysis{Path: path}
	data, _, err := environment.Files.ReadFile(ctx, path, 2<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return analysis, support.FactEvidence(path, map[string]any{"exists": false}), nil
		}
		return analysis, model.Evidence{}, err
	}
	analysis.Exists = true
	depth := 0
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		commands, splitErr := splitShellCommands(raw)
		if splitErr != nil {
			if strings.Contains(strings.ToUpper(raw), "TMOUT") {
				analysis.Ambiguous = true
				analysis.Reasons = append(analysis.Reasons, fmt.Sprintf("line %d 구문 해석 실패", lineNumber+1))
			}
			continue
		}
		for _, command := range commands {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				continue
			}
			first := strings.ToLower(fields[0])
			if closesShellBlock(first) && depth > 0 {
				depth--
			}
			mentions := shellMentionsName(command, "TMOUT")
			if mentions && (depth > 0 || hasDynamicShellSyntax(command)) {
				analysis.Ambiguous = true
				analysis.Reasons = append(analysis.Reasons, fmt.Sprintf("line %d 조건부 또는 동적 참조", lineNumber+1))
			} else if mentions {
				if !applyTimeoutCommand(&analysis, fields, lineNumber+1) {
					analysis.Ambiguous = true
					analysis.Reasons = append(analysis.Reasons, fmt.Sprintf("line %d 지원하지 않는 TMOUT 구문", lineNumber+1))
				}
			}
			if opensShellBlock(fields) {
				depth++
			}
		}
	}
	if depth != 0 {
		analysis.Ambiguous = true
		analysis.Reasons = append(analysis.Reasons, "shell 블록 경계를 확정할 수 없음")
	}
	sort.Strings(analysis.Reasons)
	evidence := support.FactEvidence(path, map[string]any{
		"exists": true, "directives": analysis.Directives, "ambiguous": analysis.Ambiguous,
		"ambiguity_reasons": analysis.Reasons,
	})
	return analysis, evidence, nil
}

func applyTimeoutCommand(analysis *timeoutAnalysis, fields []string, line int) bool {
	index := 0
	exported := false
	readonly := false
	switch strings.ToLower(fields[0]) {
	case "export":
		exported = true
		index = 1
	case "readonly":
		readonly = true
		index = 1
	case "declare", "typeset":
		index = 1
		if index < len(fields) && strings.HasPrefix(fields[index], "-") {
			flags := strings.TrimPrefix(fields[index], "-")
			exported = strings.Contains(flags, "x")
			readonly = strings.Contains(flags, "r")
			index++
		}
	}
	if index >= len(fields) || len(fields)-index != 1 {
		return false
	}
	token := fields[index]
	if token == "TMOUT" {
		if exported {
			analysis.Exported = true
		}
		if readonly {
			analysis.Readonly = true
		}
		analysis.Directives = append(analysis.Directives, map[string]any{
			"line": line, "operation": fields[0], "name": "TMOUT",
		})
		return exported || readonly
	}
	name, rawValue, found := strings.Cut(token, "=")
	if name != "TMOUT" || !found {
		return false
	}
	value, err := strconv.Atoi(strings.Trim(strings.TrimSpace(rawValue), "'\""))
	if err != nil || value < 0 {
		return false
	}
	if analysis.Readonly {
		analysis.Directives = append(analysis.Directives, map[string]any{
			"line": line, "operation": "ignored_assignment_after_readonly", "name": "TMOUT", "value": value,
		})
		return true
	}
	analysis.Value = &value
	analysis.Line = line
	analysis.Exported = exported
	analysis.Readonly = readonly
	analysis.Directives = append(analysis.Directives, map[string]any{
		"line": line, "operation": "assign", "name": "TMOUT", "value": value,
		"exported": exported, "readonly": readonly,
	})
	return true
}

func splitShellCommands(line string) ([]string, error) {
	commands := make([]string, 0, 2)
	var builder strings.Builder
	quote := rune(0)
	escaped := false
	for _, character := range line {
		if escaped {
			builder.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			builder.WriteRune(character)
			continue
		}
		if quote != 0 {
			builder.WriteRune(character)
			if character == quote {
				quote = 0
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
			builder.WriteRune(character)
		case '#':
			goto finished
		case ';':
			if command := strings.TrimSpace(builder.String()); command != "" {
				commands = append(commands, command)
			}
			builder.Reset()
		default:
			builder.WriteRune(character)
		}
	}

finished:
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unterminated quote or escape")
	}
	if command := strings.TrimSpace(builder.String()); command != "" {
		commands = append(commands, command)
	}
	return commands, nil
}

func shellMentionsName(command, name string) bool {
	for _, token := range strings.FieldsFunc(command, func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character) && character != '_'
	}) {
		if token == name {
			return true
		}
	}
	return false
}

func hasDynamicShellSyntax(command string) bool {
	return strings.Contains(command, "$(") || strings.Contains(command, "`") ||
		strings.Contains(command, "&&") || strings.Contains(command, "||") ||
		strings.Contains(command, "${") || strings.Contains(command, "|")
}

func opensShellBlock(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	switch strings.ToLower(fields[0]) {
	case "if", "for", "while", "until", "case", "select", "function":
		return true
	default:
		return strings.HasSuffix(fields[0], "()") && len(fields) > 1 && fields[1] == "{"
	}
}

func closesShellBlock(first string) bool {
	switch first {
	case "fi", "done", "esac", "}":
		return true
	default:
		return false
	}
}

func supportedTimeoutShell(shell string) bool {
	switch strings.TrimSpace(shell) {
	case "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh":
		return true
	default:
		return false
	}
}
