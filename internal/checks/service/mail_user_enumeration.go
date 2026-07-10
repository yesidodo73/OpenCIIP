package service

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

const EvaluatorMailUserEnumeration = "unix.service.mail_user_enumeration"

var mailEnumerationProducts = []serviceProduct{
	{
		id:        "postfix",
		label:     "Postfix",
		units:     []string{"postfix.service"},
		processes: []string{"master"},
	},
	{
		id:        "sendmail",
		label:     "Sendmail",
		units:     []string{"sendmail.service"},
		processes: []string{"sendmail"},
	},
	{
		id:        "exim",
		label:     "Exim",
		units:     []string{"exim.service", "exim4.service"},
		processes: []string{"exim", "exim4"},
	},
}

func evaluateMailUserEnumeration(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectServiceTarget(ctx, environment, "메일 서비스", mailEnumerationProducts, []int{25, 465, 587}, "tcp")
	if terminal != nil {
		return *terminal
	}

	switch target.product.id {
	case "postfix":
		return evaluatePostfixUserEnumeration(ctx, environment, target)
	case "sendmail":
		return evaluateSendmailUserEnumeration(ctx, environment, target)
	default:
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 메일 제품의 VRFY 및 EXPN 실효 설정을 지원하지 않습니다.",
			Expected:      "VRFY와 EXPN 사용자 열거 기능이 모두 비활성화되어야 합니다.",
			Observed:      target.product.label,
			Evidence:      target.evidence,
		}
	}
}

func evaluatePostfixUserEnumeration(ctx context.Context, environment evaluator.Environment, target serviceTarget) evaluator.Outcome {
	multiInstance, multiEvidence, err := postconfValue(ctx, environment, "multi_instance_enable")
	if err != nil {
		return mailEnumerationError("postfix_effective_config_failed", err)
	}
	evidence := append(append([]model.Evidence(nil), target.evidence...), multiEvidence)
	switch strings.ToLower(multiInstance) {
	case "yes":
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "Postfix 다중 인스턴스의 모든 실효 설정을 확정할 수 없습니다.",
			Expected:      "모든 활성 Postfix 인스턴스에서 VRFY가 비활성화되어야 합니다.",
			Observed:      "multi_instance_enable=yes",
			Evidence:      evidence,
		}
	case "no":
	default:
		return mailEnumerationError("postfix_effective_config_invalid", fmt.Errorf("multi_instance_enable has an unsupported value"))
	}

	disableVRFY, settingEvidence, err := postconfValue(ctx, environment, "disable_vrfy_command")
	if err != nil {
		return mailEnumerationError("postfix_effective_config_failed", err)
	}
	evidence = append(evidence, settingEvidence)
	expected := "Postfix의 VRFY가 비활성화되어야 하며 구현되지 않은 EXPN 경로가 없어야 합니다."
	switch strings.ToLower(disableVRFY) {
	case "yes":
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "Postfix의 사용자 열거 명령이 비활성화되어 있습니다.",
			Expected: expected,
			Observed: "disable_vrfy_command=yes; Postfix는 EXPN 명령을 제공하지 않음",
			Evidence: evidence,
		}
	case "no":
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "Postfix에서 VRFY 사용자 열거 명령을 허용하고 있습니다.",
			Expected: expected,
			Observed: "disable_vrfy_command=no",
			Evidence: evidence,
		}
	default:
		return mailEnumerationError("postfix_effective_config_invalid", fmt.Errorf("disable_vrfy_command has an unsupported value"))
	}
}

func postconfValue(ctx context.Context, environment evaluator.Environment, name string) (string, model.Evidence, error) {
	spec := executor.Spec{
		Name:      "postconf",
		Arguments: []string{"-h", name},
		Timeout:   10 * time.Second,
		MaxOutput: 64 << 10,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return "", model.Evidence{}, fmt.Errorf("read Postfix setting %s: %w", name, err)
	}
	evidence := support.CommandEvidence(spec, result)
	if result.ExitCode != 0 || result.Truncated {
		return "", evidence, fmt.Errorf("read Postfix setting %s: exit=%d truncated=%t", name, result.ExitCode, result.Truncated)
	}
	value := strings.TrimSpace(string(result.Stdout))
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", evidence, fmt.Errorf("read Postfix setting %s: invalid output", name)
	}
	return value, evidence, nil
}

func evaluateSendmailUserEnumeration(ctx context.Context, environment evaluator.Environment, target serviceTarget) evaluator.Outcome {
	const (
		configurationPath = "/etc/mail/sendmail.cf"
		sysconfigPath     = "/etc/sysconfig/sendmail"
	)
	evidence := append([]model.Evidence(nil), target.evidence...)

	exists, err := environment.Files.Exists(sysconfigPath)
	if err != nil {
		return mailEnumerationError("sendmail_sysconfig_stat_failed", err)
	}
	if exists {
		data, _, readErr := environment.Files.ReadFile(ctx, sysconfigPath, 256<<10)
		if readErr != nil {
			return mailEnumerationError("sendmail_sysconfig_read_failed", readErr)
		}
		customConfig, parseErr := sendmailUsesCustomConfig(string(data))
		if parseErr != nil {
			return mailEnumerationError("sendmail_sysconfig_parse_failed", parseErr)
		}
		evidence = append(evidence, support.FactEvidence(sysconfigPath, map[string]any{
			"custom_config_path": customConfig,
		}))
		if customConfig {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "Sendmail이 사용자 지정 설정 파일로 실행되고 있습니다.",
				Expected:      "활성 Sendmail 인스턴스의 전체 실효 PrivacyOptions를 확인할 수 있어야 합니다.",
				Observed:      "시작 옵션에 사용자 지정 설정 경로가 있습니다.",
				Evidence:      evidence,
			}
		}
	}

	data, _, err := environment.Files.ReadFile(ctx, configurationPath, 2<<20)
	if err != nil {
		return mailEnumerationError("sendmail_config_read_failed", err)
	}
	privacy, complete, err := parseSendmailPrivacyOptions(string(data))
	if err != nil {
		return mailEnumerationError("sendmail_config_parse_failed", err)
	}
	noEXPN := privacy["noexpn"]
	noVRFY := privacy["novrfy"]
	evidence = append(evidence, support.FactEvidence(configurationPath, map[string]any{
		"fully_interpreted": complete,
		"noexpn":            noEXPN,
		"novrfy":            noVRFY,
	}))
	if !complete {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "Sendmail 설정의 include 또는 동적 값을 완전히 해석할 수 없습니다.",
			Expected:      "전체 실효 PrivacyOptions에서 noexpn과 novrfy가 설정되어야 합니다.",
			Observed:      "정적으로 확정할 수 없는 설정 구성이 있습니다.",
			Evidence:      evidence,
		}
	}
	expected := "전체 실효 PrivacyOptions에 noexpn과 novrfy가 모두 설정되어야 합니다."
	if noEXPN && noVRFY {
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "Sendmail의 EXPN 및 VRFY 명령이 모두 제한되어 있습니다.",
			Expected: expected,
			Observed: "noexpn=true; novrfy=true",
			Evidence: evidence,
		}
	}
	missing := make([]string, 0, 2)
	if !noEXPN {
		missing = append(missing, "noexpn")
	}
	if !noVRFY {
		missing = append(missing, "novrfy")
	}
	sort.Strings(missing)
	return evaluator.Outcome{
		Status:   model.StatusFail,
		Summary:  "Sendmail의 사용자 열거 명령 제한이 불완전합니다.",
		Expected: expected,
		Observed: "누락 옵션: " + strings.Join(missing, ", "),
		Evidence: evidence,
	}
}

func sendmailUsesCustomConfig(content string) (bool, error) {
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		tokens, err := shellAssignmentTokens(raw)
		if err != nil {
			return false, fmt.Errorf("line %d has invalid quoting", lineNumber+1)
		}
		for _, token := range tokens {
			if token == "-C" || (strings.HasPrefix(token, "-C") && len(token) > 2) {
				return true, nil
			}
		}
	}
	return false, nil
}

func shellAssignmentTokens(line string) ([]string, error) {
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

func parseSendmailPrivacyOptions(content string) (map[string]bool, bool, error) {
	var value string
	found := false
	complete := true
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, ".include") || strings.HasPrefix(lower, "include(") {
			complete = false
			continue
		}
		if strings.HasPrefix(lower, "o privacyoptions") || strings.HasPrefix(lower, "oprivacyoptions") {
			if strings.HasSuffix(line, "\\") {
				complete = false
			}
			_, optionValue, ok := strings.Cut(line, "=")
			if !ok {
				return nil, false, fmt.Errorf("line %d has an invalid PrivacyOptions assignment", lineNumber+1)
			}
			value = strings.TrimSpace(optionValue)
			found = true
			continue
		}
		if strings.HasPrefix(line, "Op") && len(line) > 2 {
			if strings.HasSuffix(line, "\\") {
				complete = false
			}
			value = strings.TrimSpace(line[2:])
			found = true
		}
	}
	options := make(map[string]bool)
	if !found {
		return options, complete, nil
	}
	if value == "" || strings.ContainsAny(value, "$`\r\n") {
		return options, false, nil
	}
	for _, option := range strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return character == ',' || character == ' ' || character == '\t'
	}) {
		if option != "" {
			options[option] = true
		}
	}
	if options["goaway"] {
		options["noexpn"] = true
		options["novrfy"] = true
	}
	return options, complete, nil
}

func mailEnumerationError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "메일 서비스의 사용자 열거 설정을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
