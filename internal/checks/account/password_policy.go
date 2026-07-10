package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorPasswordPolicy = "unix.account.password_policy"

type configSetting struct {
	Value  string
	Source string
	Line   int
}

func evaluatePasswordPolicy(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	minimumLength, err := requiredIntParameter(rule, "min_password_length")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	requiredClasses, err := requiredIntParameter(rule, "required_character_classes")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	historyCount, err := requiredIntParameter(rule, "password_history")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	minimumDays, err := requiredIntParameter(rule, "min_password_days")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	maximumDays, err := requiredIntParameter(rule, "max_password_days")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}

	currentSpec := executor.Spec{Name: "authselect", Arguments: []string{"current"}, Timeout: 10 * time.Second}
	current, err := environment.Commands.Run(ctx, currentSpec)
	if err != nil {
		return checkError("authselect_current_failed", err)
	}
	evidence := []model.Evidence{support.CommandEvidence(currentSpec, current)}
	if current.ExitCode != 0 || current.Truncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "authselect가 관리하지 않는 인증 구성은 비밀번호 정책을 자동 확정할 수 없습니다.",
			Expected:      "지원되는 authselect 프로필과 일관된 PAM 구성이 필요합니다.",
			Observed:      fmt.Sprintf("exit=%d truncated=%t", current.ExitCode, current.Truncated),
			Evidence:      evidence,
		}
	}
	checkSpec := executor.Spec{Name: "authselect", Arguments: []string{"check"}, Timeout: 10 * time.Second}
	check, err := environment.Commands.Run(ctx, checkSpec)
	if err != nil {
		return checkError("authselect_check_failed", err)
	}
	evidence = append(evidence, support.CommandEvidence(checkSpec, check))
	if check.ExitCode != 0 || check.Truncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "authselect 구성이 수정되었거나 일관되지 않아 비밀번호 정책을 자동 확정할 수 없습니다.",
			Expected:      "authselect check가 성공해야 합니다.",
			Observed:      fmt.Sprintf("exit=%d truncated=%t", check.ExitCode, check.Truncated),
			Evidence:      evidence,
		}
	}

	pwquality, pwqualityEvidence, err := readPWQualitySettings(ctx, environment)
	if err != nil {
		return checkError("pwquality_config_failed", err)
	}
	evidence = append(evidence, pwqualityEvidence...)
	pwhistory, historyEvidence, err := readSimpleSecurityConfig(ctx, environment, "/etc/security/pwhistory.conf")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return checkError("pwhistory_config_failed", err)
	}
	if err == nil {
		evidence = append(evidence, historyEvidence)
	}
	loginDefs, loginEvidence, err := readLoginDefsSettings(ctx, environment, []string{"PASS_MIN_DAYS", "PASS_MAX_DAYS"})
	if err != nil {
		return checkError("login_defs_read_failed", err)
	}
	evidence = append(evidence, loginEvidence)

	pamStacks := []string{"system-auth", "password-auth"}
	pamRules := make(map[string][]support.PAMRule, len(pamStacks))
	for _, stack := range pamStacks {
		rules, stackEvidence, stackErr := support.ReadPAMService(ctx, environment.Files, stack)
		if stackErr != nil {
			return checkError("pam_password_stack_failed", stackErr)
		}
		pamRules[stack] = rules
		evidence = append(evidence, stackEvidence...)
	}

	violations := make([]string, 0)
	unknowns := make([]string, 0)
	if !containsToken(string(current.Stdout), "with-pwhistory") {
		violations = append(violations, "authselect with-pwhistory 기능이 활성화되지 않음")
	}
	for stack, rules := range pamRules {
		qualityRule, state := singlePasswordModule(rules, "pam_pwquality.so")
		switch state {
		case moduleMissing:
			violations = append(violations, stack+"에 pam_pwquality가 없음")
		case moduleAmbiguous:
			unknowns = append(unknowns, stack+"의 pam_pwquality 적용 경로가 여러 개임")
		case modulePresent:
			if control := passwordModuleControl(qualityRule.Control); control == moduleControlBypassable {
				violations = append(violations, stack+"의 pam_pwquality 제어 플래그가 정책 실패를 강제하지 않음")
			} else if control == moduleControlAmbiguous {
				unknowns = append(unknowns, stack+"의 pam_pwquality PAM 제어 흐름을 확정할 수 없음")
			}
			qualitySettings, overrideErr := applyPAMSettingOverrides(pwquality, qualityRule.Args, pwqualityOptionKeys())
			if overrideErr != nil {
				unknowns = append(unknowns, stack+"의 pam_pwquality 대체 설정을 해석할 수 없음: "+overrideErr.Error())
			} else {
				minimumLengthValue, ok := integerSetting(qualitySettings, "minlen")
				if !ok {
					unknowns = append(unknowns, stack+"의 pwquality minlen을 확인할 수 없음")
				} else if minimumLengthValue < minimumLength {
					violations = append(violations, fmt.Sprintf("%s minlen=%d", stack, minimumLengthValue))
				}
				classCount := requiredClassCount(qualitySettings)
				if classCount < requiredClasses {
					violations = append(violations, fmt.Sprintf("%s 필수 문자 종류=%d", stack, classCount))
				}
				if allowed, exists := stringSetting(qualitySettings, "allowclasses"); exists && !allCharacterClassesAllowed(allowed) {
					violations = append(violations, stack+"의 allowclasses가 네 문자 종류를 모두 허용하지 않음")
				}
				if !booleanSetting(qualitySettings, "enforce_for_root") {
					violations = append(violations, stack+"의 pwquality enforce_for_root 없음")
				}
			}
		}

		historyRule, state := singlePasswordModule(rules, "pam_pwhistory.so")
		switch state {
		case moduleMissing:
			violations = append(violations, stack+"에 pam_pwhistory가 없음")
		case moduleAmbiguous:
			unknowns = append(unknowns, stack+"의 pam_pwhistory 적용 경로가 여러 개임")
		case modulePresent:
			if control := passwordModuleControl(historyRule.Control); control == moduleControlBypassable {
				violations = append(violations, stack+"의 pam_pwhistory 제어 플래그가 정책 실패를 강제하지 않음")
			} else if control == moduleControlAmbiguous {
				unknowns = append(unknowns, stack+"의 pam_pwhistory PAM 제어 흐름을 확정할 수 없음")
			}
			historySettings, overrideErr := applyPAMSettingOverrides(pwhistory, historyRule.Args, pwhistoryOptionKeys())
			if overrideErr != nil {
				unknowns = append(unknowns, stack+"의 pam_pwhistory 대체 설정을 해석할 수 없음: "+overrideErr.Error())
			} else {
				remember, rememberKnown := integerSetting(historySettings, "remember")
				if !rememberKnown {
					unknowns = append(unknowns, stack+"의 비밀번호 이력 remember를 확인할 수 없음")
				} else if remember < historyCount {
					violations = append(violations, fmt.Sprintf("%s remember=%d", stack, remember))
				}
				if !booleanSetting(historySettings, "enforce_for_root") {
					violations = append(violations, stack+"의 pwhistory enforce_for_root 없음")
				}
			}
		}
	}

	passMin, passMinKnown := integerSetting(loginDefs, "pass_min_days")
	passMax, passMaxKnown := integerSetting(loginDefs, "pass_max_days")
	if !passMinKnown || !passMaxKnown {
		unknowns = append(unknowns, "login.defs 비밀번호 사용 기간을 확인할 수 없음")
	} else {
		if passMin < minimumDays {
			violations = append(violations, fmt.Sprintf("PASS_MIN_DAYS=%d", passMin))
		}
		if passMax > maximumDays || passMax < minimumDays {
			violations = append(violations, fmt.Sprintf("PASS_MAX_DAYS=%d", passMax))
		}
	}

	shadow, shadowEvidence, err := support.ReadShadowSummary(ctx, environment.Files)
	if err != nil {
		return checkError("shadow_read_failed", err)
	}
	evidence = append(evidence, shadowEvidence)
	for name, entry := range shadow {
		if entry.State != "active" {
			continue
		}
		if entry.MinDays == nil || entry.MaxDays == nil {
			unknowns = append(unknowns, name+" 계정의 사용 기간이 비어 있음")
			continue
		}
		if *entry.MinDays < minimumDays || *entry.MaxDays > maximumDays || *entry.MaxDays < minimumDays {
			violations = append(violations, fmt.Sprintf("%s(min=%d,max=%d)", name, *entry.MinDays, *entry.MaxDays))
		}
	}

	localAccounts, localEvidence, err := support.ReadPasswd(ctx, environment.Files)
	if err != nil {
		return checkError("passwd_read_failed", err)
	}
	effectiveAccounts, effectiveEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("getent_passwd_failed", err)
	}
	evidence = append(evidence, localEvidence, effectiveEvidence)
	localNames := make(map[string]struct{}, len(localAccounts))
	for _, account := range localAccounts {
		localNames[account.Name] = struct{}{}
	}
	for _, account := range effectiveAccounts {
		if _, local := localNames[account.Name]; !local && !isNonLoginShell(account.Shell) {
			unknowns = append(unknowns, account.Name+" 외부 계정 정책 미확인")
		}
	}

	sort.Strings(violations)
	sort.Strings(unknowns)
	expected := fmt.Sprintf("길이 %d자 이상, 문자 종류 %d개, 이력 %d회, 사용 기간 %d~%d일 정책이 모든 적용 계정에 유효해야 합니다.", minimumLength, requiredClasses, historyCount, minimumDays, maximumDays)
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "비밀번호 관리 정책이 가이드 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: strings.Join(uniqueSorted(violations), "; "),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "일부 비밀번호 정책의 실효 적용 상태를 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      strings.Join(uniqueSorted(unknowns), "; "),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "비밀번호 관리 정책과 적용 계정이 가이드 기준을 충족합니다.",
		Expected: expected,
		Observed: "pwquality, pwhistory, login.defs와 기존 로컬 계정의 사용 기간이 기준을 충족합니다.",
		Evidence: evidence,
	}
}

func readPWQualitySettings(ctx context.Context, environment evaluator.Environment) (map[string]configSetting, []model.Evidence, error) {
	// libpwquality merges vendor and administrator drop-ins by file name, reads
	// them in ASCII order, and finally applies the main administrator file.
	// An /etc drop-in with the same name replaces its /usr/lib counterpart.
	vendor, err := securityDropIns(environment, "/usr/lib/security/pwquality.conf.d")
	if err != nil {
		return nil, nil, err
	}
	administrator, err := securityDropIns(environment, "/etc/security/pwquality.conf.d")
	if err != nil {
		return nil, nil, err
	}
	for name, path := range administrator {
		vendor[name] = path
	}
	names := make([]string, 0, len(vendor))
	for name := range vendor {
		names = append(names, name)
	}
	sort.Strings(names)
	paths := make([]string, 0, len(names)+1)
	for _, name := range names {
		paths = append(paths, vendor[name])
	}
	mainPath := "/etc/security/pwquality.conf"
	if _, statErr := environment.Files.Lstat(mainPath); errors.Is(statErr, os.ErrNotExist) {
		mainPath = "/usr/lib/security/pwquality.conf"
	} else if statErr != nil {
		return nil, nil, statErr
	}
	paths = append(paths, mainPath)
	settings := make(map[string]configSetting)
	evidence := make([]model.Evidence, 0, len(paths))
	for _, path := range paths {
		parsed, parsedEvidence, readErr := readSimpleSecurityConfig(ctx, environment, path)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) && path == "/usr/lib/security/pwquality.conf" {
				continue
			}
			return nil, nil, readErr
		}
		for key, setting := range parsed {
			settings[key] = setting
		}
		evidence = append(evidence, parsedEvidence)
	}
	return settings, evidence, nil
}

func readSimpleSecurityConfig(ctx context.Context, environment evaluator.Environment, path string) (map[string]configSetting, model.Evidence, error) {
	data, _, err := environment.Files.ReadFile(ctx, path, 1<<20)
	if err != nil {
		return nil, model.Evidence{}, err
	}
	settings := make(map[string]configSetting)
	facts := make([]map[string]any, 0)
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := stripComment(raw)
		if line == "" {
			continue
		}
		key := ""
		value := "true"
		if left, right, found := strings.Cut(line, "="); found {
			key = strings.ToLower(strings.TrimSpace(left))
			value = strings.TrimSpace(right)
		} else {
			fields := strings.Fields(line)
			if len(fields) == 1 {
				key = strings.ToLower(fields[0])
			} else if len(fields) == 2 {
				key = strings.ToLower(fields[0])
				value = fields[1]
			} else {
				return nil, model.Evidence{}, fmt.Errorf("parse %s line %d: unsupported syntax", path, index+1)
			}
		}
		if key == "" || strings.ContainsAny(key, " \t") {
			return nil, model.Evidence{}, fmt.Errorf("parse %s line %d: invalid key", path, index+1)
		}
		setting := configSetting{Value: value, Source: path, Line: index + 1}
		settings[key] = setting
		evidenceValue := any("[수집 생략]")
		if safeSecuritySettingValue(key) {
			evidenceValue = value
		}
		facts = append(facts, map[string]any{"line": setting.Line, "key": key, "value": evidenceValue})
	}
	return settings, support.FactEvidence(path, map[string]any{"settings": facts}), nil
}

func readLoginDefsSettings(ctx context.Context, environment evaluator.Environment, keys []string) (map[string]configSetting, model.Evidence, error) {
	data, _, err := environment.Files.ReadFile(ctx, "/etc/login.defs", 1<<20)
	if err != nil {
		return nil, model.Evidence{}, err
	}
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[strings.ToLower(key)] = struct{}{}
	}
	settings := make(map[string]configSetting)
	facts := make([]map[string]any, 0)
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		fields := strings.Fields(stripComment(raw))
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if _, exists := wanted[key]; !exists {
			continue
		}
		setting := configSetting{Value: fields[1], Source: "/etc/login.defs", Line: index + 1}
		settings[key] = setting
		facts = append(facts, map[string]any{"line": setting.Line, "key": key, "value": setting.Value})
	}
	return settings, support.FactEvidence("/etc/login.defs", map[string]any{"settings": facts}), nil
}

func integerSetting(settings map[string]configSetting, key string) (int, bool) {
	setting, exists := settings[strings.ToLower(key)]
	if !exists {
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(setting.Value))
	return value, err == nil
}

func booleanSetting(settings map[string]configSetting, key string) bool {
	setting, exists := settings[strings.ToLower(key)]
	if !exists {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(setting.Value)) {
	case "true", "yes", "1", "on":
		return true
	default:
		return false
	}
}

func stringSetting(settings map[string]configSetting, key string) (string, bool) {
	setting, exists := settings[strings.ToLower(key)]
	if !exists {
		return "", false
	}
	return strings.TrimSpace(setting.Value), true
}

func requiredClassCount(settings map[string]configSetting) int {
	if minClass, ok := integerSetting(settings, "minclass"); ok && minClass >= 4 {
		return 4
	}
	count := 0
	for _, key := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		if value, ok := integerSetting(settings, key); ok && value <= -1 {
			count++
		}
	}
	return count
}

type moduleState uint8

const (
	modulePresent moduleState = iota
	moduleMissing
	moduleAmbiguous
)

func singlePasswordModule(rules []support.PAMRule, module string) (support.PAMRule, moduleState) {
	matches := make([]support.PAMRule, 0, 1)
	for _, rule := range rules {
		if rule.Type == "password" && filepath.Base(rule.Module) == module {
			matches = append(matches, rule)
		}
	}
	if len(matches) == 0 {
		return support.PAMRule{}, moduleMissing
	}
	if len(matches) != 1 {
		return support.PAMRule{}, moduleAmbiguous
	}
	return matches[0], modulePresent
}

type moduleControl uint8

const (
	moduleControlEnforcing moduleControl = iota
	moduleControlBypassable
	moduleControlAmbiguous
)

func passwordModuleControl(control string) moduleControl {
	switch strings.ToLower(strings.TrimSpace(control)) {
	case "required", "requisite":
		return moduleControlEnforcing
	case "optional", "sufficient":
		return moduleControlBypassable
	default:
		return moduleControlAmbiguous
	}
}

func applyPAMSettingOverrides(base map[string]configSetting, arguments []string, supported map[string]bool) (map[string]configSetting, error) {
	result := make(map[string]configSetting, len(base))
	for key, setting := range base {
		result[key] = setting
	}
	for index, argument := range arguments {
		key, value, hasValue := strings.Cut(argument, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "conf" {
			return nil, fmt.Errorf("conf 대체 경로 %q", value)
		}
		if !supported[key] {
			continue
		}
		if !hasValue {
			value = "true"
		}
		result[key] = configSetting{Value: strings.TrimSpace(value), Source: "PAM module argument", Line: index + 1}
	}
	return result, nil
}

func pwqualityOptionKeys() map[string]bool {
	return map[string]bool{
		"minlen": true, "minclass": true, "dcredit": true, "ucredit": true,
		"lcredit": true, "ocredit": true, "enforce_for_root": true,
		"allowclasses": true,
	}
}

func pwhistoryOptionKeys() map[string]bool {
	return map[string]bool{"remember": true, "enforce_for_root": true}
}

func allCharacterClassesAllowed(value string) bool {
	classes := make(map[rune]bool)
	for _, character := range strings.ToLower(strings.TrimSpace(value)) {
		classes[character] = true
	}
	return classes['d'] && classes['u'] && classes['l'] && classes['o']
}

func securityDropIns(environment evaluator.Environment, directory string) (map[string]string, error) {
	entries, err := environment.Files.ReadDir(directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	result := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".conf") || filepath.Base(name) != name {
			continue
		}
		result[name] = directory + "/" + name
	}
	return result, nil
}

func safeSecuritySettingValue(key string) bool {
	switch strings.ToLower(key) {
	case "minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit",
		"enforce_for_root", "allowclasses", "remember", "retry":
		return true
	default:
		return false
	}
}

func requiredIntParameter(rule model.ResolvedRule, key string) (int, error) {
	value, found, err := support.IntParameter(rule.Parameters, key)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("required parameter %s is missing", key)
	}
	return value, nil
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
