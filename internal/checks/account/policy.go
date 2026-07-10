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

const (
	EvaluatorLockoutThreshold = "unix.account.lockout_threshold"
	EvaluatorPasswordHash     = "unix.account.password_hash"
)

func policyImplementations() map[string]evaluator.Func {
	return map[string]evaluator.Func{
		EvaluatorRemoteRootLogin:  evaluateRemoteRootLogin,
		EvaluatorSessionTimeout:   evaluateSessionTimeout,
		EvaluatorPasswordPolicy:   evaluatePasswordPolicy,
		EvaluatorLockoutThreshold: evaluateLockoutThreshold,
		EvaluatorPasswordHash:     evaluatePasswordHash,
		EvaluatorSURestriction:    evaluateSURestriction,
	}
}

func evaluateLockoutThreshold(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	defaultDeny, hasDefault, err := support.IntParameter(rule.Parameters, "default_deny")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	currentSpec := executor.Spec{Name: "authselect", Arguments: []string{"current"}, Timeout: 10 * time.Second}
	current, err := environment.Commands.Run(ctx, currentSpec)
	if err != nil {
		return checkError("authselect_current_failed", err)
	}
	evidence := []model.Evidence{support.CommandEvidence(currentSpec, current)}
	if current.Truncated {
		return checkError("authselect_output_truncated", fmt.Errorf("authselect current output exceeded the limit"))
	}
	if current.ExitCode != 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "authselect가 관리하지 않는 인증 구성은 자동 확정할 수 없습니다.",
			Expected:      "지원되는 authselect 프로필에서 pam_faillock이 활성화되어야 합니다.",
			Observed:      fmt.Sprintf("authselect current exit=%d", current.ExitCode),
			Evidence:      evidence,
		}
	}
	if !containsToken(string(current.Stdout), "with-faillock") {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "authselect 프로필에 계정 잠금 기능이 활성화되어 있지 않습니다.",
			Expected: "with-faillock 기능과 10회 이하의 deny 값이 적용되어야 합니다.",
			Observed: "with-faillock 없음",
			Evidence: evidence,
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
			Summary:       "authselect 구성이 수정되었거나 일관되지 않아 잠금 정책을 자동 확정할 수 없습니다.",
			Expected:      "authselect check가 성공해야 합니다.",
			Observed:      fmt.Sprintf("exit=%d truncated=%t", check.ExitCode, check.Truncated),
			Evidence:      evidence,
		}
	}

	deny, source, denyEvidence, err := readFaillockDeny(ctx, environment, defaultDeny, hasDefault)
	if err != nil {
		return checkError("faillock_config_failed", err)
	}
	evidence = append(evidence, denyEvidence)
	pamStacks, pamEvidence, err := readPolicyPAMStacks(ctx, environment, "system-auth", "password-auth")
	if err != nil {
		return checkError("pam_faillock_stack_failed", err)
	}
	evidence = append(evidence, pamEvidence...)

	violations := make([]string, 0)
	unknowns := make([]string, 0)
	effective := make([]string, 0)
	for _, stack := range []string{"system-auth", "password-auth"} {
		stackEffective, stackViolations, stackUnknowns := inspectFaillockDenyOverrides(stack, pamStacks[stack], deny, source)
		effective = append(effective, stackEffective...)
		violations = append(violations, stackViolations...)
		unknowns = append(unknowns, stackUnknowns...)
		topologyViolations, topologyUnknowns := assessFaillockPAMTopology(stack, pamStacks[stack])
		violations = append(violations, topologyViolations...)
		unknowns = append(unknowns, topologyUnknowns...)
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "계정 잠금 임계값이 가이드 기준을 충족하지 않습니다.",
			Expected: "실패 횟수 deny가 1회 이상 10회 이하여야 합니다.",
			Observed: strings.Join(uniqueSorted(violations), "; "),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		sort.Strings(unknowns)
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "PAM 계정 잠금 임계값의 실효 설정을 확정할 수 없습니다.",
			Expected:      "유효 PAM 스택의 모든 pam_faillock.so deny 설정을 해석할 수 있어야 합니다.",
			Observed:      strings.Join(uniqueSorted(unknowns), "; "),
			Evidence:      evidence,
		}
	}
	sort.Strings(effective)
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "계정 잠금 임계값이 가이드 기준을 충족합니다.",
		Expected: "실패 횟수 deny가 1회 이상 10회 이하여야 합니다.",
		Observed: strings.Join(uniqueSorted(effective), "; "),
		Evidence: evidence,
	}
}

func readPolicyPAMStacks(ctx context.Context, environment evaluator.Environment, names ...string) (map[string][]support.PAMRule, []model.Evidence, error) {
	stacks := make(map[string][]support.PAMRule, len(names))
	evidence := make([]model.Evidence, 0, len(names))
	for _, name := range names {
		rules, stackEvidence, err := support.ReadPAMService(ctx, environment.Files, name)
		if err != nil {
			return nil, nil, fmt.Errorf("read PAM stack %s: %w", name, err)
		}
		stacks[name] = rules
		evidence = append(evidence, stackEvidence...)
	}
	return stacks, evidence, nil
}

func inspectFaillockDenyOverrides(stack string, rules []support.PAMRule, configuredDeny int, configuredSource string) ([]string, []string, []string) {
	effective := make([]string, 0)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	authModuleFound := false
	for _, rule := range rules {
		if filepath.Base(rule.Module) != "pam_faillock.so" || (rule.Type != "auth" && rule.Type != "account") {
			continue
		}
		if rule.Type == "auth" {
			authModuleFound = true
		}
		deny := configuredDeny
		source := configuredSource
		overrideFound := false
		ambiguous := false
		for _, argument := range rule.Args {
			key, value, hasValue := strings.Cut(argument, "=")
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "conf":
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_faillock conf 대체 경로", stack, rule.Path, rule.Line))
				ambiguous = true
			case "deny":
				if !hasValue || strings.TrimSpace(value) == "" {
					unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_faillock deny 값 없음", stack, rule.Path, rule.Line))
					ambiguous = true
					continue
				}
				parsed, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil {
					unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_faillock deny 해석 불가", stack, rule.Path, rule.Line))
					ambiguous = true
					continue
				}
				if overrideFound && parsed != deny {
					unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_faillock deny 중복 충돌", stack, rule.Path, rule.Line))
					ambiguous = true
					continue
				}
				deny = parsed
				source = fmt.Sprintf("%s:%d PAM 재정의", rule.Path, rule.Line)
				overrideFound = true
			}
		}
		if ambiguous {
			continue
		}
		description := fmt.Sprintf("%s deny=%d (%s)", stack, deny, source)
		effective = append(effective, description)
		if deny < 1 || deny > 10 {
			violations = append(violations, description)
		}
	}
	if !authModuleFound {
		unknowns = append(unknowns, stack+"에 auth pam_faillock.so가 없음")
	}
	return effective, violations, unknowns
}

func assessFaillockPAMTopology(stack string, rules []support.PAMRule) ([]string, []string) {
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	preauthIndexes := make([]int, 0, 1)
	authfailIndexes := make([]int, 0, 1)
	authsuccIndexes := make([]int, 0, 1)
	accountIndexes := make([]int, 0, 1)
	for index, rule := range rules {
		if filepath.Base(rule.Module) != "pam_faillock.so" {
			continue
		}
		if rule.Type == "account" {
			accountIndexes = append(accountIndexes, index)
			control := strings.ToLower(strings.TrimSpace(rule.Control))
			if control != "required" && control != "requisite" {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d account pam_faillock 제어=%s", stack, rule.Path, rule.Line, rule.Control))
			}
			continue
		}
		if rule.Type != "auth" {
			continue
		}
		mode, modeKnown := faillockAuthMode(rule.Args)
		if !modeKnown {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_faillock auth 모드를 확정할 수 없음", stack, rule.Path, rule.Line))
			continue
		}
		control := strings.ToLower(strings.TrimSpace(rule.Control))
		switch mode {
		case "preauth":
			preauthIndexes = append(preauthIndexes, index)
			if control == "optional" || control == "sufficient" {
				violations = append(violations, fmt.Sprintf("%s %s:%d preauth 제어=%s로 잠금 실패를 강제하지 않음", stack, rule.Path, rule.Line, rule.Control))
			} else if control != "required" && control != "requisite" {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d preauth 제어 흐름을 확정할 수 없음", stack, rule.Path, rule.Line))
			}
		case "authfail":
			authfailIndexes = append(authfailIndexes, index)
			if !safeFaillockAuthfailControl(control) {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d authfail 제어 흐름을 확정할 수 없음", stack, rule.Path, rule.Line))
			}
		case "authsucc":
			authsuccIndexes = append(authsuccIndexes, index)
			if control != "sufficient" {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d authsucc가 문서화된 sufficient 제어를 사용하지 않음", stack, rule.Path, rule.Line))
			}
		}
	}

	if len(authfailIndexes) == 0 {
		violations = append(violations, stack+"에 실패 횟수를 기록하는 authfail pam_faillock.so가 없음")
		return violations, unknowns
	}
	if len(authfailIndexes) != 1 || len(preauthIndexes) > 1 || len(authsuccIndexes) > 1 || len(accountIndexes) > 1 {
		unknowns = append(unknowns, stack+"의 pam_faillock 모드별 적용 경로가 여러 개임")
	}
	authfailIndex := authfailIndexes[0]
	for index, rule := range rules {
		if rule.Type != "auth" {
			continue
		}
		module := strings.ToLower(filepath.Base(rule.Module))
		control := strings.ToLower(strings.TrimSpace(rule.Control))
		if index < authfailIndex && module == "pam_permit.so" && control == "sufficient" {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d sufficient pam_permit.so의 루트 스택 도달성과 잠금 우회를 확정할 수 없음", stack, rule.Path, rule.Line))
		} else if index < authfailIndex && module == "pam_permit.so" && strings.HasPrefix(control, "[") {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_permit.so 복합 제어의 잠금 우회를 확정할 수 없음", stack, rule.Path, rule.Line))
		}
		if index >= authfailIndex {
			continue
		}
		isPreauth := module == "pam_faillock.so" && containsFold(rule.Args, "preauth")
		if control == "requisite" && !isPreauth {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d requisite %s가 authfail 기록 전에 인증을 종료할 수 있음", stack, rule.Path, rule.Line, module))
		} else if strings.HasPrefix(control, "[") && pamBracketCanBypassTarget(control, rules, index, authfailIndex, "auth", stack, false) {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d 복합 제어가 인증 실패 시 authfail 기록 경로를 건너뛸 수 있음", stack, rule.Path, rule.Line))
		}
	}

	if len(preauthIndexes) == 1 {
		preauthIndex := preauthIndexes[0]
		if preauthIndex >= authfailIndex {
			violations = append(violations, stack+"의 preauth pam_faillock.so가 authfail보다 뒤에 있음")
		}
		for index, rule := range rules {
			if index >= preauthIndex || rule.Type != "auth" {
				continue
			}
			control := strings.ToLower(strings.TrimSpace(rule.Control))
			module := strings.ToLower(filepath.Base(rule.Module))
			if strings.HasPrefix(control, "[") {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d 복합 제어가 preauth를 건너뛸 수 있음", stack, rule.Path, rule.Line))
			} else if control == "sufficient" && module != "pam_deny.so" {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d sufficient %s가 preauth를 건너뛸 수 있음", stack, rule.Path, rule.Line, module))
			}
		}
	}

	accountTopology := len(preauthIndexes) == 1 && len(accountIndexes) == 1
	authSuccessTopology := len(authsuccIndexes) == 1 && authsuccIndexes[0] > authfailIndex
	if accountTopology {
		accountIndex := accountIndexes[0]
		if !hasDirectSufficientAuthenticationBefore(rules, authfailIndex, stack) {
			unknowns = append(unknowns, stack+"의 정상 인증 성공 경로가 authfail 전에 종료되는지 확정할 수 없음")
		}
		for index, rule := range rules {
			if index >= accountIndex || rule.Type != "account" {
				continue
			}
			module := strings.ToLower(filepath.Base(rule.Module))
			control := strings.ToLower(strings.TrimSpace(rule.Control))
			description := fmt.Sprintf("%s %s:%d %s control=%s", stack, rule.Path, rule.Line, module, rule.Control)
			if module == "pam_permit.so" && control == "sufficient" {
				violations = append(violations, description+"이 account pam_faillock.so를 우회함")
			} else if control == "sufficient" && module != "pam_deny.so" {
				unknowns = append(unknowns, description+"이 account pam_faillock.so보다 먼저 성공할 수 있음")
			} else if strings.HasPrefix(control, "[") && pamBracketCanBypassTarget(control, rules, index, accountIndex, "account", stack, true) {
				unknowns = append(unknowns, description+"이 account pam_faillock.so를 건너뛸 수 있음")
			}
		}
	}
	if authSuccessTopology {
		authsuccIndex := authsuccIndexes[0]
		authfailControl := strings.ToLower(strings.TrimSpace(rules[authfailIndex].Control))
		if !terminatingFaillockAuthfailControl(authfailControl) {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d authfail 실패가 authsucc까지 진행되어 실패 횟수를 지울 수 있음", stack, rules[authfailIndex].Path, rules[authfailIndex].Line))
		}
		for index, rule := range rules {
			if index >= authsuccIndex || rule.Type != "auth" || index == authfailIndex {
				continue
			}
			module := strings.ToLower(filepath.Base(rule.Module))
			control := strings.ToLower(strings.TrimSpace(rule.Control))
			description := fmt.Sprintf("%s %s:%d %s control=%s", stack, rule.Path, rule.Line, module, rule.Control)
			if control == "sufficient" && module != "pam_deny.so" {
				unknowns = append(unknowns, description+"이 authsucc pam_faillock.so보다 먼저 성공할 수 있음")
			} else if strings.HasPrefix(control, "[") && pamBracketCanBypassTarget(control, rules, index, authsuccIndex, "auth", stack, true) {
				unknowns = append(unknowns, description+"이 authsucc pam_faillock.so를 건너뛸 수 있음")
			}
		}
		authsuccControl := strings.ToLower(strings.TrimSpace(rules[authsuccIndex].Control))
		if authsuccControl == "sufficient" && !hasRejectingPAMDenyAfter(rules, authsuccIndex, "auth") {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d authsucc 실패 뒤 인증을 확실히 거부하는 pam_deny.so가 없음", stack, rules[authsuccIndex].Path, rules[authsuccIndex].Line))
		}
		if !accountTopology && !hasVerifiedSuccessJumpOverFaillock(rules, authfailIndex, stack) {
			unknowns = append(unknowns, stack+"의 성공 인증 경로가 authfail을 건너 authsucc에 도달하는지 확정할 수 없음")
		}
	}
	if !accountTopology && !authSuccessTopology {
		unknowns = append(unknowns, stack+"에 검증된 preauth+account 또는 authfail+authsucc 잠금 구조가 없음")
	}
	if len(authsuccIndexes) == 1 && authsuccIndexes[0] <= authfailIndex {
		violations = append(violations, stack+"의 authsucc pam_faillock.so가 authfail보다 앞에 있음")
	}
	return violations, unknowns
}

func faillockAuthMode(arguments []string) (string, bool) {
	mode := ""
	for _, argument := range arguments {
		normalized := strings.ToLower(strings.TrimSpace(argument))
		if normalized != "preauth" && normalized != "authfail" && normalized != "authsucc" {
			continue
		}
		if mode != "" && mode != normalized {
			return "", false
		}
		mode = normalized
	}
	return mode, mode != ""
}

func safeFaillockAuthfailControl(control string) bool {
	if control == "required" || control == "requisite" {
		return true
	}
	if !strings.HasPrefix(control, "[") || !strings.HasSuffix(control, "]") {
		return false
	}
	fields := strings.Fields(strings.Trim(control, "[]"))
	return len(fields) == 1 && (fields[0] == "default=die" || fields[0] == "default=bad")
}

func terminatingFaillockAuthfailControl(control string) bool {
	if control == "requisite" {
		return true
	}
	if !strings.HasPrefix(control, "[") || !strings.HasSuffix(control, "]") {
		return false
	}
	fields := strings.Fields(strings.Trim(control, "[]"))
	return len(fields) == 1 && fields[0] == "default=die"
}

func hasRejectingPAMDenyAfter(rules []support.PAMRule, currentIndex int, ruleType string) bool {
	for index := currentIndex + 1; index < len(rules); index++ {
		rule := rules[index]
		if rule.Type != ruleType {
			continue
		}
		control := strings.ToLower(strings.TrimSpace(rule.Control))
		return filepath.Base(rule.Module) == "pam_deny.so" && (control == "required" || control == "requisite")
	}
	return false
}

func hasVerifiedSuccessJumpOverFaillock(rules []support.PAMRule, authfailIndex int, rootService string) bool {
	for index := 0; index < authfailIndex; index++ {
		rule := rules[index]
		if rule.Type != "auth" || !strings.HasPrefix(strings.TrimSpace(rule.Control), "[") {
			continue
		}
		if rule.Service != "" && rule.Service != rootService {
			continue
		}
		module := strings.ToLower(filepath.Base(rule.Module))
		switch module {
		case "pam_unix.so", "pam_sss.so", "pam_ldap.so", "pam_winbind.so", "pam_krb5.so", "pam_fprintd.so":
		default:
			continue
		}
		actions, valid := pamControlActions(rule.Control)
		if !valid {
			continue
		}
		action, exists := actions["success"]
		if !exists {
			action, exists = actions["default"]
		}
		if !exists {
			continue
		}
		jump, err := strconv.Atoi(action)
		if err != nil {
			continue
		}
		distance, exact := pamTargetDistance(rules, index, authfailIndex, "auth", rootService)
		if exact && jump == distance {
			return true
		}
	}
	return false
}

func hasDirectSufficientAuthenticationBefore(rules []support.PAMRule, targetIndex int, rootService string) bool {
	for index := 0; index < targetIndex; index++ {
		rule := rules[index]
		if rule.Type != "auth" || strings.ToLower(strings.TrimSpace(rule.Control)) != "sufficient" {
			continue
		}
		if rule.Service != "" && rule.Service != rootService {
			continue
		}
		switch strings.ToLower(filepath.Base(rule.Module)) {
		case "pam_unix.so", "pam_sss.so", "pam_ldap.so", "pam_winbind.so", "pam_krb5.so", "pam_fprintd.so":
			return true
		}
	}
	return false
}

func pamBracketCanBypassTarget(control string, rules []support.PAMRule, currentIndex, targetIndex int, ruleType, rootService string, successPath bool) bool {
	distance, exact := pamTargetDistance(rules, currentIndex, targetIndex, ruleType, rootService)
	if !exact {
		return true
	}
	if distance == 0 {
		return false
	}
	actions, valid := pamControlActions(control)
	if !valid {
		return true
	}
	if successPath {
		action, exists := actions["success"]
		if !exists {
			action, exists = actions["default"]
		}
		return !exists || pamActionBypassesTarget(action, distance)
	}
	if _, exists := actions["default"]; !exists {
		return true
	}
	for result, action := range actions {
		if result == "success" {
			continue
		}
		if pamActionBypassesTarget(action, distance) {
			return true
		}
	}
	return false
}

func pamControlActions(control string) (map[string]string, bool) {
	fields := strings.Fields(strings.Trim(control, "[]"))
	if len(fields) == 0 {
		return nil, false
	}
	actions := make(map[string]string, len(fields))
	for _, field := range fields {
		result, action, found := strings.Cut(strings.ToLower(field), "=")
		if !found || result == "" || action == "" {
			return nil, false
		}
		if previous, exists := actions[result]; exists && previous != action {
			return nil, false
		}
		actions[result] = action
	}
	return actions, true
}

func pamTargetDistance(rules []support.PAMRule, currentIndex, targetIndex int, ruleType, rootService string) (int, bool) {
	if currentIndex < 0 || currentIndex >= len(rules) || targetIndex < currentIndex || targetIndex >= len(rules) {
		return 0, false
	}
	if rules[currentIndex].Service != "" && rules[currentIndex].Service != rootService {
		return 0, false
	}
	distance := 0
	for index := currentIndex + 1; index <= targetIndex && index < len(rules); index++ {
		if rules[index].Type != ruleType {
			continue
		}
		if rules[index].Service != "" && rules[index].Service != rootService {
			return 0, false
		}
		distance++
	}
	return distance, true
}

func pamActionBypassesTarget(action string, distance int) bool {
	switch action {
	case "bad", "ignore", "ok", "reset":
		return false
	case "die", "done":
		return true
	}
	jump, err := strconv.Atoi(action)
	if err != nil || jump < 0 {
		return true
	}
	return jump >= distance
}

func readFaillockDeny(ctx context.Context, environment evaluator.Environment, defaultValue int, hasDefault bool) (int, string, model.Evidence, error) {
	data, _, err := environment.Files.ReadFile(ctx, "/etc/security/faillock.conf", 1<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && hasDefault {
			return defaultValue, "RHEL 9 기본값", support.FactEvidence("/etc/security/faillock.conf", map[string]any{
				"exists":       false,
				"default_deny": defaultValue,
			}), nil
		}
		return 0, "", model.Evidence{}, err
	}
	deny := 0
	found := false
	lineNumber := 0
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := stripComment(raw)
		if line == "" {
			continue
		}
		key, value, hasEquals := strings.Cut(line, "=")
		if !hasEquals || !strings.EqualFold(strings.TrimSpace(key), "deny") {
			continue
		}
		parsed, parseErr := strconv.Atoi(strings.TrimSpace(value))
		if parseErr != nil {
			return 0, "", model.Evidence{}, fmt.Errorf("line %d has invalid deny value", index+1)
		}
		deny = parsed
		found = true
		lineNumber = index + 1
	}
	if !found {
		if !hasDefault {
			return 0, "", model.Evidence{}, fmt.Errorf("deny is not set and no verified platform default is available")
		}
		return defaultValue, "RHEL 9 기본값", support.FactEvidence("/etc/security/faillock.conf", map[string]any{
			"exists":       true,
			"deny_set":     false,
			"default_deny": defaultValue,
		}), nil
	}
	return deny, fmt.Sprintf("faillock.conf:%d", lineNumber), support.FactEvidence("/etc/security/faillock.conf", map[string]any{
		"line": lineNumber,
		"deny": deny,
	}), nil
}

func evaluatePasswordHash(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	safeMethods, found, err := support.StringSliceParameter(rule.Parameters, "safe_login_defs_methods")
	if err != nil || !found {
		if err == nil {
			err = fmt.Errorf("safe_login_defs_methods is missing")
		}
		return checkError("invalid_rule_parameter", err)
	}
	safeAlgorithms, found, err := support.StringSliceParameter(rule.Parameters, "safe_shadow_algorithms")
	if err != nil || !found {
		if err == nil {
			err = fmt.Errorf("safe_shadow_algorithms is missing")
		}
		return checkError("invalid_rule_parameter", err)
	}
	method, line, loginEvidence, err := readLoginDefsMethod(ctx, environment)
	if err != nil {
		return checkError("login_defs_read_failed", err)
	}
	shadow, shadowEvidence, err := support.ReadShadowSummary(ctx, environment.Files)
	if err != nil {
		return checkError("shadow_read_failed", err)
	}
	pamStacks, pamEvidence, err := readPolicyPAMStacks(ctx, environment, "system-auth", "password-auth")
	if err != nil {
		return checkError("pam_password_hash_stack_failed", err)
	}
	evidence := []model.Evidence{loginEvidence, shadowEvidence}
	evidence = append(evidence, pamEvidence...)
	activeAlgorithms := make(map[string][]string)
	for name, entry := range shadow {
		if entry.State != "active" {
			continue
		}
		activeAlgorithms[entry.Algorithm] = append(activeAlgorithms[entry.Algorithm], name)
	}
	unsafe := make([]string, 0)
	unknown := make([]string, 0)
	for algorithm, accounts := range activeAlgorithms {
		sort.Strings(accounts)
		description := fmt.Sprintf("algorithm=%s accounts=%s", algorithm, strings.Join(accounts, ","))
		if containsFold(safeAlgorithms, algorithm) {
			continue
		}
		if isKnownWeakHash(algorithm) {
			unsafe = append(unsafe, description)
		} else {
			unknown = append(unknown, description)
		}
	}
	methodSafe := containsFold(safeMethods, method)
	if !methodSafe && isKnownWeakMethod(method) {
		unsafe = append(unsafe, "ENCRYPT_METHOD="+method)
	} else if !methodSafe {
		unknown = append(unknown, "ENCRYPT_METHOD="+method)
	}
	effectiveMethods := []string{fmt.Sprintf("ENCRYPT_METHOD=%s line=%d", method, line)}
	for _, stack := range []string{"system-auth", "password-auth"} {
		stackMethods, stackUnsafe, stackUnknown := inspectPAMUnixHashMethods(stack, pamStacks[stack], method, safeMethods)
		effectiveMethods = append(effectiveMethods, stackMethods...)
		unsafe = append(unsafe, stackUnsafe...)
		unknown = append(unknown, stackUnknown...)
	}
	sort.Strings(unsafe)
	sort.Strings(unknown)
	if len(unsafe) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "안전하지 않은 비밀번호 암호화 알고리즘이 사용되고 있습니다.",
			Expected: "신규 정책과 기존 활성 해시가 SHA-2 이상의 알고리즘을 사용해야 합니다.",
			Observed: strings.Join(unsafe, "; "),
			Evidence: evidence,
		}
	}
	if len(unknown) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "알 수 없는 비밀번호 암호화 알고리즘을 자동 평가할 수 없습니다.",
			Expected:      "신규 정책과 기존 활성 해시가 SHA-2 이상의 알고리즘을 사용해야 합니다.",
			Observed:      strings.Join(unknown, "; "),
			Evidence:      evidence,
		}
	}
	if len(activeAlgorithms) == 0 {
		sort.Strings(effectiveMethods)
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "신규 비밀번호 해시 정책은 안전하지만 활성 상태의 로컬 비밀번호 해시가 없습니다.",
			Expected: "신규 정책과 기존 활성 해시가 SHA-2 이상의 알고리즘을 사용해야 합니다.",
			Observed: strings.Join(uniqueSorted(effectiveMethods), "; "),
			Evidence: evidence,
		}
	}
	sort.Strings(effectiveMethods)
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "비밀번호 암호화 알고리즘이 가이드 기준을 충족합니다.",
		Expected: "신규 정책과 기존 활성 해시가 SHA-2 이상의 알고리즘을 사용해야 합니다.",
		Observed: strings.Join(uniqueSorted(effectiveMethods), "; ") + "; 활성 해시 알고리즘이 모두 허용 목록에 포함됩니다.",
		Evidence: evidence,
	}
}

func inspectPAMUnixHashMethods(stack string, rules []support.PAMRule, fallbackMethod string, safeMethods []string) ([]string, []string, []string) {
	type indexedRule struct {
		index int
		rule  support.PAMRule
	}
	matches := make([]indexedRule, 0, 1)
	for index, rule := range rules {
		if rule.Type == "password" && filepath.Base(rule.Module) == "pam_unix.so" {
			matches = append(matches, indexedRule{index: index, rule: rule})
		}
	}
	if len(matches) == 0 {
		return nil, nil, []string{stack + "에 password pam_unix.so가 없음"}
	}

	effective := make([]string, 0, len(matches))
	unsafe := make([]string, 0)
	unknown := make([]string, 0)
	if len(matches) > 1 {
		unknown = append(unknown, stack+"의 password pam_unix.so 적용 경로가 여러 개임")
	}
	for _, match := range matches {
		rule := match.rule
		unknown = append(unknown, assessPAMUnixHashReachability(stack, rules, match.index)...)
		control := strings.ToLower(strings.TrimSpace(rule.Control))
		if control != "required" && control != "requisite" && control != "sufficient" {
			unknown = append(unknown, fmt.Sprintf("%s %s:%d pam_unix PAM 제어 흐름을 확정할 수 없음", stack, rule.Path, rule.Line))
		}
		method, overridden, err := pamUnixHashMethod(rule.Args, fallbackMethod)
		if err != nil {
			unknown = append(unknown, fmt.Sprintf("%s %s:%d pam_unix 해시 대체 설정을 해석할 수 없음", stack, rule.Path, rule.Line))
			continue
		}
		source := "login.defs"
		if overridden {
			source = fmt.Sprintf("%s:%d PAM 재정의", rule.Path, rule.Line)
		}
		description := fmt.Sprintf("%s pam_unix=%s (%s)", stack, method, source)
		effective = append(effective, description)
		if containsFold(safeMethods, method) {
			continue
		}
		if isKnownWeakMethod(method) {
			unsafe = append(unsafe, description)
		} else {
			unknown = append(unknown, description)
		}
	}
	return effective, unsafe, unknown
}

func assessPAMUnixHashReachability(stack string, rules []support.PAMRule, pamUnixIndex int) []string {
	unknowns := make([]string, 0)
	for index, rule := range rules {
		if index >= pamUnixIndex || rule.Type != "password" {
			continue
		}
		module := strings.ToLower(filepath.Base(rule.Module))
		control := strings.ToLower(strings.TrimSpace(rule.Control))
		description := fmt.Sprintf("%s %s:%d %s control=%s", stack, rule.Path, rule.Line, module, rule.Control)
		if strings.HasPrefix(control, "[") {
			unknowns = append(unknowns, description+"이 pam_unix.so를 건너뛸 수 있음")
			continue
		}
		if control == "sufficient" && module != "pam_deny.so" {
			unknowns = append(unknowns, description+"이 pam_unix.so보다 먼저 성공할 수 있음")
			continue
		}
		if control != "required" && control != "requisite" && control != "optional" {
			unknowns = append(unknowns, description+"의 PAM 제어 흐름을 확정할 수 없음")
			continue
		}
		role := passwordPAMModuleRole(module)
		if role == passwordRoleWriter {
			unknowns = append(unknowns, description+"이 pam_unix.so보다 먼저 비밀번호를 변경할 수 있음")
		} else if role == passwordRoleUnknown {
			unknowns = append(unknowns, description+"의 비밀번호 변경 여부를 확정할 수 없음")
		}
	}
	for index := pamUnixIndex + 1; index < len(rules); index++ {
		rule := rules[index]
		if rule.Type != "password" || filepath.Base(rule.Module) == "pam_unix.so" {
			continue
		}
		module := strings.ToLower(filepath.Base(rule.Module))
		role := passwordPAMModuleRole(module)
		if role == passwordRoleWriter && !knownPostUnixWriterUsesAuthtok(module, rule.Args) {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d %s가 pam_unix.so 뒤에서 비밀번호를 다시 변경할 수 있는 대체 경로가 있음", stack, rule.Path, rule.Line, module))
		} else if role == passwordRoleUnknown {
			unknowns = append(unknowns, fmt.Sprintf("%s %s:%d %s의 pam_unix.so 후속 비밀번호 변경 여부를 확정할 수 없음", stack, rule.Path, rule.Line, module))
		}
	}
	return unknowns
}

func pamUnixHashMethod(arguments []string, fallbackMethod string) (string, bool, error) {
	knownMethods := map[string]string{
		"des":           "DES",
		"md5":           "MD5",
		"bigcrypt":      "BIGCRYPT",
		"sha256":        "SHA256",
		"sha512":        "SHA512",
		"blowfish":      "BLOWFISH",
		"yescrypt":      "YESCRYPT",
		"gost_yescrypt": "GOST_YESCRYPT",
	}
	selected := ""
	for _, argument := range arguments {
		normalized := strings.ToLower(strings.TrimSpace(argument))
		if method, exists := knownMethods[normalized]; exists {
			if selected != "" && selected != method {
				return "", false, fmt.Errorf("multiple password hash methods")
			}
			selected = method
			continue
		}
		key, _, hasValue := strings.Cut(normalized, "=")
		if hasValue && (key == "crypt_style" || key == "hash" || key == "algorithm") {
			return "", false, fmt.Errorf("unsupported password hash selector")
		}
	}
	if selected == "" {
		return strings.ToUpper(strings.TrimSpace(fallbackMethod)), false, nil
	}
	return selected, true, nil
}

func readLoginDefsMethod(ctx context.Context, environment evaluator.Environment) (string, int, model.Evidence, error) {
	data, _, err := environment.Files.ReadFile(ctx, "/etc/login.defs", 1<<20)
	if err != nil {
		return "", 0, model.Evidence{}, err
	}
	method := ""
	lineNumber := 0
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := stripComment(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "ENCRYPT_METHOD") {
			method = strings.ToUpper(fields[1])
			lineNumber = index + 1
		}
	}
	if method == "" {
		return "", 0, model.Evidence{}, fmt.Errorf("ENCRYPT_METHOD is not configured")
	}
	evidence := support.FactEvidence("/etc/login.defs", map[string]any{
		"line":           lineNumber,
		"encrypt_method": method,
	})
	return method, lineNumber, evidence, nil
}

func stripComment(line string) string {
	if index := strings.IndexByte(line, '#'); index >= 0 {
		line = line[:index]
	}
	return strings.TrimSpace(line)
}

func containsToken(value, wanted string) bool {
	for _, token := range strings.FieldsFunc(value, func(character rune) bool {
		return character == ' ' || character == '\t' || character == '\r' || character == '\n' || character == ',' || character == '-'
	}) {
		if strings.EqualFold(token, wanted) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(wanted))
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(wanted)) {
			return true
		}
	}
	return false
}

func isKnownWeakHash(algorithm string) bool {
	switch strings.ToLower(algorithm) {
	case "1", "2", "2a", "2b", "2x", "2y", "legacy_or_unknown":
		return true
	default:
		return false
	}
}

func isKnownWeakMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "DES", "MD5", "BIGCRYPT", "BLOWFISH":
		return true
	default:
		return false
	}
}
