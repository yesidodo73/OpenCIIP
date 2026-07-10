package account

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	if deny < 1 || deny > 10 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "계정 잠금 임계값이 가이드 기준을 충족하지 않습니다.",
			Expected: "실패 횟수 deny가 1회 이상 10회 이하여야 합니다.",
			Observed: fmt.Sprintf("deny=%d (%s)", deny, source),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "계정 잠금 임계값이 가이드 기준을 충족합니다.",
		Expected: "실패 횟수 deny가 1회 이상 10회 이하여야 합니다.",
		Observed: fmt.Sprintf("deny=%d (%s)", deny, source),
		Evidence: evidence,
	}
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
	evidence := []model.Evidence{loginEvidence, shadowEvidence}
	activeAlgorithms := make(map[string][]string)
	for name, entry := range shadow {
		if entry.State != "active" {
			continue
		}
		activeAlgorithms[entry.Algorithm] = append(activeAlgorithms[entry.Algorithm], name)
	}
	if len(activeAlgorithms) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "활성 상태의 로컬 비밀번호 해시가 없습니다.",
			Expected: "활성 로컬 비밀번호 해시는 SHA-2 이상의 알고리즘을 사용해야 합니다.",
			Observed: fmt.Sprintf("ENCRYPT_METHOD=%s line=%d", method, line),
			Evidence: evidence,
		}
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
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "비밀번호 암호화 알고리즘이 가이드 기준을 충족합니다.",
		Expected: "신규 정책과 기존 활성 해시가 SHA-2 이상의 알고리즘을 사용해야 합니다.",
		Observed: "ENCRYPT_METHOD=" + method + ", 활성 해시 알고리즘이 모두 허용 목록에 포함됩니다.",
		Evidence: evidence,
	}
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
	case "DES", "MD5", "BLOWFISH":
		return true
	default:
		return false
	}
}
