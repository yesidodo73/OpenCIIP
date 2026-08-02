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
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorLockoutThreshold = "unix.account.lockout_threshold"
	EvaluatorPasswordHash     = "unix.account.password_hash"
	unmanagedRHELSSHProbeUser = "openciip-audit"
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
	if environment.Platform.Family == "debian" {
		return evaluateDebianLockoutThreshold(ctx, environment)
	}
	if environment.Platform.Family != "rhel" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "이 Linux 계열의 계정 잠금 적용 경로를 자동 확정할 수 없습니다.",
			Expected:      "지원되는 PAM 계정 잠금 경로를 확인할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("family=%s id=%s version=%s", environment.Platform.Family, environment.Platform.ID, environment.Platform.VersionID),
			Evidence: []model.Evidence{support.FactEvidence("platform", map[string]any{
				"family": environment.Platform.Family, "id": environment.Platform.ID, "version_id": environment.Platform.VersionID,
			})},
		}
	}
	currentSpec := executor.Spec{Name: "authselect", Arguments: []string{"current"}, Timeout: 10 * time.Second}
	current, err := environment.Commands.Run(ctx, currentSpec)
	if err != nil {
		return checkError("authselect_current_failed", err)
	}
	evidence := []model.Evidence{support.CommandEvidence(currentSpec, current)}
	if current.Truncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "authselect 관리 상태를 완전히 확인하지 못했습니다.",
			Expected:      "지원되는 authselect 프로필 또는 확정 가능한 실제 인증 경로를 확인할 수 있어야 합니다.",
			Observed:      "authselect current output truncated",
			Evidence:      evidence,
		}
	}
	if current.ExitCode != 0 {
		if authselectReportsNoConfiguration(current) {
			return evaluateUnmanagedRHELLockout(ctx, environment, evidence)
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "authselect 관리 상태를 확정할 수 없어 계정 잠금 정책을 자동 판정하지 않습니다.",
			Expected:      "지원되는 authselect 프로필 또는 확정 가능한 실제 인증 경로를 확인할 수 있어야 합니다.",
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
			Details: []model.ResultDetail{{
				Label: "계정 잠금", Current: "비활성 (with-faillock 없음)",
				Expected: "활성, 실패 허용 횟수 1~10회", Source: "authselect 프로필",
			}},
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

func authselectReportsNoConfiguration(result executor.Result) bool {
	const message = "No existing configuration detected."
	if result.ExitCode != 2 || result.Truncated || result.TimedOut {
		return false
	}
	stdout := strings.TrimSpace(string(result.Stdout))
	stderr := strings.TrimSpace(string(result.Stderr))
	return (stdout == message && stderr == "") || (stderr == message && stdout == "")
}

func evaluateUnmanagedRHELLockout(
	ctx context.Context,
	environment evaluator.Environment,
	evidence []model.Evidence,
) evaluator.Outcome {
	unknown := func(summary, observed string) evaluator.Outcome {
		return unmanagedRHELLockoutUnknown(summary, observed, evidence)
	}
	if environment.Platform.InitSystem != "systemd" {
		initSystem := strings.TrimSpace(environment.Platform.InitSystem)
		if initSystem == "" {
			initSystem = "unknown"
		}
		return unknown(
			"authselect 미구성 환경의 실제 SSH 인증 경로를 확정할 수 없습니다.",
			"init="+initSystem,
		)
	}

	sshActive, _, unitStates, serviceEvidence, err := inspectRemoteService(
		ctx,
		environment,
		sshRemoteUnitNames(),
		[]string{"sshd"},
		22,
	)
	evidence = append(evidence, serviceEvidence...)
	if err != nil {
		return checkErrorWithEvidence("unmanaged_rhel_ssh_target_failed", err, evidence)
	}
	if !sshActive {
		return unknown(
			"활성 SSH 비밀번호 인증 경로를 확인할 수 없어 다른 PAM 엔트리포인트의 잠금 정책을 수동으로 확인해야 합니다.",
			"활성 SSH unit, sshd 프로세스 또는 TCP 22 리스너 없음",
		)
	}

	launchUnits, launchEvidence, launchUnknowns, err := resolveSSHLaunchUnits(ctx, environment, unitStates)
	evidence = append(evidence, launchEvidence...)
	if err != nil {
		return checkErrorWithEvidence("unmanaged_rhel_ssh_launch_units_failed", err, evidence)
	}
	if len(launchUnknowns) > 0 || len(launchUnits) == 0 {
		return unknown(
			"활성 SSH 서비스의 실제 실행 구성을 확정할 수 없습니다.",
			strings.Join(uniqueSorted(launchUnknowns), "; "),
		)
	}

	profiles := make([]sshLaunchProfile, 0, len(launchUnits))
	profileUnknowns := make([]string, 0)
	for _, unitName := range launchUnits {
		profile, profileEvidence, reason, profileErr := inspectSSHDLaunchProfile(ctx, environment, unitName)
		evidence = append(evidence, profileEvidence...)
		if profileErr != nil {
			return checkErrorWithEvidence("unmanaged_rhel_ssh_launch_profile_failed", profileErr, evidence)
		}
		if reason != "" {
			profileUnknowns = append(profileUnknowns, unitName+": "+reason)
			continue
		}
		if profile.CustomConfiguration {
			profileUnknowns = append(profileUnknowns, unitName+": 사용자 지정 SSH 실행 구성을 사용함")
			continue
		}
		profiles = append(profiles, profile)
	}
	if len(profileUnknowns) > 0 || len(profiles) == 0 {
		return unknown(
			"활성 SSH 서비스의 표준 실행 구성을 확정할 수 없습니다.",
			strings.Join(uniqueSorted(profileUnknowns), "; "),
		)
	}

	configAmbiguous, unsafeMatch, _, configEvidence, err := inspectSSHDMatchOverrides(ctx, environment)
	evidence = append(evidence, configEvidence...)
	if err != nil {
		return unknown(
			"SSH Match 또는 Include 구성을 해석하지 못해 비밀번호 인증 경로를 확정할 수 없습니다.",
			err.Error(),
		)
	}
	if configAmbiguous || unsafeMatch {
		return unknown(
			"SSH Match 또는 사용자 지정 Include 조건 때문에 모든 비밀번호 인증 경로를 확정할 수 없습니다.",
			fmt.Sprintf("match_or_include_ambiguous=%t unsafe_match=%t", configAmbiguous, unsafeMatch),
		)
	}

	host := strings.TrimSpace(environment.Platform.Hostname)
	if host == "" || strings.ContainsAny(host, ",=\x00\r\n") {
		host = "localhost"
	}
	addresses := []string{"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1"}
	effectivePaths := make([]string, 0, len(profiles)*len(addresses))
	effectiveAuthenticationPaths := make([]string, 0, len(profiles)*len(addresses))
	for _, profile := range profiles {
		for _, address := range addresses {
			arguments := append([]string(nil), profile.ConfigurationArguments...)
			arguments = append(arguments, "-T", "-C", "user="+unmanagedRHELSSHProbeUser+",host="+host+",addr="+address)
			spec := executor.Spec{
				Name:      "sshd",
				Arguments: arguments,
				Timeout:   15 * time.Second,
				MaxOutput: 2 << 20,
			}
			result, runErr := environment.Commands.Run(ctx, spec)
			resultEvidence := support.CommandSummaryEvidence("sshd-effective-password-pam", spec, result, map[string]any{
				"unit":           profile.Unit,
				"address":        address,
				"context_user":   unmanagedRHELSSHProbeUser,
				"synthetic_user": true,
				"non_root":       true,
			})
			evidence = append(evidence, resultEvidence)
			if runErr != nil {
				return checkErrorWithEvidence("unmanaged_rhel_sshd_effective_failed", runErr, evidence)
			}
			if result.ExitCode != 0 || result.Truncated {
				return unknown(
					"SSH 실효 비밀번호 인증 설정을 완전히 확인하지 못했습니다.",
					fmt.Sprintf("%s %s exit=%d truncated=%t", profile.Unit, address, result.ExitCode, result.Truncated),
				)
			}
			settings, parseErr := parseSSHDTestOutput(string(result.Stdout))
			if parseErr != nil {
				return unknown(
					"SSH 실효 비밀번호 인증 설정을 해석하지 못했습니다.",
					profile.Unit+" "+address+": "+parseErr.Error(),
				)
			}
			usePAM, hasUsePAM := settings["usepam"]
			resultEvidence.Fact["use_pam"] = usePAM
			if passwordAuthentication, exists := settings["passwordauthentication"]; exists {
				resultEvidence.Fact["password_authentication"] = passwordAuthentication
			}
			if keyboardInteractive, exists := settings["kbdinteractiveauthentication"]; exists {
				resultEvidence.Fact["kbd_interactive_authentication"] = keyboardInteractive
			} else if challengeResponse, exists := settings["challengeresponseauthentication"]; exists {
				resultEvidence.Fact["challenge_response_authentication"] = challengeResponse
			}
			if authenticationMethods, exists := settings["authenticationmethods"]; exists {
				resultEvidence.Fact["authentication_methods"] = authenticationMethods
			}
			if !hasUsePAM {
				return unknown(
					"SSH 실효 설정에서 PAM 기반 비밀번호 인증 여부를 확인할 수 없습니다.",
					fmt.Sprintf("%s %s usepam_present=false", profile.Unit, address),
				)
			}
			if !strings.EqualFold(usePAM, "yes") {
				return unknown(
					"SSH가 PAM을 사용하지 않아 이 경로만으로 계정 잠금 정책을 확정할 수 없습니다.",
					fmt.Sprintf("%s %s usepam=%s", profile.Unit, address, usePAM),
				)
			}
			for _, settingName := range []string{"allowusers", "denyusers", "allowgroups", "denygroups"} {
				if strings.TrimSpace(settings[settingName]) == "" {
					continue
				}
				resultEvidence.Fact["access_restriction"] = settingName
				return unknown(
					"SSH 전역 사용자 또는 그룹 제한 때문에 합성 비-root 사용자의 실제 인증 도달성을 확정할 수 없습니다.",
					fmt.Sprintf("%s %s access_restriction=%s", profile.Unit, address, settingName),
				)
			}
			pamAuthenticationPath, reason := inspectSSHPAMPasswordPath(settings)
			if reason != "" {
				return unknown(
					"SSH의 실제 PAM 비밀번호 인증 순서를 확정할 수 없습니다.",
					fmt.Sprintf("%s %s %s", profile.Unit, address, reason),
				)
			}
			resultEvidence.Fact["pam_password_path"] = pamAuthenticationPath
			effectivePaths = append(effectivePaths, profile.Unit+" "+address)
			effectiveAuthenticationPaths = append(effectiveAuthenticationPaths, pamAuthenticationPath)
		}
	}

	_, pamEvidence, err := support.ReadPAMService(ctx, environment.Files, "sshd")
	evidence = append(evidence, pamEvidence...)
	if err != nil {
		return unknown(
			"SSH PAM include 및 substack 경로를 완전히 해석하지 못했습니다.",
			err.Error(),
		)
	}
	pamUnixSource, pamReason := inspectUnmanagedRHELLocalPAMPath(ctx, environment.Files, pamEvidence)
	if pamReason != "" {
		return unknown(
			"SSH PAM 경로에서 로컬 계정 잠금 정책의 부재를 확정할 수 없습니다.",
			pamReason,
		)
	}

	sort.Strings(effectivePaths)
	effectiveUnits := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		effectiveUnits = append(effectiveUnits, profile.Unit)
	}
	effectiveUnits = uniqueSorted(effectiveUnits)
	pathSource := strings.Join(effectiveUnits, ", ") + " → /etc/pam.d/sshd → " + pamUnixSource
	return evaluator.Outcome{
		Status:   model.StatusFail,
		Summary:  "활성 SSH 비밀번호 인증 경로에 계정 잠금 정책이 적용되어 있지 않습니다.",
		Expected: "실패 허용 횟수가 1회 이상 10회 이하가 되도록 실제 PAM 인증 경로에 계정 잠금 모듈이 적용되어야 합니다.",
		Observed: strings.Join([]string{
			"authselect 미구성",
			fmt.Sprintf("도달 가능한 SSH PAM 비밀번호 인증 조건=%d개", len(effectivePaths)),
			"SSH 인증 방식=" + strings.Join(uniqueSorted(effectiveAuthenticationPaths), ", "),
			"로컬 pam_unix.so 인증 경로=" + pamUnixSource,
			"pam_faillock.so/pam_tally2.so 없음",
		}, "; "),
		Details: []model.ResultDetail{{
			Label:    "SSH 계정 잠금",
			Current:  "활성 로컬 비밀번호 인증 경로에 잠금 모듈 없음",
			Expected: "실패 허용 횟수 1~10회",
			Source:   pathSource,
		}},
		Evidence: evidence,
	}
}

func inspectSSHPAMPasswordPath(settings map[string]string) (string, string) {
	authenticationMethods, exists := settings["authenticationmethods"]
	authenticationMethods = strings.ToLower(strings.TrimSpace(authenticationMethods))
	if !exists || authenticationMethods == "" {
		return "", "authenticationmethods 누락"
	}

	passwordEnabled := strings.EqualFold(strings.TrimSpace(settings["passwordauthentication"]), "yes")
	keyboardInteractive := settings["kbdinteractiveauthentication"]
	if strings.TrimSpace(keyboardInteractive) == "" {
		keyboardInteractive = settings["challengeresponseauthentication"]
	}
	keyboardInteractiveEnabled := strings.EqualFold(strings.TrimSpace(keyboardInteractive), "yes")

	alternatives := strings.Fields(authenticationMethods)
	if len(alternatives) == 1 && alternatives[0] == "any" {
		switch {
		case passwordEnabled:
			return "AuthenticationMethods=any → password", ""
		case keyboardInteractiveEnabled:
			return "AuthenticationMethods=any → keyboard-interactive(PAM)", ""
		default:
			return "", fmt.Sprintf(
				"authenticationmethods=any passwordauthentication=%s kbdinteractiveauthentication=%s",
				sshdSettingValue(settings, "passwordauthentication"),
				sshdKeyboardInteractiveSettingValue(settings),
			)
		}
	}
	for _, alternative := range alternatives {
		if alternative == "any" {
			return "", "authenticationmethods에서 any와 다른 인증 순서를 함께 사용함"
		}
	}

	for _, alternative := range alternatives {
		methods := strings.Split(alternative, ",")
		if len(methods) == 0 {
			continue
		}
		switch strings.TrimSpace(methods[0]) {
		case "password":
			if !passwordEnabled {
				continue
			}
			return "AuthenticationMethods=" + alternative, ""
		case "keyboard-interactive", "keyboard-interactive:pam":
			if !keyboardInteractiveEnabled {
				continue
			}
			return "AuthenticationMethods=" + alternative, ""
		}
	}

	return "", fmt.Sprintf(
		"authenticationmethods=%s passwordauthentication=%s kbdinteractiveauthentication=%s; 도달 가능한 PAM 비밀번호 인증 순서 없음",
		authenticationMethods,
		sshdSettingValue(settings, "passwordauthentication"),
		sshdKeyboardInteractiveSettingValue(settings),
	)
}

func sshdSettingValue(settings map[string]string, name string) string {
	value, exists := settings[name]
	value = strings.TrimSpace(value)
	if !exists || value == "" {
		return "missing"
	}
	return strings.ToLower(value)
}

func sshdKeyboardInteractiveSettingValue(settings map[string]string) string {
	if value := sshdSettingValue(settings, "kbdinteractiveauthentication"); value != "missing" {
		return value
	}
	return sshdSettingValue(settings, "challengeresponseauthentication")
}

type unmanagedPAMEntry struct {
	Path          string
	Line          int
	Type          string
	Control       string
	Module        string
	IgnoreMissing bool
}

type unmanagedPAMExpectation struct {
	Control string
	Module  string
}

func inspectUnmanagedRHELLocalPAMPath(
	ctx context.Context,
	files system.Reader,
	evidence []model.Evidence,
) (string, string) {
	allowedServices := map[string]bool{
		"/etc/pam.d/sshd":          true,
		"/etc/pam.d/password-auth": true,
		"/etc/pam.d/system-auth":   true,
		"/etc/pam.d/postlogin":     true,
	}
	for _, item := range evidence {
		source := filepath.ToSlash(strings.TrimSpace(item.Source))
		if strings.HasPrefix(source, "/etc/pam.d/") && !allowedServices[source] {
			return "", "사용자 지정 PAM include/substack 경로: " + source
		}
	}

	entriesByPath := make(map[string][]unmanagedPAMEntry, 3)
	for _, path := range []string{
		"/etc/pam.d/sshd",
		"/etc/pam.d/password-auth",
		"/etc/pam.d/postlogin",
	} {
		entries, err := readUnmanagedPAMEntries(ctx, files, path)
		if err != nil {
			return "", err.Error()
		}
		entriesByPath[path] = entries
		for _, entry := range entries {
			if entry.Type == "@include" {
				return "", fmt.Sprintf(
					"%s:%d 전역 @include 경계는 자동 확정하지 않음: %s",
					entry.Path,
					entry.Line,
					entry.Module,
				)
			}
			switch entry.Type {
			case "auth", "account", "password", "session":
			default:
				return "", fmt.Sprintf(
					"%s:%d 알 수 없는 PAM type=%s",
					entry.Path,
					entry.Line,
					entry.Type,
				)
			}
		}
	}

	sshdAuth := unmanagedPAMEntriesOfType(entriesByPath["/etc/pam.d/sshd"], "auth")
	if reason := requireUnmanagedPAMSequence(
		"/etc/pam.d/sshd",
		"auth",
		sshdAuth,
		[]unmanagedPAMExpectation{
			{Control: "substack", Module: "password-auth"},
			{Control: "include", Module: "postlogin"},
		},
	); reason != "" {
		return "", reason
	}
	sshdAccount := unmanagedPAMEntriesOfType(entriesByPath["/etc/pam.d/sshd"], "account")
	if reason := requireUnmanagedPAMSequence(
		"/etc/pam.d/sshd",
		"account",
		sshdAccount,
		[]unmanagedPAMExpectation{
			{Control: "required", Module: "pam_sepermit.so"},
			{Control: "required", Module: "pam_nologin.so"},
			{Control: "include", Module: "password-auth"},
		},
	); reason != "" {
		return "", reason
	}

	passwordAuth := unmanagedPAMEntriesOfType(entriesByPath["/etc/pam.d/password-auth"], "auth")
	if reason := validateUnmanagedPasswordAuthOrder(passwordAuth); reason != "" {
		return "", reason
	}
	if reason := requireUnmanagedPAMSequence(
		"/etc/pam.d/password-auth",
		"auth",
		passwordAuth,
		[]unmanagedPAMExpectation{
			{Control: "required", Module: "pam_env.so"},
			{Control: "sufficient", Module: "pam_unix.so"},
			{Control: "required", Module: "pam_deny.so"},
		},
	); reason != "" {
		return "", reason
	}
	passwordAccount := unmanagedPAMEntriesOfType(entriesByPath["/etc/pam.d/password-auth"], "account")
	if reason := requireUnmanagedPAMSequence(
		"/etc/pam.d/password-auth",
		"account",
		passwordAccount,
		[]unmanagedPAMExpectation{{Control: "required", Module: "pam_unix.so"}},
	); reason != "" {
		return "", reason
	}

	for _, ruleType := range []string{"auth", "account"} {
		postlogin := unmanagedPAMEntriesOfType(entriesByPath["/etc/pam.d/postlogin"], ruleType)
		if len(postlogin) > 0 {
			return "", fmt.Sprintf(
				"/etc/pam.d/postlogin %s 경로가 비어 있지 않음: %s",
				ruleType,
				summarizeUnmanagedPAMEntries(postlogin),
			)
		}
	}

	return fmt.Sprintf("%s:%d", passwordAuth[1].Path, passwordAuth[1].Line), ""
}

func validateUnmanagedPasswordAuthOrder(entries []unmanagedPAMEntry) string {
	pamUnixIndex := -1
	pamDenyIndex := -1
	pamUnixCount := 0
	pamDenyCount := 0
	for index, entry := range entries {
		switch entry.Module {
		case "pam_unix.so":
			pamUnixCount++
			pamUnixIndex = index
		case "pam_deny.so":
			pamDenyCount++
			pamDenyIndex = index
		}
	}
	summary := summarizeUnmanagedPAMEntries(entries)
	if pamUnixCount != 1 {
		return fmt.Sprintf(
			"/etc/pam.d/password-auth auth에서 pam_unix.so 경로 수=%d, 예상=1: %s",
			pamUnixCount,
			summary,
		)
	}
	if pamDenyCount != 1 {
		return fmt.Sprintf(
			"/etc/pam.d/password-auth auth에서 pam_unix.so 이후 단일 pam_deny.so 인증 종료 경로가 없음(count=%d): %s",
			pamDenyCount,
			summary,
		)
	}
	if pamDenyIndex < pamUnixIndex {
		return fmt.Sprintf(
			"%s:%d pam_deny.so가 pam_unix.so보다 먼저 실행됨: %s",
			entries[pamDenyIndex].Path,
			entries[pamDenyIndex].Line,
			summary,
		)
	}
	if entries[pamUnixIndex].Path != entries[pamDenyIndex].Path {
		return fmt.Sprintf(
			"pam_unix.so와 pam_deny.so가 서로 다른 PAM 파일에 있음: %s",
			summary,
		)
	}
	return ""
}

func readUnmanagedPAMEntries(
	ctx context.Context,
	files system.Reader,
	path string,
) ([]unmanagedPAMEntry, error) {
	metadata, err := files.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat %s topology: %w", path, err)
	}
	if metadata.FileType != "regular" {
		return nil, fmt.Errorf("%s topology file type=%s, regular 필요", path, metadata.FileType)
	}
	data, _, err := files.ReadFile(ctx, path, 2<<20)
	if err != nil {
		return nil, fmt.Errorf("read %s topology: %w", path, err)
	}

	entries := make([]unmanagedPAMEntry, 0)
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		lineNumber := index + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			return nil, fmt.Errorf("%s:%d PAM continuation은 자동 확정하지 않음", path, lineNumber)
		}
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = strings.TrimSpace(line[:comment])
		}
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 0 && strings.TrimPrefix(fields[0], "-") == "@include" {
			if len(fields) != 2 || strings.HasPrefix(fields[0], "-") {
				return nil, fmt.Errorf("%s:%d @include 구조를 확정할 수 없음", path, lineNumber)
			}
			entries = append(entries, unmanagedPAMEntry{
				Path: path, Line: lineNumber, Type: "@include", Control: "include", Module: fields[1],
			})
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("%s:%d PAM 규칙 구조를 확정할 수 없음", path, lineNumber)
		}

		controlEnd := 1
		if strings.HasPrefix(fields[1], "[") {
			for controlEnd < len(fields) && !strings.HasSuffix(fields[controlEnd], "]") {
				controlEnd++
			}
			if controlEnd >= len(fields) || !strings.HasSuffix(fields[controlEnd], "]") {
				return nil, fmt.Errorf("%s:%d 복합 PAM 제어가 닫히지 않음", path, lineNumber)
			}
		}
		moduleIndex := controlEnd + 1
		if moduleIndex >= len(fields) {
			return nil, fmt.Errorf("%s:%d PAM module이 없음", path, lineNumber)
		}
		entries = append(entries, unmanagedPAMEntry{
			Path:          path,
			Line:          lineNumber,
			Type:          strings.TrimPrefix(fields[0], "-"),
			Control:       strings.Join(fields[1:moduleIndex], " "),
			Module:        fields[moduleIndex],
			IgnoreMissing: strings.HasPrefix(fields[0], "-"),
		})
	}
	return entries, nil
}

func unmanagedPAMEntriesOfType(entries []unmanagedPAMEntry, ruleType string) []unmanagedPAMEntry {
	filtered := make([]unmanagedPAMEntry, 0)
	for _, entry := range entries {
		if entry.Type == ruleType {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func requireUnmanagedPAMSequence(
	path string,
	ruleType string,
	entries []unmanagedPAMEntry,
	expected []unmanagedPAMExpectation,
) string {
	if len(entries) != len(expected) {
		return fmt.Sprintf(
			"%s %s topology 항목 수=%d, 예상=%d: %s",
			path,
			ruleType,
			len(entries),
			len(expected),
			summarizeUnmanagedPAMEntries(entries),
		)
	}
	for index, want := range expected {
		entry := entries[index]
		if entry.IgnoreMissing {
			return fmt.Sprintf(
				"%s:%d auth/account PAM type의 '-' 접두어는 자동 확정하지 않음",
				entry.Path,
				entry.Line,
			)
		}
		if strings.HasPrefix(entry.Control, "[") {
			return fmt.Sprintf("%s:%d 복합 PAM 제어=%s", entry.Path, entry.Line, entry.Control)
		}
		if entry.Control != want.Control || entry.Module != want.Module {
			return fmt.Sprintf(
				"%s %s topology 순서 %d 불일치: %s:%d %s %s, 예상=%s %s",
				path,
				ruleType,
				index+1,
				entry.Path,
				entry.Line,
				entry.Control,
				entry.Module,
				want.Control,
				want.Module,
			)
		}
	}
	return ""
}

func summarizeUnmanagedPAMEntries(entries []unmanagedPAMEntry) string {
	if len(entries) == 0 {
		return "없음"
	}
	summary := make([]string, 0, len(entries))
	for _, entry := range entries {
		summary = append(summary, fmt.Sprintf(
			"%s:%d %s %s",
			entry.Path,
			entry.Line,
			entry.Control,
			entry.Module,
		))
	}
	return strings.Join(summary, "; ")
}

func unmanagedRHELLockoutUnknown(summary, observed string, evidence []model.Evidence) evaluator.Outcome {
	if strings.TrimSpace(observed) == "" {
		observed = "확정 가능한 활성 SSH PAM 경로 없음"
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       summary,
		Expected:      "활성 비밀번호 인증 엔트리포인트의 PAM 경로에서 실패 허용 횟수 1~10회를 확인할 수 있어야 합니다.",
		Observed:      observed,
		Evidence:      append([]model.Evidence(nil), evidence...),
	}
}

func checkErrorWithEvidence(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	outcome := checkError(code, err)
	outcome.Evidence = append([]model.Evidence(nil), evidence...)
	return outcome
}

func evaluateDebianLockoutThreshold(ctx context.Context, environment evaluator.Environment) evaluator.Outcome {
	stackNames := []string{"common-auth", "common-account"}
	stacks, evidence, err := readPolicyPAMStacks(ctx, environment, stackNames...)
	if err != nil {
		return checkError("pam_lockout_stack_failed", err)
	}
	evidence = append([]model.Evidence{support.FactEvidence("PAM policy platform", map[string]any{
		"family":         environment.Platform.Family,
		"id":             environment.Platform.ID,
		"version_id":     environment.Platform.VersionID,
		"lockout_stacks": append([]string(nil), stackNames...),
	})}, evidence...)

	modules := make([]string, 0)
	for _, stack := range stackNames {
		for _, pamRule := range stacks[stack] {
			module := strings.ToLower(filepath.Base(pamRule.Module))
			if module != "pam_faillock.so" && module != "pam_tally2.so" {
				continue
			}
			modules = append(modules, fmt.Sprintf("%s %s:%d %s %s",
				stack, pamRule.Path, pamRule.Line, module, strings.Join(pamRule.Args, " ")))
		}
	}
	if len(modules) == 0 {
		unresolvedPaths := unresolvedDebianLockoutPaths(stackNames, stacks)
		if len(unresolvedPaths) > 0 {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "외부 또는 사용자 정의 PAM 인증 경로가 있어 계정 잠금 정책의 실효 적용 상태를 확정할 수 없습니다.",
				Expected:      "모든 적용 인증 경로에서 실패 허용 횟수가 1~10회여야 합니다.",
				Observed:      "공통 PAM 잠금 모듈 없음; 확인이 필요한 인증 경로: " + strings.Join(unresolvedPaths, "; "),
				Evidence:      evidence,
			}
		}
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "공통 PAM 인증 경로에 계정 잠금 정책이 적용되어 있지 않습니다.",
			Expected: "인증 실패 횟수가 10회 이하가 되도록 공통 PAM 경로에 계정 잠금 모듈이 적용되어야 합니다.",
			Observed: "common-auth와 common-account에 pam_faillock.so 또는 pam_tally2.so 없음",
			Details: []model.ResultDetail{{
				Label: "계정 잠금", Current: "공통 PAM 잠금 모듈 없음",
				Expected: "실패 허용 횟수 1~10회", Source: "/etc/pam.d/common-auth, /etc/pam.d/common-account",
			}},
			Evidence: evidence,
		}
	}
	sort.Strings(modules)
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       "Debian 계열 PAM 잠금 모듈의 전체 실효 제어 흐름을 아직 자동 확정할 수 없습니다.",
		Expected:      "모든 적용 인증 경로에서 실패 허용 횟수가 1~10회여야 합니다.",
		Observed:      strings.Join(uniqueSorted(modules), "; "),
		Evidence:      evidence,
	}
}

func unresolvedDebianLockoutPaths(stackNames []string, stacks map[string][]support.PAMRule) []string {
	paths := make([]string, 0)
	for _, stack := range stackNames {
		for _, pamRule := range stacks[stack] {
			if pamRule.Type != "auth" && pamRule.Type != "account" {
				continue
			}
			module := strings.ToLower(filepath.Base(pamRule.Module))
			if knownLocalDebianLockoutModule(module) {
				continue
			}
			paths = append(paths, fmt.Sprintf("%s %s:%d %s", stack, pamRule.Path, pamRule.Line, module))
		}
	}
	return uniqueSorted(paths)
}

func knownLocalDebianLockoutModule(module string) bool {
	switch module {
	case "pam_unix.so", "pam_faillock.so", "pam_tally2.so",
		"pam_deny.so", "pam_permit.so", "pam_cap.so", "pam_env.so",
		"pam_faildelay.so", "pam_securetty.so", "pam_nologin.so", "pam_rootok.so",
		"pam_localuser.so", "pam_usertype.so", "pam_succeed_if.so",
		"pam_warn.so", "pam_debug.so", "pam_echo.so", "pam_access.so",
		"pam_time.so", "pam_shells.so", "pam_group.so", "pam_listfile.so",
		"pam_issue.so", "pam_limits.so":
		return true
	default:
		return false
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
	pamStackNames := make([]string, 0, 2)
	switch environment.Platform.Family {
	case "rhel":
		pamStackNames = append(pamStackNames, "system-auth", "password-auth")
	case "debian":
		pamStackNames = append(pamStackNames, "common-password")
	default:
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "이 Linux 계열의 비밀번호 해시 적용 경로를 자동 확정할 수 없습니다.",
			Expected:      "지원되는 PAM 비밀번호 스택과 해시 정책을 확인할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("family=%s id=%s version=%s", environment.Platform.Family, environment.Platform.ID, environment.Platform.VersionID),
			Evidence: []model.Evidence{support.FactEvidence("platform", map[string]any{
				"family": environment.Platform.Family, "id": environment.Platform.ID, "version_id": environment.Platform.VersionID,
			})},
		}
	}
	method, line, loginEvidence, err := readLoginDefsMethod(ctx, environment)
	if err != nil {
		return checkError("login_defs_read_failed", err)
	}
	shadow, shadowEvidence, err := support.ReadShadowSummary(ctx, environment.Files)
	if err != nil {
		return checkError("shadow_read_failed", err)
	}
	pamStacks, pamEvidence, err := readPolicyPAMStacks(ctx, environment, pamStackNames...)
	if err != nil {
		return checkError("pam_password_hash_stack_failed", err)
	}
	evidence := []model.Evidence{loginEvidence, shadowEvidence}
	evidence = append(evidence, support.FactEvidence("PAM policy platform", map[string]any{
		"family":          environment.Platform.Family,
		"id":              environment.Platform.ID,
		"version_id":      environment.Platform.VersionID,
		"password_stacks": append([]string(nil), pamStackNames...),
	}))
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
	for _, stack := range pamStackNames {
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
		if !supportedPAMUnixHashControl(control) {
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

func supportedPAMUnixHashControl(control string) bool {
	switch control {
	case "required", "requisite", "sufficient", "optional":
		return true
	}
	if !strings.HasPrefix(control, "[") || !strings.HasSuffix(control, "]") {
		return false
	}
	_, valid := pamControlActions(control)
	return valid
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
