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

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
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

	pamStacks := make([]string, 0, 1)
	evidence := make([]model.Evidence, 0)
	switch environment.Platform.Family {
	case "rhel":
		pamStacks = append(pamStacks, "system-auth")
	case "debian":
		pamStacks = append(pamStacks, "common-password")
	default:
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "이 Linux 계열의 비밀번호 정책 적용 경로를 자동 확정할 수 없습니다.",
			Expected:      "지원되는 PAM 비밀번호 정책 경로를 확인할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("family=%s id=%s version=%s", environment.Platform.Family, environment.Platform.ID, environment.Platform.VersionID),
			Evidence: []model.Evidence{support.FactEvidence("platform", map[string]any{
				"family": environment.Platform.Family, "id": environment.Platform.ID, "version_id": environment.Platform.VersionID,
			})},
		}
	}
	evidence = append(evidence, support.FactEvidence("PAM policy platform", map[string]any{
		"family": environment.Platform.Family, "id": environment.Platform.ID,
		"version_id": environment.Platform.VersionID, "password_stacks": append([]string(nil), pamStacks...),
	}))

	pwquality := make(map[string]configSetting)
	pwhistory := make(map[string]configSetting)
	if len(pamStacks) > 0 {
		var pwqualityEvidence []model.Evidence
		pwquality, pwqualityEvidence, err = readPWQualitySettings(ctx, environment)
		if err != nil {
			return checkError("pwquality_config_failed", err)
		}
		evidence = append(evidence, pwqualityEvidence...)
		var historyEvidence model.Evidence
		pwhistory, historyEvidence, err = readSimpleSecurityConfig(ctx, environment, "/etc/security/pwhistory.conf")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return checkError("pwhistory_config_failed", err)
		}
		if err == nil {
			evidence = append(evidence, historyEvidence)
		}
	}
	loginDefs, loginEvidence, err := readLoginDefsSettings(ctx, environment, []string{"PASS_MIN_DAYS", "PASS_MAX_DAYS"})
	if err != nil {
		return checkError("login_defs_read_failed", err)
	}
	evidence = append(evidence, loginEvidence)

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
	lengthDetails := make([]model.ResultDetail, 0)
	confirmedDetails := make([]model.ResultDetail, 0)
	qualityMissing := make([]string, 0)
	classFindings := make([]string, 0)
	rootQualityMissing := make([]string, 0)
	historyMissing := make([]string, 0)
	historyCountFindings := make([]string, 0)
	historyCountSources := make([]string, 0)
	rootHistoryMissing := make([]string, 0)
	historyFileFindings := make([]string, 0)
	pamFlowFindings := make([]string, 0)
	var loginPeriodDetail *model.ResultDetail
	for _, stack := range pamStacks {
		rules := pamRules[stack]
		flowViolations, flowUnknowns := passwordPolicyModuleOrderFindings(stack, rules)
		stackViolations := append([]string(nil), flowViolations...)
		unknowns = append(unknowns, flowUnknowns...)
		pamFlowFindings = append(pamFlowFindings, flowViolations...)

		qualityRule, state := singlePasswordModule(rules, "pam_pwquality.so")
		switch state {
		case moduleMissing:
			finding := stack + "에 pam_pwquality가 없음"
			stackViolations = append(stackViolations, finding)
			qualityMissing = append(qualityMissing, fmt.Sprintf("%s 인증 설정에서 비밀번호 품질 검사 모듈(pam_pwquality)을 찾지 못했습니다.", stack))
		case moduleAmbiguous:
			unknowns = append(unknowns, stack+"의 pam_pwquality 적용 경로가 여러 개임")
		case modulePresent:
			qualitySettings, overrideErr := applyPAMSettingOverrides(pwquality, qualityRule.Args, pwqualityOptionKeys())
			if overrideErr != nil {
				unknowns = append(unknowns, stack+"의 pam_pwquality 대체 설정을 해석할 수 없음: "+overrideErr.Error())
			} else {
				minimumLengthValue, ok := integerSetting(qualitySettings, "minlen")
				if !ok {
					unknowns = append(unknowns, stack+"의 pwquality minlen을 확인할 수 없음")
				} else {
					detail := model.ResultDetail{
						Label: "비밀번호 길이", Current: fmt.Sprintf("%s %d자", stack, minimumLengthValue),
						Expected: fmt.Sprintf("%d자 이상", minimumLength), Source: passwordSettingSource(qualitySettings["minlen"], qualityRule),
					}
					confirmedDetails = append(confirmedDetails, detail)
					if minimumLengthValue < minimumLength {
						stackViolations = append(stackViolations, fmt.Sprintf("%s minlen=%d", stack, minimumLengthValue))
						lengthDetails = append(lengthDetails, detail)
					}
				}
				classCount := exactRequiredClassCount(qualitySettings)
				confirmedDetails = append(confirmedDetails, model.ResultDetail{
					Label: "문자 종류", Current: fmt.Sprintf("%s 필수 %d개", stack, classCount),
					Expected: fmt.Sprintf("%d개 이상", requiredClasses), Source: "PAM 및 pwquality 설정",
				})
				if classCount < requiredClasses {
					stackViolations = append(stackViolations, fmt.Sprintf("%s 필수 문자 종류=%d", stack, classCount))
					classFindings = append(classFindings, fmt.Sprintf("%s %d개", stack, classCount))
				}
				if !booleanSetting(qualitySettings, "enforce_for_root") {
					stackViolations = append(stackViolations, stack+"의 pwquality enforce_for_root 없음")
					rootQualityMissing = append(rootQualityMissing, stack)
				}
			}
		}

		historyRule, state := singlePasswordModule(rules, "pam_pwhistory.so")
		switch state {
		case moduleMissing:
			finding := stack + "에 pam_pwhistory가 없음"
			stackViolations = append(stackViolations, finding)
			historyMissing = append(historyMissing, fmt.Sprintf("%s 인증 설정에서 이전 비밀번호 재사용을 제한하는 모듈(pam_pwhistory)을 찾지 못했습니다.", stack))
		case moduleAmbiguous:
			unknowns = append(unknowns, stack+"의 pam_pwhistory 적용 경로가 여러 개임")
		case modulePresent:
			historySettings, overrideErr := applyPAMSettingOverrides(pwhistory, historyRule.Args, pwhistoryOptionKeys())
			if overrideErr != nil {
				unknowns = append(unknowns, stack+"의 pam_pwhistory 대체 설정을 해석할 수 없음: "+overrideErr.Error())
			} else {
				remember, rememberKnown := integerSetting(historySettings, "remember")
				if !rememberKnown {
					unknowns = append(unknowns, stack+"의 비밀번호 이력 remember를 확인할 수 없음")
				} else {
					source := passwordSettingSource(historySettings["remember"], historyRule)
					confirmedDetails = append(confirmedDetails, model.ResultDetail{
						Label: "비밀번호 이력 횟수", Current: fmt.Sprintf("%s remember=%d", stack, remember),
						Expected: fmt.Sprintf("remember=%d 이상", historyCount), Source: source,
					})
					if remember < historyCount {
						stackViolations = append(stackViolations, fmt.Sprintf("%s remember=%d", stack, remember))
						historyCountFindings = append(historyCountFindings, fmt.Sprintf("%s remember=%d", stack, remember))
						historyCountSources = append(historyCountSources, source)
					}
				}
				if environment.Platform.Family == "rhel" && !booleanSetting(historySettings, "enforce_for_root") {
					stackViolations = append(stackViolations, stack+"의 pwhistory enforce_for_root 없음")
					rootHistoryMissing = append(rootHistoryMissing, stack)
				}
				if environment.Platform.Family == "rhel" {
					historyFile := strings.TrimSpace(historySettings["file"].Value)
					if historyFile != "/etc/security/opasswd" {
						if historyFile == "" {
							historyFile = "설정 없음"
						}
						stackViolations = append(stackViolations, stack+" pwhistory file="+historyFile)
						historyFileFindings = append(historyFileFindings, stack+" "+historyFile)
					}
				}
			}
		}
		violations = append(violations, stackViolations...)
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
		if passMin < minimumDays || passMax > maximumDays || passMax < minimumDays {
			loginPeriodDetail = &model.ResultDetail{
				Label: "계정 생성 시 사용 기간 기본값", Current: fmt.Sprintf("PASS_MIN_DAYS=%d  PASS_MAX_DAYS=%d", passMin, passMax),
				Expected: fmt.Sprintf("최소 %d일 / 최대 %d일", minimumDays, maximumDays), Source: "/etc/login.defs",
			}
		}
	}

	details := append([]model.ResultDetail(nil), lengthDetails...)
	pamSources := make([]string, 0, len(pamStacks))
	for _, stack := range pamStacks {
		pamSources = append(pamSources, "/etc/pam.d/"+stack)
	}
	if len(qualityMissing) > 0 {
		details = append(details, model.ResultDetail{Label: "비밀번호 품질 모듈", Current: strings.Join(uniqueSorted(qualityMissing), "\n"), Expected: "비밀번호를 변경할 때 적용되는 PAM 인증 설정에서 비밀번호 품질 검사 모듈(pam_pwquality)을 사용해야 합니다.", Source: strings.Join(pamSources, ", ")})
	}
	if len(classFindings) > 0 {
		details = append(details, model.ResultDetail{Label: "문자 종류", Current: strings.Join(uniqueSorted(classFindings), ", "), Expected: fmt.Sprintf("%d개", requiredClasses), Source: strings.Join(pamStacks, ", ")})
	}
	if len(historyMissing) > 0 {
		details = append(details, model.ResultDetail{Label: "비밀번호 이력", Current: strings.Join(uniqueSorted(historyMissing), "\n"), Expected: fmt.Sprintf("최근 %d회 사용한 비밀번호의 재사용을 제한해야 합니다.", historyCount), Source: strings.Join(pamSources, ", ")})
	}
	if len(historyCountFindings) > 0 {
		details = append(details, model.ResultDetail{
			Label: "비밀번호 이력 횟수", Current: strings.Join(uniqueSorted(historyCountFindings), ", "),
			Expected: fmt.Sprintf("remember=%d 이상", historyCount), Source: strings.Join(uniqueSorted(historyCountSources), ", "),
		})
	}
	if len(rootQualityMissing) > 0 {
		details = append(details, model.ResultDetail{Label: "root 정책 적용", Current: strings.Join(uniqueSorted(rootQualityMissing), ", ") + "에서 강제되지 않음", Expected: "root에도 품질 정책 강제", Source: "pam_pwquality enforce_for_root"})
	}
	if len(rootHistoryMissing) > 0 {
		details = append(details, model.ResultDetail{Label: "root 이력 정책", Current: strings.Join(uniqueSorted(rootHistoryMissing), ", ") + "에서 강제되지 않음", Expected: "root에도 이력 정책 강제", Source: "pam_pwhistory enforce_for_root"})
	}
	if len(historyFileFindings) > 0 {
		details = append(details, model.ResultDetail{Label: "비밀번호 이력 파일", Current: strings.Join(uniqueSorted(historyFileFindings), ", "), Expected: "/etc/security/opasswd", Source: "pam_pwhistory file"})
	}
	if len(pamFlowFindings) > 0 {
		details = append(details, model.ResultDetail{
			Label: "PAM 적용 경로", Current: strings.Join(uniqueSorted(pamFlowFindings), "; "),
			Expected: "품질·이력 검사를 우회하지 않고 검증된 비밀번호 토큰으로 변경", Source: strings.Join(pamStacks, ", "),
		})
	}
	if loginPeriodDetail != nil {
		details = append(details, *loginPeriodDetail)
	}

	sort.Strings(violations)
	sort.Strings(unknowns)
	expected := fmt.Sprintf("길이 %d자 이상, 문자 종류 %d개, 이력 %d회, 사용 기간 %d~%d일 정책이 모든 적용 계정에 유효해야 합니다.", minimumLength, requiredClasses, historyCount, minimumDays, maximumDays)
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "비밀번호 관리 정책이 가이드 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: strings.Join(uniqueSorted(violations), "\n"),
			Details:  details,
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "일부 비밀번호 정책 설정을 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      strings.Join(uniqueSorted(unknowns), "\n"),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "비밀번호 관리 정책이 가이드의 Linux 설정 기준을 충족합니다.",
		Expected: expected,
		Observed: "pwquality, pwhistory, PAM 모듈 순서와 login.defs 설정이 기준을 충족합니다.",
		Details: append(confirmedDetails, model.ResultDetail{
			Label: "계정 생성 시 사용 기간 기본값", Current: fmt.Sprintf("PASS_MIN_DAYS=%d  PASS_MAX_DAYS=%d", passMin, passMax),
			Expected: fmt.Sprintf("최소 %d일 / 최대 %d일", minimumDays, maximumDays), Source: "/etc/login.defs",
		}),
		Evidence: evidence,
	}
}

func pamRuleSource(rule support.PAMRule) string {
	if rule.Line <= 0 {
		return rule.Path
	}
	return fmt.Sprintf("%s:%d", rule.Path, rule.Line)
}

func passwordSettingSource(setting configSetting, rule support.PAMRule) string {
	if setting.Source == "PAM module argument" {
		return pamRuleSource(rule)
	}
	if setting.Line <= 0 {
		return setting.Source
	}
	return fmt.Sprintf("%s:%d", setting.Source, setting.Line)
}

func assessPasswordPolicyPAMFlow(stack string, rules []support.PAMRule) ([]string, []string) {
	return assessPasswordPolicyPAMFlowWithAlternatives(stack, rules, false)
}

func assessPasswordPolicyPAMFlowWithAlternatives(stack string, rules []support.PAMRule, standardPolicyUncertain bool) ([]string, []string) {
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	qualitySeen := false
	historySeen := false
	pamUnixCount := 0
	for _, rule := range rules {
		if rule.Type != "password" {
			continue
		}
		module := strings.ToLower(filepath.Base(rule.Module))
		switch module {
		case "pam_pwquality.so":
			qualitySeen = true
			continue
		case "pam_pwhistory.so":
			if !qualitySeen {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_pwhistory.so가 pam_pwquality.so보다 먼저 실행됨", stack, rule.Path, rule.Line))
			}
			if !hasPAMArgument(rule.Args, "use_authtok") {
				unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_pwhistory.so가 이전 정책 모듈의 비밀번호 토큰을 강제하지 않음", stack, rule.Path, rule.Line))
			}
			historySeen = true
			continue
		}
		if module == "pam_unix.so" {
			pamUnixCount++
			if !qualitySeen || !historySeen {
				finding := fmt.Sprintf("%s %s:%d pam_unix.so가 pwquality/pwhistory보다 먼저 실행됨", stack, rule.Path, rule.Line)
				if standardPolicyUncertain {
					unknowns = append(unknowns, finding+"; 대체 경로의 정책 적용 순서를 확인해야 함")
				} else {
					violations = append(violations, finding)
				}
			} else {
				control := strings.ToLower(strings.TrimSpace(rule.Control))
				if control != "required" && control != "requisite" && control != "sufficient" {
					unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_unix.so 제어 흐름을 확정할 수 없음", stack, rule.Path, rule.Line))
				}
				if !hasPAMArgument(rule.Args, "use_authtok") {
					unknowns = append(unknowns, fmt.Sprintf("%s %s:%d pam_unix.so가 검증된 비밀번호 토큰을 강제하지 않음", stack, rule.Path, rule.Line))
				}
			}
			continue
		}
		if pamUnixCount > 0 {
			control := strings.ToLower(strings.TrimSpace(rule.Control))
			description := fmt.Sprintf("%s %s:%d %s control=%s", stack, rule.Path, rule.Line, module, rule.Control)
			switch passwordPAMModuleRole(module) {
			case passwordRoleWriter:
				if !knownPostUnixWriterUsesAuthtok(module, rule.Args) {
					unknowns = append(unknowns, description+"이 pam_unix.so 뒤에서 검증되지 않은 새 비밀번호 토큰을 받을 수 있음")
				}
				if strings.HasPrefix(control, "[") || (control != "required" && control != "requisite" && control != "sufficient" && control != "optional") {
					unknowns = append(unknowns, description+"의 후속 비밀번호 변경 흐름을 확정할 수 없음")
				}
			case passwordRoleUnknown:
				unknowns = append(unknowns, description+"의 후속 비밀번호 변경 여부를 확정할 수 없음")
			}
			continue
		}
		control := strings.ToLower(strings.TrimSpace(rule.Control))
		description := fmt.Sprintf("%s %s:%d %s control=%s", stack, rule.Path, rule.Line, module, rule.Control)
		role := passwordPAMModuleRole(module)
		if role == passwordRoleWriter {
			unknowns = append(unknowns, description+"이 검증된 pam_unix.so보다 먼저 비밀번호를 변경할 수 있음")
		} else if role == passwordRoleUnknown {
			unknowns = append(unknowns, description+"의 비밀번호 변경 여부를 확정할 수 없음")
		}
		if strings.HasPrefix(control, "[") {
			unknowns = append(unknowns, description+"이 뒤의 비밀번호 정책 또는 pam_unix.so를 건너뛸 수 있음")
			continue
		}
		if control != "sufficient" {
			if control != "required" && control != "requisite" && control != "optional" {
				unknowns = append(unknowns, description+"의 PAM 제어 흐름을 확정할 수 없음")
			}
			continue
		}
		switch module {
		case "pam_permit.so":
			if rule.Service == "" || rule.Service == stack {
				violations = append(violations, description+"이 뒤의 비밀번호 정책 또는 pam_unix.so를 우회함")
			} else {
				unknowns = append(unknowns, description+"의 include/substack 반환 범위를 확정할 수 없음")
			}
		case "pam_rootok.so":
			violations = append(violations, description+"이 root 비밀번호 정책을 우회함")
		case "pam_deny.so":
			// pam_deny cannot produce the successful result required by sufficient.
		default:
			unknowns = append(unknowns, description+"이 뒤의 비밀번호 정책 또는 pam_unix.so를 우회할 수 있음")
		}
	}
	if pamUnixCount == 0 {
		unknowns = append(unknowns, stack+"에 로컬 비밀번호를 갱신하는 pam_unix.so가 없음")
	} else if pamUnixCount > 1 {
		unknowns = append(unknowns, stack+"의 password pam_unix.so 적용 경로가 여러 개임")
	}
	return violations, unknowns
}

func unresolvedDebianPasswordPolicyPaths(rules []support.PAMRule) []string {
	paths := make([]string, 0)
	for _, rule := range rules {
		if rule.Type != "password" {
			continue
		}
		module := strings.ToLower(filepath.Base(rule.Module))
		switch module {
		case "pam_passwdqc.so", "pam_cracklib.so",
			"pam_sss.so", "pam_ldap.so", "pam_winbind.so", "pam_krb5.so", "pam_exec.so":
			paths = append(paths, fmt.Sprintf("%s:%d %s", rule.Path, rule.Line, module))
		default:
			if passwordPAMModuleRole(module) == passwordRoleUnknown {
				paths = append(paths, fmt.Sprintf("%s:%d %s", rule.Path, rule.Line, module))
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return uniqueSorted(paths)
}

type passwordModuleRole uint8

const (
	passwordRoleControl passwordModuleRole = iota
	passwordRolePolicy
	passwordRoleWriter
	passwordRoleUnknown
)

func passwordPAMModuleRole(module string) passwordModuleRole {
	switch strings.ToLower(filepath.Base(module)) {
	case "pam_pwquality.so", "pam_pwhistory.so", "pam_passwdqc.so", "pam_cracklib.so":
		return passwordRolePolicy
	case "pam_unix.so", "pam_sss.so", "pam_ldap.so", "pam_winbind.so", "pam_krb5.so", "pam_exec.so":
		return passwordRoleWriter
	case "pam_deny.so", "pam_permit.so", "pam_warn.so", "pam_debug.so", "pam_echo.so",
		"pam_localuser.so", "pam_usertype.so", "pam_succeed_if.so":
		return passwordRoleControl
	default:
		return passwordRoleUnknown
	}
}

func hasPAMArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if strings.EqualFold(strings.TrimSpace(argument), wanted) {
			return true
		}
	}
	return false
}

func knownPostUnixWriterUsesAuthtok(module string, arguments []string) bool {
	switch strings.ToLower(filepath.Base(module)) {
	case "pam_sss.so", "pam_ldap.so", "pam_winbind.so", "pam_krb5.so":
		return hasPAMArgument(arguments, "use_authtok")
	default:
		return false
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

func exactRequiredClassCount(settings map[string]configSetting) int {
	count := 0
	for _, key := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		if value, ok := integerSetting(settings, key); ok && value == -1 {
			count++
		}
	}
	return count
}

func passwordPolicyModuleOrderFindings(stack string, rules []support.PAMRule) ([]string, []string) {
	qualityIndexes := make([]int, 0, 1)
	historyIndexes := make([]int, 0, 1)
	unixIndexes := make([]int, 0, 1)
	for index, rule := range rules {
		if rule.Type != "password" {
			continue
		}
		switch filepath.Base(rule.Module) {
		case "pam_pwquality.so":
			qualityIndexes = append(qualityIndexes, index)
		case "pam_pwhistory.so":
			historyIndexes = append(historyIndexes, index)
		case "pam_unix.so":
			unixIndexes = append(unixIndexes, index)
		}
	}
	if len(unixIndexes) == 0 {
		return nil, []string{stack + "에 password pam_unix.so가 없음"}
	}
	if len(unixIndexes) > 1 {
		return nil, []string{stack + "의 password pam_unix.so 적용 경로가 여러 개임"}
	}
	violations := make([]string, 0, 2)
	for _, candidate := range []struct {
		name    string
		indexes []int
	}{
		{name: "pam_pwquality.so", indexes: qualityIndexes},
		{name: "pam_pwhistory.so", indexes: historyIndexes},
	} {
		if len(candidate.indexes) == 1 && candidate.indexes[0] > unixIndexes[0] {
			violations = append(violations, fmt.Sprintf("%s의 %s가 pam_unix.so보다 뒤에 있음", stack, candidate.name))
		}
	}
	return violations, nil
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
