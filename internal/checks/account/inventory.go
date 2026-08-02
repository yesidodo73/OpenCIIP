package account

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

const (
	EvaluatorUnnecessaryAccounts = "unix.account.unnecessary_accounts"
	EvaluatorAdminMembership     = "unix.account.admin_group_membership"
	EvaluatorUnnecessaryGroups   = "unix.account.unnecessary_groups"
	EvaluatorServiceShell        = "unix.account.service_shell"
)

func inventoryImplementations() map[string]evaluator.Func {
	return map[string]evaluator.Func{
		EvaluatorUnnecessaryAccounts: evaluateUnnecessaryAccounts,
		EvaluatorAdminMembership:     evaluateAdminMembership,
		EvaluatorUnnecessaryGroups:   evaluateUnnecessaryGroups,
		EvaluatorServiceShell:        evaluateServiceShell,
	}
}

func evaluateUnnecessaryAccounts(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("account_inventory_failed", err)
	}
	evidence := []model.Evidence{accountEvidence}
	shadow, shadowEvidence, shadowErr := support.ReadShadowSummary(ctx, environment.Files)
	shadowAvailable := shadowErr == nil
	if shadowAvailable {
		evidence = append(evidence, shadowEvidence)
	} else {
		evidence = append(evidence, support.FactEvidence("account-status-summary", map[string]any{
			"available":                false,
			"reason":                   "shadow_summary_unavailable",
			"account_details_redacted": true,
		}))
	}
	approved, hasApproved, parameterErr := support.StringSliceParameter(rule.Parameters, "approved_accounts")
	if parameterErr != nil {
		return checkError("invalid_rule_parameter", parameterErr)
	}
	if !hasApproved {
		observed := fmt.Sprintf("NSS에서 %d개 계정을 수집했으나 로컬 계정 상태를 확인할 수 없고 approved_accounts 정책이 없습니다.", len(accounts))
		if shadowAvailable {
			observed = fmt.Sprintf("NSS 계정 %d개와 로컬 shadow 상태 %d개를 수집했으나 approved_accounts 정책이 없습니다.", len(accounts), len(shadow))
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "계정의 업무상 필요성을 자동으로 판단할 수 없습니다.",
			Expected:      "유효 계정을 승인된 계정 대장 및 계정 상태·사용 근거와 대조해야 합니다.",
			Observed:      observed,
			Details: []model.ResultDetail{{
				Label: "계정 승인 정책", Current: fmt.Sprintf("NSS 계정 %d개, 승인 목록 없음", len(accounts)),
				Expected: "모든 유효 계정이 approved_accounts에 등록됨", Source: "NSS, /etc/shadow",
			}},
			Evidence: evidence,
		}
	}
	approvedSet, listErr := normalizedNameSet(approved)
	if listErr != nil {
		return checkError("invalid_rule_parameter", listErr)
	}
	accountSet := make(map[string]bool, len(accounts))
	unapproved := make([]string, 0)
	for _, account := range accounts {
		accountSet[account.Name] = true
		if !approvedSet[account.Name] {
			unapproved = append(unapproved, account.Name)
		}
	}
	missingApproved := make([]string, 0)
	for name := range approvedSet {
		if !accountSet[name] {
			missingApproved = append(missingApproved, name)
		}
	}
	sort.Strings(unapproved)
	sort.Strings(missingApproved)
	if len(unapproved) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "승인된 계정 대장에 없는 계정이 있습니다.",
			Expected: "모든 NSS 계정이 완전한 approved_accounts 정책에 포함되어야 합니다.",
			Observed: strings.Join(unapproved, ", "),
			Evidence: evidence,
		}
	}
	if len(missingApproved) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "승인 계정 대장의 일부 계정을 현재 NSS에서 확인할 수 없습니다.",
			Expected:      "NSS 계정 집합과 approved_accounts가 양방향으로 정확히 일치해야 합니다.",
			Observed:      "NSS에 없는 승인 계정: " + strings.Join(missingApproved, ", "),
			Evidence:      evidence,
		}
	}
	if !shadowAvailable {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "승인 계정 대장과 NSS 목록은 일치하지만 로컬 계정 상태를 확인하지 못했습니다.",
			Expected:      "모든 NSS 계정이 승인 목록에 있고 로컬 계정 상태와 사용 근거를 확인할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("승인 계정 %d개와 NSS 계정 %d개가 일치하며 shadow 상태 증적은 없습니다.", len(approvedSet), len(accounts)),
			Evidence:      evidence,
		}
	}
	missingShadowStatus := make([]string, 0)
	for _, account := range accounts {
		if _, exists := shadow[account.Name]; !exists {
			missingShadowStatus = append(missingShadowStatus, account.Name)
		}
	}
	sort.Strings(missingShadowStatus)
	if len(missingShadowStatus) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "일부 NSS 계정의 비밀번호 상태 출처 증적을 확인할 수 없습니다.",
			Expected:      "NSS 계정 집합과 승인 목록이 일치하고 각 계정의 shadow 상태 출처 증적이 있어야 합니다.",
			Observed:      "shadow 상태가 없는 NSS 계정: " + strings.Join(missingShadowStatus, ", "),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "NSS 계정 집합과 승인 계정 대장이 일치하며 모든 계정의 상태 출처 증적이 있습니다.",
		Expected: "NSS 계정 집합과 approved_accounts가 일치하고 각 계정의 shadow 상태 출처 증적이 있어야 합니다.",
		Observed: fmt.Sprintf("승인 계정 %d개, NSS 계정 %d개, shadow 상태 %d개를 대조했습니다.", len(approvedSet), len(accounts), len(accounts)),
		Evidence: evidence,
	}
}

func evaluateAdminMembership(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	evidence := make([]model.Evidence, 0, 3)
	observed := make([]string, 0, 2)
	for _, name := range []string{"root", "wheel"} {
		group, groupEvidence, exists, err := support.ReadEffectiveGroup(ctx, environment.Commands, name)
		if err != nil {
			return checkError("admin_group_lookup_failed", err)
		}
		evidence = append(evidence, groupEvidence)
		if exists {
			observed = append(observed, fmt.Sprintf("%s=%s", name, strings.Join(group.Members, ",")))
		}
	}
	if environment.Commands.Available("visudo") {
		spec := executor.Spec{Name: "visudo", Arguments: []string{"-c"}, Timeout: 20 * time.Second, MaxOutput: 2 << 20}
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return checkError("sudoers_validation_failed", err)
		}
		evidence = append(evidence, support.CommandEvidence(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return checkError("sudoers_validation_failed", fmt.Errorf("visudo exit=%d truncated=%t", result.ExitCode, result.Truncated))
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "관리자 권한 보유 계정의 필요성을 수동으로 확인해야 합니다.",
		Expected:      "root·wheel·sudoers·외부 권한 그룹의 구성원이 승인 관리자 목록과 일치해야 합니다.",
		Observed:      strings.Join(observed, "; ") + "; 승인 관리자 목록과 외부 그룹 증적이 필요합니다.",
		Details: []model.ResultDetail{{
			Label: "관리자 그룹 구성원", Current: strings.Join(observed, ", "),
			Expected: "승인 관리자 목록과 일치", Source: "root, wheel, sudoers",
		}},
		Evidence: evidence,
	}
}

func evaluateUnnecessaryGroups(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	groups, groupEvidence, err := support.ReadEffectiveGroups(ctx, environment.Commands)
	if err != nil {
		return checkError("group_inventory_failed", err)
	}
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("account_inventory_failed", err)
	}
	usedPrimary := make(map[uint32]bool)
	for _, account := range accounts {
		usedPrimary[account.GID] = true
	}
	candidates := make([]string, 0)
	for _, group := range groups {
		if len(group.Members) == 0 && !usedPrimary[group.GID] {
			candidates = append(candidates, fmt.Sprintf("%s(%d)", group.Name, group.GID))
		}
	}
	sort.Strings(candidates)
	observed := "계정 구성원이나 primary GID가 없는 그룹이 없습니다."
	if len(candidates) > 0 {
		observed = "추가 검토 후보: " + strings.Join(candidates, ", ")
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "그룹의 서비스·파일 소유 목적과 필요성을 수동으로 확인해야 합니다.",
		Expected:      "구성원이 없는 그룹도 파일 소유와 서비스 목적 및 승인 목록을 확인해야 합니다.",
		Observed:      observed,
		Details: []model.ResultDetail{{
			Label: "미사용 가능 그룹", Current: fmt.Sprintf("검토 후보 %d개", len(candidates)),
			Expected: "서비스·파일 소유 목적 또는 승인 근거 확인", Source: "NSS 그룹 및 primary GID",
		}},
		Evidence: []model.Evidence{groupEvidence, accountEvidence},
	}
}

func evaluateServiceShell(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	accounts, evidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("account_inventory_failed", err)
	}
	uidMin, uidEvidence, err := readUIDMin(ctx, environment)
	if err != nil {
		return checkError("uid_min_read_failed", err)
	}
	required, hasRequired, parameterErr := support.StringSliceParameter(rule.Parameters, "nonlogin_required_accounts")
	if parameterErr != nil {
		return checkError("invalid_rule_parameter", parameterErr)
	}
	byName := make(map[string]support.PasswdEntry, len(accounts))
	serviceCandidates := make([]string, 0)
	for _, account := range accounts {
		byName[account.Name] = account
		if account.UID > 0 && int(account.UID) < uidMin && !isNonLoginShell(account.Shell) {
			serviceCandidates = append(serviceCandidates, account.Name+"="+account.Shell)
		}
	}
	allEvidence := []model.Evidence{evidence, uidEvidence}
	if !hasRequired {
		sort.Strings(serviceCandidates)
		observed := fmt.Sprintf("UID_MIN=%d, 대화형 shell이 설정된 시스템 UID 계정 없음", uidMin)
		if len(serviceCandidates) > 0 {
			observed = strings.Join(serviceCandidates, ", ")
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "계정 역할을 알 수 없어 대화형 shell의 필요성을 확정할 수 없습니다.",
			Expected:      "nonlogin_required_accounts 정책으로 로그인 불필요 계정을 명시해야 합니다.",
			Observed:      observed,
			Details: []model.ResultDetail{{
				Label: "대화형 shell 계정", Current: observed,
				Expected: "로그인 불필요 계정을 정책으로 지정", Source: "NSS 계정, /etc/login.defs UID_MIN",
			}},
			Evidence: allEvidence,
		}
	}
	_, listErr := normalizedNameSet(required)
	if listErr != nil {
		return checkError("invalid_rule_parameter", listErr)
	}
	missing := make([]string, 0)
	violations := make([]string, 0)
	for _, name := range required {
		account, exists := byName[name]
		if !exists {
			missing = append(missing, name)
			continue
		}
		if !isNonLoginShell(account.Shell) {
			violations = append(violations, name+"="+account.Shell)
		}
	}
	sort.Strings(missing)
	sort.Strings(violations)
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "로그인이 불필요하다고 지정된 계정에 대화형 shell이 설정되어 있습니다.",
			Expected: "지정된 모든 계정이 /sbin/nologin 또는 /bin/false 계열을 사용해야 합니다.",
			Observed: strings.Join(violations, ", "),
			Evidence: allEvidence,
		}
	}
	if len(missing) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "정책에 지정된 일부 계정을 NSS에서 확인할 수 없습니다.",
			Expected:      "정책 대상 계정이 모두 조회되고 non-login shell을 사용해야 합니다.",
			Observed:      strings.Join(missing, ", "),
			Evidence:      allEvidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "로그인이 불필요하다고 지정된 계정이 모두 non-login shell을 사용합니다.",
		Expected: "정책 대상 계정이 모두 non-login shell을 사용해야 합니다.",
		Observed: fmt.Sprintf("정책 대상 %d개", len(required)),
		Evidence: allEvidence,
	}
}

func normalizedNameSet(values []string) (map[string]bool, error) {
	result := make(map[string]bool, len(values))
	for index, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != value {
			return nil, fmt.Errorf("item %d has surrounding whitespace", index)
		}
		value = trimmed
		if value == "" || strings.ContainsAny(value, " \t/\\:") {
			return nil, fmt.Errorf("item %d has invalid account or group name", index)
		}
		if result[value] {
			return nil, fmt.Errorf("item %d duplicates %s", index, value)
		}
		result[value] = true
	}
	return result, nil
}
