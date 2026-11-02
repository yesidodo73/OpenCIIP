package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func evaluateFTPAccountShell(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectFTPTarget(ctx, environment)
	if terminal != nil {
		if terminal.Status == model.StatusNotApplicable {
			return evaluator.Outcome{Status: model.StatusPass, Summary: "FTP 서비스가 비활성화되어 있습니다.", Expected: rule.Criteria.Pass, Observed: "활성 FTP 서비스 없음", Evidence: terminal.Evidence}
		}
		return *terminal
	}
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return ftpCheckError("ftp_account_collection_failed", err, target.evidence)
	}
	evidence := append(append([]model.Evidence(nil), target.evidence...), accountEvidence)
	for _, account := range accounts {
		if account.Name != "ftp" {
			continue
		}
		if !isFTPNonLoginShell(account.Shell) {
			return evaluator.Outcome{Status: model.StatusFail, Summary: "FTP 계정에 로그인 가능한 shell이 설정되어 있습니다.", Expected: rule.Criteria.Pass, Observed: "ftp=" + account.Shell, Evidence: evidence}
		}
		return evaluator.Outcome{Status: model.StatusPass, Summary: "FTP 계정에 로그인할 수 없는 shell이 설정되어 있습니다.", Expected: rule.Criteria.Pass, Observed: "ftp=" + account.Shell, Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "FTP 기본 계정이 존재하지 않습니다.", Expected: rule.Criteria.Pass, Observed: "ftp 계정 없음", Evidence: evidence}
}

func evaluateFTPAccountShellLegacy(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	policyAccounts, policySet, err := ftpServiceAccountPolicy(rule.Parameters)
	if err != nil {
		return ftpCheckError("invalid_rule_parameter", err, nil)
	}
	candidates := append([]string(nil), policyAccounts...)
	target, terminal := inspectFTPTarget(ctx, environment)
	evidence := make([]model.Evidence, 0)
	inspectActiveProduct := terminal == nil
	if terminal != nil {
		evidence = append(evidence, terminal.Evidence...)
		if terminal.Status != model.StatusNotApplicable {
			return *terminal
		}
		present, known, _, componentEvidence, inspectErr := inspectFTPComponents(ctx, environment)
		evidence = append(evidence, componentEvidence...)
		if inspectErr != nil {
			return ftpCheckError("ftp_component_inventory_failed", inspectErr, evidence)
		}
		if len(policyAccounts) == 0 {
			if !present && known {
				terminal.Evidence = evidence
				return *terminal
			}
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownManualVerification,
				Summary:       "비활성 FTP 구성요소와 연결된 전용 계정 범위를 확정할 수 없습니다.",
				Expected:      rule.Criteria.Pass,
				Observed:      "ftp_service_accounts 정책이 없거나 구성요소 설치 여부가 불완전합니다.",
				Evidence:      evidence,
			}
		}
	} else {
		evidence = append(evidence, target.evidence...)
	}

	if inspectActiveProduct {
		switch target.product.id {
		case "vsftpd":
			configuration, collectedEvidence, inspectErr := inspectVSFTPDConfiguration(ctx, environment, evidence)
			if inspectErr != nil {
				return ftpCheckError("vsftpd_config_failed", inspectErr, evidence)
			}
			evidence = collectedEvidence
			dynamicLoad, settingErr := vsftpdHasDynamicConfiguration(configuration)
			if settingErr != nil {
				return ftpCheckError("vsftpd_config_failed", settingErr, evidence)
			}
			if configuration.dynamicConfig || dynamicLoad || strings.TrimSpace(configuration.settings["user_config_dir"]) != "" {
				return unsupportedFTPCheck("FTP 계정 shell", "사용자별 vsftpd 설정이 계정 매핑을 변경할 수 있습니다.", evidence)
			}
			localEnabled, localSet, boolErr := explicitVSFTPDBoolean(configuration, "local_enable")
			if boolErr != nil {
				return ftpCheckError("vsftpd_config_failed", boolErr, evidence)
			}
			anonymousEnabled, anonymousSet, boolErr := explicitVSFTPDBoolean(configuration, "anonymous_enable")
			if boolErr != nil {
				return ftpCheckError("vsftpd_config_failed", boolErr, evidence)
			}
			guestEnabled, _, boolErr := explicitVSFTPDBoolean(configuration, "guest_enable")
			if boolErr != nil {
				return ftpCheckError("vsftpd_config_failed", boolErr, evidence)
			}
			if !localSet || !anonymousSet {
				return unsupportedFTPCheck("FTP 계정 shell", "local 및 anonymous 로그인 경로를 명시적으로 확정할 수 없습니다.", evidence)
			}
			if guestEnabled {
				return unsupportedFTPCheck("FTP 계정 shell", "virtual user의 실제 시스템 계정 매핑을 확정할 수 없습니다.", evidence)
			}
			if localEnabled && !policySet {
				return ftpAccountPolicyUnknown(rule, evidence)
			}
			if anonymousEnabled {
				account := strings.TrimSpace(configuration.settings["ftp_username"])
				if account == "" || !validFTPAccountName(account) {
					return unsupportedFTPCheck("FTP 계정 shell", "anonymous FTP 전용 계정을 명시적으로 식별할 수 없습니다.", evidence)
				}
				candidates = append(candidates, account)
			}
		case "proftpd":
			configuration, collectedEvidence, inspectErr := inspectProFTPDConfiguration(ctx, environment, evidence)
			if inspectErr != nil {
				if errors.Is(inspectErr, errFTPUnsupportedConfiguration) {
					return unsupportedFTPCheck("FTP 계정 shell", "ProFTPD include 구성을 완전히 해석할 수 없습니다.", evidence)
				}
				return ftpCheckError("proftpd_config_failed", inspectErr, evidence)
			}
			evidence = collectedEvidence
			if proFTPDUsesVirtualUsers(configuration.nodes) {
				return unsupportedFTPCheck("FTP 계정 shell", "ProFTPD virtual user 또는 외부 인증 매핑이 있습니다.", evidence)
			}
			if !policySet {
				return ftpAccountPolicyUnknown(rule, evidence)
			}
			anonymousAccounts, complete := proFTPDAnonymousAccounts(configuration.nodes)
			if !complete {
				return unsupportedFTPCheck("FTP 계정 shell", "ProFTPD anonymous 계정 매핑을 확정할 수 없습니다.", evidence)
			}
			candidates = append(candidates, anonymousAccounts...)
		default:
			return unsupportedFTPProduct("FTP 계정 shell", target)
		}
	}

	candidates = uniqueStrings(candidates)
	if len(candidates) == 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "활성 FTP 서비스에서 FTP 전용 시스템 계정을 식별하지 못했습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      "ftp_service_accounts 정책과 명시적 서비스 계정 매핑이 없음",
			Evidence:      evidence,
		}
	}
	entries, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return ftpCheckError("ftp_account_collection_failed", err, evidence)
	}
	evidence = append(evidence, accountEvidence)
	byName := make(map[string]string, len(entries))
	for _, entry := range entries {
		if _, exists := byName[entry.Name]; exists {
			return ftpCheckError("ftp_account_collection_failed", fmt.Errorf("effective passwd has a duplicate account"), evidence)
		}
		byName[entry.Name] = entry.Shell
	}
	missing := 0
	interactive := 0
	nonLogin := 0
	accountFacts := make([]string, 0, len(candidates))
	for _, account := range candidates {
		shell, exists := byName[account]
		if !exists {
			missing++
			accountFacts = append(accountFacts, account+"\x00missing")
			continue
		}
		if isFTPNonLoginShell(shell) {
			nonLogin++
			accountFacts = append(accountFacts, account+"\x00non-login")
		} else {
			interactive++
			accountFacts = append(accountFacts, account+"\x00interactive")
		}
	}
	evidence = append(evidence, support.FactEvidence("ftp-account-shell-summary", map[string]any{
		"account_count":           len(candidates),
		"account_state_sha256":    hashFTPStrings(accountFacts),
		"non_login_shell_count":   nonLogin,
		"interactive_shell_count": interactive,
		"missing_account_count":   missing,
		"user_details_redacted":   true,
	}))
	if interactive > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "확정된 FTP 전용 계정에 대화형 shell이 설정되어 있습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("대화형 shell 계정 %d개", interactive),
			Evidence: evidence,
		}
	}
	if missing > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "일부 FTP 전용 계정의 실효 passwd 항목을 확인하지 못했습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("조회되지 않은 계정 %d개", missing),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 확정된 FTP 전용 계정이 non-login shell을 사용합니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("non-login shell 계정 %d개", nonLogin),
		Evidence: evidence,
	}
}

func ftpServiceAccountPolicy(parameters map[string]any) ([]string, bool, error) {
	values, exists, err := support.StringSliceParameter(parameters, "ftp_service_accounts")
	if err != nil {
		return nil, exists, err
	}
	seen := make(map[string]bool, len(values))
	for index, value := range values {
		if !validFTPAccountName(value) || seen[value] {
			return nil, exists, fmt.Errorf("ftp_service_accounts item %d is invalid or duplicated", index)
		}
		seen[value] = true
	}
	return uniqueStrings(values), exists, nil
}

func validFTPAccountName(value string) bool {
	if value == "" || len(value) > 256 || strings.HasPrefix(value, "-") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("_.-$", character) {
			return false
		}
	}
	return true
}

func ftpAccountPolicyUnknown(rule model.ResolvedRule, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "FTP 로그인이 가능한 계정 중 FTP 전용 계정의 승인 목록이 없습니다.",
		Expected:      rule.Criteria.Pass,
		Observed:      "ftp_service_accounts 정책 없음",
		Evidence:      evidence,
	}
}

func proFTPDUsesVirtualUsers(nodes []proFTPDNode) bool {
	relevant := map[string]bool{
		"authuserfile": true, "authgroupfile": true, "useralias": true, "authaliasonly": true,
		"sqlengine": true, "sqlauthenticate": true, "ldapserver": true, "radiusengine": true,
	}
	if len(allProFTPDNodes(nodes, relevant)) > 0 || hasProFTPDDynamicScope(nodes, relevant) ||
		len(allProFTPDNodes(nodes, map[string]bool{"includeoptions": true})) > 0 {
		return true
	}
	var hasExternalAuthDirective func([]proFTPDNode) bool
	hasExternalAuthDirective = func(current []proFTPDNode) bool {
		for _, node := range current {
			if strings.HasPrefix(node.name, "sql") || strings.HasPrefix(node.name, "ldap") || strings.HasPrefix(node.name, "radius") {
				return true
			}
			if node.block && hasExternalAuthDirective(node.children) {
				return true
			}
		}
		return false
	}
	if hasExternalAuthDirective(nodes) {
		return true
	}
	for _, authOrder := range allProFTPDNodes(nodes, map[string]bool{"authorder": true}) {
		for _, module := range authOrder.args {
			module = strings.TrimSuffix(strings.ToLower(module), "*")
			if module != "mod_auth_unix.c" && module != "mod_auth_pam.c" {
				return true
			}
		}
	}
	return false
}

func proFTPDAnonymousAccounts(nodes []proFTPDNode) ([]string, bool) {
	if hasProFTPDDynamicScope(nodes, map[string]bool{"anonymous": true, "user": true}) ||
		len(directProFTPDNodes(nodes, "global")) > 0 {
		return nil, false
	}
	accounts := make([]string, 0)
	for _, anonymous := range allProFTPDNodes(nodes, map[string]bool{"anonymous": true}) {
		user, state := singleProFTPDDirective(anonymous.children, "user")
		if state != "ok" || len(user.args) != 1 || !validFTPAccountName(user.args[0]) {
			return nil, false
		}
		accounts = append(accounts, user.args[0])
	}
	return uniqueStrings(accounts), true
}

type ftpAccessInspection struct {
	complete             bool
	sources              []string
	explicitUnrestricted bool
}

func evaluateFTPAccessControl(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectFTPTarget(ctx, environment)
	if terminal != nil {
		return *terminal
	}
	evidence := append([]model.Evidence(nil), target.evidence...)

	var inspection ftpAccessInspection
	var err error
	configurationUnsupported := false
	switch target.product.id {
	case "vsftpd":
		var configuration vsftpdConfiguration
		configuration, evidence, err = inspectVSFTPDConfiguration(ctx, environment, evidence)
		if err == nil {
			inspection, err = inspectVSFTPDHostAccess(configuration)
		}
	case "proftpd":
		var configuration proFTPDConfiguration
		configuration, evidence, err = inspectProFTPDConfiguration(ctx, environment, evidence)
		if err == nil {
			inspection, err = inspectProFTPDHostAccess(configuration)
		}
	default:
		return unsupportedFTPProduct("FTP IP 접근 통제", target)
	}
	if err != nil {
		if errors.Is(err, errFTPUnsupportedConfiguration) {
			configurationUnsupported = true
			inspection.complete = false
			err = nil
		} else {
			return ftpCheckError("ftp_access_config_failed", err, evidence)
		}
	}
	evidence = append(evidence, support.FactEvidence("ftp-local-access-summary", map[string]any{
		"fully_interpreted":       inspection.complete,
		"allowed_source_count":    len(inspection.sources),
		"allowed_sources_sha256":  hashFTPStrings(inspection.sources),
		"explicitly_unrestricted": inspection.explicitUnrestricted,
		"source_details_redacted": true,
	}))
	if !inspection.complete {
		evidence, err = collectFTPFirewallEvidence(ctx, environment, evidence)
		if err != nil {
			return ftpCheckError("ftp_firewall_collection_failed", err, evidence)
		}
	}
	if configurationUnsupported {
		return unsupportedFTPCheck("FTP IP 접근 통제", "include, host 규칙 또는 동적 접근 모듈을 완전히 해석할 수 없습니다.", evidence)
	}
	if !inspection.complete {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "FTP 서버 설정과 검증된 외부 ACL만으로 모든 접속 출발지 제한을 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      "firewalld/nftables 또는 외부 ACL의 추가 검증이 필요함",
			Evidence:      evidence,
		}
	}
	if inspection.explicitUnrestricted {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "FTP 서버에 접근 제어가 설정되어 있지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: "모든 IP 주소 또는 호스트에서 접속 가능",
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "FTP 서버 접근이 특정 IP 주소 또는 호스트로 제한되어 있습니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("명시적으로 허용된 접근 출발지 %d개", len(inspection.sources)),
		Evidence: evidence,
	}
}

func collectFTPFirewallEvidence(
	ctx context.Context,
	environment evaluator.Environment,
	evidence []model.Evidence,
) ([]model.Evidence, error) {
	if environment.Platform.InitSystem == "systemd" {
		units, rawUnitEvidence, err := support.InspectUnits(ctx, environment, []string{"firewalld.service", "nftables.service"})
		if err != nil {
			return evidence, err
		}
		evidence = append(evidence, sanitizeFTPEvidence(rawUnitEvidence)...)
		if len(units) == 2 {
			evidence = append(evidence, support.FactEvidence("ftp-firewall-manager-summary", map[string]any{
				"firewalld_active":       support.UnitActive(units[0]),
				"firewalld_boot_enabled": support.UnitEnabled(units[0]),
				"nftables_active":        support.UnitActive(units[1]),
				"nftables_boot_enabled":  support.UnitEnabled(units[1]),
			}))
		}
	}

	if environment.Commands.Available("nft") {
		spec := executor.Spec{Name: "nft", Arguments: []string{"-j", "list", "ruleset"}, Timeout: 30 * time.Second, MaxOutput: 8 << 20}
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return evidence, err
		}
		evidence = append(evidence, privateCommandSummary(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return evidence, fmt.Errorf("nft ruleset collection failed: exit=%d truncated=%t", result.ExitCode, result.Truncated)
		}
	} else {
		evidence = append(evidence, support.FactEvidence("ftp-nftables-summary", map[string]any{"command_available": false}))
	}

	if !environment.Commands.Available("firewall-cmd") {
		evidence = append(evidence, support.FactEvidence("ftp-firewalld-summary", map[string]any{"command_available": false}))
		return evidence, nil
	}
	stateSpec := executor.Spec{Name: "firewall-cmd", Arguments: []string{"--state"}, Timeout: 10 * time.Second}
	stateResult, err := environment.Commands.Run(ctx, stateSpec)
	if err != nil {
		return evidence, err
	}
	evidence = append(evidence, privateCommandSummary(stateSpec, stateResult))
	if stateResult.Truncated {
		return evidence, fmt.Errorf("firewalld state collection was truncated")
	}
	if stateResult.ExitCode != 0 || !strings.EqualFold(strings.TrimSpace(string(stateResult.Stdout)), "running") {
		return evidence, nil
	}
	for _, arguments := range [][]string{
		{"--list-all-zones"},
		{"--permanent", "--list-all-zones"},
		{"--list-all-policies"},
		{"--permanent", "--list-all-policies"},
	} {
		spec := executor.Spec{Name: "firewall-cmd", Arguments: arguments, Timeout: 30 * time.Second, MaxOutput: 8 << 20}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return evidence, runErr
		}
		evidence = append(evidence, privateCommandSummary(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return evidence, fmt.Errorf("firewalld configuration collection failed: exit=%d truncated=%t", result.ExitCode, result.Truncated)
		}
	}
	return evidence, nil
}

func ftpSourcePolicy(parameters map[string]any, key string) ([]string, bool, error) {
	values, exists, err := support.StringSliceParameter(parameters, key)
	if err != nil {
		return nil, exists, err
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for index, value := range values {
		source, valid := normalizeFTPSource(value)
		if !valid {
			if strings.TrimSpace(value) == value && value != "" {
				return nil, exists, fmt.Errorf("%w: %s item %d is not a numeric IP prefix", errFTPUnsupportedConfiguration, key, index)
			}
			return nil, exists, fmt.Errorf("%s item %d is invalid", key, index)
		}
		if seen[source] {
			return nil, exists, fmt.Errorf("%s item %d is invalid or duplicated", key, index)
		}
		seen[source] = true
		normalized = append(normalized, source)
	}
	sort.Strings(normalized)
	return normalized, exists, nil
}

func normalizeFTPSource(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		address = address.Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(address, bits).String(), true
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", false
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() {
		return "", false
	}
	return prefix.String(), true
}

func evaluateFTPSourceSubset(rule model.ResolvedRule, layer string, actual, approved []string, evidence []model.Evidence) evaluator.Outcome {
	outside := countFTPPolicyOutsideSources(actual, approved)
	if outside > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  layer + "의 FTP 허용 범위가 승인 IP 정책보다 넓습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("승인 정책 밖 출발지 %d개", outside),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  layer + "이 FTP 접속을 승인된 출발지 범위 안으로 제한합니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("허용 출발지 %d개", len(actual)),
		Evidence: evidence,
	}
}

func countFTPPolicyOutsideSources(actual, approved []string) int {
	approvedSet := make(map[string]bool, len(approved))
	for _, source := range approved {
		approvedSet[source] = true
	}
	outside := 0
	for _, source := range actual {
		if !approvedSet[source] && !ftpSourceCoveredByPolicy(source, approved) {
			outside++
		}
	}
	return outside
}

func ftpSourceCoveredByPolicy(source string, approved []string) bool {
	actual, err := netip.ParsePrefix(source)
	if err != nil {
		return false
	}
	for _, value := range approved {
		policy, parseErr := netip.ParsePrefix(value)
		if parseErr == nil && policy.Bits() <= actual.Bits() && policy.Contains(actual.Addr()) {
			return true
		}
	}
	return false
}

func inspectVSFTPDHostAccess(configuration vsftpdConfiguration) (ftpAccessInspection, error) {
	if configuration.dynamicConfig || strings.TrimSpace(configuration.settings["user_config_dir"]) != "" {
		return ftpAccessInspection{}, fmt.Errorf("%w: vsftpd has dynamic per-user configuration", errFTPUnsupportedConfiguration)
	}
	wrappers, wrappersSet, err := explicitVSFTPDBoolean(configuration, "tcp_wrappers")
	if err != nil {
		return ftpAccessInspection{}, err
	}
	if wrappersSet && wrappers {
		return ftpAccessInspection{}, fmt.Errorf("%w: vsftpd tcp_wrappers runtime support is not verified", errFTPUnsupportedConfiguration)
	}
	return ftpAccessInspection{complete: false}, nil
}

func splitFTPAccessList(value string) []string {
	return strings.FieldsFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || character == ','
	})
}

func inspectProFTPDHostAccess(configuration proFTPDConfiguration) (ftpAccessInspection, error) {
	relevant := map[string]bool{
		"limit": true, "order": true, "allow": true, "deny": true, "allowall": true, "denyall": true,
		"wrapengine": true, "wraptables": true, "tcpaccessfiles": true, "allowclass": true, "denyclass": true,
	}
	if hasProFTPDDynamicScope(configuration.nodes, relevant) || len(directProFTPDNodes(configuration.nodes, "global")) > 0 ||
		len(allProFTPDNodes(configuration.nodes, map[string]bool{
			"includeoptions": true, "wrapengine": true, "wraptables": true, "tcpaccessfiles": true,
		})) > 0 || proFTPDHasHostAccessModuleDirective(configuration.nodes) {
		return ftpAccessInspection{}, fmt.Errorf("%w: ProFTPD has dynamic access configuration", errFTPUnsupportedConfiguration)
	}
	inspection := ftpAccessInspection{complete: true}
	for _, serverScope := range proFTPDServerScopes(configuration.nodes) {
		accessScopes := [][]proFTPDNode{serverScope}
		for _, anonymous := range directProFTPDNodes(serverScope, "anonymous") {
			accessScopes = append(accessScopes, anonymous.children)
		}
		for _, scope := range accessScopes {
			limits := make([]proFTPDNode, 0)
			for _, limit := range directProFTPDNodes(scope, "limit") {
				for _, command := range limit.args {
					if strings.EqualFold(command, "LOGIN") {
						limits = append(limits, limit)
					}
				}
			}
			if len(limits) != 1 {
				inspection.complete = false
				continue
			}
			sources, unrestricted, complete, err := parseProFTPDLoginLimit(limits[0].children)
			if err != nil {
				return ftpAccessInspection{}, err
			}
			if !complete {
				inspection.complete = false
				continue
			}
			inspection.sources = append(inspection.sources, sources...)
			inspection.explicitUnrestricted = inspection.explicitUnrestricted || unrestricted
		}
	}
	inspection.sources = uniqueStrings(inspection.sources)
	return inspection, nil
}

func proFTPDHasHostAccessModuleDirective(nodes []proFTPDNode) bool {
	for _, node := range nodes {
		if strings.HasPrefix(node.name, "wrap") || strings.HasPrefix(node.name, "tcpaccess") ||
			strings.HasPrefix(node.name, "tcpuseraccess") || strings.HasPrefix(node.name, "tcpgroupaccess") {
			return true
		}
		if node.block && proFTPDHasHostAccessModuleDirective(node.children) {
			return true
		}
	}
	return false
}

func parseProFTPDLoginLimit(nodes []proFTPDNode) ([]string, bool, bool, error) {
	order, orderState := singleProFTPDDirective(nodes, "order")
	if orderState != "ok" || len(order.args) != 1 || !strings.EqualFold(strings.ReplaceAll(order.args[0], " ", ""), "allow,deny") {
		return nil, false, false, nil
	}
	if len(directProFTPDNodes(nodes, "allowall")) > 0 {
		return []string{"all"}, true, true, nil
	}
	allow, allowState := singleProFTPDDirective(nodes, "allow")
	deny, denyState := singleProFTPDDirective(nodes, "deny")
	denyAll := len(directProFTPDNodes(nodes, "denyall")) == 1
	if len(directProFTPDNodes(nodes, "denyall")) > 1 || len(directProFTPDNodes(nodes, "allowclass")) > 0 ||
		len(directProFTPDNodes(nodes, "denyclass")) > 0 {
		return nil, false, false, nil
	}
	if denyState == "ok" {
		denyAll = denyAll || len(deny.args) == 2 && strings.EqualFold(deny.args[0], "from") && strings.EqualFold(deny.args[1], "all")
	} else if denyState == "conflict" {
		return nil, false, false, nil
	}
	if !denyAll {
		return nil, false, false, nil
	}
	if allowState == "missing" {
		return nil, false, true, nil
	}
	if allowState != "ok" || len(allow.args) < 2 || !strings.EqualFold(allow.args[0], "from") {
		return nil, false, false, nil
	}
	sources := make([]string, 0)
	for _, item := range allow.args[1:] {
		for _, source := range splitFTPAccessList(item) {
			if strings.EqualFold(source, "all") {
				return []string{"all"}, true, true, nil
			}
			normalized, valid := normalizeFTPSource(source)
			if !valid {
				return nil, false, false, nil
			}
			sources = append(sources, normalized)
		}
	}
	return uniqueStrings(sources), false, true, nil
}
