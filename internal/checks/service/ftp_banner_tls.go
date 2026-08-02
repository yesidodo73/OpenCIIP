package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorFTPBanner            = "unix.service.ftp_banner"
	EvaluatorPlaintextFTPDisabled = "unix.service.plaintext_ftp_disabled"
	EvaluatorFTPAccountShell      = "unix.service.ftp_account_shell"
	EvaluatorFTPAccessControl     = "unix.service.ftp_access_control"
)

func evaluateFTPBanner(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectFTPTarget(ctx, environment)
	if terminal != nil {
		return *terminal
	}
	approved, policySet, err := approvedFTPBannerHashes(rule.Parameters)
	if err != nil {
		return ftpCheckError("invalid_rule_parameter", err, target.evidence)
	}

	var fragments []string
	dynamic := false
	evidence := append([]model.Evidence(nil), target.evidence...)
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
		if configuration.dynamicConfig || dynamicLoad {
			dynamic = true
		} else if bannerPath := strings.TrimSpace(configuration.settings["banner_file"]); bannerPath != "" {
			data, fileEvidence, readErr := readFTPPrivateFile(ctx, environment.Files, bannerPath)
			if readErr != nil {
				if errors.Is(readErr, errFTPUnsupportedConfiguration) {
					return unsupportedFTPCheck("FTP 배너", "vsftpd 배너 파일 경로가 동적으로 결정됩니다.", evidence)
				}
				return ftpCheckError("vsftpd_banner_file_failed", readErr, evidence)
			}
			evidence = append(evidence, fileEvidence)
			fragments = append(fragments, canonicalFTPText(string(data)))
		} else if banner, exists := configuration.settings["ftpd_banner"]; exists && banner != "" {
			fragments = append(fragments, canonicalFTPText(banner))
		} else {
			dynamic = true
		}
	case "proftpd":
		configuration, collectedEvidence, inspectErr := inspectProFTPDConfiguration(ctx, environment, evidence)
		if inspectErr != nil {
			if errors.Is(inspectErr, errFTPUnsupportedConfiguration) {
				return unsupportedFTPCheck("FTP 배너", "ProFTPD include 구성을 정적으로 확정할 수 없습니다.", evidence)
			}
			return ftpCheckError("proftpd_config_failed", inspectErr, evidence)
		}
		evidence = collectedEvidence
		fragments, dynamic, err = inspectProFTPDBanners(ctx, environment, configuration)
		if err != nil {
			if errors.Is(err, errFTPUnsupportedConfiguration) {
				return unsupportedFTPCheck("FTP 배너", "ProFTPD 배너 파일 경로가 동적으로 결정됩니다.", evidence)
			}
			return ftpCheckError("proftpd_banner_failed", err, evidence)
		}
	default:
		return unsupportedFTPProduct("FTP 배너", target)
	}

	fragmentHashes := make([]string, 0, len(fragments))
	mismatches := 0
	for _, fragment := range fragments {
		hash := hashFTPStrings([]string{fragment})
		fragmentHashes = append(fragmentHashes, hash)
		if policySet && !approved[hash] {
			mismatches++
		}
	}
	evidence = append(evidence, support.FactEvidence("ftp-banner-summary", map[string]any{
		"banner_fragment_count": len(fragments),
		"banner_set_sha256":     hashFTPStrings(fragmentHashes),
		"dynamic_banner":        dynamic,
		"approved_policy_set":   policySet,
		"policy_mismatch_count": mismatches,
		"content_redacted":      true,
	}))
	if dynamic || len(fragments) == 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "FTP 접속 시 실제로 표시되는 배너를 정적으로 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      "기본값, 동적 파일 또는 조건부 배너가 적용될 수 있음",
			Evidence:      evidence,
		}
	}
	if !policySet {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "승인된 FTP 경고 배너 문구가 없어 정보 노출 여부를 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("정적으로 확인한 배너 조각 %d개", len(fragments)),
			Evidence:      evidence,
		}
	}
	if mismatches > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "FTP 배너가 기관의 승인된 경고 문구와 일치하지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("승인 정책과 다른 배너 조각 %d개", mismatches),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 확인된 FTP 접속 배너가 승인된 경고 문구와 일치합니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("승인된 배너 조각 %d개", len(fragments)),
		Evidence: evidence,
	}
}

func approvedFTPBannerHashes(parameters map[string]any) (map[string]bool, bool, error) {
	values, exists, err := support.StringSliceParameter(parameters, "approved_ftp_banners")
	if err != nil {
		return nil, exists, err
	}
	result := make(map[string]bool, len(values))
	for index, value := range values {
		canonical := canonicalFTPText(value)
		if canonical == "" {
			return nil, exists, fmt.Errorf("approved_ftp_banners item %d is empty", index)
		}
		digest := hashFTPStrings([]string{canonical})
		if result[digest] {
			return nil, exists, fmt.Errorf("approved_ftp_banners has a duplicate item")
		}
		result[digest] = true
	}
	return result, exists && len(result) > 0, nil
}

func inspectProFTPDBanners(ctx context.Context, environment evaluator.Environment, configuration proFTPDConfiguration) ([]string, bool, error) {
	relevant := map[string]bool{"serverident": true, "displayconnect": true}
	if hasProFTPDDynamicScope(configuration.nodes, relevant) || len(directProFTPDNodes(configuration.nodes, "global")) > 0 ||
		len(allProFTPDNodes(configuration.nodes, map[string]bool{"includeoptions": true})) > 0 {
		return nil, true, nil
	}
	fragments := make([]string, 0)
	for _, scope := range proFTPDServerScopes(configuration.nodes) {
		ident, state := singleProFTPDDirective(scope, "serverident")
		if state != "ok" || len(ident.args) < 1 {
			return fragments, true, nil
		}
		switch strings.ToLower(ident.args[0]) {
		case "on":
			if len(ident.args) != 2 || ident.args[1] == "" || strings.Contains(ident.args[1], "%") {
				return fragments, true, nil
			}
			fragments = append(fragments, canonicalFTPText(ident.args[1]))
		case "off":
			return fragments, true, nil
		default:
			return nil, false, fmt.Errorf("ProFTPD ServerIdent has an invalid value")
		}

		display, displayState := singleProFTPDDirective(scope, "displayconnect")
		if displayState == "conflict" {
			return fragments, true, nil
		}
		if displayState == "ok" {
			if len(display.args) != 1 || strings.Contains(display.args[0], "%") {
				return fragments, true, nil
			}
			data, _, err := readFTPPrivateFile(ctx, environment.Files, display.args[0])
			if err != nil {
				return nil, false, err
			}
			if strings.Contains(string(data), "%") {
				return fragments, true, nil
			}
			fragments = append(fragments, canonicalFTPText(string(data)))
		}
	}
	return fragments, false, nil
}

func evaluatePlaintextFTPDisabled(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectFTPTarget(ctx, environment)
	if terminal != nil {
		if terminal.Status == model.StatusNotApplicable {
			present, known, explicitlyDisabled, componentEvidence, inspectErr := inspectFTPComponents(ctx, environment)
			terminal.Evidence = append(terminal.Evidence, componentEvidence...)
			if inspectErr != nil {
				return ftpCheckError("ftp_component_inventory_failed", inspectErr, terminal.Evidence)
			}
			if present {
				if !explicitlyDisabled {
					return evaluator.Outcome{
						Status:        model.StatusUnknown,
						UnknownReason: model.UnknownUnsupportedConfiguration,
						Summary:       "설치된 FTP 서버 구성요소의 재부팅 후 비활성 상태를 확정할 수 없습니다.",
						Expected:      rule.Criteria.Pass,
						Observed:      "inactive 구성요소가 disabled 또는 영구 masked 상태임을 확인하지 못했습니다.",
						Evidence:      terminal.Evidence,
					}
				}
				return evaluator.Outcome{
					Status:   model.StatusPass,
					Summary:  "설치된 FTP 서버 구성요소의 현재 및 부팅 활성 경로가 비활성화되어 있습니다.",
					Expected: rule.Criteria.Pass,
					Observed: "설치된 FTP 패키지 또는 unit은 있으나 active/enabled unit, 프로세스 및 listener가 없습니다.",
					Evidence: terminal.Evidence,
				}
			}
			if !known {
				return evaluator.Outcome{
					Status:        model.StatusUnknown,
					UnknownReason: model.UnknownInsufficientEvidence,
					Summary:       "FTP 서버 구성요소의 설치 여부를 확정할 수 없습니다.",
					Expected:      rule.Criteria.Pass,
					Observed:      "배포판 패키지 데이터베이스와 표준 systemd unit에서 구성요소 부재를 모두 확인하지 못했습니다.",
					Evidence:      terminal.Evidence,
				}
			}
		}
		return *terminal
	}
	evidence := append([]model.Evidence(nil), target.evidence...)
	var state ftpTLSState
	var err error
	switch target.product.id {
	case "vsftpd":
		var configuration vsftpdConfiguration
		configuration, evidence, err = inspectVSFTPDConfiguration(ctx, environment, evidence)
		if err == nil {
			state, err = inspectVSFTPDEncryption(configuration)
		}
	case "proftpd":
		var configuration proFTPDConfiguration
		configuration, evidence, err = inspectProFTPDConfiguration(ctx, environment, evidence)
		if err == nil {
			state, err = inspectProFTPDEncryption(configuration)
		}
	default:
		return unsupportedFTPProduct("FTP 암호화", target)
	}
	if err != nil {
		if errors.Is(err, errFTPUnsupportedConfiguration) {
			return unsupportedFTPCheck("FTP 암호화", "include, 조건부 또는 사용자별 TLS 구성을 완전히 해석할 수 없습니다.", evidence)
		}
		return ftpCheckError("ftp_tls_config_failed", err, evidence)
	}
	evidence = append(evidence, support.FactEvidence("ftp-tls-enforcement-summary", map[string]any{
		"scope_count":                    state.scopeCount,
		"authentication_tls_forced":      state.authenticationForced,
		"data_tls_forced":                state.dataForced,
		"explicit_plaintext_scope_count": state.explicitPlaintext,
		"unknown_scope_count":            state.unknown,
		"details_redacted":               true,
	}))
	if state.explicitPlaintext > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "FTP 인증 또는 데이터 채널에서 평문 사용을 명시적으로 허용하는 경로가 있습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("평문 허용 범위 %d개", state.explicitPlaintext),
			Evidence: evidence,
		}
	}
	if state.unknown > 0 || !state.authenticationForced || !state.dataForced {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "모든 FTP 인증과 데이터 채널에서 TLS가 강제되는지 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("확정 불가 범위 %d개", state.unknown),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 확인된 FTP 인증 및 데이터 채널에서 TLS가 강제됩니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("TLS 강제 범위 %d개", state.scopeCount),
		Evidence: evidence,
	}
}

type ftpTLSState struct {
	scopeCount           int
	authenticationForced bool
	dataForced           bool
	explicitPlaintext    int
	unknown              int
}

func inspectVSFTPDEncryption(configuration vsftpdConfiguration) (ftpTLSState, error) {
	state := ftpTLSState{scopeCount: 1}
	dynamicLoad, err := vsftpdHasDynamicConfiguration(configuration)
	if err != nil {
		return ftpTLSState{}, err
	}
	if configuration.dynamicConfig || dynamicLoad || strings.TrimSpace(configuration.settings["user_config_dir"]) != "" {
		state.unknown++
		return state, nil
	}
	localEnabled, localSet, err := explicitVSFTPDBoolean(configuration, "local_enable")
	if err != nil {
		return ftpTLSState{}, err
	}
	anonymousEnabled, anonymousSet, err := explicitVSFTPDBoolean(configuration, "anonymous_enable")
	if err != nil {
		return ftpTLSState{}, err
	}
	guestEnabled, guestSet, err := explicitVSFTPDBoolean(configuration, "guest_enable")
	if err != nil {
		return ftpTLSState{}, err
	}
	if !localSet || !anonymousSet || (guestSet && guestEnabled) {
		state.unknown++
		return state, nil
	}
	if !localEnabled && !anonymousEnabled {
		state.unknown++
		return state, nil
	}
	sslEnabled, sslSet, err := explicitVSFTPDBoolean(configuration, "ssl_enable")
	if err != nil {
		return ftpTLSState{}, err
	}
	if !sslSet {
		state.unknown++
		return state, nil
	}
	if !sslEnabled {
		state.explicitPlaintext++
		return state, nil
	}
	implicit, _, err := explicitVSFTPDBoolean(configuration, "implicit_ssl")
	if err != nil {
		return ftpTLSState{}, err
	}
	authenticationForced := true
	dataForced := true
	unknown := false
	plaintext := false
	if localEnabled {
		loginForced, loginSet, settingErr := explicitVSFTPDBoolean(configuration, "force_local_logins_ssl")
		if settingErr != nil {
			return ftpTLSState{}, settingErr
		}
		data, dataSet, settingErr := explicitVSFTPDBoolean(configuration, "force_local_data_ssl")
		if settingErr != nil {
			return ftpTLSState{}, settingErr
		}
		if (!implicit && loginSet && !loginForced) || (dataSet && !data) {
			plaintext = true
		}
		if (!implicit && !loginSet) || !dataSet {
			unknown = true
		}
		authenticationForced = authenticationForced && (implicit || loginSet && loginForced)
		dataForced = dataForced && dataSet && data
	}
	if anonymousEnabled {
		allowed, allowedSet, settingErr := explicitVSFTPDBoolean(configuration, "allow_anon_ssl")
		if settingErr != nil {
			return ftpTLSState{}, settingErr
		}
		loginForced, loginSet, settingErr := explicitVSFTPDBoolean(configuration, "force_anon_logins_ssl")
		if settingErr != nil {
			return ftpTLSState{}, settingErr
		}
		data, dataSet, settingErr := explicitVSFTPDBoolean(configuration, "force_anon_data_ssl")
		if settingErr != nil {
			return ftpTLSState{}, settingErr
		}
		if (!implicit && allowedSet && !allowed) || (!implicit && loginSet && !loginForced) || (dataSet && !data) {
			plaintext = true
		}
		if !allowedSet || (implicit && !allowed) || (!implicit && !loginSet) || !dataSet {
			unknown = true
		}
		authenticationForced = authenticationForced && allowedSet && allowed && (implicit || loginSet && loginForced)
		dataForced = dataForced && allowedSet && allowed && dataSet && data
	}
	if plaintext {
		state.explicitPlaintext++
	}
	if unknown {
		state.unknown++
	}
	state.authenticationForced = authenticationForced
	state.dataForced = dataForced
	return state, nil
}

func explicitVSFTPDBoolean(configuration vsftpdConfiguration, key string) (bool, bool, error) {
	value, exists := configuration.settings[key]
	if !exists || strings.TrimSpace(value) == "" {
		return false, false, nil
	}
	switch strings.ToLower(value) {
	case "yes":
		return true, true, nil
	case "no":
		return false, true, nil
	default:
		return false, true, fmt.Errorf("vsftpd boolean directive has an invalid value")
	}
}

func vsftpdHasDynamicConfiguration(configuration vsftpdConfiguration) (bool, error) {
	tcpWrappers, configured, err := explicitVSFTPDBoolean(configuration, "tcp_wrappers")
	if err != nil {
		return false, err
	}
	return configured && tcpWrappers, nil
}

func inspectProFTPDEncryption(configuration proFTPDConfiguration) (ftpTLSState, error) {
	state := ftpTLSState{}
	relevant := map[string]bool{"tlsengine": true, "tlsrequired": true, "tlsoptions": true}
	if hasProFTPDDynamicScope(configuration.nodes, relevant) || len(directProFTPDNodes(configuration.nodes, "global")) > 0 ||
		len(allProFTPDNodes(configuration.nodes, map[string]bool{"includeoptions": true})) > 0 {
		return state, fmt.Errorf("%w: ProFTPD has conditional TLS configuration", errFTPUnsupportedConfiguration)
	}
	for _, scope := range proFTPDServerScopes(configuration.nodes) {
		state.scopeCount++
		engine, engineState := singleProFTPDDirective(scope, "tlsengine")
		required, requiredState := singleProFTPDDirective(scope, "tlsrequired")
		if engineState == "conflict" || requiredState == "conflict" {
			state.unknown++
			continue
		}
		if engineState == "missing" || requiredState == "missing" {
			state.unknown++
			continue
		}
		if len(engine.args) != 1 || len(required.args) != 1 {
			return ftpTLSState{}, fmt.Errorf("ProFTPD TLS directive has invalid arguments")
		}
		engineOn := strings.EqualFold(engine.args[0], "on")
		if !engineOn && !strings.EqualFold(engine.args[0], "off") {
			return ftpTLSState{}, fmt.Errorf("ProFTPD TLSEngine has an invalid value")
		}
		requiredValue := strings.ToLower(required.args[0])
		fullTLS := requiredValue == "on" || requiredValue == "auth+data"
		if !engineOn || !fullTLS {
			state.explicitPlaintext++
			continue
		}
		allowPerUser := false
		for _, options := range directProFTPDNodes(scope, "tlsoptions") {
			for _, option := range options.args {
				allowPerUser = allowPerUser || strings.EqualFold(option, "AllowPerUser")
			}
		}
		if allowPerUser && requiredValue == "on" {
			state.explicitPlaintext++
			continue
		}
		for _, anonymous := range directProFTPDNodes(scope, "anonymous") {
			anonymousRequired, anonymousState := singleProFTPDDirective(anonymous.children, "tlsrequired")
			if anonymousState == "conflict" {
				state.unknown++
				continue
			}
			if anonymousState == "ok" {
				if len(anonymousRequired.args) != 1 {
					return ftpTLSState{}, fmt.Errorf("ProFTPD anonymous TLSRequired has invalid arguments")
				}
				value := strings.ToLower(anonymousRequired.args[0])
				if value != "on" && value != "auth+data" {
					state.explicitPlaintext++
				}
			}
		}
	}
	if state.scopeCount > 0 && state.explicitPlaintext == 0 && state.unknown == 0 {
		state.authenticationForced = true
		state.dataForced = true
	}
	return state, nil
}

func unsupportedFTPProduct(check string, target serviceTarget) evaluator.Outcome {
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       "활성 FTP 제품의 " + check + " 실효 설정을 확인할 수 없습니다.",
		Expected:      "지원되는 FTP 서버의 전체 실효 설정을 확인할 수 있어야 합니다.",
		Observed:      target.product.label,
		Evidence:      target.evidence,
	}
}

func unsupportedFTPCheck(check, observed string, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       check + " 실효 설정을 결정적으로 해석할 수 없습니다.",
		Expected:      "모든 include, 조건부 및 제품별 우선순위를 확인할 수 있어야 합니다.",
		Observed:      observed,
		Evidence:      evidence,
	}
}
