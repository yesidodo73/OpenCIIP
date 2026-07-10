package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorMailPatchLevel       = "unix.service.mail_patch_level"
	EvaluatorMailQueueRestriction = "unix.service.mail_queue_restriction"
	EvaluatorMailRelay            = "unix.service.mail_relay"
)

func evaluateMailPatchLevel(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectServiceTarget(ctx, environment, "메일 서비스", mailEnumerationProducts, []int{25, 465, 587}, "tcp")
	if terminal != nil {
		return *terminal
	}
	evidence := append([]model.Evidence(nil), target.evidence...)
	var specs []executor.Spec
	switch target.product.id {
	case "postfix":
		specs = append(specs,
			executor.Spec{Name: "postconf", Arguments: []string{"-h", "mail_version"}, Timeout: 10 * time.Second, MaxOutput: 64 << 10},
			executor.Spec{Name: "rpm", Arguments: []string{"-q", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", "postfix"}, Timeout: 30 * time.Second, MaxOutput: 1 << 20},
		)
	case "sendmail":
		specs = append(specs,
			executor.Spec{Name: "sendmail", Arguments: []string{"-d0.1", "-bv", "root"}, Timeout: 20 * time.Second, MaxOutput: 1 << 20},
			executor.Spec{Name: "rpm", Arguments: []string{"-q", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", "sendmail"}, Timeout: 30 * time.Second, MaxOutput: 1 << 20},
		)
	default:
		return unsupportedTargetOutcome("메일 서비스", "지원하지 않는 MTA의 vendor 패치 수준입니다.", evidence)
	}
	if !environment.Commands.Available("dnf") || !environment.Commands.Available("rpm") {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "MTA 패키지와 vendor 권고를 수집할 도구가 없습니다.", Expected: "RPM NEVRA와 최신 Rocky 보안 metadata를 대조해야 합니다.", Observed: target.product.label, Evidence: evidence}
	}
	specs = append(specs, executor.Spec{Name: "dnf", Arguments: []string{"--cacheonly", "--setopt=metadata_expire=never", "-q", "updateinfo", "list", "--security"}, Timeout: 2 * time.Minute, MaxOutput: 8 << 20})
	for _, spec := range specs {
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return mailPolicyError("mail_patch_evidence_failed", err, evidence)
		}
		evidence = append(evidence, privateCommandSummary(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return mailPolicyError("mail_patch_evidence_failed", fmt.Errorf("%s exit=%d truncated=%t", spec.Name, result.ExitCode, result.Truncated), evidence)
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "활성 MTA의 버전과 캐시된 보안 권고를 수집했으며 최신 패치 여부는 수동 확인이 필요합니다.",
		Expected:      "신뢰 가능한 최신 Rocky metadata와 기관 패치 절차를 기준으로 MTA 보안 권고가 모두 반영되어야 합니다.",
		Observed:      target.product.label + " upstream 버전 문자열만으로 vendor backport 상태를 판정하지 않았습니다.",
		Evidence:      evidence,
	}
}

func evaluateMailQueueRestriction(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectServiceTarget(ctx, environment, "메일 서비스", mailEnumerationProducts, []int{25, 465, 587}, "tcp")
	if terminal != nil {
		return *terminal
	}
	switch target.product.id {
	case "sendmail":
		data, _, err := environment.Files.ReadFile(ctx, "/etc/mail/sendmail.cf", 2<<20)
		if err != nil {
			return mailPolicyError("sendmail_config_read_failed", err, target.evidence)
		}
		privacy, complete, err := parseSendmailPrivacyOptions(string(data))
		if err != nil {
			return mailPolicyError("sendmail_config_parse_failed", err, target.evidence)
		}
		evidence := append(target.evidence, support.FactEvidence("/etc/mail/sendmail.cf", map[string]any{"fully_interpreted": complete, "restrictqrun": privacy["restrictqrun"]}))
		if !complete {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Sendmail PrivacyOptions의 전체 실효값을 확정할 수 없습니다.", Expected: "PrivacyOptions에 restrictqrun이 적용되어야 합니다.", Observed: "include 또는 동적 설정", Evidence: evidence}
		}
		if !privacy["restrictqrun"] {
			return evaluator.Outcome{Status: model.StatusFail, Summary: "일반 사용자의 Sendmail queue 실행이 제한되지 않았습니다.", Expected: "PrivacyOptions에 restrictqrun이 적용되어야 합니다.", Observed: "restrictqrun 없음", Evidence: evidence}
		}
		return evaluator.Outcome{Status: model.StatusPass, Summary: "Sendmail queue 실행이 제한되어 있습니다.", Expected: "PrivacyOptions에 restrictqrun이 적용되어야 합니다.", Observed: "restrictqrun 설정됨", Evidence: evidence}
	case "postfix":
		metadata, err := environment.Files.Lstat("/usr/sbin/postsuper")
		if err != nil {
			return mailPolicyError("postsuper_stat_failed", err, target.evidence)
		}
		evidence := append(target.evidence, support.FileMetadataEvidence(metadata))
		if metadata.FileType != "regular" || metadata.UID < 0 {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Postfix queue 관리 도구의 유형과 소유자를 확정할 수 없습니다.", Expected: "일반 사용자가 queue 관리 권한을 얻지 않아야 합니다.", Observed: metadata.FileType, Evidence: evidence}
		}
		if metadata.UID != 0 || metadata.Mode.Perm()&0o022 != 0 || metadata.Mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return evaluator.Outcome{Status: model.StatusFail, Summary: "Postfix queue 관리 도구에 명백히 위험한 소유자 또는 권한이 있습니다.", Expected: "root 소유이고 비소유자 쓰기와 setuid/setgid가 없어야 합니다.", Observed: fmt.Sprintf("uid=%d mode=%s", metadata.UID, metadata.Mode.String()), Evidence: evidence}
		}
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Postfix 자체 queue 권한 모델과 Rocky 기본 실행 비트를 VM에서 확인해야 합니다.", Expected: "일반 사용자가 postsuper queue 관리 작업을 수행하지 못해야 합니다.", Observed: fmt.Sprintf("uid=%d mode=%s", metadata.UID, metadata.Mode.String()), Evidence: evidence}
	default:
		return unsupportedTargetOutcome("메일 서비스", "지원하지 않는 MTA queue 권한 모델입니다.", target.evidence)
	}
}

func evaluateMailRelay(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectServiceTarget(ctx, environment, "메일 서비스", mailEnumerationProducts, []int{25, 465, 587}, "tcp")
	if terminal != nil {
		return *terminal
	}
	if target.product.id != "postfix" {
		return unsupportedTargetOutcome("메일 서비스", "현재 릴리스는 Postfix relay 제한만 결정적으로 해석합니다.", target.evidence)
	}
	settings := make(map[string]string)
	evidence := append([]model.Evidence(nil), target.evidence...)
	for _, name := range []string{"multi_instance_enable", "smtpd_relay_restrictions", "smtpd_recipient_restrictions", "mynetworks", "relay_domains"} {
		value, valueEvidence, err := postconfPrivateValue(ctx, environment, name)
		if err != nil {
			return mailPolicyError("postfix_relay_config_failed", err, evidence)
		}
		settings[name] = value
		evidence = append(evidence, valueEvidence)
	}
	if !strings.EqualFold(settings["multi_instance_enable"], "no") {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Postfix 다중 인스턴스의 모든 relay 정책을 확정할 수 없습니다.", Expected: "모든 활성 인스턴스의 relay 제한을 확인할 수 있어야 합니다.", Observed: "multi_instance_enable=" + settings["multi_instance_enable"], Evidence: evidence}
	}
	relayTokens := restrictionTokens(settings["smtpd_relay_restrictions"])
	recipientTokens := restrictionTokens(settings["smtpd_recipient_restrictions"])
	unsafe := make([]string, 0)
	if permitBeforeRelayReject(relayTokens) || (len(relayTokens) == 0 && permitBeforeRelayReject(recipientTokens)) {
		unsafe = append(unsafe, "unauth destination 거부 전에 무조건 permit")
	}
	if !containsRelayReject(relayTokens) && !containsRelayReject(recipientTokens) {
		unsafe = append(unsafe, "reject/defer_unauth_destination 없음")
	}
	networks := listParameterValues(settings["mynetworks"])
	for _, network := range networks {
		normalized := strings.ToLower(network)
		if normalized == "0.0.0.0/0" || normalized == "0/0" || normalized == "::/0" || normalized == "[::]/0" || normalized == "*" {
			unsafe = append(unsafe, "모든 주소를 포함하는 mynetworks")
		}
	}
	domains := listParameterValues(settings["relay_domains"])
	for _, domain := range domains {
		if domain == "*" {
			unsafe = append(unsafe, "relay_domains=*")
		}
	}
	unsafe = uniqueStrings(unsafe)
	if len(unsafe) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "Postfix relay 제한에 명백한 open relay 구성이 있습니다.", Expected: "인증 또는 승인 네트워크·도메인만 relay하고 나머지는 unauth destination으로 거부해야 합니다.", Observed: strings.Join(unsafe, "; "), Evidence: evidence}
	}
	approvedNetworks, networkPolicy, err := support.StringSliceParameter(rule.Parameters, "approved_relay_clients")
	if err != nil {
		return mailPolicyError("invalid_rule_parameter", err, evidence)
	}
	approvedDomains, domainPolicy, err := support.StringSliceParameter(rule.Parameters, "approved_relay_domains")
	if err != nil {
		return mailPolicyError("invalid_rule_parameter", err, evidence)
	}
	if !networkPolicy || !domainPolicy || containsDynamicPostfixValue(networks) || containsDynamicPostfixValue(domains) {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "Postfix relay 흐름은 거부 조건을 포함하지만 승인 client·domain 정책과 완전히 대조할 수 없습니다.", Expected: "approved_relay_clients와 approved_relay_domains를 실효값과 대조해야 합니다.", Observed: fmt.Sprintf("mynetworks 항목 %d개, relay_domains 항목 %d개", len(networks), len(domains)), Evidence: evidence}
	}
	networkPolicySet, setErr := makePolicySet(approvedNetworks, "approved_relay_clients")
	if setErr != nil {
		return mailPolicyError("invalid_rule_parameter", setErr, evidence)
	}
	domainPolicySet, setErr := makePolicySet(approvedDomains, "approved_relay_domains")
	if setErr != nil {
		return mailPolicyError("invalid_rule_parameter", setErr, evidence)
	}
	outside := make([]string, 0)
	for _, network := range networks {
		if !networkPolicySet[network] {
			outside = append(outside, "승인 목록 밖 relay client")
		}
	}
	for _, domain := range domains {
		if !domainPolicySet[domain] {
			outside = append(outside, "승인 목록 밖 relay domain")
		}
	}
	if len(outside) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "Postfix relay 범위가 승인 정책보다 넓습니다.", Expected: "실효 relay client와 domain이 승인 목록의 부분집합이어야 합니다.", Observed: strings.Join(uniqueStrings(outside), "; "), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "Postfix relay가 인증 또는 승인된 client·domain으로 제한되어 있습니다.", Expected: "승인 범위 외 relay가 unauth destination으로 거부되어야 합니다.", Observed: fmt.Sprintf("승인 client %d개와 domain %d개를 대조했습니다.", len(networks), len(domains)), Evidence: evidence}
}

func postconfPrivateValue(ctx context.Context, environment evaluator.Environment, name string) (string, model.Evidence, error) {
	spec := executor.Spec{Name: "postconf", Arguments: []string{"-h", name}, Timeout: 10 * time.Second, MaxOutput: 1 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return "", model.Evidence{}, err
	}
	if result.ExitCode != 0 || result.Truncated {
		return "", privateCommandSummary(spec, result), fmt.Errorf("postconf %s exit=%d truncated=%t", name, result.ExitCode, result.Truncated)
	}
	value := strings.TrimSpace(string(result.Stdout))
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", privateCommandSummary(spec, result), fmt.Errorf("postconf %s returned invalid output", name)
	}
	digest := sha256.Sum256(result.Stdout)
	evidence := support.FactEvidence("postconf "+name, map[string]any{
		"executable": result.Executable, "parameter": name, "value_sha256": fmt.Sprintf("%x", digest),
		"value_item_count": len(listParameterValues(value)), "content_redacted": true,
	})
	return value, evidence, nil
}

func restrictionTokens(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return character == ',' || character == ' ' || character == '\t' || character == '\r' || character == '\n'
	})
}

func containsRelayReject(tokens []string) bool {
	for _, token := range tokens {
		if token == "reject_unauth_destination" || token == "defer_unauth_destination" {
			return true
		}
	}
	return false
}

func permitBeforeRelayReject(tokens []string) bool {
	for _, token := range tokens {
		switch token {
		case "reject_unauth_destination", "defer_unauth_destination":
			return false
		case "permit":
			return true
		}
	}
	return false
}

func listParameterValues(value string) []string {
	values := strings.FieldsFunc(strings.TrimSpace(value), func(character rune) bool {
		return character == ',' || character == ' ' || character == '\t' || character == '\r' || character == '\n'
	})
	return uniqueStrings(values)
}

func containsDynamicPostfixValue(values []string) bool {
	for _, value := range values {
		if strings.ContainsAny(value, "$:{}[]") || strings.Contains(value, "=") {
			return true
		}
	}
	return false
}

func mailPolicyError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{Status: model.StatusError, Summary: "메일 서비스 정책을 수집하거나 해석하지 못했습니다.", ErrorCode: code, ErrorMessage: err.Error(), Evidence: evidence}
}
