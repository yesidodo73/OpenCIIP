package service

import (
	"context"
	"crypto/sha256"
	"fmt"
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
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "MTA 패키지와 배포판 보안 권고를 수집할 도구가 없습니다.", Expected: "RPM NEVRA와 최신 배포판 보안 메타데이터를 대조해야 합니다.", Observed: target.product.label, Evidence: evidence}
	}
	specs = append(specs, executor.Spec{Name: "dnf", Arguments: []string{"--cacheonly", "--setopt=metadata_expire=never", "-q", "updateinfo", "list", "--security"}, Timeout: 2 * time.Minute, MaxOutput: 8 << 20})
	for _, spec := range specs {
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return mailPolicyError("mail_patch_evidence_failed", err, evidence)
		}
		evidence = append(evidence, privateCommandSummary(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			if spec.Name == "dnf" && support.DNFCacheUnavailable(result) {
				return evaluator.Outcome{
					Status:        model.StatusUnknown,
					UnknownReason: model.UnknownInsufficientEvidence,
					Summary:       "캐시된 저장소 메타데이터가 없어 MTA 보안 패치 상태를 확인할 수 없습니다.",
					Expected:      "신뢰 가능한 최신 벤더 저장소 메타데이터와 로컬 MTA 패키지를 대조해야 합니다.",
					Observed:      "오프라인 DNF 캐시에 필요한 저장소 메타데이터가 없습니다.",
					Evidence:      evidence,
				}
			}
			return mailPolicyError("mail_patch_evidence_failed", fmt.Errorf("%s exit=%d truncated=%t", spec.Name, result.ExitCode, result.Truncated), evidence)
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "활성 MTA의 버전과 캐시된 보안 권고를 수집했으며 최신 패치 여부는 수동 확인이 필요합니다.",
		Expected:      "신뢰 가능한 최신 배포판 보안 메타데이터와 기관 패치 절차를 기준으로 MTA 보안 권고가 모두 반영되어야 합니다.",
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
		return evaluateMailQueueCommandPermission(environment, target, "/usr/sbin/postsuper")
	case "exim":
		return evaluateMailQueueCommandPermission(environment, target, "/usr/sbin/exiqgrep")
	default:
		return unsupportedTargetOutcome("메일 서비스", "지원하지 않는 MTA queue 제한 방식입니다.", target.evidence)
	}
}

func evaluateMailQueueCommandPermission(environment evaluator.Environment, target serviceTarget, commandPath string) evaluator.Outcome {
	metadata, err := environment.Files.Lstat(commandPath)
	if err != nil {
		return mailPolicyError("mail_queue_command_stat_failed", err, target.evidence)
	}
	evidence := append(target.evidence, support.FileMetadataEvidence(metadata))
	if metadata.FileType != "regular" {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "메일 queue 관리 명령의 파일 유형을 확정할 수 없습니다.", Expected: "일반 사용자의 실행 권한이 제거되어야 합니다.", Observed: commandPath + " type=" + metadata.FileType, Evidence: evidence}
	}
	if metadata.Mode.Perm()&0o001 != 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "일반 사용자에게 메일 queue 관리 명령 실행 권한이 있습니다.", Expected: "일반 사용자의 실행 권한이 제거되어야 합니다.", Observed: fmt.Sprintf("%s mode=%04o", commandPath, metadata.Mode.Perm()), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "일반 사용자의 메일 queue 관리 명령 실행 권한이 제거되어 있습니다.", Expected: "일반 사용자의 실행 권한이 제거되어야 합니다.", Observed: fmt.Sprintf("%s mode=%04o", commandPath, metadata.Mode.Perm()), Evidence: evidence}
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
	restrictionAssessment := assessPostfixRelayRestrictions(relayTokens, recipientTokens)
	unsafe := append([]string(nil), restrictionAssessment.unsafe...)
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
	evidence = append(evidence, support.FactEvidence("Postfix relay restriction 파생 정보", map[string]any{
		"relay_restriction_count": len(relayTokens), "recipient_restriction_count": len(recipientTokens),
		"unsafe_count": len(unsafe), "indeterminate_count": len(restrictionAssessment.indeterminate), "content_redacted": true,
	}))
	if len(unsafe) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "Postfix relay 제한에 명백한 open relay 구성이 있습니다.", Expected: "인증 또는 승인 네트워크·도메인만 relay하고 나머지는 unauth destination으로 거부해야 합니다.", Observed: strings.Join(unsafe, "; "), Evidence: evidence}
	}
	if containsDynamicPostfixValue(networks) || containsDynamicPostfixValue(domains) {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Postfix relay 제한의 동적 client 또는 domain 값을 해석할 수 없습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("mynetworks 항목 %d개, relay_domains 항목 %d개", len(networks), len(domains)), Evidence: evidence}
	}
	if len(restrictionAssessment.indeterminate) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Postfix unauth destination 거부 전에 실행되는 restriction의 허용 동작을 결정적으로 해석할 수 없습니다.", Expected: "승인 범위 외 relay가 access map이나 사용자 정의 restriction보다 먼저 또는 그 결과와 관계없이 거부됨을 증명해야 합니다.", Observed: strings.Join(restrictionAssessment.indeterminate, "; "), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "Postfix relay 제한이 설정되어 있습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("relay client %d개와 domain %d개, unauth destination 거부 확인", len(networks), len(domains)), Evidence: evidence}
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

type postfixRelayRestrictionAssessment struct {
	unsafe        []string
	indeterminate []string
}

func assessPostfixRelayRestrictions(relayTokens, recipientTokens []string) postfixRelayRestrictionAssessment {
	assessment := postfixRelayRestrictionAssessment{}
	if relayGuard := postfixRelayGuardIndex(relayTokens); relayGuard >= 0 {
		assessment.addPrefix(relayTokens[:relayGuard])
		return assessment.normalized()
	}
	assessment.addPrefix(relayTokens)
	if recipientGuard := postfixRelayGuardIndex(recipientTokens); recipientGuard >= 0 {
		assessment.addPrefix(recipientTokens[:recipientGuard])
		return assessment.normalized()
	}
	assessment.unsafe = append(assessment.unsafe, "reject/defer_unauth_destination 없음")
	return assessment.normalized()
}

func postfixRelayGuardIndex(tokens []string) int {
	for index, token := range tokens {
		if token == "reject_unauth_destination" || token == "defer_unauth_destination" {
			return index
		}
	}
	return -1
}

func (assessment *postfixRelayRestrictionAssessment) addPrefix(tokens []string) {
	for _, token := range tokens {
		switch {
		case token == "permit":
			assessment.unsafe = append(assessment.unsafe, "unauth destination 거부 전에 무조건 permit")
		case token == "permit_mynetworks", token == "permit_sasl_authenticated", token == "permit_auth_destination":
			// These permits are bounded by values evaluated separately below.
		case token == "reject", token == "defer", token == "dunno", token == "defer_if_permit", token == "defer_if_reject":
			// These tokens cannot grant relay permission by themselves.
		case strings.HasPrefix(token, "reject_"), strings.HasPrefix(token, "defer_"):
			// Reject and defer restrictions cannot grant relay permission by themselves.
		default:
			assessment.indeterminate = append(assessment.indeterminate, "unauth destination 거부 전 사용자 정의·lookup restriction 동작 미확정")
		}
	}
}

func (assessment postfixRelayRestrictionAssessment) normalized() postfixRelayRestrictionAssessment {
	assessment.unsafe = uniqueStrings(assessment.unsafe)
	assessment.indeterminate = uniqueStrings(assessment.indeterminate)
	return assessment
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
