package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorLoginWarning = "unix.service.login_warning"

type warningFinding struct {
	Endpoint string
	State    string
	Reason   string
	Evidence []model.Evidence
}

func evaluateLoginWarning(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	approved, policySet, err := approvedWarningHashes(rule.Parameters)
	if err != nil {
		return loginWarningError("invalid_rule_parameter", err, nil)
	}
	findings := make([]warningFinding, 0, 8)

	issue, err := inspectWarningFile(ctx, environment, "local-console-pre-auth", "/etc/issue", approved, policySet, true)
	if err != nil {
		return loginWarningError("issue_inspection_failed", err, nil)
	}
	findings = append(findings, issue)
	motd, err := inspectWarningFile(ctx, environment, "local-login-post-auth", "/etc/motd", approved, policySet, false)
	if err != nil {
		return loginWarningError("motd_inspection_failed", err, issue.Evidence)
	}
	if dynamic, dynamicEvidence, inspectErr := dynamicMOTDPresent(environment); inspectErr != nil {
		return loginWarningError("motd_dynamic_source_failed", inspectErr, append(issue.Evidence, motd.Evidence...))
	} else {
		motd.Evidence = append(motd.Evidence, dynamicEvidence...)
		if dynamic {
			switch motd.State {
			case "pass":
				motd.State = "unknown"
				motd.Reason = "동적 MOTD 조각이 정적 /etc/motd와 함께 표시될 수 있음"
			case "fail":
				// PAM의 pam_motd는 정적 파일이 없거나 비어 있어도
				// motd.d 및 runtime 조각을 표시할 수 있습니다. 조각의
				// 실효 순서와 내용을 수집하기 전에는 정적 파일 상태만으로
				// 취약하다고 확정하지 않습니다.
				motd.State = "unknown"
				motd.Reason = "정적 /etc/motd는 기준을 충족하지 않지만 동적 MOTD 소스의 실효 문구를 확인하지 못함"
			}
		}
	}
	findings = append(findings, motd)

	findings = append(findings, inspectSSHWarning(ctx, environment, approved, policySet))
	findings = append(findings, inspectTelnetWarning(ctx, environment, approved, policySet))
	findings = append(findings, inspectFTPWarning(ctx, rule, environment))
	findings = append(findings, inspectSMTPWarning(ctx, environment, approved, policySet))
	findings = append(findings, inspectDNSWarning(ctx, environment))

	evidence := make([]model.Evidence, 0)
	counts := map[string]int{"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0, "error": 0}
	reasons := make([]string, 0)
	for _, finding := range findings {
		if finding.State == "" {
			continue
		}
		evidence = append(evidence, finding.Evidence...)
		counts[finding.State]++
		if finding.State == "fail" || finding.State == "unknown" || finding.State == "error" {
			reasons = append(reasons, finding.Endpoint+": "+finding.Reason)
		}
	}
	sort.Strings(reasons)
	evidence = append(evidence, support.FactEvidence("로그인 경고 메시지 파생 정보", map[string]any{
		"endpoint_count": len(findings), "pass_count": counts["pass"], "fail_count": counts["fail"],
		"unknown_count": counts["unknown"], "not_applicable_count": counts["not_applicable"],
		"error_count": counts["error"], "approved_policy_set": policySet, "content_redacted": true,
	}))
	if counts["error"] > 0 {
		return evaluator.Outcome{Status: model.StatusError, Summary: "일부 로그인 endpoint의 경고 메시지를 수집하거나 해석하지 못했습니다.", ErrorCode: "login_warning_endpoint_failed", ErrorMessage: strings.Join(reasons, "; "), Evidence: evidence}
	}
	if counts["fail"] > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "적용 로그인 endpoint에 경고 메시지가 없거나 승인된 문구와 일치하지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("명백한 위반 endpoint %d개", counts["fail"]),
			Evidence: evidence,
		}
	}
	if counts["unknown"] > 0 {
		reason := model.UnknownUnsupportedConfiguration
		if !policySet {
			reason = model.UnknownManualVerification
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       "일부 endpoint의 실제 경고 문구 또는 기관 승인 여부를 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("확정 불가 endpoint %d개", counts["unknown"]),
			Evidence:      evidence,
		}
	}
	if counts["pass"] == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "적용 가능한 로그인 endpoint가 없습니다.", Expected: rule.Criteria.Pass, Observed: "활성 endpoint 없음", Evidence: evidence}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 확인 가능한 로그인 endpoint가 승인된 경고 메시지를 사용합니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("승인 문구와 일치한 endpoint %d개", counts["pass"]),
		Evidence: evidence,
	}
}

func approvedWarningHashes(parameters map[string]any) (map[string]struct{}, bool, error) {
	values, exists, err := support.StringSliceParameter(parameters, "approved_login_warnings")
	if err != nil {
		return nil, exists, err
	}
	hashes := make(map[string]struct{}, len(values))
	for index, value := range values {
		canonical := canonicalWarningText(value)
		if canonical == "" || canonical != value {
			return nil, exists, fmt.Errorf("approved_login_warnings item %d is empty or non-canonical", index)
		}
		digest := warningDigest(canonical)
		if _, duplicate := hashes[digest]; duplicate {
			return nil, exists, fmt.Errorf("approved_login_warnings contains duplicate content")
		}
		hashes[digest] = struct{}{}
	}
	return hashes, exists && len(hashes) > 0, nil
}

func inspectWarningFile(ctx context.Context, environment evaluator.Environment, endpoint, filePath string, approved map[string]struct{}, policySet, issueEscapes bool) (warningFinding, error) {
	finding := warningFinding{Endpoint: endpoint}
	data, metadata, err := environment.Files.ReadFile(ctx, filePath, 2<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			finding.State = "fail"
			finding.Reason = "경고 파일 없음"
			finding.Evidence = append(finding.Evidence, support.FactEvidence(filePath, map[string]any{"exists": false}))
			return finding, nil
		}
		return finding, err
	}
	canonical := canonicalWarningText(string(data))
	digest := warningDigest(canonical)
	finding.Evidence = append(finding.Evidence,
		support.FileMetadataEvidence(metadata),
		support.FactEvidence(filePath, map[string]any{
			"content_sha256": digest, "content_bytes": len(data), "canonical_empty": canonical == "",
			"dynamic_escape_present": issueEscapes && strings.Contains(canonical, "\\"), "content_redacted": true,
		}),
	)
	if canonical == "" {
		finding.State = "fail"
		finding.Reason = "경고 문구가 비어 있음"
		return finding, nil
	}
	if issueEscapes && strings.Contains(canonical, "\\") {
		finding.State = "unknown"
		finding.Reason = "로그인 시 동적으로 확장되는 issue escape가 있음"
		return finding, nil
	}
	if !policySet {
		finding.State = "unknown"
		finding.Reason = "승인된 기관 경고 문구가 제공되지 않음"
		return finding, nil
	}
	if _, accepted := approved[digest]; !accepted {
		finding.State = "fail"
		finding.Reason = "승인된 경고 문구와 불일치"
		return finding, nil
	}
	finding.State = "pass"
	finding.Reason = "승인 문구 일치"
	return finding, nil
}

func dynamicMOTDPresent(environment evaluator.Environment) (bool, []model.Evidence, error) {
	paths := []string{"/run/motd.dynamic"}
	for _, directory := range []string{"/etc/motd.d", "/run/motd.d", "/usr/lib/motd.d"} {
		entries, err := environment.Files.ReadDir(directory)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false, nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() && path.Base(entry.Name()) == entry.Name() {
				paths = append(paths, path.Join(directory, entry.Name()))
			}
		}
	}
	dynamic := false
	for _, filePath := range paths {
		exists, err := environment.Files.Exists(filePath)
		if err != nil {
			return false, nil, err
		}
		dynamic = dynamic || exists
	}
	return dynamic, []model.Evidence{support.FactEvidence("동적 MOTD 경로", map[string]any{"candidate_count": len(paths), "dynamic_source_present": dynamic, "paths_redacted": true})}, nil
}

func inspectSSHWarning(ctx context.Context, environment evaluator.Environment, approved map[string]struct{}, policySet bool) warningFinding {
	finding := warningFinding{Endpoint: "ssh"}
	target, terminal := inspectServiceTarget(ctx, environment, "SSH 서비스", []serviceProduct{{id: "openssh", label: "OpenSSH", units: []string{"sshd.service", "sshd.socket"}, processes: []string{"sshd"}}}, []int{22}, "tcp")
	if terminal != nil {
		return warningFindingFromOutcome("ssh", *terminal)
	}
	finding.Evidence = append(finding.Evidence, target.evidence...)
	ambiguous, ambiguityEvidence, err := sshBannerConfigurationAmbiguous(ctx, environment)
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	finding.Evidence = append(finding.Evidence, ambiguityEvidence...)
	bannerPaths := make(map[string]struct{})
	for _, address := range []string{"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1"} {
		spec := executor.Spec{Name: "sshd", Arguments: []string{"-T", "-C", "user=root,host=localhost,addr=" + address}, Timeout: 15 * time.Second, MaxOutput: 2 << 20}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			finding.State, finding.Reason = "error", runErr.Error()
			return finding
		}
		finding.Evidence = append(finding.Evidence, privateCommandSummary(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			finding.State, finding.Reason = "error", fmt.Sprintf("sshd -T exit=%d truncated=%t", result.ExitCode, result.Truncated)
			return finding
		}
		settings, parseErr := parseSimpleSpaceSettings(string(result.Stdout))
		if parseErr != nil {
			finding.State, finding.Reason = "error", parseErr.Error()
			return finding
		}
		banner := strings.TrimSpace(settings["banner"])
		if banner == "" || strings.EqualFold(banner, "none") {
			finding.State, finding.Reason = "fail", "sshd Banner가 비활성임"
			return finding
		}
		if !path.IsAbs(banner) || path.Clean(banner) != banner || strings.ContainsAny(banner, "\x00\r\n") {
			finding.State, finding.Reason = "unknown", "sshd Banner 경로를 안전하게 해석할 수 없음"
			return finding
		}
		bannerPaths[banner] = struct{}{}
	}
	for bannerPath := range bannerPaths {
		fileFinding, readErr := inspectWarningFile(ctx, environment, "ssh", bannerPath, approved, policySet, false)
		if readErr != nil {
			finding.State, finding.Reason = "error", readErr.Error()
			return finding
		}
		finding.Evidence = append(finding.Evidence, fileFinding.Evidence...)
		if fileFinding.State == "fail" || fileFinding.State == "unknown" {
			finding.State, finding.Reason = fileFinding.State, fileFinding.Reason
			return finding
		}
	}
	if ambiguous {
		finding.State, finding.Reason = "unknown", "Match 또는 비표준 Include의 모든 연결 조건을 열거할 수 없음"
		return finding
	}
	finding.State, finding.Reason = "pass", "모든 확인 조건의 Banner가 승인 문구와 일치"
	return finding
}

func inspectTelnetWarning(ctx context.Context, environment evaluator.Environment, approved map[string]struct{}, policySet bool) warningFinding {
	target, terminal := inspectServiceTarget(ctx, environment, "Telnet 서비스", []serviceProduct{{id: "telnet", label: "Telnet", units: []string{"telnet.service", "telnet.socket", "telnet@.service"}, processes: []string{"in.telnetd", "telnetd"}}}, []int{23}, "tcp")
	if terminal != nil {
		return warningFindingFromOutcome("telnet", *terminal)
	}
	finding := warningFinding{Endpoint: "telnet", Evidence: append([]model.Evidence(nil), target.evidence...)}
	fileFinding, err := inspectWarningFile(ctx, environment, "telnet", "/etc/issue.net", approved, policySet, true)
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	finding.Evidence = append(finding.Evidence, fileFinding.Evidence...)
	if fileFinding.State == "fail" {
		finding.State, finding.Reason = "unknown", "실행 인자에 따른 실제 Telnet 배너 경로를 확정할 수 없음"
		return finding
	}
	finding.State, finding.Reason = "unknown", "Telnet daemon 실행 인자와 실제 전송 배너를 정적으로 확정할 수 없음"
	return finding
}

func inspectFTPWarning(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) warningFinding {
	parameters := make(map[string]any, len(rule.Parameters)+1)
	for key, value := range rule.Parameters {
		parameters[key] = value
	}
	if approved, exists := parameters["approved_login_warnings"]; exists {
		parameters["approved_ftp_banners"] = approved
	}
	rule.Parameters = parameters
	outcome := evaluateFTPBanner(ctx, rule, environment)
	return warningFindingFromOutcome("ftp", outcome)
}

func inspectSMTPWarning(ctx context.Context, environment evaluator.Environment, approved map[string]struct{}, policySet bool) warningFinding {
	target, terminal := inspectServiceTarget(ctx, environment, "메일 서비스", mailEnumerationProducts, []int{25, 465, 587}, "tcp")
	if terminal != nil {
		return warningFindingFromOutcome("smtp", *terminal)
	}
	finding := warningFinding{Endpoint: "smtp", Evidence: append([]model.Evidence(nil), target.evidence...)}
	if target.product.id != "postfix" {
		finding.State, finding.Reason = "unknown", "지원하지 않는 MTA의 실제 SMTP 배너"
		return finding
	}
	banner, bannerEvidence, err := postconfPrivateValue(ctx, environment, "smtpd_banner")
	finding.Evidence = append(finding.Evidence, bannerEvidence)
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	banner = canonicalWarningText(banner)
	if banner == "" {
		finding.State, finding.Reason = "fail", "Postfix SMTP 배너가 비어 있음"
		return finding
	}
	if strings.Contains(banner, "$") {
		finding.State, finding.Reason = "unknown", "Postfix 변수 확장 후 실제 SMTP 배너를 확정할 수 없음"
		return finding
	}
	if !policySet {
		finding.State, finding.Reason = "unknown", "승인된 기관 경고 문구가 제공되지 않음"
		return finding
	}
	if _, accepted := approved[warningDigest(banner)]; !accepted {
		finding.State, finding.Reason = "fail", "승인된 경고 문구와 불일치"
		return finding
	}
	finding.State, finding.Reason = "pass", "승인 문구 일치"
	return finding
}

func inspectDNSWarning(ctx context.Context, environment evaluator.Environment) warningFinding {
	target, terminal := inspectServiceTarget(ctx, environment, "DNS 서비스", bindProducts, []int{53}, "")
	if terminal != nil {
		return warningFindingFromOutcome("dns", *terminal)
	}
	return warningFinding{
		Endpoint: "dns", State: "unknown", Reason: "DNS 서비스에 로그인 경고를 적용한다는 가이드 의미를 제품 동작과 연결할 수 없음",
		Evidence: append([]model.Evidence(nil), target.evidence...),
	}
}

func warningFindingFromOutcome(endpoint string, outcome evaluator.Outcome) warningFinding {
	state := "unknown"
	switch outcome.Status {
	case model.StatusPass:
		state = "pass"
	case model.StatusFail:
		state = "fail"
	case model.StatusError:
		state = "error"
	case model.StatusNotApplicable, model.StatusSkipped:
		state = "not_applicable"
	}
	reason := outcome.Observed
	if reason == "" {
		reason = outcome.Summary
	}
	return warningFinding{Endpoint: endpoint, State: state, Reason: reason, Evidence: outcome.Evidence}
}

func sshBannerConfigurationAmbiguous(ctx context.Context, environment evaluator.Environment) (bool, []model.Evidence, error) {
	files := []string{"/etc/ssh/sshd_config"}
	entries, err := environment.Files.ReadDir("/etc/ssh/sshd_config.d")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, nil, err
	}
	if err == nil {
		names := make([]string, 0)
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") && path.Base(entry.Name()) == entry.Name() {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			files = append(files, "/etc/ssh/sshd_config.d/"+name)
		}
	}
	ambiguous := false
	evidence := make([]model.Evidence, 0, len(files))
	for _, filePath := range files {
		data, metadata, readErr := environment.Files.ReadFile(ctx, filePath, 2<<20)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) && filePath != "/etc/ssh/sshd_config" {
				continue
			}
			return false, evidence, readErr
		}
		directives := 0
		for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			line := stripSimpleConfigComment(raw)
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch strings.ToLower(fields[0]) {
			case "match":
				ambiguous = true
				directives++
			case "include":
				directives++
				if len(fields) != 2 || fields[1] != "/etc/ssh/sshd_config.d/*.conf" {
					ambiguous = true
				}
			}
		}
		digest := sha256.Sum256(data)
		evidence = append(evidence, support.FactEvidence(filePath, map[string]any{
			"size": metadata.Size, "configuration_sha256": fmt.Sprintf("%x", digest),
			"conditional_or_include_directive_count": directives, "content_redacted": true,
		}))
	}
	return ambiguous, evidence, nil
}

func parseSimpleSpaceSettings(output string) (map[string]string, error) {
	settings := make(map[string]string)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("setting line %d is invalid", lineNumber+1)
		}
		settings[strings.ToLower(fields[0])] = strings.Join(fields[1:], " ")
	}
	return settings, nil
}

func stripSimpleConfigComment(value string) string {
	quoted := false
	escaped := false
	for index, character := range value {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			quoted = !quoted
			continue
		}
		if character == '#' && !quoted {
			return strings.TrimSpace(value[:index])
		}
	}
	return strings.TrimSpace(value)
}

func canonicalWarningText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.TrimSpace(value)
}

func warningDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", digest)
}

func loginWarningError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{Status: model.StatusError, Summary: "로그인 경고 메시지 설정을 수집하거나 해석하지 못했습니다.", ErrorCode: code, ErrorMessage: err.Error(), Evidence: evidence}
}
