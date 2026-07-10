package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorAnonymousShare = "unix.service.anonymous_share"

func evaluateAnonymousShare(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	findings := []warningFinding{
		inspectAnonymousFTP(ctx, environment),
		inspectAnonymousSamba(ctx, environment),
		inspectAnonymousNFS(ctx, rule, environment),
	}
	evidence := make([]model.Evidence, 0)
	counts := map[string]int{"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0, "error": 0}
	for _, finding := range findings {
		counts[finding.State]++
		evidence = append(evidence, finding.Evidence...)
	}
	evidence = append(evidence, support.FactEvidence("익명 공유 접근 파생 정보", map[string]any{
		"ftp_state": findings[0].State, "samba_state": findings[1].State, "nfs_state": findings[2].State,
		"pass_count": counts["pass"], "fail_count": counts["fail"], "unknown_count": counts["unknown"],
		"not_applicable_count": counts["not_applicable"], "error_count": counts["error"], "details_redacted": true,
	}))
	if counts["error"] > 0 {
		return evaluator.Outcome{Status: model.StatusError, Summary: "공유 서비스의 익명 접근 설정을 수집하거나 해석하지 못했습니다.", ErrorCode: "anonymous_share_collection_failed", ErrorMessage: anonymousFindingReasons(findings, "error"), Evidence: evidence}
	}
	if counts["fail"] > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "활성 공유 서비스에 명시적인 익명 또는 무제한 접근 경로가 있습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("명백한 익명 접근 서비스 %d개", counts["fail"]), Evidence: evidence}
	}
	if counts["unknown"] > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "일부 공유 서비스의 접근 범위를 승인 정책과 대조하거나 완전히 해석할 수 없습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("확정 불가 서비스 %d개", counts["unknown"]), Evidence: evidence}
	}
	if counts["pass"] == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "활성 FTP, Samba 또는 NFS 공유 서비스가 없습니다.", Expected: rule.Criteria.Pass, Observed: "공유 endpoint 없음", Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "모든 활성 공유 서비스에서 익명 접근이 차단되거나 승인된 client로 제한됩니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("서비스 %d개 확인", counts["pass"]), Evidence: evidence}
}

func inspectAnonymousFTP(ctx context.Context, environment evaluator.Environment) warningFinding {
	target, terminal := inspectFTPTarget(ctx, environment)
	if terminal != nil {
		return warningFindingFromOutcome("ftp", *terminal)
	}
	finding := warningFinding{Endpoint: "ftp", Evidence: append([]model.Evidence(nil), target.evidence...)}
	switch target.product.id {
	case "vsftpd":
		configuration, evidence, err := inspectVSFTPDConfiguration(ctx, environment, finding.Evidence)
		finding.Evidence = evidence
		if err != nil {
			finding.State, finding.Reason = "error", err.Error()
			return finding
		}
		if configuration.dynamicConfig {
			finding.State, finding.Reason = "unknown", "동적 vsftpd 설정 경로가 있음"
			return finding
		}
		enabled, explicitlySet, err := explicitVSFTPDBoolean(configuration, "anonymous_enable")
		if err != nil {
			finding.State, finding.Reason = "error", err.Error()
			return finding
		}
		// Upstream vsftpd documents anonymous_enable=NO as the compiled-in
		// default; an explicit YES is therefore the only anonymous path here.
		if explicitlySet && enabled {
			finding.State, finding.Reason = "fail", "vsftpd anonymous_enable=YES"
			return finding
		}
		finding.State, finding.Reason = "pass", "vsftpd 익명 로그인이 비활성"
		return finding
	case "proftpd":
		configuration, evidence, err := inspectProFTPDConfiguration(ctx, environment, finding.Evidence)
		finding.Evidence = evidence
		if err != nil {
			if errors.Is(err, errFTPUnsupportedConfiguration) {
				finding.State, finding.Reason = "unknown", "ProFTPD include 구성을 완전히 해석할 수 없음"
			} else {
				finding.State, finding.Reason = "error", err.Error()
			}
			return finding
		}
		summary := inspectProFTPDAnonymousBlocks(configuration.nodes, false)
		finding.Evidence = append(finding.Evidence, support.FactEvidence("proftpd-anonymous-summary", map[string]any{
			"anonymous_block_count": summary.total, "login_blocked_count": summary.blocked,
			"indeterminate_count": summary.indeterminate, "configuration_redacted": true,
		}))
		if summary.indeterminate > 0 {
			finding.State, finding.Reason = "unknown", "일부 ProFTPD Anonymous 블록의 실효 LOGIN 접근을 확정할 수 없음"
			return finding
		}
		if summary.total > 0 {
			finding.State, finding.Reason = "pass", "모든 ProFTPD Anonymous 블록에서 LOGIN이 명시적으로 차단됨"
			return finding
		}
		finding.State, finding.Reason = "pass", "ProFTPD Anonymous 블록 없음"
		return finding
	default:
		finding.State, finding.Reason = "unknown", "지원하지 않는 FTP 제품"
		return finding
	}
}

type proFTPDAnonymousSummary struct {
	total         int
	blocked       int
	indeterminate int
}

func inspectProFTPDAnonymousBlocks(nodes []proFTPDNode, conditionalAncestor bool) proFTPDAnonymousSummary {
	result := proFTPDAnonymousSummary{}
	for _, node := range nodes {
		dynamic := conditionalAncestor || (node.block && (node.name == "ifmodule" || node.name == "ifdefine" || node.name == "ifsession" || node.name == "ifuser" || node.name == "ifgroup" || node.name == "ifclass"))
		if node.block && node.name == "anonymous" {
			result.total++
			if dynamic || !proFTPDAnonymousLoginDenied(node.children) {
				result.indeterminate++
			} else {
				result.blocked++
			}
		}
		if node.block {
			child := inspectProFTPDAnonymousBlocks(node.children, dynamic)
			result.total += child.total
			result.blocked += child.blocked
			result.indeterminate += child.indeterminate
		}
	}
	return result
}

// A ProFTPD Anonymous block is treated as disabled only for the narrow,
// deterministic form <Limit LOGIN> DenyAll </Limit>. Other access-control
// combinations can inherit or merge server/global policy and therefore remain
// UNKNOWN instead of being inferred vulnerable from the block's presence.
func proFTPDAnonymousLoginDenied(nodes []proFTPDNode) bool {
	loginLimits := make([]proFTPDNode, 0, 1)
	for _, node := range directProFTPDNodes(nodes, "limit") {
		for _, command := range node.args {
			if strings.EqualFold(command, "LOGIN") {
				loginLimits = append(loginLimits, node)
				break
			}
		}
	}
	if len(loginLimits) != 1 {
		return false
	}
	children := loginLimits[0].children
	return len(children) == 1 && !children[0].block && children[0].name == "denyall" && len(children[0].args) == 0
}

func inspectAnonymousSamba(ctx context.Context, environment evaluator.Environment) warningFinding {
	target, terminal := inspectServiceTarget(ctx, environment, "Samba 서비스", []serviceProduct{{
		id: "samba", label: "Samba", units: []string{"smb.service", "smbd.service"}, processes: []string{"smbd"},
	}}, []int{139, 445}, "tcp")
	if terminal != nil {
		return warningFindingFromOutcome("samba", *terminal)
	}
	finding := warningFinding{Endpoint: "samba", Evidence: append([]model.Evidence(nil), target.evidence...)}
	if !environment.Commands.Available("testparm") {
		finding.State, finding.Reason = "unknown", "Samba 실효 설정 검증 도구 testparm이 없음"
		return finding
	}
	spec := executor.Spec{Name: "testparm", Arguments: []string{"-s", "-v"}, Timeout: 30 * time.Second, MaxOutput: 8 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	finding.Evidence = append(finding.Evidence, privateCommandSummary(spec, result))
	if result.ExitCode != 0 || result.Truncated {
		finding.State, finding.Reason = "error", fmt.Sprintf("testparm exit=%d truncated=%t", result.ExitCode, result.Truncated)
		return finding
	}
	sections, err := parseTestparmSections(string(result.Stdout))
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	shareCount := 0
	guestShares := 0
	unknownShares := 0
	for name, settings := range sections {
		if name == "global" {
			continue
		}
		shareCount++
		guestOK, ok := sambaBoolean(settings["guest ok"])
		if !ok {
			unknownShares++
			continue
		}
		guestOnly, guestOnlyOK := sambaBoolean(settings["guest only"])
		if !guestOnlyOK {
			unknownShares++
			continue
		}
		if guestOK {
			guestShares++
		} else if guestOnly {
			unknownShares++
		}
	}
	usershareGuests := false
	usershareKnown := true
	if global, exists := sections["global"]; exists {
		usershareGuests, usershareKnown = sambaBoolean(global["usershare allow guests"])
	} else {
		usershareKnown = false
	}
	finding.Evidence = append(finding.Evidence, support.FactEvidence("samba-guest-summary", map[string]any{
		"share_count": shareCount, "guest_share_count": guestShares, "unknown_share_count": unknownShares,
		"usershare_allow_guests": usershareGuests, "usershare_setting_known": usershareKnown, "configuration_redacted": true,
	}))
	if guestShares > 0 {
		finding.State, finding.Reason = "fail", "guest ok/guest only 공유가 있음"
		return finding
	}
	if unknownShares > 0 || !usershareKnown || usershareGuests {
		finding.State, finding.Reason = "unknown", "동적 usershare 또는 일부 guest 실효값을 확정할 수 없음"
		return finding
	}
	if shareCount == 0 {
		finding.State, finding.Reason = "not_applicable", "Samba 공유 섹션 없음"
		return finding
	}
	finding.State, finding.Reason = "pass", "모든 Samba 공유의 guest 접근 비활성"
	return finding
}

func parseTestparmSections(output string) (map[string]map[string]string, error) {
	sections := make(map[string]map[string]string)
	current := ""
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			if current == "" {
				return nil, fmt.Errorf("testparm line %d has an empty section", lineNumber+1)
			}
			if _, exists := sections[current]; !exists {
				sections[current] = make(map[string]string)
			}
			continue
		}
		if current == "" {
			return nil, fmt.Errorf("testparm line %d is outside a section", lineNumber+1)
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("testparm line %d is not key=value", lineNumber+1)
		}
		sections[current][strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return sections, nil
}

func sambaBoolean(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "1":
		return true, true
	case "no", "false", "0":
		return false, true
	default:
		return false, false
	}
}

func inspectAnonymousNFS(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) warningFinding {
	finding := warningFinding{Endpoint: "nfs"}
	if !environment.Commands.Available("exportfs") {
		finding.State, finding.Reason = "not_applicable", "exportfs 없음"
		return finding
	}
	spec := executor.Spec{Name: "exportfs", Arguments: []string{"-v"}, Timeout: 20 * time.Second, MaxOutput: 4 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	finding.Evidence = append(finding.Evidence, privateCommandSummary(spec, result))
	if result.ExitCode != 0 || result.Truncated {
		finding.State, finding.Reason = "error", fmt.Sprintf("exportfs exit=%d truncated=%t", result.ExitCode, result.Truncated)
		return finding
	}
	exports, err := parseEffectiveNFSExports(result.Stdout)
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	if len(exports) == 0 {
		finding.State, finding.Reason = "not_applicable", "활성 NFS export 없음"
		return finding
	}
	approvedClients, clientsSet, err := support.StringSliceParameter(rule.Parameters, "approved_nfs_clients")
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	approvedFlavors, flavorsSet, err := support.StringSliceParameter(rule.Parameters, "approved_nfs_security_flavors")
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	clientPolicy, err := makePolicySet(approvedClients, "approved_nfs_clients")
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	flavorPolicy, err := makePolicySet(approvedFlavors, "approved_nfs_security_flavors")
	if err != nil {
		finding.State, finding.Reason = "error", err.Error()
		return finding
	}
	unsafe := 0
	outsidePolicy := 0
	unknown := 0
	for _, export := range exports {
		if export.Client == "*" || export.Client == "<world>" {
			unsafe++
		} else if !clientsSet {
			unknown++
		} else if !clientPolicy[export.Client] {
			outsidePolicy++
		}
		flavors := strings.Split(export.Options["sec"], ":")
		if export.Options["sec"] == "" {
			unknown++
			continue
		}
		for _, flavor := range flavors {
			if flavor == "none" {
				unsafe++
			} else if !flavorsSet {
				unknown++
			} else if !flavorPolicy[flavor] {
				outsidePolicy++
			}
		}
	}
	finding.Evidence = append(finding.Evidence, support.FactEvidence("nfs-anonymous-summary", map[string]any{
		"export_count": len(exports), "unrestricted_or_sec_none_count": unsafe, "outside_policy_count": outsidePolicy,
		"unknown_policy_count": unknown, "selectors_redacted": true,
	}))
	if unsafe > 0 || outsidePolicy > 0 {
		finding.State, finding.Reason = "fail", "world/sec=none 또는 승인 정책 밖 NFS export가 있음"
		return finding
	}
	if unknown > 0 {
		finding.State, finding.Reason = "unknown", "승인 client/security flavor 정책과 대조할 수 없음"
		return finding
	}
	finding.State, finding.Reason = "pass", "모든 NFS export가 승인 client와 security flavor로 제한됨"
	return finding
}

func anonymousFindingReasons(findings []warningFinding, state string) string {
	reasons := make([]string, 0)
	for _, finding := range findings {
		if finding.State == state {
			reasons = append(reasons, finding.Endpoint+": "+finding.Reason)
		}
	}
	sort.Strings(reasons)
	return strings.Join(reasons, "; ")
}
