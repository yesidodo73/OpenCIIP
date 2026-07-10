package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorDNSZoneTransfer  = "unix.service.dns_zone_transfer"
	EvaluatorDNSDynamicUpdate = "unix.service.dns_dynamic_update"
)

var bindProducts = []serviceProduct{{
	id: "bind", label: "BIND", units: []string{"named.service", "named-chroot.service"}, processes: []string{"named"},
}}

type bindNode struct {
	Name     string
	Args     []string
	Children []bindNode
}

type bindZone struct {
	Node bindNode
	View *bindNode
	Type string
}

func evaluateDNSZoneTransfer(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	root, zones, evidence, terminal := inspectBINDConfig(ctx, environment)
	if terminal != nil {
		return *terminal
	}
	approved, policySet, err := support.StringSliceParameter(rule.Parameters, "approved_dns_transfer_selectors")
	if err != nil {
		return dnsConfigError("invalid_rule_parameter", err, evidence)
	}
	approvedSet, err := makePolicySet(approved, "approved_dns_transfer_selectors")
	if err != nil {
		return dnsConfigError("invalid_rule_parameter", err, evidence)
	}
	unsafe := 0
	unknown := 0
	outsidePolicy := 0
	for _, zone := range zones {
		directive, state := effectiveBINDDirective(root, zone, "allow-transfer")
		if state != "ok" {
			// BIND changed the absent default from any to none in 9.20, so an
			// unverified Rocky package version must not inherit either default.
			unknown++
			continue
		}
		selectors, complete := bindACLSelectors(directive)
		if !complete {
			unknown++
			continue
		}
		if isOnlySelector(selectors, "none") {
			continue
		}
		if containsString(selectors, "any") {
			unsafe++
			continue
		}
		if !policySet {
			unknown++
			continue
		}
		for _, selector := range selectors {
			if !approvedSet[selector] {
				outsidePolicy++
			}
		}
	}
	evidence = append(evidence, support.FactEvidence("BIND allow-transfer 파생 정보", map[string]any{
		"authoritative_zone_count": len(zones), "unsafe_zone_count": unsafe,
		"outside_policy_count": outsidePolicy, "unknown_zone_count": unknown, "details_redacted": true,
	}))
	if unsafe > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "모든 호스트에 DNS zone transfer를 허용하는 zone이 있습니다.", Expected: "zone transfer를 비활성화하거나 승인 secondary/TSIG로만 제한해야 합니다.", Observed: fmt.Sprintf("allow-transfer any 적용 zone %d개", unsafe), Evidence: evidence}
	}
	if outsidePolicy > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "DNS zone transfer 허용 범위가 승인 정책보다 넓습니다.", Expected: "모든 transfer selector가 approved_dns_transfer_selectors에 포함되어야 합니다.", Observed: fmt.Sprintf("승인 목록 밖 selector를 가진 zone %d건", outsidePolicy), Evidence: evidence}
	}
	if unknown > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "일부 DNS zone transfer 정책을 패키지 기본값 또는 승인 목록과 대조할 수 없습니다.", Expected: "모든 authoritative zone의 allow-transfer를 명시적으로 제한해야 합니다.", Observed: fmt.Sprintf("확정 불가 zone %d개", unknown), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "모든 authoritative DNS zone의 transfer가 비활성 또는 승인 selector로 제한되어 있습니다.", Expected: "zone transfer를 비활성화하거나 승인 secondary/TSIG로만 제한해야 합니다.", Observed: fmt.Sprintf("authoritative zone %d개 확인", len(zones)), Evidence: evidence}
}

func evaluateDNSDynamicUpdate(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	root, zones, evidence, terminal := inspectBINDConfig(ctx, environment)
	if terminal != nil {
		return *terminal
	}
	approved, policySet, err := support.StringSliceParameter(rule.Parameters, "approved_dns_update_identities")
	if err != nil {
		return dnsConfigError("invalid_rule_parameter", err, evidence)
	}
	approvedSet, err := makePolicySet(approved, "approved_dns_update_identities")
	if err != nil {
		return dnsConfigError("invalid_rule_parameter", err, evidence)
	}
	unsafe := 0
	unknown := 0
	outsidePolicy := 0
	for _, zone := range zones {
		if zone.Type != "master" && zone.Type != "primary" {
			forwarding, state := effectiveBINDDirective(root, zone, "allow-update-forwarding")
			if state != "ok" {
				continue // BIND's documented default is none.
			}
			selectors, complete := bindACLSelectors(forwarding)
			if !complete {
				unknown++
			} else if containsString(selectors, "any") {
				unsafe++
			} else if !isOnlySelector(selectors, "none") {
				unknown++
			}
			continue
		}
		policy, policyState := directBINDDirective(zone.Node.Children, "update-policy")
		update, updateState := effectiveBINDDirective(root, zone, "allow-update")
		if policyState == "duplicate" || updateState == "duplicate" || (policyState == "ok" && updateState == "ok") {
			unknown++
			continue
		}
		if policyState == "ok" {
			identities, complete := bindUpdatePolicyIdentities(policy)
			if !complete {
				unknown++
				continue
			}
			if len(identities) == 0 {
				continue
			}
			if !policySet {
				unknown++
				continue
			}
			for _, identity := range identities {
				if !approvedSet[identity] {
					outsidePolicy++
				}
			}
			continue
		}
		if updateState != "ok" {
			continue // allow-update defaults to deny all clients.
		}
		selectors, complete := bindACLSelectors(update)
		if !complete {
			unknown++
			continue
		}
		if containsString(selectors, "any") {
			unsafe++
			continue
		}
		if isOnlySelector(selectors, "none") {
			continue
		}
		keyIdentities := make([]string, 0)
		for _, selector := range selectors {
			if !strings.HasPrefix(selector, "key:") {
				unknown++
				continue
			}
			keyIdentities = append(keyIdentities, strings.TrimPrefix(selector, "key:"))
		}
		if len(keyIdentities) > 0 && !policySet {
			unknown++
			continue
		}
		for _, identity := range keyIdentities {
			if !approvedSet[identity] && !approvedSet["key:"+identity] {
				outsidePolicy++
			}
		}
	}
	evidence = append(evidence, support.FactEvidence("BIND dynamic update 파생 정보", map[string]any{
		"authoritative_zone_count": len(zones), "unsafe_zone_count": unsafe,
		"outside_policy_count": outsidePolicy, "unknown_zone_count": unknown, "details_redacted": true,
	}))
	if unsafe > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "모든 주체에 DNS 동적 업데이트를 허용하는 zone이 있습니다.", Expected: "동적 업데이트를 비활성화하거나 승인 TSIG/update-policy 주체로만 제한해야 합니다.", Observed: fmt.Sprintf("무제한 update zone %d개", unsafe), Evidence: evidence}
	}
	if outsidePolicy > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "DNS 동적 업데이트 주체가 승인 정책보다 넓습니다.", Expected: "모든 update identity가 approved_dns_update_identities에 포함되어야 합니다.", Observed: fmt.Sprintf("승인 목록 밖 identity %d건", outsidePolicy), Evidence: evidence}
	}
	if unknown > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "일부 DNS 동적 업데이트 정책을 결정적으로 해석하거나 승인 목록과 대조할 수 없습니다.", Expected: "동적 업데이트를 비활성화하거나 승인 TSIG/update-policy 주체로만 제한해야 합니다.", Observed: fmt.Sprintf("확정 불가 zone/조건 %d건", unknown), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "DNS 동적 업데이트가 비활성 또는 승인된 서명 주체로 제한되어 있습니다.", Expected: "동적 업데이트를 비활성화하거나 승인 TSIG/update-policy 주체로만 제한해야 합니다.", Observed: fmt.Sprintf("authoritative zone %d개 확인", len(zones)), Evidence: evidence}
}

func inspectBINDConfig(ctx context.Context, environment evaluator.Environment) ([]bindNode, []bindZone, []model.Evidence, *evaluator.Outcome) {
	target, terminal := inspectServiceTarget(ctx, environment, "DNS 서비스", bindProducts, []int{53}, "")
	if terminal != nil {
		return nil, nil, nil, terminal
	}
	spec := executor.Spec{Name: "named-checkconf", Arguments: []string{"-p", "-x"}, Timeout: 30 * time.Second, MaxOutput: 8 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		outcome := dnsConfigError("named_checkconf_failed", err, target.evidence)
		return nil, nil, nil, &outcome
	}
	evidence := append(target.evidence, privateCommandSummary(spec, result))
	if result.ExitCode != 0 || result.Truncated {
		outcome := dnsConfigError("named_checkconf_failed", fmt.Errorf("exit=%d truncated=%t", result.ExitCode, result.Truncated), evidence)
		return nil, nil, nil, &outcome
	}
	tokens, err := lexBINDConfig(string(result.Stdout))
	if err != nil {
		outcome := dnsConfigError("named_config_lex_failed", err, evidence)
		return nil, nil, nil, &outcome
	}
	index := 0
	root, err := parseBINDNodes(tokens, &index, false)
	if err != nil || index != len(tokens) {
		if err == nil {
			err = fmt.Errorf("configuration has trailing tokens")
		}
		outcome := dnsConfigError("named_config_parse_failed", err, evidence)
		return nil, nil, nil, &outcome
	}
	zones, complete := collectBINDZones(root)
	if !complete {
		outcome := evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "BIND zone 계층을 결정적으로 해석할 수 없습니다.", Expected: "options, view와 zone별 실효 설정을 확인할 수 있어야 합니다.", Observed: "중복 또는 지원하지 않는 zone type", Evidence: evidence}
		return nil, nil, nil, &outcome
	}
	if len(zones) == 0 {
		outcome := evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "적용 가능한 authoritative DNS zone이 없습니다.", Expected: "authoritative zone에만 transfer/update 기준을 적용합니다.", Observed: "primary/secondary/mirror zone 없음", Evidence: evidence}
		return nil, nil, nil, &outcome
	}
	digest := sha256.Sum256(result.Stdout)
	evidence = append(evidence, support.FactEvidence("named-checkconf 파생 정보", map[string]any{
		"configuration_sha256": fmt.Sprintf("%x", digest), "token_count": len(tokens),
		"authoritative_zone_count": len(zones), "configuration_redacted": true,
	}))
	return root, zones, evidence, nil
}

func lexBINDConfig(content string) ([]string, error) {
	tokens := make([]string, 0)
	for index := 0; index < len(content); {
		character := content[index]
		if unicode.IsSpace(rune(character)) {
			index++
			continue
		}
		if character == '#' {
			for index < len(content) && content[index] != '\n' {
				index++
			}
			continue
		}
		if character == '/' && index+1 < len(content) && content[index+1] == '/' {
			index += 2
			for index < len(content) && content[index] != '\n' {
				index++
			}
			continue
		}
		if character == '/' && index+1 < len(content) && content[index+1] == '*' {
			end := strings.Index(content[index+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated block comment")
			}
			index += end + 4
			continue
		}
		if strings.ContainsRune("{};", rune(character)) {
			tokens = append(tokens, string(character))
			index++
			continue
		}
		if character == '"' {
			index++
			var builder strings.Builder
			escaped := false
			closed := false
			for index < len(content) {
				current := content[index]
				index++
				if escaped {
					builder.WriteByte(current)
					escaped = false
					continue
				}
				if current == '\\' {
					escaped = true
					continue
				}
				if current == '"' {
					closed = true
					break
				}
				builder.WriteByte(current)
			}
			if !closed || escaped {
				return nil, fmt.Errorf("unterminated quoted string")
			}
			tokens = append(tokens, builder.String())
			continue
		}
		start := index
		for index < len(content) && !unicode.IsSpace(rune(content[index])) && !strings.ContainsRune("{};\"#", rune(content[index])) {
			if content[index] == '/' && index+1 < len(content) && (content[index+1] == '/' || content[index+1] == '*') {
				break
			}
			index++
		}
		if start == index {
			return nil, fmt.Errorf("unsupported character at byte %d", index)
		}
		tokens = append(tokens, content[start:index])
	}
	return tokens, nil
}

func parseBINDNodes(tokens []string, index *int, nested bool) ([]bindNode, error) {
	nodes := make([]bindNode, 0)
	statement := make([]string, 0)
	for *index < len(tokens) {
		token := tokens[*index]
		(*index)++
		switch token {
		case "}":
			if !nested || len(statement) > 0 {
				return nil, fmt.Errorf("unexpected closing brace")
			}
			return nodes, nil
		case ";":
			if len(statement) == 0 {
				continue
			}
			nodes = append(nodes, bindNode{Name: strings.ToLower(statement[0]), Args: append([]string(nil), statement[1:]...)})
			statement = statement[:0]
		case "{":
			if len(statement) == 0 {
				return nil, fmt.Errorf("block has no statement name")
			}
			children, err := parseBINDNodes(tokens, index, true)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, bindNode{Name: strings.ToLower(statement[0]), Args: append([]string(nil), statement[1:]...), Children: children})
			statement = statement[:0]
		default:
			statement = append(statement, token)
		}
	}
	if nested {
		return nil, fmt.Errorf("unterminated block")
	}
	if len(statement) > 0 {
		return nil, fmt.Errorf("unterminated statement")
	}
	return nodes, nil
}

func collectBINDZones(root []bindNode) ([]bindZone, bool) {
	zones := make([]bindZone, 0)
	complete := true
	add := func(node bindNode, view *bindNode) {
		typeNode, state := directBINDDirective(node.Children, "type")
		if state != "ok" || len(typeNode.Args) != 1 {
			complete = false
			return
		}
		zoneType := strings.ToLower(typeNode.Args[0])
		switch zoneType {
		case "master", "primary", "slave", "secondary", "mirror":
			zones = append(zones, bindZone{Node: node, View: view, Type: zoneType})
		case "hint", "forward", "stub", "static-stub", "redirect", "delegation-only":
		default:
			complete = false
		}
	}
	for index := range root {
		node := &root[index]
		switch node.Name {
		case "zone":
			add(*node, nil)
		case "view":
			for childIndex := range node.Children {
				if node.Children[childIndex].Name == "zone" {
					add(node.Children[childIndex], node)
				}
			}
		}
	}
	return zones, complete
}

func effectiveBINDDirective(root []bindNode, zone bindZone, name string) (bindNode, string) {
	if node, state := directBINDDirective(zone.Node.Children, name); state != "missing" {
		return node, state
	}
	if zone.View != nil {
		if node, state := directBINDDirective(zone.View.Children, name); state != "missing" {
			return node, state
		}
	}
	options, state := directBINDDirective(root, "options")
	if state != "ok" {
		return bindNode{}, state
	}
	return directBINDDirective(options.Children, name)
}

func directBINDDirective(nodes []bindNode, name string) (bindNode, string) {
	found := make([]bindNode, 0, 1)
	for _, node := range nodes {
		if strings.EqualFold(node.Name, name) {
			found = append(found, node)
		}
	}
	if len(found) == 0 {
		return bindNode{}, "missing"
	}
	if len(found) > 1 {
		return bindNode{}, "duplicate"
	}
	return found[0], "ok"
}

func bindACLSelectors(node bindNode) ([]string, bool) {
	if len(node.Children) == 0 {
		return nil, false
	}
	selectors := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		if len(child.Children) > 0 {
			return nil, false
		}
		name := strings.ToLower(child.Name)
		switch name {
		case "key":
			if len(child.Args) != 1 {
				return nil, false
			}
			selectors = append(selectors, "key:"+child.Args[0])
		case "!":
			return nil, false
		default:
			if len(child.Args) != 0 {
				return nil, false
			}
			selectors = append(selectors, child.Name)
		}
	}
	return uniqueStrings(selectors), true
}

func bindUpdatePolicyIdentities(node bindNode) ([]string, bool) {
	if len(node.Args) == 1 && strings.EqualFold(node.Args[0], "local") && len(node.Children) == 0 {
		return []string{"local"}, true
	}
	identities := make([]string, 0)
	for _, rule := range node.Children {
		switch strings.ToLower(rule.Name) {
		case "deny":
			continue
		case "grant":
			if len(rule.Args) < 3 {
				return nil, false
			}
			identities = append(identities, rule.Args[0])
		default:
			return nil, false
		}
	}
	return uniqueStrings(identities), true
}

func isOnlySelector(values []string, wanted string) bool {
	return len(values) == 1 && strings.EqualFold(values[0], wanted)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func dnsConfigError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{Status: model.StatusError, Summary: "DNS 서비스 설정을 수집하거나 해석하지 못했습니다.", ErrorCode: code, ErrorMessage: err.Error(), Evidence: evidence}
}
