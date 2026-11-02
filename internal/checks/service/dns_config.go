package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path"
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
	unsafe := 0
	unknown := 0
	for _, zone := range zones {
		directive, state := effectiveBINDDirective(root, zone, "allow-transfer")
		if state != "ok" {
			// BIND changed the absent default from any to none in 9.20, so an
			// unverified Rocky package version must not inherit either default.
			unknown++
			continue
		}
		selectors, complete := bindACLSelectors(root, directive)
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
	}
	evidence = append(evidence, support.FactEvidence("BIND allow-transfer 파생 정보", map[string]any{
		"authoritative_zone_count": len(zones), "unsafe_zone_count": unsafe,
		"unknown_zone_count": unknown, "details_redacted": true,
	}))
	if unsafe > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "모든 호스트에 DNS zone transfer를 허용하는 zone이 있습니다.", Expected: "zone transfer를 비활성화하거나 승인 secondary/TSIG로만 제한해야 합니다.", Observed: fmt.Sprintf("allow-transfer any 적용 zone %d개", unsafe), Evidence: evidence}
	}
	if unknown > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "일부 DNS zone transfer 제한을 확정할 수 없습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("확정 불가 zone %d개", unknown), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "모든 authoritative DNS zone의 transfer가 비활성화되었거나 특정 대상으로 제한되어 있습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("authoritative zone %d개 확인", len(zones)), Evidence: evidence}
}

func evaluateDNSDynamicUpdate(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	root, zones, evidence, terminal := inspectBINDConfig(ctx, environment)
	if terminal != nil {
		return *terminal
	}
	unsafe := 0
	unknown := 0
	for _, zone := range zones {
		if zone.Type != "master" && zone.Type != "primary" {
			forwarding, state := effectiveBINDDirective(root, zone, "allow-update-forwarding")
			if state != "ok" {
				continue // BIND's documented default is none.
			}
			selectors, complete := bindACLSelectors(root, forwarding)
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
			_ = identities
			continue
		}
		if updateState != "ok" {
			continue // allow-update defaults to deny all clients.
		}
		selectors, complete := bindACLSelectors(root, update)
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
	}
	evidence = append(evidence, support.FactEvidence("BIND dynamic update 파생 정보", map[string]any{
		"authoritative_zone_count": len(zones), "unsafe_zone_count": unsafe,
		"unknown_zone_count": unknown, "details_redacted": true,
	}))
	if unsafe > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "모든 주체에 DNS 동적 업데이트를 허용하는 zone이 있습니다.", Expected: "동적 업데이트를 비활성화하거나 승인 TSIG/update-policy 주체로만 제한해야 합니다.", Observed: fmt.Sprintf("무제한 update zone %d개", unsafe), Evidence: evidence}
	}
	if unknown > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "일부 DNS 동적 업데이트 접근 통제를 확정할 수 없습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("확정 불가 zone/조건 %d건", unknown), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "DNS 동적 업데이트가 비활성화되었거나 접근 통제가 설정되어 있습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("authoritative zone %d개 확인", len(zones)), Evidence: evidence}
}

func inspectBINDConfig(ctx context.Context, environment evaluator.Environment) ([]bindNode, []bindZone, []model.Evidence, *evaluator.Outcome) {
	target, terminal := inspectServiceTarget(
		ctx,
		environment,
		"DNS 서비스",
		bindProducts,
		[]int{53},
		"",
		withSystemdResolvedStubExclusion(),
	)
	if terminal != nil {
		return nil, nil, nil, terminal
	}
	configPath, startupEvidence, startupComplete, startupErr := inspectNamedStartupConfig(ctx, environment)
	if startupErr != nil {
		outcome := dnsConfigError("named_startup_config_failed", startupErr, target.evidence)
		return nil, nil, nil, &outcome
	}
	evidence := append([]model.Evidence(nil), target.evidence...)
	evidence = append(evidence, startupEvidence...)
	if !startupComplete {
		outcome := evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "named의 실효 시작 설정 경로를 결정적으로 해석할 수 없습니다.", Expected: "활성 unit의 ExecStart·EnvironmentFile과 -c 경로를 확인할 수 있어야 합니다.", Observed: "custom or ambiguous named startup", Evidence: evidence}
		return nil, nil, nil, &outcome
	}
	spec := executor.Spec{Name: "named-checkconf", Arguments: []string{"-p", "-x", configPath}, Timeout: 30 * time.Second, MaxOutput: 8 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		outcome := dnsConfigError("named_checkconf_failed", err, target.evidence)
		return nil, nil, nil, &outcome
	}
	evidence = append(evidence, privateCommandSummary(spec, result))
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
		outcome := evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "BIND zone 계층을 결정적으로 해석할 수 없습니다.", Expected: "options, view와 zone별 실효 설정을 확인할 수 있어야 합니다.", Observed: "중복되거나 해석할 수 없는 zone type", Evidence: evidence}
		return nil, nil, nil, &outcome
	}
	if containsBINDDynamicZoneBackend(root) {
		outcome := evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "BIND가 정적 zone 블록 외의 동적 authoritative backend를 사용합니다.", Expected: "DLZ·dyndb를 포함한 모든 authoritative zone의 transfer/update 정책을 해석할 수 있어야 합니다.", Observed: "dlz 또는 dyndb backend 발견", Evidence: evidence}
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

func inspectNamedStartupConfig(ctx context.Context, environment evaluator.Environment) (string, []model.Evidence, bool, error) {
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"named.service", "named-chroot.service"})
	if err != nil {
		return "", nil, false, err
	}
	active := make([]support.UnitState, 0, 1)
	for _, unit := range units {
		if support.UnitActive(unit) {
			active = append(active, unit)
		}
	}
	if len(active) != 1 || active[0].Name != "named.service" {
		return "", unitEvidence, false, nil
	}
	spec := executor.Spec{
		Name:      "systemctl",
		Arguments: []string{"show", "--no-pager", "--property=ExecStart,Environment,EnvironmentFiles", "--", active[0].InspectionName},
		Timeout:   15 * time.Second, MaxOutput: 2 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := append(unitEvidence, privateCommandSummary(spec, result))
	if err != nil {
		return "", evidence, false, err
	}
	if result.ExitCode != 0 || result.Truncated {
		return "", evidence, false, fmt.Errorf("systemctl named startup query exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	properties, err := support.ParseKeyValueOutput(string(result.Stdout))
	if err != nil {
		return "", evidence, false, err
	}
	environmentFiles, ok := properties["EnvironmentFiles"]
	if !ok {
		return "", evidence, false, nil
	}
	environmentFiles = strings.TrimSpace(environmentFiles)
	usesSysconfig := environmentFiles != ""
	if usesSysconfig && environmentFiles != "/etc/sysconfig/named" && environmentFiles != "/etc/sysconfig/named (ignore_errors=yes)" {
		return "", evidence, false, nil
	}
	sysconfig := ""
	if usesSysconfig {
		exists, statErr := environment.Files.Exists("/etc/sysconfig/named")
		if statErr != nil {
			return "", evidence, false, statErr
		}
		if exists {
			data, metadata, readErr := environment.Files.ReadFile(ctx, "/etc/sysconfig/named", 256<<10)
			if readErr != nil {
				return "", evidence, false, readErr
			}
			sysconfig = string(data)
			evidence = append(evidence, support.FileMetadataEvidence(metadata))
		}
	}
	configPath, complete, err := namedConfigPathFromSystemdProperties(properties, sysconfig)
	if err != nil {
		return "", evidence, false, err
	}
	evidence = append(evidence, support.FactEvidence("named startup configuration", map[string]any{"custom_config_path": configPath != "/etc/named.conf", "content_redacted": true}))
	return configPath, evidence, complete, nil
}

func namedConfigPathFromSystemdProperties(properties map[string]string, sysconfig string) (string, bool, error) {
	if strings.TrimSpace(properties["Environment"]) != "" {
		return "", false, nil
	}
	execStart, ok := properties["ExecStart"]
	if !ok || strings.Count(execStart, "argv[]=") != 1 {
		return "", false, nil
	}
	pathMarker := "path=/usr/sbin/named ;"
	if !strings.Contains(execStart, pathMarker) {
		return "", false, nil
	}
	start := strings.Index(execStart, "argv[]=") + len("argv[]=")
	remainder := execStart[start:]
	end := strings.Index(remainder, " ;")
	if end < 0 {
		return "", false, nil
	}
	argv := strings.Fields(strings.TrimSpace(remainder[:end]))
	if len(argv) == 0 || argv[0] != "/usr/sbin/named" {
		return "", false, nil
	}
	variables, err := namedSysconfigVariables(sysconfig)
	if err != nil {
		return "", false, err
	}
	expanded := make([]string, 0, len(argv))
	for _, token := range argv {
		name := ""
		if strings.HasPrefix(token, "${") && strings.HasSuffix(token, "}") {
			name = strings.TrimSuffix(strings.TrimPrefix(token, "${"), "}")
		} else if strings.HasPrefix(token, "$") {
			name = strings.TrimPrefix(token, "$")
		}
		if name != "" {
			if name != "OPTIONS" && name != "NAMEDCONF" && name != "NAMED_OPTIONS" {
				return "", false, nil
			}
			expanded = append(expanded, variables[name]...)
			continue
		}
		if strings.ContainsAny(token, "$`%\\\x00\r\n") {
			return "", false, nil
		}
		expanded = append(expanded, token)
	}
	selected := "/etc/named.conf"
	explicit := false
	for index, token := range expanded[1:] {
		actualIndex := index + 1
		candidate := ""
		switch {
		case token == "-t" || strings.HasPrefix(token, "-t"):
			return "", false, nil
		case token == "-c":
			if actualIndex+1 >= len(expanded) {
				return "", false, nil
			}
			candidate = expanded[actualIndex+1]
		case strings.HasPrefix(token, "-c") && len(token) > 2:
			candidate = strings.TrimPrefix(token, "-c")
		}
		if candidate == "" {
			continue
		}
		candidate = strings.TrimPrefix(candidate, "=")
		if !path.IsAbs(candidate) || path.Clean(candidate) != candidate || strings.ContainsAny(candidate, "\\\x00\r\n\"'`$%") {
			return "", false, nil
		}
		if explicit && selected != candidate {
			return "", false, nil
		}
		selected = candidate
		explicit = true
	}
	return selected, true, nil
}

func namedSysconfigVariables(content string) (map[string][]string, error) {
	variables := make(map[string][]string)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		tokens, err := shellAssignmentTokens(raw)
		if err != nil {
			return nil, fmt.Errorf("sysconfig line %d: %w", lineNumber+1, err)
		}
		if len(tokens) == 0 {
			continue
		}
		name := tokens[0]
		if name != "OPTIONS" && name != "NAMEDCONF" && name != "NAMED_OPTIONS" {
			continue
		}
		if _, duplicate := variables[name]; duplicate {
			return nil, fmt.Errorf("sysconfig repeats %s", name)
		}
		values, err := shellAssignmentTokens(strings.Join(tokens[1:], " "))
		if err != nil {
			return nil, fmt.Errorf("sysconfig line %d value: %w", lineNumber+1, err)
		}
		variables[name] = values
	}
	return variables, nil
}

func containsBINDDynamicZoneBackend(root []bindNode) bool {
	for _, node := range root {
		switch strings.ToLower(node.Name) {
		case "dlz", "dyndb":
			return true
		case "view":
			for _, child := range node.Children {
				if strings.EqualFold(child.Name, "dlz") || strings.EqualFold(child.Name, "dyndb") {
					return true
				}
			}
		}
	}
	return false
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

func bindACLSelectors(root []bindNode, node bindNode) ([]string, bool) {
	definitions := make(map[string]bindNode)
	for _, candidate := range root {
		if !strings.EqualFold(candidate.Name, "acl") {
			continue
		}
		if len(candidate.Args) != 1 || len(candidate.Children) == 0 {
			return nil, false
		}
		name := strings.ToLower(candidate.Args[0])
		if name == "" {
			return nil, false
		}
		if _, duplicate := definitions[name]; duplicate {
			return nil, false
		}
		definitions[name] = candidate
	}
	return expandBINDACLSelectors(node, definitions, make(map[string]bool))
}

func expandBINDACLSelectors(node bindNode, definitions map[string]bindNode, resolving map[string]bool) ([]string, bool) {
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
			definition, custom := definitions[name]
			if !custom {
				selectors = append(selectors, child.Name)
				continue
			}
			if resolving[name] {
				return nil, false
			}
			resolving[name] = true
			expanded, complete := expandBINDACLSelectors(definition, definitions, resolving)
			delete(resolving, name)
			if !complete {
				return nil, false
			}
			selectors = append(selectors, expanded...)
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
