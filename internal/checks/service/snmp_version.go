package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const EvaluatorSNMPVersion = "unix.service.snmp_version"

var snmpVersionProducts = []serviceProduct{
	{
		id:        "net-snmp",
		label:     "Net-SNMP",
		units:     []string{"snmpd.service", "snmpd.socket"},
		processes: []string{"snmpd"},
	},
}

func evaluateSNMPVersion(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectServiceTarget(ctx, environment, "SNMP agent", snmpVersionProducts, []int{161}, "udp")
	if terminal != nil {
		return *terminal
	}
	if target.product.id != "net-snmp" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 SNMP agent 제품의 버전 접근 경로를 지원하지 않습니다.",
			Expected:      "SNMP v3 접근 경로만 활성화되어야 합니다.",
			Observed:      target.product.label,
			Evidence:      target.evidence,
		}
	}
	return evaluateNetSNMPVersion(ctx, environment, target)
}

func evaluateNetSNMPVersion(ctx context.Context, environment evaluator.Environment, target serviceTarget) evaluator.Outcome {
	const (
		configurationPath = "/etc/snmp/snmpd.conf"
		sysconfigPath     = "/etc/sysconfig/snmpd"
	)
	evidence := append([]model.Evidence(nil), target.evidence...)

	exists, err := environment.Files.Exists(sysconfigPath)
	if err != nil {
		return snmpVersionError("snmp_sysconfig_stat_failed", err)
	}
	if exists {
		data, _, readErr := environment.Files.ReadFile(ctx, sysconfigPath, 256<<10)
		if readErr != nil {
			return snmpVersionError("snmp_sysconfig_read_failed", readErr)
		}
		custom, parseErr := snmpUsesCustomConfiguration(string(data))
		if parseErr != nil {
			return snmpVersionError("snmp_sysconfig_parse_failed", parseErr)
		}
		evidence = append(evidence, support.FactEvidence(sysconfigPath, map[string]any{
			"custom_configuration": custom,
		}))
		if custom {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "Net-SNMP가 사용자 지정 설정 경로나 모듈 구성으로 실행되고 있습니다.",
				Expected:      "표준 Net-SNMP 설정 전체에서 v1 및 v2c 접근 경로가 없어야 합니다.",
				Observed:      "시작 옵션이 기본 설정 로딩 방식을 변경합니다.",
				Evidence:      evidence,
			}
		}
	}

	graph := newSNMPAccessGraph()
	if err := inspectSNMPConfig(ctx, environment.Files, configurationPath, make(map[string]struct{}), graph); err != nil {
		return snmpVersionError("snmp_config_parse_failed", err)
	}
	v1v2Paths, v3Paths := graph.accessPathCounts()
	sort.Strings(graph.files)
	evidence = append(evidence, support.FactEvidence(configurationPath, map[string]any{
		"files_inspected":   graph.files,
		"fully_interpreted": graph.complete,
		"v1_v2c_paths":      v1v2Paths,
		"v3_paths":          v3Paths,
	}))
	if !graph.complete {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "Net-SNMP의 include 또는 사용자 지정 접근 모듈을 완전히 해석할 수 없습니다.",
			Expected:      "모든 실효 설정 파일에서 v1 및 v2c 접근 경로가 없어야 합니다.",
			Observed:      "확인하지 못한 include 또는 동적 접근 모듈이 있습니다.",
			Evidence:      evidence,
		}
	}
	expected := "활성 Net-SNMP agent가 v3 접근 경로만 허용해야 합니다."
	if v1v2Paths > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "Net-SNMP에서 v1 또는 v2c 접근 경로가 활성화되어 있습니다.",
			Expected: expected,
			Observed: fmt.Sprintf("v1/v2c 접근 경로 %d개; v3 접근 경로 %d개", v1v2Paths, v3Paths),
			Evidence: evidence,
		}
	}
	if v3Paths > 0 {
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "Net-SNMP가 v3 접근 경로만 사용하도록 설정되어 있습니다.",
			Expected: expected,
			Observed: fmt.Sprintf("v1/v2c 접근 경로 없음; v3 접근 경로 %d개", v3Paths),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownInsufficientEvidence,
		Summary:       "Net-SNMP의 활성 접근 버전을 확인할 수 없습니다.",
		Expected:      expected,
		Observed:      "해석된 설정에서 v1, v2c 또는 v3 접근 경로를 찾지 못했습니다.",
		Evidence:      evidence,
	}
}

func snmpUsesCustomConfiguration(content string) (bool, error) {
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		tokens, err := shellAssignmentTokens(raw)
		if err != nil {
			return false, fmt.Errorf("line %d has invalid quoting", lineNumber+1)
		}
		for _, token := range tokens {
			if token == "SNMPCONFPATH" || token == "-C" || token == "-c" || token == "-I" ||
				(strings.HasPrefix(token, "-c") && len(token) > 2) || (strings.HasPrefix(token, "-I") && len(token) > 2) {
				return true, nil
			}
		}
	}
	return false, nil
}

type snmpAccessGraph struct {
	complete          bool
	files             []string
	directV1V2        int
	directV3          int
	communityNames    map[string]struct{}
	v1V2Groups        map[string]string
	v3Groups          map[string]string
	accessGroups      map[string]struct{}
	weakCommunities   int
	strongCommunities int
	communityAccess   []snmpAccessPrincipal
	userAccess        []snmpAccessPrincipal
	securitySources   map[string][]string
	groupMembers      map[string][]snmpGroupMember
	accessRules       []snmpVACMRule
	views             map[string]snmpViewSummary
}

type snmpAccessPrincipal struct {
	Name          string
	Source        string
	View          string
	Write         bool
	SecurityLevel string
}

type snmpGroupMember struct {
	Model    string
	Security string
}

type snmpVACMRule struct {
	Group string
	Model string
	Level string
	Read  string
	Write string
}

type snmpViewSummary struct {
	FullIncluded bool
	RuleCount    int
}

func newSNMPAccessGraph() *snmpAccessGraph {
	return &snmpAccessGraph{
		complete:        true,
		communityNames:  make(map[string]struct{}),
		v1V2Groups:      make(map[string]string),
		v3Groups:        make(map[string]string),
		accessGroups:    make(map[string]struct{}),
		securitySources: make(map[string][]string),
		groupMembers:    make(map[string][]snmpGroupMember),
		views:           make(map[string]snmpViewSummary),
	}
}

func (g *snmpAccessGraph) accessPathCounts() (int, int) {
	v1v2 := g.directV1V2
	v3 := g.directV3
	for group, securityName := range g.v1V2Groups {
		if _, hasAccess := g.accessGroups[group]; !hasAccess {
			continue
		}
		if _, hasCommunitySource := g.communityNames[securityName]; hasCommunitySource {
			v1v2++
		}
	}
	for group := range g.v3Groups {
		if _, hasAccess := g.accessGroups[group]; hasAccess {
			v3++
		}
	}
	return v1v2, v3
}

func inspectSNMPConfig(
	ctx context.Context,
	files system.Reader,
	filePath string,
	visited map[string]struct{},
	graph *snmpAccessGraph,
) error {
	if len(visited) >= 64 {
		return fmt.Errorf("SNMP include depth exceeds the supported limit")
	}
	if _, exists := visited[filePath]; exists {
		return nil
	}
	visited[filePath] = struct{}{}
	graph.files = append(graph.files, filePath)
	data, _, err := files.ReadFile(ctx, filePath, 2<<20)
	if err != nil {
		return err
	}

	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		switch directive {
		case "includefile":
			if len(fields) != 2 || !path.IsAbs(fields[1]) || strings.ContainsAny(fields[1], "*?[]") {
				graph.complete = false
				continue
			}
			if err := inspectSNMPConfig(ctx, files, fields[1], visited, graph); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					graph.complete = false
					continue
				}
				return fmt.Errorf("SNMP include at line %d: %w", lineNumber+1, err)
			}
		case "includedir", "includesearch":
			graph.complete = false
		case "rocommunity", "rwcommunity", "rocommunity6", "rwcommunity6":
			if len(fields) < 2 {
				return fmt.Errorf("SNMP access directive at line %d is incomplete", lineNumber+1)
			}
			graph.directV1V2++
			graph.recordCommunity(fields[1])
			source := "default"
			viewStart := 3
			if len(fields) >= 3 && fields[2] == "-V" {
				viewStart = 2
			} else if len(fields) >= 3 {
				source = fields[2]
			}
			graph.communityAccess = append(graph.communityAccess, snmpAccessPrincipal{
				Source: source, View: simpleSNMPView(fields, viewStart), Write: strings.Contains(directive, "rw"),
			})
		case "authcommunity":
			if len(fields) < 3 {
				return fmt.Errorf("SNMP authcommunity directive at line %d is incomplete", lineNumber+1)
			}
			graph.directV1V2++
			graph.recordCommunity(fields[2])
			source := "default"
			viewStart := 4
			if len(fields) >= 4 && fields[3] == "-V" {
				viewStart = 3
			} else if len(fields) >= 4 {
				source = fields[3]
			}
			graph.communityAccess = append(graph.communityAccess, snmpAccessPrincipal{
				Source: source, View: simpleSNMPView(fields, viewStart), Write: containsSNMPAccessType(fields[1], "write"),
			})
		case "rouser", "rwuser", "authuser":
			if len(fields) < 2 {
				return fmt.Errorf("SNMP v3 directive at line %d is incomplete", lineNumber+1)
			}
			graph.directV3++
			principal, ok := parseSimpleSNMPUser(directive, fields)
			if !ok {
				graph.complete = false
			} else {
				graph.userAccess = append(graph.userAccess, principal)
			}
		case "com2sec", "com2sec6":
			if len(fields) < 4 {
				return fmt.Errorf("SNMP security mapping at line %d is incomplete", lineNumber+1)
			}
			graph.communityNames[fields[1]] = struct{}{}
			graph.securitySources[fields[1]] = append(graph.securitySources[fields[1]], fields[2])
			graph.recordCommunity(fields[3])
		case "group":
			if len(fields) < 4 {
				return fmt.Errorf("SNMP group directive at line %d is incomplete", lineNumber+1)
			}
			switch strings.ToLower(fields[2]) {
			case "v1", "v2c":
				graph.v1V2Groups[fields[1]] = fields[3]
			case "usm":
				graph.v3Groups[fields[1]] = fields[3]
			default:
				graph.complete = false
			}
			graph.groupMembers[fields[1]] = append(graph.groupMembers[fields[1]], snmpGroupMember{Model: strings.ToLower(fields[2]), Security: fields[3]})
		case "access":
			if len(fields) < 9 {
				return fmt.Errorf("SNMP access directive at line %d is incomplete", lineNumber+1)
			}
			if strings.ToLower(fields[6]) != "none" || strings.ToLower(fields[7]) != "none" || strings.ToLower(fields[8]) != "none" {
				graph.accessGroups[fields[1]] = struct{}{}
			}
			graph.accessRules = append(graph.accessRules, snmpVACMRule{Group: fields[1], Model: strings.ToLower(fields[3]), Level: strings.ToLower(fields[4]), Read: fields[6], Write: fields[7]})
		case "view":
			if len(fields) < 4 {
				return fmt.Errorf("SNMP view directive at line %d is incomplete", lineNumber+1)
			}
			summary := graph.views[fields[1]]
			summary.RuleCount++
			if strings.EqualFold(fields[2], "included") && (fields[3] == ".1" || strings.EqualFold(fields[3], "iso")) {
				summary.FullIncluded = true
			}
			graph.views[fields[1]] = summary
		case "authgroup", "disableauthorization", "dlmod", "perl":
			graph.complete = false
		case "createuser":
			// Credential provisioning alone does not grant access. No value is retained.
		}
	}
	return nil
}

func (g *snmpAccessGraph) recordCommunity(value string) {
	if communityStrong(value) {
		g.strongCommunities++
	} else {
		g.weakCommunities++
	}
}

func communityStrong(value string) bool {
	if strings.EqualFold(value, "public") || strings.EqualFold(value, "private") {
		return false
	}
	letters := false
	digits := false
	special := false
	length := 0
	for _, character := range value {
		length++
		switch {
		case unicode.IsLetter(character):
			letters = true
		case unicode.IsDigit(character):
			digits = true
		default:
			special = true
		}
	}
	return letters && digits && (length >= 10 || (special && length >= 8))
}

func simpleSNMPView(fields []string, start int) string {
	if start >= len(fields) {
		return "full"
	}
	if fields[start] == "-V" && start+1 < len(fields) {
		return fields[start+1]
	}
	return "oid:" + fields[start]
}

func containsSNMPAccessType(value, wanted string) bool {
	for _, item := range strings.Split(strings.ToLower(value), ",") {
		if strings.TrimSpace(item) == wanted {
			return true
		}
	}
	return false
}

func parseSimpleSNMPUser(directive string, fields []string) (snmpAccessPrincipal, bool) {
	write := directive == "rwuser"
	index := 1
	if directive == "authuser" {
		write = containsSNMPAccessType(fields[1], "write")
		index++
	}
	if index+1 < len(fields) && fields[index] == "-s" {
		index += 2
	}
	if index >= len(fields) {
		return snmpAccessPrincipal{}, false
	}
	principal := snmpAccessPrincipal{Name: fields[index], Write: write, SecurityLevel: "auth", View: "full"}
	index++
	if index < len(fields) {
		switch strings.ToLower(fields[index]) {
		case "noauth", "auth", "priv":
			principal.SecurityLevel = strings.ToLower(fields[index])
			index++
		}
	}
	if index < len(fields) {
		if fields[index] == "-V" && index+1 < len(fields) {
			principal.View = fields[index+1]
		} else {
			principal.View = "oid:" + fields[index]
		}
	}
	return principal, true
}

func snmpVersionError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "SNMP 버전 설정을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
