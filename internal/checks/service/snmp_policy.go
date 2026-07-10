package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorSNMPCredentialComplexity = "unix.service.snmp_credential_complexity"
	EvaluatorSNMPAccessControl        = "unix.service.snmp_access_control"
)

func evaluateSNMPCredentialComplexity(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	graph, evidence, terminal := collectNetSNMPAccess(ctx, environment)
	if terminal != nil {
		return *terminal
	}
	v1v2, v3 := graph.accessPathCounts()
	evidence = append(evidence, support.FactEvidence("SNMP 자격증명 파생 정보", map[string]any{
		"weak_community_count": graph.weakCommunities, "strong_community_count": graph.strongCommunities,
		"v1_v2c_access_path_count": v1v2, "v3_access_path_count": v3, "credential_values_redacted": true,
	}))
	if graph.weakCommunities > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "복잡성 기준을 충족하지 않는 SNMP community string이 있습니다.",
			Expected: "community는 public/private가 아니고 영문·숫자 10자 이상 또는 영문·숫자·특수문자 8자 이상이어야 합니다.",
			Observed: fmt.Sprintf("약한 community %d개", graph.weakCommunities),
			Evidence: evidence,
		}
	}
	v3Compliant, attestationSet, err := support.BoolParameter(rule.Parameters, "snmp_v3_credentials_compliant")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	if v3 > 0 {
		if !attestationSet {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "SNMPv3 기존 인증·암호화 비밀번호는 설정에서 복원할 수 없어 정책 준수 증적이 필요합니다.", Expected: "snmp_v3_credentials_compliant attestation 또는 생성·변경 증적이 필요합니다.", Observed: fmt.Sprintf("v3 접근 경로 %d개", v3), Evidence: evidence}
		}
		if !v3Compliant {
			return evaluator.Outcome{Status: model.StatusFail, Summary: "기관 증적에서 SNMPv3 자격증명 정책 미준수가 확인되었습니다.", Expected: "SNMPv3 자격증명이 승인된 복잡성 정책을 충족해야 합니다.", Observed: "snmp_v3_credentials_compliant=false", Evidence: evidence}
		}
	}
	if graph.strongCommunities == 0 && v3 == 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownInsufficientEvidence, Summary: "활성 SNMP 접근 자격증명의 복잡성을 평가할 증적이 없습니다.", Expected: "활성 접근 경로의 community 또는 v3 자격증명 증적이 필요합니다.", Observed: "평가 가능한 자격증명 없음", Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "확인 가능한 SNMP community와 attested v3 자격증명이 복잡성 기준을 충족합니다.", Expected: "모든 활성 SNMP 접근 자격증명이 승인된 복잡성 정책을 충족해야 합니다.", Observed: fmt.Sprintf("강한 community %d개, attested v3 경로 %d개", graph.strongCommunities, v3), Evidence: evidence}
}

func evaluateSNMPAccessControl(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	graph, evidence, terminal := collectNetSNMPAccess(ctx, environment)
	if terminal != nil {
		return *terminal
	}
	communityPrincipals := append([]snmpAccessPrincipal(nil), graph.communityAccess...)
	userPrincipals := append([]snmpAccessPrincipal(nil), graph.userAccess...)
	unknownMappings := 0
	for _, access := range graph.accessRules {
		members := graph.groupMembers[access.Group]
		if len(members) == 0 {
			unknownMappings++
			continue
		}
		for _, member := range members {
			if access.Model != "any" && access.Model != member.Model {
				continue
			}
			switch member.Model {
			case "v1", "v2c":
				sources := graph.securitySources[member.Security]
				if len(sources) == 0 {
					unknownMappings++
					continue
				}
				for _, source := range sources {
					if !strings.EqualFold(access.Read, "none") {
						communityPrincipals = append(communityPrincipals, snmpAccessPrincipal{Source: source, View: access.Read, SecurityLevel: access.Level})
					}
					if !strings.EqualFold(access.Write, "none") {
						communityPrincipals = append(communityPrincipals, snmpAccessPrincipal{Source: source, View: access.Write, Write: true, SecurityLevel: access.Level})
					}
				}
			case "usm", "tsm", "ksm":
				if !strings.EqualFold(access.Read, "none") {
					userPrincipals = append(userPrincipals, snmpAccessPrincipal{Name: member.Security, View: access.Read, SecurityLevel: access.Level})
				}
				if !strings.EqualFold(access.Write, "none") {
					userPrincipals = append(userPrincipals, snmpAccessPrincipal{Name: member.Security, View: access.Write, Write: true, SecurityLevel: access.Level})
				}
			default:
				unknownMappings++
			}
		}
	}
	if len(communityPrincipals) == 0 && len(userPrincipals) == 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownInsufficientEvidence, Summary: "SNMP 접근 주체와 view 경로를 확인할 수 없습니다.", Expected: "활성 SNMP 접근 경로가 승인 source/user 및 최소 view로 제한되어야 합니다.", Observed: "해석된 접근 principal 없음", Evidence: evidence}
	}
	approvedSources, sourcesSet, err := support.StringSliceParameter(rule.Parameters, "approved_snmp_sources")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	approvedUsers, usersSet, err := support.StringSliceParameter(rule.Parameters, "approved_snmp_users")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	approvedViews, viewsSet, err := support.StringSliceParameter(rule.Parameters, "approved_snmp_views")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	approvedWriters, writersSet, err := support.StringSliceParameter(rule.Parameters, "approved_snmp_write_principals")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	sourcePolicy, err := makePolicySet(approvedSources, "approved_snmp_sources")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	userPolicy, err := makePolicySet(approvedUsers, "approved_snmp_users")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	viewPolicy, err := makePolicySet(approvedViews, "approved_snmp_views")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	writerPolicy, err := makePolicySet(approvedWriters, "approved_snmp_write_principals")
	if err != nil {
		return snmpPolicyError("invalid_rule_parameter", err, evidence)
	}
	unsafe := 0
	outsidePolicy := 0
	unknownPolicy := unknownMappings
	writeCount := 0
	for _, principal := range communityPrincipals {
		if broadSNMPSource(principal.Source) {
			unsafe++
		}
		if !sourcesSet {
			unknownPolicy++
		} else if !sourcePolicy[principal.Source] {
			outsidePolicy++
		}
		if !viewsSet {
			unknownPolicy++
		} else if !viewPolicy[principal.View] {
			outsidePolicy++
		}
		if !snmpViewPolicySelfDescribing(principal.View) {
			unknownPolicy++
		}
		if principal.Write {
			writeCount++
			if !writersSet {
				unknownPolicy++
			} else if !writerPolicy["source:"+principal.Source] && !writerPolicy[principal.Source] {
				outsidePolicy++
			}
		}
	}
	for _, principal := range userPrincipals {
		if principal.SecurityLevel == "noauth" {
			unsafe++
		}
		if !usersSet {
			unknownPolicy++
		} else if !userPolicy[principal.Name] {
			outsidePolicy++
		}
		if !viewsSet {
			unknownPolicy++
		} else if !viewPolicy[principal.View] {
			outsidePolicy++
		}
		if !snmpViewPolicySelfDescribing(principal.View) {
			unknownPolicy++
		}
		if principal.Write {
			writeCount++
			if !writersSet {
				unknownPolicy++
			} else if !writerPolicy["user:"+principal.Name] && !writerPolicy[principal.Name] {
				outsidePolicy++
			}
		}
	}
	evidence = append(evidence, support.FactEvidence("SNMP 접근 통제 파생 정보", map[string]any{
		"community_principal_count": len(communityPrincipals), "v3_principal_count": len(userPrincipals),
		"write_path_count": writeCount, "unsafe_path_count": unsafe,
		"outside_policy_count": outsidePolicy, "unknown_mapping_or_policy_count": unknownPolicy,
		"principal_values_redacted": true,
	}))
	if unsafe > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "모든 source를 허용하거나 인증 없는 SNMP 접근 경로가 있습니다.", Expected: "승인 source/user와 필요한 최소 view로 제한하고 v3 인증을 요구해야 합니다.", Observed: fmt.Sprintf("명백히 무통제인 접근 경로 %d개", unsafe), Evidence: evidence}
	}
	if outsidePolicy > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "SNMP 접근 범위가 승인 source/user/view 정책보다 넓습니다.", Expected: "모든 접근 principal과 view가 승인 정책의 부분집합이어야 합니다.", Observed: fmt.Sprintf("승인 정책 밖 조건 %d건", outsidePolicy), Evidence: evidence}
	}
	if unknownPolicy > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "SNMP VACM 경로를 승인 source/user/view 정책과 완전히 대조할 수 없습니다.", Expected: "approved_snmp_sources/users/views와 쓰기 principal 정책이 필요합니다.", Observed: fmt.Sprintf("확정 불가 mapping/policy 조건 %d건", unknownPolicy), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "SNMP 접근 경로가 승인 source/user와 view로 제한되어 있습니다.", Expected: "모든 접근 principal과 view가 승인 정책의 부분집합이어야 합니다.", Observed: fmt.Sprintf("community 경로 %d개, v3 경로 %d개", len(communityPrincipals), len(userPrincipals)), Evidence: evidence}
}

func snmpViewPolicySelfDescribing(view string) bool {
	view = strings.TrimSpace(view)
	return view == "full" || strings.HasPrefix(view, "oid:")
}

func collectNetSNMPAccess(ctx context.Context, environment evaluator.Environment) (*snmpAccessGraph, []model.Evidence, *evaluator.Outcome) {
	target, terminal := inspectServiceTarget(ctx, environment, "SNMP agent", snmpVersionProducts, []int{161}, "udp")
	if terminal != nil {
		return nil, nil, terminal
	}
	evidence := append([]model.Evidence(nil), target.evidence...)
	if exists, err := environment.Files.Exists("/etc/sysconfig/snmpd"); err != nil {
		outcome := snmpPolicyError("snmp_sysconfig_stat_failed", err, evidence)
		return nil, nil, &outcome
	} else if exists {
		data, _, readErr := environment.Files.ReadFile(ctx, "/etc/sysconfig/snmpd", 256<<10)
		if readErr != nil {
			outcome := snmpPolicyError("snmp_sysconfig_read_failed", readErr, evidence)
			return nil, nil, &outcome
		}
		custom, parseErr := snmpUsesCustomConfiguration(string(data))
		if parseErr != nil {
			outcome := snmpPolicyError("snmp_sysconfig_parse_failed", parseErr, evidence)
			return nil, nil, &outcome
		}
		evidence = append(evidence, support.FactEvidence("/etc/sysconfig/snmpd", map[string]any{"custom_configuration": custom}))
		if custom {
			outcome := evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Net-SNMP가 사용자 지정 설정 경로나 접근 모듈로 실행되고 있습니다.", Expected: "표준 설정 전체를 해석할 수 있어야 합니다.", Observed: "기본 설정 로딩 방식 변경", Evidence: evidence}
			return nil, nil, &outcome
		}
	}
	graph := newSNMPAccessGraph()
	discoveryEvidence, discoveryComplete, err := inspectNetSNMPEffectiveConfig(ctx, environment, graph)
	evidence = append(evidence, discoveryEvidence)
	if err != nil {
		outcome := snmpPolicyError("snmp_config_parse_failed", err, evidence)
		return nil, nil, &outcome
	}
	if !discoveryComplete {
		outcome := evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Net-SNMP의 전체 기본 설정 검색 경로를 결정적으로 확인할 수 없습니다.", Expected: "snmpd.conf, snmpd.local.conf와 persistent 설정의 모든 접근 경로를 확인해야 합니다.", Observed: "snmpd read_config discovery incomplete", Evidence: evidence}
		return nil, nil, &outcome
	}
	if !graph.complete {
		outcome := evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "Net-SNMP include 또는 동적 VACM 구성을 완전히 해석할 수 없습니다.", Expected: "모든 접근 설정 파일과 VACM 경로를 확인할 수 있어야 합니다.", Observed: "지원하지 않는 include 또는 access 모듈", Evidence: evidence}
		return nil, nil, &outcome
	}
	evidence = append(evidence, support.FactEvidence("Net-SNMP 실효 기본 설정", map[string]any{
		"files_inspected_count": len(graph.files), "community_access_count": len(graph.communityAccess),
		"user_access_count": len(graph.userAccess), "vacm_access_count": len(graph.accessRules), "values_redacted": true,
	}))
	return graph, evidence, nil
}

func broadSNMPSource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "default", "*", "0.0.0.0/0", "0/0", "::/0", "[::]/0":
		return true
	default:
		return false
	}
}

func snmpPolicyError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{Status: model.StatusError, Summary: "SNMP 정책 설정을 수집하거나 해석하지 못했습니다.", ErrorCode: code, ErrorMessage: err.Error(), Evidence: evidence}
}
