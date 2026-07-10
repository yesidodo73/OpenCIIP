package service

import (
	"context"
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

const EvaluatorNFSAccessControl = "unix.service.nfs_access_control"

type effectiveNFSExport struct {
	Path    string
	Client  string
	Options map[string]string
}

func evaluateNFSAccessControl(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if !environment.Commands.Available("exportfs") {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "NFS export 관리 도구가 없어 활성 export 유무를 확정할 수 없습니다.", Expected: "활성 NFS export와 접근 통제 설정을 결정적으로 확인할 수 있어야 합니다.", Observed: "exportfs 없음"}
	}
	spec := executor.Spec{Name: "exportfs", Arguments: []string{"-v"}, Timeout: 20 * time.Second, MaxOutput: 4 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return serviceError("nfs_exportfs_failed", "NFS 접근 통제", err)
	}
	evidence := []model.Evidence{privateCommandSummary(spec, result)}
	if result.ExitCode != 0 || result.Truncated {
		return serviceError("nfs_exportfs_failed", "NFS 접근 통제", fmt.Errorf("exit=%d truncated=%t", result.ExitCode, result.Truncated))
	}
	exports, err := parseEffectiveNFSExports(result.Stdout)
	if err != nil {
		return serviceError("nfs_exportfs_parse_failed", "NFS 접근 통제", err)
	}
	if len(exports) == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "활성 NFS export가 없습니다.", Expected: "활성 NFS export에만 접근 통제 기준을 적용합니다.", Observed: "exportfs -v 결과 없음", Evidence: evidence}
	}

	configPaths, err := nfsExportConfigPaths(environment)
	if err != nil {
		return serviceError("nfs_exports_inspection_failed", "NFS 접근 통제", err)
	}
	permissionExcess := false
	permissionUnknown := false
	configSeen := false
	for _, configPath := range configPaths {
		metadata, statErr := environment.Files.Lstat(configPath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return serviceError("nfs_exports_stat_failed", "NFS 접근 통제", statErr)
		}
		configSeen = true
		evidence = append(evidence, support.FileMetadataEvidence(metadata))
		if metadata.FileType != "regular" || metadata.UID < 0 {
			permissionUnknown = true
			continue
		}
		if metadata.UID != 0 || metadata.Mode.Perm()&^os.FileMode(0o644) != 0 || metadata.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			permissionExcess = true
		}
		aclSpec := executor.Spec{Name: "getfacl", Arguments: []string{"-cpn", "--absolute-names", "--", configPath}, Timeout: 15 * time.Second, MaxOutput: 1 << 20}
		acl, aclErr := environment.Commands.Run(ctx, aclSpec)
		if aclErr != nil {
			return serviceError("nfs_exports_acl_failed", "NFS 접근 통제", aclErr)
		}
		evidence = append(evidence, support.CommandEvidence(aclSpec, acl))
		if acl.ExitCode != 0 || acl.Truncated {
			return serviceError("nfs_exports_acl_failed", "NFS 접근 통제", fmt.Errorf("exit=%d truncated=%t", acl.ExitCode, acl.Truncated))
		}
		excess, parseErr := nfsConfigACLExcess(string(acl.Stdout))
		if parseErr != nil {
			return serviceError("nfs_exports_acl_parse_failed", "NFS 접근 통제", parseErr)
		}
		permissionExcess = permissionExcess || excess
	}
	if !configSeen {
		permissionUnknown = true
	}

	approvedClients, clientsSet, parameterErr := support.StringSliceParameter(rule.Parameters, "approved_nfs_clients")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "NFS 접근 통제", parameterErr)
	}
	approvedFlavors, flavorsSet, parameterErr := support.StringSliceParameter(rule.Parameters, "approved_nfs_security_flavors")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "NFS 접근 통제", parameterErr)
	}
	approvedRWPaths, rwSet, parameterErr := support.StringSliceParameter(rule.Parameters, "approved_nfs_rw_paths")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "NFS 접근 통제", parameterErr)
	}
	clientPolicy, parameterErr := makePolicySet(approvedClients, "approved_nfs_clients")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "NFS 접근 통제", parameterErr)
	}
	flavorPolicy, parameterErr := makePolicySet(approvedFlavors, "approved_nfs_security_flavors")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "NFS 접근 통제", parameterErr)
	}
	rwPolicy, parameterErr := makePolicySet(approvedRWPaths, "approved_nfs_rw_paths")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "NFS 접근 통제", parameterErr)
	}
	uncontrolled := false
	policyViolations := make([]string, 0)
	unknowns := make([]string, 0)
	for _, export := range exports {
		if export.Client == "*" || export.Client == "<world>" {
			uncontrolled = true
			policyViolations = append(policyViolations, "모든 클라이언트에 허용된 export")
		} else if clientsSet && !clientPolicy[export.Client] {
			policyViolations = append(policyViolations, "승인 목록 밖 client selector")
		} else if !clientsSet {
			unknowns = append(unknowns, "approved_nfs_clients 없음")
		}
		if _, disabled := export.Options["no_root_squash"]; disabled {
			policyViolations = append(policyViolations, "no_root_squash")
		} else if _, enabled := export.Options["root_squash"]; !enabled {
			unknowns = append(unknowns, "root_squash 실효값 미확인")
		}
		flavors := strings.Split(export.Options["sec"], ":")
		if export.Options["sec"] == "" {
			unknowns = append(unknowns, "NFS security flavor 미확인")
		} else if !flavorsSet {
			unknowns = append(unknowns, "approved_nfs_security_flavors 없음")
		} else {
			for _, flavor := range flavors {
				if !flavorPolicy[flavor] {
					policyViolations = append(policyViolations, "승인 목록 밖 security flavor")
				}
			}
		}
		if _, writable := export.Options["rw"]; writable {
			if !rwSet {
				unknowns = append(unknowns, "approved_nfs_rw_paths 없음")
			} else if !rwPolicy[export.Path] {
				policyViolations = append(policyViolations, "승인 목록 밖 쓰기 export")
			}
		}
	}
	policyViolations = uniqueStrings(policyViolations)
	unknowns = uniqueStrings(unknowns)
	evidence = append(evidence, support.FactEvidence("exportfs -v 파생 정보", map[string]any{
		"export_count": len(exports), "uncontrolled_client": uncontrolled,
		"policy_violation_count": len(policyViolations), "unknown_count": len(unknowns), "content_redacted": true,
	}))
	if uncontrolled && permissionExcess {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "NFS 접근 통제가 없고 exports 설정 파일 권한도 기준을 초과합니다.", Expected: "승인 client로 제한하고 exports 파일을 root 소유 0644 허용 비트 이내로 유지해야 합니다.", Observed: "world export와 설정 파일 권한 초과가 함께 확인됨", Evidence: evidence}
	}
	if len(policyViolations) > 0 || permissionExcess || permissionUnknown || len(unknowns) > 0 {
		parts := append([]string(nil), policyViolations...)
		if permissionExcess {
			parts = append(parts, "설정 파일 소유자·권한 초과")
		}
		if permissionUnknown {
			parts = append(parts, "설정 파일 유형·소유자 확정 불가")
		}
		parts = append(parts, unknowns...)
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "NFS 접근 통제의 일부 조건을 정책과 대조하거나 확정해야 합니다.", Expected: "승인 client·security flavor·쓰기 경로로 제한하고 exports 파일 권한이 안전해야 합니다.", Observed: strings.Join(uniqueStrings(parts), "; "), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "NFS export가 승인 정책으로 제한되고 설정 파일 권한이 안전합니다.", Expected: "승인 client·security flavor·쓰기 경로로 제한하고 exports 파일 권한이 안전해야 합니다.", Observed: fmt.Sprintf("export %d개를 승인 정책과 대조했습니다.", len(exports)), Evidence: evidence}
}

func parseEffectiveNFSExports(data []byte) ([]effectiveNFSExport, error) {
	result := make([]effectiveNFSExport, 0)
	currentPath := ""
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		index := 0
		if strings.HasPrefix(fields[0], "/") {
			currentPath = path.Clean(fields[0])
			if currentPath != fields[0] {
				return nil, fmt.Errorf("exportfs line %d has a non-canonical path", lineNumber+1)
			}
			index = 1
		}
		if currentPath == "" {
			return nil, fmt.Errorf("exportfs line %d has no export path", lineNumber+1)
		}
		for ; index < len(fields); index++ {
			token := fields[index]
			open := strings.IndexByte(token, '(')
			if open < 1 || !strings.HasSuffix(token, ")") {
				return nil, fmt.Errorf("exportfs line %d has an unsupported client expression", lineNumber+1)
			}
			client := token[:open]
			optionText := strings.TrimSuffix(token[open+1:], ")")
			options := make(map[string]string)
			for _, option := range strings.Split(optionText, ",") {
				key, value, _ := strings.Cut(strings.TrimSpace(option), "=")
				if key == "" {
					return nil, fmt.Errorf("exportfs line %d has an empty option", lineNumber+1)
				}
				options[key] = value
			}
			result = append(result, effectiveNFSExport{Path: currentPath, Client: client, Options: options})
		}
	}
	return result, nil
}

func nfsExportConfigPaths(environment evaluator.Environment) ([]string, error) {
	paths := []string{"/etc/exports"}
	entries, err := environment.Files.ReadDir("/etc/exports.d")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return paths, nil
		}
		return nil, err
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".exports") && path.Base(entry.Name()) == entry.Name() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		paths = append(paths, path.Join("/etc/exports.d", name))
	}
	return paths, nil
}

func nfsConfigACLExcess(content string) (bool, error) {
	mask := os.FileMode(0o7)
	type entry struct {
		tag, qualifier string
		permissions    os.FileMode
	}
	entries := make([]entry, 0)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "default:") {
			continue
		}
		mainPart, _, _ := strings.Cut(line, "#")
		fields := strings.Split(strings.TrimSpace(mainPart), ":")
		if len(fields) != 3 {
			return false, fmt.Errorf("ACL line %d is invalid", lineNumber+1)
		}
		permissions, err := parseSimpleACLMode(fields[2])
		if err != nil {
			return false, fmt.Errorf("ACL line %d: %w", lineNumber+1, err)
		}
		item := entry{tag: fields[0], qualifier: fields[1], permissions: permissions}
		if item.tag == "mask" && item.qualifier == "" {
			mask = permissions
		}
		entries = append(entries, item)
	}
	for _, item := range entries {
		actual := item.permissions
		allowed := os.FileMode(0o4)
		switch {
		case item.tag == "user" && item.qualifier == "":
			allowed = 0o6
		case item.tag == "other" && item.qualifier == "":
			allowed = 0o4
		case item.tag == "mask" && item.qualifier == "":
			allowed = 0o4
		case item.tag == "user" || item.tag == "group":
			actual &= mask
		default:
			return false, fmt.Errorf("unsupported ACL tag %q", item.tag)
		}
		if actual&^allowed != 0 {
			return true, nil
		}
	}
	return false, nil
}

func parseSimpleACLMode(value string) (os.FileMode, error) {
	value = strings.TrimSpace(value)
	if len(value) != 3 {
		return 0, fmt.Errorf("invalid ACL permissions %q", value)
	}
	var result os.FileMode
	for index, expected := range []byte{'r', 'w', 'x'} {
		if value[index] == '-' {
			continue
		}
		if value[index] != expected {
			return 0, fmt.Errorf("invalid ACL permissions %q", value)
		}
		result |= 1 << (2 - index)
	}
	return result, nil
}

func makePolicySet(values []string, name string) (map[string]bool, error) {
	result := make(map[string]bool, len(values))
	for index, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || trimmed != value || strings.IndexByte(trimmed, 0) >= 0 {
			return nil, fmt.Errorf("%s item %d is invalid", name, index)
		}
		if result[trimmed] {
			return nil, fmt.Errorf("%s repeats %q", name, trimmed)
		}
		result[trimmed] = true
	}
	return result, nil
}
