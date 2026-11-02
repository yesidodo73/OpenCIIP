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
		presence := evaluateNFSDisabled(ctx, rule, environment)
		return nfsAccessWithoutExportfs(presence)
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
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "활성 NFS export가 없습니다.", Expected: rule.Criteria.Pass, Observed: "exportfs -v 결과 없음", Evidence: evidence}
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
		if metadata.FileType != "regular" {
			permissionUnknown = true
			continue
		}
		if metadata.Mode.Perm()&^os.FileMode(0o644) != 0 || metadata.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			permissionExcess = true
		}
	}
	if !configSeen {
		permissionUnknown = true
	}

	uncontrolled := false
	for _, export := range exports {
		if export.Client == "*" || export.Client == "<world>" {
			uncontrolled = true
		}
	}
	evidence = append(evidence, support.FactEvidence("exportfs -v 파생 정보", map[string]any{
		"export_count": len(exports), "uncontrolled_client": uncontrolled,
		"permission_excess": permissionExcess, "permission_unknown": permissionUnknown, "content_redacted": true,
	}))
	if uncontrolled && permissionExcess {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "NFS 접근 통제가 없고 설정 파일 권한도 644를 초과합니다.", Expected: rule.Criteria.Pass, Observed: "모든 클라이언트에 허용된 export와 설정 파일 권한 초과가 함께 확인됨", Evidence: evidence}
	}
	if uncontrolled || permissionExcess || permissionUnknown {
		parts := make([]string, 0, 3)
		if uncontrolled {
			parts = append(parts, "모든 클라이언트에 허용된 export")
		}
		if permissionExcess {
			parts = append(parts, "설정 파일 권한 644 초과")
		}
		if permissionUnknown {
			parts = append(parts, "설정 파일 유형 또는 권한 확정 불가")
		}
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownAmbiguousResult, Summary: "가이드의 양호·취약 복합 조건 중 한쪽만 확인되어 수동 판단이 필요합니다.", Expected: rule.Criteria.Pass, Observed: strings.Join(parts, "; "), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "NFS 접근 통제가 설정되어 있고 설정 파일 권한이 644 이하입니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("접근 제한 export %d개와 설정 파일 권한을 확인했습니다.", len(exports)), Evidence: evidence}
}

func nfsAccessWithoutExportfs(presence evaluator.Outcome) evaluator.Outcome {
	if presence.Status == model.StatusError {
		return presence
	}
	if presence.Status == model.StatusNotApplicable || presence.Status == model.StatusPass {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "NFS 서버 구성요소와 export가 없습니다.",
			Expected: presence.Expected,
			Observed: presence.Observed,
			Evidence: presence.Evidence,
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       "NFS export 관리 도구가 없어 활성 export의 접근 통제를 확정할 수 없습니다.",
		Expected:      "활성 NFS export와 접근 통제 설정을 결정적으로 확인할 수 있어야 합니다.",
		Observed:      "exportfs 없음; " + presence.Observed,
		Evidence:      presence.Evidence,
	}
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
