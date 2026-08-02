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

const EvaluatorSudoersPermissions = "unix.service.sudoers_permissions"

const maxSudoersObjects = 4096

type sudoersObjectSet struct {
	Files       []string
	Directories []string
	Complete    bool
	Evidence    []model.Evidence
}

func evaluateSudoersPermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	installed, packageEvidence, err := sudoPackageInstalled(ctx, environment)
	if err != nil {
		return sudoersError("sudo_package_inspection_failed", err, nil)
	}
	evidence := []model.Evidence{packageEvidence}
	mainExists, err := environment.Files.Exists("/etc/sudoers")
	if err != nil {
		return sudoersError("sudoers_stat_failed", err, evidence)
	}
	if !installed && !mainExists && !environment.Commands.Available("visudo") {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "sudo 패키지와 로컬 sudoers 정책이 없습니다.",
			Expected: "sudo가 설치되어 사용될 때 로컬 정책 파일의 소유자와 권한을 점검합니다.",
			Observed: "sudo RPM, visudo, /etc/sudoers 없음",
			Evidence: evidence,
		}
	}
	if !mainExists {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "sudo가 존재하지만 기본 로컬 sudoers 파일이 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      "/etc/sudoers 없음; 중앙 정책 또는 비표준 경로 사용 여부를 확정할 수 없음",
			Evidence:      evidence,
		}
	}
	if !environment.Commands.Available("visudo") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "sudoers 전체 include와 구문을 검증할 visudo가 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      "/etc/sudoers는 존재하지만 visudo를 사용할 수 없음",
			Evidence:      evidence,
		}
	}

	validationSpec := executor.Spec{
		Name: "visudo", Arguments: []string{"-c", "-f", "/etc/sudoers"},
		Timeout: 30 * time.Second, MaxOutput: 2 << 20,
	}
	validation, err := environment.Commands.Run(ctx, validationSpec)
	if err != nil {
		return sudoersError("sudoers_validation_failed", err, evidence)
	}
	evidence = append(evidence, privateCommandSummary(validationSpec, validation))
	if validation.ExitCode != 0 || validation.Truncated {
		return sudoersError("sudoers_validation_failed", fmt.Errorf("visudo exit=%d truncated=%t", validation.ExitCode, validation.Truncated), evidence)
	}

	objects, err := collectSudoersObjects(ctx, environment)
	if err != nil {
		return sudoersError("sudoers_include_collection_failed", err, evidence)
	}
	evidence = append(evidence, objects.Evidence...)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	for _, directory := range objects.Directories {
		assessment, inspectErr := support.InspectPermissions(ctx, environment.Files, environment.Commands, directory, support.PermissionPolicy{
			AllowedUIDs: map[int]struct{}{0: {}}, AllowedMode: 0o755,
			AllowedTypes: map[string]struct{}{"directory": {}}, CheckDefaultACL: true,
		})
		if inspectErr != nil {
			return sudoersError("sudoers_directory_permission_failed", inspectErr, evidence)
		}
		evidence = append(evidence, assessment.Evidence...)
		appendPermissionFindings(directory, assessment, &violations, &unknowns)
	}
	for _, filePath := range objects.Files {
		assessment, inspectErr := support.InspectPermissions(ctx, environment.Files, environment.Commands, filePath, support.PermissionPolicy{
			AllowedUIDs: map[int]struct{}{0: {}}, AllowedMode: 0o640,
			AllowedTypes: map[string]struct{}{"regular": {}},
		})
		if inspectErr != nil {
			return sudoersError("sudoers_file_permission_failed", inspectErr, evidence)
		}
		evidence = append(evidence, assessment.Evidence...)
		appendPermissionFindings(filePath, assessment, &violations, &unknowns)
	}

	selinuxEnforcing, selinuxKnown, selinuxEvidence, err := sudoersSELinuxState(ctx, environment)
	if err != nil {
		return sudoersError("selinux_state_failed", err, evidence)
	}
	evidence = append(evidence, selinuxEvidence...)
	if !selinuxKnown {
		unknowns = append(unknowns, "SELinux Enforcing 상태를 확정할 수 없음")
	} else if selinuxEnforcing {
		if !environment.Commands.Available("matchpathcon") {
			unknowns = append(unknowns, "SELinux 기본 context 검증 도구가 없음")
		} else {
			allPaths := append(append([]string(nil), objects.Directories...), objects.Files...)
			for _, objectPath := range allPaths {
				spec := executor.Spec{Name: "matchpathcon", Arguments: []string{"-V", objectPath}, Timeout: 15 * time.Second, MaxOutput: 1 << 20}
				result, runErr := environment.Commands.Run(ctx, spec)
				if runErr != nil {
					return sudoersError("sudoers_selinux_context_failed", runErr, evidence)
				}
				evidence = append(evidence, privateCommandSummary(spec, result))
				if result.Truncated {
					return sudoersError("sudoers_selinux_context_failed", fmt.Errorf("matchpathcon output truncated for %s", objectPath), evidence)
				}
				switch result.ExitCode {
				case 0:
					if len(result.Stderr) > 0 {
						return sudoersError("sudoers_selinux_context_failed", fmt.Errorf("matchpathcon emitted diagnostics for %s", objectPath), evidence)
					}
				case 1:
					output := strings.TrimSpace(string(result.Stdout))
					if len(result.Stderr) > 0 || output == "" || strings.Contains(output, " error: ") || !strings.Contains(output, " should be ") {
						return sudoersError("sudoers_selinux_context_failed", fmt.Errorf("matchpathcon could not verify %s", objectPath), evidence)
					}
					unknowns = append(unknowns, objectPath+": SELinux context가 정책 기본값과 다름")
				default:
					return sudoersError("sudoers_selinux_context_failed", fmt.Errorf("matchpathcon exit=%d for %s", result.ExitCode, objectPath), evidence)
				}
			}
		}
	}
	if !objects.Complete {
		unknowns = append(unknowns, "비표준 또는 동적 include 경로를 완전히 열거할 수 없음")
	}
	sort.Strings(violations)
	sort.Strings(unknowns)
	evidence = append(evidence, support.FactEvidence("sudoers 권한 파생 정보", map[string]any{
		"file_count": len(objects.Files), "directory_count": len(objects.Directories),
		"violation_count": len(violations), "unknown_count": len(unknowns),
		"include_graph_complete": objects.Complete, "selinux_enforcing": selinuxEnforcing, "selinux_state_known": selinuxKnown,
	}))
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "sudoers 정책 경로에 허용되지 않은 소유자, 권한 또는 ACL이 있습니다.",
			Expected: rule.Criteria.Pass,
			Observed: fmt.Sprintf("명백한 위반 %d건", len(violations)),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "일부 sudoers include, 파일 유형, ACL 또는 SELinux 상태를 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("확정 불가 %d건", len(unknowns)),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "visudo 구문 검증을 통과한 모든 sudoers 경로의 소유자와 권한이 안전합니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("파일 %d개와 include 디렉터리 %d개 확인", len(objects.Files), len(objects.Directories)),
		Evidence: evidence,
	}
}

func sudoPackageInstalled(ctx context.Context, environment evaluator.Environment) (bool, model.Evidence, error) {
	if !environment.Commands.Available("rpm") {
		return false, support.FactEvidence("sudo RPM", map[string]any{"available": false}), nil
	}
	spec := executor.Spec{Name: "rpm", Arguments: []string{"-q", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", "sudo"}, Timeout: 30 * time.Second, MaxOutput: 1 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return false, model.Evidence{}, err
	}
	evidence := privateCommandSummary(spec, result)
	if result.Truncated {
		return false, evidence, fmt.Errorf("rpm output was truncated")
	}
	switch result.ExitCode {
	case 0:
		return true, evidence, nil
	case 1:
		return false, evidence, nil
	default:
		return false, evidence, fmt.Errorf("rpm exit=%d", result.ExitCode)
	}
}

func collectSudoersObjects(ctx context.Context, environment evaluator.Environment) (sudoersObjectSet, error) {
	result := sudoersObjectSet{Complete: true}
	fileQueue := []string{"/etc/sudoers"}
	directoryQueue := make([]string, 0)
	seenFiles := make(map[string]struct{})
	seenDirectories := make(map[string]struct{})
	for len(fileQueue) > 0 || len(directoryQueue) > 0 {
		if len(seenFiles)+len(seenDirectories) >= maxSudoersObjects {
			return result, fmt.Errorf("sudoers include graph exceeds %d objects", maxSudoersObjects)
		}
		if len(directoryQueue) > 0 {
			directory := directoryQueue[0]
			directoryQueue = directoryQueue[1:]
			if _, seen := seenDirectories[directory]; seen {
				continue
			}
			seenDirectories[directory] = struct{}{}
			metadata, err := environment.Files.Lstat(directory)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					result.Complete = false
					result.Evidence = append(result.Evidence, support.FactEvidence(directory, map[string]any{"missing": true}))
					continue
				}
				return result, err
			}
			result.Directories = append(result.Directories, directory)
			if metadata.FileType != "directory" {
				result.Complete = false
				continue
			}
			entries, err := environment.Files.ReadDir(directory)
			if err != nil {
				return result, err
			}
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") || path.Base(name) != name {
					continue
				}
				fileQueue = append(fileQueue, path.Join(directory, name))
			}
			continue
		}

		filePath := fileQueue[0]
		fileQueue = fileQueue[1:]
		if _, seen := seenFiles[filePath]; seen {
			continue
		}
		seenFiles[filePath] = struct{}{}
		data, metadata, err := environment.Files.ReadFile(ctx, filePath, 2<<20)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				result.Complete = false
				result.Evidence = append(result.Evidence, support.FactEvidence(filePath, map[string]any{"missing": true}))
				continue
			}
			if errors.Is(err, os.ErrPermission) {
				return result, err
			}
			// Symlinks and non-regular objects are evaluated by lstat below, but
			// their contents cannot safely drive additional include discovery.
			result.Files = append(result.Files, filePath)
			result.Complete = false
			result.Evidence = append(result.Evidence, support.FactEvidence(filePath, map[string]any{"include_scan_complete": false}))
			continue
		}
		result.Files = append(result.Files, filePath)
		includes, includeDirectories, complete := parseSudoersIncludes(string(data))
		if !complete {
			result.Complete = false
		}
		fileQueue = append(fileQueue, includes...)
		directoryQueue = append(directoryQueue, includeDirectories...)
		result.Evidence = append(result.Evidence, support.FactEvidence(filePath, map[string]any{
			"size": metadata.Size, "include_count": len(includes), "includedir_count": len(includeDirectories),
			"include_scan_complete": complete, "content_redacted": true,
		}))
	}
	result.Files = uniqueSortedServiceStrings(result.Files)
	result.Directories = uniqueSortedServiceStrings(result.Directories)
	return result, nil
}

func parseSudoersIncludes(content string) (files, directories []string, complete bool) {
	complete = true
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		kind := ""
		remainder := ""
		for _, directive := range []struct {
			prefix string
			kind   string
		}{
			{"@includedir", "directory"}, {"#includedir", "directory"},
			{"@include", "file"}, {"#include", "file"},
		} {
			if lower == directive.prefix || (strings.HasPrefix(lower, directive.prefix) && len(line) > len(directive.prefix) && (line[len(directive.prefix)] == ' ' || line[len(directive.prefix)] == '\t')) {
				kind = directive.kind
				remainder = strings.TrimSpace(line[len(directive.prefix):])
				break
			}
		}
		if kind == "" {
			continue
		}
		fields := strings.Fields(remainder)
		if len(fields) == 0 {
			complete = false
			continue
		}
		includePath := fields[0]
		trailingOK := len(fields) == 1 || strings.HasPrefix(fields[1], "#")
		if !trailingOK || !safeSudoersIncludePath(includePath) {
			complete = false
			continue
		}
		if kind == "directory" {
			directories = append(directories, includePath)
		} else {
			files = append(files, includePath)
		}
	}
	return uniqueSortedServiceStrings(files), uniqueSortedServiceStrings(directories), complete
}

func safeSudoersIncludePath(value string) bool {
	return value != "" && path.IsAbs(value) && path.Clean(value) == value &&
		!strings.HasPrefix(value, "-") && !strings.ContainsAny(value, "\x00\r\n\\\"'`$%*?[")
}

func sudoersSELinuxState(ctx context.Context, environment evaluator.Environment) (enforcing, known bool, evidence []model.Evidence, err error) {
	data, metadata, readErr := environment.Files.ReadFile(ctx, "/sys/fs/selinux/enforce", 64)
	if readErr == nil {
		value := strings.TrimSpace(string(data))
		evidence = append(evidence, support.FactEvidence(metadata.Path, map[string]any{"value": value}))
		if value == "1" {
			return true, true, evidence, nil
		}
		if value == "0" {
			return false, true, evidence, nil
		}
		return false, false, evidence, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return false, false, evidence, readErr
	}
	lsmData, lsmMetadata, lsmErr := environment.Files.ReadFile(ctx, "/sys/kernel/security/lsm", 4<<10)
	if lsmErr == nil {
		active, valid := parseActiveLSMs(string(lsmData))
		evidence = append(evidence, support.FactEvidence(lsmMetadata.Path, map[string]any{"active_lsms": active}))
		absent, conclusive := selinuxAbsentFromActiveLSMs(active, valid)
		if !conclusive || !absent {
			return false, false, evidence, nil
		}
		return false, true, evidence, nil
	}
	if !errors.Is(lsmErr, os.ErrNotExist) {
		return false, false, evidence, lsmErr
	}
	config, metadata, configErr := environment.Files.ReadFile(ctx, "/etc/selinux/config", 1<<20)
	if configErr != nil {
		if errors.Is(configErr, os.ErrNotExist) {
			return false, false, evidence, nil
		}
		return false, false, evidence, configErr
	}
	configured := ""
	for _, raw := range strings.Split(strings.ReplaceAll(string(config), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "SELINUX") {
			configured = strings.ToLower(strings.TrimSpace(value))
			break
		}
	}
	evidence = append(evidence, support.FactEvidence(metadata.Path, map[string]any{"configured_mode": configured, "runtime_state_available": false}))
	if configured == "disabled" {
		return false, true, evidence, nil
	}
	return false, false, evidence, nil
}

func parseActiveLSMs(content string) ([]string, bool) {
	value := strings.TrimSpace(content)
	if value == "" {
		return nil, false
	}
	items := strings.Split(value, ",")
	active := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, raw := range items {
		name := strings.TrimSpace(raw)
		if name == "" || strings.ToLower(name) != name || strings.ContainsAny(name, " \t\r\n\x00") {
			return nil, false
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, false
		}
		seen[name] = struct{}{}
		active = append(active, name)
	}
	return active, true
}

func selinuxAbsentFromActiveLSMs(active []string, valid bool) (absent, conclusive bool) {
	if !valid {
		return false, false
	}
	for _, name := range active {
		if name == "selinux" {
			return false, true
		}
	}
	return true, true
}

func appendPermissionFindings(objectPath string, assessment support.PermissionAssessment, violations, unknowns *[]string) {
	if !assessment.Exists {
		*unknowns = append(*unknowns, objectPath+": 로드 대상 없음")
	}
	for _, violation := range assessment.Violations {
		*violations = append(*violations, objectPath+": "+violation)
	}
	for _, unknown := range assessment.Unknowns {
		*unknowns = append(*unknowns, objectPath+": "+unknown)
	}
}

func uniqueSortedServiceStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sudoersError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status: model.StatusError, Summary: "sudoers 정책의 소유자와 권한을 수집하거나 검증하지 못했습니다.",
		ErrorCode: code, ErrorMessage: err.Error(), Evidence: evidence,
	}
}
