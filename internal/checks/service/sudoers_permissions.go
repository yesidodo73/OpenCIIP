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
	assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, "/etc/sudoers", support.PermissionPolicy{
		AllowedUIDs: map[int]struct{}{0: {}}, AllowedMode: 0o640,
		AllowedTypes: map[string]struct{}{"regular": {}},
		SkipACL:      true,
	})
	if err != nil {
		return sudoersError("sudoers_permission_failed", err, nil)
	}
	if !assessment.Exists {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "/etc/sudoers 파일이 없습니다.",
			Expected: rule.Criteria.Pass,
			Observed: "파일 없음",
			Evidence: assessment.Evidence,
		}
	}
	if len(assessment.Violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "/etc/sudoers 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: strings.Join(assessment.Violations, "\n"),
			Evidence: assessment.Evidence,
		}
	}
	if len(assessment.Unknowns) > 0 {
		return evaluator.Outcome{
			Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:  "/etc/sudoers 파일의 소유자 또는 권한을 확정할 수 없습니다.",
			Expected: rule.Criteria.Pass, Observed: strings.Join(assessment.Unknowns, "\n"), Evidence: assessment.Evidence,
		}
	}
	if assessment.Metadata.Mode.Perm() != 0o640 {
		return evaluator.Outcome{
			Status: model.StatusUnknown, UnknownReason: model.UnknownAmbiguousResult,
			Summary:  "/etc/sudoers 파일 권한이 가이드의 양호 조건과 취약 조건 어느 쪽에도 해당하지 않습니다.",
			Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("uid=%d mode=%04o", assessment.Metadata.UID, assessment.Metadata.Mode.Perm()), Evidence: assessment.Evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "/etc/sudoers 파일의 소유자와 권한이 기준을 충족합니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("uid=%d mode=%04o", assessment.Metadata.UID, assessment.Metadata.Mode.Perm()),
		Evidence: assessment.Evidence,
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
