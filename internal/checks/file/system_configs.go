package filecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorStartupPermissions = "unix.file.startup_permissions"
	EvaluatorInetdPermissions   = "unix.file.inetd_permissions"
	EvaluatorSyslogPermissions  = "unix.file.syslog_permissions"
)

func evaluateStartupPermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	files, collectionUnknowns, evidence, err := collectGuideStartupFiles(ctx, environment.Files)
	if err != nil {
		return fileError("startup_file_listing_failed", "시스템 시작 스크립트 파일을 확인하지 못했습니다.", err)
	}
	violations := make([]string, 0)
	unknowns := append([]string(nil), collectionUnknowns...)
	for _, initial := range files {
		current, statErr := environment.Files.Stat(initial.Path)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				unknowns = append(unknowns, initial.Path+": 점검 중 파일이 사라짐")
				continue
			}
			return fileError("startup_file_revalidation_failed", "시스템 시작 스크립트 파일을 다시 확인하지 못했습니다.", statErr)
		}
		current.Path = initial.Path
		if !sameGuideStartupFile(initial, current) {
			unknowns = append(unknowns, initial.Path+": 점검 중 파일 대상, 소유자 또는 권한이 변경됨")
			continue
		}
		if current.UID != 0 {
			violations = append(violations, fmt.Sprintf("%s: 소유자 UID=%d", current.Path, current.UID))
		}
		if current.Mode.Perm()&0o002 != 0 {
			violations = append(violations, fmt.Sprintf("%s: 일반 사용자 쓰기 권한 mode=%04o", current.Path, current.Mode.Perm()))
		}
	}
	violations = uniqueSortedPaths(violations)
	unknowns = uniqueSortedPaths(unknowns)
	evidence = append(evidence, support.FactEvidence("시스템 시작 스크립트 점검 결과", map[string]any{
		"file_count": len(files), "violation_count": len(violations), "unknown_count": len(unknowns),
	}))
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status: model.StatusFail, Summary: "시스템 시작 스크립트 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.",
			Expected: rule.Criteria.Pass, Observed: strings.Join(violations, "\n"),
			Details: startupPermissionDetails("권한 위반", violations, "root 소유, 일반 사용자 쓰기 권한 없음"), Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status: model.StatusUnknown, UnknownReason: model.UnknownInsufficientEvidence,
			Summary:  "일부 시스템 시작 스크립트 파일의 소유자 또는 권한을 확정할 수 없습니다.",
			Expected: rule.Criteria.Pass, Observed: strings.Join(unknowns, "\n"),
			Details: startupPermissionDetails("확인하지 못한 파일", unknowns, "파일 대상, 소유자 및 권한 확인"), Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status: model.StatusPass, Summary: "시스템 시작 스크립트 파일의 소유자와 권한이 기준을 충족합니다.",
		Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("시작 스크립트 파일 %d개 확인", len(files)), Evidence: evidence,
	}
}

func collectGuideStartupFiles(ctx context.Context, files system.Reader) ([]system.FileMetadata, []string, []model.Evidence, error) {
	return collectGuideStartupFilesWithLimit(ctx, files, 16384)
}

func collectGuideStartupFilesWithLimit(ctx context.Context, files system.Reader, maxEntries int) ([]system.FileMetadata, []string, []model.Evidence, error) {
	type pendingDirectory struct {
		path  string
		depth int
		limit int
	}
	queue := make([]pendingDirectory, 0, 8)
	for _, root := range []pendingDirectory{{path: "/etc/systemd/system", limit: 4}, {path: "/etc/rc.d", limit: 2}} {
		exists, err := files.Exists(root.path)
		if err != nil {
			return nil, nil, nil, err
		}
		if exists {
			queue = append(queue, root)
		}
	}
	seenDirectories := make(map[string]struct{})
	seenFiles := make(map[string]struct{})
	result := make([]system.FileMetadata, 0)
	unknowns := make([]string, 0)
	evidence := make([]model.Evidence, 0)
	entryCount := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, nil, evidence, err
		}
		directory := queue[0]
		queue = queue[1:]
		if _, seen := seenDirectories[directory.path]; seen {
			continue
		}
		seenDirectories[directory.path] = struct{}{}
		entries, truncated, err := readGuideStartupDirectory(files, directory.path, maxEntries-entryCount)
		if err != nil {
			return nil, nil, evidence, err
		}
		entryCount += len(entries)
		if truncated {
			unknowns = append(unknowns, fmt.Sprintf("시작 스크립트 디렉터리 항목이 점검 한도 %d개를 초과함", maxEntries))
		}
		for _, entry := range entries {
			name := entry.Name()
			if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\r\n\x00") {
				unknowns = append(unknowns, directory.path+": 안전하게 확인할 수 없는 파일 이름")
				continue
			}
			candidate := path.Join(directory.path, name)
			metadata, err := files.Lstat(candidate)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					unknowns = append(unknowns, candidate+": 점검 중 파일이 사라짐")
					continue
				}
				return nil, nil, evidence, err
			}
			if metadata.FileType == "symlink" {
				metadata, err = files.Stat(candidate)
				if err != nil {
					unknowns = append(unknowns, candidate+": 심볼릭 링크 대상을 확인할 수 없음")
					continue
				}
			}
			switch metadata.FileType {
			case "directory":
				if directory.depth < directory.limit {
					queue = append(queue, pendingDirectory{path: candidate, depth: directory.depth + 1, limit: directory.limit})
				} else {
					unknowns = append(unknowns, candidate+": 하위 디렉터리가 점검 깊이 한도를 초과함")
				}
			case "regular":
				if _, seen := seenFiles[candidate]; seen {
					continue
				}
				metadata.Path = candidate
				seenFiles[candidate] = struct{}{}
				result = append(result, metadata)
				evidence = append(evidence, support.FileMetadataEvidence(metadata))
			}
		}
		if truncated {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, uniqueSortedPaths(unknowns), evidence, nil
}

func readGuideStartupDirectory(files system.Reader, directory string, limit int) ([]os.DirEntry, bool, error) {
	if bounded, ok := files.(system.BoundedDirectoryReader); ok {
		return bounded.ReadDirBounded(directory, limit)
	}
	entries, err := files.ReadDir(directory)
	if err != nil {
		return nil, false, err
	}
	if len(entries) > limit {
		return entries[:limit], true, nil
	}
	return entries, false, nil
}

func sameGuideStartupFile(before, after system.FileMetadata) bool {
	if after.FileType != "regular" || before.UID != after.UID || before.GID != after.GID || before.Mode != after.Mode {
		return false
	}
	if before.Device != 0 || before.Inode != 0 {
		return before.Device == after.Device && before.Inode == after.Inode
	}
	return true
}

func startupPermissionDetails(label string, findings []string, expected string) []model.ResultDetail {
	if len(findings) == 0 {
		return nil
	}
	return []model.ResultDetail{{Label: label, Current: strings.Join(findings, "\n"), Expected: expected, Source: "시스템 시작 스크립트"}}
}

func evaluateInetdPermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	return evaluateGuideConfigPermissions(ctx, rule, environment, []string{"/etc/inetd.conf", "/etc/xinetd.conf"}, map[int]struct{}{0: {}}, 0o600)
}

func evaluateSyslogPermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	paths := make([]string, 0, 2)
	missingEvidence := make([]model.Evidence, 0, 2)
	missingDetails := make([]model.ResultDetail, 0, 2)
	for _, candidate := range []string{"/etc/syslog.conf", "/etc/rsyslog.conf"} {
		exists, err := environment.Files.Exists(candidate)
		if err != nil {
			return fileError("syslog_config_stat_failed", "syslog 설정 파일을 확인하지 못했습니다.", err)
		}
		if exists {
			paths = append(paths, candidate)
		} else {
			missingEvidence = append(missingEvidence, support.FactEvidence(candidate, map[string]any{"exists": false}))
			missingDetails = append(missingDetails, model.ResultDetail{Label: "파일 존재 여부", Current: "없음", Source: candidate})
		}
	}
	if len(paths) == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "/etc/(r)syslog.conf 파일이 없습니다.", Expected: rule.Criteria.Pass, Observed: "점검 대상 파일 없음", Details: missingDetails, Evidence: missingEvidence}
	}
	owners, ownerEvidence, err := allowedRsyslogOwners(ctx, environment)
	if err != nil {
		return fileError("syslog_owner_lookup_failed", "syslog 허용 소유자를 확인하지 못했습니다.", err)
	}
	outcome := evaluateGuideConfigPermissions(ctx, rule, environment, paths, owners, 0o640)
	outcome.Evidence = append(append([]model.Evidence{ownerEvidence}, outcome.Evidence...), missingEvidence...)
	outcome.Details = append(outcome.Details, missingDetails...)
	return outcome
}

func evaluateGuideConfigPermissions(
	ctx context.Context,
	rule model.ResolvedRule,
	environment evaluator.Environment,
	paths []string,
	allowedUIDs map[int]struct{},
	allowedMode os.FileMode,
) evaluator.Outcome {
	evidence := make([]model.Evidence, 0)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	details := make([]model.ResultDetail, 0)
	missingDetails := make([]model.ResultDetail, 0)
	existing := 0
	for _, configPath := range paths {
		assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, configPath, support.PermissionPolicy{
			AllowedUIDs: allowedUIDs, AllowedMode: allowedMode, AllowedTypes: map[string]struct{}{"regular": {}}, SkipACL: true,
		})
		if err != nil {
			return fileError("config_permission_inspection_failed", "설정 파일의 소유자와 권한을 확인하지 못했습니다.", err)
		}
		if !assessment.Exists {
			evidence = append(evidence, support.FactEvidence(configPath, map[string]any{"exists": false}))
			missingDetails = append(missingDetails, model.ResultDetail{Label: "파일 존재 여부", Current: "없음", Source: configPath})
			continue
		}
		existing++
		evidence = append(evidence, assessment.Evidence...)
		details = append(details, permissionMetadataDetail(configPath, assessment.Metadata, rule.Criteria.Pass))
		if assessment.ExtraModeBits != 0 {
			details = append(details, model.ResultDetail{Label: "권한 판정 설명", Current: permissionExcessExplanation(assessment.ExtraModeBits), Source: configPath})
		}
		for _, finding := range assessment.Violations {
			violations = append(violations, configPath+": "+finding)
		}
		for _, finding := range assessment.Unknowns {
			unknowns = append(unknowns, configPath+": "+finding)
		}
	}
	details = append(details, missingDetails...)
	if existing == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "점검 대상 설정 파일이 없습니다.", Expected: rule.Criteria.Pass, Observed: "파일 없음", Details: details, Evidence: evidence}
	}
	if len(violations) > 0 {
		observed := strings.Join(uniqueSortedPaths(violations), "\n")
		details = append(details, model.ResultDetail{Label: "판정 결과", Current: observed})
		return evaluator.Outcome{Status: model.StatusFail, Summary: "설정 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.", Expected: rule.Criteria.Pass, Observed: observed, Details: details, Evidence: evidence}
	}
	if len(unknowns) > 0 {
		observed := strings.Join(uniqueSortedPaths(unknowns), "\n")
		details = append(details, model.ResultDetail{Label: "확인하지 못한 내용", Current: observed})
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "설정 파일의 소유자 또는 권한을 확정할 수 없습니다.", Expected: rule.Criteria.Pass, Observed: observed, Details: details, Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "설정 파일의 소유자와 권한이 기준을 충족합니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("파일 %d개 확인", existing), Details: details, Evidence: evidence}
}

func allowedRsyslogOwners(ctx context.Context, environment evaluator.Environment) (map[int]struct{}, model.Evidence, error) {
	accounts, evidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return nil, model.Evidence{}, err
	}
	allowed := map[int]struct{}{0: {}}
	for _, account := range accounts {
		if account.Name == "root" || account.Name == "bin" || account.Name == "sys" {
			allowed[int(account.UID)] = struct{}{}
		}
	}
	return allowed, evidence, nil
}
