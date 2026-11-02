package logging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorLogFilePermissions = "unix.log.file_permissions"
	maxLogFiles                 = 4096
)

func evaluateLogFilePermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	files, collectionUnknowns, evidence, err := collectGuideLogFiles(ctx, environment.Files)
	if err != nil {
		return logFilePermissionError("log_inventory_failed", err)
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
			return logFilePermissionError("log_file_revalidation_failed", statErr)
		}
		if !sameGuideLogFile(initial, current) {
			unknowns = append(unknowns, initial.Path+": 점검 중 파일 대상, 소유자 또는 권한이 변경됨")
			continue
		}
		violations = append(violations, assessGuideLogFile(current)...)
	}

	sort.Strings(violations)
	sort.Strings(unknowns)
	evidence = append(evidence, support.FactEvidence("로그 파일 권한 점검 결과", map[string]any{
		"file_count":        len(files),
		"violation_count":   len(violations),
		"unconfirmed_count": len(unknowns),
	}))

	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "로그 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.",
			Expected: rule.Criteria.Pass,
			Observed: strings.Join(violations, "\n"),
			Details: []model.ResultDetail{{
				Label: "로그 파일 권한", Current: strings.Join(violations, "\n"),
				Expected: "root 소유, 권한 0644 이하", Source: "/var/log",
			}},
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "일부 로그 파일의 소유자 또는 권한을 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      strings.Join(unknowns, "\n"),
			Details: []model.ResultDetail{{
				Label: "확인하지 못한 로그 파일", Current: strings.Join(unknowns, "\n"),
				Expected: "파일 대상, 소유자 및 권한 확인", Source: "/var/log",
			}},
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "/var/log 디렉터리 내 로그 파일의 소유자와 권한이 기준을 충족합니다.",
		Expected: rule.Criteria.Pass,
		Observed: fmt.Sprintf("로그 파일 %d개 확인", len(files)),
		Evidence: evidence,
	}
}

func collectGuideLogFiles(ctx context.Context, files system.Reader) ([]system.FileMetadata, []string, []model.Evidence, error) {
	entries, truncated, err := readLogDirectoryEntries(files, "/var/log", maxLogFiles)
	if err != nil {
		return nil, nil, nil, err
	}
	result := make([]system.FileMetadata, 0, len(entries))
	unknowns := make([]string, 0)
	evidence := make([]model.Evidence, 0, len(entries))
	if truncated {
		unknowns = append(unknowns, fmt.Sprintf("/var/log 항목이 점검 한도 %d개를 초과함", maxLogFiles))
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, nil, evidence, err
		}
		if !safeLogEntryName(entry.Name()) {
			unknowns = append(unknowns, "/var/log에 안전하게 표시할 수 없는 파일 이름이 있음")
			continue
		}
		filePath := path.Join("/var/log", entry.Name())
		metadata, statErr := files.Lstat(filePath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				unknowns = append(unknowns, filePath+": 디렉터리 조회 후 파일이 사라짐")
				continue
			}
			return nil, nil, evidence, statErr
		}
		if metadata.FileType == "symlink" {
			metadata, statErr = files.Stat(filePath)
			if statErr != nil {
				unknowns = append(unknowns, filePath+": 심볼릭 링크 대상을 확인하지 못함")
				continue
			}
		}
		if metadata.FileType != "regular" {
			continue
		}
		metadata.Path = filePath
		result = append(result, metadata)
		evidence = append(evidence, support.FileMetadataEvidence(metadata))
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	sort.Strings(unknowns)
	return result, unknowns, evidence, nil
}

func readLogDirectoryEntries(files system.Reader, directory string, limit int) ([]os.DirEntry, bool, error) {
	if bounded, ok := files.(system.BoundedDirectoryReader); ok {
		return bounded.ReadDirBounded(directory, limit)
	}
	entries, err := files.ReadDir(directory)
	if err != nil {
		return nil, false, err
	}
	if len(entries) <= limit {
		return entries, false, nil
	}
	return entries[:limit], true, nil
}

func safeLogEntryName(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) {
		return false
	}
	for _, character := range name {
		if character == '/' || character == '\\' || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func sameGuideLogFile(before, after system.FileMetadata) bool {
	if after.FileType != "regular" || before.UID != after.UID || before.GID != after.GID || before.Mode != after.Mode {
		return false
	}
	if before.Device != 0 || before.Inode != 0 {
		return before.Device == after.Device && before.Inode == after.Inode
	}
	return true
}

func assessGuideLogFile(metadata system.FileMetadata) []string {
	violations := make([]string, 0, 2)
	if metadata.UID != 0 {
		violations = append(violations, fmt.Sprintf("%s: 소유자 UID=%d", metadata.Path, metadata.UID))
	}
	if metadata.Mode.Perm()&^os.FileMode(0o644) != 0 || metadata.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		violations = append(violations, fmt.Sprintf("%s: 권한 %04o", metadata.Path, metadata.Mode.Perm()))
	}
	return violations
}

func logFilePermissionError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "로그 파일의 소유자 또는 권한을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
