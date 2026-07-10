package filecheck

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorOrphanedOwner = "unix.file.orphaned_owner"

func filesystemImplementations() map[string]evaluator.Func {
	return map[string]evaluator.Func{
		EvaluatorOrphanedOwner:              evaluateOrphanedOwner,
		EvaluatorSpecialBits:                evaluateSpecialBits,
		EvaluatorUserEnvironmentPermissions: evaluateUserEnvironmentPermissions,
		EvaluatorWorldWritable:              evaluateWorldWritable,
		EvaluatorInvalidDeviceNodes:         evaluateInvalidDeviceNodes,
		EvaluatorRHostsTrust:                evaluateRHostsTrust,
		EvaluatorHomePermissions:            evaluateHomePermissions,
		EvaluatorHomeExists:                 evaluateHomeExists,
		EvaluatorSuspiciousHidden:           evaluateSuspiciousHidden,
		EvaluatorRootPath:                   evaluateRootPath,
		EvaluatorUmask:                      evaluateUmask,
	}
}

type findmntOutput struct {
	Filesystems []findmntEntry `json:"filesystems"`
}

type findmntEntry struct {
	Target   string         `json:"target"`
	FSType   string         `json:"fstype"`
	Options  string         `json:"options"`
	Children []findmntEntry `json:"children"`
}

func evaluateOrphanedOwner(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	mountSpec := executor.Spec{
		Name:      "findmnt",
		Arguments: []string{"--json", "--list", "--real", "--output", "TARGET,FSTYPE,OPTIONS"},
		Timeout:   20 * time.Second,
		MaxOutput: 4 << 20,
	}
	mountResult, err := environment.Commands.Run(ctx, mountSpec)
	if err != nil {
		return fileError("findmnt_failed", "로컬 파일 시스템을 확인하지 못했습니다.", err)
	}
	if mountResult.ExitCode != 0 || mountResult.Truncated {
		return fileError("findmnt_failed", "로컬 파일 시스템을 확인하지 못했습니다.", fmt.Errorf("exit=%d truncated=%t", mountResult.ExitCode, mountResult.Truncated))
	}
	var output findmntOutput
	if err := json.Unmarshal(mountResult.Stdout, &output); err != nil {
		return fileError("findmnt_parse_failed", "로컬 파일 시스템 정보를 해석하지 못했습니다.", err)
	}
	mounts := persistentMounts(output.Filesystems)
	evidence := []model.Evidence{support.CommandEvidence(mountSpec, mountResult)}
	if len(mounts) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "검색 가능한 로컬 영속 파일 시스템이 없습니다.",
			Expected: "검색 가능한 모든 로컬 영속 파일 시스템에서 소유자 없는 항목이 없어야 합니다.",
			Observed: "대상 마운트 없음",
			Evidence: evidence,
		}
	}
	candidates := make(map[string]struct{})
	outputTruncated := false
	for _, mount := range mounts {
		if !filepath.IsAbs(mount) || strings.IndexByte(mount, 0) >= 0 {
			return fileError("invalid_mount_path", "파일 시스템 마운트 경로가 안전하지 않습니다.", fmt.Errorf("invalid mount target %q", mount))
		}
		findSpec := executor.Spec{
			Name: "find",
			Arguments: []string{
				mount,
				"-xdev",
				"(",
				"-nouser",
				"-o",
				"-nogroup",
				")",
				"-print0",
			},
			Timeout:   5 * time.Minute,
			MaxOutput: 8 << 20,
		}
		findResult, runErr := environment.Commands.Run(ctx, findSpec)
		if runErr != nil {
			return fileError("orphan_search_failed", "소유자 없는 파일 검색을 완료하지 못했습니다.", runErr)
		}
		if findResult.ExitCode != 0 {
			return fileError("orphan_search_failed", "소유자 없는 파일 검색을 완료하지 못했습니다.", fmt.Errorf("find on %s exited with %d", mount, findResult.ExitCode))
		}
		outputTruncated = outputTruncated || findResult.Truncated
		evidence = append(evidence, support.CommandEvidence(findSpec, findResult))
		for _, path := range strings.Split(string(findResult.Stdout), "\x00") {
			if path != "" {
				candidates[path] = struct{}{}
			}
		}
	}
	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	summaryFacts := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		if utf8.ValidString(path) {
			summaryFacts = append(summaryFacts, map[string]any{"path": path, "encoding": "utf-8"})
		} else {
			summaryFacts = append(summaryFacts, map[string]any{"path": base64.StdEncoding.EncodeToString([]byte(path)), "encoding": "base64"})
		}
	}
	evidence = append(evidence, support.FactEvidence("orphaned-owner-summary", map[string]any{
		"mounts":           mounts,
		"candidate_count":  len(paths),
		"output_truncated": outputTruncated,
		"candidates":       summaryFacts,
	}))
	if len(paths) > 0 {
		observed := fmt.Sprintf("소유자 또는 그룹이 없는 항목 %d개", len(paths))
		if outputTruncated {
			observed += " 이상(증적 출력 제한 도달)"
		}
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "소유자 또는 그룹이 존재하지 않는 파일이나 디렉터리가 발견되었습니다.",
			Expected: "모든 로컬 영속 파일과 디렉터리의 소유자 및 그룹이 존재해야 합니다.",
			Observed: observed,
			Evidence: evidence,
		}
	}
	if outputTruncated {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "검색 결과가 출력 제한을 초과하여 소유자 없는 항목의 부재를 확정할 수 없습니다.",
			Expected:      "모든 로컬 영속 파일 시스템 검색이 완전해야 합니다.",
			Observed:      "find 출력 제한 도달",
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "검색한 로컬 영속 파일 시스템에 소유자 없는 항목이 없습니다.",
		Expected: "모든 로컬 영속 파일과 디렉터리의 소유자 및 그룹이 존재해야 합니다.",
		Observed: fmt.Sprintf("%d개 마운트 검색 완료", len(mounts)),
		Evidence: evidence,
	}
}

func persistentMounts(entries []findmntEntry) []string {
	seen := make(map[string]struct{})
	var visit func([]findmntEntry)
	visit = func(items []findmntEntry) {
		for _, item := range items {
			if isPersistentLocalFilesystem(item.FSType) && item.Target != "" {
				seen[item.Target] = struct{}{}
			}
			visit(item.Children)
		}
	}
	visit(entries)
	result := make([]string, 0, len(seen))
	for target := range seen {
		result = append(result, target)
	}
	sort.Strings(result)
	return result
}

func isPersistentLocalFilesystem(filesystemType string) bool {
	filesystemType = strings.ToLower(strings.TrimSpace(filesystemType))
	if filesystemType == "" {
		return false
	}
	for _, excluded := range []string{
		"autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs", "efivarfs",
		"fusectl", "hugetlbfs", "mqueue", "nsfs", "overlay", "proc", "pstore", "ramfs", "rpc_pipefs",
		"securityfs", "squashfs", "sysfs", "tmpfs", "tracefs", "nfs", "nfs4", "cifs", "ceph", "glusterfs",
	} {
		if filesystemType == excluded || strings.HasPrefix(filesystemType, "fuse.") {
			return false
		}
	}
	return true
}

func fileError(code, summary string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      summary,
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
