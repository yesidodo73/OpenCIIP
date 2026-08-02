package logging

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorLogFilePermissions = "unix.log.file_permissions"
	maxLogFiles                 = 4096
	maxLogDirectories           = 4096
	maxLogEntries               = 16384
	maxLogInventoryBoundaries   = 512
	aclBatchSize                = 48
)

type logInventory struct {
	files                   []system.FileMetadata
	evidence                []model.Evidence
	boundaries              []logInventoryBoundary
	incomplete              bool
	symlinkFiles            int
	symlinkRegularFiles     int
	crossDeviceRegularFiles int
	crossDeviceMounts       int
	directoriesScanned      int
	directoryAliases        int
	entriesScanned          int
	boundaryCount           int
	unsupportedBoundary     bool
	directoryGuards         []logDirectoryGuard
}

type logInventoryBoundary struct {
	Path   string
	Kind   string
	Reason string
}

type logDirectoryIdentity struct {
	device uint64
	inode  uint64
}

type logDirectorySnapshot struct {
	path     string
	metadata system.FileMetadata
}

type logDirectoryGuard struct {
	path        string
	metadata    system.FileMetadata
	entryCount  int
	entryDigest [sha256.Size]byte
}

type aclAssessment struct {
	clearReasons     []string
	ambiguousReasons []string
	snapshot         *system.FileMetadata
}

func evaluateLogFilePermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	expected := strings.TrimSpace(rule.Criteria.Pass)
	if expected == "" {
		expected = "로그 파일은 root 소유이고 권한과 ACL이 0644 허용 비트 이내여야 합니다."
	}

	inventory, err := inventoryLogFiles(ctx, environment.Files)
	if err != nil {
		return logFilePermissionError("log_inventory_failed", err)
	}
	evidence := append([]model.Evidence(nil), inventory.evidence...)
	if len(inventory.files) == 0 {
		_, finalEvidence, err := revalidateLogInventory(ctx, environment.Files, &inventory)
		if err != nil {
			return logFilePermissionError("log_inventory_revalidation_failed", err)
		}
		evidence = append(evidence, finalEvidence...)
		evidence = append(evidence, logInventoryEvidence(inventory))
		if inventory.incomplete {
			reason := model.UnknownAmbiguousResult
			if logInventoryHasUnsupportedBoundary(inventory) {
				reason = model.UnknownUnsupportedConfiguration
			}
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: reason,
				Summary:       "로그 파일 목록을 완전히 수집하지 못했습니다.",
				Expected:      expected,
				Observed:      summarizeLogInventoryBoundaries(inventory.boundaries, inventory.boundaryCount, 12),
				Evidence:      evidence,
			}
		}
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "적용 가능한 일반 로그 파일이 없습니다.",
			Expected: expected,
			Observed: "/var/log에서 일반 로그 파일을 찾지 못했습니다.",
			Evidence: evidence,
		}
	}

	paths := make([]string, len(inventory.files))
	for index, metadata := range inventory.files {
		paths[index] = metadata.Path
	}
	aclResults, aclEvidence, aclComplete, err := inspectLogACLs(ctx, environment, paths)
	if err != nil {
		return logFilePermissionError("log_acl_inspection_failed", err)
	}
	evidence = append(evidence, aclEvidence...)
	finalFileStability, finalEvidence, err := revalidateLogInventory(ctx, environment.Files, &inventory)
	if err != nil {
		return logFilePermissionError("log_inventory_revalidation_failed", err)
	}
	evidence = append(evidence, finalEvidence...)
	evidence = append(evidence, logInventoryEvidence(inventory))

	clearViolations := make([]string, 0)
	ambiguous := make([]string, 0)
	for _, metadata := range inventory.files {
		if !finalFileStability[metadata.Path] {
			continue
		}
		assessment, exists := aclResults[metadata.Path]
		if !exists {
			assessment = aclAssessment{
				ambiguousReasons: []string{"ACL 결과를 확인할 수 없음"},
			}
		}
		if assessment.snapshot != nil && !sameLogPermissionTarget(metadata, *assessment.snapshot) {
			assessment.clearReasons = nil
			assessment.ambiguousReasons = append(
				assessment.ambiguousReasons,
				"파일 목록 수집과 ACL 수집 사이에 경로 대상이 변경됨",
			)
		}
		clear, uncertain := assessLogFile(metadata, assessment)
		clearViolations = append(clearViolations, clear...)
		ambiguous = append(ambiguous, uncertain...)
	}
	for _, boundary := range inventory.boundaries {
		ambiguous = append(ambiguous, boundary.Path+": "+boundary.Reason)
	}
	if omitted := inventory.boundaryCount - len(inventory.boundaries); omitted > 0 {
		ambiguous = append(
			ambiguous,
			fmt.Sprintf("/var/log: 저장 한도를 초과한 추가 로그 경계 %d건", omitted),
		)
	}
	sort.Strings(clearViolations)
	sort.Strings(ambiguous)
	evidence = append(evidence, support.FactEvidence("log-file-permission-findings", map[string]any{
		"clear_violation_count": len(clearViolations),
		"ambiguous_count":       len(ambiguous),
		"clear_violations":      limitedStrings(clearViolations, 100),
		"ambiguous_findings":    limitedStrings(ambiguous, 100),
	}))

	if len(clearViolations) > 0 {
		details := []model.ResultDetail{{
			Label: "로그 파일 권한", Current: summarizeStrings(clearViolations, 12),
			Expected: "root 소유, 권한·ACL 0644 이내", Source: "/var/log",
		}}
		if len(ambiguous) > 0 {
			details = append(details, model.ResultDetail{
				Label:    "추가 확인 필요",
				Current:  summarizeStrings(ambiguous, 12),
				Expected: "모든 로그 경계와 ACL을 같은 파일 스냅샷에서 확인",
				Source:   "/var/log",
			})
		}
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "로그 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: summarizeStrings(clearViolations, 12),
			Details:  details,
			Evidence: evidence,
		}
	}
	if inventory.incomplete || !aclComplete || len(ambiguous) > 0 {
		reason := model.UnknownAmbiguousResult
		summary := "일부 로그 파일의 소유자·ACL 또는 수집 시점의 경로 대상을 확정할 수 없습니다."
		if !aclComplete {
			reason = model.UnknownUnsupportedConfiguration
			summary = "일부 로그 파일의 POSIX ACL을 같은 파일 스냅샷에서 확인할 수 없습니다."
		} else if inventory.incomplete && logInventoryHasUnsupportedBoundary(inventory) {
			reason = model.UnknownUnsupportedConfiguration
			summary = "일부 로그 경계의 파일 목록을 완전히 확인하지 못했습니다."
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       summary,
			Expected:      expected,
			Observed:      summarizeStrings(ambiguous, 12),
			Details: []model.ResultDetail{{
				Label: "예외 확인이 필요한 로그", Current: summarizeStrings(ambiguous, 12),
				Expected: "소유자·ACL 및 경로 대상 재확인", Source: "/var/log",
			}},
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 확인된 로그 파일의 소유자, 권한 및 ACL이 기준을 충족합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("일반 로그 파일 %d개 확인", len(inventory.files)),
		Evidence: evidence,
	}
}

func sameLogPermissionTarget(before, after system.FileMetadata) bool {
	if before.FileType != after.FileType || before.Mode != after.Mode ||
		before.UID != after.UID || before.GID != after.GID {
		return false
	}
	if before.Device != 0 || before.Inode != 0 {
		return after.Device != 0 && after.Inode != 0 &&
			before.Device == after.Device && before.Inode == after.Inode
	}
	return true
}

func revalidateLogInventory(
	ctx context.Context,
	files system.Reader,
	inventory *logInventory,
) (map[string]bool, []model.Evidence, error) {
	if inventory == nil {
		return nil, nil, fmt.Errorf("log inventory is required")
	}
	initialBoundaryCount := inventory.boundaryCount
	stableFiles := 0
	stableDirectories := 0
	fileDigest := sha256.New()
	directoryDigest := sha256.New()
	fileStability := make(map[string]bool, len(inventory.files))
	evidence := make([]model.Evidence, 0)

	for _, metadata := range inventory.files {
		fileStability[metadata.Path] = false
		if err := ctx.Err(); err != nil {
			return fileStability, evidence, err
		}
		current, err := files.Stat(metadata.Path)
		if err != nil {
			if isLogSnapshotBoundaryError(err) {
				addLogInventoryBoundary(
					inventory,
					metadata.Path,
					"file_changed_after_acl",
					"ACL 수집 후 로그 파일이 사라지거나 경로 대상을 확인할 수 없음",
				)
				continue
			}
			return fileStability, evidence, err
		}
		if !sameLogPermissionTarget(metadata, current) {
			evidence = append(evidence, support.FileMetadataEvidence(current))
			addLogInventoryBoundary(
				inventory,
				metadata.Path,
				"file_changed_after_acl",
				"ACL 수집 후 로그 파일의 경로 대상·소유자 또는 권한이 변경됨",
			)
			continue
		}
		fileStability[metadata.Path] = true
		stableFiles++
		_, _ = fmt.Fprintf(
			fileDigest,
			"%s\x00%d\x00%d\x00%d\x00%d\x00%o\x00",
			metadata.Path,
			metadata.Device,
			metadata.Inode,
			metadata.UID,
			metadata.GID,
			metadata.Mode,
		)
	}

	for _, guard := range inventory.directoryGuards {
		if err := ctx.Err(); err != nil {
			return fileStability, evidence, err
		}
		before, err := files.Stat(guard.path)
		if err != nil {
			if isLogSnapshotBoundaryError(err) {
				addLogInventoryBoundary(
					inventory,
					guard.path,
					"directory_changed_after_acl",
					"ACL 수집 후 로그 디렉터리가 사라지거나 경로 대상을 확인할 수 없음",
				)
				continue
			}
			return fileStability, evidence, err
		}
		if !sameLogDirectoryTarget(guard.metadata, before) {
			evidence = append(evidence, support.FileMetadataEvidence(before))
			addLogInventoryBoundary(
				inventory,
				guard.path,
				"directory_changed_after_acl",
				"ACL 수집 후 로그 디렉터리의 경로 대상 또는 항목 상태가 변경됨",
			)
			continue
		}
		entries, truncated, err := readLogDirectoryEntries(files, guard.path, guard.entryCount)
		if err != nil {
			if isLogSnapshotBoundaryError(err) {
				addLogInventoryBoundary(
					inventory,
					guard.path,
					"directory_changed_after_acl",
					"ACL 수집 후 로그 디렉터리 항목을 다시 확인할 수 없음",
				)
				continue
			}
			return fileStability, evidence, err
		}
		after, err := files.Stat(guard.path)
		if err != nil {
			if isLogSnapshotBoundaryError(err) {
				addLogInventoryBoundary(
					inventory,
					guard.path,
					"directory_changed_after_acl",
					"최종 항목 재검증 중 로그 디렉터리가 사라짐",
				)
				continue
			}
			return fileStability, evidence, err
		}
		if truncated ||
			logDirectoryEntryDigest(entries) != guard.entryDigest ||
			!sameLogDirectoryTarget(guard.metadata, after) {
			evidence = append(evidence, support.FileMetadataEvidence(after))
			addLogInventoryBoundary(
				inventory,
				guard.path,
				"directory_entries_changed_after_acl",
				"ACL 수집 후 로그 디렉터리의 항목 집합 또는 경로 대상이 변경됨",
			)
			continue
		}
		stableDirectories++
		_, _ = fmt.Fprintf(
			directoryDigest,
			"%s\x00%d\x00%d\x00%d\x00%x\x00",
			guard.path,
			guard.metadata.Device,
			guard.metadata.Inode,
			guard.entryCount,
			guard.entryDigest,
		)
	}

	evidence = append(evidence, support.FactEvidence("log-inventory-final-guard", map[string]any{
		"files_revalidated":       len(inventory.files),
		"files_stable":            stableFiles,
		"directories_revalidated": len(inventory.directoryGuards),
		"directories_stable":      stableDirectories,
		"new_boundary_count":      inventory.boundaryCount - initialBoundaryCount,
		"stable_files_sha256":     fmt.Sprintf("%x", fileDigest.Sum(nil)),
		"stable_directories_sha256": fmt.Sprintf(
			"%x",
			directoryDigest.Sum(nil),
		),
	}))
	return fileStability, evidence, nil
}

func isLogSnapshotBoundaryError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, system.ErrFileChanged)
}

func logInventoryEvidence(inventory logInventory) model.Evidence {
	return support.FactEvidence("/var/log", map[string]any{
		"regular_files":              len(inventory.files),
		"inventory_complete":         !inventory.incomplete,
		"boundary_count":             inventory.boundaryCount,
		"reported_boundary_count":    len(inventory.boundaries),
		"boundaries_truncated":       inventory.boundaryCount > len(inventory.boundaries),
		"boundaries":                 limitedLogInventoryBoundaries(inventory.boundaries, 100),
		"symlink_files":              inventory.symlinkFiles,
		"symlink_regular_files":      inventory.symlinkRegularFiles,
		"cross_device_regular_files": inventory.crossDeviceRegularFiles,
		"cross_device_mounts":        inventory.crossDeviceMounts,
		"directories_scanned":        inventory.directoriesScanned,
		"directory_aliases":          inventory.directoryAliases,
		"entries_scanned":            inventory.entriesScanned,
		"entry_limit":                maxLogEntries,
	})
}

func logInventoryHasUnsupportedBoundary(inventory logInventory) bool {
	return inventory.unsupportedBoundary
}

func inventoryLogFiles(ctx context.Context, files system.Reader) (logInventory, error) {
	root, err := files.Stat("/var/log")
	if err != nil {
		return logInventory{}, err
	}
	if root.FileType != "directory" {
		return logInventory{}, fmt.Errorf("/var/log is not a directory")
	}
	result := logInventory{}
	rootIdentity, rootIdentified := logDirectoryIdentityOf(root)
	if !rootIdentified {
		addLogInventoryBoundary(
			&result,
			"/var/log",
			"directory_identity_unavailable",
			"로그 루트 디렉터리의 장치·inode 식별값을 확인할 수 없음",
		)
		return result, nil
	}
	directories := []logDirectorySnapshot{{path: "/var/log", metadata: root}}
	seenDirectories := map[logDirectoryIdentity]struct{}{rootIdentity: {}}
	seenFiles := make(map[string]struct{})
	for len(directories) > 0 {
		if err := ctx.Err(); err != nil {
			return logInventory{}, err
		}
		directory := directories[0]
		directories = directories[1:]
		before, err := files.Stat(directory.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				addLogInventoryBoundary(
					&result,
					directory.path,
					"directory_changed",
					"목록 수집 전에 로그 디렉터리가 사라짐",
				)
				continue
			}
			return logInventory{}, err
		}
		if !sameLogDirectoryTarget(directory.metadata, before) {
			addLogInventoryBoundary(
				&result,
				directory.path,
				"directory_changed",
				"목록 수집 전에 로그 디렉터리의 경로 대상이 변경됨",
			)
			continue
		}
		remainingEntries := maxLogEntries - result.entriesScanned
		if remainingEntries < 0 {
			remainingEntries = 0
		}
		entries, entriesTruncated, err := readLogDirectoryEntries(files, directory.path, remainingEntries)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				addLogInventoryBoundary(
					&result,
					directory.path,
					"directory_changed",
					"목록 수집 전에 로그 디렉터리가 사라짐",
				)
				continue
			}
			return logInventory{}, err
		}
		result.entriesScanned += len(entries)
		if entriesTruncated {
			addLogInventoryBoundary(
				&result,
				directory.path,
				"entry_limit",
				fmt.Sprintf("로그 항목 수가 점검 한도 %d개를 초과함", maxLogEntries),
			)
		}
		entryDigest := logDirectoryEntryDigest(entries)
		result.directoriesScanned++
		for _, entry := range entries {
			name := entry.Name()
			if !safeLogEntryName(name) {
				addLogInventoryBoundary(
					&result,
					unsafeLogEntryPath(directory.path, name),
					"unsupported_name",
					"파일 이름을 안전하게 표시하거나 점검할 수 없어 확인하지 못함",
				)
				continue
			}
			filePath := path.Join(directory.path, name)
			metadata, err := files.Lstat(filePath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					addLogInventoryBoundary(
						&result,
						filePath,
						"path_changed",
						"목록 수집 중 로그 항목이 사라짐",
					)
					continue
				}
				return logInventory{}, err
			}
			switch metadata.FileType {
			case "directory":
				verified, statErr := files.Stat(filePath)
				if statErr != nil {
					if errors.Is(statErr, os.ErrNotExist) {
						addLogInventoryBoundary(&result, filePath, "path_changed", "목록 수집 중 로그 디렉터리가 사라짐")
						continue
					}
					return logInventory{}, statErr
				}
				if !sameLogDirectoryTarget(metadata, verified) {
					addLogInventoryBoundary(&result, filePath, "path_changed", "목록 수집 중 로그 디렉터리의 경로 대상이 변경됨")
					continue
				}
				identity, identified := logDirectoryIdentityOf(verified)
				if !identified {
					addLogInventoryBoundary(
						&result,
						filePath,
						"directory_identity_unavailable",
						"로그 디렉터리의 장치·inode 식별값을 확인할 수 없음",
					)
					continue
				}
				if root.Device != 0 && metadata.Device != 0 && metadata.Device != root.Device {
					result.crossDeviceMounts++
				}
				if _, seen := seenDirectories[identity]; seen {
					result.directoryAliases++
					continue
				}
				if len(seenDirectories) >= maxLogDirectories {
					addLogInventoryBoundary(
						&result,
						filePath,
						"directory_limit",
						fmt.Sprintf("로그 디렉터리 수가 점검 한도 %d개에 도달함", maxLogDirectories),
					)
					sort.Slice(result.files, func(i, j int) bool { return result.files[i].Path < result.files[j].Path })
					return result, nil
				}
				seenDirectories[identity] = struct{}{}
				directories = append(directories, logDirectorySnapshot{path: filePath, metadata: verified})
			case "regular":
				verified, statErr := files.Stat(filePath)
				if statErr != nil {
					if errors.Is(statErr, os.ErrNotExist) {
						addLogInventoryBoundary(&result, filePath, "path_changed", "목록 수집 중 일반 로그 파일이 사라짐")
						continue
					}
					return logInventory{}, statErr
				}
				if verified.FileType != "regular" || metadata.Device != verified.Device || metadata.Inode != verified.Inode {
					addLogInventoryBoundary(&result, filePath, "path_changed", "목록 수집 중 일반 로그 파일의 경로 대상이 변경됨")
					continue
				}
				if verified.Device == 0 || verified.Inode == 0 {
					addLogInventoryBoundary(
						&result,
						filePath,
						"file_identity_unavailable",
						"일반 로그 파일의 장치·inode 식별값을 확인할 수 없음",
					)
					continue
				}
				if addLogFile(&result, seenFiles, verified) == logFileLimitExceeded {
					addLogInventoryBoundary(&result, "/var/log", "file_limit", fmt.Sprintf("로그 파일 수가 점검 한도 %d개를 초과함", maxLogFiles))
					sort.Slice(result.files, func(i, j int) bool { return result.files[i].Path < result.files[j].Path })
					return result, nil
				}
			case "symlink":
				result.symlinkFiles++
				result.evidence = append(result.evidence, support.FileMetadataEvidence(metadata))
				verified, statErr := files.Stat(filePath)
				if statErr != nil {
					if errors.Is(statErr, os.ErrNotExist) {
						addLogInventoryBoundary(&result, filePath, "broken_symlink", "심볼릭 링크 대상이 존재하지 않음")
						continue
					}
					if errors.Is(statErr, syscall.ELOOP) {
						addLogInventoryBoundary(&result, filePath, "symlink_cycle", "심볼릭 링크 순환으로 대상을 확인할 수 없음")
						continue
					}
					return logInventory{}, statErr
				}
				switch verified.FileType {
				case "regular":
					if verified.Device == 0 || verified.Inode == 0 {
						addLogInventoryBoundary(
							&result,
							filePath,
							"file_identity_unavailable",
							"심볼릭 링크 대상 로그 파일의 장치·inode 식별값을 확인할 수 없음",
						)
						continue
					}
					result.symlinkRegularFiles++
					if root.Device != 0 && verified.Device != 0 && verified.Device != root.Device {
						result.crossDeviceRegularFiles++
					}
					if addLogFile(&result, seenFiles, verified) == logFileLimitExceeded {
						addLogInventoryBoundary(&result, "/var/log", "file_limit", fmt.Sprintf("로그 파일 수가 점검 한도 %d개를 초과함", maxLogFiles))
						sort.Slice(result.files, func(i, j int) bool { return result.files[i].Path < result.files[j].Path })
						return result, nil
					}
				case "directory":
					addLogInventoryBoundary(&result, filePath, "symlink_directory", "심볼릭 링크가 가리키는 디렉터리를 순회하지 않음")
				default:
					addLogInventoryBoundary(
						&result,
						filePath,
						"unsupported_symlink_target",
						"심볼릭 링크 대상 유형을 로그 파일로 확인할 수 없음("+verified.FileType+")",
					)
				}
			}
		}
		if entriesTruncated {
			sort.Slice(result.files, func(i, j int) bool { return result.files[i].Path < result.files[j].Path })
			return result, nil
		}
		finalEntries, finalEntriesTruncated, err := readLogDirectoryEntries(files, directory.path, len(entries))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				addLogInventoryBoundary(
					&result,
					directory.path,
					"directory_changed",
					"목록 재검증 전에 로그 디렉터리가 사라짐",
				)
				continue
			}
			return logInventory{}, err
		}
		entrySetStable := !finalEntriesTruncated && logDirectoryEntryDigest(finalEntries) == entryDigest
		if !entrySetStable {
			addLogInventoryBoundary(
				&result,
				directory.path,
				"directory_entries_changed",
				"목록 수집 중 로그 디렉터리 항목이 변경됨",
			)
		}
		after, err := files.Stat(directory.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				addLogInventoryBoundary(
					&result,
					directory.path,
					"directory_changed",
					"목록 수집 후 로그 디렉터리가 사라짐",
				)
				continue
			}
			return logInventory{}, err
		}
		directoryStable := sameLogDirectoryTarget(directory.metadata, after)
		if !directoryStable {
			addLogInventoryBoundary(
				&result,
				directory.path,
				"directory_changed",
				"목록 수집 중 로그 디렉터리의 경로 대상이 변경됨",
			)
		}
		if entrySetStable && directoryStable {
			result.directoryGuards = append(result.directoryGuards, logDirectoryGuard{
				path:        directory.path,
				metadata:    after,
				entryCount:  len(entries),
				entryDigest: entryDigest,
			})
		}
	}
	sort.Slice(result.files, func(i, j int) bool { return result.files[i].Path < result.files[j].Path })
	return result, nil
}

func logDirectoryIdentityOf(metadata system.FileMetadata) (logDirectoryIdentity, bool) {
	if metadata.FileType != "directory" || metadata.Device == 0 || metadata.Inode == 0 {
		return logDirectoryIdentity{}, false
	}
	return logDirectoryIdentity{device: metadata.Device, inode: metadata.Inode}, true
}

func sameLogDirectoryTarget(before, after system.FileMetadata) bool {
	return before.FileType == "directory" &&
		after.FileType == "directory" &&
		before.Device == after.Device &&
		before.Inode == after.Inode &&
		before.Size == after.Size &&
		before.ModTime.Equal(after.ModTime)
}

func logDirectoryEntryDigest(entries []os.DirEntry) [sha256.Size]byte {
	type entryRecord struct {
		name     string
		typeBits os.FileMode
	}
	records := make([]entryRecord, 0, len(entries))
	for _, entry := range entries {
		records = append(records, entryRecord{name: entry.Name(), typeBits: entry.Type()})
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].name != records[right].name {
			return records[left].name < records[right].name
		}
		return records[left].typeBits < records[right].typeBits
	})
	digest := sha256.New()
	var encoded [8]byte
	for _, record := range records {
		binary.BigEndian.PutUint64(encoded[:], uint64(len(record.name)))
		_, _ = digest.Write(encoded[:])
		_, _ = digest.Write([]byte(record.name))
		binary.BigEndian.PutUint64(encoded[:], uint64(record.typeBits))
		_, _ = digest.Write(encoded[:])
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
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
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) ||
		strings.ContainsAny(name, " /\r\n\t\\") {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) ||
			unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) ||
			unicode.Is(unicode.Zp, character) {
			return false
		}
	}
	return true
}

func unsafeLogEntryPath(directory, name string) string {
	digest := sha256.Sum256([]byte(name))
	return path.Join(directory, fmt.Sprintf("(안전하지 않은 이름 sha256=%x)", digest))
}

func addLogInventoryBoundary(inventory *logInventory, path, kind, reason string) {
	inventory.incomplete = true
	inventory.boundaryCount++
	if unsupportedLogInventoryBoundary(kind) {
		inventory.unsupportedBoundary = true
	}
	if len(inventory.boundaries) >= maxLogInventoryBoundaries {
		return
	}
	inventory.boundaries = append(inventory.boundaries, logInventoryBoundary{
		Path:   path,
		Kind:   kind,
		Reason: reason,
	})
}

func unsupportedLogInventoryBoundary(kind string) bool {
	switch kind {
	case "directory_identity_unavailable",
		"directory_limit",
		"entry_limit",
		"file_identity_unavailable",
		"file_limit",
		"unsupported_name",
		"broken_symlink",
		"symlink_cycle",
		"symlink_directory",
		"unsupported_symlink_target":
		return true
	default:
		return false
	}
}

type logFileAddResult uint8

const (
	logFileAlreadySeen logFileAddResult = iota
	logFileAdded
	logFileLimitExceeded
)

func addLogFile(inventory *logInventory, seen map[string]struct{}, metadata system.FileMetadata) logFileAddResult {
	key := metadata.Path
	if metadata.Device != 0 || metadata.Inode != 0 {
		key = fmt.Sprintf("%d:%d", metadata.Device, metadata.Inode)
	}
	if _, exists := seen[key]; exists {
		return logFileAlreadySeen
	}
	if len(inventory.files) >= maxLogFiles {
		return logFileLimitExceeded
	}
	seen[key] = struct{}{}
	inventory.files = append(inventory.files, metadata)
	inventory.evidence = append(inventory.evidence, support.FileMetadataEvidence(metadata))
	return logFileAdded
}

func inspectLogACLs(
	ctx context.Context,
	environment evaluator.Environment,
	paths []string,
) (map[string]aclAssessment, []model.Evidence, bool, error) {
	assessments := make(map[string]aclAssessment, len(paths))
	if _, native := environment.Files.(system.XAttrReader); native {
		return inspectLogACLsNatively(ctx, environment, paths)
	}
	availabilityEvidence, availabilityErr := support.RequireACLTool(environment.Commands, "/var/log")
	if availabilityErr != nil {
		if support.IsACLToolUnavailable(availabilityErr) {
			for _, filePath := range paths {
				assessments[filePath] = aclAssessment{ambiguousReasons: []string{support.ACLInspectionUnavailableReason}}
			}
			return assessments, []model.Evidence{availabilityEvidence}, false, nil
		}
		return nil, nil, false, availabilityErr
	}
	evidence := make([]model.Evidence, 0, (len(paths)+aclBatchSize-1)/aclBatchSize)
	for start := 0; start < len(paths); start += aclBatchSize {
		end := start + aclBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		arguments := append([]string{"-pn", "--"}, paths[start:end]...)
		spec := executor.Spec{Name: "getfacl", Arguments: arguments, Timeout: 30 * time.Second, MaxOutput: 8 << 20}
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return nil, nil, false, err
		}
		evidence = append(evidence, support.CommandEvidence(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return nil, evidence, false, fmt.Errorf("getfacl exit=%d truncated=%t", result.ExitCode, result.Truncated)
		}
		parsed, err := parseACLDocuments(string(result.Stdout))
		if err != nil {
			return nil, evidence, false, err
		}
		for _, filePath := range paths[start:end] {
			assessment, exists := parsed[filePath]
			if !exists {
				return nil, evidence, false, fmt.Errorf("getfacl output is missing a requested path")
			}
			if len(assessment.clearReasons) > 0 {
				assessment.ambiguousReasons = append(
					assessment.ambiguousReasons,
					"경로 기반 ACL 결과에서 기준 초과 후보가 확인되었으나 동일 파일 스냅샷으로 확정할 수 없음",
				)
			}
			assessment.clearReasons = nil
			assessment.ambiguousReasons = append(
				assessment.ambiguousReasons,
				"경로 기반 ACL 결과를 동일 파일 스냅샷으로 확정할 수 없음",
			)
			assessments[filePath] = assessment
		}
	}
	evidence = append(evidence, support.FactEvidence("posix_acl_path_fallback", map[string]any{
		"paths_checked":  len(paths),
		"snapshot_bound": false,
	}))
	return assessments, evidence, false, nil
}

func inspectLogACLsNatively(
	ctx context.Context,
	environment evaluator.Environment,
	paths []string,
) (map[string]aclAssessment, []model.Evidence, bool, error) {
	assessments := make(map[string]aclAssessment, len(paths))
	evidence := make([]model.Evidence, 0)
	present := 0
	absent := 0
	fallback := 0
	unavailable := 0
	unavailablePaths := make([]string, 0)
	snapshotBoundaries := 0
	snapshotBoundaryPaths := make([]string, 0)
	for _, filePath := range paths {
		inspection, err := support.InspectPOSIXACL(
			ctx,
			environment.Files,
			environment.Commands,
			filePath,
			true,
			false,
			nil,
		)
		if err != nil {
			if support.IsACLToolUnavailable(err) {
				unavailable++
				unavailablePaths = append(unavailablePaths, filePath)
				assessments[filePath] = aclAssessment{ambiguousReasons: []string{support.ACLInspectionUnavailableReason}}
				continue
			}
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, system.ErrFileChanged) {
				snapshotBoundaries++
				snapshotBoundaryPaths = append(snapshotBoundaryPaths, filePath)
				assessments[filePath] = aclAssessment{ambiguousReasons: []string{
					"ACL 수집 중 로그 경로가 사라지거나 파일 스냅샷이 변경됨",
				}}
				if inspection.Evidence.Source != "" {
					evidence = append(evidence, inspection.Evidence)
				}
				continue
			}
			if inspection.Evidence.Source != "" {
				evidence = append(evidence, inspection.Evidence)
			}
			return nil, evidence, false, err
		}
		lines := aclDocumentLines(inspection.Content)
		assessment, err := assessACLDocument(lines)
		if err != nil {
			return nil, evidence, false, err
		}
		assessment.snapshot = inspection.Metadata
		if inspection.Metadata == nil {
			if len(assessment.clearReasons) > 0 {
				assessment.ambiguousReasons = append(
					assessment.ambiguousReasons,
					"경로 기반 ACL 결과에서 기준 초과 후보가 확인되었으나 동일 파일 스냅샷으로 확정할 수 없음",
				)
			}
			assessment.clearReasons = nil
			assessment.ambiguousReasons = append(
				assessment.ambiguousReasons,
				"경로 기반 ACL 결과를 동일 파일 스냅샷으로 확정할 수 없음",
			)
		}
		assessments[filePath] = assessment
		if inspection.Evidence.Source == "posix_acl_xattr" {
			if inspection.Evidence.Fact["access_acl_present"] == true {
				present++
				evidence = append(evidence, inspection.Evidence)
			} else {
				absent++
			}
		} else {
			fallback++
			evidence = append(evidence, inspection.Evidence)
		}
	}
	evidence = append([]model.Evidence{support.FactEvidence("posix_acl_xattr_batch", map[string]any{
		"paths_checked":        len(paths),
		"access_acl_present":   present,
		"access_acl_absent":    absent,
		"fallback_inspections": fallback,
		"unavailable":          unavailable,
		"unavailable_paths":    limitedStrings(unavailablePaths, 32),
		"snapshot_boundaries":  snapshotBoundaries,
		"snapshot_paths":       limitedStrings(snapshotBoundaryPaths, 32),
	})}, evidence...)
	return assessments, evidence, unavailable == 0 && fallback == 0, nil
}

func aclDocumentLines(content string) []string {
	lines := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func parseACLDocuments(content string) (map[string]aclAssessment, error) {
	documents := make(map[string][]string)
	currentPath := ""
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "# file: ") {
			currentPath = strings.TrimSpace(strings.TrimPrefix(line, "# file: "))
			if currentPath == "" {
				return nil, fmt.Errorf("getfacl output contains an empty file header")
			}
			if _, exists := documents[currentPath]; exists {
				return nil, fmt.Errorf("getfacl output contains a duplicate file header")
			}
			documents[currentPath] = nil
			continue
		}
		if currentPath == "" || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		documents[currentPath] = append(documents[currentPath], line)
	}
	result := make(map[string]aclAssessment, len(documents))
	for filePath, lines := range documents {
		assessment, err := assessACLDocument(lines)
		if err != nil {
			return nil, err
		}
		result[filePath] = assessment
	}
	return result, nil
}

func assessACLDocument(lines []string) (aclAssessment, error) {
	type entry struct {
		tag       string
		qualifier string
		perms     uint8
		effective *uint8
	}
	entries := make([]entry, 0, len(lines))
	mask := uint8(0o7)
	assessment := aclAssessment{}
	for _, raw := range lines {
		mainPart, comment, _ := strings.Cut(raw, "#")
		mainPart = strings.TrimSpace(mainPart)
		if strings.HasPrefix(mainPart, "default:") {
			assessment.ambiguousReasons = append(assessment.ambiguousReasons, "regular 파일에 default ACL이 보고됨")
			continue
		}
		fields := strings.Split(mainPart, ":")
		if len(fields) != 3 {
			return aclAssessment{}, fmt.Errorf("getfacl output contains an invalid ACL entry")
		}
		permissions, err := parseACLPermission(fields[2])
		if err != nil {
			return aclAssessment{}, err
		}
		item := entry{tag: fields[0], qualifier: fields[1], perms: permissions}
		comment = strings.TrimSpace(comment)
		if strings.HasPrefix(comment, "effective:") {
			effective, err := parseACLPermission(strings.TrimSpace(strings.TrimPrefix(comment, "effective:")))
			if err != nil {
				return aclAssessment{}, err
			}
			item.effective = &effective
		}
		if item.tag == "mask" && item.qualifier == "" {
			mask = item.perms
		}
		entries = append(entries, item)
	}
	for _, item := range entries {
		if item.tag == "mask" && item.qualifier == "" {
			continue
		}
		actual := item.perms
		if item.effective != nil {
			actual = *item.effective
		} else if item.tag == "group" || item.qualifier != "" {
			actual &= mask
		}
		allowed := uint8(0o4)
		switch {
		case item.tag == "user" && item.qualifier == "":
			allowed = 0o6
		case item.tag == "group", item.tag == "user" && item.qualifier != "":
			allowed = 0o4
		case item.tag == "other" && item.qualifier == "":
			allowed = 0o4
		default:
			assessment.ambiguousReasons = append(assessment.ambiguousReasons, "지원하지 않는 ACL 항목")
			continue
		}
		extra := actual &^ allowed
		if extra == 0 {
			continue
		}
		reason := fmt.Sprintf("ACL %s:%s 권한이 기준을 초과함", item.tag, item.qualifier)
		assessment.clearReasons = append(assessment.clearReasons, reason)
	}
	return assessment, nil
}

func parseACLPermission(value string) (uint8, error) {
	value = strings.TrimSpace(value)
	if len(value) != 3 {
		return 0, fmt.Errorf("getfacl output contains an invalid permission")
	}
	var result uint8
	for index, expected := range []byte{'r', 'w', 'x'} {
		if value[index] == '-' {
			continue
		}
		if value[index] != expected {
			return 0, fmt.Errorf("getfacl output contains an invalid permission")
		}
		result |= 1 << (2 - index)
	}
	return result, nil
}

func assessLogFile(metadata system.FileMetadata, acl aclAssessment) ([]string, []string) {
	clear := make([]string, 0)
	ambiguous := make([]string, 0)
	prefix := metadata.Path + ": "
	if metadata.UID < 0 {
		ambiguous = append(ambiguous, prefix+"소유자 UID를 확인할 수 없음")
	} else if metadata.UID != 0 {
		clear = append(clear, fmt.Sprintf("%s비-root 소유자 uid=%d", prefix, metadata.UID))
	}
	mode := metadata.Mode.Perm()
	if metadata.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		clear = append(clear, prefix+"특수 권한 비트가 설정됨")
	}
	if mode&0o111 != 0 {
		clear = append(clear, fmt.Sprintf("%s실행 비트가 설정됨 mode=%04o", prefix, mode))
	}
	if mode&0o002 != 0 {
		clear = append(clear, fmt.Sprintf("%sother 쓰기 권한이 설정됨 mode=%04o", prefix, mode))
	}
	if mode&0o020 != 0 {
		clear = append(clear, fmt.Sprintf("%sgroup 쓰기 권한 mode=%04o", prefix, mode))
	}
	for _, reason := range acl.clearReasons {
		clear = append(clear, prefix+reason)
	}
	for _, reason := range acl.ambiguousReasons {
		ambiguous = append(ambiguous, prefix+reason)
	}
	return clear, ambiguous
}

func limitedLogInventoryBoundaries(boundaries []logInventoryBoundary, limit int) []map[string]string {
	ordered := append([]logInventoryBoundary(nil), boundaries...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		if ordered[i].Kind != ordered[j].Kind {
			return ordered[i].Kind < ordered[j].Kind
		}
		return ordered[i].Reason < ordered[j].Reason
	})
	if limit > 0 && len(ordered) > limit {
		ordered = ordered[:limit]
	}
	result := make([]map[string]string, 0, len(ordered))
	for _, boundary := range ordered {
		result = append(result, map[string]string{
			"path":   boundary.Path,
			"kind":   boundary.Kind,
			"reason": boundary.Reason,
		})
	}
	return result
}

func summarizeLogInventoryBoundaries(boundaries []logInventoryBoundary, total, limit int) string {
	if len(boundaries) == 0 {
		if total > 0 {
			return fmt.Sprintf("확인하지 못한 로그 경계 %d건", total)
		}
		return "로그 파일 목록을 완전히 확인하지 못했습니다."
	}
	values := make([]string, 0, len(boundaries))
	for _, boundary := range boundaries {
		values = append(values, boundary.Path+": "+boundary.Reason)
	}
	sort.Strings(values)
	summary := limitedStrings(values, limit)
	reported := min(len(values), limit)
	if total > reported {
		if len(summary) > reported {
			summary = summary[:reported]
		}
		summary = append(summary, fmt.Sprintf("... %d개 추가", total-reported))
	}
	return strings.Join(summary, "; ")
}

func limitedStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return append([]string(nil), values...)
	}
	result := append([]string(nil), values[:limit]...)
	result = append(result, fmt.Sprintf("... %d개 추가", len(values)-limit))
	return result
}

func summarizeStrings(values []string, limit int) string {
	if len(values) == 0 {
		return "해당 항목 없음"
	}
	return strings.Join(limitedStrings(values, limit), "; ")
}

func logFilePermissionError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "로그 파일의 소유자, 권한 또는 ACL을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
