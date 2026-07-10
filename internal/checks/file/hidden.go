package filecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorSuspiciousHidden = "unix.file.suspicious_hidden"
	hiddenHashPerFileLimit    = int64(4 << 20)
	hiddenHashTotalLimit      = int64(32 << 20)
)

type hiddenFinding struct {
	PathSHA256       string
	MetadataSHA256   string
	ContentSHA256    string
	ContentHashState string
	FileType         string
	Mode             string
	UID              int
	GID              int
	Size             int64
	ModifiedAt       string
	Executable       bool
	Package          string
}

func evaluateSuspiciousHidden(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	expected := "로컬 영속 파일 시스템의 숨김 항목 전체를 정상 baseline 및 업무 필요성과 대조해야 합니다."
	namespace, err := inspectMountNamespace(environment.Files)
	if err != nil {
		return fileError("mount_namespace_failed", "마운트 네임스페이스 경계를 확인하지 못했습니다.", err)
	}
	before, err := collectFilesystemSnapshot(ctx, environment)
	if err != nil {
		return fileError("filesystem_snapshot_failed", "로컬 영속 파일 시스템을 확인하지 못했습니다.", err)
	}
	evidence := []model.Evidence{namespace.Evidence, before.Evidence}
	candidates := make([]string, 0)
	searchIncomplete := false
	for _, mount := range before.Eligible {
		search, searchErr := runPathSearch(ctx, environment, mount.Target, "-name", ".*")
		if searchErr != nil {
			return fileError("hidden_file_search_failed", "숨김 파일 및 디렉터리 검색을 완료하지 못했습니다.", searchErr)
		}
		evidence = append(evidence, search.Evidence)
		candidates = append(candidates, search.Paths...)
		searchIncomplete = searchIncomplete || search.Incomplete
	}
	candidates = uniqueSortedPaths(candidates)
	after, err := collectFilesystemSnapshot(ctx, environment)
	if err != nil {
		return fileError("filesystem_snapshot_failed", "검색 후 파일 시스템 상태를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, after.Evidence)

	incompleteReasons := make([]string, 0)
	if !namespace.Known {
		incompleteReasons = append(incompleteReasons, "mount_namespace_unknown")
	} else if !namespace.HostWide {
		incompleteReasons = append(incompleteReasons, "non_host_mount_namespace")
	}
	if before.UnsupportedCount > 0 || after.UnsupportedCount > 0 {
		incompleteReasons = append(incompleteReasons, "unsupported_or_ambiguous_filesystem")
	}
	if !validateSnapshotStability(before, after) {
		incompleteReasons = append(incompleteReasons, "mount_snapshot_changed")
	}
	if searchIncomplete {
		incompleteReasons = append(incompleteReasons, "search_output_incomplete")
	}
	limit := len(candidates)
	if limit > maxDetailedFileFindings {
		limit = maxDetailedFileFindings
		incompleteReasons = append(incompleteReasons, "candidate_processing_limit")
	}

	findings := make([]hiddenFinding, 0, minInt(limit, maxEvidenceFileFindings))
	contentBudget := hiddenHashTotalLimit
	packageUnknown := 0
	for index, candidate := range candidates[:limit] {
		metadata, statErr := environment.Files.Lstat(candidate)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				incompleteReasons = append(incompleteReasons, "candidate_disappeared")
				continue
			}
			return fileError("hidden_candidate_stat_failed", "숨김 항목의 메타데이터를 확인하지 못했습니다.", privatePathError("lstat", candidate, statErr))
		}
		mount, found := mountForPath(before.Eligible, candidate)
		if !found || metadata.Device == 0 || metadata.Device != mount.Device {
			incompleteReasons = append(incompleteReasons, "mount_membership_or_device_ambiguous")
			continue
		}
		if index >= maxEvidenceFileFindings {
			continue
		}
		finding := hiddenFinding{
			PathSHA256:     pathDigest(candidate),
			MetadataSHA256: hiddenMetadataDigest(metadata.Mode, metadata.UID, metadata.GID, metadata.Size, metadata.Device, metadata.Inode, metadata.ModTime),
			FileType:       metadata.FileType,
			Mode:           fmt.Sprintf("%04o", posixMode(metadata.Mode)),
			UID:            metadata.UID,
			GID:            metadata.GID,
			Size:           metadata.Size,
			ModifiedAt:     metadata.ModTime.UTC().Format(time.RFC3339Nano),
			Executable:     metadata.Mode.Perm()&0o111 != 0,
		}
		switch {
		case metadata.FileType != "regular":
			finding.ContentHashState = "not_regular"
		case metadata.Size < 0:
			finding.ContentHashState = "invalid_size"
			incompleteReasons = append(incompleteReasons, "candidate_size_invalid")
		case metadata.Size > hiddenHashPerFileLimit:
			finding.ContentHashState = "per_file_limit"
		case metadata.Size > contentBudget:
			finding.ContentHashState = "total_budget_limit"
		default:
			data, readMetadata, readErr := environment.Files.ReadFile(ctx, candidate, hiddenHashPerFileLimit)
			if readErr != nil {
				if errors.Is(readErr, os.ErrNotExist) {
					finding.ContentHashState = "candidate_disappeared"
					incompleteReasons = append(incompleteReasons, "candidate_disappeared")
					break
				}
				return fileError("hidden_candidate_hash_failed", "숨김 일반 파일의 해시를 계산하지 못했습니다.", privatePathError("read", candidate, readErr))
			}
			if readMetadata.Device != metadata.Device || readMetadata.Inode != metadata.Inode || readMetadata.FileType != "regular" {
				finding.ContentHashState = "candidate_changed_during_hash"
				incompleteReasons = append(incompleteReasons, "candidate_changed_during_hash")
				break
			}
			finding.ContentSHA256 = bytesDigest(data)
			finding.ContentHashState = "collected"
			contentBudget -= int64(len(data))
		}
		if environment.Commands.Available("rpm") {
			ownership, ownerErr := inspectRPMOwnership(ctx, environment, candidate)
			if ownerErr != nil {
				return fileError("rpm_ownership_failed", "숨김 항목의 RPM 소유 정보를 확인하지 못했습니다.", ownerErr)
			}
			if ownership.Evidence.Kind != "" {
				evidence = append(evidence, ownership.Evidence)
			}
			if !ownership.Complete {
				packageUnknown++
			} else if ownership.Owned {
				finding.Package = ownership.NEVRA
			}
		} else {
			packageUnknown++
		}
		stable, stableErr := confirmMetadataStable(environment.Files, candidate, metadata)
		if stableErr != nil {
			return fileError("hidden_candidate_stability_failed", "숨김 항목의 안정성을 재확인하지 못했습니다.", stableErr)
		}
		if !stable {
			finding.ContentSHA256 = ""
			finding.ContentHashState = "candidate_changed_after_inspection"
			incompleteReasons = append(incompleteReasons, "candidate_changed_after_inspection")
		}
		findings = append(findings, finding)
	}
	finalSnapshot, err := collectFilesystemSnapshot(ctx, environment)
	if err != nil {
		return fileError("filesystem_snapshot_failed", "숨김 항목 수집 후 파일 시스템 상태를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, finalSnapshot.Evidence)
	if finalSnapshot.UnsupportedCount > 0 {
		incompleteReasons = append(incompleteReasons, "unsupported_or_ambiguous_filesystem")
	}
	if !validateSnapshotStability(before, finalSnapshot) {
		incompleteReasons = append(incompleteReasons, "mount_snapshot_changed")
	}
	incompleteReasons = uniqueSortedPaths(incompleteReasons)
	evidence = append(evidence, support.FactEvidence("hidden-entry-inventory-summary", map[string]any{
		"candidate_count":               len(candidates),
		"candidate_set_sha256":          pathSetDigest(candidates),
		"content_hash_algorithm":        "sha256",
		"content_hash_budget_bytes":     hiddenHashTotalLimit,
		"content_hash_per_file_bytes":   hiddenHashPerFileLimit,
		"detailed_candidates":           hiddenFindingFacts(findings),
		"detailed_candidate_limit":      maxEvidenceFileFindings,
		"incomplete_reasons":            incompleteReasons,
		"package_context_unknown_count": packageUnknown,
		"paths_redacted_as_sha256":      true,
	}))

	if len(incompleteReasons) > 0 || limit < len(candidates) {
		reason := model.UnknownInsufficientEvidence
		if containsAny(incompleteReasons, "mount_namespace_unknown", "non_host_mount_namespace", "unsupported_or_ambiguous_filesystem") {
			reason = model.UnknownUnsupportedConfiguration
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       "숨김 항목 inventory 또는 로컬 영속 파일 시스템 범위를 완전히 수집하지 못했습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("후보 %d건, 상세 메타데이터 %d건", len(candidates), len(findings)),
			Evidence:      evidence,
		}
	}
	if len(before.Eligible) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "검색할 로컬 영속 POSIX 파일 시스템이 없습니다.",
			Expected: expected,
			Observed: "대상 마운트 없음",
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "숨김 이름만으로 악성 또는 불필요 여부를 판단할 수 없어 정상 baseline과 수동 대조가 필요합니다.",
		Expected:      expected,
		Observed:      fmt.Sprintf("숨김 파일 및 디렉터리 후보 %d건", len(candidates)),
		Evidence:      evidence,
	}
}

func hiddenMetadataDigest(mode os.FileMode, uid, gid int, size int64, device, inode uint64, modified time.Time) string {
	return pathDigest(fmt.Sprintf("%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%s", mode, uid, gid, size, device, inode, modified.UTC().Format(time.RFC3339Nano)))
}

func hiddenFindingFacts(findings []hiddenFinding) []map[string]any {
	facts := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		fact := map[string]any{
			"content_hash_state": finding.ContentHashState,
			"executable":         finding.Executable,
			"file_type":          finding.FileType,
			"group_gid":          finding.GID,
			"metadata_sha256":    finding.MetadataSHA256,
			"mode":               finding.Mode,
			"modified_at":        finding.ModifiedAt,
			"owner_uid":          finding.UID,
			"path_sha256":        finding.PathSHA256,
			"size":               finding.Size,
		}
		if finding.ContentSHA256 != "" {
			fact["content_sha256"] = finding.ContentSHA256
		}
		if finding.Package != "" {
			fact["package"] = finding.Package
		}
		facts = append(facts, fact)
	}
	return facts
}
