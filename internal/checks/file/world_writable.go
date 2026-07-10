package filecheck

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorWorldWritable = "unix.file.world_writable"

type worldWritableFinding struct {
	PathSHA256 string
	Mode       string
	UID        int
	FSType     string
	ReadOnly   bool
	Package    string
	Approved   bool
}

func evaluateWorldWritable(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	expected := "world-writable 일반 파일이 없거나 모든 후보가 완전한 기관 승인 예외 목록에 포함되어야 합니다."
	approved, policySet, err := approvedPathParameter(rule.Parameters, "approved_world_writable_paths", "")
	if err != nil {
		return fileError("invalid_rule_parameter", "world-writable 승인 목록을 해석하지 못했습니다.", err)
	}
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
		search, searchErr := runPathSearch(ctx, environment, mount.Target,
			"-type", "f", "-perm", "-0002")
		if searchErr != nil {
			return fileError("world_writable_search_failed", "world-writable 일반 파일 검색을 완료하지 못했습니다.", searchErr)
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

	findings := make([]worldWritableFinding, 0, limit)
	stableCandidates := 0
	unapprovedCandidates := 0
	packageUnknown := 0
	for _, candidate := range candidates[:limit] {
		metadata, statErr := environment.Files.Lstat(candidate)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				incompleteReasons = append(incompleteReasons, "candidate_disappeared")
				continue
			}
			return fileError("world_writable_stat_failed", "world-writable 후보의 메타데이터를 확인하지 못했습니다.", privatePathError("lstat", candidate, statErr))
		}
		if metadata.FileType != "regular" || metadata.Mode.Perm()&0o002 == 0 {
			incompleteReasons = append(incompleteReasons, "candidate_changed_during_scan")
			continue
		}
		mount, found := mountForPath(before.Eligible, candidate)
		if !found || metadata.Device == 0 || metadata.Device != mount.Device {
			incompleteReasons = append(incompleteReasons, "mount_membership_or_device_ambiguous")
			continue
		}
		_, isApproved := approved[candidate]
		finding := worldWritableFinding{
			PathSHA256: pathDigest(candidate),
			Mode:       fmt.Sprintf("%04o", posixMode(metadata.Mode)),
			UID:        metadata.UID,
			FSType:     mount.FSType,
			ReadOnly:   mount.ReadOnly,
			Approved:   isApproved,
		}
		if environment.Commands.Available("rpm") && len(findings) < maxEvidenceFileFindings {
			ownership, ownerErr := inspectRPMOwnership(ctx, environment, candidate)
			if ownerErr != nil {
				return fileError("rpm_ownership_failed", "world-writable 후보의 RPM 소유 정보를 확인하지 못했습니다.", ownerErr)
			}
			if ownership.Evidence.Kind != "" {
				evidence = append(evidence, ownership.Evidence)
			}
			if !ownership.Complete {
				packageUnknown++
			} else if ownership.Owned {
				finding.Package = ownership.NEVRA
			}
		} else if !environment.Commands.Available("rpm") {
			packageUnknown++
		}
		stable, stableErr := confirmMetadataStable(environment.Files, candidate, metadata)
		if stableErr != nil {
			return fileError("world_writable_stability_failed", "world-writable 후보의 안정성을 재확인하지 못했습니다.", stableErr)
		}
		if !stable {
			incompleteReasons = append(incompleteReasons, "candidate_changed_after_inspection")
			continue
		}
		stableCandidates++
		if !isApproved {
			unapprovedCandidates++
		}
		findings = append(findings, finding)
	}
	finalSnapshot, err := collectFilesystemSnapshot(ctx, environment)
	if err != nil {
		return fileError("filesystem_snapshot_failed", "파일 검증 후 파일 시스템 상태를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, finalSnapshot.Evidence)
	if finalSnapshot.UnsupportedCount > 0 {
		incompleteReasons = append(incompleteReasons, "unsupported_or_ambiguous_filesystem")
	}
	if !validateSnapshotStability(before, finalSnapshot) {
		incompleteReasons = append(incompleteReasons, "mount_snapshot_changed")
	}
	incompleteReasons = uniqueSortedPaths(incompleteReasons)
	evidence = append(evidence, support.FactEvidence("world-writable-inventory-summary", map[string]any{
		"acl_interpretation":            "POSIX ACL other class is reflected by the authoritative st_mode other-write bit",
		"approved_policy_count":         len(approved),
		"approved_policy_set":           policySet,
		"candidate_count":               len(candidates),
		"candidate_set_sha256":          pathSetDigest(candidates),
		"detailed_candidates":           worldWritableFindingFacts(findings, maxEvidenceFileFindings),
		"incomplete_reasons":            incompleteReasons,
		"package_context_unknown_count": packageUnknown,
		"stable_candidate_count":        stableCandidates,
		"unapproved_candidate_count":    unapprovedCandidates,
	}))

	if policySet && unapprovedCandidates > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "완전한 기관 승인 예외 목록에 포함되지 않은 world-writable 일반 파일이 있습니다.",
			Expected: expected,
			Observed: fmt.Sprintf("미승인 후보 %d건, 전체 후보 %d건", unapprovedCandidates, len(candidates)),
			Evidence: evidence,
		}
	}
	if len(incompleteReasons) > 0 || stableCandidates < len(candidates) {
		reason := model.UnknownInsufficientEvidence
		if containsAny(incompleteReasons, "mount_namespace_unknown", "non_host_mount_namespace", "unsupported_or_ambiguous_filesystem") {
			reason = model.UnknownUnsupportedConfiguration
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       "일부 로컬 영속 파일 시스템 또는 world-writable 후보를 완전히 확인하지 못했습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("후보 %d건 중 안정적으로 확인한 후보 %d건", len(candidates), stableCandidates),
			Evidence:      evidence,
		}
	}
	if len(candidates) > 0 && !policySet {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "world-writable 일반 파일의 설정 이유와 업무상 필요성을 승인 정책 없이 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("검토할 후보 %d건", len(candidates)),
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
		Status:   model.StatusPass,
		Summary:  "world-writable 일반 파일이 없거나 모든 후보가 기관 승인 예외 목록에 포함되어 있습니다.",
		Expected: expected,
		Observed: fmt.Sprintf("로컬 영속 마운트 %d개, 승인 후보 %d건", len(before.Eligible), len(candidates)),
		Evidence: evidence,
	}
}

func worldWritableFindingFacts(findings []worldWritableFinding, limit int) []map[string]any {
	if len(findings) > limit {
		findings = findings[:limit]
	}
	facts := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		fact := map[string]any{
			"approved":        finding.Approved,
			"filesystem_type": finding.FSType,
			"mode":            finding.Mode,
			"owner_uid":       finding.UID,
			"path_sha256":     finding.PathSHA256,
			"read_only_mount": finding.ReadOnly,
		}
		if finding.Package != "" {
			fact["package"] = finding.Package
		}
		facts = append(facts, fact)
	}
	return facts
}
