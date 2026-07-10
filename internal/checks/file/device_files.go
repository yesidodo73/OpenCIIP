package filecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorInvalidDeviceNodes = "unix.file.invalid_device_nodes"

type deviceRegularFinding struct {
	PathSHA256     string
	Mode           string
	UID            int
	Size           int64
	Approved       bool
	ConfirmedBad   bool
	UdevKnown      bool
	UdevChecked    bool
	ProcessInUse   bool
	ProcessChecked bool
}

func evaluateInvalidDeviceNodes(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	expected := "/dev의 같은 파일 시스템에 있는 일반 파일이 승인된 용도로만 존재하고, 불필요하다고 확인된 후보가 없어야 합니다."
	approved, approvedSet, err := approvedPathParameter(rule.Parameters, "approved_dev_regular_paths", "/dev")
	if err != nil {
		return fileError("invalid_rule_parameter", "/dev 일반 파일 승인 목록을 해석하지 못했습니다.", err)
	}
	confirmedInvalid, invalidSet, err := approvedPathParameter(rule.Parameters, "confirmed_invalid_dev_regular_paths", "/dev")
	if err != nil {
		return fileError("invalid_rule_parameter", "/dev 불필요 파일 확인 목록을 해석하지 못했습니다.", err)
	}
	for candidate := range approved {
		if _, conflict := confirmedInvalid[candidate]; conflict {
			return fileError("invalid_rule_parameter", "/dev 정책 목록이 서로 충돌합니다.", fmt.Errorf("a path is both approved and confirmed invalid"))
		}
	}

	namespace, err := inspectMountNamespace(environment.Files)
	if err != nil {
		return fileError("mount_namespace_failed", "마운트 네임스페이스 경계를 확인하지 못했습니다.", err)
	}
	before, err := collectFilesystemSnapshot(ctx, environment)
	if err != nil {
		return fileError("filesystem_snapshot_failed", "/dev 마운트 경계를 확인하지 못했습니다.", err)
	}
	rootMetadata, err := environment.Files.Lstat("/dev")
	if err != nil {
		return fileError("dev_stat_failed", "/dev 메타데이터를 확인하지 못했습니다.", err)
	}
	evidence := []model.Evidence{namespace.Evidence, before.Evidence, support.FileMetadataEvidence(rootMetadata)}
	search, err := runPathSearch(ctx, environment, "/dev", "-type", "f")
	if err != nil {
		return fileError("dev_regular_search_failed", "/dev 일반 파일 검색을 완료하지 못했습니다.", err)
	}
	evidence = append(evidence, search.Evidence)
	after, err := collectFilesystemSnapshot(ctx, environment)
	if err != nil {
		return fileError("filesystem_snapshot_failed", "검색 후 /dev 마운트 경계를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, after.Evidence)

	incompleteReasons := make([]string, 0)
	if rootMetadata.FileType != "directory" {
		incompleteReasons = append(incompleteReasons, "dev_is_not_directory")
	}
	if rootMetadata.Device == 0 {
		incompleteReasons = append(incompleteReasons, "dev_device_identity_unavailable")
	}
	if !namespace.Known {
		incompleteReasons = append(incompleteReasons, "mount_namespace_unknown")
	} else if !namespace.HostWide {
		incompleteReasons = append(incompleteReasons, "non_host_mount_namespace")
	}
	devMounts := exactTargetMounts(before.All, "/dev")
	if len(devMounts) != 1 || devMounts[0].FSType != "devtmpfs" {
		incompleteReasons = append(incompleteReasons, "dev_mount_is_not_unique_devtmpfs")
	}
	if !validateSnapshotStability(before, after) {
		incompleteReasons = append(incompleteReasons, "mount_snapshot_changed")
	}
	if search.Incomplete {
		incompleteReasons = append(incompleteReasons, "search_output_incomplete")
	}

	limit := len(search.Paths)
	if limit > maxDetailedFileFindings {
		limit = maxDetailedFileFindings
		incompleteReasons = append(incompleteReasons, "candidate_processing_limit")
	}
	findings := make([]deviceRegularFinding, 0, limit)
	confirmedCount := 0
	unclassifiedCount := 0
	approvedCount := 0
	contextIncomplete := 0
	for _, candidate := range search.Paths[:limit] {
		metadata, statErr := environment.Files.Lstat(candidate)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				incompleteReasons = append(incompleteReasons, "candidate_disappeared")
				continue
			}
			return fileError("dev_candidate_stat_failed", "/dev 일반 파일 후보의 메타데이터를 확인하지 못했습니다.", privatePathError("lstat", candidate, statErr))
		}
		if metadata.FileType != "regular" || (rootMetadata.Device != 0 && metadata.Device != rootMetadata.Device) {
			incompleteReasons = append(incompleteReasons, "candidate_changed_or_crossed_device")
			continue
		}
		_, isApproved := approved[candidate]
		_, isConfirmedInvalid := confirmedInvalid[candidate]
		finding := deviceRegularFinding{
			PathSHA256:   pathDigest(candidate),
			Mode:         fmt.Sprintf("%04o", posixMode(metadata.Mode)),
			UID:          metadata.UID,
			Size:         metadata.Size,
			Approved:     isApproved,
			ConfirmedBad: isConfirmedInvalid,
		}
		if len(findings) < maxEvidenceFileFindings {
			udevKnown, udevChecked, udevEvidence, inspectErr := inspectUdevCandidate(ctx, environment, candidate)
			if inspectErr != nil {
				return fileError("udev_candidate_failed", "/dev 일반 파일 후보의 udev 정보를 확인하지 못했습니다.", inspectErr)
			}
			if udevEvidence.Kind != "" {
				evidence = append(evidence, udevEvidence)
			}
			finding.UdevKnown = udevKnown
			finding.UdevChecked = udevChecked
			inUse, processChecked, processEvidence, inspectErr := inspectCandidateUse(ctx, environment, candidate)
			if inspectErr != nil {
				return fileError("dev_candidate_use_failed", "/dev 일반 파일 후보의 프로세스 사용 여부를 확인하지 못했습니다.", inspectErr)
			}
			if processEvidence.Kind != "" {
				evidence = append(evidence, processEvidence)
			}
			finding.ProcessInUse = inUse
			finding.ProcessChecked = processChecked
			if !udevChecked || !processChecked {
				contextIncomplete++
			}
		}
		stable, stableErr := confirmMetadataStable(environment.Files, candidate, metadata)
		if stableErr != nil {
			return fileError("dev_candidate_stability_failed", "/dev 일반 파일 후보의 안정성을 재확인하지 못했습니다.", stableErr)
		}
		if !stable {
			incompleteReasons = append(incompleteReasons, "candidate_changed_after_inspection")
			continue
		}
		if isConfirmedInvalid {
			confirmedCount++
		} else if isApproved {
			approvedCount++
		} else {
			unclassifiedCount++
		}
		findings = append(findings, finding)
	}
	finalSnapshot, err := collectFilesystemSnapshot(ctx, environment)
	if err != nil {
		return fileError("filesystem_snapshot_failed", "후보 검증 후 /dev 마운트 경계를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, finalSnapshot.Evidence)
	if !validateSnapshotStability(before, finalSnapshot) {
		incompleteReasons = append(incompleteReasons, "mount_snapshot_changed")
	}
	incompleteReasons = uniqueSortedPaths(incompleteReasons)
	evidence = append(evidence, support.FactEvidence("dev-regular-file-inventory-summary", map[string]any{
		"approved_candidate_count":       approvedCount,
		"approved_policy_count":          len(approved),
		"approved_policy_set":            approvedSet,
		"candidate_count":                len(search.Paths),
		"candidate_set_sha256":           pathSetDigest(search.Paths),
		"confirmed_invalid_count":        confirmedCount,
		"confirmed_invalid_policy_count": len(confirmedInvalid),
		"confirmed_invalid_policy_set":   invalidSet,
		"context_incomplete_count":       contextIncomplete,
		"detailed_candidates":            deviceRegularFindingFacts(findings, maxEvidenceFileFindings),
		"incomplete_reasons":             incompleteReasons,
		"unclassified_candidate_count":   unclassifiedCount + len(search.Paths) - limit,
	}))

	if confirmedCount > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "불필요하거나 위장 파일이라고 확인된 일반 파일이 /dev에 있습니다.",
			Expected: expected,
			Observed: fmt.Sprintf("확정된 불필요 후보 %d건", confirmedCount),
			Evidence: evidence,
		}
	}
	if len(incompleteReasons) > 0 || limit < len(search.Paths) {
		reason := model.UnknownInsufficientEvidence
		if containsAny(incompleteReasons, "mount_namespace_unknown", "non_host_mount_namespace", "dev_mount_is_not_unique_devtmpfs") {
			reason = model.UnknownUnsupportedConfiguration
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       "/dev 파일 시스템 또는 일부 일반 파일 후보를 완전히 확인하지 못했습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("후보 %d건, 분류 완료 %d건", len(search.Paths), approvedCount+confirmedCount),
			Evidence:      evidence,
		}
	}
	if len(search.Paths) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "/dev의 같은 파일 시스템에 일반 파일이 없습니다.",
			Expected: expected,
			Observed: "일반 파일 후보 없음",
			Evidence: evidence,
		}
	}
	if unclassifiedCount > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "/dev 일반 파일의 생성 주체와 업무상 용도를 자동으로 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("분류가 필요한 후보 %d건", unclassifiedCount),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "/dev의 모든 일반 파일 후보가 기관 승인 목록에 포함되어 있습니다.",
		Expected: expected,
		Observed: fmt.Sprintf("승인 후보 %d건", approvedCount),
		Evidence: evidence,
	}
}

func inspectUdevCandidate(ctx context.Context, environment evaluator.Environment, candidate string) (bool, bool, model.Evidence, error) {
	if !environment.Commands.Available("udevadm") {
		return false, false, model.Evidence{}, nil
	}
	spec := executor.Spec{
		Name:      "udevadm",
		Arguments: []string{"info", "--query=property", "--name", candidate},
		Timeout:   15 * time.Second,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return false, false, model.Evidence{}, err
	}
	evidence := privateCommandSummary("udev-candidate-command", spec, result)
	if result.Truncated {
		return false, false, evidence, nil
	}
	switch result.ExitCode {
	case 0:
		return true, true, evidence, nil
	case 1:
		return false, true, evidence, nil
	default:
		return false, false, evidence, fmt.Errorf("udevadm exit=%d", result.ExitCode)
	}
}

func inspectCandidateUse(ctx context.Context, environment evaluator.Environment, candidate string) (bool, bool, model.Evidence, error) {
	if !environment.Commands.Available("fuser") {
		return false, false, model.Evidence{}, nil
	}
	spec := executor.Spec{
		Name:      "fuser",
		Arguments: []string{"-s", "--", candidate},
		Timeout:   15 * time.Second,
		MaxOutput: 64 << 10,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return false, false, model.Evidence{}, err
	}
	evidence := privateCommandSummary("dev-candidate-process-use-command", spec, result)
	if result.Truncated || len(result.Stdout) > 0 || len(result.Stderr) > 0 {
		return false, false, evidence, nil
	}
	switch result.ExitCode {
	case 0:
		return true, true, evidence, nil
	case 1:
		return false, true, evidence, nil
	default:
		return false, false, evidence, fmt.Errorf("fuser exit=%d", result.ExitCode)
	}
}

func exactTargetMounts(mounts []scanMount, target string) []scanMount {
	result := make([]scanMount, 0)
	for _, mount := range mounts {
		if mount.Target == target {
			result = append(result, mount)
		}
	}
	sort.Slice(result, func(i, j int) bool { return mountFingerprint(result[i]) < mountFingerprint(result[j]) })
	return result
}

func deviceRegularFindingFacts(findings []deviceRegularFinding, limit int) []map[string]any {
	if len(findings) > limit {
		findings = findings[:limit]
	}
	facts := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		facts = append(facts, map[string]any{
			"approved":          finding.Approved,
			"confirmed_invalid": finding.ConfirmedBad,
			"mode":              finding.Mode,
			"owner_uid":         finding.UID,
			"path_sha256":       finding.PathSHA256,
			"process_checked":   finding.ProcessChecked,
			"process_in_use":    finding.ProcessInUse,
			"size":              finding.Size,
			"udev_checked":      finding.UdevChecked,
			"udev_known":        finding.UdevKnown,
		})
	}
	return facts
}
