package filecheck

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorSpecialBits    = "unix.file.special_bits"
	maxSpecialBitCandidates = 256
)

type specialBitFinding struct {
	PathSHA256 string
	Mode       string
	Package    string
	Signature  string
	FSType     string
	NoSUID     bool
	ContentSHA string
	Reason     string
	State      string
}

type specialBitApproval struct {
	ContentSHA256 string
	Mode          uint64
}

func evaluateSpecialBits(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	expected := "모든 SUID/SGID 일반 파일이 기관이 승인한 경로·모드·내용 해시와 일치해야 하며, RPM 서명·무결성은 업무 필요성 승인을 대신하지 않습니다."
	approved, policySet, err := specialBitApprovalParameter(rule.Parameters)
	if err != nil {
		return fileError("invalid_rule_parameter", "특수 권한 승인 목록을 해석하지 못했습니다.", err)
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

	specialPaths := make([]string, 0)
	stickyPaths := make([]string, 0)
	searchIncomplete := false
	for _, mount := range before.Eligible {
		special, searchErr := runPathSearch(ctx, environment, mount.Target,
			"-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")")
		if searchErr != nil {
			return fileError("special_bit_search_failed", "SUID/SGID 일반 파일 검색을 완료하지 못했습니다.", searchErr)
		}
		evidence = append(evidence, special.Evidence)
		specialPaths = append(specialPaths, special.Paths...)
		searchIncomplete = searchIncomplete || special.Incomplete

		sticky, searchErr := runPathSearch(ctx, environment, mount.Target,
			"-type", "d", "-perm", "-1000")
		if searchErr != nil {
			return fileError("sticky_bit_search_failed", "sticky 디렉터리 검색을 완료하지 못했습니다.", searchErr)
		}
		evidence = append(evidence, sticky.Evidence)
		stickyPaths = append(stickyPaths, sticky.Paths...)
		searchIncomplete = searchIncomplete || sticky.Incomplete
	}
	specialPaths = uniqueSortedPaths(specialPaths)
	stickyPaths = uniqueSortedPaths(stickyPaths)
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

	limit := len(specialPaths)
	if limit > maxSpecialBitCandidates {
		limit = maxSpecialBitCandidates
		incompleteReasons = append(incompleteReasons, "candidate_processing_limit")
	}
	findings := make([]specialBitFinding, 0, limit)
	packageCache := make(map[string]rpmPackageInspection)
	rpmEvidenceTotal := 0
	definiteFailures := 0
	unknownCandidates := 0
	verifiedCandidates := 0
	for _, candidate := range specialPaths[:limit] {
		metadata, statErr := environment.Files.Lstat(candidate)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				unknownCandidates++
				incompleteReasons = append(incompleteReasons, "candidate_changed_during_inspection")
				findings = append(findings, specialBitFinding{PathSHA256: pathDigest(candidate), State: "unknown", Reason: "candidate_disappeared"})
				continue
			}
			return fileError("special_bit_stat_failed", "특수 권한 파일 메타데이터를 확인하지 못했습니다.", privatePathError("lstat", candidate, statErr))
		}
		actualSpecial := posixSpecialBits(metadata.Mode)
		finding := specialBitFinding{
			PathSHA256: pathDigest(candidate),
			Mode:       fmt.Sprintf("%04o", posixMode(metadata.Mode)),
		}
		if metadata.FileType != "regular" || actualSpecial == 0 {
			unknownCandidates++
			incompleteReasons = append(incompleteReasons, "candidate_changed_during_inspection")
			finding.State = "unknown"
			finding.Reason = "candidate_changed_during_scan"
			findings = append(findings, finding)
			continue
		}
		mount, found := mountForPath(before.Eligible, candidate)
		if !found || metadata.Device == 0 || metadata.Device != mount.Device {
			unknownCandidates++
			incompleteReasons = append(incompleteReasons, "mount_membership_or_device_ambiguous")
			finding.State = "unknown"
			finding.Reason = "mount_membership_or_device_ambiguous"
			findings = append(findings, finding)
			continue
		}
		finding.FSType = mount.FSType
		finding.NoSUID = mount.NoSUID

		approval, pathApproved := approved[candidate]
		if pathApproved {
			if approval.Mode != posixMode(metadata.Mode) {
				stable, stableErr := confirmMetadataStable(environment.Files, candidate, metadata)
				if stableErr != nil {
					return fileError("special_bit_stability_failed", "특수 권한 파일의 안정성을 재확인하지 못했습니다.", stableErr)
				}
				if stable {
					definiteFailures++
					finding.State = "fail"
					finding.Reason = "approved_mode_baseline_mismatch"
				} else {
					unknownCandidates++
					incompleteReasons = append(incompleteReasons, "candidate_changed_during_inspection")
					finding.State = "unknown"
					finding.Reason = "candidate_changed_after_inspection"
				}
				findings = append(findings, finding)
				continue
			}
			contentSHA, hashEvidence, hashErr := hashSpecialBitFile(ctx, environment, candidate)
			if hashErr != nil {
				return fileError("special_bit_hash_failed", "승인된 특수 권한 파일의 내용 해시를 확인하지 못했습니다.", hashErr)
			}
			evidence = append(evidence, hashEvidence)
			finding.ContentSHA = contentSHA
			stable, stableErr := confirmMetadataStable(environment.Files, candidate, metadata)
			if stableErr != nil {
				return fileError("special_bit_stability_failed", "특수 권한 파일의 안정성을 재확인하지 못했습니다.", stableErr)
			}
			if !stable {
				unknownCandidates++
				incompleteReasons = append(incompleteReasons, "candidate_changed_during_inspection")
				finding.State = "unknown"
				finding.Reason = "candidate_changed_after_inspection"
			} else if contentSHA != approval.ContentSHA256 {
				definiteFailures++
				finding.State = "fail"
				finding.Reason = "approved_content_baseline_mismatch"
			} else {
				verifiedCandidates++
				finding.State = "approved"
				finding.Reason = "institution_mode_and_content_baseline"
			}
			findings = append(findings, finding)
			continue
		}
		if policySet {
			stable, stableErr := confirmMetadataStable(environment.Files, candidate, metadata)
			if stableErr != nil {
				return fileError("special_bit_stability_failed", "특수 권한 파일의 안정성을 재확인하지 못했습니다.", stableErr)
			}
			if stable {
				definiteFailures++
				finding.State, finding.Reason = classifyUnapprovedSpecialBitCandidate(true, false)
			} else {
				unknownCandidates++
				incompleteReasons = append(incompleteReasons, "candidate_changed_during_inspection")
				finding.State = "unknown"
				finding.Reason = "candidate_changed_after_inspection"
			}
			findings = append(findings, finding)
			continue
		}
		if !environment.Commands.Available("rpm") {
			unknownCandidates++
			incompleteReasons = append(incompleteReasons, "rpm_unavailable")
			finding.State = "unknown"
			finding.Reason = "rpm_unavailable_and_not_approved"
			findings = append(findings, finding)
			continue
		}

		ownership, ownerErr := inspectRPMOwnership(ctx, environment, candidate)
		if ownerErr != nil {
			return fileError("rpm_ownership_failed", "특수 권한 파일의 RPM 소유 정보를 확인하지 못했습니다.", ownerErr)
		}
		if ownership.Evidence.Kind != "" {
			rpmEvidenceTotal++
			if rpmEvidenceTotal <= 128 {
				evidence = append(evidence, ownership.Evidence)
			}
		}
		if !ownership.Complete {
			unknownCandidates++
			incompleteReasons = append(incompleteReasons, "rpm_evidence_incomplete")
			finding.State = "unknown"
			finding.Reason = "rpm_ownership_incomplete"
			findings = append(findings, finding)
			continue
		}
		if !ownership.Owned {
			if policySet {
				definiteFailures++
				finding.State = "fail"
				finding.Reason = "unowned_file_outside_complete_baseline"
			} else {
				unknownCandidates++
				finding.State = "unknown"
				finding.Reason = "unowned_file_requires_approval"
			}
			findings = append(findings, finding)
			continue
		}
		finding.Package = ownership.NEVRA
		if ownership.SignaturePresent {
			finding.Signature = ownership.SignatureSHA256
		}
		inspection, cached := packageCache[ownership.NEVRA]
		if !cached {
			inspection, err = inspectRPMPackage(ctx, environment, ownership.NEVRA)
			if err != nil {
				return fileError("rpm_verification_failed", "RPM 설치 파일 기준을 확인하지 못했습니다.", err)
			}
			packageCache[ownership.NEVRA] = inspection
			for _, item := range []model.Evidence{inspection.ModeEvidence, inspection.VerifyEvidence} {
				if item.Kind == "" {
					continue
				}
				rpmEvidenceTotal++
				if rpmEvidenceTotal <= 128 {
					evidence = append(evidence, item)
				}
			}
		}
		if !inspection.Complete {
			unknownCandidates++
			incompleteReasons = append(incompleteReasons, "rpm_evidence_incomplete")
			finding.State = "unknown"
			finding.Reason = "rpm_package_verification_incomplete"
			findings = append(findings, finding)
			continue
		}
		expectedFile, exists := inspection.ExpectedFiles[candidate]
		if !exists {
			unknownCandidates++
			incompleteReasons = append(incompleteReasons, "rpm_file_record_missing")
			finding.State = "unknown"
			finding.Reason = "rpm_file_mode_record_missing"
			findings = append(findings, finding)
			continue
		}
		if expectedFile.Mode&0o6000 != actualSpecial&0o6000 {
			definiteFailures++
			finding.State = "fail"
			finding.Reason = "special_bits_differ_from_package_metadata"
			findings = append(findings, finding)
			continue
		}
		if expectedFile.VerifyFlags&0o1 == 0 {
			unknownCandidates++
			finding.State = "unknown"
			finding.Reason = "package_digest_verification_disabled"
			findings = append(findings, finding)
			continue
		}
		_, modified := inspection.ModifiedPaths[candidate]
		if modified {
			definiteFailures++
			finding.State = "fail"
			finding.Reason = "rpm_verification_reported_file_change"
			findings = append(findings, finding)
			continue
		}
		if !ownership.SignaturePresent {
			unknownCandidates++
			finding.State = "unknown"
			finding.Reason = "package_signature_not_available"
			findings = append(findings, finding)
			continue
		}
		stable, stableErr := confirmMetadataStable(environment.Files, candidate, metadata)
		if stableErr != nil {
			return fileError("special_bit_stability_failed", "특수 권한 파일의 안정성을 재확인하지 못했습니다.", stableErr)
		}
		if !stable {
			unknownCandidates++
			incompleteReasons = append(incompleteReasons, "candidate_changed_during_inspection")
			finding.State = "unknown"
			finding.Reason = "candidate_changed_after_inspection"
		} else {
			unknownCandidates++
			finding.State, finding.Reason = classifyUnapprovedSpecialBitCandidate(false, true)
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
	evidence = append(evidence, support.FactEvidence("special-bit-inventory-summary", map[string]any{
		"approved_policy_count":       len(approved),
		"approved_policy_set":         policySet,
		"candidate_count":             len(specialPaths),
		"candidate_set_sha256":        pathSetDigest(specialPaths),
		"definite_failure_count":      definiteFailures,
		"detailed_candidates":         specialBitFindingFacts(findings, maxEvidenceFileFindings),
		"detailed_candidate_count":    len(findings),
		"incomplete_reasons":          incompleteReasons,
		"rpm_evidence_record_count":   rpmEvidenceTotal,
		"sticky_directory_count":      len(stickyPaths),
		"sticky_directory_set_sha256": pathSetDigest(stickyPaths),
		"unknown_candidate_count":     unknownCandidates + len(specialPaths) - limit,
		"verified_candidate_count":    verifiedCandidates,
	}))

	if definiteFailures > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "RPM 설치 기준과 다르거나 완전한 승인 목록 밖에 있는 특수 권한 파일이 확인되었습니다.",
			Expected: expected,
			Observed: fmt.Sprintf("확정 위반 %d건, 확정 불가 %d건", definiteFailures, unknownCandidates+len(specialPaths)-limit),
			Evidence: evidence,
		}
	}
	if len(incompleteReasons) > 0 || unknownCandidates > 0 || limit < len(specialPaths) {
		reason := model.UnknownInsufficientEvidence
		if containsAny(incompleteReasons, "mount_namespace_unknown", "non_host_mount_namespace", "unsupported_or_ambiguous_filesystem", "mount_membership_or_device_ambiguous", "rpm_unavailable") {
			reason = model.UnknownUnsupportedConfiguration
		} else if unknownCandidates > 0 && len(incompleteReasons) == 0 {
			reason = model.UnknownManualVerification
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       "일부 특수 권한 파일 또는 파일 시스템 검색 범위를 결정적으로 검증할 수 없습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("후보 %d건, 확정 %d건, 확정 불가 %d건", len(specialPaths), verifiedCandidates, unknownCandidates+len(specialPaths)-limit),
			Evidence:      evidence,
		}
	}
	if len(before.Eligible) == 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "SUID/SGID 파일을 점검할 로컬 영속 파일 시스템 범위를 확인할 수 없습니다.",
			Expected:      expected,
			Observed:      "대상 마운트 없음",
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 SUID/SGID 일반 파일이 기관이 승인한 모드·내용 해시와 일치하거나 대상 파일이 없습니다.",
		Expected: expected,
		Observed: fmt.Sprintf("SUID/SGID 파일 %d개와 sticky 디렉터리 %d개를 확인했습니다.", len(specialPaths), len(stickyPaths)),
		Evidence: evidence,
	}
}

func classifyUnapprovedSpecialBitCandidate(completeApprovalPolicy, packageIntegrityVerified bool) (string, string) {
	if completeApprovalPolicy {
		return "fail", "file_outside_complete_institution_baseline"
	}
	if packageIntegrityVerified {
		return "unknown", "package_integrity_verified_manual_approval_required"
	}
	return "unknown", "institution_approval_required"
}

func specialBitApprovalParameter(parameters map[string]any) (map[string]specialBitApproval, bool, error) {
	const key = "approved_special_bit_files"
	values, exists, err := support.StringSliceParameter(parameters, key)
	if err != nil {
		return nil, exists, err
	}
	if !exists {
		return nil, false, nil
	}
	result := make(map[string]specialBitApproval, len(values))
	for index, value := range values {
		parts := strings.Split(value, "|")
		if len(parts) != 3 {
			return nil, true, fmt.Errorf("parameter %s item %d must use path|sha256|mode", key, index)
		}
		filePath := parts[0]
		digest := parts[1]
		modeText := parts[2]
		if err := validateAbsoluteSystemPath(filePath); err != nil {
			return nil, true, fmt.Errorf("parameter %s item %d has an invalid path", key, index)
		}
		if len(digest) != 64 || digest != strings.ToLower(digest) {
			return nil, true, fmt.Errorf("parameter %s item %d has an invalid SHA-256", key, index)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, true, fmt.Errorf("parameter %s item %d has an invalid SHA-256", key, index)
		}
		if len(modeText) != 4 {
			return nil, true, fmt.Errorf("parameter %s item %d has an invalid mode", key, index)
		}
		mode, err := strconv.ParseUint(modeText, 8, 16)
		if err != nil || mode > 0o7777 || fmt.Sprintf("%04o", mode) != modeText || mode&0o6000 == 0 {
			return nil, true, fmt.Errorf("parameter %s item %d has an invalid special-bit mode", key, index)
		}
		if _, duplicate := result[filePath]; duplicate {
			return nil, true, fmt.Errorf("parameter %s contains a duplicate path", key)
		}
		result[filePath] = specialBitApproval{ContentSHA256: digest, Mode: mode}
	}
	return result, true, nil
}

func hashSpecialBitFile(ctx context.Context, environment evaluator.Environment, candidate string) (string, model.Evidence, error) {
	if !environment.Commands.Available("sha256sum") {
		return "", model.Evidence{}, fmt.Errorf("sha256sum is unavailable")
	}
	spec := executor.Spec{
		Name:      "sha256sum",
		Arguments: []string{"--zero", "--", candidate},
		Timeout:   2 * time.Minute,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return "", model.Evidence{}, fmt.Errorf("run sha256sum: %w", err)
	}
	evidence := privateCommandSummary("special-bit-content-hash-command", spec, result)
	if result.ExitCode != 0 || result.Truncated || len(result.Stderr) > 0 {
		return "", evidence, fmt.Errorf("sha256sum exit=%d truncated=%t diagnostics=%t", result.ExitCode, result.Truncated, len(result.Stderr) > 0)
	}
	if len(result.Stdout) != 67+len(candidate) || result.Stdout[len(result.Stdout)-1] != 0 || string(result.Stdout[64:66]) != "  " || string(result.Stdout[66:len(result.Stdout)-1]) != candidate {
		return "", evidence, fmt.Errorf("sha256sum output format is invalid")
	}
	digest := string(result.Stdout[:64])
	if digest != strings.ToLower(digest) {
		return "", evidence, fmt.Errorf("sha256sum output digest is invalid")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", evidence, fmt.Errorf("sha256sum output digest is invalid")
	}
	return digest, evidence, nil
}

func posixMode(mode os.FileMode) uint64 {
	value := uint64(mode.Perm())
	value |= posixSpecialBits(mode)
	return value
}

func posixSpecialBits(mode os.FileMode) uint64 {
	var value uint64
	if mode&os.ModeSetuid != 0 {
		value |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		value |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		value |= 0o1000
	}
	return value
}

func specialBitFindingFacts(findings []specialBitFinding, limit int) []map[string]any {
	if len(findings) > limit {
		findings = findings[:limit]
	}
	facts := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		fact := map[string]any{
			"filesystem_type": finding.FSType,
			"mode":            finding.Mode,
			"no_suid_mount":   finding.NoSUID,
			"path_sha256":     finding.PathSHA256,
			"reason":          finding.Reason,
			"state":           finding.State,
		}
		if finding.ContentSHA != "" {
			fact["content_sha256"] = finding.ContentSHA
		}
		if finding.Package != "" {
			fact["package"] = finding.Package
		}
		if finding.Signature != "" {
			fact["package_signature_sha256"] = finding.Signature
		}
		facts = append(facts, fact)
	}
	return facts
}

func containsAny(values []string, candidates ...string) bool {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	for _, candidate := range candidates {
		if _, exists := set[candidate]; exists {
			return true
		}
	}
	return false
}
