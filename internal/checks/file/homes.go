package filecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorUserEnvironmentPermissions = "unix.file.user_environment_permissions"
	EvaluatorHomePermissions            = "unix.file.home_permissions"
	EvaluatorHomeExists                 = "unix.file.home_exists"
)

var userEnvironmentCandidates = []string{
	".profile",
	".bash_profile",
	".bash_login",
	".bashrc",
	".bash_logout",
	".kshrc",
	".mkshrc",
	".cshrc",
	".tcshrc",
	".login",
	".logout",
	".zshenv",
	".zshenv.zwc",
	".zprofile",
	".zprofile.zwc",
	".zshrc",
	".zshrc.zwc",
	".zlogin",
	".zlogin.zwc",
	".zlogout",
	".zlogout.zwc",
	".exrc",
	".netrc",
	".config/fish/config.fish",
	".config/fish/conf.d",
}

const fishUserConfigurationDirectory = ".config/fish/conf.d"

const maximumFishUserConfigurationFragments = 1_024

const (
	maximumUserEnvironmentCandidates    = 16_384
	maximumUserEnvironmentEvidenceBytes = 64 << 20
	maximumUserEnvironmentEvidenceItems = 131_072
)

type inspectionEvidenceBudget struct {
	byteLimit int
	bytesUsed int
	itemLimit int
	itemsUsed int
	exhausted bool
}

func newInspectionEvidenceBudget(byteLimit, itemLimit int) *inspectionEvidenceBudget {
	if byteLimit < 0 {
		byteLimit = 0
	}
	if itemLimit < 0 {
		itemLimit = 0
	}
	return &inspectionEvidenceBudget{byteLimit: byteLimit, itemLimit: itemLimit}
}

func (budget *inspectionEvidenceBudget) append(
	target *[]model.Evidence,
	items ...model.Evidence,
) bool {
	if budget == nil {
		*target = append(*target, items...)
		return true
	}
	for _, item := range items {
		encoded, err := json.Marshal(item)
		encodedBytes := len(encoded) + 1
		if err != nil ||
			budget.itemsUsed >= budget.itemLimit ||
			encodedBytes > budget.byteLimit-budget.bytesUsed {
			budget.exhausted = true
			return false
		}
		budget.bytesUsed += encodedBytes
		budget.itemsUsed++
		*target = append(*target, item)
	}
	return true
}

func userEnvironmentBudgetEvidence(
	pathBudget *pathInspectionBudget,
	evidenceBudget *inspectionEvidenceBudget,
	candidatesCompleted int,
	phase string,
) model.Evidence {
	pathRemaining := 0
	pathLimit := 0
	pathExhausted := false
	pathExhaustionReason := ""
	if pathBudget != nil {
		pathLimit = pathBudget.limit
		pathRemaining = pathBudget.remaining
		pathExhausted = pathBudget.isExhausted()
		pathExhaustionReason = pathBudget.reason
	}
	evidenceUsed := 0
	evidenceLimit := 0
	evidenceItems := 0
	evidenceItemLimit := 0
	evidenceExhausted := false
	if evidenceBudget != nil {
		evidenceUsed = evidenceBudget.bytesUsed
		evidenceLimit = evidenceBudget.byteLimit
		evidenceItems = evidenceBudget.itemsUsed
		evidenceItemLimit = evidenceBudget.itemLimit
		evidenceExhausted = evidenceBudget.exhausted
	}
	return support.FactEvidence("user-environment-resource-budget", map[string]any{
		"path_operation_limit":      pathLimit,
		"path_operations_used":      pathLimit - pathRemaining,
		"path_budget_exhausted":     pathExhausted,
		"path_exhaustion_reason":    pathExhaustionReason,
		"evidence_byte_limit":       evidenceLimit,
		"evidence_bytes_used":       evidenceUsed,
		"evidence_item_limit":       evidenceItemLimit,
		"evidence_items_used":       evidenceItems,
		"evidence_budget_exhausted": evidenceExhausted,
		"candidates_completed":      candidatesCompleted,
		"phase":                     phase,
	})
}

type userEnvironmentPathState uint8

const (
	userEnvironmentPathMissing userEnvironmentPathState = iota
	userEnvironmentPathBlocked
	userEnvironmentPathPresent
)

type userEnvironmentPathSnapshot struct {
	Candidate        string
	State            userEnvironmentPathState
	ResolvedPath     string
	ResolutionDigest string
	DirectoryDigest  string
	Metadata         system.FileMetadata
	ACLDigest        string
}

func evaluateUserEnvironmentPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	return evaluateUserEnvironmentPermissionsWithLimits(
		ctx,
		environment,
		maximumUserEnvironmentPathOperations,
		maximumUserEnvironmentEvidenceBytes,
		maximumUserEnvironmentEvidenceItems,
	)
}

func evaluateUserEnvironmentPermissionsWithLimits(
	ctx context.Context,
	environment evaluator.Environment,
	pathOperationLimit int,
	evidenceByteLimit int,
	evidenceItemLimit int,
) evaluator.Outcome {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return fileError("effective_passwd_failed", "실효 계정 목록을 확인하지 못했습니다.", err)
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		if isHomeMountInventoryLimit(err) {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownInsufficientEvidence,
				Summary:       "마운트 목록이 안전한 점검 한도를 초과해 환경변수 파일의 파일 시스템을 확정할 수 없습니다.",
				Expected:      "홈 환경변수 파일은 root 또는 해당 계정 소유이고 소유자 외 쓰기 권한이 없어야 합니다.",
				Observed:      fmt.Sprintf("마운트 항목 상한 %d개 초과", maximumHomeMountEntries),
				Evidence: []model.Evidence{
					accountEvidence,
					mountEvidence,
					homeMountInventoryLimitEvidence(err),
				},
			}
		}
		return fileError("home_mounts_failed", "홈 디렉터리의 파일 시스템 유형을 확인하지 못했습니다.", err)
	}
	evidence := make([]model.Evidence, 0)
	evidenceBudget := newInspectionEvidenceBudget(evidenceByteLimit, evidenceItemLimit)
	if !evidenceBudget.append(&evidence, accountEvidence, mountEvidence) {
		evidence = append(evidence, userEnvironmentBudgetEvidence(nil, evidenceBudget, 0, "inventory"))
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "환경변수 파일 점검 증적이 안전한 보존 한도를 초과했습니다.",
			Expected:      "홈 환경변수 파일은 root 또는 해당 계정 소유이고 소유자 외 쓰기 권한이 없어야 합니다.",
			Observed:      "증적 보존 한도 초과",
			Evidence:      evidence,
		}
	}
	grouped := groupAccountsByHome(accounts)
	if userEnvironmentCandidateLimitExceeded(len(grouped)) {
		limitEvidence := support.FactEvidence("user-environment-candidate-limit", map[string]any{
			"home_count":          len(grouped),
			"candidates_per_home": len(userEnvironmentCandidates),
			"candidate_limit":     maximumUserEnvironmentCandidates,
			"limit_exceeded":      true,
		})
		if !evidenceBudget.append(&evidence, limitEvidence) {
			evidence = append(evidence, userEnvironmentBudgetEvidence(nil, evidenceBudget, 0, "candidate_inventory"))
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "홈 환경변수 파일 후보가 안전한 점검 한도를 초과했습니다.",
			Expected:      "홈 환경변수 파일은 root 또는 해당 계정 소유이고 소유자 외 쓰기 권한이 없어야 합니다.",
			Observed:      fmt.Sprintf("고유 홈 %d개, 후보 상한 %d개", len(grouped), maximumUserEnvironmentCandidates),
			Evidence:      evidence,
		}
	}
	violations := make([]pathFinding, 0)
	unknowns := make([]pathFinding, 0)
	snapshots := make([]userEnvironmentPathSnapshot, 0, len(grouped)*len(userEnvironmentCandidates))
	checked := 0
	aclUnavailable := false
	fishConfigurationPathUnknown := false
	pathBudget := newPathInspectionBudget(pathOperationLimit)
	pathPolicy := localMountPathInspectionPolicy(mounts)
	candidatesCompleted := 0
	resourceLimitExceeded := false

scanHomes:
	for _, home := range sortedHomes(grouped) {
		homeAccounts := grouped[home]
		accountsLabel := accountNames(homeAccounts)
		if err := validateAbsoluteSystemPath(home); err != nil {
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: "절대 홈 경로가 아님"})
			continue
		}
		kind, mount, found := mounts.classify(home)
		if !found {
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: "포함 마운트를 확인할 수 없음"})
			continue
		}
		if kind != homeMountLocal {
			reason := fmt.Sprintf("%s 홈 정책 미확인(%s:%s)", kind, mount.Target, mount.FSType)
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: reason})
			continue
		}
		if hasConfiguredFishShell(homeAccounts) {
			fishConfigurationPathUnknown = true
			unknowns = append(unknowns, pathFinding{
				Account: accountsLabel,
				Path:    "fish 사용자 설정 경로",
				Reason:  "XDG_CONFIG_HOME 재정의 여부를 정적으로 확정할 수 없음",
			})
		}

		homeCandidates := append([]string(nil), userEnvironmentCandidates...)
		for candidateIndex := 0; candidateIndex < len(homeCandidates); candidateIndex++ {
			name := homeCandidates[candidateIndex]
			if candidatesCompleted >= maximumUserEnvironmentCandidates {
				resourceLimitExceeded = true
				unknowns = append(unknowns, pathFinding{
					Account: accountsLabel,
					Path:    home,
					Reason:  "환경 파일 후보가 안전한 점검 한도를 초과함",
				})
				break scanHomes
			}
			candidate, err := fixedRelativeSystemPath(home, name)
			if err != nil {
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: "환경 파일 절대 경로 생성 실패"})
				break
			}
			inspected, err := inspectPathFollowingSymlinksWithPolicy(
				environment.Files,
				candidate,
				pathPolicy,
				pathBudget,
			)
			if err != nil {
				if isUserEnvironmentPathUnstable(err) {
					unknowns = append(unknowns, pathFinding{
						Account: accountsLabel,
						Path:    candidate,
						Reason:  "환경 파일 경로를 점검 중 안정적으로 다시 열 수 없음",
					})
					continue
				}
				return fileError("environment_file_stat_failed", "환경변수 파일의 유형과 소유자를 확인하지 못했습니다.", fmt.Errorf("%s: %w", candidate, err))
			}
			if !evidenceBudget.append(&evidence, inspected.Evidence...) {
				resourceLimitExceeded = true
				unknowns = append(unknowns, pathFinding{
					Account: accountsLabel,
					Path:    candidate,
					Reason:  "점검 증적 보존 한도 초과",
				})
				break scanHomes
			}
			candidatesCompleted++
			if inspected.Unknown != "" {
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: candidate, Reason: inspected.Unknown})
				if pathBudget.isExhausted() {
					resourceLimitExceeded = true
					break scanHomes
				}
				continue
			}
			resolvedPath := inspected.ResolvedPath
			if resolvedPath == "" {
				resolvedPath = candidate
			}
			resolvedKind, resolvedMount, resolvedFound := mounts.classify(resolvedPath)
			if !resolvedFound {
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: candidate, Reason: "심볼릭 링크 대상의 포함 마운트를 확인할 수 없음"})
				continue
			}
			if resolvedKind != homeMountLocal {
				reason := fmt.Sprintf("심볼릭 링크 대상의 %s 정책 미확인(%s:%s)", resolvedKind, resolvedMount.Target, resolvedMount.FSType)
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: candidate, Reason: reason})
				continue
			}
			snapshot, snapshotOK := newUserEnvironmentPathSnapshot(candidate, inspected, "")
			if !snapshotOK {
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: candidate, Reason: "경로 해석 스냅샷을 고정할 수 없음"})
				continue
			}
			if !inspected.Exists && inspected.TerminalSymlink {
				unknowns = append(unknowns, pathFinding{
					Account: accountsLabel,
					Path:    candidate,
					Reason:  "환경 파일 심볼릭 링크의 대상이 없음",
				})
				continue
			}
			if !inspected.Exists || snapshot.State == userEnvironmentPathBlocked {
				snapshots = append(snapshots, snapshot)
				continue
			}
			metadata := inspected.Metadata
			if name == fishUserConfigurationDirectory {
				if metadata.FileType != "directory" {
					snapshot.State = userEnvironmentPathBlocked
					snapshots = append(snapshots, snapshot)
					continue
				}
				fragments, directoryDigest, directoryEvidence, directoryUnknown, directoryErr :=
					collectFishUserConfigurationFragments(
						environment.Files,
						candidate,
						metadata,
						pathBudget,
					)
				if directoryErr != nil {
					return fileError(
						"fish_environment_directory_failed",
						"fish 사용자 구성 조각을 확인하지 못했습니다.",
						fmt.Errorf("%s: %w", candidate, directoryErr),
					)
				}
				if strings.TrimSpace(directoryEvidence.Source) != "" &&
					!evidenceBudget.append(&evidence, directoryEvidence) {
					resourceLimitExceeded = true
					unknowns = append(unknowns, pathFinding{
						Account: accountsLabel,
						Path:    candidate,
						Reason:  "점검 증적 보존 한도 초과",
					})
					break scanHomes
				}
				if directoryUnknown != "" {
					unknowns = append(unknowns, pathFinding{
						Account: accountsLabel,
						Path:    candidate,
						Reason:  directoryUnknown,
					})
					if pathBudget.isExhausted() {
						resourceLimitExceeded = true
						break scanHomes
					}
					continue
				}
				snapshot.DirectoryDigest = directoryDigest
				snapshots = append(snapshots, snapshot)
				for _, fragment := range fragments {
					homeCandidates = append(
						homeCandidates,
						path.Join(fishUserConfigurationDirectory, fragment),
					)
				}
				continue
			}
			if metadata.FileType != "regular" {
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: candidate, Reason: "일반 파일이 아님"})
				continue
			}
			if metadata.UID < 0 {
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: candidate, Reason: "소유자 UID 확인 불가"})
				continue
			}

			reasons := make([]string, 0, 3)
			if !userEnvironmentOwnerAllowed(metadata.UID, homeAccounts) {
				reasons = append(reasons, fmt.Sprintf("소유자 UID %d가 root 또는 공유 홈의 모든 계정 UID와 일치하지 않음", metadata.UID))
			}
			if extraWrite := metadata.Mode.Perm() & 0o022; extraWrite != 0 {
				reasons = append(reasons, fmt.Sprintf("비소유자 쓰기 비트 %04o", extraWrite))
			}
			aclViolations, aclEvidence, aclDigest, err := inspectNonOwnerACLSnapshot(
				ctx,
				environment,
				metadata,
				os.FileMode(0o2),
				true,
			)
			if strings.TrimSpace(aclEvidence.Source) != "" {
				if !evidenceBudget.append(&evidence, aclEvidence) {
					resourceLimitExceeded = true
					unknowns = append(unknowns, pathFinding{
						Account: accountsLabel,
						Path:    candidate,
						Reason:  "점검 증적 보존 한도 초과",
					})
					if len(reasons) > 0 {
						violations = append(violations, pathFinding{
							Account: accountsLabel,
							Path:    candidate,
							Reason:  strings.Join(reasons, ", "),
						})
					}
					break scanHomes
				}
			}
			if err != nil {
				if support.IsACLToolUnavailable(err) {
					aclUnavailable = true
					unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: candidate, Reason: support.ACLInspectionUnavailableReason})
					if len(reasons) > 0 {
						violations = append(violations, pathFinding{Account: accountsLabel, Path: candidate, Reason: strings.Join(reasons, ", ")})
					}
					continue
				}
				if isUserEnvironmentPathUnstable(err) {
					unknowns = append(unknowns, pathFinding{
						Account: accountsLabel,
						Path:    candidate,
						Reason:  "ACL 수집 중 환경 파일 대상을 안정적으로 다시 열 수 없음",
					})
					if len(reasons) > 0 {
						violations = append(violations, pathFinding{
							Account: accountsLabel,
							Path:    candidate,
							Reason:  strings.Join(reasons, ", "),
						})
					}
					continue
				}
				return fileError("environment_file_acl_failed", "환경변수 파일의 ACL을 확인하지 못했습니다.", fmt.Errorf("%s: %w", candidate, err))
			}
			reasons = append(reasons, aclViolations...)
			snapshot.ACLDigest = aclDigest
			snapshots = append(snapshots, snapshot)
			checked++
			if len(reasons) > 0 {
				violations = append(violations, pathFinding{Account: accountsLabel, Path: candidate, Reason: strings.Join(reasons, ", ")})
			}
		}
	}

	summaryEvidence := findingEvidence("user-environment-permissions-summary", checked, violations, unknowns)
	if !evidenceBudget.append(&evidence, summaryEvidence) {
		resourceLimitExceeded = true
	}
	if resourceLimitExceeded {
		evidence = append(evidence, userEnvironmentBudgetEvidence(pathBudget, evidenceBudget, candidatesCompleted, "initial_scan"))
	}
	expected := "홈 환경변수 파일은 root 또는 해당 계정 소유이고 소유자 외 쓰기 권한이 없어야 합니다."
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "홈 환경변수 파일의 소유자 또는 쓰기 권한이 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: findingsObserved(violations, unknowns),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		reason := model.UnknownAmbiguousResult
		summary := "원격·불명확 마운트, 지원하지 않는 파일 유형 또는 불안정한 경로가 있어 환경변수 파일 권한을 확정할 수 없습니다."
		if resourceLimitExceeded {
			reason = model.UnknownInsufficientEvidence
			summary = "환경변수 파일 점검의 안전한 작업량 또는 증적 보존 한도를 초과했습니다."
		} else if aclUnavailable {
			reason = model.UnknownUnsupportedConfiguration
			summary = "POSIX ACL을 확인할 수 있는 수집 방법이 없어 환경변수 파일 권한을 확정할 수 없습니다."
		} else if fishConfigurationPathUnknown {
			reason = model.UnknownUnsupportedConfiguration
			summary = "fish의 XDG_CONFIG_HOME 재정의 여부를 정적으로 확정할 수 없어 모든 사용자 설정 경로를 확인할 수 없습니다."
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       summary,
			Expected:      expected,
			Observed:      findingsObserved(nil, unknowns),
			Evidence:      evidence,
		}
	}
	revalidationEvidence, stable, err := revalidateUserEnvironmentSnapshot(
		ctx,
		environment,
		accounts,
		mounts,
		snapshots,
		pathBudget,
		evidenceBudget,
	)
	evidence = append(evidence, revalidationEvidence...)
	if err != nil {
		outcome := fileError(
			"environment_snapshot_revalidation_failed",
			"환경변수 파일 점검의 최종 상태를 재확인하지 못했습니다.",
			err,
		)
		outcome.Evidence = evidence
		return outcome
	}
	if !stable {
		reason := model.UnknownAmbiguousResult
		summary := "점검 중 계정, 마운트, 경로 또는 ACL 상태가 변경되어 환경변수 파일 권한을 확정할 수 없습니다."
		observed := "최종 환경변수 파일 스냅샷 변경 감지"
		if pathBudget.isExhausted() || evidenceBudget.exhausted {
			reason = model.UnknownInsufficientEvidence
			summary = "환경변수 파일 최종 재검증의 안전한 작업량 또는 증적 보존 한도를 초과했습니다."
			observed = "최종 재검증 자원 한도 초과"
			evidence = append(evidence, userEnvironmentBudgetEvidence(pathBudget, evidenceBudget, candidatesCompleted, "final_revalidation"))
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       summary,
			Expected:      expected,
			Observed:      observed,
			Evidence:      evidence,
		}
	}
	if checked == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "점검할 홈 환경변수 파일이 없습니다.",
			Expected: expected,
			Observed: "대상 파일 없음",
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "홈 환경변수 파일의 소유자와 쓰기 권한이 기준을 충족합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("환경변수 파일 %d개 확인", checked),
		Evidence: evidence,
	}
}

func userEnvironmentCandidateLimitExceeded(homeCount int) bool {
	return homeCount < 0 ||
		len(userEnvironmentCandidates) == 0 ||
		homeCount > maximumUserEnvironmentCandidates/len(userEnvironmentCandidates)
}

func newUserEnvironmentPathSnapshot(
	candidate string,
	inspected inspectedPath,
	aclDigest string,
) (userEnvironmentPathSnapshot, bool) {
	resolvedPath := inspected.ResolvedPath
	if resolvedPath == "" {
		resolvedPath = candidate
	}
	resolutionDigest, resolutionKnown := inspectedPathResolutionDigest(inspected)
	if !resolutionKnown {
		return userEnvironmentPathSnapshot{}, false
	}
	state := userEnvironmentPathPresent
	switch {
	case !inspected.Exists:
		state = userEnvironmentPathMissing
	case userEnvironmentPathBlockedByNonDirectory(candidate, inspected):
		state = userEnvironmentPathBlocked
	}
	return userEnvironmentPathSnapshot{
		Candidate:        candidate,
		State:            state,
		ResolvedPath:     resolvedPath,
		ResolutionDigest: resolutionDigest,
		Metadata:         inspected.Metadata,
		ACLDigest:        aclDigest,
	}, true
}

func collectFishUserConfigurationFragments(
	files system.Reader,
	directory string,
	expected system.FileMetadata,
	pathBudget *pathInspectionBudget,
) ([]string, string, model.Evidence, string, error) {
	reader, ok := files.(system.BoundedDirectorySnapshotReader)
	if !ok {
		return nil, "", model.Evidence{},
			"fish conf.d 구성 조각을 안정된 디렉터리 스냅샷으로 열거할 수 없습니다.",
			nil
	}
	if !pathBudget.consume() {
		return nil, "", model.Evidence{},
			"경로 검사 작업량이 안전한 상한을 초과했습니다.",
			nil
	}
	entries, directoryMetadata, truncated, err := reader.ReadDirBoundedSnapshot(
		directory,
		maximumFishUserConfigurationFragments,
		&expected,
	)
	if err != nil {
		if isUserEnvironmentPathUnstable(err) {
			return nil, "", model.Evidence{},
				"fish conf.d 구성 조각 디렉터리가 점검 중 변경되었거나 안정적으로 다시 열리지 않습니다.",
				nil
		}
		return nil, "", model.Evidence{}, "", err
	}
	names := make([]string, 0, len(entries))
	unsafeDigests := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".fish") {
			continue
		}
		if !safeConfiguredHomePathText(name) ||
			strings.Contains(name, "/") ||
			name == "." ||
			name == ".." {
			unsafeDigests = append(unsafeDigests, pathDigest(name))
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	sort.Strings(unsafeDigests)
	digest := pathSetDigest(names)
	evidence := support.FactEvidence("fish-user-configuration-fragments", map[string]any{
		"directory":                directory,
		"fragment_count":           len(names),
		"fragment_set_sha256":      digest,
		"entry_limit":              maximumFishUserConfigurationFragments,
		"entries_truncated":        truncated,
		"unsafe_name_count":        len(unsafeDigests),
		"unsafe_name_set_sha256":   pathSetDigest(unsafeDigests),
		"unsafe_names_not_exposed": true,
		"directory_device":         directoryMetadata.Device,
		"directory_inode":          directoryMetadata.Inode,
	})
	switch {
	case truncated:
		pathBudget.exhausted = true
		pathBudget.reason = "directory_entries"
		return nil, digest, evidence,
			fmt.Sprintf("fish conf.d 구성 조각이 %d개 상한을 초과했습니다.", maximumFishUserConfigurationFragments),
			nil
	case len(unsafeDigests) > 0:
		return nil, digest, evidence,
			"fish conf.d에 안전하게 처리할 수 없는 파일명이 있습니다.",
			nil
	default:
		return names, digest, evidence, "", nil
	}
}

func userEnvironmentPathBlockedByNonDirectory(candidate string, inspected inspectedPath) bool {
	if !inspected.Exists || inspected.Unknown != "" || inspected.Metadata.Path == "" ||
		inspected.ResolvedPath == "" || inspected.Metadata.FileType == "directory" {
		return false
	}
	if inspected.Metadata.Path == candidate || inspected.Metadata.Path == inspected.ResolvedPath {
		return false
	}
	return pathContains(inspected.Metadata.Path, inspected.ResolvedPath)
}

func userEnvironmentOwnerAllowed(ownerUID int, accounts []support.PasswdEntry) bool {
	if ownerUID == 0 {
		return true
	}
	if ownerUID < 0 || len(accounts) == 0 {
		return false
	}
	for _, account := range accounts {
		if uint64(ownerUID) != uint64(account.UID) {
			return false
		}
	}
	return true
}

func hasConfiguredFishShell(accounts []support.PasswdEntry) bool {
	for _, account := range accounts {
		shell := strings.TrimSpace(account.Shell)
		if shell != "" && path.Base(path.Clean(shell)) == "fish" {
			return true
		}
	}
	return false
}

func sameUserEnvironmentPathSnapshot(before, after userEnvironmentPathSnapshot) bool {
	if before.Candidate != after.Candidate ||
		before.State != after.State ||
		before.ResolvedPath != after.ResolvedPath ||
		before.ResolutionDigest != after.ResolutionDigest ||
		before.DirectoryDigest != after.DirectoryDigest {
		return false
	}
	switch before.State {
	case userEnvironmentPathMissing:
		return true
	case userEnvironmentPathBlocked, userEnvironmentPathPresent:
		return samePathSecuritySnapshot(before.Metadata, after.Metadata)
	default:
		return false
	}
}

func revalidateUserEnvironmentSnapshot(
	ctx context.Context,
	environment evaluator.Environment,
	initialAccounts []support.PasswdEntry,
	initialMounts homeMountTable,
	initialPaths []userEnvironmentPathSnapshot,
	pathBudget *pathInspectionBudget,
	evidenceBudget *inspectionEvidenceBudget,
) ([]model.Evidence, bool, error) {
	finalAccounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return nil, false, fmt.Errorf("revalidate effective account inventory: %w", err)
	}
	finalMounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		evidence := make([]model.Evidence, 0, 1)
		evidenceBudget.append(&evidence, accountEvidence)
		if isHomeMountInventoryLimit(err) {
			evidenceBudget.append(&evidence, mountEvidence, homeMountInventoryLimitEvidence(err))
			pathBudget.exhausted = true
			pathBudget.reason = "mount_inventory"
			return evidence, false, nil
		}
		return evidence, false, fmt.Errorf("revalidate mount inventory: %w", err)
	}
	evidence := make([]model.Evidence, 0)
	if !evidenceBudget.append(&evidence, accountEvidence, mountEvidence) {
		return evidence, false, nil
	}
	accountStable := sameHomeAccountInventory(initialAccounts, finalAccounts)
	mountsStable := sameHomeMountInventory(initialMounts, finalMounts)
	pathsStable := true
	changedPaths := 0
	pathPolicy := localMountPathInspectionPolicy(finalMounts)

	for _, initial := range initialPaths {
		current, inspectErr := inspectPathFollowingSymlinksWithPolicy(
			environment.Files,
			initial.Candidate,
			pathPolicy,
			pathBudget,
		)
		if inspectErr != nil {
			if isUserEnvironmentPathUnstable(inspectErr) {
				pathsStable = false
				changedPaths++
				continue
			}
			return evidence, false, fmt.Errorf("revalidate %s: %w", initial.Candidate, inspectErr)
		}
		if !evidenceBudget.append(&evidence, current.Evidence...) {
			pathsStable = false
			changedPaths++
			break
		}
		if current.Unknown != "" {
			pathsStable = false
			changedPaths++
			if pathBudget.isExhausted() {
				break
			}
			continue
		}
		resolvedPath := current.ResolvedPath
		if resolvedPath == "" {
			resolvedPath = initial.Candidate
		}
		resolvedKind, _, resolvedFound := finalMounts.classify(resolvedPath)
		if !resolvedFound || resolvedKind != homeMountLocal {
			pathsStable = false
			changedPaths++
			continue
		}
		currentSnapshot, snapshotOK := newUserEnvironmentPathSnapshot(initial.Candidate, current, "")
		if snapshotOK && initial.DirectoryDigest != "" {
			if current.Metadata.FileType != "directory" {
				pathsStable = false
				changedPaths++
				continue
			}
			_, directoryDigest, directoryEvidence, directoryUnknown, directoryErr :=
				collectFishUserConfigurationFragments(
					environment.Files,
					initial.Candidate,
					current.Metadata,
					pathBudget,
				)
			if directoryErr != nil {
				return evidence, false, fmt.Errorf(
					"revalidate fish configuration directory %s: %w",
					initial.Candidate,
					directoryErr,
				)
			}
			if strings.TrimSpace(directoryEvidence.Source) != "" &&
				!evidenceBudget.append(&evidence, directoryEvidence) {
				pathsStable = false
				changedPaths++
				break
			}
			if directoryUnknown != "" {
				pathsStable = false
				changedPaths++
				if pathBudget.isExhausted() {
					break
				}
				continue
			}
			currentSnapshot.DirectoryDigest = directoryDigest
		}
		if !snapshotOK || !sameUserEnvironmentPathSnapshot(initial, currentSnapshot) {
			pathsStable = false
			changedPaths++
			continue
		}
		if initial.State != userEnvironmentPathPresent {
			continue
		}
		if initial.DirectoryDigest != "" {
			continue
		}
		_, aclEvidence, aclDigest, aclErr := inspectNonOwnerACLSnapshot(
			ctx,
			environment,
			current.Metadata,
			os.FileMode(0o2),
			true,
		)
		if strings.TrimSpace(aclEvidence.Source) != "" {
			if !evidenceBudget.append(&evidence, aclEvidence) {
				pathsStable = false
				changedPaths++
				break
			}
		}
		if aclErr != nil {
			if support.IsACLToolUnavailable(aclErr) ||
				isUserEnvironmentPathUnstable(aclErr) {
				pathsStable = false
				changedPaths++
				continue
			}
			return evidence, false, fmt.Errorf("revalidate ACL %s: %w", initial.Candidate, aclErr)
		}
		if initial.ACLDigest != aclDigest {
			pathsStable = false
			changedPaths++
		}
	}
	stable := accountStable && mountsStable && pathsStable
	summaryEvidence := support.FactEvidence("user-environment-snapshot-revalidation", map[string]any{
		"account_inventory_stable": accountStable,
		"mount_inventory_stable":   mountsStable,
		"path_snapshots_stable":    pathsStable,
		"initial_account_count":    len(initialAccounts),
		"final_account_count":      len(finalAccounts),
		"initial_mount_count":      len(initialMounts.mounts),
		"final_mount_count":        len(finalMounts.mounts),
		"path_snapshot_count":      len(initialPaths),
		"changed_path_count":       changedPaths,
		"all_stable":               stable,
	})
	if !evidenceBudget.append(&evidence, summaryEvidence) {
		stable = false
	}
	return evidence, stable, nil
}

const (
	maximumHomePermissionAccounts              = 65_536
	maximumHomePermissionDirectories           = 16_384
	maximumHomePermissionPathOperationsPerPass = 131_072
	maximumHomePermissionEvidenceBytes         = 32 << 20
	maximumHomePermissionEvidenceItems         = 65_536
)

func evaluateHomePermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	return evaluateHomePermissionsWithLimits(
		ctx,
		environment,
		maximumHomePermissionAccounts,
		maximumHomePermissionDirectories,
		maximumHomePermissionPathOperationsPerPass,
		maximumHomePermissionEvidenceBytes,
		maximumHomePermissionEvidenceItems,
	)
}

func evaluateHomePermissionsWithLimits(
	ctx context.Context,
	environment evaluator.Environment,
	accountLimit int,
	directoryLimit int,
	pathOperationsPerPass int,
	evidenceByteLimit int,
	evidenceItemLimit int,
) evaluator.Outcome {
	expected := "홈 디렉터리는 해당 계정 소유이고 다른 사용자에게 쓰기 권한이 없어야 합니다."
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return fileError("effective_passwd_failed", "실효 계정 목록을 확인하지 못했습니다.", err)
	}
	if accountLimit < 0 {
		accountLimit = 0
	}
	if len(accounts) > accountLimit {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "계정별 홈 권한 점검 대상이 안전한 상한을 초과했습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("계정 %d개, 상한 %d개", len(accounts), accountLimit),
			Evidence: []model.Evidence{
				accountEvidence,
				support.FactEvidence("home-permission-account-limit", map[string]any{
					"account_count":  len(accounts),
					"account_limit":  accountLimit,
					"limit_exceeded": true,
				}),
			},
		}
	}
	grouped := groupAccountsByHome(accounts)
	if directoryLimit < 0 {
		directoryLimit = 0
	}
	if len(grouped) > directoryLimit {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "고유 홈 디렉터리 점검 대상이 안전한 상한을 초과했습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("고유 홈 %d개, 상한 %d개", len(grouped), directoryLimit),
			Evidence: []model.Evidence{
				accountEvidence,
				support.FactEvidence("home-permission-directory-limit", map[string]any{
					"directory_count": len(grouped),
					"directory_limit": directoryLimit,
					"limit_exceeded":  true,
				}),
			},
		}
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		if isHomeMountInventoryLimit(err) {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownInsufficientEvidence,
				Summary:       "마운트 목록이 안전한 점검 한도를 초과해 홈 디렉터리 권한을 확정할 수 없습니다.",
				Expected:      expected,
				Observed:      fmt.Sprintf("마운트 항목 상한 %d개 초과", maximumHomeMountEntries),
				Evidence: []model.Evidence{
					accountEvidence,
					mountEvidence,
					homeMountInventoryLimitEvidence(err),
				},
			}
		}
		return fileError("home_mounts_failed", "홈 디렉터리의 파일 시스템 유형을 확인하지 못했습니다.", err)
	}
	evidence := make([]model.Evidence, 0)
	evidenceBudget := newInspectionEvidenceBudget(evidenceByteLimit, evidenceItemLimit)
	if !evidenceBudget.append(&evidence, accountEvidence, mountEvidence) {
		evidence = append(evidence, homePermissionBudgetEvidence(
			nil,
			evidenceBudget,
			0,
			pathOperationsPerPass,
			"inventory",
		))
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "홈 권한 점검 증적이 안전한 보존 한도를 초과했습니다.",
			Expected:      expected,
			Observed:      "초기 계정 또는 마운트 증적 보존 한도 초과",
			Evidence:      evidence,
		}
	}
	violations := make([]pathFinding, 0)
	unknowns := make([]pathFinding, 0)
	snapshots := make(map[string]userEnvironmentPathSnapshot, len(grouped))
	checked := 0
	aclUnavailable := false
	resourceLimited := false
	pathBudget := newPathInspectionBudget(pathOperationsPerPass)
	pathPolicy := localMountPathInspectionPolicy(mounts)

scanHomePermissions:
	for _, home := range sortedHomes(grouped) {
		homeAccounts := grouped[home]
		if err := validateAbsoluteSystemPath(home); err != nil {
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "절대 홈 경로가 아님"})
			continue
		}
		kind, mount, found := mounts.classify(home)
		if !found {
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "포함 마운트를 확인할 수 없음"})
			continue
		}
		if kind != homeMountLocal {
			reason := fmt.Sprintf("%s 홈 정책 미확인(%s:%s)", kind, mount.Target, mount.FSType)
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: reason})
			continue
		}
		accountsLabel := accountNames(homeAccounts)
		inspected, err := inspectPathWithoutSymlinksWithPolicy(
			environment.Files,
			home,
			pathPolicy,
			pathBudget,
		)
		if err != nil {
			return fileError("home_stat_failed", "홈 디렉터리의 유형과 소유자를 확인하지 못했습니다.", fmt.Errorf("%s: %w", home, err))
		}
		if !evidenceBudget.append(&evidence, inspected.Evidence...) {
			resourceLimited = true
			break scanHomePermissions
		}
		if !inspected.Exists {
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: "홈이 없으며 U-32에서 존재 여부 판정"})
			continue
		}
		if inspected.Unknown != "" {
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: inspected.Unknown})
			if pathBudget.isExhausted() {
				resourceLimited = true
				break scanHomePermissions
			}
			continue
		}
		metadata := inspected.Metadata
		snapshot, snapshotOK := newUserEnvironmentPathSnapshot(home, inspected, "")
		if !snapshotOK || snapshot.State != userEnvironmentPathPresent {
			unknowns = append(unknowns, pathFinding{
				Account: accountsLabel,
				Path:    home,
				Reason:  "홈 경로 해석 스냅샷을 고정할 수 없음",
			})
			continue
		}
		if metadata.FileType != "directory" {
			violations = append(violations, pathFinding{Account: accountsLabel, Path: home, Reason: "디렉터리가 아님"})
			snapshots[home] = snapshot
			continue
		}
		if metadata.UID < 0 {
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: "소유자 UID 확인 불가"})
			continue
		}
		pathViolations := make([]pathFinding, 0, len(homeAccounts)+1)
		for _, account := range homeAccounts {
			if uint64(metadata.UID) != uint64(account.UID) {
				pathViolations = append(pathViolations, pathFinding{
					Account: account.Name,
					Path:    home,
					Reason:  fmt.Sprintf("소유자 UID %d, 계정 UID %d", metadata.UID, account.UID),
				})
			}
		}
		reasons := make([]string, 0, 2)
		if extraWrite := metadata.Mode.Perm() & 0o022; extraWrite != 0 {
			reasons = append(reasons, fmt.Sprintf("비소유자 쓰기 비트 %04o", extraWrite))
		}
		aclViolations, aclEvidence, aclDigest, err := inspectNonOwnerACLSnapshot(
			ctx,
			environment,
			metadata,
			os.FileMode(0o2),
			false,
		)
		if strings.TrimSpace(aclEvidence.Source) != "" {
			if !evidenceBudget.append(&evidence, aclEvidence) {
				resourceLimited = true
				break scanHomePermissions
			}
		}
		if err != nil {
			if support.IsACLToolUnavailable(err) {
				aclUnavailable = true
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: support.ACLInspectionUnavailableReason})
				snapshots[home] = snapshot
				violations = append(violations, pathViolations...)
				if len(reasons) > 0 {
					violations = append(violations, pathFinding{Account: accountsLabel, Path: home, Reason: strings.Join(reasons, ", ")})
				}
				continue
			}
			if isUserEnvironmentPathUnstable(err) {
				unknowns = append(unknowns, pathFinding{
					Account: accountsLabel,
					Path:    home,
					Reason:  "ACL 대상이 점검 중 변경되었거나 안정적으로 다시 열리지 않음",
				})
				continue
			}
			return fileError("home_acl_failed", "홈 디렉터리의 ACL을 확인하지 못했습니다.", fmt.Errorf("%s: %w", home, err))
		}
		snapshot.ACLDigest = aclDigest
		snapshots[home] = snapshot
		violations = append(violations, pathViolations...)
		reasons = append(reasons, aclViolations...)
		checked += len(homeAccounts)
		if len(reasons) > 0 {
			violations = append(violations, pathFinding{Account: accountsLabel, Path: home, Reason: strings.Join(reasons, ", ")})
		}
	}

	if !evidenceBudget.append(&evidence, findingEvidence("home-permissions-summary", checked, violations, unknowns)) {
		resourceLimited = true
	}
	if resourceLimited || pathBudget.isExhausted() || evidenceBudget.exhausted {
		evidence = append(evidence, homePermissionBudgetEvidence(
			pathBudget,
			evidenceBudget,
			len(snapshots),
			pathOperationsPerPass,
			"initial_inspection",
		))
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "홈 권한 점검 작업량 또는 증적이 안전한 상한을 초과했습니다.",
			Expected:      expected,
			Observed:      "전체 홈 권한 상태를 제한 범위 안에서 확인하지 못함",
			Evidence:      evidence,
		}
	}

	revalidationEvidence, accountStable, mountsStable, mountLimited, err := revalidateHomeExistenceSnapshot(
		ctx,
		environment,
		accounts,
		mounts,
	)
	if err != nil {
		outcome := fileError(
			"home_permission_snapshot_revalidation_failed",
			"홈 권한 점검의 최종 계정·마운트 상태를 재확인하지 못했습니다.",
			err,
		)
		outcome.Evidence = evidence
		return outcome
	}
	if !evidenceBudget.append(&evidence, revalidationEvidence...) {
		evidence = append(evidence, homePermissionBudgetEvidence(
			nil,
			evidenceBudget,
			len(snapshots),
			pathOperationsPerPass,
			"inventory_revalidation",
		))
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "최종 계정·마운트 증적이 안전한 보존 한도를 초과했습니다.",
			Expected:      expected,
			Observed:      "최종 inventory 증적 보존 한도 초과",
			Evidence:      evidence,
		}
	}
	if mountLimited {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "최종 마운트 목록이 안전한 점검 한도를 초과해 홈 권한을 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("최종 마운트 항목 상한 %d개 초과", maximumHomeMountEntries),
			Evidence:      evidence,
		}
	}
	if !accountStable || !mountsStable {
		changed := make([]string, 0, 2)
		if !accountStable {
			changed = append(changed, "실효 계정 및 홈 목록")
		}
		if !mountsStable {
			changed = append(changed, "마운트 목록")
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "점검 중 계정 또는 마운트 구성이 변경되어 동일한 상태의 홈 권한을 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      strings.Join(changed, ", ") + " 변경 감지",
			Evidence:      evidence,
		}
	}

	revalidationBudget := newPathInspectionBudget(pathOperationsPerPass)
	pathEvidence, pathsStable, pathResourceLimited, err := revalidateHomePermissionPaths(
		ctx,
		environment,
		mounts,
		snapshots,
		revalidationBudget,
		evidenceBudget,
	)
	evidence = append(evidence, pathEvidence...)
	if err != nil {
		outcome := fileError(
			"home_permission_path_revalidation_failed",
			"홈 권한 점검의 최종 경로·ACL 상태를 재확인하지 못했습니다.",
			err,
		)
		outcome.Evidence = evidence
		return outcome
	}
	if pathResourceLimited {
		evidence = append(evidence, homePermissionBudgetEvidence(
			revalidationBudget,
			evidenceBudget,
			len(snapshots),
			pathOperationsPerPass,
			"path_revalidation",
		))
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "최종 홈 경로·ACL 재검증이 안전한 상한을 초과했습니다.",
			Expected:      expected,
			Observed:      "최종 경로 재검증 작업량 또는 증적 보존 한도 초과",
			Evidence:      evidence,
		}
	}
	if !pathsStable {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "점검 중 홈 경로 또는 ACL이 변경되어 동일한 상태의 권한을 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      "최종 홈 경로 또는 ACL 스냅샷 변경 감지",
			Evidence:      evidence,
		}
	}

	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "홈 디렉터리의 소유자 또는 쓰기 권한이 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: findingsObserved(violations, unknowns),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		reason := model.UnknownAmbiguousResult
		summary := "원격 홈, 누락 홈, 심볼릭 링크 또는 점검 중 변경된 경로가 있어 홈 권한을 확정할 수 없습니다."
		if aclUnavailable {
			reason = model.UnknownUnsupportedConfiguration
			summary = "POSIX ACL을 확인할 수 있는 수집 방법이 없어 홈 디렉터리 권한을 확정할 수 없습니다."
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       summary,
			Expected:      expected,
			Observed:      findingsObserved(nil, unknowns),
			Evidence:      evidence,
		}
	}
	if checked == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "권한을 확인할 적용 가능한 홈 디렉터리가 없습니다.",
			Expected: expected,
			Observed: "대상 홈 없음",
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "홈 디렉터리의 소유자와 쓰기 권한이 기준을 충족합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("계정별 홈 소유권 및 권한 %d건 확인", checked),
		Evidence: evidence,
	}
}

func homePermissionBudgetEvidence(
	pathBudget *pathInspectionBudget,
	evidenceBudget *inspectionEvidenceBudget,
	snapshotCount int,
	pathOperationsPerPass int,
	phase string,
) model.Evidence {
	pathUsed := 0
	pathExhausted := false
	pathReason := ""
	if pathBudget != nil {
		pathUsed = pathBudget.limit - pathBudget.remaining
		pathExhausted = pathBudget.isExhausted()
		pathReason = pathBudget.reason
	}
	evidenceBytes := 0
	evidenceByteLimit := 0
	evidenceItems := 0
	evidenceItemLimit := 0
	evidenceExhausted := false
	if evidenceBudget != nil {
		evidenceBytes = evidenceBudget.bytesUsed
		evidenceByteLimit = evidenceBudget.byteLimit
		evidenceItems = evidenceBudget.itemsUsed
		evidenceItemLimit = evidenceBudget.itemLimit
		evidenceExhausted = evidenceBudget.exhausted
	}
	return support.FactEvidence("home-permission-resource-budget", map[string]any{
		"phase":                         phase,
		"snapshot_count":                snapshotCount,
		"path_operation_limit_per_pass": pathOperationsPerPass,
		"path_operations_used":          pathUsed,
		"path_budget_exhausted":         pathExhausted,
		"path_exhaustion_reason":        pathReason,
		"evidence_byte_limit":           evidenceByteLimit,
		"evidence_bytes_used":           evidenceBytes,
		"evidence_item_limit":           evidenceItemLimit,
		"evidence_items_used":           evidenceItems,
		"evidence_budget_exhausted":     evidenceExhausted,
	})
}

func revalidateHomePermissionPaths(
	ctx context.Context,
	environment evaluator.Environment,
	mounts homeMountTable,
	initial map[string]userEnvironmentPathSnapshot,
	pathBudget *pathInspectionBudget,
	evidenceBudget *inspectionEvidenceBudget,
) ([]model.Evidence, bool, bool, error) {
	paths := make([]string, 0, len(initial))
	for home := range initial {
		paths = append(paths, home)
	}
	sort.Strings(paths)
	evidence := make([]model.Evidence, 0)
	stable := true
	changed := 0
	resourceLimited := false
	pathPolicy := localMountPathInspectionPolicy(mounts)

	for _, home := range paths {
		current, err := inspectPathWithoutSymlinksWithPolicy(
			environment.Files,
			home,
			pathPolicy,
			pathBudget,
		)
		if err != nil {
			if isUserEnvironmentPathUnstable(err) {
				stable = false
				changed++
				continue
			}
			return evidence, false, false, fmt.Errorf("%s: %w", home, err)
		}
		if !evidenceBudget.append(&evidence, current.Evidence...) {
			return evidence, false, true, nil
		}
		if current.Unknown != "" || !current.Exists {
			stable = false
			changed++
			if pathBudget.isExhausted() {
				resourceLimited = true
				break
			}
			continue
		}
		currentSnapshot, snapshotOK := newUserEnvironmentPathSnapshot(home, current, "")
		if !snapshotOK ||
			currentSnapshot.State != userEnvironmentPathPresent ||
			!sameUserEnvironmentPathSnapshot(initial[home], currentSnapshot) {
			stable = false
			changed++
			continue
		}
		if initial[home].ACLDigest == "" {
			continue
		}
		_, aclEvidence, aclDigest, aclErr := inspectNonOwnerACLSnapshot(
			ctx,
			environment,
			current.Metadata,
			os.FileMode(0o2),
			false,
		)
		if strings.TrimSpace(aclEvidence.Source) != "" &&
			!evidenceBudget.append(&evidence, aclEvidence) {
			return evidence, false, true, nil
		}
		if aclErr != nil {
			if support.IsACLToolUnavailable(aclErr) || isUserEnvironmentPathUnstable(aclErr) {
				stable = false
				changed++
				continue
			}
			return evidence, false, false, fmt.Errorf("revalidate ACL %s: %w", home, aclErr)
		}
		if initial[home].ACLDigest != aclDigest {
			stable = false
			changed++
		}
	}

	summary := support.FactEvidence("home-permission-path-snapshot-revalidation", map[string]any{
		"path_count":       len(paths),
		"changed_count":    changed,
		"all_stable":       stable,
		"resource_limited": resourceLimited,
	})
	if !evidenceBudget.append(&evidence, summary) {
		resourceLimited = true
	}
	return evidence, stable, resourceLimited, nil
}

func evaluateHomeExists(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return fileError("effective_passwd_failed", "실효 계정 목록을 확인하지 못했습니다.", err)
	}
	evidence := []model.Evidence{accountEvidence}
	violations := make([]pathFinding, 0)
	unknowns := make([]pathFinding, 0)
	grouped := make(map[string][]support.PasswdEntry)
	normalizations := make([]map[string]string, 0)
	for _, account := range accounts {
		configured := account.Home
		if configured == "" {
			violations = append(violations, pathFinding{
				Account: account.Name,
				Path:    "(미지정)",
				Reason:  "홈 경로가 지정되지 않음",
			})
			continue
		}
		home, normalized, invalidReason := normalizeConfiguredHomePath(configured)
		if invalidReason != "" {
			unknowns = append(unknowns, pathFinding{
				Account: account.Name,
				Path:    displayConfiguredHomePath(configured),
				Reason:  invalidReason,
			})
			continue
		}
		grouped[home] = append(grouped[home], account)
		if normalized {
			normalizations = append(normalizations, map[string]string{
				"account":         account.Name,
				"configured_path": configured,
				"canonical_path":  home,
			})
		}
	}
	if len(normalizations) > 0 {
		evidence = append(evidence, support.FactEvidence("home-path-normalization", map[string]any{
			"normalization_count": len(normalizations),
			"paths":               normalizations,
		}))
	}
	expected := "모든 계정은 실제 디렉터리로 존재하는 절대 홈 경로를 지정해야 합니다."
	if len(violations) > 0 && len(grouped) == 0 {
		evidence = append(evidence, findingEvidence("home-existence-summary", 0, violations, unknowns))
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "홈 디렉터리가 없거나 홈 경로가 디렉터리가 아닌 계정이 있습니다.",
			Expected: expected,
			Observed: findingsObserved(violations, unknowns),
			Evidence: evidence,
		}
	}

	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		if isHomeMountInventoryLimit(err) {
			for _, home := range sortedHomes(grouped) {
				unknowns = append(unknowns, pathFinding{
					Account: accountNames(grouped[home]),
					Path:    home,
					Reason:  "마운트 목록이 안전한 점검 한도를 초과함",
				})
			}
			evidence = append(
				evidence,
				mountEvidence,
				homeMountInventoryLimitEvidence(err),
				findingEvidence("home-existence-summary", 0, violations, unknowns),
			)
			if len(violations) > 0 {
				return evaluator.Outcome{
					Status:   model.StatusFail,
					Summary:  "홈 경로가 지정되지 않은 계정이 있으며 다른 홈의 존재 여부는 일부 확인하지 못했습니다.",
					Expected: expected,
					Observed: findingsObserved(violations, unknowns),
					Evidence: evidence,
				}
			}
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownInsufficientEvidence,
				Summary:       "마운트 목록이 안전한 점검 한도를 초과해 홈 존재 여부를 확정할 수 없습니다.",
				Expected:      expected,
				Observed:      fmt.Sprintf("마운트 항목 상한 %d개 초과", maximumHomeMountEntries),
				Evidence:      evidence,
			}
		}
		if len(violations) == 0 {
			return fileError("home_mounts_failed", "홈 디렉터리의 파일 시스템 유형을 확인하지 못했습니다.", err)
		}
		for _, home := range sortedHomes(grouped) {
			unknowns = append(unknowns, pathFinding{
				Account: accountNames(grouped[home]),
				Path:    home,
				Reason:  "파일 시스템 유형을 확인하지 못해 홈 존재 여부를 점검하지 못함",
			})
		}
		evidence = append(evidence,
			support.FactEvidence("home-mount-inventory-error", map[string]any{
				"error":                 err.Error(),
				"unverified_home_count": len(grouped),
			}),
			findingEvidence("home-existence-summary", 0, violations, unknowns),
		)
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "홈 경로가 지정되지 않은 계정이 있으며 다른 홈의 존재 여부는 일부 확인하지 못했습니다.",
			Expected: expected,
			Observed: findingsObserved(violations, unknowns),
			Evidence: evidence,
		}
	}
	evidence = append(evidence, mountEvidence)
	checked := 0
	homeSnapshots := make(map[string]userEnvironmentPathSnapshot, len(grouped))
	pathBudget := newPathInspectionBudget(maximumHomeExistencePathOperations)
	pathPolicy := localMountPathInspectionPolicy(mounts)

scanHomeExistence:
	for _, home := range sortedHomes(grouped) {
		homeAccounts := grouped[home]
		accountsLabel := accountNames(homeAccounts)
		kind, mount, found := mounts.classify(home)
		if !found {
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: "포함 마운트를 확인할 수 없음"})
			continue
		}
		if kind != homeMountLocal {
			reason := fmt.Sprintf("%s 홈 정책 미확인(%s:%s)", kind, mount.Target, mount.FSType)
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: reason})
			continue
		}
		inspected, err := inspectPathFollowingSymlinksWithPolicy(
			environment.Files,
			home,
			pathPolicy,
			pathBudget,
		)
		if err != nil {
			return fileError("home_stat_failed", "홈 디렉터리의 존재 여부를 확인하지 못했습니다.", fmt.Errorf("%s: %w", home, err))
		}
		evidence = append(evidence, inspected.Evidence...)
		resolvedHome := inspected.ResolvedPath
		if resolvedHome == "" {
			resolvedHome = home
		}
		if resolvedHome != home {
			resolvedKind, resolvedMount, resolvedFound := mounts.classify(resolvedHome)
			if !resolvedFound {
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: "심볼릭 링크 대상의 포함 마운트를 확인할 수 없음"})
				continue
			}
			if resolvedKind != homeMountLocal {
				reason := fmt.Sprintf("심볼릭 링크 대상의 %s 홈 정책 미확인(%s:%s)", resolvedKind, resolvedMount.Target, resolvedMount.FSType)
				unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: reason})
				continue
			}
		}
		if inspected.Unknown != "" {
			unknowns = append(unknowns, pathFinding{Account: accountsLabel, Path: home, Reason: inspected.Unknown})
			if pathBudget.isExhausted() {
				break scanHomeExistence
			}
			continue
		}
		if !inspected.Exists {
			violations = append(violations, pathFinding{Account: accountsLabel, Path: home, Reason: "홈 디렉터리가 없음"})
			continue
		}
		if inspected.Metadata.FileType != "directory" {
			violations = append(violations, pathFinding{Account: accountsLabel, Path: home, Reason: "홈 경로가 디렉터리가 아님"})
			continue
		}
		snapshot, snapshotOK := newUserEnvironmentPathSnapshot(home, inspected, "")
		if !snapshotOK || snapshot.State != userEnvironmentPathPresent {
			unknowns = append(unknowns, pathFinding{
				Account: accountsLabel,
				Path:    home,
				Reason:  "홈 경로 해석 스냅샷을 고정할 수 없음",
			})
			continue
		}
		homeSnapshots[home] = snapshot
		checked++
	}

	evidence = append(evidence, findingEvidence("home-existence-summary", checked, violations, unknowns))
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "홈 디렉터리가 없거나 홈 경로가 디렉터리가 아닌 계정이 있습니다.",
			Expected: expected,
			Observed: findingsObserved(violations, unknowns),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "원격·불명확 마운트 또는 점검 중 변경된 경로 때문에 홈 존재 여부를 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      findingsObserved(nil, unknowns),
			Evidence:      evidence,
		}
	}
	if checked == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "존재 여부를 확인할 적용 가능한 홈 디렉터리가 없습니다.",
			Expected: expected,
			Observed: "대상 홈 없음",
			Evidence: evidence,
		}
	}
	revalidationEvidence, accountStable, mountsStable, resourceLimited, err := revalidateHomeExistenceSnapshot(
		ctx,
		environment,
		accounts,
		mounts,
	)
	evidence = append(evidence, revalidationEvidence...)
	if err != nil {
		outcome := fileError(
			"home_snapshot_revalidation_failed",
			"홈 디렉터리 점검의 최종 계정·마운트 상태를 재확인하지 못했습니다.",
			err,
		)
		outcome.Evidence = evidence
		return outcome
	}
	if resourceLimited {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownInsufficientEvidence,
			Summary:       "최종 마운트 목록이 안전한 점검 한도를 초과해 홈 존재 여부를 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("최종 마운트 항목 상한 %d개 초과", maximumHomeMountEntries),
			Evidence:      evidence,
		}
	}
	if !accountStable || !mountsStable {
		changed := make([]string, 0, 2)
		if !accountStable {
			changed = append(changed, "실효 계정 및 홈 목록")
		}
		if !mountsStable {
			changed = append(changed, "마운트 목록")
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "점검 중 계정 또는 마운트 구성이 변경되어 동일한 상태의 홈 존재 여부를 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      strings.Join(changed, ", ") + " 변경 감지",
			Evidence:      evidence,
		}
	}
	pathEvidence, pathsStable, err := revalidateHomeExistencePaths(
		environment.Files,
		mounts,
		homeSnapshots,
		pathBudget,
	)
	evidence = append(evidence, pathEvidence...)
	if err != nil {
		outcome := fileError(
			"home_path_revalidation_failed",
			"홈 디렉터리 점검의 최종 경로 상태를 재확인하지 못했습니다.",
			err,
		)
		outcome.Evidence = evidence
		return outcome
	}
	if !pathsStable {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "점검 중 홈 경로 대상이 변경되어 동일한 상태의 존재 여부를 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      "최종 홈 경로 스냅샷 변경 감지",
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 계정에 지정된 홈 경로가 디렉터리로 존재합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("홈 디렉터리 %d개 확인", checked),
		Evidence: evidence,
	}
}

func revalidateHomeExistencePaths(
	files system.Reader,
	mounts homeMountTable,
	initial map[string]userEnvironmentPathSnapshot,
	pathBudget *pathInspectionBudget,
) ([]model.Evidence, bool, error) {
	paths := make([]string, 0, len(initial))
	for home := range initial {
		paths = append(paths, home)
	}
	sort.Strings(paths)
	evidence := make([]model.Evidence, 0, len(paths)+1)
	stable := true
	changed := 0
	pathPolicy := localMountPathInspectionPolicy(mounts)
	for _, home := range paths {
		current, err := inspectPathFollowingSymlinksWithPolicy(
			files,
			home,
			pathPolicy,
			pathBudget,
		)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				stable = false
				changed++
				continue
			}
			return evidence, false, fmt.Errorf("%s: %w", home, err)
		}
		evidence = append(evidence, current.Evidence...)
		if current.Unknown != "" {
			stable = false
			changed++
			if pathBudget.isExhausted() {
				break
			}
			continue
		}
		currentSnapshot, snapshotOK := newUserEnvironmentPathSnapshot(home, current, "")
		if !snapshotOK ||
			currentSnapshot.State != userEnvironmentPathPresent ||
			!sameUserEnvironmentPathSnapshot(initial[home], currentSnapshot) {
			stable = false
			changed++
		}
	}
	evidence = append(evidence, support.FactEvidence("home-existence-path-snapshot-revalidation", map[string]any{
		"path_count":    len(paths),
		"changed_count": changed,
		"all_stable":    stable,
	}))
	return evidence, stable, nil
}

func revalidateHomeExistenceSnapshot(
	ctx context.Context,
	environment evaluator.Environment,
	initialAccounts []support.PasswdEntry,
	initialMounts homeMountTable,
) ([]model.Evidence, bool, bool, bool, error) {
	finalAccounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return nil, false, false, false, fmt.Errorf("revalidate effective account inventory: %w", err)
	}
	finalMounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		if isHomeMountInventoryLimit(err) {
			return []model.Evidence{
				accountEvidence,
				mountEvidence,
				homeMountInventoryLimitEvidence(err),
			}, false, false, true, nil
		}
		return []model.Evidence{accountEvidence}, false, false, false, fmt.Errorf("revalidate mount inventory: %w", err)
	}
	accountStable := sameHomeAccountInventory(initialAccounts, finalAccounts)
	mountsStable := sameHomeMountInventory(initialMounts, finalMounts)
	return []model.Evidence{
		accountEvidence,
		mountEvidence,
		support.FactEvidence("home-existence-snapshot-revalidation", map[string]any{
			"account_inventory_stable": accountStable,
			"mount_inventory_stable":   mountsStable,
			"initial_account_count":    len(initialAccounts),
			"final_account_count":      len(finalAccounts),
			"initial_mount_count":      len(initialMounts.mounts),
			"final_mount_count":        len(finalMounts.mounts),
		}),
	}, accountStable, mountsStable, false, nil
}

func sameHomeAccountInventory(before, after []support.PasswdEntry) bool {
	if len(before) != len(after) {
		return false
	}
	type homeAccount struct {
		UID   uint32
		GID   uint32
		Home  string
		Shell string
	}
	accounts := make(map[string]homeAccount, len(before))
	for _, entry := range before {
		accounts[entry.Name] = homeAccount{
			UID: entry.UID, GID: entry.GID, Home: entry.Home, Shell: entry.Shell,
		}
	}
	for _, entry := range after {
		previous, exists := accounts[entry.Name]
		current := homeAccount{
			UID: entry.UID, GID: entry.GID, Home: entry.Home, Shell: entry.Shell,
		}
		if !exists || previous != current {
			return false
		}
		delete(accounts, entry.Name)
	}
	return len(accounts) == 0
}

func isUserEnvironmentPathUnstable(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, system.ErrFileChanged) ||
		errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, syscall.ELOOP)
}

func sameHomeMountInventory(before, after homeMountTable) bool {
	if len(before.mounts) != len(after.mounts) {
		return false
	}
	counts := make(map[homeMount]int, len(before.mounts))
	for _, mount := range before.mounts {
		counts[mount]++
	}
	for _, mount := range after.mounts {
		if counts[mount] == 0 {
			return false
		}
		counts[mount]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func normalizeConfiguredHomePath(configured string) (string, bool, string) {
	if !safeConfiguredHomePathText(configured) {
		return "", false, "홈 경로에 안전하게 표시할 수 없는 제어 또는 형식 문자가 포함됨"
	}
	if !path.IsAbs(configured) {
		return "", false, "절대 홈 경로가 아님"
	}
	for _, component := range strings.Split(configured, "/") {
		if component == ".." {
			return "", false, "상위 경로 구성요소(..)가 있어 안전하게 정규화할 수 없음"
		}
	}
	canonical := path.Clean(configured)
	if err := validateAbsoluteSystemPath(canonical); err != nil {
		return "", false, "홈 경로를 안전하게 정규화할 수 없음"
	}
	return canonical, canonical != configured, ""
}

func displayConfiguredHomePath(configured string) string {
	if configured == "" {
		return "(미지정)"
	}
	if !safeConfiguredHomePathText(configured) {
		return "(유효하지 않은 경로)"
	}
	return configured
}

func safeConfiguredHomePathText(configured string) bool {
	if len(configured) > maximumAbsoluteSystemPathBytes ||
		systemPathComponentCount(configured) > maximumAbsoluteSystemPathComponents ||
		!utf8.ValidString(configured) {
		return false
	}
	for _, character := range configured {
		if unicode.IsControl(character) ||
			unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) ||
			unicode.Is(unicode.Zp, character) {
			return false
		}
	}
	return true
}
