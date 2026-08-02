package filecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorStartupPermissions = "unix.file.startup_permissions"
	EvaluatorInetdPermissions   = "unix.file.inetd_permissions"
	EvaluatorSyslogPermissions  = "unix.file.syslog_permissions"
)

var errStartupDependencyInventory = errors.New("systemd startup dependency inventory failed")

func evaluateStartupPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "활성 및 부팅 활성 시작 파일의 경로와 권한을 확인할 수 없습니다.", Expected: "활성 또는 부팅 시 실행되는 모든 시작 파일의 소유자와 권한을 확인할 수 있어야 합니다.", Observed: "init=" + environment.Platform.InitSystem}
	}
	inventory, inventoryEvidence, err := inspectStartupUnitInventory(ctx, environment)
	if err != nil {
		if errors.Is(err, errStartupDependencyInventory) {
			return fileError("systemd_dependency_inspection_failed", "systemd 시작 의존 관계를 확인하지 못했습니다.", err)
		}
		return fileError("systemd_unit_listing_failed", "systemd 시작 대상을 열거하지 못했습니다.", err)
	}
	evidence := append([]model.Evidence(nil), inventoryEvidence...)
	unitNames := inventory.ExpandedUnits
	unsupportedUnitCount := inventory.UnsupportedUnitCount
	seenPaths := make(map[string]struct{})
	pathGuards := make(map[string][]*startupFilesystemSnapshot)
	pathUnitGuards := make(map[string][]*startupSystemdUnitGuard)
	pathAllowsMissing := make(map[string]bool)
	unitGuards := make([]*startupSystemdUnitGuard, 0, len(unitNames))
	violations := make([]string, 0)
	unknowns := append([]string(nil), inventory.DependencyUnknowns...)
	if unsupportedUnitCount > 0 {
		unknowns = append(unknowns, fmt.Sprintf("이스케이프되거나 비표준인 unit 이름 %d개", unsupportedUnitCount))
	}
	for _, unitName := range unitNames {
		states, stateEvidence, err := inspectStartupUnit(ctx, environment, unitName)
		if err != nil {
			return fileError("systemd_unit_inspection_failed", "systemd unit 경로를 확인하지 못했습니다.", err)
		}
		evidence = append(evidence, stateEvidence...)
		if len(states) != 1 {
			return fileError("systemd_unit_inspection_failed", "systemd unit 경로를 확인하지 못했습니다.", fmt.Errorf("unexpected state count for %s", unitName))
		}
		state := states[0]
		inspectionName := state.InspectionName
		if inspectionName == "" {
			inspectionName = unitName
		}
		unitGuard := &startupSystemdUnitGuard{
			UnitName:           unitName,
			InspectionName:     inspectionName,
			InitialStateDigest: startupUnitStateDigest(state),
		}
		unitGuards = append(unitGuards, unitGuard)
		if startupUnitAbsent(state) {
			continue
		}
		unitPaths, reason := startupUnitPaths(state)
		if reason != "" {
			unitGuard.InitialUnknowns = append(unitGuard.InitialUnknowns, unitName+": "+reason)
		}
		unitGuard.ConfigurationPaths = uniqueSortedPaths(unitPaths)
		for _, configurationPath := range unitGuard.ConfigurationPaths {
			recordStartupPathMissingAllowance(
				pathAllowsMissing,
				configurationPath,
				false,
			)
		}
		if strings.HasSuffix(unitName, ".service") {
			executablePaths, complete, executableEvidence, executableDigest, inspectErr :=
				startupExecutablePathsGuarded(ctx, environment, inspectionName)
			if inspectErr != nil {
				return fileError("systemd_execstart_inspection_failed", "systemd unit의 실제 시작 실행 파일을 확인하지 못했습니다.", inspectErr)
			}
			unitGuard.CheckExecutableProperties = true
			unitGuard.InitialExecutableDigest = executableDigest
			evidence = append(evidence, executableEvidence...)
			for _, executablePath := range executablePaths {
				unitPaths = append(unitPaths, executablePath.Path)
				recordStartupPathMissingAllowance(
					pathAllowsMissing,
					executablePath.Path,
					executablePath.AllowMissing,
				)
				if executablePath.Snapshot != nil {
					pathGuards[executablePath.Path] = append(
						pathGuards[executablePath.Path],
						executablePath.Snapshot,
					)
				}
			}
			if !complete {
				unitGuard.InitialUnknowns = append(
					unitGuard.InitialUnknowns,
					unitName+": ExecCondition/ExecStart 계열의 실제 스크립트 경로를 결정적으로 해석할 수 없음",
				)
			}
		}
		for _, unitPath := range uniqueSortedPaths(unitPaths) {
			seenPaths[unitPath] = struct{}{}
			pathUnitGuards[unitPath] = appendUniqueStartupUnitGuard(pathUnitGuards[unitPath], unitGuard)
		}
	}
	legacyPaths, legacyInactiveGuards, legacyEvidence, legacyUnknowns :=
		inspectStartupLegacyPathGuards(environment.Files)
	evidence = append(evidence, legacyEvidence...)
	unknowns = append(unknowns, legacyUnknowns...)
	for legacyPath, legacyGuard := range legacyPaths {
		seenPaths[legacyPath] = struct{}{}
		recordStartupPathMissingAllowance(pathAllowsMissing, legacyPath, false)
		if legacyGuard != nil {
			pathGuards[legacyPath] = append(pathGuards[legacyPath], legacyGuard)
		}
	}
	pendingPermissions, permissionEvidence := collectStartupPermissionPathAssessments(
		ctx,
		environment,
		seenPaths,
		pathGuards,
	)
	for index := range pendingPermissions {
		pendingPermissions[index].AllowMissing =
			pathAllowsMissing[pendingPermissions[index].Path]
	}
	evidence = append(evidence, permissionEvidence...)
	inventoryStable, inventoryGuardEvidence := revalidateStartupUnitInventory(
		ctx,
		environment,
		inventory,
	)
	evidence = append(evidence, inventoryGuardEvidence...)
	if !inventoryStable {
		unknowns = append(
			unknowns,
			"점검 중 활성·부팅 활성 unit 목록 또는 시작 의존 관계가 변경되었거나 다시 확인되지 않음",
		)
	}
	permissionRequeryEvidence := requeryStartupPermissionPathAssessments(
		ctx,
		environment,
		pendingPermissions,
	)
	evidence = append(evidence, permissionRequeryEvidence...)
	auxiliaryValidations, auxiliaryGuardEvidence :=
		revalidateStartupPermissionAuxiliaryGuards(ctx, environment, pendingPermissions)
	evidence = append(evidence, auxiliaryGuardEvidence...)
	unitQueryValidations, unitGuardEvidence := revalidateStartupSystemdUnitGuards(
		ctx,
		environment,
		unitGuards,
	)
	evidence = append(evidence, unitGuardEvidence...)

	// No command or semantic requery is allowed after this boundary. The
	// remaining guards only compare the initial filesystem snapshots.
	legacyGuardUnknowns, legacyGuardEvidence := revalidateStartupInactiveLegacyGuards(
		environment.Files,
		legacyInactiveGuards,
	)
	evidence = append(evidence, legacyGuardEvidence...)
	unknowns = append(unknowns, legacyGuardUnknowns...)
	filesystemValidations := revalidateStartupPermissionFilesystemGuards(
		environment.Files,
		pendingPermissions,
		auxiliaryValidations,
	)
	unitGuardValidations, unitFilesystemEvidence := startupUnitGuardFinalValidations(
		unitGuards,
		unitQueryValidations,
		pendingPermissions,
		filesystemValidations,
	)
	evidence = append(evidence, unitFilesystemEvidence...)
	permissionGuardEvidence := finalizeStartupPermissionPathAssessments(
		pendingPermissions,
		func(systemPath string) bool {
			if _, legacy := legacyPaths[systemPath]; legacy {
				return true
			}
			if !inventoryStable {
				return false
			}
			return startupPermissionPathHasStableUnitGuard(
				pathUnitGuards[systemPath],
				unitGuardValidations,
			)
		},
		filesystemValidations,
	)
	evidence = append(evidence, permissionGuardEvidence...)
	for _, unitGuard := range unitGuards {
		if unitGuardValidations[unitGuard] {
			unknowns = append(unknowns, unitGuard.InitialUnknowns...)
			continue
		}
		unknowns = append(
			unknowns,
			unitGuard.UnitName+": 점검 중 unit 상태, ExecStart 계열 구성 또는 fragment/drop-in 파일이 변경되었거나 다시 확인되지 않음",
		)
	}
	systemdViolations, systemdUnknowns, permissionErr := acceptStartupPermissionAssessments(
		pendingPermissions,
		pathUnitGuards,
		unitGuardValidations,
		inventoryStable,
		legacyPaths,
	)
	if permissionErr != nil {
		return fileError("startup_permission_inspection_failed", "시작 파일 권한을 확인하지 못했습니다.", permissionErr)
	}
	violations = append(violations, systemdViolations...)
	unknowns = append(unknowns, systemdUnknowns...)
	violations = uniqueSortedPaths(violations)
	unknowns = uniqueSortedPaths(unknowns)
	summaryEvidence := support.FactEvidence("systemd 시작 파일 권한 파생 정보", map[string]any{
		"unit_count": len(unitNames), "unique_path_count": len(seenPaths),
		"violation_count": len(violations), "unknown_count": len(unknowns), "unsupported_unit_count": unsupportedUnitCount,
		"violation_sample": limitedStrings(violations, 20), "unknown_sample": limitedStrings(unknowns, 20),
	})
	evidence = append(evidence, summaryEvidence)
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status: model.StatusFail, Summary: "활성 또는 부팅 활성 시작 파일에 비-root 소유나 비소유자 쓰기 권한이 있습니다.",
			Expected: "모든 fragment, drop-in 및 실제 시작 실행 파일이 root 소유이고 group/other 쓰기가 없어야 합니다.",
			Observed: fmt.Sprintf("위반 %d건", len(violations)),
			Details:  startupPermissionDetails("권한 위반", violations, "root 소유, group/other 쓰기 권한 없음"),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:  "일부 활성 또는 부팅 활성 unit의 실제 시작 경로를 확정할 수 없습니다.",
			Expected: "모든 활성 또는 부팅 활성 unit의 실제 시작 파일을 확인할 수 있어야 합니다.",
			Observed: fmt.Sprintf("확정 불가 %d건", len(unknowns)),
			Details:  startupPermissionDetails("확인하지 못한 경로", unknowns, "실제 시작 경로와 권한 확인"),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "활성 및 부팅 활성 systemd 시작 파일과 실제 실행 파일의 소유자·권한이 안전합니다.", Expected: "모든 fragment, drop-in 및 실제 시작 실행 파일이 root 소유이고 group/other 쓰기가 없어야 합니다.", Observed: fmt.Sprintf("unit %d개, 경로 %d개 확인", len(unitNames), len(seenPaths)), Evidence: evidence}
}

func startupPermissionDetails(label string, findings []string, expected string) []model.ResultDetail {
	if len(findings) == 0 {
		return nil
	}
	const limit = 20
	lines := limitedStrings(findings, limit)
	if len(findings) > len(lines) {
		lines = append(lines, fmt.Sprintf("... 외 %d건", len(findings)-len(lines)))
	}
	return []model.ResultDetail{{
		Label:    label,
		Current:  strings.Join(lines, "\n"),
		Expected: expected,
		Source:   "systemd unit 및 실행 경로",
	}}
}

func recordStartupPathMissingAllowance(
	allowances map[string]bool,
	systemPath string,
	allowMissing bool,
) {
	current, exists := allowances[systemPath]
	if !exists {
		allowances[systemPath] = allowMissing
		return
	}
	allowances[systemPath] = current && allowMissing
}

func startupPermissionPolicy() support.PermissionPolicy {
	return support.PermissionPolicy{
		AllowedUIDs:        map[int]struct{}{0: {}},
		AllowedMode:        0o755,
		AllowedTypes:       map[string]struct{}{"regular": {}},
		AllowedSpecialBits: os.ModeSetuid | os.ModeSetgid | os.ModeSticky,
		FollowFinalSymlink: true,
	}
}

func startupParentDirectoryPermissionPolicy() support.PermissionPolicy {
	return support.PermissionPolicy{
		AllowedUIDs:        map[int]struct{}{0: {}},
		AllowedMode:        0o755,
		AllowedTypes:       map[string]struct{}{"directory": {}},
		FollowFinalSymlink: true,
	}
}

type startupUnitInventorySnapshot struct {
	BaseUnits             []string
	ExpandedUnits         []string
	DependencyDigest      string
	DependencyUnknowns    []string
	UnsupportedUnitCount  int
	UnsupportedUnitDigest string
}

func inspectStartupUnitInventory(
	ctx context.Context,
	environment evaluator.Environment,
) (startupUnitInventorySnapshot, []model.Evidence, error) {
	specs := []executor.Spec{
		{Name: "systemctl", Arguments: []string{"list-unit-files", "--no-pager", "--no-legend", "--plain", "--state=enabled,enabled-runtime,linked,linked-runtime"}, Timeout: 30 * time.Second, MaxOutput: 4 << 20},
		{Name: "systemctl", Arguments: []string{"list-units", "--all", "--no-pager", "--no-legend", "--plain", "--state=active,activating,reloading", "--type=service", "--type=socket", "--type=timer", "--type=path", "--type=mount", "--type=automount", "--type=target", "--type=swap", "--type=slice"}, Timeout: 30 * time.Second, MaxOutput: 4 << 20},
	}
	units := make(map[string]struct{})
	unsupportedUnits := make([]string, 0)
	evidence := make([]model.Evidence, 0, len(specs))
	for _, spec := range specs {
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return startupUnitInventorySnapshot{}, evidence, err
		}
		evidence = append(evidence, support.CommandEvidence(spec, result))
		if result.ExitCode != 0 || result.TimedOut || result.Truncated {
			return startupUnitInventorySnapshot{}, evidence,
				fmt.Errorf("systemd unit inventory exit=%d timed_out=%t truncated=%t", result.ExitCode, result.TimedOut, result.Truncated)
		}
		for _, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
			fields := strings.Fields(raw)
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			if name == "●" && len(fields) > 1 {
				name = fields[1]
			} else {
				name = strings.TrimPrefix(name, "●")
			}
			if !validSystemdUnitToken(name) {
				unsupportedUnits = append(unsupportedUnits, name)
				continue
			}
			units[name] = struct{}{}
		}
	}
	baseUnits := make([]string, 0, len(units))
	for name := range units {
		baseUnits = append(baseUnits, name)
	}
	sort.Strings(baseUnits)
	expandedUnits, dependencyEvidence, dependencyUnknowns, dependencyDigest, err :=
		expandStartupUnitDependenciesGuarded(ctx, environment, baseUnits)
	evidence = append(evidence, dependencyEvidence...)
	if err != nil {
		return startupUnitInventorySnapshot{}, evidence,
			fmt.Errorf("%w: %w", errStartupDependencyInventory, err)
	}
	sort.Strings(unsupportedUnits)
	return startupUnitInventorySnapshot{
		BaseUnits:             baseUnits,
		ExpandedUnits:         expandedUnits,
		DependencyDigest:      dependencyDigest,
		DependencyUnknowns:    dependencyUnknowns,
		UnsupportedUnitCount:  len(unsupportedUnits),
		UnsupportedUnitDigest: startupStringSetDigest(unsupportedUnits),
	}, evidence, nil
}

func revalidateStartupUnitInventory(
	ctx context.Context,
	environment evaluator.Environment,
	initial startupUnitInventorySnapshot,
) (bool, []model.Evidence) {
	current, rawEvidence, err := inspectStartupUnitInventory(ctx, environment)
	evidence := maskStartupUnitRevalidationEvidence(rawEvidence)
	requerySucceeded := err == nil
	baseStable := requerySucceeded &&
		startupStringSetDigest(initial.BaseUnits) == startupStringSetDigest(current.BaseUnits)
	expandedStable := requerySucceeded &&
		startupStringSetDigest(initial.ExpandedUnits) == startupStringSetDigest(current.ExpandedUnits)
	dependencyStable := requerySucceeded &&
		initial.DependencyDigest == current.DependencyDigest &&
		startupStringSetDigest(initial.DependencyUnknowns) == startupStringSetDigest(current.DependencyUnknowns)
	unsupportedStable := requerySucceeded &&
		initial.UnsupportedUnitCount == current.UnsupportedUnitCount &&
		initial.UnsupportedUnitDigest == current.UnsupportedUnitDigest
	stable := baseStable && expandedStable && dependencyStable && unsupportedStable
	evidence = append(evidence, support.FactEvidence("systemd-start-inventory-snapshot-guard", map[string]any{
		"requery_succeeded":             requerySucceeded,
		"initial_base_units_sha256":     startupStringSetDigest(initial.BaseUnits),
		"current_base_units_sha256":     startupStringSetDigest(current.BaseUnits),
		"base_units_stable":             baseStable,
		"initial_expanded_units_sha256": startupStringSetDigest(initial.ExpandedUnits),
		"current_expanded_units_sha256": startupStringSetDigest(current.ExpandedUnits),
		"expanded_units_stable":         expandedStable,
		"initial_dependency_sha256":     initial.DependencyDigest,
		"current_dependency_sha256":     current.DependencyDigest,
		"dependency_graph_stable":       dependencyStable,
		"unsupported_units_stable":      unsupportedStable,
		"all_stable":                    stable,
	}))
	return stable, evidence
}

func startupStringSetDigest(values []string) string {
	ordered := append([]string(nil), values...)
	sort.Strings(ordered)
	return bytesDigest([]byte(strings.Join(ordered, "\x00")))
}

type startupPendingPermissionAssessment struct {
	Path                 string
	Assessment           support.PermissionAssessment
	ParentAssessments    []support.PermissionAssessment
	AllowMissing         bool
	Guards               []*startupFilesystemSnapshot
	InspectErr           error
	GuardsStable         bool
	GuardCaptureComplete bool
	AssessmentStable     bool
}

type startupFilesystemGuardValidation struct {
	Stable                  bool
	InitialDigest           string
	CurrentDigest           string
	MismatchCount           int
	ReadErrorCount          int
	AuxiliaryMismatchCount  int
	AuxiliaryReadErrorCount int
}

type startupAuxiliaryGuardValidation struct {
	Stable         bool
	CurrentDigest  string
	MismatchCount  int
	ReadErrorCount int
}

func inspectStartupPermissionPaths(
	ctx context.Context,
	environment evaluator.Environment,
	paths map[string]struct{},
	pathGuards map[string][]*startupFilesystemSnapshot,
) ([]string, []string, []model.Evidence, error) {
	pending, evidence := collectStartupPermissionPathAssessments(
		ctx,
		environment,
		paths,
		pathGuards,
	)
	guardEvidence := revalidateStartupPermissionPathAssessments(ctx, environment, pending, nil)
	evidence = append(evidence, guardEvidence...)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	for _, item := range pending {
		if !item.GuardsStable {
			unknowns = append(
				unknowns,
				item.Path+": 권한 검사 중 경로, 권한, ACL, mount 상태 또는 상위 디렉터리가 변경됨",
			)
			continue
		}
		if item.InspectErr != nil {
			return nil, unknowns, evidence, fmt.Errorf(
				"inspect startup permissions for %s: %w",
				item.Path,
				item.InspectErr,
			)
		}
		violations = append(violations, startupPermissionAssessmentViolations(item)...)
		unknowns = append(unknowns, startupPermissionAssessmentUnknowns(item)...)
	}
	return violations, unknowns, evidence, nil
}

func collectStartupPermissionPathAssessments(
	ctx context.Context,
	environment evaluator.Environment,
	paths map[string]struct{},
	pathGuards map[string][]*startupFilesystemSnapshot,
) ([]startupPendingPermissionAssessment, []model.Evidence) {
	orderedPaths := make([]string, 0, len(paths))
	for systemPath := range paths {
		orderedPaths = append(orderedPaths, systemPath)
	}
	sort.Strings(orderedPaths)

	pending := make([]startupPendingPermissionAssessment, 0, len(orderedPaths))
	evidence := make([]model.Evidence, 0)
	for _, systemPath := range orderedPaths {
		guards := uniqueStartupSnapshotGuards(pathGuards[systemPath])
		guardComplete := len(guards) > 0
		if len(guards) == 0 {
			permissionGuard, captured := captureStartupPermissionFilesystemSnapshot(
				environment.Files,
				systemPath,
			)
			guardComplete = captured
			if permissionGuard != nil {
				guards = uniqueStartupSnapshotGuards(append(guards, permissionGuard))
			}
		}
		assessment, err := support.InspectPermissions(
			ctx,
			environment.Files,
			environment.Commands,
			systemPath,
			startupPermissionPolicy(),
		)
		evidence = append(evidence, assessment.Evidence...)
		parentAssessments, parentEvidence, parentErr :=
			inspectStartupParentPermissionAssessments(
				ctx,
				environment,
				startupParentPermissionPaths(guards),
			)
		evidence = append(evidence, parentEvidence...)
		if snapshotErr := addStartupParentPermissionSnapshots(
			guards,
			parentAssessments,
		); snapshotErr != nil {
			parentErr = errors.Join(parentErr, snapshotErr)
		}
		pending = append(pending, startupPendingPermissionAssessment{
			Path:                 systemPath,
			Assessment:           assessment,
			ParentAssessments:    parentAssessments,
			Guards:               guards,
			InspectErr:           errors.Join(err, parentErr),
			GuardsStable:         false,
			GuardCaptureComplete: guardComplete && len(guards) > 0,
			AssessmentStable:     false,
		})
	}

	return pending, evidence
}

func startupParentPermissionPaths(
	guards []*startupFilesystemSnapshot,
) []string {
	paths := make([]string, 0)
	for _, guard := range guards {
		if guard == nil {
			continue
		}
		for _, entry := range guard.Entries {
			if entry.Roles&startupSnapshotRoleParent == 0 ||
				!entry.Follow ||
				!entry.Exists ||
				entry.Metadata.FileType != "directory" ||
				!entry.Metadata.Mode.IsDir() {
				continue
			}
			paths = append(paths, entry.Path)
		}
	}
	return uniqueSortedPaths(paths)
}

func inspectStartupParentPermissionAssessments(
	ctx context.Context,
	environment evaluator.Environment,
	parentPaths []string,
) ([]support.PermissionAssessment, []model.Evidence, error) {
	assessments := make([]support.PermissionAssessment, 0, len(parentPaths))
	evidence := make([]model.Evidence, 0)
	for _, parentPath := range parentPaths {
		assessment, err := support.InspectPermissions(
			ctx,
			environment.Files,
			environment.Commands,
			parentPath,
			startupParentDirectoryPermissionPolicy(),
		)
		evidence = append(evidence, assessment.Evidence...)
		if err != nil {
			return assessments, evidence, err
		}
		assessments = append(assessments, assessment)
	}
	return assessments, evidence, nil
}

func addStartupParentPermissionSnapshots(
	guards []*startupFilesystemSnapshot,
	assessments []support.PermissionAssessment,
) error {
	for _, assessment := range assessments {
		for _, guard := range guards {
			if !startupSnapshotContainsFollowedParent(guard, assessment.Path) {
				continue
			}
			if !addStartupAuxiliarySnapshot(
				guard,
				startupAuxiliarySnapshot{
					Kind:  startupAuxiliaryParentPermission,
					Path:  assessment.Path,
					State: startupPermissionAssessmentDigest(assessment),
				},
			) {
				return fmt.Errorf(
					"conflicting startup parent permission snapshot for %s",
					assessment.Path,
				)
			}
		}
	}
	return nil
}

func startupSnapshotContainsFollowedParent(
	snapshot *startupFilesystemSnapshot,
	parentPath string,
) bool {
	if snapshot == nil {
		return false
	}
	for _, entry := range snapshot.Entries {
		if entry.Path == parentPath &&
			entry.Follow &&
			entry.Exists &&
			entry.Roles&startupSnapshotRoleParent != 0 {
			return true
		}
	}
	return false
}

func revalidateStartupPermissionPathAssessments(
	ctx context.Context,
	environment evaluator.Environment,
	pending []startupPendingPermissionAssessment,
	resultEligible func(string) bool,
) []model.Evidence {
	evidence := requeryStartupPermissionPathAssessments(ctx, environment, pending)
	auxiliaryValidations, auxiliaryEvidence :=
		revalidateStartupPermissionAuxiliaryGuards(ctx, environment, pending)
	evidence = append(evidence, auxiliaryEvidence...)
	filesystemValidations := revalidateStartupPermissionFilesystemGuards(
		environment.Files,
		pending,
		auxiliaryValidations,
	)
	evidence = append(
		evidence,
		finalizeStartupPermissionPathAssessments(
			pending,
			resultEligible,
			filesystemValidations,
		)...,
	)
	return evidence
}

func requeryStartupPermissionPathAssessments(
	ctx context.Context,
	environment evaluator.Environment,
	pending []startupPendingPermissionAssessment,
) []model.Evidence {
	evidence := make([]model.Evidence, 0, len(pending))
	for index := range pending {
		item := &pending[index]
		currentAssessmentDigest := bytesDigest(nil)
		assessmentRequerySucceeded := false
		assessmentStable := item.InspectErr != nil
		if item.InspectErr == nil {
			currentAssessment, currentErr := support.InspectPermissions(
				ctx,
				environment.Files,
				environment.Commands,
				item.Path,
				startupPermissionPolicy(),
			)
			currentParentAssessments, _, parentErr :=
				inspectStartupParentPermissionAssessments(
					ctx,
					environment,
					startupPermissionAssessmentPaths(item.ParentAssessments),
				)
			currentErr = errors.Join(currentErr, parentErr)
			if currentErr == nil {
				assessmentRequerySucceeded = true
				currentAssessmentDigest = startupPermissionAssessmentBundleDigest(
					currentAssessment,
					currentParentAssessments,
				)
				assessmentStable = currentAssessmentDigest ==
					startupPermissionAssessmentBundleDigest(
						item.Assessment,
						item.ParentAssessments,
					)
			}
		}
		item.AssessmentStable = assessmentStable
		evidence = append(evidence, support.FactEvidence("systemd-start-permission-revalidation-summary", map[string]any{
			"path_sha256":                  pathDigest(item.Path),
			"requery_succeeded":            assessmentRequerySucceeded,
			"initial_inspection_succeeded": item.InspectErr == nil,
			"initial_assessment_sha256": startupPermissionAssessmentBundleDigest(
				item.Assessment,
				item.ParentAssessments,
			),
			"current_assessment_sha256": currentAssessmentDigest,
			"assessment_stable":         assessmentStable,
			"raw_permission_redacted":   true,
		}))
	}
	return evidence
}

func startupPermissionAssessmentPaths(
	assessments []support.PermissionAssessment,
) []string {
	paths := make([]string, 0, len(assessments))
	for _, assessment := range assessments {
		paths = append(paths, assessment.Path)
	}
	return uniqueSortedPaths(paths)
}

func startupPermissionAssessmentBundleDigest(
	assessment support.PermissionAssessment,
	parentAssessments []support.PermissionAssessment,
) string {
	records := []string{
		"target\x00" + startupPermissionAssessmentDigest(assessment),
	}
	for _, parentAssessment := range parentAssessments {
		records = append(
			records,
			"parent\x00"+parentAssessment.Path+"\x00"+
				startupPermissionAssessmentDigest(parentAssessment),
		)
	}
	sort.Strings(records)
	return bytesDigest([]byte(strings.Join(records, "\n")))
}

func finalizeStartupPermissionPathAssessments(
	pending []startupPendingPermissionAssessment,
	resultEligible func(string) bool,
	validations map[*startupFilesystemSnapshot]startupFilesystemGuardValidation,
) []model.Evidence {
	evidence := make([]model.Evidence, 0, len(pending))
	for index := range pending {
		item := &pending[index]
		assessmentAccepted := item.InspectErr == nil
		if resultEligible != nil {
			assessmentAccepted = assessmentAccepted && resultEligible(item.Path)
		}
		guardEvidence, stable := startupPermissionGuardEvidence(
			item.Path,
			item.Guards,
			assessmentAccepted && item.GuardCaptureComplete && item.AssessmentStable,
			validations,
		)
		evidence = append(evidence, guardEvidence)
		item.GuardsStable = item.GuardCaptureComplete && item.AssessmentStable && stable
	}
	return evidence
}

func startupPermissionAssessmentDigest(assessment support.PermissionAssessment) string {
	var builder strings.Builder
	fmt.Fprintf(
		&builder,
		"exists=%t\x00named_acl=%t\x00path=%s\x00type=%s\x00mode=%d\x00uid=%d\x00gid=%d\x00device=%d\x00inode=%d\x00size=%d\x00mtime=%d\x00",
		assessment.Exists,
		assessment.NamedAccessACL,
		assessment.Metadata.Path,
		assessment.Metadata.FileType,
		assessment.Metadata.Mode,
		assessment.Metadata.UID,
		assessment.Metadata.GID,
		assessment.Metadata.Device,
		assessment.Metadata.Inode,
		assessment.Metadata.Size,
		assessment.Metadata.ModTime.UnixNano(),
	)
	for _, value := range assessment.Violations {
		builder.WriteString("violation=")
		builder.WriteString(value)
		builder.WriteByte(0)
	}
	for _, value := range assessment.Unknowns {
		builder.WriteString("unknown=")
		builder.WriteString(value)
		builder.WriteByte(0)
	}
	return bytesDigest([]byte(builder.String()))
}

func startupPermissionAssessmentViolations(item startupPendingPermissionAssessment) []string {
	violations := make([]string, 0, len(item.Assessment.Violations))
	for _, violation := range item.Assessment.Violations {
		violations = append(violations, item.Path+": "+violation)
	}
	for _, parentAssessment := range item.ParentAssessments {
		for _, violation := range parentAssessment.Violations {
			violations = append(
				violations,
				parentAssessment.Path+": "+violation,
			)
		}
	}
	return uniqueSortedPaths(violations)
}

func startupPermissionAssessmentUnknowns(item startupPendingPermissionAssessment) []string {
	unknowns := make([]string, 0, len(item.Assessment.Unknowns)+1)
	for _, unknown := range item.Assessment.Unknowns {
		unknowns = append(unknowns, item.Path+": "+unknown)
	}
	if !item.Assessment.Exists && !item.AllowMissing {
		unknowns = append(unknowns, item.Path+": 파일 없음")
	}
	for _, parentAssessment := range item.ParentAssessments {
		for _, unknown := range parentAssessment.Unknowns {
			unknowns = append(
				unknowns,
				parentAssessment.Path+": "+unknown,
			)
		}
		if !parentAssessment.Exists {
			unknowns = append(
				unknowns,
				parentAssessment.Path+": 상위 디렉터리 없음",
			)
		}
	}
	return uniqueSortedPaths(unknowns)
}

func uniqueStartupSnapshotGuards(
	guards []*startupFilesystemSnapshot,
) []*startupFilesystemSnapshot {
	seen := make(map[*startupFilesystemSnapshot]struct{}, len(guards))
	result := make([]*startupFilesystemSnapshot, 0, len(guards))
	for _, guard := range guards {
		if guard == nil {
			continue
		}
		if _, duplicate := seen[guard]; duplicate {
			continue
		}
		seen[guard] = struct{}{}
		result = append(result, guard)
	}
	return result
}

func startupPermissionGuardEvidence(
	systemPath string,
	guards []*startupFilesystemSnapshot,
	resultEligible bool,
	validations map[*startupFilesystemSnapshot]startupFilesystemGuardValidation,
) (model.Evidence, bool) {
	initialDigests := make([]string, 0, len(guards))
	currentDigests := make([]string, 0, len(guards))
	stableCount := 0
	mismatchCount := 0
	readErrorCount := 0
	for _, guard := range guards {
		validation, exists := validations[guard]
		if !exists {
			validation = startupFilesystemGuardValidation{
				InitialDigest:  startupFilesystemSnapshotDigest(guard),
				CurrentDigest:  bytesDigest(nil),
				ReadErrorCount: 1,
			}
		}
		initialDigests = append(initialDigests, validation.InitialDigest)
		currentDigests = append(currentDigests, validation.CurrentDigest)
		mismatchCount += validation.MismatchCount
		readErrorCount += validation.ReadErrorCount
		mismatchCount += validation.AuxiliaryMismatchCount
		readErrorCount += validation.AuxiliaryReadErrorCount
		if validation.Stable {
			stableCount++
		}
	}
	sort.Strings(initialDigests)
	sort.Strings(currentDigests)
	allStable := len(guards) > 0 && stableCount == len(guards)
	return support.FactEvidence("systemd-start-permission-snapshot-guard", map[string]any{
		"path_sha256":                pathDigest(systemPath),
		"guard_count":                len(guards),
		"stable_guard_count":         stableCount,
		"unstable_guard_count":       len(guards) - stableCount,
		"snapshot_mismatch_count":    mismatchCount,
		"snapshot_read_error_count":  readErrorCount,
		"initial_guard_set_sha256":   bytesDigest([]byte(strings.Join(initialDigests, "\n"))),
		"current_guard_set_sha256":   bytesDigest([]byte(strings.Join(currentDigests, "\n"))),
		"all_guards_stable":          allStable,
		"permission_result_accepted": resultEligible && allStable,
	}), allStable
}

func startupPermissionSnapshotGuards(
	pending []startupPendingPermissionAssessment,
) []*startupFilesystemSnapshot {
	seen := make(map[*startupFilesystemSnapshot]struct{})
	guards := make([]*startupFilesystemSnapshot, 0)
	for _, item := range pending {
		for _, guard := range item.Guards {
			if guard == nil {
				continue
			}
			if _, exists := seen[guard]; exists {
				continue
			}
			seen[guard] = struct{}{}
			guards = append(guards, guard)
		}
	}
	return guards
}

func revalidateStartupPermissionAuxiliaryGuards(
	ctx context.Context,
	environment evaluator.Environment,
	pending []startupPendingPermissionAssessment,
) (map[*startupFilesystemSnapshot]startupAuxiliaryGuardValidation, []model.Evidence) {
	validations := make(map[*startupFilesystemSnapshot]startupAuxiliaryGuardValidation)
	evidence := make([]model.Evidence, 0)
	for _, guard := range startupPermissionSnapshotGuards(pending) {
		stable, currentDigest, mismatchCount, readErrorCount, guardEvidence :=
			revalidateStartupAuxiliarySnapshot(ctx, environment, guard)
		evidence = append(evidence, guardEvidence...)
		validations[guard] = startupAuxiliaryGuardValidation{
			Stable:         stable,
			CurrentDigest:  currentDigest,
			MismatchCount:  mismatchCount,
			ReadErrorCount: readErrorCount,
		}
	}
	return validations, evidence
}

func revalidateStartupPermissionFilesystemGuards(
	files system.Reader,
	pending []startupPendingPermissionAssessment,
	auxiliaryValidations map[*startupFilesystemSnapshot]startupAuxiliaryGuardValidation,
) map[*startupFilesystemSnapshot]startupFilesystemGuardValidation {
	validations := make(map[*startupFilesystemSnapshot]startupFilesystemGuardValidation)
	for _, guard := range startupPermissionSnapshotGuards(pending) {
		auxiliary, exists := auxiliaryValidations[guard]
		if !exists {
			auxiliary = startupAuxiliaryGuardValidation{
				CurrentDigest:  bytesDigest(nil),
				ReadErrorCount: 1,
			}
		}
		stable, currentDigest, mismatchCount, readErrorCount :=
			revalidateStartupFilesystemSnapshot(files, guard)
		initialDigest := bytesDigest([]byte(
			startupFilesystemSnapshotDigest(guard) + "\n" +
				startupAuxiliarySnapshotDigest(guard.Auxiliary),
		))
		currentCombinedDigest := bytesDigest([]byte(
			currentDigest + "\n" + auxiliary.CurrentDigest,
		))
		validations[guard] = startupFilesystemGuardValidation{
			Stable:                  stable && auxiliary.Stable,
			InitialDigest:           initialDigest,
			CurrentDigest:           currentCombinedDigest,
			MismatchCount:           mismatchCount,
			ReadErrorCount:          readErrorCount,
			AuxiliaryMismatchCount:  auxiliary.MismatchCount,
			AuxiliaryReadErrorCount: auxiliary.ReadErrorCount,
		}
	}
	return validations
}

func revalidateStartupAuxiliarySnapshot(
	ctx context.Context,
	environment evaluator.Environment,
	snapshot *startupFilesystemSnapshot,
) (bool, string, int, int, []model.Evidence) {
	if snapshot == nil {
		return false, bytesDigest(nil), 0, 1, nil
	}
	current := make([]startupAuxiliarySnapshot, 0, len(snapshot.Auxiliary))
	mismatchCount := 0
	readErrorCount := 0
	evidence := make([]model.Evidence, 0, len(snapshot.Auxiliary))
	for _, expected := range snapshot.Auxiliary {
		state := "uncertain"
		requerySucceeded := false
		switch expected.Kind {
		case startupAuxiliaryExecutionACL:
			metadata, err := environment.Files.Stat(expected.Path)
			if err == nil {
				acl, aclErr := support.InspectPOSIXACL(
					ctx,
					environment.Files,
					environment.Commands,
					expected.Path,
					true,
					false,
					&metadata,
				)
				usable := aclErr == nil &&
					!(acl.Evidence.Kind == model.EvidenceCommand && strings.TrimSpace(acl.Content) == "") &&
					startupACLAllowsAllExecution(acl.Content)
				state = startupAuxiliaryState(usable)
				requerySucceeded = aclErr == nil
			}
		case startupAuxiliaryExecutablePrefix:
			data, metadata, err := readStartupExecutablePrefix(
				ctx,
				environment.Files,
				expected.Path,
			)
			if err == nil {
				state = startupExecutablePrefixState(data, metadata)
				requerySucceeded = true
			}
		case startupAuxiliaryMountExec:
			mountState, mountEvidence := inspectStartupExecutableMount(ctx, environment, expected.Path)
			if mountEvidence.Source != "" {
				evidence = append(evidence, mountEvidence)
			}
			state = startupExecutableCandidateStateName(mountState)
			requerySucceeded = mountState != startupExecutableUncertain
		case startupAuxiliaryParentPermission:
			assessment, err := support.InspectPermissions(
				ctx,
				environment.Files,
				environment.Commands,
				expected.Path,
				startupParentDirectoryPermissionPolicy(),
			)
			if err == nil {
				state = startupPermissionAssessmentDigest(assessment)
				requerySucceeded = true
			}
		}
		current = append(current, startupAuxiliarySnapshot{
			Kind: expected.Kind, Path: expected.Path, State: state,
		})
		if !requerySucceeded {
			readErrorCount++
		}
		if state != expected.State {
			mismatchCount++
		}
		evidence = append(evidence, support.FactEvidence("systemd-start-auxiliary-snapshot-guard", map[string]any{
			"kind":                expected.Kind,
			"path_sha256":         pathDigest(expected.Path),
			"initial_state":       expected.State,
			"current_state":       state,
			"requery_succeeded":   requerySucceeded,
			"state_stable":        requerySucceeded && state == expected.State,
			"raw_result_redacted": true,
		}))
	}
	stable := mismatchCount == 0 && readErrorCount == 0
	return stable, startupAuxiliarySnapshotDigest(current), mismatchCount, readErrorCount, evidence
}

func startupAuxiliarySnapshotDigest(items []startupAuxiliarySnapshot) string {
	ordered := append([]startupAuxiliarySnapshot(nil), items...)
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].Kind != ordered[right].Kind {
			return ordered[left].Kind < ordered[right].Kind
		}
		if ordered[left].Path != ordered[right].Path {
			return ordered[left].Path < ordered[right].Path
		}
		return ordered[left].State < ordered[right].State
	})
	var builder strings.Builder
	for _, item := range ordered {
		builder.WriteString(item.Kind)
		builder.WriteByte(0)
		builder.WriteString(item.Path)
		builder.WriteByte(0)
		builder.WriteString(item.State)
		builder.WriteByte(0)
	}
	return bytesDigest([]byte(builder.String()))
}

func evaluateInetdPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"xinetd.service", "inetd.service"})
	if err != nil {
		return fileError("inetd_unit_inspection_failed", "inetd/xinetd 상태를 확인하지 못했습니다.", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"xinetd", "inetd"})
	if err != nil {
		return fileError("inetd_process_inspection_failed", "inetd/xinetd 상태를 확인하지 못했습니다.", err)
	}
	evidence := append(unitEvidence, processEvidence)
	installed := false
	active := len(processes) > 0
	xinetdManaged := false
	inetdManaged := false
	for _, unit := range units {
		installed = installed || support.UnitInstalled(unit)
		active = active || support.UnitActive(unit) || support.UnitEnabled(unit)
	}
	for _, unit := range units {
		if !support.UnitInstalled(unit) || (!support.UnitActive(unit) && !support.UnitEnabled(unit)) {
			continue
		}
		if unit.Name == "xinetd.service" {
			xinetdManaged = true
		} else if unit.Name == "inetd.service" {
			inetdManaged = true
		}
		spec := executor.Spec{Name: "systemctl", Arguments: []string{"show", "--no-pager", "--property=ExecStart", "--", unit.Name}, Timeout: 15 * time.Second, MaxOutput: 1 << 20}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return fileError("inetd_execstart_failed", "inetd/xinetd 실행 경로를 확인하지 못했습니다.", runErr)
		}
		evidence = append(evidence, privateCommandSummary("inetd-execstart-summary", spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return fileError("inetd_execstart_failed", "inetd/xinetd 실행 경로를 확인하지 못했습니다.", fmt.Errorf("unit=%s exit=%d truncated=%t", unit.Name, result.ExitCode, result.Truncated))
		}
		if unit.Name == "xinetd.service" && xinetdUsesCustomConfig(string(result.Stdout)) {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "inetd/xinetd가 사용자 지정 설정 경로로 실행되고 있습니다.", Expected: "실제로 로드되는 모든 설정 경로를 확인할 수 있어야 합니다.", Observed: "ExecStart에 custom config option이 있습니다.", Evidence: evidence}
		}
		if unit.Name == "inetd.service" {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "활성 inetd 제품의 positional 설정 파일과 디렉터리 의미를 확정할 수 없습니다.", Expected: "실제로 로드되는 모든 설정 경로를 확인할 수 있어야 합니다.", Observed: "inetd.service의 제품별 실행 인자를 추가로 확인해야 함", Evidence: evidence}
		}
	}
	for _, processName := range processes {
		if (processName == "xinetd" && !xinetdManaged) || (processName == "inetd" && !inetdManaged) {
			return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "systemd unit 밖에서 실행 중인 inetd/xinetd의 설정 경로를 확정할 수 없습니다.", Expected: "실제로 로드되는 모든 설정 경로를 확인할 수 있어야 합니다.", Observed: "process active, managed unit 없음", Evidence: evidence}
		}
	}
	paths, complete, pathEvidence, err := inetdConfigPaths(ctx, environment, xinetdManaged)
	if err != nil {
		return fileError("inetd_config_listing_failed", "inetd/xinetd 설정 파일을 열거하지 못했습니다.", err)
	}
	evidence = append(evidence, pathEvidence...)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	if !complete {
		unknowns = append(unknowns, "xinetd include/includedir 그래프를 완전히 해석할 수 없음")
	}
	existing := 0
	for _, configPath := range paths {
		assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, configPath, support.PermissionPolicy{
			AllowedUIDs: map[int]struct{}{0: {}}, AllowedMode: 0o600, AllowedTypes: map[string]struct{}{"regular": {}},
		})
		if err != nil {
			return fileError("inetd_permission_inspection_failed", "inetd/xinetd 설정 권한을 확인하지 못했습니다.", err)
		}
		if !assessment.Exists {
			continue
		}
		existing++
		evidence = append(evidence, assessment.Evidence...)
		for _, violation := range assessment.Violations {
			violations = append(violations, configPath+": "+violation)
		}
		for _, unknown := range assessment.Unknowns {
			unknowns = append(unknowns, configPath+": "+unknown)
		}
	}
	evidence = append(evidence, support.FactEvidence("inetd 설정 권한 파생 정보", map[string]any{"file_count": existing, "violation_count": len(violations), "unknown_count": len(unknowns)}))
	if !installed && !active && existing == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "inetd/xinetd와 설정 파일이 없습니다.", Expected: "사용되는 inetd/xinetd 설정에만 권한 기준을 적용합니다.", Observed: "unit, process, config 없음", Evidence: evidence}
	}
	if len(violations) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "inetd/xinetd 설정 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.", Expected: "사용되는 모든 설정 파일이 root 소유이고 0600 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("위반 %d건", len(violations)), Evidence: evidence}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "일부 inetd/xinetd 설정 파일의 실효 대상이나 권한을 확정할 수 없습니다.", Expected: "모든 설정 파일 유형과 ACL을 확인할 수 있어야 합니다.", Observed: fmt.Sprintf("확정 불가 %d건", len(unknowns)), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "inetd/xinetd 설정 파일의 소유자와 권한이 안전합니다.", Expected: "사용되는 모든 설정 파일이 root 소유이고 0600 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("설정 파일 %d개 확인, active=%t", existing, active), Evidence: evidence}
}

func evaluateSyslogPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"rsyslog.service"})
	if err != nil {
		return fileError("rsyslog_unit_inspection_failed", "rsyslog 상태를 확인하지 못했습니다.", err)
	}
	evidence := append([]model.Evidence(nil), unitEvidence...)
	if len(units) != 1 || !support.UnitInstalled(units[0]) || (!support.UnitActive(units[0]) && !support.UnitEnabled(units[0])) {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "활성 또는 부팅 활성 rsyslog 서비스가 없습니다.", Expected: "사용되는 rsyslog 설정에만 권한 기준을 적용합니다.", Observed: "journald-only 또는 rsyslog 비활성", Evidence: evidence}
	}
	unit := units[0]
	if unit.FragmentPath == "" || strings.TrimSpace(unit.DropInPaths) != "" || (!strings.HasPrefix(unit.FragmentPath, "/usr/lib/systemd/system/") && !strings.HasPrefix(unit.FragmentPath, "/lib/systemd/system/")) {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "비표준 rsyslog unit 또는 drop-in으로 설정 경로가 변경될 수 있습니다.", Expected: "실제로 로드되는 rsyslog 설정 경로를 확인할 수 있어야 합니다.", Observed: "custom unit or drop-in", Evidence: evidence}
	}
	rootConfig, startupPaths, startupEvidence, startupComplete, err := inspectRsyslogStartupPath(ctx, environment.Files)
	if err != nil {
		return fileError("rsyslog_startup_config_failed", "rsyslog 시작 설정을 해석하지 못했습니다.", err)
	}
	evidence = append(evidence, startupEvidence...)
	if !startupComplete {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "rsyslog 시작 옵션의 실효 설정 경로를 결정적으로 해석할 수 없습니다.", Expected: "EnvironmentFile과 -f 옵션에서 실제 설정 경로를 확정할 수 있어야 합니다.", Observed: "dynamic or conflicting rsyslog startup option", Evidence: evidence}
	}
	validationSpec := executor.Spec{Name: "rsyslogd", Arguments: []string{"-N1", "-f", rootConfig}, Timeout: 30 * time.Second, MaxOutput: 2 << 20}
	validation, err := environment.Commands.Run(ctx, validationSpec)
	if err != nil {
		return fileError("rsyslog_validation_failed", "rsyslog 설정 구문을 검증하지 못했습니다.", err)
	}
	evidence = append(evidence, support.CommandEvidence(validationSpec, validation))
	if validation.ExitCode != 0 || validation.Truncated {
		return fileError("rsyslog_validation_failed", "rsyslog 설정 구문을 검증하지 못했습니다.", fmt.Errorf("exit=%d truncated=%t", validation.ExitCode, validation.Truncated))
	}
	paths, complete, pathEvidence, err := collectRsyslogConfigPaths(ctx, environment, rootConfig)
	if err != nil {
		return fileError("rsyslog_include_failed", "rsyslog include 경로를 해석하지 못했습니다.", err)
	}
	evidence = append(evidence, pathEvidence...)
	paths = uniqueSortedPaths(append(paths, startupPaths...))
	if !complete {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "동적 또는 비표준 rsyslog include 경로를 완전히 해석할 수 없습니다.", Expected: "로드되는 모든 rsyslog 설정 파일을 열거할 수 있어야 합니다.", Observed: "unsupported include pattern", Evidence: evidence}
	}
	allowedOwners, ownerEvidence, err := allowedRsyslogOwners(ctx, environment)
	if err != nil {
		return fileError("rsyslog_owner_lookup_failed", "rsyslog 허용 소유자를 확인하지 못했습니다.", err)
	}
	evidence = append(evidence, ownerEvidence)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	for _, configPath := range paths {
		assessment, err := support.InspectPermissions(ctx, environment.Files, environment.Commands, configPath, support.PermissionPolicy{
			AllowedUIDs: allowedOwners, AllowedMode: 0o640, AllowedTypes: map[string]struct{}{"regular": {}},
		})
		if err != nil {
			return fileError("rsyslog_permission_inspection_failed", "rsyslog 설정 권한을 확인하지 못했습니다.", err)
		}
		if !assessment.Exists {
			return fileError("rsyslog_config_missing", "로드되는 rsyslog 설정 파일이 없습니다.", fmt.Errorf("%s", configPath))
		}
		evidence = append(evidence, assessment.Evidence...)
		for _, violation := range assessment.Violations {
			violations = append(violations, configPath+": "+violation)
		}
		for _, unknown := range assessment.Unknowns {
			unknowns = append(unknowns, configPath+": "+unknown)
		}
	}
	evidence = append(evidence, support.FactEvidence("rsyslog 설정 권한 파생 정보", map[string]any{"file_count": len(paths), "violation_count": len(violations), "unknown_count": len(unknowns)}))
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status: model.StatusFail, Summary: "로드되는 rsyslog 설정 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.",
			Expected: "모든 설정 파일이 root/bin/sys 소유이고 0640 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("위반 %d건", len(violations)),
			Details: []model.ResultDetail{{
				Label: "rsyslog 설정 권한", Current: strings.Join(uniqueSortedPaths(violations), ", "),
				Expected: "root/bin/sys 소유, 권한 0640 이내", Source: strings.Join(paths, ", "),
			}}, Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "일부 rsyslog 설정 파일의 유형 또는 ACL을 확정할 수 없습니다.", Expected: "모든 로드 파일의 소유자·권한·ACL을 확인할 수 있어야 합니다.", Observed: fmt.Sprintf("확정 불가 %d건", len(unknowns)), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "로드되는 rsyslog 설정 파일의 소유자와 권한이 안전합니다.", Expected: "모든 설정 파일이 root/bin/sys 소유이고 0640 허용 비트 이내여야 합니다.", Observed: fmt.Sprintf("설정 파일 %d개 확인", len(paths)), Evidence: evidence}
}

func validSystemdUnitToken(value string) bool {
	if value == "" || (strings.HasPrefix(value, "-") && value != "-.mount" && value != "-.slice") || !strings.Contains(value, ".") {
		return false
	}
	if strings.Contains(value, "\\") && strings.Contains(value, "@.") {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := rune(value[index])
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("@_.:-", character) {
			if character != '\\' || index+3 >= len(value) || value[index+1] != 'x' ||
				!isASCIIHex(value[index+2]) || !isASCIIHex(value[index+3]) {
				return false
			}
			index += 3
		}
	}
	return true
}

func isASCIIHex(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
}

func inspectStartupUnit(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
) ([]support.UnitState, []model.Evidence, error) {
	if !strings.Contains(unitName, "\\") && unitName != "-.slice" {
		return support.InspectUnits(ctx, environment, []string{unitName})
	}
	spec := executor.Spec{
		Name: "systemctl",
		Arguments: []string{
			"show", "--no-pager",
			"--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths",
			"--", unitName,
		},
		Timeout: 10 * time.Second, MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return nil, nil, err
	}
	evidence := []model.Evidence{support.CommandEvidence(spec, result)}
	if result.ExitCode != 0 || result.Truncated {
		return nil, evidence, fmt.Errorf("inspect systemd unit %s: exit=%d truncated=%t", unitName, result.ExitCode, result.Truncated)
	}
	properties, err := support.ParseKeyValueOutput(string(result.Stdout))
	if err != nil {
		return nil, evidence, err
	}
	if properties["LoadState"] == "" {
		return nil, evidence, fmt.Errorf("inspect systemd unit %s: LoadState is missing", unitName)
	}
	return []support.UnitState{{
		Name:           firstNonEmpty(properties["Id"], unitName),
		InspectionName: unitName,
		LoadState:      properties["LoadState"],
		ActiveState:    properties["ActiveState"],
		SubState:       properties["SubState"],
		UnitFileState:  properties["UnitFileState"],
		FragmentPath:   properties["FragmentPath"],
		DropInPaths:    properties["DropInPaths"],
	}}, evidence, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type startupSystemdUnitGuard struct {
	UnitName                  string
	InspectionName            string
	ConfigurationPaths        []string
	InitialStateDigest        string
	CheckExecutableProperties bool
	InitialExecutableDigest   string
	InitialUnknowns           []string
}

func appendUniqueStartupUnitGuard(
	guards []*startupSystemdUnitGuard,
	candidate *startupSystemdUnitGuard,
) []*startupSystemdUnitGuard {
	if candidate == nil {
		return guards
	}
	for _, guard := range guards {
		if guard == candidate {
			return guards
		}
	}
	return append(guards, candidate)
}

func startupUnitStateDigest(unit support.UnitState) string {
	var builder strings.Builder
	inScope := support.UnitActive(unit) || support.UnitEnabled(unit)
	unitPaths, unitPathReason := startupUnitPaths(unit)
	unitPathState := strings.Join(unitPaths, "\n")
	if unitPathReason != "" {
		unitPathState = strings.Join([]string{
			unitPathReason,
			strings.TrimSpace(unit.FragmentPath),
			strings.Join(uniqueSortedPaths(strings.Fields(unit.DropInPaths)), "\n"),
		}, "\x00")
	}
	fields := []struct {
		name  string
		value string
	}{
		{name: "name", value: unit.Name},
		{name: "inspection_name", value: unit.InspectionName},
		{name: "load_state", value: unit.LoadState},
		{name: "in_scope", value: strconv.FormatBool(inScope)},
		{name: "definitively_absent", value: strconv.FormatBool(startupUnitAbsent(unit))},
		{name: "unit_paths", value: unitPathState},
	}
	for _, field := range fields {
		builder.WriteString(field.name)
		builder.WriteByte(0)
		builder.WriteString(field.value)
		builder.WriteByte(0)
	}
	return bytesDigest([]byte(builder.String()))
}

func revalidateStartupSystemdUnitGuards(
	ctx context.Context,
	environment evaluator.Environment,
	guards []*startupSystemdUnitGuard,
) (map[*startupSystemdUnitGuard]bool, []model.Evidence) {
	validations := make(map[*startupSystemdUnitGuard]bool, len(guards))
	evidence := make([]model.Evidence, 0, len(guards)*3)
	for _, guard := range guards {
		if guard == nil {
			continue
		}
		currentStateDigest := bytesDigest(nil)
		currentExecutableDigest := bytesDigest(nil)
		stateRequerySucceeded := false
		executableRequerySucceeded := !guard.CheckExecutableProperties
		stateStable := false
		executableStable := !guard.CheckExecutableProperties

		states, stateEvidence, stateErr := inspectStartupUnit(ctx, environment, guard.UnitName)
		evidence = append(evidence, maskStartupUnitRevalidationEvidence(stateEvidence)...)
		if stateErr == nil && len(states) == 1 {
			stateRequerySucceeded = true
			currentStateDigest = startupUnitStateDigest(states[0])
			stateStable = currentStateDigest == guard.InitialStateDigest
		}

		if guard.CheckExecutableProperties {
			properties, executableEvidence, namespaceResolved, executableErr :=
				inspectStartupExecutableProperties(ctx, environment, guard.InspectionName)
			evidence = append(evidence, executableEvidence...)
			if executableErr == nil {
				executableRequerySucceeded = true
				currentExecutableDigest = startupExecutablePropertiesDigest(properties, namespaceResolved)
				executableStable = currentExecutableDigest == guard.InitialExecutableDigest
			}
		}

		stable := stateRequerySucceeded &&
			executableRequerySucceeded &&
			stateStable &&
			executableStable
		validations[guard] = stable
		evidence = append(evidence, support.FactEvidence("systemd-start-unit-snapshot-guard", map[string]any{
			"unit_name_sha256":              pathDigest(guard.UnitName),
			"state_guarded":                 true,
			"state_requery_succeeded":       stateRequerySucceeded,
			"initial_state_sha256":          guard.InitialStateDigest,
			"current_state_sha256":          currentStateDigest,
			"state_stable":                  stateStable,
			"executable_properties_guarded": guard.CheckExecutableProperties,
			"executable_requery_succeeded":  executableRequerySucceeded,
			"initial_executable_sha256":     guard.InitialExecutableDigest,
			"current_executable_sha256":     currentExecutableDigest,
			"executable_stable":             executableStable,
			"all_stable":                    stable,
		}))
	}
	return validations, evidence
}

func startupUnitGuardFinalValidations(
	guards []*startupSystemdUnitGuard,
	unitQueryValidations map[*startupSystemdUnitGuard]bool,
	pending []startupPendingPermissionAssessment,
	filesystemValidations map[*startupFilesystemSnapshot]startupFilesystemGuardValidation,
) (map[*startupSystemdUnitGuard]bool, []model.Evidence) {
	pathStable := make(map[string]bool, len(pending))
	for _, item := range pending {
		stable := item.GuardCaptureComplete && len(item.Guards) > 0
		for _, guard := range item.Guards {
			validation, exists := filesystemValidations[guard]
			if !exists || !validation.Stable {
				stable = false
			}
		}
		pathStable[item.Path] = stable
	}

	validations := make(map[*startupSystemdUnitGuard]bool, len(guards))
	evidence := make([]model.Evidence, 0, len(guards))
	for _, guard := range guards {
		if guard == nil {
			continue
		}
		stableConfigurationPaths := 0
		configurationStable := true
		for _, systemPath := range guard.ConfigurationPaths {
			if pathStable[systemPath] {
				stableConfigurationPaths++
				continue
			}
			configurationStable = false
		}
		queryStable := unitQueryValidations[guard]
		stable := queryStable && configurationStable
		validations[guard] = stable
		evidence = append(evidence, support.FactEvidence("systemd-start-unit-final-guard", map[string]any{
			"unit_name_sha256":              pathDigest(guard.UnitName),
			"unit_query_stable":             queryStable,
			"configuration_path_count":      len(guard.ConfigurationPaths),
			"stable_configuration_paths":    stableConfigurationPaths,
			"configuration_paths_sha256":    pathSetDigest(guard.ConfigurationPaths),
			"configuration_files_stable":    configurationStable,
			"permission_results_acceptable": stable,
		}))
	}
	return validations, evidence
}

func maskStartupUnitRevalidationEvidence(items []model.Evidence) []model.Evidence {
	masked := make([]model.Evidence, 0, len(items))
	for _, item := range items {
		if item.Command == nil {
			masked = append(masked, item)
			continue
		}
		command := item.Command
		masked = append(masked, support.FactEvidence("systemd-start-unit-revalidation-summary", map[string]any{
			"argument_count":    len(command.Arguments),
			"duration_ms":       command.DurationMS,
			"executable_sha256": pathDigest(command.Executable),
			"exit_code":         command.ExitCode,
			"stderr_bytes":      len(command.Stderr),
			"stderr_sha256":     bytesDigest([]byte(command.Stderr)),
			"stdout_bytes":      len(command.Stdout),
			"stdout_sha256":     bytesDigest([]byte(command.Stdout)),
			"timed_out":         command.TimedOut,
			"truncated":         command.Truncated,
		}))
	}
	return masked
}

func startupPermissionPathHasStableUnitGuard(
	guards []*startupSystemdUnitGuard,
	validations map[*startupSystemdUnitGuard]bool,
) bool {
	for _, guard := range guards {
		if validations[guard] {
			return true
		}
	}
	return false
}

func acceptStartupPermissionAssessments(
	pending []startupPendingPermissionAssessment,
	pathUnitGuards map[string][]*startupSystemdUnitGuard,
	validations map[*startupSystemdUnitGuard]bool,
	inventoryStable bool,
	legacyPaths map[string]*startupFilesystemSnapshot,
) ([]string, []string, error) {
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	for _, item := range pending {
		_, legacy := legacyPaths[item.Path]
		if !legacy {
			unitGuards := pathUnitGuards[item.Path]
			if len(unitGuards) == 0 {
				unknowns = append(unknowns, item.Path+": 연결된 systemd unit 상태를 다시 확인할 수 없음")
				continue
			}
			if !inventoryStable ||
				!startupPermissionPathHasStableUnitGuard(unitGuards, validations) {
				continue
			}
		}
		if !item.GuardsStable {
			unknowns = append(
				unknowns,
				item.Path+": 권한 검사 중 경로, 권한, ACL, mount 상태 또는 상위 디렉터리가 변경됨",
			)
			continue
		}
		if item.InspectErr != nil {
			return nil, unknowns, fmt.Errorf(
				"inspect startup permissions for %s: %w",
				item.Path,
				item.InspectErr,
			)
		}
		violations = append(violations, startupPermissionAssessmentViolations(item)...)
		unknowns = append(unknowns, startupPermissionAssessmentUnknowns(item)...)
	}
	return violations, unknowns, nil
}

func startupUnitAbsent(unit support.UnitState) bool {
	return unit.LoadState == "not-found" &&
		(unit.ActiveState == "" || unit.ActiveState == "inactive") &&
		(unit.SubState == "" || unit.SubState == "dead") &&
		unit.UnitFileState == "" &&
		strings.TrimSpace(unit.FragmentPath) == "" &&
		strings.TrimSpace(unit.DropInPaths) == ""
}

func startupUnitPaths(unit support.UnitState) ([]string, string) {
	fragment := strings.TrimSpace(unit.FragmentPath)
	paths := make([]string, 0, 1)
	if fragment != "" {
		if !validStartupUnitFilePath(fragment) {
			return nil, "잘못된 fragment 경로"
		}
		normalized := path.Clean(fragment)
		if !path.IsAbs(normalized) {
			return nil, "잘못된 fragment 경로"
		}
		paths = append(paths, normalized)
	} else if unit.LoadState == "not-found" {
		return nil, "unit을 로드할 수 없음"
	}
	for _, dropIn := range strings.Fields(unit.DropInPaths) {
		if !validStartupUnitFilePath(dropIn) || path.Clean(dropIn) != dropIn {
			return nil, "drop-in 경로를 결정적으로 해석할 수 없음"
		}
		paths = append(paths, dropIn)
	}
	sort.Strings(paths)
	return paths, ""
}

func validStartupUnitFilePath(value string) bool {
	if !path.IsAbs(value) || value == "/" || strings.ContainsAny(value, "\x00\r\n\"'`$%") {
		return false
	}
	for index := 0; index < len(value); index++ {
		switch {
		case value[index] == '\\':
			if index+3 >= len(value) || value[index+1] != 'x' ||
				!isASCIIHex(value[index+2]) || !isASCIIHex(value[index+3]) {
				return false
			}
			index += 3
		case value[index] < 0x20 || value[index] == 0x7f:
			return false
		}
	}
	return true
}

func startupExecutablePaths(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
) ([]string, bool, []model.Evidence, error) {
	guardedPaths, complete, evidence, _, err := startupExecutablePathsGuarded(ctx, environment, unitName)
	paths := make([]string, 0, len(guardedPaths))
	for _, guardedPath := range guardedPaths {
		paths = append(paths, guardedPath.Path)
	}
	return uniqueSortedPaths(paths), complete, evidence, err
}

var startupExecutablePropertyNames = []string{
	"LoadState",
	"Type",
	"RemainAfterExit",
	"ExecSearchPath",
	"Environment",
	"EnvironmentFiles",
	"PassEnvironment",
	"RootDirectory",
	"RootImage",
	"RootMStack",
	"BindPaths",
	"BindReadOnlyPaths",
	"TemporaryFileSystem",
	"MountImages",
	"ExtensionImages",
	"ExtensionDirectories",
	"PrivateTmp",
	"PrivateTmpEx",
	"PrivateDevices",
	"ProtectHome",
	"InaccessiblePaths",
	"ExecPaths",
	"NoExecPaths",
	"JoinsNamespaceOf",
	"ExecCondition",
	"ExecStartPre",
	"ExecStart",
	"ExecStartPost",
	"ExecStopPost",
}

func startupExecutablePathsGuarded(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
) ([]startupGuardedPath, bool, []model.Evidence, string, error) {
	properties, evidence, namespaceResolved, err := inspectStartupExecutableProperties(
		ctx,
		environment,
		unitName,
	)
	if err != nil {
		return nil, false, evidence, "", err
	}
	propertiesDigest := startupExecutablePropertiesDigest(properties, namespaceResolved)
	if !namespaceResolved {
		return nil, false, evidence, propertiesDigest, nil
	}
	commandProperties := []string{
		"ExecCondition",
		"ExecStartPre",
		"ExecStart",
		"ExecStartPost",
		"ExecStopPost",
	}
	hasCommands := false
	for _, property := range commandProperties {
		if strings.TrimSpace(properties[property]) != "" {
			hasCommands = true
			break
		}
	}
	if !hasCommands {
		return nil, properties["LoadState"] == "loaded", evidence, propertiesDigest, nil
	}
	if startupNamespaceAlwaysUncertain(properties) {
		return nil, false, evidence, propertiesDigest, nil
	}
	complete := true
	if strings.TrimSpace(properties["ExecStart"]) == "" &&
		!(properties["Type"] == "oneshot" && properties["RemainAfterExit"] == "yes") {
		complete = false
	}
	guardedPaths := make([]startupGuardedPath, 0)
	var searchPaths []string
	searchPathsLoaded := false
	for _, property := range commandProperties {
		value := properties[property]
		if strings.TrimSpace(value) == "" {
			continue
		}
		commands, parsed := parseSystemdCommands(value)
		complete = complete && parsed
		for _, command := range commands {
			configuredExecutable := command.Executable
			selectedExecutable := configuredExecutable
			finalPath := ""
			exists := false
			var snapshot *startupFilesystemSnapshot
			if path.IsAbs(configuredExecutable) {
				if !validStartupSystemPath(configuredExecutable) {
					complete = false
					continue
				}
				snapshot = newStartupFilesystemSnapshot()
				var (
					resolved        bool
					resolutionPaths []string
				)
				finalPath, exists, resolved, resolutionPaths = resolveStartupExecutableSnapshot(
					environment.Files,
					selectedExecutable,
					snapshot,
				)
				if resolved {
					resolved = captureStartupParentSnapshots(
						environment.Files,
						snapshot,
						append(
							[]string{configuredExecutable, selectedExecutable, finalPath},
							resolutionPaths...,
						)...,
					)
				}
				if !resolved {
					complete = false
					continue
				}
				if exists {
					directoryEvidence, traversable := inspectStartupExecutableDirectories(
						ctx,
						environment,
						resolutionPaths,
						snapshot,
					)
					evidence = append(evidence, directoryEvidence...)
					if !traversable {
						complete = false
						continue
					}
					state, verificationEvidence, _ := inspectStartupExecutableCandidateGuarded(
						ctx,
						environment,
						finalPath,
						false,
						snapshot,
					)
					evidence = append(evidence, verificationEvidence...)
					if state != startupExecutableUsable {
						complete = false
						continue
					}
				}
			} else {
				if !validStartupExecutableName(configuredExecutable) {
					complete = false
					continue
				}
				if startupEnvironmentMaySupplyPath(properties) {
					complete = false
					continue
				}
				if !searchPathsLoaded {
					searchPathsLoaded = true
					if strings.TrimSpace(properties["ExecSearchPath"]) != "" {
						searchPaths, parsed = parseStartupBinarySearchPath(properties["ExecSearchPath"])
					} else {
						var searchEvidence model.Evidence
						searchPaths, searchEvidence, parsed = startupBinarySearchPaths(ctx, environment)
						if searchEvidence.Source != "" {
							evidence = append(evidence, searchEvidence)
						}
					}
					complete = complete && parsed
				}
				if !parsed {
					complete = false
					continue
				}
				var resolutionEvidence []model.Evidence
				var resolved bool
				selectedExecutable, finalPath, _, snapshot, resolutionEvidence, resolved = firstStartupExecutable(
					ctx,
					environment,
					searchPaths,
					configuredExecutable,
				)
				evidence = append(evidence, resolutionEvidence...)
				if !resolved {
					complete = false
					continue
				}
				exists = true
				if startupSearchPathAffectedByPrivateNamespace(properties, searchPaths, selectedExecutable) {
					complete = false
					continue
				}
			}

			if startupPrivateNamespaceAffectsAny(
				properties,
				configuredExecutable,
				selectedExecutable,
				finalPath,
			) {
				complete = false
				continue
			}

			relation := startupResolutionRelation{
				ConfiguredExecutable: configuredExecutable,
				SelectedExecutable:   selectedExecutable,
				FinalExecutable:      finalPath,
				ExecutableExists:     exists,
			}
			commandPaths := []string{finalPath}
			if exists {
				shebangPaths, shebangEvidence, shebangComplete, directShebang :=
					inspectStartupShebangExecutionChain(
						ctx,
						environment,
						properties,
						finalPath,
						snapshot,
					)
				evidence = append(evidence, shebangEvidence...)
				commandPaths = append(commandPaths, shebangPaths...)
				complete = complete && shebangComplete

				originalDispatcher := isStartupDispatcher(path.Base(configuredExecutable))
				finalDispatcher := isStartupDispatcher(path.Base(finalPath))
				if shebangComplete && !directShebang &&
					(originalDispatcher || finalDispatcher) {
					switch {
					case isPythonDispatcher(path.Base(configuredExecutable)) ||
						isPythonDispatcher(path.Base(finalPath)):
						scriptPath, scriptResolved := startupPythonScriptPath(command)
						if !scriptResolved {
							complete = false
						} else {
							finalScriptPath, scriptExists, scriptComplete := resolveStartupPythonScript(
								environment.Files,
								scriptPath,
								snapshot,
							)
							relation.ScriptPath = scriptPath
							relation.FinalScriptPath = finalScriptPath
							relation.ScriptExists = scriptExists
							switch {
							case !scriptComplete:
								complete = false
							case startupPrivateNamespaceAffectsAny(properties, scriptPath, finalScriptPath):
								complete = false
							default:
								commandPaths = append(commandPaths, finalScriptPath)
							}
						}
					case isShellDispatcher(path.Base(configuredExecutable)) ||
						isShellDispatcher(path.Base(finalPath)):
						scriptPath, scriptResolved := startupShellScriptPath(command)
						if !scriptResolved {
							complete = false
						} else {
							finalScriptPath, scriptExists, scriptComplete := resolveStartupShellScript(
								environment.Files,
								scriptPath,
								snapshot,
							)
							relation.ScriptPath = scriptPath
							relation.FinalScriptPath = finalScriptPath
							relation.ScriptExists = scriptExists
							switch {
							case !scriptComplete:
								complete = false
							case startupPrivateNamespaceAffectsAny(properties, scriptPath, finalScriptPath):
								complete = false
							default:
								commandPaths = append(commandPaths, finalScriptPath)
							}
						}
					default:
						complete = false
					}
				}
			}
			resolutionEvidence, stable := startupExecutableResolutionEvidence(
				environment.Files,
				relation,
				snapshot,
			)
			evidence = append(evidence, resolutionEvidence)
			if !stable {
				complete = false
				continue
			}
			// Missing paths are retained for permission assessment, which
			// reports them as unresolved instead of an internal error.
			for _, commandPath := range commandPaths {
				guardedPaths = append(guardedPaths, startupGuardedPath{
					Path: commandPath, Snapshot: snapshot,
					AllowMissing: !exists &&
						command.IgnoreErrorsSeen &&
						command.IgnoreErrors,
				})
			}
		}
	}
	return guardedPaths, complete, evidence, propertiesDigest, nil
}

func inspectStartupExecutableProperties(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
) (map[string]string, []model.Evidence, bool, error) {
	spec := executor.Spec{
		Name: "systemctl",
		Arguments: []string{
			"show", "--no-pager",
			"--property=" + strings.Join(startupExecutablePropertyNames, ","),
			"--", unitName,
		},
		Timeout: 15 * time.Second, MaxOutput: 2 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := []model.Evidence{privateCommandSummary("systemd-start-command-summary", spec, result)}
	if err != nil {
		return nil, evidence, false, err
	}
	if result.ExitCode != 0 || result.Truncated {
		return nil, evidence, false, fmt.Errorf("systemctl show %s exit=%d truncated=%t", unitName, result.ExitCode, result.Truncated)
	}
	properties, err := support.ParseKeyValueOutput(string(result.Stdout))
	if err != nil {
		return nil, evidence, false, err
	}
	var namespaceEvidence []model.Evidence
	var namespaceResolved bool
	properties, namespaceEvidence, namespaceResolved = resolveStartupNamespaceProperties(ctx, environment, unitName, properties)
	evidence = append(evidence, namespaceEvidence...)
	return properties, evidence, namespaceResolved, nil
}

func startupExecutablePropertiesDigest(
	properties map[string]string,
	namespaceResolved bool,
) string {
	commandProperties := map[string]struct{}{
		"ExecCondition": {},
		"ExecStartPre":  {},
		"ExecStart":     {},
		"ExecStartPost": {},
		"ExecStopPost":  {},
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "namespace_resolved=%t\n", namespaceResolved)
	for _, property := range startupExecutablePropertyNames {
		value := properties[property]
		builder.WriteString(property)
		builder.WriteByte(0)
		if _, commandProperty := commandProperties[property]; !commandProperty {
			builder.WriteString(value)
			builder.WriteByte(0)
			continue
		}
		commands, complete := parseSystemdCommands(value)
		fmt.Fprintf(&builder, "present=%t\x00complete=%t\x00count=%d\x00", value != "", complete, len(commands))
		for _, command := range commands {
			builder.WriteString(command.Executable)
			builder.WriteByte(0)
			fmt.Fprintf(
				&builder,
				"ignore_errors_seen=%t\x00ignore_errors=%t\x00",
				command.IgnoreErrorsSeen,
				command.IgnoreErrors,
			)
			fmt.Fprintf(&builder, "%d\x00", len(command.Arguments))
			for _, argument := range command.Arguments {
				builder.WriteString(argument)
				builder.WriteByte(0)
			}
		}
	}
	return bytesDigest([]byte(builder.String()))
}

func expandStartupUnitDependencies(
	ctx context.Context,
	environment evaluator.Environment,
	initial []string,
) ([]string, []model.Evidence, []string, error) {
	units, evidence, unknowns, _, err := expandStartupUnitDependenciesGuarded(
		ctx,
		environment,
		initial,
	)
	return units, evidence, unknowns, err
}

type startupTemplateObservation struct {
	Name      string
	Canonical string
}

func startupUnitTemplateIdentity(
	unitName string,
) (string, string, bool) {
	for _, suffix := range []string{
		".service",
		".socket",
		".timer",
		".path",
		".mount",
		".automount",
		".target",
		".swap",
		".slice",
	} {
		if !strings.HasSuffix(unitName, suffix) {
			continue
		}
		stem := strings.TrimSuffix(unitName, suffix)
		at := strings.LastIndexByte(stem, '@')
		if at < 0 {
			return "", "", false
		}
		return stem[:at+1] + suffix, stem[at+1:], true
	}
	return "", "", false
}

func startupTemplateProbeUnitName(
	templateName string,
	instance string,
) (string, bool) {
	canonical, configuredInstance, templated :=
		startupUnitTemplateIdentity(templateName)
	if !templated || configuredInstance != "" ||
		canonical != templateName ||
		!validStartupExecutableName(instance) {
		return "", false
	}
	at := strings.LastIndexByte(templateName, '@')
	if at < 0 {
		return "", false
	}
	probeName := templateName[:at+1] + instance + templateName[at+1:]
	return probeName, validSystemdUnitToken(probeName)
}

func inspectStartupTemplateCanonicalName(
	ctx context.Context,
	environment evaluator.Environment,
	templateName string,
) (string, []model.Evidence, error) {
	const probeInstance = "openciip-audit"
	probeName, valid := startupTemplateProbeUnitName(
		templateName,
		probeInstance,
	)
	if !valid {
		return "", nil, fmt.Errorf(
			"invalid systemd template unit %s",
			templateName,
		)
	}
	spec := executor.Spec{
		Name: "systemctl",
		Arguments: []string{
			"show",
			"--no-pager",
			"--property=Id,LoadState",
			"--",
			probeName,
		},
		Timeout:   15 * time.Second,
		MaxOutput: 64 << 10,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := []model.Evidence{
		privateCommandSummary(
			"systemd-start-template-identity-summary",
			spec,
			result,
		),
	}
	if err != nil {
		return "", evidence, err
	}
	if result.ExitCode != 0 || result.TimedOut || result.Truncated {
		return "", evidence, fmt.Errorf(
			"systemctl template identity query %s exit=%d timed_out=%t truncated=%t",
			templateName,
			result.ExitCode,
			result.TimedOut,
			result.Truncated,
		)
	}
	values, err := support.ParseKeyValueOutput(string(result.Stdout))
	if err != nil {
		return "", evidence, err
	}
	if values["LoadState"] != "loaded" {
		return "", evidence, fmt.Errorf(
			"systemctl template identity query %s load_state=%s",
			templateName,
			values["LoadState"],
		)
	}
	canonical, returnedInstance, templated :=
		startupUnitTemplateIdentity(values["Id"])
	if !templated ||
		returnedInstance != probeInstance ||
		!validSystemdUnitToken(canonical) {
		return "", evidence, fmt.Errorf(
			"systemctl template identity query %s returned invalid Id",
			templateName,
		)
	}
	return canonical, evidence, nil
}

func expandStartupUnitDependenciesGuarded(
	ctx context.Context,
	environment evaluator.Environment,
	initial []string,
) ([]string, []model.Evidence, []string, string, error) {
	const maximumUnits = 4096
	queue := uniqueSortedPaths(initial)
	if len(queue) > maximumUnits {
		return nil, nil, nil, "", fmt.Errorf(
			"initial systemd startup unit count %d exceeds safe limit %d",
			len(queue),
			maximumUnits,
		)
	}
	seen := make(map[string]struct{}, len(queue))
	inspectable := make(map[string]struct{}, len(queue))
	for _, unitName := range queue {
		seen[unitName] = struct{}{}
		_, instance, templated := startupUnitTemplateIdentity(unitName)
		if !templated || instance != "" {
			inspectable[unitName] = struct{}{}
		}
	}
	evidence := make([]model.Evidence, 0)
	unknowns := make([]string, 0)
	dependencyRecords := make([]string, 0)
	templateObservations := make([]startupTemplateObservation, 0)
	for index := 0; index < len(queue); index++ {
		unitName := queue[index]
		if !startupRelevantUnitType(unitName) {
			continue
		}
		if _, instance, templated := startupUnitTemplateIdentity(unitName); templated &&
			instance == "" {
			canonicalTemplate, templateEvidence, err :=
				inspectStartupTemplateCanonicalName(ctx, environment, unitName)
			evidence = append(evidence, templateEvidence...)
			if err != nil {
				return nil, evidence, unknowns, "", err
			}
			templateObservations = append(
				templateObservations,
				startupTemplateObservation{
					Name:      unitName,
					Canonical: canonicalTemplate,
				},
			)
			continue
		}
		propertyNames := startupDependencyPropertyNames(unitName, true)
		queryPropertyNames := propertyNames
		runDependencyQuery := func() (executor.Result, error) {
			properties := strings.Join(queryPropertyNames, ",")
			spec := executor.Spec{
				Name: "systemctl", Arguments: []string{"show", "--no-pager", "--property=" + properties, "--", unitName},
				Timeout: 15 * time.Second, MaxOutput: 1 << 20,
			}
			result, err := environment.Commands.Run(ctx, spec)
			evidence = append(evidence, privateCommandSummary("systemd-start-dependency-summary", spec, result))
			return result, err
		}
		result, err := runDependencyQuery()
		if err != nil {
			return nil, evidence, unknowns, "", err
		}
		optionalSupported := map[string]bool{
			"Upholds":   true,
			"OnSuccess": true,
		}
		if startupOptionalDependencyPropertiesUnsupported(result) {
			// Upholds= and OnSuccess= were introduced in systemd 249. Retry
			// without optional properties so older managers retain coverage
			// for the relations they do support.
			optionalSupported["Upholds"] = false
			optionalSupported["OnSuccess"] = false
			queryPropertyNames = startupDependencyPropertyNames(unitName, false)
			result, err = runDependencyQuery()
			if err != nil {
				return nil, evidence, unknowns, "", err
			}
		}
		if result.ExitCode != 0 || result.TimedOut || result.Truncated {
			return nil, evidence, unknowns, "",
				fmt.Errorf(
					"systemctl dependency query %s exit=%d timed_out=%t truncated=%t",
					unitName,
					result.ExitCode,
					result.TimedOut,
					result.Truncated,
				)
		}
		values, err := support.ParseKeyValueOutput(string(result.Stdout))
		if err != nil {
			return nil, evidence, unknowns, "", err
		}
		for property := range optionalSupported {
			if _, exists := values[property]; !exists {
				optionalSupported[property] = false
			}
		}
		for _, property := range propertyNames {
			if supported, optional := optionalSupported[property]; optional && !supported {
				dependencyRecords = append(
					dependencyRecords,
					unitName+"\x00"+property+"\x00<unsupported>",
				)
				continue
			}
			value := strings.TrimSpace(values[property])
			if property != "Accept" {
				value = strings.Join(uniqueSortedPaths(strings.Fields(value)), "\n")
			} else {
				value = strings.ToLower(value)
			}
			dependencyRecords = append(
				dependencyRecords,
				unitName+"\x00"+property+"\x00"+value,
			)
		}
		triggerResolved := 0
		for _, property := range propertyNames {
			if property == "Accept" || property == "Service" {
				continue
			}
			value := values[property]
			for _, dependency := range strings.Fields(value) {
				if !startupRelevantUnitType(dependency) {
					continue
				}
				if !validSystemdUnitToken(dependency) {
					unknowns = append(unknowns, unitName+": 이스케이프되거나 비표준인 시작 의존 unit")
					continue
				}
				if property == "Triggers" {
					triggerResolved++
				}
				if _, exists := seen[dependency]; exists {
					continue
				}
				if len(seen) >= maximumUnits {
					unknowns = append(unknowns, "systemd 시작 의존 unit 수가 안전 한도를 초과함")
					continue
				}
				seen[dependency] = struct{}{}
				queue = append(queue, dependency)
				if _, instance, templated := startupUnitTemplateIdentity(dependency); !templated ||
					instance != "" {
					inspectable[dependency] = struct{}{}
				}
			}
		}
		if strings.HasSuffix(unitName, ".socket") && triggerResolved == 0 {
			dependency := strings.TrimSpace(values["Service"])
			if dependency == "" {
				if strings.EqualFold(values["Accept"], "yes") {
					dependency = strings.TrimSuffix(unitName, ".socket") + "@.service"
				} else {
					dependency = strings.TrimSuffix(unitName, ".socket") + ".service"
				}
			}
			if !validSystemdUnitToken(dependency) {
				unknowns = append(unknowns, unitName+": socket 활성화 대상 unit 이름을 해석할 수 없음")
			} else {
				if _, exists := seen[dependency]; !exists {
					if len(seen) >= maximumUnits {
						unknowns = append(unknowns, "systemd 시작 의존 unit 수가 안전 한도를 초과함")
					} else {
						seen[dependency] = struct{}{}
						queue = append(queue, dependency)
						if _, instance, templated := startupUnitTemplateIdentity(dependency); !templated ||
							instance != "" {
							inspectable[dependency] = struct{}{}
						}
					}
				}
			}
		}
		if (strings.HasSuffix(unitName, ".timer") || strings.HasSuffix(unitName, ".path")) &&
			triggerResolved == 0 {
			unknowns = append(unknowns, unitName+": 활성화 대상 unit을 확인할 수 없음")
		}
	}
	concreteTemplates := make(map[string]struct{})
	canonicalTemplates := make(map[string]string, len(templateObservations))
	for _, observation := range templateObservations {
		canonicalTemplates[observation.Name] = observation.Canonical
	}
	for unitName := range inspectable {
		templateName, instance, templated := startupUnitTemplateIdentity(unitName)
		if templated && instance != "" {
			if canonical, exists := canonicalTemplates[templateName]; exists {
				templateName = canonical
			}
			concreteTemplates[templateName] = struct{}{}
		}
	}
	for _, observation := range templateObservations {
		_, covered := concreteTemplates[observation.Canonical]
		dependencyRecords = append(
			dependencyRecords,
			observation.Name+"\x00TemplateCanonical\x00"+
				observation.Canonical+"\x00covered="+strconv.FormatBool(covered),
		)
		if !covered {
			unknowns = append(
				unknowns,
				observation.Name+": 활성화된 템플릿의 실제 인스턴스를 확인할 수 없음",
			)
		}
	}
	result := make([]string, 0, len(inspectable))
	for unitName := range inspectable {
		result = append(result, unitName)
	}
	sort.Strings(result)
	sort.Strings(dependencyRecords)
	return result, evidence, uniqueSortedPaths(unknowns),
		bytesDigest([]byte(strings.Join(dependencyRecords, "\n"))), nil
}

func startupDependencyPropertyNames(unitName string, includeOptionalDependencies bool) []string {
	propertyNames := []string{"Wants", "Requires", "BindsTo", "OnFailure"}
	if includeOptionalDependencies {
		propertyNames = append(propertyNames, "Upholds", "OnSuccess")
	}
	switch {
	case strings.HasSuffix(unitName, ".socket"):
		propertyNames = append(propertyNames, "Triggers", "Accept", "Service")
	case strings.HasSuffix(unitName, ".timer"), strings.HasSuffix(unitName, ".path"):
		propertyNames = append(propertyNames, "Triggers")
	}
	return propertyNames
}

func startupOptionalDependencyPropertiesUnsupported(result executor.Result) bool {
	if result.ExitCode == 0 || result.TimedOut || result.Truncated {
		return false
	}
	message := strings.ToLower(string(result.Stdout) + "\n" + string(result.Stderr))
	return strings.Contains(message, "unknown property") ||
		strings.Contains(message, "no such property") ||
		((strings.Contains(message, "upholds") ||
			strings.Contains(message, "onsuccess")) &&
			result.ExitCode == 1)
}

func startupRelevantUnitType(unitName string) bool {
	for _, suffix := range []string{".service", ".socket", ".timer", ".path", ".mount", ".automount", ".target", ".swap", ".slice"} {
		if strings.HasSuffix(unitName, suffix) {
			return true
		}
	}
	return false
}

type systemdCommand struct {
	Executable       string
	Arguments        []string
	IgnoreErrors     bool
	IgnoreErrorsSeen bool
}

func parseSystemdCommands(value string) ([]systemdCommand, bool) {
	fields := strings.Fields(value)
	commands := make([]systemdCommand, 0)
	complete := len(fields) > 0
	for index := 0; index < len(fields); {
		if fields[index] != "{" {
			return commands, false
		}
		index++
		command := systemdCommand{}
		pathSeen := false
		argumentsSeen := false
		ignoreErrorsSeen := false
		ignoreErrorsValid := true
		closed := false
		for index < len(fields) {
			if fields[index] == "}" {
				index++
				closed = true
				break
			}
			field := fields[index]
			switch {
			case strings.HasPrefix(field, "path="):
				if pathSeen {
					complete = false
				}
				pathSeen = true
				command.Executable = strings.TrimPrefix(field, "path=")
				index++
				if index >= len(fields) || fields[index] != ";" {
					return append(commands, command), false
				}
				index++
			case strings.HasPrefix(field, "argv[]="):
				if argumentsSeen {
					complete = false
				}
				argumentsSeen = true
				first := strings.TrimPrefix(field, "argv[]=")
				if first != "" {
					command.Arguments = append(command.Arguments, first)
				}
				index++
				for index < len(fields) && fields[index] != ";" {
					if fields[index] == "{" || fields[index] == "}" ||
						strings.ContainsAny(fields[index], "\x00\r\n") {
						return append(commands, command), false
					}
					command.Arguments = append(command.Arguments, fields[index])
					index++
				}
				if index >= len(fields) {
					return append(commands, command), false
				}
				index++
			case strings.HasPrefix(field, "ignore_errors="):
				if ignoreErrorsSeen {
					complete = false
					ignoreErrorsValid = false
				}
				ignoreErrorsSeen = true
				switch strings.TrimPrefix(field, "ignore_errors=") {
				case "yes":
					command.IgnoreErrors = true
				case "no":
					command.IgnoreErrors = false
				default:
					complete = false
					ignoreErrorsValid = false
				}
				index++
				if index >= len(fields) || fields[index] != ";" {
					return append(commands, command), false
				}
				index++
			default:
				for index < len(fields) && fields[index] != ";" && fields[index] != "}" {
					if fields[index] == "{" {
						return append(commands, command), false
					}
					index++
				}
				if index >= len(fields) {
					return append(commands, command), false
				}
				if fields[index] == ";" {
					index++
				}
			}
		}
		if !closed || !pathSeen || command.Executable == "" || !argumentsSeen || len(command.Arguments) == 0 {
			complete = false
		}
		command.IgnoreErrorsSeen = ignoreErrorsSeen && ignoreErrorsValid
		if pathSeen && command.Executable != "" {
			commands = append(commands, command)
		}
	}
	if len(commands) == 0 {
		complete = false
	}
	return commands, complete
}

func parseSystemdCommandPaths(value string) ([]string, bool) {
	commands, complete := parseSystemdCommands(value)
	paths := make([]string, 0)
	for _, command := range commands {
		executable := command.Executable
		if !validStartupSystemPath(executable) {
			complete = false
			continue
		}
		paths = append(paths, executable)
		if isStartupDispatcher(path.Base(executable)) {
			// The executable itself can be checked, but a secondary script or
			// dynamically selected program may be present in argv[].
			complete = false
		}
	}
	return uniqueSortedPaths(paths), complete
}

func validStartupSystemPath(value string) bool {
	return path.IsAbs(value) &&
		path.Clean(value) == value &&
		value != "/" &&
		!strings.ContainsAny(value, "\\\x00\r\n\"'`$%")
}

func validStartupExecutableName(value string) bool {
	if value == "" || strings.Contains(value, "/") {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && strings.ContainsRune("._+-", character)) {
			continue
		}
		return false
	}
	return true
}

func startupEnvironmentMaySupplyPath(properties map[string]string) bool {
	for _, property := range []string{"EnvironmentFile", "EnvironmentFiles"} {
		if strings.TrimSpace(properties[property]) != "" {
			return true
		}
	}
	for _, property := range []string{"Environment", "PassEnvironment"} {
		for _, field := range strings.Fields(properties[property]) {
			field = strings.Trim(field, "\"'")
			if field == "PATH" || strings.HasPrefix(field, "PATH=") {
				return true
			}
		}
	}
	return false
}

func resolveStartupNamespaceProperties(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
	properties map[string]string,
) (map[string]string, []model.Evidence, bool) {
	propertyTypes := map[string]string{
		"BindPaths":           "a(ssbt)",
		"BindReadOnlyPaths":   "a(ssbt)",
		"TemporaryFileSystem": "a(ss)",
		"MountImages":         "a(ssba(ss))",
		"ExtensionImages":     "a(sba(ss))",
	}
	needsFallback := false
	for property := range propertyTypes {
		if strings.TrimSpace(properties[property]) == "[unprintable]" {
			needsFallback = true
			break
		}
	}
	if !needsFallback {
		return properties, nil, true
	}
	if environment.Commands == nil || !environment.Commands.Available("busctl") {
		return properties, nil, false
	}
	objectPath, valid := systemdUnitObjectPath(unitName)
	if !valid {
		return properties, nil, false
	}
	evidence := make([]model.Evidence, 0)
	for property, expectedType := range propertyTypes {
		if strings.TrimSpace(properties[property]) != "[unprintable]" {
			continue
		}
		spec := executor.Spec{
			Name: "busctl",
			Arguments: []string{
				"get-property",
				"org.freedesktop.systemd1",
				objectPath,
				"org.freedesktop.systemd1.Service",
				property,
			},
			Timeout: 10 * time.Second, MaxOutput: 64 << 10,
		}
		result, err := environment.Commands.Run(ctx, spec)
		evidence = append(evidence, privateCommandSummary("systemd-start-namespace-property-summary", spec, result))
		if err != nil || result.ExitCode != 0 || result.TimedOut || result.Truncated || len(result.Stderr) != 0 {
			return properties, evidence, false
		}
		empty, parsed := parseBusctlArrayPresence(string(result.Stdout), expectedType)
		if !parsed {
			return properties, evidence, false
		}
		if empty {
			properties[property] = ""
		} else {
			properties[property] = "[nonempty]"
		}
	}
	return properties, evidence, true
}

func systemdUnitObjectPath(unitName string) (string, bool) {
	if !validSystemdUnitToken(unitName) {
		return "", false
	}
	var builder strings.Builder
	builder.WriteString("/org/freedesktop/systemd1/unit/")
	const hexadecimal = "0123456789abcdef"
	for index := 0; index < len(unitName); index++ {
		value := unitName[index]
		if (value >= 'a' && value <= 'z') ||
			(value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') {
			builder.WriteByte(value)
			continue
		}
		builder.WriteByte('_')
		builder.WriteByte(hexadecimal[value>>4])
		builder.WriteByte(hexadecimal[value&0x0f])
	}
	return builder.String(), true
}

func parseBusctlArrayPresence(output, expectedType string) (bool, bool) {
	if strings.Contains(output, "\r") {
		return false, false
	}
	output = strings.TrimSuffix(output, "\n")
	if output == "" || strings.Contains(output, "\n") {
		return false, false
	}
	fields := strings.Fields(output)
	if len(fields) < 2 || fields[0] != expectedType {
		return false, false
	}
	count, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return false, false
	}
	if count == 0 {
		return len(fields) == 2, len(fields) == 2
	}
	return false, len(fields) > 2
}

func startupNamespaceAlwaysUncertain(properties map[string]string) bool {
	for _, property := range []string{
		"RootDirectory",
		"RootImage",
		"RootMStack",
		"BindPaths",
		"BindReadOnlyPaths",
		"TemporaryFileSystem",
		"MountImages",
		"ExtensionImages",
		"ExtensionDirectories",
		"InaccessiblePaths",
		"ExecPaths",
		"NoExecPaths",
		"JoinsNamespaceOf",
	} {
		if strings.TrimSpace(properties[property]) != "" {
			return true
		}
	}
	return false
}

func startupSearchPathAffectedByPrivateNamespace(
	properties map[string]string,
	searchPaths []string,
	selectedExecutable string,
) bool {
	selectedDirectory := path.Dir(selectedExecutable)
	for _, directory := range searchPaths {
		if startupPrivateNamespaceAffectsAny(properties, directory) {
			return true
		}
		if directory == selectedDirectory {
			return false
		}
	}
	return true
}

func startupPrivateNamespaceAffectsAny(properties map[string]string, paths ...string) bool {
	privateTmp := startupBooleanPropertyEnabled(properties["PrivateTmp"]) ||
		startupBooleanPropertyEnabled(properties["PrivateTmpEx"])
	protectHome := startupBooleanPropertyEnabled(properties["ProtectHome"])
	privateDevices := startupBooleanPropertyEnabled(properties["PrivateDevices"])
	for _, candidate := range paths {
		if !path.IsAbs(candidate) {
			continue
		}
		if privateTmp && (pathWithin(candidate, "/tmp") || pathWithin(candidate, "/var/tmp")) {
			return true
		}
		if protectHome &&
			(pathWithin(candidate, "/home") || pathWithin(candidate, "/root") || pathWithin(candidate, "/run/user")) {
			return true
		}
		if privateDevices && pathWithin(candidate, "/dev") {
			return true
		}
	}
	return false
}

func startupBooleanPropertyEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "no", "false":
		return false
	default:
		return true
	}
}

func pathWithin(candidate, prefix string) bool {
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

func parseStartupBinarySearchPath(value string) ([]string, bool) {
	if value == "" || strings.TrimSpace(value) != value ||
		len(value) > 16<<10 || strings.ContainsAny(value, "\x00\r\n") {
		return nil, false
	}
	parts := strings.Split(value, ":")
	if len(parts) == 0 || len(parts) > 128 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(parts))
	for _, directory := range parts {
		if !validStartupSystemPath(directory) {
			return nil, false
		}
		if _, exists := seen[directory]; exists {
			return nil, false
		}
		seen[directory] = struct{}{}
	}
	return parts, true
}

func startupBinarySearchPaths(
	ctx context.Context,
	environment evaluator.Environment,
) ([]string, model.Evidence, bool) {
	if environment.Commands == nil || !environment.Commands.Available("systemd-path") {
		return nil, model.Evidence{}, false
	}
	spec := executor.Spec{
		Name: "systemd-path", Arguments: []string{"search-binaries-default"},
		Timeout: 10 * time.Second, MaxOutput: 64 << 10,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := privateCommandSummary("systemd-binary-search-path-summary", spec, result)
	if err != nil || result.ExitCode != 0 || result.TimedOut || result.Truncated || len(result.Stderr) != 0 {
		return nil, evidence, false
	}
	output := string(result.Stdout)
	if strings.Contains(output, "\r") {
		return nil, evidence, false
	}
	output = strings.TrimSuffix(output, "\n")
	if output == "" || strings.Contains(output, "\n") {
		return nil, evidence, false
	}
	searchPaths, complete := parseStartupBinarySearchPath(output)
	return searchPaths, evidence, complete
}

type startupExecutableCandidateState uint8

const (
	startupExecutableUncertain startupExecutableCandidateState = iota
	startupExecutableSkip
	startupExecutableUsable
)

type startupSnapshotRole uint8

const (
	startupSnapshotRoleChain startupSnapshotRole = 1 << iota
	startupSnapshotRoleParent
)

type startupPathSnapshot struct {
	Path     string
	Follow   bool
	Exists   bool
	Metadata system.FileMetadata
	Roles    startupSnapshotRole
}

type startupFilesystemSnapshot struct {
	Entries        []startupPathSnapshot
	Auxiliary      []startupAuxiliarySnapshot
	index          map[string]int
	auxiliaryIndex map[string]int
}

type startupGuardedPath struct {
	Path         string
	Snapshot     *startupFilesystemSnapshot
	AllowMissing bool
}

type startupResolutionRelation struct {
	ConfiguredExecutable string
	SelectedExecutable   string
	FinalExecutable      string
	ExecutableExists     bool
	ScriptPath           string
	FinalScriptPath      string
	ScriptExists         bool
}

type startupAuxiliarySnapshot struct {
	Kind  string
	Path  string
	State string
}

const (
	startupAuxiliaryExecutionACL     = "execution_acl"
	startupAuxiliaryExecutablePrefix = "executable_prefix"
	startupAuxiliaryMountExec        = "mount_execution"
	startupAuxiliaryParentPermission = "parent_permission"
)

func newStartupFilesystemSnapshot() *startupFilesystemSnapshot {
	return &startupFilesystemSnapshot{
		index:          make(map[string]int),
		auxiliaryIndex: make(map[string]int),
	}
}

func startupAuxiliaryState(usable bool) string {
	if usable {
		return "usable"
	}
	return "uncertain"
}

func startupExecutableCandidateStateName(state startupExecutableCandidateState) string {
	switch state {
	case startupExecutableSkip:
		return "skip"
	case startupExecutableUsable:
		return "usable"
	default:
		return "uncertain"
	}
}

func addStartupAuxiliarySnapshot(
	snapshot *startupFilesystemSnapshot,
	observation startupAuxiliarySnapshot,
) bool {
	if snapshot == nil {
		return true
	}
	if observation.Kind == "" ||
		(observation.Path != "/" && !validStartupSnapshotSystemPath(observation.Path)) ||
		observation.State == "" {
		return false
	}
	if snapshot.auxiliaryIndex == nil {
		snapshot.auxiliaryIndex = make(map[string]int)
	}
	key := observation.Kind + "\x00" + observation.Path
	if index, exists := snapshot.auxiliaryIndex[key]; exists {
		return snapshot.Auxiliary[index] == observation
	}
	snapshot.auxiliaryIndex[key] = len(snapshot.Auxiliary)
	snapshot.Auxiliary = append(snapshot.Auxiliary, observation)
	return true
}

func firstStartupExecutable(
	ctx context.Context,
	environment evaluator.Environment,
	searchPaths []string,
	executable string,
) (string, string, system.FileMetadata, *startupFilesystemSnapshot, []model.Evidence, bool) {
	if environment.Files == nil || !validStartupExecutableName(executable) {
		return "", "", system.FileMetadata{}, nil, nil, false
	}
	snapshot := newStartupFilesystemSnapshot()
	evidence := make([]model.Evidence, 0)
	for _, directory := range searchPaths {
		candidate := path.Join(directory, executable)
		if !validStartupSystemPath(candidate) {
			return "", "", system.FileMetadata{}, snapshot, evidence, false
		}
		finalPath, exists, complete, resolutionPaths := resolveStartupExecutableSnapshot(
			environment.Files,
			candidate,
			snapshot,
		)
		if !complete {
			return "", "", system.FileMetadata{}, snapshot, evidence, false
		}
		if !captureStartupParentSnapshots(
			environment.Files,
			snapshot,
			append([]string{candidate, finalPath}, resolutionPaths...)...,
		) {
			return "", "", system.FileMetadata{}, snapshot, evidence, false
		}
		if !exists {
			// A broken link is equivalent to ENOENT for systemd's executable
			// search, so the next ordered directory can be considered.
			continue
		}
		directoryEvidence, traversable := inspectStartupExecutableDirectories(
			ctx,
			environment,
			resolutionPaths,
			snapshot,
		)
		evidence = append(evidence, directoryEvidence...)
		if !traversable {
			return "", "", system.FileMetadata{}, snapshot, evidence, false
		}
		state, candidateEvidence, metadata := inspectStartupExecutableCandidateGuarded(
			ctx,
			environment,
			finalPath,
			true,
			snapshot,
		)
		evidence = append(evidence, candidateEvidence...)
		switch state {
		case startupExecutableSkip:
			// systemd continues after a non-regular target or a target with no
			// execute bits.
			continue
		case startupExecutableUsable:
			return candidate, finalPath, metadata, snapshot, evidence, true
		default:
			return "", "", system.FileMetadata{}, snapshot, evidence, false
		}
	}
	return "", "", system.FileMetadata{}, snapshot, evidence, false
}

func inspectStartupExecutableDirectories(
	ctx context.Context,
	environment evaluator.Environment,
	resolutionPaths []string,
	snapshot *startupFilesystemSnapshot,
) ([]model.Evidence, bool) {
	directories := make(map[string]struct{})
	for _, executablePath := range resolutionPaths {
		if !validStartupSystemPath(executablePath) {
			return nil, false
		}
		current := path.Dir(executablePath)
		for {
			directories[current] = struct{}{}
			if current == "/" {
				break
			}
			current = path.Dir(current)
		}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	sort.Slice(ordered, func(left, right int) bool {
		leftDepth := strings.Count(ordered[left], "/")
		rightDepth := strings.Count(ordered[right], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return ordered[left] < ordered[right]
	})
	evidence := make([]model.Evidence, 0, len(ordered))
	for _, directory := range ordered {
		lexicalMetadata, err := environment.Files.Lstat(directory)
		if err != nil {
			return evidence, false
		}
		metadata := lexicalMetadata
		if lexicalMetadata.FileType == "symlink" ||
			lexicalMetadata.Mode&os.ModeSymlink != 0 {
			metadata, err = environment.Files.Stat(directory)
			if err != nil {
				return evidence, false
			}
		}
		if metadata.FileType != "directory" || !metadata.Mode.IsDir() ||
			metadata.Mode.Perm()&0o111 != 0o111 {
			return evidence, false
		}
		acl, aclErr := support.InspectPOSIXACL(
			ctx,
			environment.Files,
			environment.Commands,
			directory,
			true,
			false,
			&metadata,
		)
		if acl.Evidence.Source != "" {
			evidence = append(evidence, acl.Evidence)
		}
		aclState := startupAuxiliaryState(
			aclErr == nil &&
				!(acl.Evidence.Kind == model.EvidenceCommand && strings.TrimSpace(acl.Content) == "") &&
				startupACLAllowsAllExecution(acl.Content),
		)
		if !addStartupAuxiliarySnapshot(
			snapshot,
			startupAuxiliarySnapshot{
				Kind: startupAuxiliaryExecutionACL, Path: directory, State: aclState,
			},
		) {
			return evidence, false
		}
		if aclState != "usable" ||
			(acl.Evidence.Kind == model.EvidenceCommand && strings.TrimSpace(acl.Content) == "") ||
			!startupACLAllowsAllExecution(acl.Content) {
			return evidence, false
		}
	}
	return evidence, true
}

func inspectStartupExecutableCandidate(
	ctx context.Context,
	environment evaluator.Environment,
	target string,
	checkMountExecution bool,
) (startupExecutableCandidateState, []model.Evidence, system.FileMetadata) {
	return inspectStartupExecutableCandidateGuarded(
		ctx,
		environment,
		target,
		checkMountExecution,
		nil,
	)
}

func inspectStartupExecutableCandidateGuarded(
	ctx context.Context,
	environment evaluator.Environment,
	target string,
	checkMountExecution bool,
	snapshot *startupFilesystemSnapshot,
) (startupExecutableCandidateState, []model.Evidence, system.FileMetadata) {
	metadata, err := environment.Files.Lstat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return startupExecutableSkip, nil, system.FileMetadata{}
		}
		return startupExecutableUncertain, nil, system.FileMetadata{}
	}
	if metadata.FileType != "regular" || !metadata.Mode.IsRegular() {
		return startupExecutableSkip, nil, metadata
	}
	executeBits := metadata.Mode.Perm() & 0o111
	if executeBits == 0 {
		return startupExecutableSkip, nil, metadata
	}
	if executeBits != 0o111 {
		// The effective service identity is needed to decide whether systemd's
		// access(X_OK) check succeeds for a partially executable file.
		return startupExecutableUncertain, nil, metadata
	}
	acl, aclErr := support.InspectPOSIXACL(
		ctx,
		environment.Files,
		environment.Commands,
		target,
		true,
		false,
		&metadata,
	)
	evidence := make([]model.Evidence, 0, 1)
	if acl.Evidence.Source != "" {
		evidence = append(evidence, acl.Evidence)
	}
	aclUsable := aclErr == nil &&
		!(acl.Evidence.Kind == model.EvidenceCommand && strings.TrimSpace(acl.Content) == "") &&
		startupACLAllowsAllExecution(acl.Content)
	if !addStartupAuxiliarySnapshot(
		snapshot,
		startupAuxiliarySnapshot{
			Kind: startupAuxiliaryExecutionACL, Path: target,
			State: startupAuxiliaryState(aclUsable),
		},
	) {
		return startupExecutableUncertain, evidence, metadata
	}
	if !aclUsable ||
		(acl.Evidence.Kind == model.EvidenceCommand && strings.TrimSpace(acl.Content) == "") ||
		!startupACLAllowsAllExecution(acl.Content) {
		return startupExecutableUncertain, evidence, metadata
	}
	if checkMountExecution {
		mountState, mountEvidence := inspectStartupExecutableMount(ctx, environment, target)
		if mountEvidence.Source != "" {
			evidence = append(evidence, mountEvidence)
		}
		if !addStartupAuxiliarySnapshot(
			snapshot,
			startupAuxiliarySnapshot{
				Kind: startupAuxiliaryMountExec, Path: target,
				State: startupExecutableCandidateStateName(mountState),
			},
		) {
			return startupExecutableUncertain, evidence, metadata
		}
		if mountState != startupExecutableUsable {
			return mountState, evidence, metadata
		}
	}
	return startupExecutableUsable, evidence, metadata
}

const (
	startupShebangPrefixReadLimit int64 = 256
	startupShebangMaximumChain          = 16
)

type startupShebangInfo struct {
	Present          bool
	Interpreter      string
	OptionalArgument string
}

type startupShebangWalker struct {
	ctx         context.Context
	environment evaluator.Environment
	properties  map[string]string
	snapshot    *startupFilesystemSnapshot
	seen        map[string]struct{}
	paths       []string
	evidence    []model.Evidence
	nodeCount   int
}

func inspectStartupShebangExecutionChain(
	ctx context.Context,
	environment evaluator.Environment,
	properties map[string]string,
	executable string,
	snapshot *startupFilesystemSnapshot,
) ([]string, []model.Evidence, bool, bool) {
	walker := &startupShebangWalker{
		ctx:         ctx,
		environment: environment,
		properties:  properties,
		snapshot:    snapshot,
		seen:        make(map[string]struct{}),
	}
	info, complete := walker.inspect(executable)
	return uniqueSortedPaths(walker.paths), walker.evidence, complete, info.Present
}

func (walker *startupShebangWalker) inspect(
	executable string,
) (startupShebangInfo, bool) {
	if walker == nil ||
		walker.environment.Files == nil ||
		walker.snapshot == nil ||
		!validStartupSystemPath(executable) ||
		walker.nodeCount >= startupShebangMaximumChain {
		return startupShebangInfo{}, false
	}
	if _, duplicate := walker.seen[executable]; duplicate {
		return startupShebangInfo{}, false
	}
	walker.seen[executable] = struct{}{}
	walker.nodeCount++

	info, evidence, complete := inspectStartupShebangFile(
		walker.ctx,
		walker.environment.Files,
		executable,
		walker.snapshot,
	)
	walker.evidence = append(walker.evidence, evidence)
	if !complete || !info.Present {
		return info, complete
	}

	interpreter, interpreterComplete := walker.guardTarget(info.Interpreter)
	if !interpreterComplete {
		return info, false
	}
	interpreterInfo, interpreterComplete := walker.inspect(interpreter)
	if !interpreterComplete {
		return info, false
	}

	if !interpreterInfo.Present {
		envSemantics := classifyStartupShebangEnv(
			info.Interpreter,
			interpreter,
		)
		if envSemantics == startupShebangEnvAmbiguous {
			return info, false
		}
		if envSemantics != startupShebangEnvCanonical {
			if info.OptionalArgument == "" ||
				safeStartupShebangOptionalFlag(info.OptionalArgument) {
				return info, true
			}
			return info, walker.guardPayload(info.OptionalArgument)
		}
		envExecutable, exact := startupEnvShebangExecutable(info.OptionalArgument)
		if !exact {
			return info, false
		}
		finalEnvExecutable, envExecutableComplete := walker.guardTarget(envExecutable)
		if !envExecutableComplete {
			return info, false
		}
		if _, envExecutableComplete = walker.inspect(finalEnvExecutable); !envExecutableComplete {
			return info, false
		}
	}
	return info, true
}

func (walker *startupShebangWalker) guardTarget(
	configuredPath string,
) (string, bool) {
	if !validStartupSystemPath(configuredPath) {
		return "", false
	}
	finalPath, exists, complete, resolutionPaths := resolveStartupExecutableSnapshot(
		walker.environment.Files,
		configuredPath,
		walker.snapshot,
	)
	if finalPath != "" {
		walker.paths = append(walker.paths, finalPath)
	}
	if complete {
		complete = captureStartupParentSnapshots(
			walker.environment.Files,
			walker.snapshot,
			append([]string{configuredPath, finalPath}, resolutionPaths...)...,
		)
	}
	if !complete || !exists ||
		startupPrivateNamespaceAffectsAny(
			walker.properties,
			append([]string{configuredPath, finalPath}, resolutionPaths...)...,
		) {
		return finalPath, false
	}
	directoryEvidence, traversable := inspectStartupExecutableDirectories(
		walker.ctx,
		walker.environment,
		resolutionPaths,
		walker.snapshot,
	)
	walker.evidence = append(walker.evidence, directoryEvidence...)
	if !traversable {
		return finalPath, false
	}
	state, candidateEvidence, _ := inspectStartupExecutableCandidateGuarded(
		walker.ctx,
		walker.environment,
		finalPath,
		false,
		walker.snapshot,
	)
	walker.evidence = append(walker.evidence, candidateEvidence...)
	return finalPath, state == startupExecutableUsable
}

func (walker *startupShebangWalker) guardPayload(
	configuredPath string,
) bool {
	if !path.IsAbs(configuredPath) || !validStartupSystemPath(configuredPath) {
		return false
	}
	finalPath, exists, complete, resolutionPaths := resolveStartupExecutableSnapshot(
		walker.environment.Files,
		configuredPath,
		walker.snapshot,
	)
	if finalPath != "" {
		walker.paths = append(walker.paths, finalPath)
	}
	if complete {
		complete = captureStartupParentSnapshots(
			walker.environment.Files,
			walker.snapshot,
			append([]string{configuredPath, finalPath}, resolutionPaths...)...,
		)
	}
	if !complete || !exists ||
		startupPrivateNamespaceAffectsAny(
			walker.properties,
			append([]string{configuredPath, finalPath}, resolutionPaths...)...,
		) {
		return false
	}
	metadata, finalExists, observed := startupSnapshotLstat(
		walker.snapshot,
		finalPath,
	)
	return observed &&
		finalExists &&
		metadata.FileType == "regular" &&
		metadata.Mode.IsRegular()
}

func inspectStartupShebangFile(
	ctx context.Context,
	files system.Reader,
	executable string,
	snapshot *startupFilesystemSnapshot,
) (startupShebangInfo, model.Evidence, bool) {
	expectedMetadata, exists, observed := startupSnapshotLstat(snapshot, executable)
	if files == nil || !observed || !exists ||
		expectedMetadata.FileType != "regular" ||
		!expectedMetadata.Mode.IsRegular() {
		return startupShebangInfo{}, startupShebangInspectionEvidence(
			executable,
			0,
			false,
			false,
			false,
			false,
			false,
			false,
			"",
		), false
	}

	data, metadata, err := readStartupExecutablePrefix(ctx, files, executable)
	metadataStable := err == nil &&
		sameStartupPathSnapshot(expectedMetadata, metadata)
	if err != nil || !metadataStable {
		return startupShebangInfo{}, startupShebangInspectionEvidence(
			executable,
			len(data),
			err == nil,
			metadataStable,
			false,
			false,
			false,
			errors.Is(err, system.ErrReadLimit),
			"",
		), false
	}

	contentState := startupExecutablePrefixState(data, metadata)
	if !addStartupAuxiliarySnapshot(
		snapshot,
		startupAuxiliarySnapshot{
			Kind:  startupAuxiliaryExecutablePrefix,
			Path:  executable,
			State: contentState,
		},
	) {
		return startupShebangInfo{}, startupShebangInspectionEvidence(
			executable,
			len(data),
			true,
			true,
			false,
			false,
			false,
			false,
			contentState,
		), false
	}

	info, parsed := parseStartupShebang(data)
	return info, startupShebangInspectionEvidence(
		executable,
		len(data),
		true,
		true,
		info.Present,
		parsed,
		info.OptionalArgument != "",
		false,
		contentState,
	), parsed
}

func readStartupExecutablePrefix(
	ctx context.Context,
	files system.Reader,
	executable string,
) ([]byte, system.FileMetadata, error) {
	if files == nil {
		return nil, system.FileMetadata{}, errors.New("startup file reader is unavailable")
	}
	if reader, ok := files.(system.BoundedFilePrefixReader); ok {
		return reader.ReadFilePrefix(
			ctx,
			executable,
			startupShebangPrefixReadLimit,
		)
	}
	// Lightweight test and embedded readers may not expose the optional prefix
	// capability. Their complete file must still fit the same strict bound.
	return files.ReadFile(ctx, executable, startupShebangPrefixReadLimit)
}

func startupShebangInspectionEvidence(
	executable string,
	contentBytes int,
	readSucceeded bool,
	metadataStable bool,
	shebangPresent bool,
	parseSupported bool,
	optionalArgumentPresent bool,
	readLimitExceeded bool,
	contentState string,
) model.Evidence {
	return support.FactEvidence("systemd-start-shebang-inspection-summary", map[string]any{
		"path_sha256":                pathDigest(executable),
		"content_bytes":              contentBytes,
		"bounded_read_limit_bytes":   startupShebangPrefixReadLimit,
		"read_succeeded":             readSucceeded,
		"metadata_matches_snapshot":  metadataStable,
		"shebang_present":            shebangPresent,
		"parse_supported":            parseSupported,
		"optional_argument_present":  optionalArgumentPresent,
		"read_limit_exceeded":        readLimitExceeded,
		"prefix_snapshot_sha256":     contentState,
		"raw_file_content_redacted":  true,
		"interpreter_path_redacted":  true,
		"optional_argument_redacted": true,
	})
}

func startupExecutablePrefixState(
	data []byte,
	metadata system.FileMetadata,
) string {
	return bytesDigest([]byte(fmt.Sprintf(
		"path=%s\x00type=%s\x00mode=%d\x00size=%d\x00uid=%d\x00gid=%d\x00device=%d\x00inode=%d\x00mtime=%d\x00content=%s",
		metadata.Path,
		metadata.FileType,
		metadata.Mode,
		metadata.Size,
		metadata.UID,
		metadata.GID,
		metadata.Device,
		metadata.Inode,
		metadata.ModTime.UnixNano(),
		bytesDigest(data),
	)))
}

func parseStartupShebang(data []byte) (startupShebangInfo, bool) {
	if len(data) < 2 || data[0] != '#' || data[1] != '!' {
		return startupShebangInfo{}, true
	}
	info := startupShebangInfo{Present: true}
	prefixLength := len(data)
	if prefixLength > int(startupShebangPrefixReadLimit) {
		prefixLength = int(startupShebangPrefixReadLimit)
	}
	lineEnd := strings.IndexByte(string(data[:prefixLength]), '\n')
	if lineEnd < 0 {
		return info, false
	}
	line := string(data[2:lineEnd])
	if strings.ContainsAny(line, "\x00\r") {
		return info, false
	}
	line = strings.Trim(line, " \t")
	if line == "" {
		return info, false
	}
	interpreterEnd := len(line)
	if separator := strings.IndexAny(line, " \t"); separator >= 0 {
		interpreterEnd = separator
	}
	info.Interpreter = line[:interpreterEnd]
	info.OptionalArgument = strings.Trim(line[interpreterEnd:], " \t")
	if !validStartupSystemPath(info.Interpreter) {
		return info, false
	}
	return info, true
}

type startupShebangEnvSemantics uint8

const (
	startupShebangNotEnv startupShebangEnvSemantics = iota
	startupShebangEnvCanonical
	startupShebangEnvAmbiguous
)

func classifyStartupShebangEnv(
	configuredPath string,
	finalPath string,
) startupShebangEnvSemantics {
	for _, candidate := range []string{configuredPath, finalPath} {
		switch candidate {
		case "/bin/env", "/usr/bin/env":
			return startupShebangEnvCanonical
		}
	}
	if path.Base(configuredPath) == "env" || path.Base(finalPath) == "env" {
		return startupShebangEnvAmbiguous
	}
	return startupShebangNotEnv
}

func startupEnvShebangExecutable(optionalArgument string) (string, bool) {
	if optionalArgument == "" ||
		!path.IsAbs(optionalArgument) ||
		!validStartupSystemPath(optionalArgument) {
		return "", false
	}
	return optionalArgument, true
}

func safeStartupShebangOptionalFlag(optionalArgument string) bool {
	if optionalArgument == "--" {
		return true
	}
	if len(optionalArgument) < 2 ||
		optionalArgument[0] != '-' ||
		optionalArgument[1] == '-' {
		return false
	}
	for _, character := range optionalArgument[1:] {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func inspectStartupExecutableMount(
	ctx context.Context,
	environment evaluator.Environment,
	target string,
) (startupExecutableCandidateState, model.Evidence) {
	if environment.Commands == nil || !environment.Commands.Available("findmnt") {
		return startupExecutableUncertain, model.Evidence{}
	}
	spec := executor.Spec{
		Name: "findmnt", Arguments: []string{"--noheadings", "--output", "OPTIONS", "--target", target},
		Timeout: 10 * time.Second, MaxOutput: 64 << 10,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := privateCommandSummary("systemd-start-executable-mount-summary", spec, result)
	if err != nil || result.ExitCode != 0 || result.TimedOut || result.Truncated || len(result.Stderr) != 0 {
		return startupExecutableUncertain, evidence
	}
	output := string(result.Stdout)
	if strings.Contains(output, "\r") {
		return startupExecutableUncertain, evidence
	}
	output = strings.TrimSuffix(output, "\n")
	if output == "" || strings.Contains(output, "\n") {
		return startupExecutableUncertain, evidence
	}
	for _, option := range strings.Split(output, ",") {
		option = strings.TrimSpace(option)
		if option == "" || strings.ContainsAny(option, "\x00\r\n") {
			return startupExecutableUncertain, evidence
		}
		if option == "noexec" {
			return startupExecutableSkip, evidence
		}
	}
	return startupExecutableUsable, evidence
}

func startupACLAllowsAllExecution(content string) bool {
	baseEntries := map[string]bool{
		"user":  false,
		"group": false,
		"other": false,
	}
	seenEntries := make(map[string]struct{})
	hasEntry := false
	hasNamedEntry := false
	hasMask := false
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hasEntry = true
		if strings.HasPrefix(line, "default:") {
			return false
		}
		mainPart, comment, _ := strings.Cut(line, "#")
		fields := strings.Split(strings.TrimSpace(mainPart), ":")
		if len(fields) != 3 {
			return false
		}
		entryType := strings.TrimSpace(fields[0])
		qualifier := strings.TrimSpace(fields[1])
		switch entryType {
		case "user", "group", "mask", "other":
		default:
			return false
		}
		if (entryType == "mask" || entryType == "other") && qualifier != "" {
			return false
		}
		entryKey := entryType + ":" + qualifier
		if _, duplicate := seenEntries[entryKey]; duplicate {
			return false
		}
		seenEntries[entryKey] = struct{}{}
		switch {
		case entryType == "user" && qualifier == "":
			baseEntries["user"] = true
		case entryType == "group" && qualifier == "":
			baseEntries["group"] = true
		case entryType == "other":
			baseEntries["other"] = true
		case entryType == "mask":
			hasMask = true
		case entryType == "user" || entryType == "group":
			hasNamedEntry = true
		}
		permissions := strings.TrimSpace(fields[2])
		if len(permissions) != 3 || permissions[2] != 'x' {
			return false
		}
		effective := strings.TrimSpace(comment)
		if effective != "" {
			if !strings.HasPrefix(effective, "effective:") {
				return false
			}
			effectivePermissions := strings.TrimSpace(strings.TrimPrefix(effective, "effective:"))
			if len(effectivePermissions) != 3 || effectivePermissions[2] != 'x' {
				return false
			}
		}
	}
	if !hasEntry {
		// Native xattr inspection represents a file without an extended access
		// ACL as empty content; the already-checked mode bits are authoritative.
		return true
	}
	if !baseEntries["user"] || !baseEntries["group"] || !baseEntries["other"] {
		return false
	}
	if hasNamedEntry && !hasMask {
		return false
	}
	return true
}

func startupExecutableResolutionEvidence(
	files system.Reader,
	relation startupResolutionRelation,
	snapshot *startupFilesystemSnapshot,
) (model.Evidence, bool) {
	stable, currentDigest, mismatchCount, readErrorCount := revalidateStartupFilesystemSnapshot(files, snapshot)
	facts := map[string]any{
		"configured_executable_sha256": pathDigest(relation.ConfiguredExecutable),
		"selected_path_sha256":         pathDigest(relation.SelectedExecutable),
		"final_path_sha256":            pathDigest(relation.FinalExecutable),
		"bare_name":                    !path.IsAbs(relation.ConfiguredExecutable),
		"configured_is_selected":       relation.ConfiguredExecutable == relation.SelectedExecutable,
		"selected_is_final":            relation.SelectedExecutable == relation.FinalExecutable,
		"symlink_resolved":             relation.SelectedExecutable != relation.FinalExecutable,
		"final_exists":                 relation.ExecutableExists,
		"snapshot_stable":              stable,
		"snapshot_sha256":              startupFilesystemSnapshotDigest(snapshot),
		"current_snapshot_sha256":      currentDigest,
		"snapshot_mismatch_count":      mismatchCount,
		"snapshot_read_error_count":    readErrorCount,
	}
	entryCount := 0
	chainCount := 0
	parentCount := 0
	followedParentCount := 0
	existingCount := 0
	missingCount := 0
	symlinkCount := 0
	directoryCount := 0
	regularCount := 0
	if snapshot != nil {
		entryCount = len(snapshot.Entries)
		for _, entry := range snapshot.Entries {
			if entry.Roles&startupSnapshotRoleChain != 0 {
				chainCount++
			}
			if entry.Roles&startupSnapshotRoleParent != 0 {
				parentCount++
				if entry.Follow {
					followedParentCount++
				}
			}
			if !entry.Exists {
				missingCount++
				continue
			}
			existingCount++
			switch entry.Metadata.FileType {
			case "symlink":
				symlinkCount++
			case "directory":
				directoryCount++
			case "regular":
				regularCount++
			}
		}
	}
	facts["snapshot_entry_count"] = entryCount
	facts["chain_snapshot_count"] = chainCount
	facts["parent_snapshot_count"] = parentCount
	facts["followed_parent_snapshot_count"] = followedParentCount
	facts["existing_snapshot_count"] = existingCount
	facts["missing_snapshot_count"] = missingCount
	facts["symlink_snapshot_count"] = symlinkCount
	facts["directory_snapshot_count"] = directoryCount
	facts["regular_snapshot_count"] = regularCount
	if relation.ScriptPath != "" {
		facts["script_path_sha256"] = pathDigest(relation.ScriptPath)
		facts["final_script_path_sha256"] = pathDigest(relation.FinalScriptPath)
		facts["script_is_final"] = relation.ScriptPath == relation.FinalScriptPath
		facts["script_exists"] = relation.ScriptExists
	}
	return support.FactEvidence("systemd-start-executable-resolution", facts), stable
}

func sameStartupPathSnapshot(left, right system.FileMetadata) bool {
	if left.Path != right.Path ||
		left.FileType != right.FileType ||
		left.Mode != right.Mode ||
		left.Size != right.Size ||
		left.UID != right.UID ||
		left.GID != right.GID ||
		left.Device != right.Device ||
		left.Inode != right.Inode ||
		left.LinkTarget != right.LinkTarget ||
		!left.ModTime.Equal(right.ModTime) {
		return false
	}
	return true
}

func resolveStartupExecutable(files system.Reader, executable string) (string, bool, bool) {
	finalPath, exists, complete, _ := resolveStartupExecutableChain(files, executable)
	return finalPath, exists, complete
}

func resolveStartupExecutableChain(files system.Reader, executable string) (string, bool, bool, []string) {
	return resolveStartupExecutableSnapshot(files, executable, newStartupFilesystemSnapshot())
}

func resolveStartupExecutableSnapshot(
	files system.Reader,
	executable string,
	snapshot *startupFilesystemSnapshot,
) (string, bool, bool, []string) {
	if !validStartupSystemPath(executable) {
		return "", false, false, nil
	}
	return resolveStartupGuardPathSnapshot(files, executable, snapshot)
}

func resolveStartupGuardPathSnapshot(
	files system.Reader,
	systemPath string,
	snapshot *startupFilesystemSnapshot,
) (string, bool, bool, []string) {
	const (
		maximumSymlinkDepth       = 40
		maximumResolvedComponents = 4096
		maximumResolvedPathLength = 64 << 10
	)
	if files == nil || snapshot == nil || !validStartupSnapshotSystemPath(systemPath) {
		return "", false, false, nil
	}
	current := systemPath
	seen := make(map[string]struct{}, maximumSymlinkDepth)
	resolutionPaths := make([]string, 0, 4)
	symlinkDepth := 0
	for {
		if len(current) > maximumResolvedPathLength ||
			!validStartupSnapshotSystemPath(current) {
			return "", false, false, resolutionPaths
		}
		if len(resolutionPaths) == 0 ||
			resolutionPaths[len(resolutionPaths)-1] != current {
			resolutionPaths = append(resolutionPaths, current)
		}

		metadata, err := files.Lstat(current)
		currentExists := err == nil
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) ||
				!addStartupSnapshotObservation(
					snapshot,
					startupPathSnapshot{
						Path: current, Exists: false, Roles: startupSnapshotRoleChain,
					},
				) {
				return "", false, false, resolutionPaths
			}
		} else if !addStartupSnapshotObservation(snapshot, startupPathSnapshot{
			Path: current, Exists: true, Metadata: metadata, Roles: startupSnapshotRoleChain,
		}) {
			return "", false, false, resolutionPaths
		}

		if currentExists &&
			(metadata.FileType == "symlink" || metadata.Mode&os.ModeSymlink != 0) {
			if symlinkDepth >= maximumSymlinkDepth {
				return "", false, false, resolutionPaths
			}
			if _, exists := seen[current]; exists {
				return "", false, false, resolutionPaths
			}
			seen[current] = struct{}{}
			symlinkDepth++
			target := metadata.LinkTarget
			if target == "" || strings.ContainsAny(target, "\\\x00\r\n\"'`$%") {
				return "", false, false, resolutionPaths
			}
			if path.IsAbs(target) {
				current = path.Clean(target)
			} else {
				current = path.Clean(path.Join(path.Dir(current), target))
			}
			continue
		}

		components := strings.Split(strings.TrimPrefix(current, "/"), "/")
		if len(components) == 0 || len(components) > maximumResolvedComponents {
			return "", false, false, resolutionPaths
		}
		parent := "/"
		rewritten := false
		for index := 0; index < len(components)-1; index++ {
			candidate := path.Join(parent, components[index])
			parentMetadata, parentErr := files.Lstat(candidate)
			if parentErr != nil {
				if !errors.Is(parentErr, os.ErrNotExist) ||
					!addStartupSnapshotObservation(
						snapshot,
						startupPathSnapshot{
							Path: candidate, Exists: false,
							Roles: startupSnapshotRoleChain,
						},
					) {
					return "", false, false, resolutionPaths
				}
				return current, false, true, resolutionPaths
			}
			if !addStartupSnapshotObservation(snapshot, startupPathSnapshot{
				Path: candidate, Exists: true, Metadata: parentMetadata,
				Roles: startupSnapshotRoleChain,
			}) {
				return "", false, false, resolutionPaths
			}
			if parentMetadata.FileType != "symlink" &&
				parentMetadata.Mode&os.ModeSymlink == 0 {
				if parentMetadata.FileType != "directory" ||
					!parentMetadata.Mode.IsDir() {
					return "", false, false, resolutionPaths
				}
				parent = candidate
				continue
			}
			if symlinkDepth >= maximumSymlinkDepth {
				return "", false, false, resolutionPaths
			}
			if _, exists := seen[candidate]; exists {
				return "", false, false, resolutionPaths
			}
			seen[candidate] = struct{}{}
			symlinkDepth++
			target := parentMetadata.LinkTarget
			if target == "" || strings.ContainsAny(target, "\\\x00\r\n\"'`$%") {
				return "", false, false, resolutionPaths
			}
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(candidate), target)
			}
			nextParts := append(
				[]string{path.Clean(target)},
				components[index+1:]...,
			)
			current = path.Clean(path.Join(nextParts...))
			rewritten = true
			break
		}
		if rewritten {
			continue
		}
		if !currentExists {
			return current, false, true, resolutionPaths
		}
		return current, true, true, resolutionPaths
	}
}

func validStartupSnapshotSystemPath(value string) bool {
	if !path.IsAbs(value) || path.Clean(value) != value || value == "/" ||
		strings.ContainsAny(value, "\x00\r\n\"'`$%") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			if value[index] < 0x20 || value[index] == 0x7f {
				return false
			}
			continue
		}
		if index+3 >= len(value) || value[index+1] != 'x' ||
			!isASCIIHex(value[index+2]) || !isASCIIHex(value[index+3]) {
			return false
		}
		index += 3
	}
	return true
}

func captureStartupPermissionFilesystemSnapshot(
	files system.Reader,
	systemPath string,
) (*startupFilesystemSnapshot, bool) {
	snapshot := newStartupFilesystemSnapshot()
	finalPath, _, complete, resolutionPaths := resolveStartupGuardPathSnapshot(
		files,
		systemPath,
		snapshot,
	)
	if !complete {
		return snapshot, false
	}
	complete = captureStartupParentSnapshots(
		files,
		snapshot,
		append([]string{systemPath, finalPath}, resolutionPaths...)...,
	)
	return snapshot, complete
}

type startupInactiveLegacyGuard struct {
	Path     string
	Snapshot *startupFilesystemSnapshot
}

func inspectStartupLegacyPathGuards(
	files system.Reader,
) (
	map[string]*startupFilesystemSnapshot,
	[]startupInactiveLegacyGuard,
	[]model.Evidence,
	[]string,
) {
	active := make(map[string]*startupFilesystemSnapshot)
	inactive := make([]startupInactiveLegacyGuard, 0, 2)
	unknowns := make([]string, 0)
	for _, legacyPath := range []string{"/etc/rc.d/rc.local", "/etc/rc.local"} {
		snapshot, complete := captureStartupPermissionFilesystemSnapshot(files, legacyPath)
		if !complete {
			unknowns = append(unknowns, legacyPath+": legacy 시작 경로의 초기 상태를 고정할 수 없음")
			continue
		}
		metadata, exists, observed := startupSnapshotLstat(snapshot, legacyPath)
		if !observed {
			unknowns = append(unknowns, legacyPath+": legacy 시작 경로의 초기 상태를 확인할 수 없음")
			continue
		}
		if exists && metadata.Mode.Perm()&0o111 != 0 {
			active[legacyPath] = snapshot
			continue
		}
		inactive = append(inactive, startupInactiveLegacyGuard{
			Path: legacyPath, Snapshot: snapshot,
		})
	}
	evidence := []model.Evidence{support.FactEvidence("legacy-start-path-snapshot-summary", map[string]any{
		"candidate_count":          2,
		"active_count":             len(active),
		"inactive_count":           len(inactive),
		"initial_unknown_count":    len(unknowns),
		"candidate_paths_redacted": true,
	})}
	return active, inactive, evidence, unknowns
}

func startupSnapshotLstat(
	snapshot *startupFilesystemSnapshot,
	systemPath string,
) (system.FileMetadata, bool, bool) {
	if snapshot == nil {
		return system.FileMetadata{}, false, false
	}
	for _, entry := range snapshot.Entries {
		if entry.Path == systemPath && !entry.Follow &&
			entry.Roles&startupSnapshotRoleChain != 0 {
			return entry.Metadata, entry.Exists, true
		}
	}
	return system.FileMetadata{}, false, false
}

func revalidateStartupInactiveLegacyGuards(
	files system.Reader,
	guards []startupInactiveLegacyGuard,
) ([]string, []model.Evidence) {
	unknowns := make([]string, 0)
	evidence := make([]model.Evidence, 0, len(guards))
	for _, guard := range guards {
		stable, currentDigest, mismatchCount, readErrorCount :=
			revalidateStartupFilesystemSnapshot(files, guard.Snapshot)
		evidence = append(evidence, support.FactEvidence("legacy-start-path-snapshot-guard", map[string]any{
			"path_sha256":               pathDigest(guard.Path),
			"initial_snapshot_sha256":   startupFilesystemSnapshotDigest(guard.Snapshot),
			"current_snapshot_sha256":   currentDigest,
			"snapshot_mismatch_count":   mismatchCount,
			"snapshot_read_error_count": readErrorCount,
			"snapshot_stable":           stable,
		}))
		if !stable {
			unknowns = append(
				unknowns,
				guard.Path+": 점검 중 legacy 시작 경로의 존재 또는 실행 상태가 변경되었거나 다시 확인되지 않음",
			)
		}
	}
	return unknowns, evidence
}

func addStartupSnapshotObservation(
	snapshot *startupFilesystemSnapshot,
	observation startupPathSnapshot,
) bool {
	if snapshot == nil || observation.Path == "" {
		return false
	}
	if snapshot.index == nil {
		snapshot.index = make(map[string]int)
	}
	key := "l:"
	if observation.Follow {
		key = "s:"
	}
	key += observation.Path
	if index, exists := snapshot.index[key]; exists {
		existing := snapshot.Entries[index]
		snapshot.Entries[index].Roles |= observation.Roles
		return existing.Exists == observation.Exists &&
			(!existing.Exists || sameStartupPathSnapshot(existing.Metadata, observation.Metadata))
	}
	snapshot.index[key] = len(snapshot.Entries)
	snapshot.Entries = append(snapshot.Entries, observation)
	return true
}

func captureStartupParentSnapshots(
	files system.Reader,
	snapshot *startupFilesystemSnapshot,
	systemPaths ...string,
) bool {
	if files == nil || snapshot == nil {
		return false
	}
	parentPaths := make(map[string]struct{})
	for _, systemPath := range systemPaths {
		if !validStartupSnapshotSystemPath(systemPath) {
			continue
		}
		parent := path.Dir(systemPath)
		for {
			parentPaths[parent] = struct{}{}
			if parent == "/" {
				break
			}
			parent = path.Dir(parent)
		}
	}
	ordered := make([]string, 0, len(parentPaths))
	for parent := range parentPaths {
		ordered = append(ordered, parent)
	}
	sort.Strings(ordered)
	for _, parent := range ordered {
		metadata, err := files.Lstat(parent)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) ||
				!addStartupSnapshotObservation(snapshot, startupPathSnapshot{
					Path: parent, Exists: false, Roles: startupSnapshotRoleParent,
				}) {
				return false
			}
		} else if !addStartupSnapshotObservation(snapshot, startupPathSnapshot{
			Path: parent, Exists: true, Metadata: metadata, Roles: startupSnapshotRoleParent,
		}) {
			return false
		}

		followed, followErr := files.Stat(parent)
		if followErr != nil {
			if !errors.Is(followErr, os.ErrNotExist) ||
				!addStartupSnapshotObservation(snapshot, startupPathSnapshot{
					Path: parent, Follow: true, Exists: false, Roles: startupSnapshotRoleParent,
				}) {
				return false
			}
			continue
		}
		if followed.FileType != "directory" || !followed.Mode.IsDir() ||
			!addStartupSnapshotObservation(snapshot, startupPathSnapshot{
				Path: parent, Follow: true, Exists: true, Metadata: followed, Roles: startupSnapshotRoleParent,
			}) {
			return false
		}
	}
	return true
}

func revalidateStartupFilesystemSnapshot(
	files system.Reader,
	snapshot *startupFilesystemSnapshot,
) (bool, string, int, int) {
	if files == nil || snapshot == nil || len(snapshot.Entries) == 0 {
		return false, bytesDigest(nil), 0, 1
	}
	currentSnapshot := newStartupFilesystemSnapshot()
	mismatchCount := 0
	readErrorCount := 0
	for _, expected := range snapshot.Entries {
		var (
			current system.FileMetadata
			err     error
		)
		if expected.Follow {
			current, err = files.Stat(expected.Path)
		} else {
			current, err = files.Lstat(expected.Path)
		}
		currentObservation := startupPathSnapshot{
			Path: expected.Path, Follow: expected.Follow, Roles: expected.Roles,
		}
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				readErrorCount++
			}
			if expected.Exists || !errors.Is(err, os.ErrNotExist) {
				mismatchCount++
			}
			_ = addStartupSnapshotObservation(currentSnapshot, currentObservation)
			continue
		}
		currentObservation.Exists = true
		currentObservation.Metadata = current
		_ = addStartupSnapshotObservation(currentSnapshot, currentObservation)
		if !expected.Exists || !sameStartupPathSnapshot(expected.Metadata, current) {
			mismatchCount++
		}
	}
	return mismatchCount == 0 && readErrorCount == 0,
		startupFilesystemSnapshotDigest(currentSnapshot),
		mismatchCount,
		readErrorCount
}

func startupFilesystemSnapshotDigest(snapshot *startupFilesystemSnapshot) string {
	if snapshot == nil {
		return bytesDigest(nil)
	}
	entries := append([]startupPathSnapshot(nil), snapshot.Entries...)
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].Path != entries[right].Path {
			return entries[left].Path < entries[right].Path
		}
		return !entries[left].Follow && entries[right].Follow
	})
	var builder strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(
			&builder,
			"%s\x00%t\x00%t\x00%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%s\x00%d\n",
			entry.Path,
			entry.Follow,
			entry.Exists,
			entry.Metadata.FileType,
			entry.Metadata.Mode,
			entry.Metadata.Size,
			entry.Metadata.UID,
			entry.Metadata.GID,
			entry.Metadata.Device,
			entry.Metadata.Inode,
			entry.Metadata.ModTime.UnixNano(),
			entry.Metadata.LinkTarget,
			entry.Roles,
		)
	}
	return bytesDigest([]byte(builder.String()))
}

func startupPythonScriptPath(command systemdCommand) (string, bool) {
	if len(command.Arguments) < 2 || command.Arguments[0] != command.Executable {
		return "", false
	}
	for index := 1; index < len(command.Arguments); index++ {
		argument := command.Arguments[index]
		if argument == "--" {
			index++
			if index >= len(command.Arguments) {
				return "", false
			}
			argument = command.Arguments[index]
			if !validStartupSystemPath(argument) {
				return "", false
			}
			return argument, true
		}
		if argument == "-" || strings.HasPrefix(argument, "-c") || strings.HasPrefix(argument, "-m") {
			return "", false
		}
		if strings.HasPrefix(argument, "-") {
			if !safePythonFlag(argument) {
				return "", false
			}
			continue
		}
		if !validStartupSystemPath(argument) {
			return "", false
		}
		return argument, true
	}
	return "", false
}

func resolveStartupPythonScript(
	files system.Reader,
	scriptPath string,
	snapshot *startupFilesystemSnapshot,
) (string, bool, bool) {
	finalPath, exists, complete, resolutionPaths := resolveStartupExecutableSnapshot(files, scriptPath, snapshot)
	if complete && !captureStartupParentSnapshots(
		files,
		snapshot,
		append([]string{scriptPath, finalPath}, resolutionPaths...)...,
	) {
		complete = false
	}
	if !complete || !exists {
		return finalPath, exists, complete
	}
	metadata, err := files.Lstat(finalPath)
	if err != nil || metadata.FileType != "regular" || !metadata.Mode.IsRegular() {
		return finalPath, true, false
	}
	for _, candidate := range []string{scriptPath, finalPath} {
		lower := strings.ToLower(path.Base(candidate))
		for _, suffix := range []string{".zip", ".pyz", ".whl", ".egg"} {
			if strings.HasSuffix(lower, suffix) {
				return finalPath, true, false
			}
		}
	}
	return finalPath, true, true
}

func startupShellScriptPath(command systemdCommand) (string, bool) {
	if len(command.Arguments) < 2 || command.Arguments[0] != command.Executable {
		return "", false
	}
	switch command.Executable {
	case "/bin/sh", "/usr/bin/sh", "/bin/dash", "/usr/bin/dash":
	default:
		return "", false
	}
	for index := 1; index < len(command.Arguments); index++ {
		argument := command.Arguments[index]
		if argument == "--" {
			index++
			if index >= len(command.Arguments) || !validStartupSystemPath(command.Arguments[index]) {
				return "", false
			}
			return command.Arguments[index], true
		}
		if strings.HasPrefix(argument, "-") {
			if !safeShellScriptFlag(argument) {
				return "", false
			}
			continue
		}
		if !validStartupSystemPath(argument) {
			return "", false
		}
		return argument, true
	}
	return "", false
}

func safeShellScriptFlag(argument string) bool {
	if len(argument) < 2 || argument[0] != '-' || strings.HasPrefix(argument, "--") {
		return false
	}
	for _, option := range argument[1:] {
		if !strings.ContainsRune("eux", option) {
			return false
		}
	}
	return true
}

func resolveStartupShellScript(
	files system.Reader,
	scriptPath string,
	snapshot *startupFilesystemSnapshot,
) (string, bool, bool) {
	finalPath, exists, complete, resolutionPaths := resolveStartupExecutableSnapshot(files, scriptPath, snapshot)
	if complete && !captureStartupParentSnapshots(
		files,
		snapshot,
		append([]string{scriptPath, finalPath}, resolutionPaths...)...,
	) {
		complete = false
	}
	if !complete || !exists {
		return finalPath, exists, complete
	}
	metadata, err := files.Lstat(finalPath)
	if err != nil || metadata.FileType != "regular" || !metadata.Mode.IsRegular() {
		return finalPath, true, false
	}
	return finalPath, true, true
}

func safePythonFlag(argument string) bool {
	if len(argument) < 2 || argument[0] != '-' || strings.HasPrefix(argument, "--") {
		return false
	}
	for _, option := range argument[1:] {
		if !strings.ContainsRune("bBdEiIOPqRsSuvx", option) {
			return false
		}
	}
	return true
}

func isPythonDispatcher(executable string) bool {
	executable = strings.ToLower(strings.TrimSpace(executable))
	switch executable {
	case "python", "python2", "python3", "pypy", "pypy3":
		return true
	}
	return hasNumericExecutableSuffix(executable, "python") ||
		hasNumericExecutableSuffix(executable, "pypy")
}

func isShellDispatcher(executable string) bool {
	executable = strings.ToLower(strings.TrimSpace(executable))
	switch executable {
	case "sh", "bash", "dash", "ash", "ksh", "zsh":
		return true
	}
	return false
}

func isStartupDispatcher(executable string) bool {
	executable = strings.ToLower(strings.TrimSpace(executable))
	switch executable {
	case "sh", "bash", "dash", "ash", "ksh", "zsh", "csh", "tcsh", "fish",
		"env", "busybox", "nice", "nohup", "setsid", "chroot", "unshare", "nsenter",
		"su", "runuser", "sudo", "doas", "setpriv", "systemd-run",
		"timeout", "stdbuf", "ionice", "taskset", "chrt",
		"python", "python2", "python3", "pypy", "pypy3", "perl", "ruby", "jruby",
		"node", "nodejs", "php", "php-cgi", "java", "jrunscript",
		"lua", "luajit", "tclsh", "wish", "awk", "gawk", "mawk", "nawk",
		"r", "rscript", "dotnet", "mono", "deno", "bun":
		return true
	}
	for _, prefix := range []string{
		"python", "pypy", "perl", "ruby", "php", "lua", "luajit",
		"tclsh", "wish", "node", "java",
	} {
		if hasNumericExecutableSuffix(executable, prefix) {
			return true
		}
	}
	return false
}

func hasNumericExecutableSuffix(executable, prefix string) bool {
	if !strings.HasPrefix(executable, prefix) || len(executable) == len(prefix) {
		return false
	}
	suffix := executable[len(prefix):]
	if suffix[0] < '0' || suffix[0] > '9' {
		return false
	}
	for _, character := range suffix {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return true
}

func xinetdUsesCustomConfig(output string) bool {
	paths, complete := parseSystemdCommandPaths(output)
	if !complete || len(paths) != 1 || strings.ToLower(path.Base(paths[0])) != "xinetd" {
		return true
	}
	for _, rawField := range strings.Fields(strings.ToLower(output)) {
		field := strings.Trim(rawField, "{};\"'")
		if field == "-f" || strings.HasPrefix(field, "-f=") || strings.HasPrefix(field, "-f/") ||
			strings.HasPrefix(field, "--file") || strings.HasPrefix(field, "--config") {
			return true
		}
	}
	return false
}

func inetdConfigPaths(
	ctx context.Context,
	environment evaluator.Environment,
	xinetdManaged bool,
) ([]string, bool, []model.Evidence, error) {
	const maximumXinetdObjects = 4096
	result := make([]string, 0)
	evidence := make([]model.Evidence, 0)
	complete := true

	if !xinetdManaged {
		if _, err := environment.Files.Lstat("/etc/inetd.conf"); err == nil {
			result = append(result, "/etc/inetd.conf")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, false, evidence, err
		}
	}

	if _, err := environment.Files.Lstat("/etc/xinetd.conf"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, evidence, err
		}
		if xinetdManaged {
			complete = false
		}
		return uniqueSortedPaths(result), complete, evidence, nil
	}

	fileQueue := []string{"/etc/xinetd.conf"}
	directoryQueue := make([]string, 0)
	seenFiles := make(map[string]struct{})
	seenDirectories := make(map[string]struct{})
	for len(fileQueue) > 0 || len(directoryQueue) > 0 {
		if len(seenFiles)+len(seenDirectories) >= maximumXinetdObjects {
			complete = false
			break
		}
		if len(directoryQueue) > 0 {
			directory := directoryQueue[0]
			directoryQueue = directoryQueue[1:]
			if _, seen := seenDirectories[directory]; seen {
				continue
			}
			seenDirectories[directory] = struct{}{}
			entries, err := environment.Files.ReadDir(directory)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					complete = false
					continue
				}
				return nil, false, evidence, err
			}
			names := make([]string, 0)
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || path.Base(name) != name || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
					continue
				}
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				fileQueue = append(fileQueue, path.Join(directory, name))
			}
			evidence = append(evidence, support.FactEvidence(directory, map[string]any{
				"included_file_count": len(names), "names_redacted": true,
			}))
			continue
		}

		current := fileQueue[0]
		fileQueue = fileQueue[1:]
		if _, seen := seenFiles[current]; seen {
			continue
		}
		seenFiles[current] = struct{}{}
		data, metadata, err := environment.Files.ReadFile(ctx, current, 2<<20)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				complete = false
				continue
			}
			return nil, false, evidence, err
		}
		result = append(result, current)
		files, directories, parsed := parseXinetdIncludes(string(data))
		complete = complete && parsed
		fileQueue = append(fileQueue, files...)
		directoryQueue = append(directoryQueue, directories...)
		evidence = append(evidence, support.FactEvidence(current, map[string]any{
			"size": metadata.Size, "include_count": len(files), "includedir_count": len(directories),
			"include_scan_complete": parsed, "content_redacted": true,
		}))
	}
	return uniqueSortedPaths(result), complete, evidence, nil
}

func parseXinetdIncludes(content string) (files, directories []string, complete bool) {
	complete = true
	depth := 0
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line, commentComplete := stripXinetdComment(raw)
		if !commentComplete {
			complete = false
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && (strings.EqualFold(fields[0], "include") || strings.EqualFold(fields[0], "includedir")) {
			if depth != 0 || len(fields) != 2 || !safeXinetdIncludePath(fields[1]) {
				complete = false
			} else if strings.EqualFold(fields[0], "includedir") {
				directories = append(directories, fields[1])
			} else {
				files = append(files, fields[1])
			}
		}
		delta, balanced := xinetdBraceDelta(line)
		if !balanced || depth+delta < 0 {
			complete = false
			continue
		}
		depth += delta
	}
	if depth != 0 {
		complete = false
	}
	return uniqueSortedPaths(files), uniqueSortedPaths(directories), complete
}

func safeXinetdIncludePath(value string) bool {
	return value != "" && path.IsAbs(value) && path.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\\\"'`$%*?[")
}

func stripXinetdComment(value string) (string, bool) {
	quote := rune(0)
	escaped := false
	for index, character := range value {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == '#' {
			return value[:index], true
		}
	}
	return value, quote == 0 && !escaped
}

func xinetdBraceDelta(value string) (int, bool) {
	delta := 0
	quote := rune(0)
	escaped := false
	for _, character := range value {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		switch character {
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta, quote == 0 && !escaped
}

func collectRsyslogConfigPaths(ctx context.Context, environment evaluator.Environment, rootConfig string) ([]string, bool, []model.Evidence, error) {
	queue := []string{rootConfig}
	seen := make(map[string]struct{})
	result := make([]string, 0)
	evidence := make([]model.Evidence, 0)
	complete := true
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		data, _, err := environment.Files.ReadFile(ctx, current, 2<<20)
		if err != nil {
			if current != "/etc/rsyslog.conf" && errors.Is(err, os.ErrNotExist) {
				complete = false
				evidence = append(evidence, support.FactEvidence(current, map[string]any{"missing": true, "content_redacted": true}))
				continue
			}
			return nil, false, evidence, err
		}
		result = append(result, current)
		includes := make([]string, 0)
		for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lower := strings.ToLower(line)
			var pattern string
			switch {
			case strings.HasPrefix(lower, "$includeconfig"):
				fields := strings.Fields(line)
				if len(fields) != 2 {
					complete = false
					continue
				}
				pattern = strings.Trim(fields[1], "\"'")
			case strings.HasPrefix(lower, "include("):
				marker := strings.Index(lower, "file=")
				if marker < 0 {
					complete = false
					continue
				}
				remainder := strings.TrimSpace(line[marker+len("file="):])
				if len(remainder) < 2 || (remainder[0] != '"' && remainder[0] != '\'') {
					complete = false
					continue
				}
				quote := remainder[0]
				end := strings.IndexByte(remainder[1:], quote)
				if end < 0 {
					complete = false
					continue
				}
				pattern = remainder[1 : end+1]
			default:
				continue
			}
			matches, ok, err := expandFixedConfigPattern(environment, pattern)
			if err != nil {
				return nil, false, evidence, err
			}
			if !ok {
				complete = false
				continue
			}
			includes = append(includes, matches...)
		}
		sort.Strings(includes)
		queue = append(queue, includes...)
		evidence = append(evidence, support.FactEvidence(current, map[string]any{"include_count": len(includes), "content_redacted": true}))
	}
	sort.Strings(result)
	return result, complete, evidence, nil
}

func inspectRsyslogStartupPath(ctx context.Context, files system.Reader) (string, []string, []model.Evidence, bool, error) {
	const sysconfigPath = "/etc/sysconfig/rsyslog"
	exists, err := files.Exists(sysconfigPath)
	if err != nil {
		return "", nil, nil, false, err
	}
	if !exists {
		return "/etc/rsyslog.conf", nil, nil, true, nil
	}
	data, metadata, err := files.ReadFile(ctx, sysconfigPath, 256<<10)
	if err != nil {
		return "", nil, nil, false, err
	}
	configPath, complete, err := rsyslogConfigPathFromSysconfig(string(data))
	evidence := []model.Evidence{
		support.FileMetadataEvidence(metadata),
		support.FactEvidence("rsyslog startup configuration", map[string]any{"custom_config_path": configPath != "/etc/rsyslog.conf", "content_redacted": true}),
	}
	return configPath, []string{sysconfigPath}, evidence, complete, err
}

func rsyslogConfigPathFromSysconfig(content string) (string, bool, error) {
	selected := "/etc/rsyslog.conf"
	explicit := false
	setPath := func(candidate string) bool {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "=")
		if !path.IsAbs(candidate) || path.Clean(candidate) != candidate || strings.ContainsAny(candidate, "\\\x00\r\n\"'`$%") {
			return false
		}
		if explicit && selected != candidate {
			return false
		}
		selected = candidate
		explicit = true
		return true
	}
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		tokens, err := sysconfigTokens(raw)
		if err != nil {
			return "", false, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if len(tokens) > 1 {
			values, valueErr := sysconfigTokens(strings.Join(tokens[1:], " "))
			if valueErr != nil {
				return "", false, fmt.Errorf("line %d value: %w", lineNumber+1, valueErr)
			}
			tokens = append([]string{tokens[0]}, values...)
		}
		for index, token := range tokens {
			switch {
			case token == "RSYSLOG_CONFIG_FILE":
				if index+1 >= len(tokens) || !setPath(tokens[index+1]) {
					return selected, false, nil
				}
			case token == "-f":
				if index+1 >= len(tokens) || !setPath(tokens[index+1]) {
					return selected, false, nil
				}
			case strings.HasPrefix(token, "-f") && len(token) > 2:
				if !setPath(strings.TrimPrefix(token, "-f")) {
					return selected, false, nil
				}
			}
		}
	}
	return selected, true, nil
}

func sysconfigTokens(line string) ([]string, error) {
	result := make([]string, 0)
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			result = append(result, current.String())
			current.Reset()
		}
	}
	for _, character := range line {
		if escaped {
			current.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
		case '#':
			flush()
			return result, nil
		case ' ', '\t', '=':
			flush()
		default:
			current.WriteRune(character)
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unterminated quoted or escaped value")
	}
	flush()
	return result, nil
}

func expandFixedConfigPattern(environment evaluator.Environment, pattern string) ([]string, bool, error) {
	if pattern == "" || !path.IsAbs(pattern) || strings.ContainsAny(pattern, "\x00\r\n") {
		return nil, false, nil
	}
	directory, filePattern := path.Split(pattern)
	if strings.ContainsAny(strings.TrimSuffix(directory, "/"), "*?[") || filePattern == "" {
		return nil, false, nil
	}
	if !strings.ContainsAny(filePattern, "*?[") {
		return []string{path.Clean(pattern)}, true, nil
	}
	entries, err := environment.Files.ReadDir(strings.TrimSuffix(directory, "/"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, err
	}
	matches := make([]string, 0)
	for _, entry := range entries {
		matched, err := path.Match(filePattern, entry.Name())
		if err != nil {
			return nil, false, err
		}
		if matched && !entry.IsDir() {
			matches = append(matches, path.Join(directory, entry.Name()))
		}
	}
	sort.Strings(matches)
	return matches, true, nil
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
