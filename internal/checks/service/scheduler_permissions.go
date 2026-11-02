package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorSchedulerPermissions = "unix.service.scheduler_permissions"

type schedulerObjectClass string

const (
	schedulerCommand      schedulerObjectClass = "command"
	schedulerConfig       schedulerObjectClass = "config"
	schedulerScript       schedulerObjectClass = "script"
	schedulerDirectory    schedulerObjectClass = "directory"
	schedulerSpoolDir     schedulerObjectClass = "spool_directory"
	schedulerCronSpool    schedulerObjectClass = "cron_spool"
	schedulerAtSpool      schedulerObjectClass = "at_spool"
	schedulerUnknownEntry schedulerObjectClass = "unknown_entry"
)

type schedulerObject struct {
	Path  string
	Class schedulerObjectClass
}

type schedulerPackageInspection struct {
	Installed        map[string]bool
	Evidence         []model.Evidence
	QueryUnavailable bool
	VerifyDifference bool
}

type schedulerPermissionDimension struct {
	ObjectCount int
	Violations  []string
	Unknowns    []string
}

func evaluateSchedulerPermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	packages, err := inspectSchedulerPackages(ctx, environment)
	if err != nil {
		return schedulerError("scheduler_package_inspection_failed", err, packages.Evidence)
	}
	objects, inventoryEvidence, err := schedulerObjects(environment)
	if err != nil {
		return schedulerError("scheduler_inventory_failed", err, packages.Evidence)
	}
	evidence := append(append([]model.Evidence(nil), packages.Evidence...), inventoryEvidence...)
	if len(packages.Installed) == 0 && len(objects) == 0 {
		if packages.QueryUnavailable {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownInsufficientEvidence,
				Summary:       "cron과 at 구성요소의 부재를 확정할 수 없습니다.",
				Expected:      rule.Criteria.Pass,
				Observed:      "관련 경로는 없지만 패키지 조회를 사용할 수 없습니다.",
				Evidence:      evidence,
			}
		}
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "cron과 at 패키지 및 관련 파일이 없습니다.", Expected: rule.Criteria.Pass, Observed: "scheduler package/path 없음", Evidence: evidence}
	}

	command := schedulerPermissionDimension{}
	relatedFiles := schedulerPermissionDimension{}
	seenCommands := make(map[string]bool)
	for _, object := range objects {
		assessment, inspectErr := inspectSchedulerObject(ctx, environment, object)
		if inspectErr != nil {
			return schedulerError("scheduler_permission_inspection_failed", inspectErr, evidence)
		}
		evidence = append(evidence, assessment.Evidence...)
		if !assessment.Exists {
			continue
		}
		switch object.Class {
		case schedulerCommand:
			seenCommands[object.Path] = true
			command.ObjectCount++
			schedulerAppendRegularObjectFindings(&command, object.Path, assessment, true)
		case schedulerConfig, schedulerScript, schedulerCronSpool, schedulerAtSpool:
			relatedFiles.ObjectCount++
			schedulerAppendRegularObjectFindings(&relatedFiles, object.Path, assessment, false)
		case schedulerSpoolDir, schedulerDirectory:
			if assessment.Metadata.FileType != "directory" {
				relatedFiles.Unknowns = append(relatedFiles.Unknowns, fmt.Sprintf(
					"%s: 관련 경로가 디렉터리가 아님(type=%s)",
					object.Path,
					assessment.Metadata.FileType,
				))
			}
		case schedulerUnknownEntry:
			relatedFiles.Unknowns = append(relatedFiles.Unknowns, fmt.Sprintf(
				"%s: 디렉터리 또는 비정규 scheduler 항목의 파일 기준 적용 여부를 확정할 수 없음(type=%s)",
				object.Path,
				assessment.Metadata.FileType,
			))
		}
	}

	if schedulerCronPackageInstalled(packages.Installed) && !seenCommands["/usr/bin/crontab"] {
		command.Unknowns = append(command.Unknowns, "cron 패키지가 설치됐지만 /usr/bin/crontab을 확인하지 못함")
	}
	if packages.Installed["at"] && !seenCommands["/usr/bin/at"] {
		command.Unknowns = append(command.Unknowns, "at가 설치됐지만 /usr/bin/at을 확인하지 못함")
	}
	if packages.QueryUnavailable && command.ObjectCount == 0 {
		command.Unknowns = append(command.Unknowns, "패키지 조회를 사용할 수 없고 scheduler 명령 경로도 확인되지 않음")
	}
	if packages.QueryUnavailable && relatedFiles.ObjectCount == 0 {
		relatedFiles.Unknowns = append(relatedFiles.Unknowns, "패키지 조회를 사용할 수 없고 관련 일반 파일도 확인되지 않음")
	}
	command.Violations = uniqueSortedServiceStrings(command.Violations)
	command.Unknowns = uniqueSortedServiceStrings(command.Unknowns)
	relatedFiles.Violations = uniqueSortedServiceStrings(relatedFiles.Violations)
	relatedFiles.Unknowns = uniqueSortedServiceStrings(relatedFiles.Unknowns)
	evidence = append(evidence, support.FactEvidence("scheduler 권한 파생 정보", map[string]any{
		"installed_package_count":   len(packages.Installed),
		"object_count":              len(objects),
		"package_query_unavailable": packages.QueryUnavailable,
		"rpm_verify_difference":     packages.VerifyDifference,
		"command_object_count":      command.ObjectCount,
		"command_violation_count":   len(command.Violations),
		"command_unknown_count":     len(command.Unknowns),
		"file_object_count":         relatedFiles.ObjectCount,
		"file_violation_count":      len(relatedFiles.Violations),
		"file_unknown_count":        len(relatedFiles.Unknowns),
		"command_violation_sample":  schedulerLimitedStrings(command.Violations, 20),
		"command_unknown_sample":    schedulerLimitedStrings(command.Unknowns, 20),
		"file_violation_sample":     schedulerLimitedStrings(relatedFiles.Violations, 20),
		"file_unknown_sample":       schedulerLimitedStrings(relatedFiles.Unknowns, 20),
	}))
	return schedulerPermissionOutcome(rule, len(objects), evidence, command, relatedFiles)
}

func schedulerCronPackageInstalled(installed map[string]bool) bool {
	return installed["cronie"] || installed["cron"] || installed["cron-daemon-common"]
}

func inspectSchedulerPackages(ctx context.Context, environment evaluator.Environment) (schedulerPackageInspection, error) {
	inspection := schedulerPackageInspection{Installed: make(map[string]bool)}
	if environment.Platform.Family == "debian" {
		if !environment.Commands.Available("dpkg-query") {
			inspection.QueryUnavailable = true
			inspection.Evidence = append(inspection.Evidence, support.FactEvidence("scheduler DPKG", map[string]any{
				"query_available":      false,
				"verify_difference":    false,
				"verify_not_attempted": true,
			}))
			return inspection, nil
		}
		packages, packageEvidence, err := support.InspectDPKGInventory(ctx, environment)
		inspection.Evidence = append(inspection.Evidence, packageEvidence)
		if err != nil {
			return inspection, err
		}
		for _, packageName := range []string{"cron", "cron-daemon-common", "anacron", "at"} {
			if support.DPKGPackageInstalled(packages, packageName) {
				inspection.Installed[packageName] = true
			}
		}
		inspection.Evidence = append(inspection.Evidence, support.FactEvidence("scheduler DPKG 상태", map[string]any{
			"query_available":      true,
			"verify_difference":    false,
			"verify_not_attempted": true,
		}))
		return inspection, nil
	}
	if !environment.Commands.Available("rpm") {
		inspection.QueryUnavailable = true
		inspection.Evidence = append(inspection.Evidence, support.FactEvidence("scheduler RPM", map[string]any{
			"query_available":      false,
			"verify_difference":    false,
			"verify_not_attempted": true,
		}))
		return inspection, nil
	}
	for _, packageName := range []string{"cronie", "cronie-anacron", "at"} {
		querySpec := executor.Spec{Name: "rpm", Arguments: []string{"-q", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", packageName}, Timeout: 30 * time.Second, MaxOutput: 1 << 20}
		query, err := environment.Commands.Run(ctx, querySpec)
		if err != nil {
			return inspection, err
		}
		inspection.Evidence = append(inspection.Evidence, privateCommandSummary(querySpec, query))
		if query.Truncated {
			return inspection, fmt.Errorf("rpm query output was truncated for %s", packageName)
		}
		if query.ExitCode == 1 {
			continue
		}
		if query.ExitCode != 0 {
			return inspection, fmt.Errorf("rpm query %s exit=%d", packageName, query.ExitCode)
		}
		inspection.Installed[packageName] = true
		verifySpec := executor.Spec{Name: "rpm", Arguments: []string{"-V", packageName}, Timeout: 60 * time.Second, MaxOutput: 4 << 20}
		verify, err := environment.Commands.Run(ctx, verifySpec)
		if err != nil {
			return inspection, err
		}
		inspection.Evidence = append(inspection.Evidence, privateCommandSummary(verifySpec, verify))
		if verify.Truncated || (verify.ExitCode != 0 && verify.ExitCode != 1) {
			return inspection, fmt.Errorf("rpm verify %s exit=%d truncated=%t", packageName, verify.ExitCode, verify.Truncated)
		}
		inspection.VerifyDifference = inspection.VerifyDifference || verify.ExitCode == 1 || len(strings.TrimSpace(string(verify.Stdout))) > 0
	}
	inspection.Evidence = append(inspection.Evidence, support.FactEvidence("scheduler RPM 상태", map[string]any{
		"query_available":   true,
		"verify_difference": inspection.VerifyDifference,
	}))
	return inspection, nil
}

func schedulerObjects(environment evaluator.Environment) ([]schedulerObject, []model.Evidence, error) {
	objects := []schedulerObject{
		{Path: "/usr/bin/crontab", Class: schedulerCommand}, {Path: "/usr/bin/at", Class: schedulerCommand},
		{Path: "/etc/crontab", Class: schedulerConfig}, {Path: "/etc/anacrontab", Class: schedulerConfig},
		{Path: "/etc/cron.allow", Class: schedulerConfig}, {Path: "/etc/cron.deny", Class: schedulerConfig},
		{Path: "/etc/at.allow", Class: schedulerConfig}, {Path: "/etc/at.deny", Class: schedulerConfig},
	}
	directories := []schedulerObject{
		{Path: "/etc/cron.d", Class: schedulerConfig},
		{Path: "/etc/cron.hourly", Class: schedulerScript}, {Path: "/etc/cron.daily", Class: schedulerScript},
		{Path: "/etc/cron.weekly", Class: schedulerScript}, {Path: "/etc/cron.monthly", Class: schedulerScript},
		{Path: "/var/spool/cron", Class: schedulerCronSpool},
		{Path: "/var/spool/cron/crontabs", Class: schedulerCronSpool},
		{Path: "/var/spool/cron/atjobs", Class: schedulerAtSpool},
		{Path: "/var/spool/at", Class: schedulerAtSpool},
	}
	evidence := make([]model.Evidence, 0)
	for _, directory := range directories {
		metadata, err := environment.Files.Lstat(directory.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, evidence, err
		}
		directoryClass := schedulerDirectory
		if directory.Class == schedulerCronSpool || directory.Class == schedulerAtSpool {
			directoryClass = schedulerSpoolDir
		}
		objects = append(objects, schedulerObject{Path: directory.Path, Class: directoryClass})
		if metadata.FileType != "directory" {
			objects = append(objects, schedulerObject{Path: directory.Path, Class: schedulerUnknownEntry})
			continue
		}
		entries, err := environment.Files.ReadDir(directory.Path)
		if err != nil {
			return nil, evidence, err
		}
		entryCount := 0
		for _, entry := range entries {
			if path.Base(entry.Name()) != entry.Name() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			entryClass := directory.Class
			if entry.IsDir() {
				entryClass = schedulerUnknownEntry
			}
			objects = append(objects, schedulerObject{Path: path.Join(directory.Path, entry.Name()), Class: entryClass})
			entryCount++
		}
		evidence = append(evidence, support.FactEvidence(directory.Path, map[string]any{"entry_count": entryCount, "names_redacted": true}))
	}
	filtered := make([]schedulerObject, 0, len(objects))
	seen := make(map[string]schedulerObjectClass)
	for _, object := range objects {
		exists, err := environment.Files.Exists(object.Path)
		if err != nil {
			return nil, evidence, err
		}
		if !exists {
			continue
		}
		if previous, duplicate := seen[object.Path]; duplicate {
			seen[object.Path] = mergeSchedulerObjectClass(previous, object.Class)
			continue
		}
		seen[object.Path] = object.Class
		filtered = append(filtered, object)
	}
	for index := range filtered {
		filtered[index].Class = seen[filtered[index].Path]
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Path < filtered[j].Path })
	return filtered, evidence, nil
}

func mergeSchedulerObjectClass(previous, current schedulerObjectClass) schedulerObjectClass {
	if previous == current {
		return previous
	}
	if previous == schedulerUnknownEntry {
		if current == schedulerDirectory || current == schedulerSpoolDir {
			return current
		}
	}
	if current == schedulerUnknownEntry {
		if previous == schedulerDirectory || previous == schedulerSpoolDir {
			return previous
		}
	}
	return schedulerUnknownEntry
}

func inspectSchedulerObject(ctx context.Context, environment evaluator.Environment, object schedulerObject) (support.PermissionAssessment, error) {
	metadata, err := environment.Files.Lstat(object.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return support.PermissionAssessment{Path: object.Path}, nil
		}
		return support.PermissionAssessment{}, err
	}
	expectedRegular := schedulerRegularObjectClass(object.Class)
	if !expectedRegular || metadata.FileType != "regular" {
		return support.PermissionAssessment{
			Path:     object.Path,
			Exists:   true,
			Metadata: metadata,
			Evidence: []model.Evidence{support.FileMetadataEvidence(metadata)},
		}, nil
	}
	policy := schedulerPermissionPolicy(object.Class)
	return support.InspectPermissions(ctx, environment.Files, environment.Commands, object.Path, policy)
}

func schedulerRegularObjectClass(class schedulerObjectClass) bool {
	switch class {
	case schedulerCommand, schedulerConfig, schedulerScript, schedulerCronSpool, schedulerAtSpool:
		return true
	default:
		return false
	}
}

func schedulerPermissionPolicy(class schedulerObjectClass) support.PermissionPolicy {
	policy := support.PermissionPolicy{AllowedTypes: map[string]struct{}{"regular": {}}, SkipACL: true}
	switch class {
	case schedulerCommand:
		policy.AllowedUIDs = map[int]struct{}{0: {}}
		policy.AllowedMode = 0o750
		policy.AllowedSpecialBits = os.ModeSetuid | os.ModeSetgid
	case schedulerConfig, schedulerScript, schedulerCronSpool, schedulerAtSpool:
		policy.AllowedUIDs = map[int]struct{}{0: {}}
		policy.AllowedMode = 0o640
	case schedulerDirectory, schedulerSpoolDir:
		policy.AllowedMode = 0o777
		policy.AllowedSpecialBits = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
		policy.AllowedTypes = map[string]struct{}{"directory": {}}
	case schedulerUnknownEntry:
		policy.AllowedMode = 0o777
		policy.AllowedSpecialBits = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
		policy.AllowedTypes = map[string]struct{}{"regular": {}, "directory": {}}
	}
	return policy
}

func schedulerAppendRegularObjectFindings(
	dimension *schedulerPermissionDimension,
	objectPath string,
	assessment support.PermissionAssessment,
	command bool,
) {
	if assessment.Metadata.FileType != "regular" {
		dimension.Unknowns = append(dimension.Unknowns, fmt.Sprintf(
			"%s: 일반 파일이 아니어서 권한 기준을 확정 적용할 수 없음(type=%s)",
			objectPath,
			assessment.Metadata.FileType,
		))
		return
	}
	for _, violation := range assessment.Violations {
		dimension.Violations = append(dimension.Violations, objectPath+": "+violation)
	}
	for _, unknown := range assessment.Unknowns {
		dimension.Unknowns = append(dimension.Unknowns, objectPath+": "+unknown)
	}
	if command {
		violations, unknowns := schedulerCommandModeFindings(objectPath, assessment.Metadata.Mode)
		dimension.Violations = append(dimension.Violations, violations...)
		dimension.Unknowns = append(dimension.Unknowns, unknowns...)
	}
}

func schedulerCommandModeFindings(commandPath string, mode os.FileMode) ([]string, []string) {
	violations := make([]string, 0, 1)
	unknowns := make([]string, 0, 1)
	if mode&os.ModeSetuid != 0 {
		violations = append(violations, commandPath+": SUID 비트가 설정됨")
	}
	if mode&os.ModeSetgid != 0 {
		unknowns = append(unknowns, commandPath+": SGID 비트의 배포판 패키지 의미를 확인해야 함")
	}
	return violations, unknowns
}

func schedulerPermissionOutcome(
	rule model.ResolvedRule,
	objectCount int,
	evidence []model.Evidence,
	command schedulerPermissionDimension,
	relatedFiles schedulerPermissionDimension,
) evaluator.Outcome {
	commandComplete := len(command.Unknowns) == 0
	filesComplete := len(relatedFiles.Unknowns) == 0
	commandUnsafe := len(command.Violations) > 0
	filesUnsafe := len(relatedFiles.Violations) > 0

	violations := append(
		schedulerPrefixedFindings("명령", command.Violations),
		schedulerPrefixedFindings("관련 파일", relatedFiles.Violations)...,
	)
	unknowns := append(
		schedulerPrefixedFindings("명령", command.Unknowns),
		schedulerPrefixedFindings("관련 파일", relatedFiles.Unknowns)...,
	)
	if commandComplete && filesComplete && commandUnsafe != filesUnsafe {
		unknowns = append(unknowns, "복합 취약 기준의 두 차원 중 한 차원에서만 위반이 확인됨")
	}
	details := schedulerPermissionDetails(violations, unknowns, rule.Criteria.Pass)
	observed := fmt.Sprintf(
		"명령=%s; 관련 파일=%s; scheduler 객체=%d",
		schedulerDimensionObserved(command),
		schedulerDimensionObserved(relatedFiles),
		objectCount,
	)
	if commandUnsafe && filesUnsafe {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "cron/at 명령과 관련 파일이 모두 취약 기준에 해당합니다.",
			Expected: rule.Criteria.Pass,
			Observed: observed,
			Details:  details,
			Evidence: evidence,
		}
	}
	if commandComplete && filesComplete && !commandUnsafe && !filesUnsafe {
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "cron/at 명령과 관련 파일이 모두 권한 기준을 충족합니다.",
			Expected: rule.Criteria.Pass,
			Observed: observed,
			Evidence: evidence,
		}
	}
	reason := model.UnknownAmbiguousResult
	summary := "복합 취약 기준의 두 차원 중 한 차원에서만 위반이 확인되었습니다."
	if !commandComplete || !filesComplete {
		reason = model.UnknownInsufficientEvidence
		summary = "cron/at 명령 또는 관련 파일 권한을 완전하게 확정할 수 없습니다."
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: reason,
		Summary:       summary,
		Expected:      rule.Criteria.Pass,
		Observed:      observed,
		Details:       details,
		Evidence:      evidence,
	}
}

func schedulerPrefixedFindings(label string, findings []string) []string {
	result := make([]string, 0, len(findings))
	for _, finding := range findings {
		result = append(result, label+" | "+finding)
	}
	return result
}

func schedulerDimensionObserved(dimension schedulerPermissionDimension) string {
	if len(dimension.Unknowns) > 0 {
		return fmt.Sprintf("확정 불가(위반 %d건, 추가 확인 %d건)", len(dimension.Violations), len(dimension.Unknowns))
	}
	if len(dimension.Violations) > 0 {
		return fmt.Sprintf("위반 %d건", len(dimension.Violations))
	}
	return "양호"
}

func schedulerPermissionDetails(violations, unknowns []string, expected string) []model.ResultDetail {
	details := make([]model.ResultDetail, 0, 2)
	if len(violations) > 0 {
		details = append(details, model.ResultDetail{
			Label:    "확인된 위반",
			Current:  strings.Join(violations, "\n"),
			Expected: expected,
			Source:   "cron/at 명령 및 관련 파일 권한",
		})
	}
	if len(unknowns) > 0 {
		details = append(details, model.ResultDetail{
			Label:    "추가 확인 필요",
			Current:  strings.Join(unknowns, "\n"),
			Expected: expected,
			Source:   "cron/at 명령 및 관련 파일 권한",
		})
	}
	return details
}

func schedulerLimitedStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:limit]...)
}

func schedulerError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{Status: model.StatusError, Summary: "cron/at 명령과 관련 파일의 권한을 수집하거나 해석하지 못했습니다.", ErrorCode: code, ErrorMessage: err.Error(), Evidence: evidence}
}
