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

type schedulerIdentitySet struct {
	Accounts    map[string]support.PasswdEntry
	GroupsByGID map[uint32][]support.GroupEntry
}

type schedulerCommandAccess struct {
	Complete             bool
	PolicyMode           string
	ExecutableNonRoot    int
	PolicyAllowedNonRoot int
	Evidence             []model.Evidence
}

func evaluateSchedulerPermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	packages, packageEvidence, rpmUnknown, err := inspectSchedulerPackages(ctx, environment)
	if err != nil {
		return schedulerError("scheduler_package_inspection_failed", err, nil)
	}
	objects, inventoryEvidence, err := schedulerObjects(environment)
	if err != nil {
		return schedulerError("scheduler_inventory_failed", err, packageEvidence)
	}
	evidence := append(packageEvidence, inventoryEvidence...)
	if len(packages) == 0 && len(objects) == 0 {
		if rpmUnknown {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownInsufficientEvidence,
				Summary:       "cron과 at 구성요소의 부재를 확정할 수 없습니다.",
				Expected:      rule.Criteria.Pass,
				Observed:      "관련 경로는 없지만 RPM 설치 여부를 조회할 수 없습니다.",
				Evidence:      evidence,
			}
		}
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "cron과 at 패키지 및 관련 파일이 없습니다.", Expected: rule.Criteria.Pass, Observed: "scheduler package/path 없음", Evidence: evidence}
	}

	identities, identityEvidence, err := schedulerIdentities(ctx, environment)
	if err != nil {
		return schedulerError("scheduler_account_lookup_failed", err, evidence)
	}
	evidence = append(evidence, identityEvidence...)
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	if rpmUnknown {
		unknowns = append(unknowns, "설치 패키지의 rpm -V 결과가 기본 상태와 다름")
	}
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
		if object.Class == schedulerCommand {
			seenCommands[object.Path] = true
		}
		for _, violation := range assessment.Violations {
			violations = append(violations, object.Path+": "+violation)
		}
		for _, unknown := range assessment.Unknowns {
			unknowns = append(unknowns, object.Path+": "+unknown)
		}
		metadata := assessment.Metadata
		switch object.Class {
		case schedulerCommand:
			access, accessErr := inspectSchedulerCommandAccess(ctx, environment, object.Path, metadata.Mode, metadata.GID, assessment.NamedAccessACL, identities)
			if accessErr != nil {
				return schedulerError("scheduler_access_policy_failed", accessErr, evidence)
			}
			evidence = append(evidence, access.Evidence...)
			if !access.Complete {
				unknowns = append(unknowns, object.Path+": group 또는 allow/deny 접근 의미를 완전히 해석할 수 없음")
			}
			if access.ExecutableNonRoot > 0 {
				unknowns = append(unknowns, object.Path+": 실효 비-root 계정에 Unix 실행 권한이 있음")
			}
			if access.PolicyAllowedNonRoot > 0 {
				unknowns = append(unknowns, object.Path+": allow/deny 정책까지 통과하는 비-root 계정이 있음")
			}
			if metadata.Mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
				unknowns = append(unknowns, object.Path+": 일반 실행 비트 또는 setuid/setgid가 Rocky 패키지 동작에 필요한지 VM 검증 필요")
			}
		case schedulerConfig:
			if metadata.Mode.Perm()&0o004 != 0 {
				unknowns = append(unknowns, object.Path+": other read 비트가 가이드 0640 기준과 Rocky 패키지 기본값 사이에서 미검증")
			}
		case schedulerCronSpool:
			name := path.Base(object.Path)
			account, exists := identities.Accounts[name]
			if !exists {
				unknowns = append(unknowns, object.Path+": 대응하는 실효 계정을 찾지 못함")
			} else if metadata.UID >= 0 && metadata.UID != int(account.UID) {
				violations = append(violations, object.Path+": 사용자 crontab 소유자가 계정 UID와 다름")
			}
		case schedulerSpoolDir, schedulerAtSpool, schedulerUnknownEntry:
			unknowns = append(unknowns, object.Path+": scheduler job/spool 항목의 패키지별 소유자·실행 비트 의미를 VM에서 확인해야 함")
		}
	}
	if packages["cronie"] && !seenCommands["/usr/bin/crontab"] {
		unknowns = append(unknowns, "cronie가 설치됐지만 /usr/bin/crontab을 확인하지 못함")
	}
	if packages["at"] && !seenCommands["/usr/bin/at"] {
		unknowns = append(unknowns, "at가 설치됐지만 /usr/bin/at을 확인하지 못함")
	}
	violations = uniqueSortedServiceStrings(violations)
	unknowns = uniqueSortedServiceStrings(unknowns)
	evidence = append(evidence, support.FactEvidence("scheduler 권한 파생 정보", map[string]any{
		"installed_package_count": len(packages), "object_count": len(objects),
		"violation_count": len(violations), "unknown_count": len(unknowns), "rpm_verify_difference": rpmUnknown,
		"violation_sample": schedulerLimitedStrings(violations, 20), "unknown_sample": schedulerLimitedStrings(unknowns, 20),
	}))
	if len(violations) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "cron/at 명령 또는 관련 파일에 명백히 과도한 쓰기 권한이나 잘못된 소유자가 있습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("명백한 위반 %d건", len(violations)), Evidence: evidence}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: "가이드 권한 기준과 Rocky 패키지 실행·spool 모델의 충돌을 VM에서 확인해야 합니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("확정 불가 %d건", len(unknowns)), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "확인한 cron/at 명령과 설정 경로에 비소유자 쓰기 또는 잘못된 소유자가 없습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("scheduler 객체 %d개 확인", len(objects)), Evidence: evidence}
}

func inspectSchedulerPackages(ctx context.Context, environment evaluator.Environment) (map[string]bool, []model.Evidence, bool, error) {
	installed := make(map[string]bool)
	evidence := make([]model.Evidence, 0)
	if !environment.Commands.Available("rpm") {
		return installed, []model.Evidence{support.FactEvidence("scheduler RPM", map[string]any{"available": false})}, true, nil
	}
	verifyUnknown := false
	for _, packageName := range []string{"cronie", "cronie-anacron", "at"} {
		querySpec := executor.Spec{Name: "rpm", Arguments: []string{"-q", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", packageName}, Timeout: 30 * time.Second, MaxOutput: 1 << 20}
		query, err := environment.Commands.Run(ctx, querySpec)
		if err != nil {
			return nil, evidence, false, err
		}
		evidence = append(evidence, privateCommandSummary(querySpec, query))
		if query.Truncated {
			return nil, evidence, false, fmt.Errorf("rpm query output was truncated for %s", packageName)
		}
		if query.ExitCode == 1 {
			continue
		}
		if query.ExitCode != 0 {
			return nil, evidence, false, fmt.Errorf("rpm query %s exit=%d", packageName, query.ExitCode)
		}
		installed[packageName] = true
		verifySpec := executor.Spec{Name: "rpm", Arguments: []string{"-V", packageName}, Timeout: 60 * time.Second, MaxOutput: 4 << 20}
		verify, err := environment.Commands.Run(ctx, verifySpec)
		if err != nil {
			return nil, evidence, false, err
		}
		evidence = append(evidence, privateCommandSummary(verifySpec, verify))
		if verify.Truncated || (verify.ExitCode != 0 && verify.ExitCode != 1) {
			return nil, evidence, false, fmt.Errorf("rpm verify %s exit=%d truncated=%t", packageName, verify.ExitCode, verify.Truncated)
		}
		verifyUnknown = verifyUnknown || verify.ExitCode == 1 || len(strings.TrimSpace(string(verify.Stdout))) > 0
	}
	return installed, evidence, verifyUnknown, nil
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
		{Path: "/var/spool/cron", Class: schedulerCronSpool}, {Path: "/var/spool/at", Class: schedulerAtSpool},
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
			if previous != object.Class {
				seen[object.Path] = schedulerUnknownEntry
			}
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

func inspectSchedulerObject(ctx context.Context, environment evaluator.Environment, object schedulerObject) (support.PermissionAssessment, error) {
	policy := support.PermissionPolicy{AllowedTypes: map[string]struct{}{"regular": {}}}
	switch object.Class {
	case schedulerCommand:
		policy.AllowedUIDs = map[int]struct{}{0: {}}
		policy.AllowedMode = 0o755
		policy.AllowedSpecialBits = os.ModeSetuid | os.ModeSetgid
	case schedulerConfig:
		policy.AllowedUIDs = map[int]struct{}{0: {}}
		policy.AllowedMode = 0o644
	case schedulerScript:
		policy.AllowedUIDs = map[int]struct{}{0: {}}
		policy.AllowedMode = 0o755
	case schedulerDirectory:
		policy.AllowedUIDs = map[int]struct{}{0: {}}
		policy.AllowedMode = 0o755
		policy.AllowedTypes = map[string]struct{}{"directory": {}}
		policy.CheckDefaultACL = true
	case schedulerSpoolDir:
		policy.AllowedMode = 0o755
		policy.AllowedTypes = map[string]struct{}{"directory": {}}
		policy.CheckDefaultACL = true
	case schedulerCronSpool:
		policy.AllowedMode = 0o600
	case schedulerAtSpool:
		policy.AllowedMode = 0o700
	case schedulerUnknownEntry:
		policy.AllowedMode = 0o755
		policy.AllowedTypes = map[string]struct{}{"regular": {}, "directory": {}}
	}
	return support.InspectPermissions(ctx, environment.Files, environment.Commands, object.Path, policy)
}

func schedulerIdentities(ctx context.Context, environment evaluator.Environment) (schedulerIdentitySet, []model.Evidence, error) {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return schedulerIdentitySet{}, nil, err
	}
	groups, groupEvidence, err := support.ReadEffectiveGroups(ctx, environment.Commands)
	if err != nil {
		return schedulerIdentitySet{}, []model.Evidence{accountEvidence}, err
	}
	result := schedulerIdentitySet{
		Accounts:    make(map[string]support.PasswdEntry, len(accounts)),
		GroupsByGID: make(map[uint32][]support.GroupEntry),
	}
	for _, account := range accounts {
		if _, duplicate := result.Accounts[account.Name]; duplicate {
			return schedulerIdentitySet{}, []model.Evidence{accountEvidence, groupEvidence}, fmt.Errorf("effective passwd contains a duplicate account")
		}
		result.Accounts[account.Name] = account
	}
	for _, group := range groups {
		result.GroupsByGID[group.GID] = append(result.GroupsByGID[group.GID], group)
	}
	return result, []model.Evidence{accountEvidence, groupEvidence}, nil
}

func inspectSchedulerCommandAccess(
	ctx context.Context,
	environment evaluator.Environment,
	commandPath string,
	mode os.FileMode,
	gid int,
	namedAccessACL bool,
	identities schedulerIdentitySet,
) (schedulerCommandAccess, error) {
	result := schedulerCommandAccess{Complete: true}
	if namedAccessACL {
		result.Complete = false
	}
	candidates := make(map[string]struct{})
	if mode.Perm()&0o001 != 0 {
		for name, account := range identities.Accounts {
			if account.UID != 0 {
				candidates[name] = struct{}{}
			}
		}
	}
	if mode.Perm()&0o010 != 0 {
		if gid < 0 {
			result.Complete = false
		} else {
			groupKnown := false
			for name, account := range identities.Accounts {
				if account.GID == uint32(gid) {
					groupKnown = true
					if account.UID != 0 {
						candidates[name] = struct{}{}
					}
				}
			}
			for _, group := range identities.GroupsByGID[uint32(gid)] {
				groupKnown = true
				for _, member := range group.Members {
					account, exists := identities.Accounts[member]
					if !exists {
						result.Complete = false
						continue
					}
					if account.UID != 0 {
						candidates[member] = struct{}{}
					}
				}
			}
			if !groupKnown {
				result.Complete = false
			}
		}
	}

	allowPath := ""
	denyPath := ""
	switch commandPath {
	case "/usr/bin/crontab":
		allowPath, denyPath = "/etc/cron.allow", "/etc/cron.deny"
	case "/usr/bin/at":
		allowPath, denyPath = "/etc/at.allow", "/etc/at.deny"
	default:
		result.Complete = false
		result.Evidence = append(result.Evidence, support.FactEvidence("scheduler-command-access-summary", map[string]any{
			"supported_command": false, "command_path_sha256": hashFTPStrings([]string{commandPath}),
		}))
		return result, nil
	}

	policyMode, policyUsers, policyComplete, policyEvidence, err := readSchedulerAccessPolicy(ctx, environment, allowPath, denyPath)
	if err != nil {
		return schedulerCommandAccess{}, err
	}
	result.PolicyMode = policyMode
	result.Complete = result.Complete && policyComplete
	result.ExecutableNonRoot = len(candidates)
	allowed := 0
	for name := range candidates {
		switch policyMode {
		case "allow":
			if policyUsers[name] {
				allowed++
			}
		case "deny":
			if !policyUsers[name] {
				allowed++
			}
		case "root_only":
		default:
			result.Complete = false
		}
	}
	result.PolicyAllowedNonRoot = allowed
	result.Evidence = append(result.Evidence, policyEvidence...)
	result.Evidence = append(result.Evidence, support.FactEvidence("scheduler-command-access-summary", map[string]any{
		"command": commandPath, "policy_mode": policyMode, "policy_complete": policyComplete,
		"executable_non_root_count": len(candidates), "policy_allowed_non_root_count": allowed,
		"named_access_acl_present": namedAccessACL, "account_details_redacted": true,
	}))
	return result, nil
}

func readSchedulerAccessPolicy(
	ctx context.Context,
	environment evaluator.Environment,
	allowPath string,
	denyPath string,
) (string, map[string]bool, bool, []model.Evidence, error) {
	for _, candidate := range []struct {
		path string
		mode string
	}{{allowPath, "allow"}, {denyPath, "deny"}} {
		metadata, err := environment.Files.Lstat(candidate.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", nil, false, nil, err
		}
		if metadata.FileType != "regular" {
			return candidate.mode, nil, false, []model.Evidence{support.FactEvidence(candidate.path, map[string]any{
				"exists": true, "file_type": metadata.FileType, "content_redacted": true,
			})}, nil
		}
		data, readMetadata, err := environment.Files.ReadFile(ctx, candidate.path, 1<<20)
		if err != nil {
			return "", nil, false, nil, err
		}
		if readMetadata.Device != metadata.Device || readMetadata.Inode != metadata.Inode || readMetadata.FileType != metadata.FileType {
			return candidate.mode, nil, false, []model.Evidence{support.FactEvidence(candidate.path, map[string]any{
				"exists": true, "changed_during_read": true, "content_redacted": true,
			})}, nil
		}
		users, complete := parseSchedulerAccessUsers(string(data))
		evidence := support.FactEvidence(candidate.path, map[string]any{
			"exists": true, "policy_mode": candidate.mode, "entry_count": len(users),
			"entry_set_sha256": hashFTPStrings(sortedBoolKeys(users)), "parse_complete": complete,
			"content_redacted": true,
		})
		return candidate.mode, users, complete, []model.Evidence{evidence}, nil
	}
	return "root_only", make(map[string]bool), true, []model.Evidence{support.FactEvidence("scheduler-access-policy", map[string]any{
		"allow_exists": false, "deny_exists": false, "effective_mode": "root_only",
	})}, nil
}

func parseSchedulerAccessUsers(content string) (map[string]bool, bool) {
	users := make(map[string]bool)
	complete := true
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		if raw == "" {
			continue
		}
		if raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, " \t:/\\\x00") {
			complete = false
			continue
		}
		users[raw] = true
	}
	return users, complete
}

func sortedBoolKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value, enabled := range values {
		if enabled {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
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
