package account

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorSURestriction = "unix.account.su_restriction"

func evaluateSURestriction(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("passwd_read_failed", err)
	}
	uidMin, uidEvidence, err := readUIDMin(ctx, environment)
	if err != nil {
		return checkError("uid_min_read_failed", err)
	}
	loginAccounts := make([]string, 0)
	for _, account := range accounts {
		if account.UID == 0 || isNonLoginShell(account.Shell) {
			continue
		}
		loginAccounts = append(loginAccounts, account.Name)
	}
	evidence := []model.Evidence{accountEvidence, uidEvidence}
	if len(loginAccounts) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "root 이외에 su 제한을 적용할 로그인 가능 계정이 없습니다.",
			Expected: "로그인 가능 일반 계정이 있으면 su 사용을 승인 그룹으로 제한해야 합니다.",
			Observed: fmt.Sprintf("UID_MIN=%d, 대상 계정 없음", uidMin),
			Evidence: evidence,
		}
	}
	pamRules, pamEvidence, err := support.ReadPAMService(ctx, environment.Files, "su")
	if err != nil {
		return checkError("pam_su_parse_failed", err)
	}
	evidence = append(evidence, pamEvidence...)
	assessment := assessSURestrictionPAM(pamRules)
	if assessment.State == suPAMUnknown {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "PAM 제어 흐름에서 su 제한의 실효 동작을 확정할 수 없습니다.",
			Expected:      "pam_wheel.so use_uid가 우회할 수 없는 required 또는 requisite 경로에 적용되어야 합니다.",
			Observed:      assessment.Observed,
			Evidence:      evidence,
		}
	}
	if assessment.State == suPAMFailed {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "일반 사용자의 su 명령 사용이 승인 그룹으로 제한되어 있지 않습니다.",
			Expected: "pam_wheel.so use_uid를 우회할 수 없는 required 또는 requisite 경로에 적용해야 합니다.",
			Observed: assessment.Observed,
			Evidence: evidence,
		}
	}
	wheelGroup := assessment.Group
	group, groupEvidence, exists, err := support.ReadEffectiveGroup(ctx, environment.Commands, wheelGroup)
	if err != nil {
		return checkError("su_group_lookup_failed", err)
	}
	evidence = append(evidence, groupEvidence)
	if !exists {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "su 제한에 지정된 그룹이 존재하지 않습니다.",
			Expected: "pam_wheel.so에 지정된 승인 그룹이 NSS에서 조회되어야 합니다.",
			Observed: wheelGroup,
			Evidence: evidence,
		}
	}
	allowedGroups, hasAllowedGroups, err := support.StringSliceParameter(rule.Parameters, "allowed_su_groups")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	if !hasAllowedGroups || !containsFold(allowedGroups, wheelGroup) {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownManualVerification,
			Summary:       "su 제한 그룹이 기관의 승인 그룹인지 확인해야 합니다.",
			Expected:      "su 제한 그룹이 승인 목록에 포함되어야 합니다.",
			Observed:      fmt.Sprintf("group=%s gid=%d", group.Name, group.GID),
			Evidence:      evidence,
		}
	}
	metadata, err := environment.Files.Stat("/usr/bin/su")
	if err != nil {
		return checkError("su_binary_stat_failed", err)
	}
	evidence = append(evidence, support.FileMetadataEvidence(metadata))
	if metadata.FileType != "regular" || metadata.UID != 0 || metadata.Mode.Perm()&0o022 != 0 || metadata.Mode&os.ModeSetuid == 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "su 실행 파일의 유형, 소유자 또는 권한이 안전하지 않습니다.",
			Expected: "root 소유 일반 파일이고 비소유자 쓰기가 금지되며 setuid가 설정되어야 합니다.",
			Observed: fmt.Sprintf("type=%s uid=%d mode=%s", metadata.FileType, metadata.UID, metadata.Mode.String()),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "su 명령 사용이 승인 그룹으로 제한되어 있습니다.",
		Expected: "pam_wheel.so use_uid가 안전한 제어 구문으로 적용되어야 합니다.",
		Observed: fmt.Sprintf("group=%s gid=%d members=%d", group.Name, group.GID, len(group.Members)),
		Evidence: evidence,
	}
}

type suPAMState uint8

const (
	suPAMEnforced suPAMState = iota + 1
	suPAMFailed
	suPAMUnknown
)

type suPAMAssessment struct {
	State    suPAMState
	Group    string
	Observed string
}

func assessSURestrictionPAM(rules []support.PAMRule) suPAMAssessment {
	definiteBypass := ""
	ambiguousPredecessors := make([]string, 0)
	ambiguousWheel := ""
	missingUseUID := false
	for _, rule := range rules {
		if rule.Type != "auth" {
			continue
		}
		module := strings.ToLower(filepath.Base(rule.Module))
		control := strings.ToLower(strings.TrimSpace(rule.Control))
		if module == "pam_wheel.so" {
			if strings.HasPrefix(control, "[") {
				ambiguousWheel = fmt.Sprintf("%s:%d pam_wheel.so의 복합 PAM 제어 구문", rule.Path, rule.Line)
			} else if control == "required" || control == "requisite" {
				group := "wheel"
				groupSet := false
				useUID := false
				deny := false
				for _, argument := range rule.Args {
					key, value, hasValue := strings.Cut(argument, "=")
					switch strings.ToLower(strings.TrimSpace(key)) {
					case "use_uid":
						if hasValue {
							return suPAMAssessment{State: suPAMUnknown, Observed: fmt.Sprintf("%s:%d pam_wheel.so use_uid 값을 해석할 수 없음", rule.Path, rule.Line)}
						}
						useUID = true
					case "deny":
						deny = true
					case "group":
						value = strings.TrimSpace(value)
						if !hasValue || value == "" {
							return suPAMAssessment{State: suPAMUnknown, Observed: fmt.Sprintf("%s:%d pam_wheel.so group 값을 해석할 수 없음", rule.Path, rule.Line)}
						}
						if groupSet && group != value {
							return suPAMAssessment{State: suPAMUnknown, Observed: fmt.Sprintf("%s:%d pam_wheel.so group 값이 중복 충돌함", rule.Path, rule.Line)}
						}
						group = value
						groupSet = true
					}
				}
				if deny {
					return suPAMAssessment{State: suPAMFailed, Observed: fmt.Sprintf("%s:%d pam_wheel.so deny 옵션이 승인 그룹 제한을 반대로 적용함", rule.Path, rule.Line)}
				}
				if !useUID {
					missingUseUID = true
				} else if definiteBypass != "" {
					return suPAMAssessment{State: suPAMFailed, Observed: definiteBypass + "가 뒤의 pam_wheel.so 제한을 우회함"}
				} else if len(ambiguousPredecessors) > 0 {
					sort.Strings(ambiguousPredecessors)
					return suPAMAssessment{State: suPAMUnknown, Observed: strings.Join(uniqueSorted(ambiguousPredecessors), "; ") + "가 뒤의 pam_wheel.so 실행을 건너뛸 수 있음"}
				} else {
					return suPAMAssessment{State: suPAMEnforced, Group: group, Observed: fmt.Sprintf("%s:%d group=%s", rule.Path, rule.Line, group)}
				}
			}
		}

		switch control {
		case "required", "requisite", "optional":
			// These controls cannot turn a successful module into an early stack success.
		case "sufficient":
			description := fmt.Sprintf("%s:%d %s sufficient", rule.Path, rule.Line, module)
			switch module {
			case "pam_permit.so":
				if rule.Service == "" || rule.Service == "su" {
					definiteBypass = description
				} else {
					ambiguousPredecessors = append(ambiguousPredecessors, description+" include/substack 반환 범위 미확정")
				}
			case "pam_rootok.so", "pam_deny.so":
				// root's intentional shortcut and a module that cannot succeed for callers
				// do not permit an unapproved general account to bypass pam_wheel.
			default:
				ambiguousPredecessors = append(ambiguousPredecessors, description)
			}
		default:
			ambiguousPredecessors = append(ambiguousPredecessors, fmt.Sprintf("%s:%d %s control=%s", rule.Path, rule.Line, module, rule.Control))
		}
	}
	if ambiguousWheel != "" {
		return suPAMAssessment{State: suPAMUnknown, Observed: ambiguousWheel}
	}
	if missingUseUID {
		return suPAMAssessment{State: suPAMFailed, Observed: "pam_wheel.so에 use_uid 없음"}
	}
	return suPAMAssessment{State: suPAMFailed, Observed: "pam_wheel.so 제한 없음"}
}

func readUIDMin(ctx context.Context, environment evaluator.Environment) (int, model.Evidence, error) {
	data, _, err := environment.Files.ReadFile(ctx, "/etc/login.defs", 1<<20)
	if err != nil {
		return 0, model.Evidence{}, err
	}
	value := 0
	lineNumber := 0
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		fields := strings.Fields(stripComment(raw))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "UID_MIN") {
			continue
		}
		parsed, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil || parsed < 1 {
			return 0, model.Evidence{}, fmt.Errorf("invalid UID_MIN on line %d", index+1)
		}
		value = parsed
		lineNumber = index + 1
	}
	if value == 0 {
		return 0, model.Evidence{}, fmt.Errorf("UID_MIN is not configured")
	}
	return value, support.FactEvidence("/etc/login.defs", map[string]any{"line": lineNumber, "uid_min": value}), nil
}

func isNonLoginShell(shell string) bool {
	switch strings.TrimSpace(shell) {
	case "/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false":
		return true
	default:
		return false
	}
}
