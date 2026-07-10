package account

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	wheelGroup := ""
	ambiguousControl := false
	missingUseUID := false
	for _, pamRule := range pamRules {
		if pamRule.Type != "auth" || filepath.Base(pamRule.Module) != "pam_wheel.so" {
			continue
		}
		if strings.HasPrefix(pamRule.Control, "[") {
			ambiguousControl = true
			continue
		}
		if pamRule.Control != "required" && pamRule.Control != "requisite" {
			continue
		}
		group := "wheel"
		useUID := false
		for _, argument := range pamRule.Args {
			if argument == "use_uid" {
				useUID = true
			}
			if strings.HasPrefix(argument, "group=") && strings.TrimPrefix(argument, "group=") != "" {
				group = strings.TrimPrefix(argument, "group=")
			}
		}
		if !useUID {
			missingUseUID = true
			continue
		}
		wheelGroup = group
		break
	}
	if wheelGroup == "" {
		if ambiguousControl {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "복합 PAM 제어 구문에서 su 제한의 실효 동작을 확정할 수 없습니다.",
				Expected:      "pam_wheel.so가 required 또는 requisite로 적용되어야 합니다.",
				Observed:      "bracketed PAM control",
				Evidence:      evidence,
			}
		}
		observed := "pam_wheel.so 제한 없음"
		if missingUseUID {
			observed = "pam_wheel.so에 use_uid 없음"
		}
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "일반 사용자의 su 명령 사용이 승인 그룹으로 제한되어 있지 않습니다.",
			Expected: "pam_wheel.so use_uid를 required 또는 requisite로 적용해야 합니다.",
			Observed: observed,
			Evidence: evidence,
		}
	}
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
