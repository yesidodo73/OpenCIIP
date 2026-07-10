package account

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorShadowPasswords = "unix.account.shadow_password"
	EvaluatorUIDZero         = "unix.account.uid_zero_unique"
	EvaluatorDuplicateUID    = "unix.account.duplicate_uid"
)

func Implementations() map[string]evaluator.Func {
	implementations := map[string]evaluator.Func{
		EvaluatorShadowPasswords: evaluateShadowPasswords,
		EvaluatorUIDZero:         evaluateUIDZero,
		EvaluatorDuplicateUID:    evaluateDuplicateUID,
	}
	for id, implementation := range policyImplementations() {
		implementations[id] = implementation
	}
	for id, implementation := range inventoryImplementations() {
		implementations[id] = implementation
	}
	return implementations
}

func evaluateShadowPasswords(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	entries, passwdEvidence, err := support.ReadPasswd(ctx, environment.Files)
	if err != nil {
		return checkError("passwd_read_failed", err)
	}
	shadowEntries, shadowEvidence, err := support.ReadShadowSummary(ctx, environment.Files)
	if err != nil {
		return checkError("shadow_read_failed", err)
	}
	unsafe := make([]string, 0)
	localAccounts := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		localAccounts[entry.Name] = struct{}{}
		value := strings.TrimSpace(entry.Password)
		if value == "x" {
			if _, exists := shadowEntries[entry.Name]; !exists {
				unsafe = append(unsafe, entry.Name+"(shadow 항목 없음)")
			}
			continue
		}
		if value == "" || (value != "*" && value != "!" && value != "!!") {
			unsafe = append(unsafe, entry.Name)
		}
	}
	for name := range shadowEntries {
		if _, exists := localAccounts[name]; !exists {
			unsafe = append(unsafe, name+"(passwd 항목 없음)")
		}
	}
	evidence := []model.Evidence{passwdEvidence, shadowEvidence}
	if len(unsafe) > 0 {
		sort.Strings(unsafe)
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "비밀번호 파일 보호 설정이 기준을 충족하지 않습니다.",
			Expected: "/etc/shadow를 사용하고 /etc/passwd에 평문 또는 해시를 저장하지 않아야 합니다.",
			Observed: fmt.Sprintf("일관되지 않거나 보호되지 않은 계정: %s", strings.Join(unsafe, ", ")),
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "비밀번호가 보호된 파일 구조로 관리되고 있습니다.",
		Expected: "/etc/shadow를 사용하고 /etc/passwd에 평문 또는 해시를 저장하지 않아야 합니다.",
		Observed: "/etc/shadow가 존재하며 /etc/passwd의 비밀번호 필드에 평문 또는 해시가 없습니다.",
		Evidence: evidence,
	}
}

func evaluateUIDZero(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	entries, evidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("passwd_read_failed", err)
	}
	accounts := make([]string, 0)
	for _, entry := range entries {
		if entry.UID == 0 && entry.Name != "root" {
			accounts = append(accounts, entry.Name)
		}
	}
	if len(accounts) > 0 {
		sort.Strings(accounts)
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "root 이외에 UID 0을 사용하는 계정이 있습니다.",
			Expected: "root 계정만 UID 0을 사용해야 합니다.",
			Observed: strings.Join(accounts, ", "),
			Evidence: []model.Evidence{evidence},
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "root 이외에 UID 0을 사용하는 계정이 없습니다.",
		Expected: "root 계정만 UID 0을 사용해야 합니다.",
		Observed: "root",
		Evidence: []model.Evidence{evidence},
	}
}

func evaluateDuplicateUID(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	entries, evidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("passwd_read_failed", err)
	}
	byUID := make(map[uint32][]string)
	for _, entry := range entries {
		byUID[entry.UID] = append(byUID[entry.UID], entry.Name)
	}
	duplicates := make([]string, 0)
	for uid, accounts := range byUID {
		if len(accounts) < 2 {
			continue
		}
		sort.Strings(accounts)
		duplicates = append(duplicates, fmt.Sprintf("uid=%d:%s", uid, strings.Join(accounts, "/")))
	}
	if len(duplicates) > 0 {
		sort.Strings(duplicates)
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "동일한 UID를 공유하는 계정이 있습니다.",
			Expected: "각 계정은 고유한 UID를 사용해야 합니다.",
			Observed: strings.Join(duplicates, ", "),
			Evidence: []model.Evidence{evidence},
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 계정이 고유한 UID를 사용합니다.",
		Expected: "각 계정은 고유한 UID를 사용해야 합니다.",
		Observed: "중복 UID가 없습니다.",
		Evidence: []model.Evidence{evidence},
	}
}

func checkError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "계정 정보를 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
