package filecheck

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorUserEnvironmentPermissions = "unix.file.user_environment_permissions"
	EvaluatorHomePermissions            = "unix.file.home_permissions"
	EvaluatorHomeExists                 = "unix.file.home_exists"
)

var userEnvironmentFiles = []string{
	".profile",
	".kshrc",
	".cshrc",
	".bashrc",
	".bash_profile",
	".login",
	".exrc",
	".netrc",
}

func evaluateUserEnvironmentPermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return fileError("effective_passwd_failed", "실효 계정 목록을 확인하지 못했습니다.", err)
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		return fileError("home_mounts_failed", "홈 디렉터리의 파일 시스템 유형을 확인하지 못했습니다.", err)
	}
	shellPolicy, shellEvidence, err := collectLoginShellPolicy(ctx, environment.Files)
	if err != nil {
		return fileError("login_shell_policy_failed", "로그인 shell 정책을 확인하지 못했습니다.", err)
	}
	evidence := []model.Evidence{accountEvidence, mountEvidence}
	evidence = append(evidence, shellEvidence...)
	grouped := groupAccountsByHome(accounts)
	violations := make([]pathFinding, 0)
	unknowns := make([]pathFinding, 0)
	checked := 0

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

		for _, name := range userEnvironmentFiles {
			candidate, err := fixedChildPath(home, name)
			if err != nil {
				unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "환경 파일 절대 경로 생성 실패"})
				break
			}
			inspected, err := inspectPathWithoutSymlinks(environment.Files, candidate)
			if err != nil {
				return fileError("environment_file_stat_failed", "환경변수 파일의 유형과 소유자를 확인하지 못했습니다.", fmt.Errorf("%s: %w", candidate, err))
			}
			if !inspected.Exists {
				continue
			}
			evidence = append(evidence, inspected.Evidence...)
			if inspected.Unknown != "" {
				unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: candidate, Reason: inspected.Unknown})
				continue
			}
			if len(homeAccounts) != 1 {
				unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: candidate, Reason: "여러 계정이 같은 홈을 사용하며 소유 정책이 없음"})
				continue
			}
			account := homeAccounts[0]
			login, loginKnown := loginCapability(account, shellPolicy)
			if !loginKnown {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: candidate, Reason: "로그인 shell 절대 경로를 확인할 수 없음"})
				continue
			}
			if !login {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: candidate, Reason: "비로그인 계정 환경 파일의 적용 정책 없음"})
				continue
			}
			metadata := inspected.Metadata
			if metadata.FileType != "regular" {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: candidate, Reason: "일반 파일이 아님"})
				continue
			}
			if metadata.UID < 0 {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: candidate, Reason: "소유자 UID 확인 불가"})
				continue
			}

			reasons := make([]string, 0, 3)
			if metadata.UID != 0 && uint64(metadata.UID) != uint64(account.UID) {
				reasons = append(reasons, fmt.Sprintf("소유자 UID %d", metadata.UID))
			}
			if extraWrite := metadata.Mode.Perm() & 0o022; extraWrite != 0 {
				reasons = append(reasons, fmt.Sprintf("비소유자 쓰기 비트 %04o", extraWrite))
			}
			aclViolations, aclEvidence, err := inspectNonOwnerACL(ctx, environment, metadata, os.FileMode(0o2))
			if err != nil {
				return fileError("environment_file_acl_failed", "환경변수 파일의 ACL을 확인하지 못했습니다.", fmt.Errorf("%s: %w", candidate, err))
			}
			evidence = append(evidence, aclEvidence)
			reasons = append(reasons, aclViolations...)
			checked++
			if len(reasons) > 0 {
				violations = append(violations, pathFinding{Account: account.Name, Path: candidate, Reason: strings.Join(reasons, ", ")})
			}
		}
	}

	evidence = append(evidence, findingEvidence("user-environment-permissions-summary", checked, violations, unknowns))
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
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "공유·원격 홈, 심볼릭 링크 또는 불명확한 경로가 있어 환경변수 파일 권한을 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      findingsObserved(nil, unknowns),
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

func evaluateHomePermissions(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return fileError("effective_passwd_failed", "실효 계정 목록을 확인하지 못했습니다.", err)
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		return fileError("home_mounts_failed", "홈 디렉터리의 파일 시스템 유형을 확인하지 못했습니다.", err)
	}
	shellPolicy, shellEvidence, err := collectLoginShellPolicy(ctx, environment.Files)
	if err != nil {
		return fileError("login_shell_policy_failed", "로그인 shell 정책을 확인하지 못했습니다.", err)
	}
	evidence := []model.Evidence{accountEvidence, mountEvidence}
	evidence = append(evidence, shellEvidence...)
	grouped := groupAccountsByHome(accounts)
	violations := make([]pathFinding, 0)
	unknowns := make([]pathFinding, 0)
	checked := 0

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
		if len(homeAccounts) != 1 {
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "여러 계정이 같은 홈을 사용하며 소유 정책이 없음"})
			continue
		}
		account := homeAccounts[0]
		login, loginKnown := loginCapability(account, shellPolicy)
		if !loginKnown {
			unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "로그인 shell 절대 경로를 확인할 수 없음"})
			continue
		}
		if !login {
			unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "비로그인 계정 홈 권한의 적용 정책 없음"})
			continue
		}
		inspected, err := inspectPathWithoutSymlinks(environment.Files, home)
		if err != nil {
			return fileError("home_stat_failed", "홈 디렉터리의 유형과 소유자를 확인하지 못했습니다.", fmt.Errorf("%s: %w", home, err))
		}
		if !inspected.Exists {
			unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "홈이 없으며 U-32에서 존재 여부 판정"})
			continue
		}
		evidence = append(evidence, inspected.Evidence...)
		if inspected.Unknown != "" {
			unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: inspected.Unknown})
			continue
		}
		metadata := inspected.Metadata
		if metadata.FileType != "directory" {
			violations = append(violations, pathFinding{Account: account.Name, Path: home, Reason: "디렉터리가 아님"})
			continue
		}
		if metadata.UID < 0 {
			unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "소유자 UID 확인 불가"})
			continue
		}
		reasons := make([]string, 0, 3)
		if uint64(metadata.UID) != uint64(account.UID) {
			reasons = append(reasons, fmt.Sprintf("소유자 UID %d, 계정 UID %d", metadata.UID, account.UID))
		}
		if extraWrite := metadata.Mode.Perm() & 0o022; extraWrite != 0 {
			reasons = append(reasons, fmt.Sprintf("비소유자 쓰기 비트 %04o", extraWrite))
		}
		aclViolations, aclEvidence, err := inspectNonOwnerACL(ctx, environment, metadata, os.FileMode(0o2))
		if err != nil {
			return fileError("home_acl_failed", "홈 디렉터리의 ACL을 확인하지 못했습니다.", fmt.Errorf("%s: %w", home, err))
		}
		evidence = append(evidence, aclEvidence)
		reasons = append(reasons, aclViolations...)
		checked++
		if len(reasons) > 0 {
			violations = append(violations, pathFinding{Account: account.Name, Path: home, Reason: strings.Join(reasons, ", ")})
		}
	}

	evidence = append(evidence, findingEvidence("home-permissions-summary", checked, violations, unknowns))
	expected := "홈 디렉터리는 해당 계정 소유이고 다른 사용자에게 쓰기 권한이 없어야 합니다."
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
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "공유·원격 홈, 누락 홈 또는 심볼릭 링크가 있어 홈 권한을 확정할 수 없습니다.",
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
		Observed: fmt.Sprintf("홈 디렉터리 %d개 확인", checked),
		Evidence: evidence,
	}
}

func evaluateHomeExists(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return fileError("effective_passwd_failed", "실효 계정 목록을 확인하지 못했습니다.", err)
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		return fileError("home_mounts_failed", "홈 디렉터리의 파일 시스템 유형을 확인하지 못했습니다.", err)
	}
	shellPolicy, shellEvidence, err := collectLoginShellPolicy(ctx, environment.Files)
	if err != nil {
		return fileError("login_shell_policy_failed", "로그인 shell 정책을 확인하지 못했습니다.", err)
	}
	evidence := []model.Evidence{accountEvidence, mountEvidence}
	evidence = append(evidence, shellEvidence...)
	grouped := groupAccountsByHome(accounts)
	violations := make([]pathFinding, 0)
	unknowns := make([]pathFinding, 0)
	checked := 0

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
		if len(homeAccounts) != 1 {
			unknowns = append(unknowns, pathFinding{Account: accountNames(homeAccounts), Path: home, Reason: "여러 계정이 같은 홈을 사용하며 적용 정책이 없음"})
			continue
		}
		account := homeAccounts[0]
		inspected, err := inspectPathWithoutSymlinks(environment.Files, home)
		if err != nil {
			return fileError("home_stat_failed", "홈 디렉터리의 존재 여부를 확인하지 못했습니다.", fmt.Errorf("%s: %w", home, err))
		}
		if !inspected.Exists {
			login, loginKnown := loginCapability(account, shellPolicy)
			if !loginKnown {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "로그인 shell 정책과 홈 필요성을 확인할 수 없음"})
				continue
			}
			if login {
				violations = append(violations, pathFinding{Account: account.Name, Path: home, Reason: "로그인 가능 계정의 홈 없음"})
			} else {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "비로그인 계정의 홈 필요성 정책 없음"})
			}
			continue
		}
		evidence = append(evidence, inspected.Evidence...)
		if inspected.Unknown != "" {
			unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: inspected.Unknown})
			continue
		}
		if inspected.Metadata.FileType != "directory" {
			login, loginKnown := loginCapability(account, shellPolicy)
			if !loginKnown {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "로그인 shell 정책과 비디렉터리 홈의 적용 여부를 확인할 수 없음"})
				continue
			}
			if login {
				violations = append(violations, pathFinding{Account: account.Name, Path: home, Reason: "홈 경로가 디렉터리가 아님"})
			} else {
				unknowns = append(unknowns, pathFinding{Account: account.Name, Path: home, Reason: "비로그인 계정의 비디렉터리 홈 정책 없음"})
			}
			continue
		}
		checked++
	}

	evidence = append(evidence, findingEvidence("home-existence-summary", checked, violations, unknowns))
	expected := "홈이 필요한 모든 계정의 절대 홈 디렉터리가 실제로 존재해야 합니다."
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
			Summary:       "공유·원격 홈, 비로그인 계정 정책 또는 심볼릭 링크 때문에 홈 존재 여부를 확정할 수 없습니다.",
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
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "적용 계정의 홈 디렉터리가 모두 존재합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("홈 디렉터리 %d개 확인", checked),
		Evidence: evidence,
	}
}
