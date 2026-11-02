package account

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	filecheck "github.com/yesidodo73/OpenCIIP/internal/checks/file"
	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorSessionTimeout = "unix.account.session_timeout"

func evaluateSessionTimeout(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	maximum, found, err := support.IntParameter(rule.Parameters, "max_session_timeout_seconds")
	if err != nil {
		return checkError("invalid_rule_parameter", err)
	}
	if !found {
		maximum = 600
	}
	if maximum < 1 || maximum > 86400 {
		return checkError("invalid_rule_parameter", fmt.Errorf("max_session_timeout_seconds must be between 1 and 86400"))
	}
	expected := fmt.Sprintf("지원되는 모든 대화형 shell에서 export·readonly TMOUT이 1~%d초여야 합니다.", maximum)
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return checkError("account_inventory_failed", err)
	}
	interactive := make([]support.PasswdEntry, 0)
	for _, account := range accounts {
		if isNonLoginShell(account.Shell) {
			continue
		}
		interactive = append(interactive, account)
	}
	if len(interactive) == 0 {
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "세션 종료 시간을 적용할 대화형 계정이 없습니다.",
			Expected: fmt.Sprintf("대화형 shell의 실효 TMOUT이 1~%d초여야 합니다.", maximum),
			Observed: "대화형 계정 없음",
			Evidence: []model.Evidence{accountEvidence},
		}
	}

	evidence := []model.Evidence{accountEvidence}
	violations := make([]string, 0)
	unknowns := make([]string, 0)
	violationDetails := make([]model.ResultDetail, 0)
	unknownDetails := make([]model.ResultDetail, 0)
	contextFacts := make([]map[string]any, 0)
	accountCounts := make(map[string]int, len(interactive))
	for _, account := range interactive {
		accountCounts[account.Name]++
	}
	sort.Slice(interactive, func(i, j int) bool {
		if interactive[i].Name != interactive[j].Name {
			return interactive[i].Name < interactive[j].Name
		}
		if interactive[i].UID != interactive[j].UID {
			return interactive[i].UID < interactive[j].UID
		}
		if interactive[i].Home != interactive[j].Home {
			return interactive[i].Home < interactive[j].Home
		}
		return interactive[i].Shell < interactive[j].Shell
	})
	for _, account := range interactive {
		if accountCounts[account.Name] != 1 {
			if accountCounts[account.Name] > 0 {
				unknowns = append(unknowns, account.Name+": NSS에 같은 이름의 계정 항목이 중복됨")
				unknownDetails = append(unknownDetails, model.ResultDetail{
					Label:    account.Name,
					Current:  "NSS에 같은 이름의 계정 항목이 중복되어 있습니다.",
					Expected: expected,
					Source:   "NSS 계정 목록",
				})
				accountCounts[account.Name] = 0
			}
			continue
		}
		contexts, startupEvidence, supported, analysisErr := filecheck.AnalyzeAccountStartup(ctx, environment, account)
		if analysisErr != nil {
			return checkError("session_timeout_startup_analysis_failed", analysisErr)
		}
		evidence = append(evidence, startupEvidence...)
		if !supported {
			unknowns = append(unknowns, account.Name+": 지원하지 않는 로그인 셸 "+account.Shell)
			unknownDetails = append(unknownDetails, model.ResultDetail{
				Label:    account.Name,
				Current:  "지원하지 않는 로그인 셸: " + account.Shell,
				Expected: expected,
				Source:   "NSS 계정 목록",
			})
			continue
		}
		for _, startupContext := range contexts {
			label := startupContext.Account + "/" + startupContext.Name
			fact := map[string]any{
				"account": startupContext.Account, "context": startupContext.Name,
				"files": startupContext.Paths, "file_count": len(startupContext.Paths),
				"unknowns": startupContext.Unknowns, "unknown_count": len(startupContext.Unknowns),
			}
			if len(startupContext.Unknowns) > 0 {
				unknowns = append(unknowns, label+": "+strings.Join(startupContext.Unknowns, ", "))
				unknownDetails = append(unknownDetails, model.ResultDetail{
					Label:    label,
					Current:  sessionTimeoutItems(startupContext.Unknowns),
					Expected: expected,
					Source:   sessionTimeoutSource(startupContext.Paths),
				})
				fact["deterministic"] = false
				contextFacts = append(contextFacts, fact)
				continue
			}
			fact["deterministic"] = true
			state, exists := startupContext.Variables["TMOUT"]
			if !exists || !state.Defined {
				violations = append(violations, label+": TMOUT 없음")
				violationDetails = append(violationDetails, model.ResultDetail{
					Label:    label,
					Current:  "TMOUT이 설정되어 있지 않습니다.",
					Expected: expected,
					Source:   sessionTimeoutSource(startupContext.Paths),
				})
				fact["tmout_defined"] = false
				contextFacts = append(contextFacts, fact)
				continue
			}
			fact["tmout_defined"] = true
			fact["exported"] = state.Exported
			fact["readonly"] = state.ReadOnly
			fact["source"] = state.Path
			fact["line"] = state.Line
			value, parseErr := strconv.Atoi(strings.TrimSpace(state.Value))
			if parseErr != nil {
				unknowns = append(unknowns, label+": TMOUT 숫자 값을 확정할 수 없음")
				unknownDetails = append(unknownDetails, model.ResultDetail{
					Label:    label,
					Current:  "TMOUT 숫자 값을 확정할 수 없습니다.",
					Expected: expected,
					Source:   sessionTimeoutStateSource(state.Path, state.Line),
				})
				fact["numeric"] = false
				contextFacts = append(contextFacts, fact)
				continue
			}
			fact["numeric"] = true
			fact["value"] = value
			contextFacts = append(contextFacts, fact)
			problems := make([]string, 0, 3)
			if value < 1 || value > maximum {
				problems = append(problems, fmt.Sprintf("TMOUT=%d", value))
			}
			if !state.Exported {
				problems = append(problems, "export 없음")
			}
			if !state.ReadOnly {
				problems = append(problems, "readonly 없음")
			}
			if len(problems) > 0 {
				violations = append(violations, label+": "+strings.Join(problems, ", "))
				violationDetails = append(violationDetails, model.ResultDetail{
					Label:    label,
					Current:  strings.Join(problems, ", "),
					Expected: expected,
					Source:   sessionTimeoutStateSource(state.Path, state.Line),
				})
			}
		}
	}
	evidence = append(evidence, support.FactEvidence("session-timeout-startup-analysis", map[string]any{
		"content_redacted": true, "contexts": contextFacts, "context_count": len(contextFacts),
		"violation_count": len(violations), "unknown_count": len(unknowns),
	}))
	sort.Strings(violations)
	sort.Strings(unknowns)
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "잠금된 세션 종료 시간이 가이드 기준을 충족하지 않습니다.",
			Expected: expected,
			Observed: strings.Join(violations, "; "),
			Details:  violationDetails,
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "모든 대화형 shell의 최종 세션 종료 시간을 정적으로 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      strings.Join(uniqueSorted(unknowns), "; "),
			Details:       unknownDetails,
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "로그인 및 비로그인 대화형 shell에 세션 종료 시간이 강제됩니다.",
		Expected: expected,
		Observed: fmt.Sprintf("%d개 시작 컨텍스트의 최종 TMOUT이 1~%d초이고 export·readonly입니다.", len(contextFacts), maximum),
		Evidence: evidence,
	}
}

func sessionTimeoutItems(items []string) string {
	items = uniqueSorted(append([]string(nil), items...))
	return strings.Join(items, "\n")
}

func sessionTimeoutSource(paths []string) string {
	paths = uniqueSorted(append([]string(nil), paths...))
	value := strings.Join(paths, ", ")
	if value == "" {
		return "시작 스크립트 분석"
	}
	return value
}

func sessionTimeoutStateSource(path string, line int) string {
	if line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	if strings.TrimSpace(path) != "" {
		return path
	}
	return "시작 스크립트 분석"
}
