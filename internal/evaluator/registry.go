package evaluator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type Environment struct {
	Files    system.Reader
	Commands executor.CommandRunner
	Platform model.PlatformInfo
}

type Outcome struct {
	Status        model.Status
	UnknownReason model.UnknownReason
	Summary       string
	Expected      string
	Observed      string
	Details       []model.ResultDetail
	Evidence      []model.Evidence
	ErrorCode     string
	ErrorMessage  string
}

type Func func(context.Context, model.ResolvedRule, Environment) Outcome

type Registry struct {
	evaluators map[string]Func
}

func NewRegistry() *Registry {
	return &Registry{evaluators: make(map[string]Func)}
}

func (r *Registry) Register(id string, evaluator Func) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("evaluator id is required")
	}
	if evaluator == nil {
		return fmt.Errorf("evaluator %s is nil", id)
	}
	if _, exists := r.evaluators[id]; exists {
		return fmt.Errorf("evaluator %s is already registered", id)
	}
	r.evaluators[id] = evaluator
	return nil
}

func (r *Registry) IDs() []string {
	ids := make([]string, 0, len(r.evaluators))
	for id := range r.evaluators {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (r *Registry) Evaluate(ctx context.Context, rule model.ResolvedRule, environment Environment) (result model.CheckResult) {
	startedAt := time.Now().UTC()
	result = model.CheckResult{
		RuleID:         rule.ID,
		Title:          rule.Title,
		Category:       rule.Category,
		Severity:       rule.Severity,
		Evaluator:      rule.Evaluator,
		Solution:       rule.Criteria.Solution,
		Verification:   rule.Verification,
		BindingSources: append([]string(nil), rule.BindingSources...),
		Reference:      rule.Reference,
		StartedAt:      startedAt,
		CompletedAt:    startedAt,
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			result.Status = model.StatusError
			result.Summary = "점검 처리 중 내부 오류가 발생했습니다."
			result.ErrorCode = "evaluator_panic"
			result.ErrorMessage = "점검 구현에서 예기치 않은 오류가 발생했습니다."
		}
		result.CompletedAt = time.Now().UTC()
		result.DurationMS = result.CompletedAt.Sub(startedAt).Milliseconds()
		normalizeResult(&result)
	}()

	if !rule.Applicable {
		result.Status = model.StatusNotApplicable
		result.Summary = "이 시스템에는 해당 점검 항목이 적용되지 않습니다."
		return result
	}
	if rule.Verification.State == model.VerificationRejected {
		result.Status = model.StatusUnknown
		result.UnknownReason = model.UnknownUnsupportedConfiguration
		result.Summary = "이 플랫폼에서 사용할 수 없는 것으로 검증된 점검 구현입니다."
		result.Expected = rule.Criteria.Pass
		result.Observed = strings.Join(rule.Verification.Environments, ", ")
		return result
	}
	if strings.TrimSpace(rule.Evaluator) == "" {
		result.Status = model.StatusUnknown
		result.UnknownReason = model.UnknownUnsupportedConfiguration
		result.Summary = "이 플랫폼에 연결된 점검 구현이 없습니다."
		return result
	}
	evaluate, exists := r.evaluators[rule.Evaluator]
	if !exists {
		result.Status = model.StatusError
		result.Summary = "규칙에 지정된 점검 구현을 찾지 못했습니다."
		result.ErrorCode = "evaluator_not_registered"
		result.ErrorMessage = rule.Evaluator
		return result
	}

	outcome := evaluate(ctx, rule, environment)
	expected := strings.TrimSpace(rule.Criteria.Pass)
	if expected == "" {
		expected = strings.TrimSpace(outcome.Expected)
	}
	outcome.Expected = expected
	result.Status = outcome.Status
	result.UnknownReason = outcome.UnknownReason
	result.Summary = outcome.Summary
	result.Expected = expected
	result.Observed = outcome.Observed
	result.DisplayDetails = append([]model.ResultDetail(nil), outcome.Details...)
	if len(result.DisplayDetails) == 0 && strings.TrimSpace(outcome.Observed) != "" {
		result.DisplayDetails = defaultDisplayDetails(outcome)
	}
	for _, metadata := range fileMetadataDetails(outcome.Evidence) {
		duplicate := false
		for _, detail := range result.DisplayDetails {
			if detail.Label == "파일 권한" && detail.Source != "" && detail.Source == metadata.Source {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result.DisplayDetails = append(result.DisplayDetails, metadata)
		}
	}
	result.Evidence = append([]model.Evidence(nil), outcome.Evidence...)
	result.ErrorCode = outcome.ErrorCode
	result.ErrorMessage = outcome.ErrorMessage
	return result
}

func defaultDisplayDetails(outcome Outcome) []model.ResultDetail {
	sources := make([]string, 0, len(outcome.Evidence))
	seen := make(map[string]struct{})
	for _, evidence := range outcome.Evidence {
		source := strings.TrimSpace(evidence.Source)
		if source == "" {
			continue
		}
		if _, exists := seen[source]; exists {
			continue
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	source := strings.Join(sources, ", ")
	return []model.ResultDetail{{
		Label: "판정 결과", Current: outcome.Observed,
		Expected: outcome.Expected, Source: source,
	}}
}

func normalizeResult(result *model.CheckResult) {
	if !result.Status.Valid() {
		result.Status = model.StatusError
		result.Summary = "점검 구현이 유효한 판정 상태를 반환하지 않았습니다."
		result.ErrorCode = "invalid_evaluator_status"
	}
	if result.Status != model.StatusUnknown {
		result.UnknownReason = ""
	} else if !result.UnknownReason.Valid() {
		result.UnknownReason = model.UnknownInsufficientEvidence
	}
	if result.Status != model.StatusError {
		result.ErrorCode = ""
		result.ErrorMessage = ""
	}
	if strings.TrimSpace(result.Summary) == "" {
		result.Summary = "점검 결과에 대한 설명이 없습니다."
	}
}
