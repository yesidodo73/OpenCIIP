package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/buildinfo"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
	"github.com/yesidodo73/OpenCIIP/internal/runid"
)

var (
	// ErrInvalidSelection identifies a syntactically valid CLI selection that
	// refers to an unknown profile/check or resolves to no checks.
	ErrInvalidSelection = errors.New("잘못된 점검 선택")
	// ErrInvalidOption identifies an invalid engine option supplied by the
	// caller, such as an unsupported evidence mode.
	ErrInvalidOption = errors.New("잘못된 점검 옵션")
)

type Options struct {
	Selection    model.Selection
	EvidenceMode string
	NoRedact     bool
}

type Engine struct {
	bundle      rules.Bundle
	registry    *evaluator.Registry
	environment evaluator.Environment
	now         func() time.Time
}

func New(bundle rules.Bundle, registry *evaluator.Registry, environment evaluator.Environment) (*Engine, error) {
	if registry == nil {
		return nil, fmt.Errorf("evaluator registry is required")
	}
	if environment.Files == nil {
		return nil, fmt.Errorf("system file reader is required")
	}
	if environment.Commands == nil {
		return nil, fmt.Errorf("command runner is required")
	}
	return &Engine{
		bundle:      bundle,
		registry:    registry,
		environment: environment,
		now:         func() time.Time { return time.Now().UTC() },
	}, nil
}

func (e *Engine) Scan(ctx context.Context, options Options) (model.ScanRun, error) {
	evidenceMode, err := normalizeEvidenceMode(options.EvidenceMode)
	if err != nil {
		return model.ScanRun{}, err
	}
	selection := normalizeSelection(options.Selection)
	startedAt := e.now()
	id, err := runid.New("scan", startedAt)
	if err != nil {
		return model.ScanRun{}, err
	}
	resolved, err := e.bundle.Resolve(e.environment.Platform)
	if err != nil {
		return model.ScanRun{}, fmt.Errorf("resolve effective rules: %w", err)
	}
	selected, err := selectRules(resolved, e.bundle.Profiles, selection)
	if err != nil {
		return model.ScanRun{}, err
	}

	results := make([]model.CheckResult, 0, len(selected))
	complete := true
	for index, rule := range selected {
		if ctx.Err() != nil {
			complete = false
			for _, remaining := range selected[index:] {
				results = append(results, skippedResult(remaining, e.now(), "사용자가 점검 실행을 중단했습니다."))
			}
			break
		}
		result := e.registry.Evaluate(ctx, rule, e.environment)
		if evidenceMode == "none" || (evidenceMode == "problems" &&
			(result.Status == model.StatusPass || result.Status == model.StatusNotApplicable || result.Status == model.StatusSkipped)) {
			result.Evidence = nil
		}
		results = append(results, result)
	}

	completedAt := e.now()
	counts := make(map[model.Status]int, 6)
	for _, result := range results {
		counts[result.Status]++
	}
	info := buildinfo.Current()
	exitStatus := exitcode.ForResults(results)
	if !complete && exitStatus < exitcode.Error {
		exitStatus = exitcode.Error
	}
	metadata := model.RunMetadata{
		SchemaVersion:  1,
		RunID:          id,
		ToolVersion:    info.Version,
		ToolCommit:     info.Commit,
		GuideYear:      e.bundle.Catalog.Guide.Year,
		RuleSetVersion: e.bundle.Version,
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		DurationMS:     completedAt.Sub(startedAt).Milliseconds(),
		Platform:       e.environment.Platform,
		Selection:      selection,
		Counts:         counts,
		EvidenceMode:   evidenceMode,
		Redaction:      !options.NoRedact,
		Complete:       complete,
		ExitCode:       exitStatus,
	}
	if e.environment.Platform.Support != model.SupportVerified && strings.TrimSpace(e.environment.Platform.VerificationWarning) != "" {
		metadata.Warnings = append(metadata.Warnings, e.environment.Platform.VerificationWarning)
	}
	return model.ScanRun{Metadata: metadata, Results: results}, nil
}

func selectRules(resolved []model.ResolvedRule, profiles model.ProfileSet, selection model.Selection) ([]model.ResolvedRule, error) {
	byID := make(map[string]model.ResolvedRule, len(resolved))
	for _, rule := range resolved {
		byID[rule.ID] = rule
	}
	selectedIDs := make(map[string]struct{})
	profileByID := make(map[string]model.Profile, len(profiles.Profiles))
	for _, profile := range profiles.Profiles {
		profileByID[profile.ID] = profile
	}
	for _, profileID := range selection.Profiles {
		profile, exists := profileByID[profileID]
		if !exists {
			return nil, fmt.Errorf("%w: 알 수 없는 점검 프로필 %q", ErrInvalidSelection, profileID)
		}
		for _, ruleID := range profile.RuleIDs {
			selectedIDs[ruleID] = struct{}{}
		}
	}
	for _, ruleID := range selection.RuleIDs {
		ruleID = strings.ToUpper(strings.TrimSpace(ruleID))
		if _, exists := byID[ruleID]; !exists {
			return nil, fmt.Errorf("%w: 알 수 없는 점검 항목 %q", ErrInvalidSelection, ruleID)
		}
		selectedIDs[ruleID] = struct{}{}
	}
	selected := make([]model.ResolvedRule, 0, len(selectedIDs))
	for id := range selectedIDs {
		rule := byID[id]
		if len(selection.Categories) > 0 && !containsCategory(selection.Categories, rule.Category) {
			continue
		}
		if len(selection.Severities) > 0 && !containsSeverity(selection.Severities, rule.Severity) {
			continue
		}
		selected = append(selected, rule)
	}
	sort.SliceStable(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	if len(selected) == 0 {
		return nil, fmt.Errorf("%w: 선택 조건에 해당하는 점검 항목이 없습니다", ErrInvalidSelection)
	}
	return selected, nil
}

func containsCategory(values []model.Category, wanted model.Category) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsSeverity(values []model.Severity, wanted model.Severity) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func skippedResult(rule model.ResolvedRule, now time.Time, summary string) model.CheckResult {
	return model.CheckResult{
		RuleID:         rule.ID,
		Title:          rule.Title,
		Category:       rule.Category,
		Severity:       rule.Severity,
		Status:         model.StatusSkipped,
		Summary:        summary,
		Evaluator:      rule.Evaluator,
		Verification:   rule.Verification,
		BindingSources: append([]string(nil), rule.BindingSources...),
		Reference:      rule.Reference,
		StartedAt:      now,
		CompletedAt:    now,
	}
}

func normalizeSelection(selection model.Selection) model.Selection {
	selection.Profiles = append([]string(nil), selection.Profiles...)
	selection.RuleIDs = append([]string(nil), selection.RuleIDs...)
	selection.Categories = append([]model.Category(nil), selection.Categories...)
	selection.Severities = append([]model.Severity(nil), selection.Severities...)
	if len(selection.Profiles) == 0 && len(selection.RuleIDs) == 0 {
		selection.Profiles = []string{"all"}
	}
	return selection
}

func normalizeEvidenceMode(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "problems", nil
	}
	if value != "problems" && value != "all" && value != "none" {
		return "", fmt.Errorf("%w: 지원하지 않는 증적 저장 범위 %q", ErrInvalidOption, value)
	}
	return value, nil
}
