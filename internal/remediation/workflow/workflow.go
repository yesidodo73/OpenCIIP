package workflow

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/app"
	"github.com/yesidodo73/OpenCIIP/internal/buildinfo"
	checksupport "github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/engine"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/platform"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/contentstore"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/hostidentity"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/orchestrator"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/recipe"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/regularfile"
	"github.com/yesidodo73/OpenCIIP/internal/report"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
	"github.com/yesidodo73/OpenCIIP/internal/runid"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

var ruleIDPattern = regexp.MustCompile(`^U-[0-9]{2}$`)

type Workflow struct {
	stateRoot  string
	systemRoot string
	files      *system.OSReader
	platform   model.PlatformInfo
	host       *hostidentity.Collector
	content    *contentstore.Store
	store      *journal.Store
	recipes    *recipe.Registry
	rules      rules.Bundle
	manager    *orchestrator.Manager
	now        func() time.Time
}

type PlanOptions struct {
	RuleIDs       []string
	FailurePolicy model.FailurePolicy
}

type PlanResult struct {
	Journal  *model.RemediationJournal
	Included []string
	Skipped  []string
}

type gateSnapshot struct {
	platform model.PlatformInfo
	rules    rules.Bundle
	recipes  *recipe.Registry
	build    model.RemediationBuildIdentity
}

func currentBuildIdentity(ctx context.Context, requireRelease bool) (model.RemediationBuildIdentity, error) {
	executableDigest, err := buildinfo.ExecutableSHA256(ctx)
	if err != nil {
		return model.RemediationBuildIdentity{}, fmt.Errorf("현재 조치 실행 파일을 식별하지 못했습니다: %w", err)
	}
	currentBuild := buildinfo.Current()
	build := model.RemediationBuildIdentity{
		Version:          currentBuild.Version,
		Commit:           currentBuild.Commit,
		ExecutableSHA256: executableDigest,
		Modified:         currentBuild.Modified,
	}
	if err := build.Validate(); err != nil {
		return model.RemediationBuildIdentity{}, fmt.Errorf("현재 조치 빌드 identity가 유효하지 않습니다: %w", err)
	}
	if requireRelease && (strings.EqualFold(build.Version, "dev") || strings.EqualFold(build.Version, "unknown") || strings.EqualFold(build.Commit, "unknown") || build.Modified) {
		return model.RemediationBuildIdentity{}, fmt.Errorf("dev, unknown 또는 수정된 빌드에서는 실제 조치나 롤백을 수행할 수 없습니다")
	}
	return build, nil
}

func New(ctx context.Context, stateRoot, systemRoot string) (*Workflow, error) {
	return openExecutionWorkflow(ctx, stateRoot, systemRoot, true)
}

func OpenExecution(ctx context.Context, stateRoot, systemRoot string) (*Workflow, error) {
	return openExecutionWorkflow(ctx, stateRoot, systemRoot, false)
}

func openExecutionWorkflow(ctx context.Context, stateRoot, systemRoot string, create bool) (*Workflow, error) {
	if strings.TrimSpace(stateRoot) == "" || strings.TrimSpace(systemRoot) == "" {
		return nil, fmt.Errorf("조치 상태 경로와 시스템 루트가 필요합니다")
	}
	files, err := system.NewOSReader(systemRoot)
	if err != nil {
		return nil, fmt.Errorf("시스템 파일 접근을 준비하지 못했습니다: %w", err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = files.Close()
		}
	}()
	platformInfo, _, err := platform.NewDetector(files).Detect(ctx)
	if err != nil {
		return nil, fmt.Errorf("플랫폼을 식별하지 못했습니다: %w", err)
	}
	host, err := hostidentity.New(systemRoot)
	if err != nil {
		return nil, fmt.Errorf("호스트 식별을 준비하지 못했습니다: %w", err)
	}
	var journalStore *journal.Store
	if create {
		journalStore, err = journal.New(stateRoot)
	} else {
		journalStore, err = journal.OpenExisting(stateRoot)
	}
	if err != nil {
		return nil, fmt.Errorf("조치 저널 저장소를 준비하지 못했습니다: %w", err)
	}
	var content *contentstore.Store
	if create {
		content, err = contentstore.New(stateRoot)
	} else {
		content, err = contentstore.OpenExisting(stateRoot)
	}
	if err != nil {
		return nil, fmt.Errorf("조치 취소용 payload 저장소를 준비하지 못했습니다: %w", err)
	}
	manager, err := orchestrator.NewWithStore(journalStore, systemRoot, content)
	if err != nil {
		return nil, fmt.Errorf("조치 오케스트레이터를 준비하지 못했습니다: %w", err)
	}
	recipes, err := recipe.LoadDefaults()
	if err != nil {
		return nil, fmt.Errorf("내장 조치 정의를 불러오지 못했습니다: %w", err)
	}
	ruleBundle, err := rules.LoadDefaults()
	if err != nil {
		return nil, fmt.Errorf("내장 점검 규칙을 불러오지 못했습니다: %w", err)
	}
	platformInfo, err = ruleBundle.ResolvePlatformSupport(platformInfo)
	if err != nil {
		return nil, fmt.Errorf("현재 플랫폼의 검증 상태를 해석하지 못했습니다: %w", err)
	}
	workflow := &Workflow{
		stateRoot: journalStore.Root(), systemRoot: systemRoot, files: files, platform: platformInfo,
		host: host, content: content, store: journalStore, recipes: recipes, rules: ruleBundle, manager: manager, now: time.Now,
	}
	succeeded = true
	return workflow, nil
}

// Close releases the rooted system handle owned by an execution workflow.
// Status, recovery, and cancellation workflows do not own one, so Close is a no-op for them.
func (w *Workflow) Close() error {
	if w == nil || w.files == nil {
		return nil
	}
	return w.files.Close()
}

func OpenStatus(stateRoot string) (*Workflow, error) {
	journalStore, err := journal.OpenExisting(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("기존 조치 저널 저장소를 열지 못했습니다: %w", err)
	}
	return &Workflow{stateRoot: journalStore.Root(), store: journalStore, now: time.Now}, nil
}

func OpenRecovery(stateRoot, systemRoot string) (*Workflow, error) {
	journalStore, err := journal.OpenExisting(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("기존 조치 저널 저장소를 열지 못했습니다: %w", err)
	}
	content, _ := contentstore.OpenExisting(stateRoot)
	manager, err := orchestrator.NewWithStore(journalStore, systemRoot, content)
	if err != nil {
		return nil, fmt.Errorf("복구 오케스트레이터를 준비하지 못했습니다: %w", err)
	}
	return &Workflow{
		stateRoot: journalStore.Root(), systemRoot: systemRoot, content: content, store: journalStore, manager: manager, now: time.Now,
	}, nil
}

func OpenCancellation(stateRoot, systemRoot string) (*Workflow, error) {
	journalStore, err := journal.OpenExisting(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("기존 조치 저널 저장소를 열지 못했습니다: %w", err)
	}
	content, err := contentstore.OpenExisting(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("기존 조치 payload 저장소를 열지 못했습니다: %w", err)
	}
	manager, err := orchestrator.NewWithStore(journalStore, systemRoot, content)
	if err != nil {
		return nil, fmt.Errorf("취소 오케스트레이터를 준비하지 못했습니다: %w", err)
	}
	return &Workflow{
		stateRoot: journalStore.Root(), systemRoot: systemRoot, content: content, store: journalStore, manager: manager, now: time.Now,
	}, nil
}

func (w *Workflow) currentGateSnapshot(ctx context.Context, requireRelease bool) (gateSnapshot, error) {
	if w == nil || w.files == nil {
		return gateSnapshot{}, fmt.Errorf("현재 플랫폼을 검증할 수 있는 workflow가 필요합니다")
	}
	currentPlatform, _, err := platform.NewDetector(w.files).Detect(ctx)
	if err != nil {
		return gateSnapshot{}, fmt.Errorf("현재 플랫폼을 다시 식별하지 못했습니다: %w", err)
	}
	currentRules, err := rules.LoadDefaults()
	if err != nil {
		return gateSnapshot{}, fmt.Errorf("현재 내장 규칙 세트를 다시 불러오지 못했습니다: %w", err)
	}
	currentPlatform, err = currentRules.ResolvePlatformSupport(currentPlatform)
	if err != nil {
		return gateSnapshot{}, fmt.Errorf("현재 플랫폼의 검증 상태를 다시 해석하지 못했습니다: %w", err)
	}
	if currentPlatform.ScanSupport != model.ScanSupportTested || currentPlatform.RemediationSupport != model.RemediationSupportVerified {
		return gateSnapshot{}, fmt.Errorf("현재 플랫폼의 자동 조치 지원 상태가 verified가 아닙니다")
	}
	if currentPlatform.Privilege != "root" {
		return gateSnapshot{}, fmt.Errorf("자동 조치 계획·승인·적용은 root 권한에서만 수행할 수 있습니다")
	}
	currentRecipes, err := recipe.LoadDefaults()
	if err != nil {
		return gateSnapshot{}, fmt.Errorf("현재 내장 조치 정의를 다시 불러오지 못했습니다: %w", err)
	}
	build, err := currentBuildIdentity(ctx, requireRelease)
	if err != nil {
		return gateSnapshot{}, err
	}
	return gateSnapshot{platform: currentPlatform, rules: currentRules, recipes: currentRecipes, build: build}, nil
}

func (w *Workflow) verifyJournalExecutionGate(ctx context.Context, runID string, requireRelease bool) (*model.RemediationJournal, error) {
	if w == nil || w.store == nil {
		return nil, fmt.Errorf("조치 저널 저장소가 초기화되지 않았습니다")
	}
	inspection, err := w.store.Inspect(ctx, runID)
	if err != nil {
		return nil, err
	}
	if inspection.IncompleteWALTail {
		return nil, fmt.Errorf("조치 저널에 불완전한 WAL tail이 있으므로 recover --yes를 먼저 실행해야 합니다")
	}
	journalValue := inspection.Journal
	return w.verifyJournalExecutionState(ctx, journalValue, requireRelease)
}

func (w *Workflow) verifyJournalExecutionState(ctx context.Context, journalValue *model.RemediationJournal, requireRelease bool) (*model.RemediationJournal, error) {
	if journalValue == nil {
		return nil, fmt.Errorf("조치 저널이 없습니다")
	}
	current, err := w.currentGateSnapshot(ctx, requireRelease)
	if err != nil {
		return nil, err
	}
	if !model.SameRemediationPlatformIdentity(journalValue.Platform, current.platform) {
		return nil, fmt.Errorf("계획에 바인딩된 플랫폼과 현재 플랫폼이 정확히 일치하지 않습니다")
	}
	if journalValue.RuleSetVersion != current.rules.Version {
		return nil, fmt.Errorf("계획에 바인딩된 규칙 세트와 현재 내장 규칙 세트가 다릅니다")
	}
	if !reflect.DeepEqual(journalValue.RemediationBuild, current.build) {
		return nil, fmt.Errorf("계획을 만든 조치 실행 파일과 현재 실행 파일 identity가 다릅니다")
	}
	resolved, err := current.rules.Resolve(current.platform)
	if err != nil {
		return nil, fmt.Errorf("현재 플랫폼 규칙을 다시 해석하지 못했습니다: %w", err)
	}
	resolvedByID := resolvedRuleMap(resolved)
	ruleIDs := make([]string, 0, len(journalValue.ChangeSets))
	for _, changeSet := range journalValue.ChangeSets {
		ruleIDs = append(ruleIDs, changeSet.RuleID)
		currentRule, exists := resolvedByID[changeSet.RuleID]
		if !exists || !currentRule.Applicable || currentRule.Verification.State != model.VerificationVerified {
			return nil, fmt.Errorf("%s 규칙은 현재 플랫폼에서 verified 조치 대상이 아닙니다", changeSet.RuleID)
		}
		if !reflect.DeepEqual(changeSet.RuleIdentity, ruleIdentity(currentRule)) {
			return nil, fmt.Errorf("%s 규칙의 evaluator 또는 binding provenance가 계획과 다릅니다", changeSet.RuleID)
		}
		currentRecipe, exists := current.recipes.Match(changeSet.RuleID, current.platform)
		if !exists {
			return nil, fmt.Errorf("%s 조치 정의가 현재 내장 정의에 없습니다", changeSet.RuleID)
		}
		if err := requireVerifiedRecipe(currentRecipe); err != nil {
			return nil, err
		}
		currentRecipeIdentity, identityErr := recipeIdentity(currentRecipe)
		if identityErr != nil {
			return nil, fmt.Errorf("%s 조치 정의 identity를 계산하지 못했습니다: %w", changeSet.RuleID, identityErr)
		}
		if !reflect.DeepEqual(changeSet.RecipeIdentity, currentRecipeIdentity) {
			return nil, fmt.Errorf("%s 조치 정의 identity가 계획과 다릅니다", changeSet.RuleID)
		}
	}
	ownerUIDs, err := w.resolveRecipeOwnerUIDs(ctx, ruleIDs, current)
	if err != nil {
		return nil, err
	}
	if err := verifyJournalRecipeResolution(journalValue, current, ownerUIDs); err != nil {
		return nil, err
	}
	freshResults, err := w.scanCurrentRules(ctx, ruleIDs, resolvedByID, current)
	if err != nil {
		return nil, err
	}
	for _, changeSet := range journalValue.ChangeSets {
		result, exists := freshResults[changeSet.RuleID]
		if !exists || result.Status != model.StatusFail {
			status := "결과 없음"
			if exists {
				status = string(result.Status)
			}
			return nil, fmt.Errorf("%s 현재 상태 재점검이 %s이므로 승인된 FAIL 조치를 계속할 수 없습니다", changeSet.RuleID, status)
		}
	}
	return journalValue, nil
}

func resolvedRuleMap(values []model.ResolvedRule) map[string]model.ResolvedRule {
	result := make(map[string]model.ResolvedRule, len(values))
	for _, value := range values {
		result[value.ID] = value
	}
	return result
}

func ruleIdentity(value model.ResolvedRule) model.RemediationRuleIdentity {
	return model.RemediationRuleIdentity{
		ID:             value.ID,
		Title:          value.Title,
		Category:       value.Category,
		Severity:       value.Severity,
		Evaluator:      value.Evaluator,
		Verification:   value.Verification,
		BindingSources: append([]string(nil), value.BindingSources...),
		Reference:      value.Reference,
	}
}

func recipeIdentity(value model.RemediationRecipe) (model.RemediationRecipeIdentity, error) {
	digest, err := journal.Digest(value)
	if err != nil {
		return model.RemediationRecipeIdentity{}, err
	}
	return model.RemediationRecipeIdentity{ID: value.ID, Selector: value.Selector, DefinitionSHA256: digest}, nil
}

func requireVerifiedRecipe(value model.RemediationRecipe) error {
	if value.Verification.State != model.RemediationRecipeVerificationVerified {
		return fmt.Errorf("%s 조치 정의의 검증 상태가 verified가 아닙니다", value.RuleID)
	}
	if err := value.Verification.Validate(); err != nil {
		return fmt.Errorf("%s 조치 정의의 검증 provenance가 유효하지 않습니다: %w", value.RuleID, err)
	}
	return nil
}

func validateReportResultIdentity(result model.CheckResult, resolved model.ResolvedRule) error {
	if result.RuleID != resolved.ID || result.Title != resolved.Title || result.Category != resolved.Category || result.Severity != resolved.Severity || result.Evaluator != resolved.Evaluator {
		return fmt.Errorf("보고서의 %s catalog 또는 evaluator identity가 현재 내장 규칙과 다릅니다", result.RuleID)
	}
	if !reflect.DeepEqual(result.Verification, resolved.Verification) || !reflect.DeepEqual(result.BindingSources, resolved.BindingSources) {
		return fmt.Errorf("보고서의 %s verification 또는 binding provenance가 현재 내장 규칙과 다릅니다", result.RuleID)
	}
	if !reflect.DeepEqual(result.Reference, resolved.Reference) {
		return fmt.Errorf("보고서의 %s 가이드 참조가 현재 내장 규칙과 다릅니다", result.RuleID)
	}
	if !result.Status.Valid() {
		return fmt.Errorf("보고서의 %s 상태가 유효하지 않습니다", result.RuleID)
	}
	return nil
}

func (w *Workflow) PlanFromReport(ctx context.Context, reportDirectory string, options PlanOptions) (PlanResult, error) {
	if w == nil {
		return PlanResult{}, fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	if !options.FailurePolicy.Valid() {
		return PlanResult{}, fmt.Errorf("실패 정책은 rollback_item 또는 rollback_run이어야 합니다")
	}
	scan, err := report.ReadScan(reportDirectory)
	if err != nil {
		return PlanResult{}, err
	}
	return w.Plan(ctx, scan, options)
}

func (w *Workflow) Plan(ctx context.Context, scan model.ScanRun, options PlanOptions) (PlanResult, error) {
	if w == nil || w.manager == nil || w.host == nil || w.recipes == nil {
		return PlanResult{}, fmt.Errorf("조치 workflow가 완전히 초기화되지 않았습니다")
	}
	if !options.FailurePolicy.Valid() {
		return PlanResult{}, fmt.Errorf("실패 정책은 rollback_item 또는 rollback_run이어야 합니다")
	}
	current, err := w.currentGateSnapshot(ctx, false)
	if err != nil {
		return PlanResult{}, err
	}
	if scan.Metadata.TargetIdentity == nil {
		return PlanResult{}, fmt.Errorf("점검 보고서에 호스트 식별 정보가 없습니다")
	}
	actualHost, err := w.host.Collect(ctx)
	if err != nil {
		return PlanResult{}, fmt.Errorf("현재 호스트 식별 정보를 수집하지 못했습니다: %w", err)
	}
	if err := hostidentity.VerifySameBoot(*scan.Metadata.TargetIdentity, actualHost); err != nil {
		return PlanResult{}, fmt.Errorf("보고서와 현재 실행 대상이 같은 호스트·부팅 세션이 아닙니다: %w", err)
	}
	if err := w.validateReportCompatibility(scan, current); err != nil {
		return PlanResult{}, err
	}
	resolvedRules, err := current.rules.Resolve(current.platform)
	if err != nil {
		return PlanResult{}, fmt.Errorf("현재 플랫폼 규칙을 해석하지 못했습니다: %w", err)
	}
	resolvedByID := resolvedRuleMap(resolvedRules)
	selected, explicit, err := normalizeRuleSelection(options.RuleIDs)
	if err != nil {
		return PlanResult{}, err
	}
	resultByID := make(map[string]model.CheckResult, len(scan.Results))
	for _, result := range scan.Results {
		if _, duplicate := resultByID[result.RuleID]; duplicate {
			return PlanResult{}, fmt.Errorf("보고서에 %s 결과가 중복되어 있습니다", result.RuleID)
		}
		resolvedRule, exists := resolvedByID[result.RuleID]
		if !exists {
			return PlanResult{}, fmt.Errorf("보고서의 %s 항목은 현재 내장 규칙에 없습니다", result.RuleID)
		}
		if err := validateReportResultIdentity(result, resolvedRule); err != nil {
			return PlanResult{}, err
		}
		resultByID[result.RuleID] = result
	}
	if explicit {
		for ruleID := range selected {
			if _, exists := resultByID[ruleID]; !exists {
				return PlanResult{}, fmt.Errorf("보고서에 선택 항목 %s가 없습니다", ruleID)
			}
		}
	}
	freshResults, err := w.recheckRemediationCandidates(ctx, scan, selected, explicit, resolvedByID, current)
	if err != nil {
		return PlanResult{}, err
	}
	ownerUIDs, err := w.resolveRecipeOwnerUIDs(ctx, sortedResultRuleIDs(freshResults), current)
	if err != nil {
		return PlanResult{}, err
	}

	runID, err := runid.New("remediation", w.now().UTC())
	if err != nil {
		return PlanResult{}, err
	}
	handler, err := regularfile.New(w.systemRoot, w.stateRoot)
	if err != nil {
		return PlanResult{}, fmt.Errorf("조치 대상 파일 처리기를 준비하지 못했습니다: %w", err)
	}
	changeSets := make([]model.ChangeSet, 0)
	included := make([]string, 0)
	skipped := make([]string, 0)
	for _, result := range scan.Results {
		if explicit {
			if _, wanted := selected[result.RuleID]; !wanted {
				continue
			}
		}
		resolvedRule := resolvedByID[result.RuleID]
		item, eligible, reason := w.eligibleRecipe(scan, result, resolvedRule, current)
		if !eligible {
			if explicit {
				return PlanResult{}, fmt.Errorf("%s 항목은 조치 계획을 만들 수 없습니다: %s", result.RuleID, reason)
			}
			if result.Status == model.StatusFail {
				skipped = append(skipped, result.RuleID+": "+reason)
			}
			continue
		}
		freshResult, exists := freshResults[result.RuleID]
		if !exists {
			return PlanResult{}, fmt.Errorf("%s 항목의 현재 상태 재점검 결과가 없습니다", result.RuleID)
		}
		if freshResult.Status != model.StatusFail {
			reason := fmt.Sprintf("현재 상태 재점검 결과가 %s이므로 과거 FAIL을 조치 근거로 사용할 수 없음", freshResult.Status)
			if explicit {
				return PlanResult{}, fmt.Errorf("%s 항목은 조치 계획을 만들 수 없습니다: %s", result.RuleID, reason)
			}
			skipped = append(skipped, result.RuleID+": "+reason)
			continue
		}
		changeSet, stale, err := w.buildChangeSet(ctx, runID, len(changeSets)+1, item, resolvedRule, ownerUIDs, handler)
		if err != nil {
			if explicit {
				return PlanResult{}, fmt.Errorf("%s 조치 계획을 만들지 못했습니다: %w", result.RuleID, err)
			}
			skipped = append(skipped, result.RuleID+": 현재 위반 형태를 내장 metadata 조치로 안전하게 복원할 수 없음")
			continue
		}
		if stale {
			if explicit {
				return PlanResult{}, fmt.Errorf("%s 대상은 이미 원하는 상태이므로 다시 점검해야 합니다", result.RuleID)
			}
			skipped = append(skipped, result.RuleID+": 현재 상태가 이미 조치 목표와 일치함")
			continue
		}
		changeSet.DryRun = fmt.Sprintf("현재 evaluator 재점검: %s (%s, %s)\n%s",
			freshResult.Status, freshResult.Evaluator, freshResult.CompletedAt.UTC().Format(time.RFC3339), changeSet.DryRun)
		changeSets = append(changeSets, changeSet)
		included = append(included, result.RuleID)
	}
	if len(changeSets) == 0 {
		return PlanResult{}, fmt.Errorf("현재 보고서에서 안전하게 계획할 수 있는 검증 완료 FAIL 항목이 없습니다")
	}
	journalValue, err := w.manager.Plan(ctx, orchestrator.PlanRequest{
		RunID: runID, ScanRunID: scan.Metadata.RunID,
		ScanToolVersion: scan.Metadata.ToolVersion, ScanToolCommit: scan.Metadata.ToolCommit,
		RuleSetVersion: scan.Metadata.RuleSetVersion, Platform: current.platform, RemediationBuild: current.build,
		FailurePolicy: options.FailurePolicy, Host: actualHost, ChangeSets: changeSets,
	})
	if err != nil {
		return PlanResult{Journal: journalValue, Included: included, Skipped: skipped}, err
	}
	sort.Strings(included)
	sort.Strings(skipped)
	return PlanResult{Journal: journalValue, Included: included, Skipped: skipped}, nil
}

func (w *Workflow) Load(ctx context.Context, runID string) (*model.RemediationJournal, error) {
	if w == nil || w.store == nil {
		return nil, fmt.Errorf("조치 저널 저장소가 초기화되지 않았습니다")
	}
	return w.store.LoadReadOnly(ctx, runID)
}

func (w *Workflow) Inspect(ctx context.Context, runID string) (journal.Inspection, error) {
	if w == nil || w.store == nil {
		return journal.Inspection{}, fmt.Errorf("조치 저널 저장소가 초기화되지 않았습니다")
	}
	return w.store.Inspect(ctx, runID)
}

func (w *Workflow) Approve(ctx context.Context, runID, planDigest, source, templateID string) error {
	if w == nil || w.manager == nil {
		return fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("승인 출처가 필요합니다")
	}
	if _, err := w.verifyJournalExecutionGate(ctx, runID, false); err != nil {
		return err
	}
	return w.manager.Approve(ctx, runID, model.Approval{
		Source: source, TemplateID: templateID, PlanDigest: planDigest, ApprovedAt: w.now().UTC(),
	})
}

func (w *Workflow) Apply(ctx context.Context, runID string) error {
	if w == nil || w.manager == nil {
		return fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	return w.manager.ApplyWithVerifier(
		ctx,
		runID,
		func(gateContext context.Context, current *model.RemediationJournal) error {
			_, err := w.verifyJournalExecutionState(gateContext, current, true)
			return err
		},
		func(verificationContext context.Context, applied *model.RemediationJournal, changeSetIDs []string) ([]string, error) {
			return w.verifyAppliedEvaluatorPostconditions(verificationContext, applied, changeSetIDs)
		},
	)
}

func (w *Workflow) verifyAppliedEvaluatorPostconditions(ctx context.Context, applied *model.RemediationJournal, changeSetIDs []string) ([]string, error) {
	if applied == nil {
		return nil, fmt.Errorf("적용 후 검증할 조치 저널이 없습니다")
	}
	if len(changeSetIDs) == 0 {
		return nil, fmt.Errorf("적용 후 검증할 변경 세트가 없습니다")
	}
	selected := make(map[string]struct{}, len(changeSetIDs))
	for _, changeSetID := range changeSetIDs {
		if _, duplicate := selected[changeSetID]; duplicate {
			return nil, fmt.Errorf("적용 후 검증 범위에 %s 변경 세트가 중복되었습니다", changeSetID)
		}
		selected[changeSetID] = struct{}{}
	}
	verificationContext, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	current, gateErr := w.currentGateSnapshot(verificationContext, true)
	failedChangeSets := make([]string, 0, len(selected))
	for _, changeSet := range applied.ChangeSets {
		if _, included := selected[changeSet.ID]; included {
			failedChangeSets = append(failedChangeSets, changeSet.ID)
			delete(selected, changeSet.ID)
		}
	}
	if len(selected) != 0 {
		return failedChangeSets, fmt.Errorf("적용 후 검증 범위에 저널에 없는 변경 세트가 있습니다")
	}
	verificationErr := gateErr
	if gateErr == nil {
		if applied.RuleSetVersion != current.rules.Version ||
			!model.SameRemediationPlatformIdentity(applied.Platform, current.platform) ||
			!reflect.DeepEqual(applied.RemediationBuild, current.build) {
			verificationErr = fmt.Errorf("적용 후 플랫폼, 규칙 또는 실행 파일 identity가 계획과 다릅니다")
		} else {
			resolved, resolveErr := current.rules.Resolve(current.platform)
			if resolveErr != nil {
				verificationErr = fmt.Errorf("적용 후 규칙을 해석하지 못했습니다: %w", resolveErr)
			} else {
				ruleIDs := make([]string, 0, len(failedChangeSets))
				changeSetByRule := make(map[string]string, len(failedChangeSets))
				included := make(map[string]struct{}, len(failedChangeSets))
				for _, changeSetID := range failedChangeSets {
					included[changeSetID] = struct{}{}
				}
				for _, changeSet := range applied.ChangeSets {
					if _, wanted := included[changeSet.ID]; !wanted {
						continue
					}
					ruleIDs = append(ruleIDs, changeSet.RuleID)
					changeSetByRule[changeSet.RuleID] = changeSet.ID
				}
				results, scanErr := w.scanCurrentRules(verificationContext, ruleIDs, resolvedRuleMap(resolved), current)
				if scanErr != nil {
					verificationErr = scanErr
				} else {
					failedChangeSets = failedChangeSets[:0]
					failures := make([]string, 0)
					for _, ruleID := range ruleIDs {
						result, exists := results[ruleID]
						if exists && result.Status == model.StatusPass {
							continue
						}
						status := "결과 없음"
						if exists {
							status = string(result.Status)
						}
						failedChangeSets = append(failedChangeSets, changeSetByRule[ruleID])
						failures = append(failures, ruleID+"="+status)
					}
					if len(failures) > 0 {
						verificationErr = fmt.Errorf("적용 후 evaluator가 PASS를 확인하지 못했습니다: %s", strings.Join(failures, ", "))
					}
				}
			}
		}
	}
	if verificationErr == nil {
		return nil, nil
	}
	return failedChangeSets, verificationErr
}

func (w *Workflow) Cancel(ctx context.Context, runID string) error {
	if w == nil || w.manager == nil {
		return fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	return w.manager.Cancel(ctx, runID)
}

func (w *Workflow) PreviewRollbackItem(ctx context.Context, runID, changeSetID string) (orchestrator.RollbackPreview, error) {
	if w == nil || w.manager == nil {
		return orchestrator.RollbackPreview{}, fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	return w.manager.PreviewRollbackItem(ctx, runID, changeSetID)
}

func (w *Workflow) PreviewRollbackRun(ctx context.Context, runID string) (orchestrator.RollbackPreview, error) {
	if w == nil || w.manager == nil {
		return orchestrator.RollbackPreview{}, fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	return w.manager.PreviewRollbackRun(ctx, runID)
}

func (w *Workflow) RollbackItem(ctx context.Context, runID, changeSetID string, cascadeApproved bool, previewDigest string) (model.RollbackAttempt, error) {
	if w == nil || w.manager == nil {
		return model.RollbackAttempt{}, fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	if _, err := currentBuildIdentity(ctx, true); err != nil {
		return model.RollbackAttempt{}, err
	}
	return w.manager.RollbackItem(ctx, runID, changeSetID, cascadeApproved, previewDigest)
}

func (w *Workflow) RollbackRun(ctx context.Context, runID, previewDigest string) (model.RollbackAttempt, error) {
	if w == nil || w.manager == nil {
		return model.RollbackAttempt{}, fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	if _, err := currentBuildIdentity(ctx, true); err != nil {
		return model.RollbackAttempt{}, err
	}
	return w.manager.RollbackRun(ctx, runID, previewDigest)
}

func (w *Workflow) Recover(ctx context.Context, runID string) (orchestrator.RecoveryAssessment, error) {
	if w == nil || w.manager == nil {
		return orchestrator.RecoveryAssessment{}, fmt.Errorf("조치 workflow가 초기화되지 않았습니다")
	}
	return w.manager.Recover(ctx, runID)
}

func (w *Workflow) validateReportCompatibility(scan model.ScanRun, current gateSnapshot) error {
	metadata := scan.Metadata
	if !metadata.Complete || !metadata.Redaction || metadata.GuideYear != 2026 {
		return fmt.Errorf("완료되고 마스킹된 2026 Unix 점검 보고서만 조치 입력으로 사용할 수 있습니다")
	}
	if metadata.RuleSetVersion != current.rules.Version {
		return fmt.Errorf("보고서 규칙 세트가 현재 실행 파일의 내장 규칙과 다릅니다")
	}
	if !model.SameRemediationPlatformIdentity(metadata.Platform, current.platform) {
		return fmt.Errorf("보고서 플랫폼과 현재 플랫폼이 일치하지 않습니다")
	}
	if metadata.Platform.ScanSupport != model.ScanSupportTested || current.platform.ScanSupport != model.ScanSupportTested ||
		metadata.Platform.RemediationSupport != model.RemediationSupportVerified || current.platform.RemediationSupport != model.RemediationSupportVerified {
		return fmt.Errorf("읽기 전용 점검과 자동 조치 검증을 모두 마친 환경에서만 자동 조치를 계획할 수 있습니다")
	}
	return nil
}

func (w *Workflow) eligibleRecipe(scan model.ScanRun, result model.CheckResult, resolved model.ResolvedRule, current gateSnapshot) (model.RemediationRecipe, bool, string) {
	if result.Status != model.StatusFail {
		return model.RemediationRecipe{}, false, "FAIL 판정이 아님"
	}
	if !resolved.Applicable || resolved.Verification.State != model.VerificationVerified {
		return model.RemediationRecipe{}, false, "현재 환경의 규칙 검증이 완료되지 않음"
	}
	item, exists := current.recipes.Match(result.RuleID, current.platform)
	if !exists {
		return model.RemediationRecipe{}, false, "지원되는 내장 조치 정의가 없음"
	}
	if err := requireVerifiedRecipe(item); err != nil {
		return model.RemediationRecipe{}, false, "현재 환경의 조치 정의 검증이 완료되지 않음"
	}
	if item.GuideYear != scan.Metadata.GuideYear {
		return model.RemediationRecipe{}, false, "조치 정의의 가이드 연도가 보고서와 다름"
	}
	return item, true, ""
}

func (w *Workflow) recheckRemediationCandidates(
	ctx context.Context,
	scan model.ScanRun,
	selected map[string]struct{},
	explicit bool,
	resolvedByID map[string]model.ResolvedRule,
	current gateSnapshot,
) (map[string]model.CheckResult, error) {
	candidateIDs := make([]string, 0)
	for _, result := range scan.Results {
		if explicit {
			if _, wanted := selected[result.RuleID]; !wanted {
				continue
			}
		}
		resolvedRule, exists := resolvedByID[result.RuleID]
		if !exists {
			continue
		}
		if _, eligible, _ := w.eligibleRecipe(scan, result, resolvedRule, current); eligible {
			candidateIDs = append(candidateIDs, result.RuleID)
		}
	}
	if len(candidateIDs) == 0 {
		return map[string]model.CheckResult{}, nil
	}

	return w.scanCurrentRules(ctx, candidateIDs, resolvedByID, current)
}

func (w *Workflow) scanCurrentRules(
	ctx context.Context,
	candidateIDs []string,
	resolvedByID map[string]model.ResolvedRule,
	current gateSnapshot,
) (map[string]model.CheckResult, error) {
	if len(candidateIDs) == 0 {
		return map[string]model.CheckResult{}, nil
	}
	checker, err := app.New(ctx, w.systemRoot)
	if err != nil {
		return nil, fmt.Errorf("현재 조치 후보 재점검을 준비하지 못했습니다: %w", err)
	}
	defer checker.Close()
	fresh, err := checker.Scan(ctx, engine.Options{
		Selection:    model.Selection{RuleIDs: candidateIDs},
		EvidenceMode: "none",
	})
	if err != nil {
		return nil, fmt.Errorf("현재 조치 후보를 재점검하지 못했습니다: %w", err)
	}
	if !fresh.Metadata.Complete {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("현재 조치 후보 재점검이 취소되었습니다: %w", err)
		}
		return nil, fmt.Errorf("현재 조치 후보 재점검이 완결되지 않았습니다")
	}
	if fresh.Metadata.RuleSetVersion != current.rules.Version || !model.SameRemediationPlatformIdentity(fresh.Metadata.Platform, current.platform) {
		return nil, fmt.Errorf("현재 조치 후보 재점검의 플랫폼 또는 규칙 identity가 계획 gate와 다릅니다")
	}

	results := make(map[string]model.CheckResult, len(fresh.Results))
	for _, result := range fresh.Results {
		resolvedRule, exists := resolvedByID[result.RuleID]
		if !exists {
			return nil, fmt.Errorf("현재 재점검의 %s 항목은 계획 규칙 세트에 없습니다", result.RuleID)
		}
		if err := validateReportResultIdentity(result, resolvedRule); err != nil {
			return nil, fmt.Errorf("현재 상태 재점검 결과가 유효하지 않습니다: %w", err)
		}
		if _, duplicate := results[result.RuleID]; duplicate {
			return nil, fmt.Errorf("현재 상태 재점검에 %s 결과가 중복되어 있습니다", result.RuleID)
		}
		results[result.RuleID] = result
	}
	if len(results) != len(candidateIDs) {
		return nil, fmt.Errorf("현재 상태 재점검 결과 수가 조치 후보 수와 다릅니다")
	}
	for _, ruleID := range candidateIDs {
		if _, exists := results[ruleID]; !exists {
			return nil, fmt.Errorf("현재 상태 재점검에 %s 결과가 없습니다", ruleID)
		}
	}
	return results, nil
}

func sortedResultRuleIDs(results map[string]model.CheckResult) []string {
	ruleIDs := make([]string, 0, len(results))
	for ruleID := range results {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	return ruleIDs
}

func (w *Workflow) resolveRecipeOwnerUIDs(ctx context.Context, ruleIDs []string, current gateSnapshot) (map[string]int, error) {
	ownerUIDs := map[string]int{"root": 0}
	wanted := make(map[string]struct{})
	for _, ruleID := range ruleIDs {
		item, exists := current.recipes.Match(ruleID, current.platform)
		if !exists {
			return nil, fmt.Errorf("%s 조치 정의가 현재 내장 정의에 없습니다", ruleID)
		}
		if err := requireVerifiedRecipe(item); err != nil {
			return nil, err
		}
		for _, operation := range item.Operations {
			for _, owner := range append(append([]string(nil), operation.AllowedOwners...), operation.RemediationOwner) {
				if owner != "root" {
					wanted[owner] = struct{}{}
				}
			}
		}
	}
	if len(wanted) == 0 {
		return ownerUIDs, nil
	}
	commands, err := executor.New([]string{"getent"})
	if err != nil {
		return nil, fmt.Errorf("허용 파일 소유자 조회기를 준비하지 못했습니다: %w", err)
	}
	accounts, _, err := checksupport.ReadEffectivePasswd(ctx, commands)
	if err != nil {
		return nil, fmt.Errorf("허용 파일 소유자를 NSS에서 확인하지 못했습니다: %w", err)
	}
	for _, account := range accounts {
		if _, needed := wanted[account.Name]; needed {
			ownerUIDs[account.Name] = int(account.UID)
		}
	}
	return ownerUIDs, nil
}

func verifyJournalRecipeResolution(value *model.RemediationJournal, current gateSnapshot, ownerUIDs map[string]int) error {
	if value == nil {
		return fmt.Errorf("조치 저널이 없습니다")
	}
	for _, changeSet := range value.ChangeSets {
		item, exists := current.recipes.Match(changeSet.RuleID, current.platform)
		if !exists {
			return fmt.Errorf("%s 조치 정의가 현재 내장 정의에 없습니다", changeSet.RuleID)
		}
		if err := requireVerifiedRecipe(item); err != nil {
			return err
		}
		byPath := make(map[string]model.FileMetadataRecipeEntry, len(item.Operations))
		for _, operation := range item.Operations {
			byPath[operation.Path] = operation
		}
		if len(byPath) != len(changeSet.Operations) {
			return fmt.Errorf("%s 계획의 작업 수가 현재 조치 정의와 다릅니다", changeSet.RuleID)
		}
		for _, planned := range changeSet.Operations {
			definition, exists := byPath[planned.Resource.Reference.ID]
			if !exists || planned.ExpectedBefore.File == nil || planned.Desired.File == nil {
				return fmt.Errorf("%s/%s 계획이 현재 조치 정의 또는 파일 snapshot과 일치하지 않습니다", changeSet.ID, planned.ID)
			}
			maximumMode, err := recipe.ParseMode(definition.MaximumMode)
			if err != nil {
				return fmt.Errorf("%s/%s 최대 허용 mode가 잘못되었습니다: %w", changeSet.ID, planned.ID, err)
			}
			allowedUIDs := make(map[int]struct{}, len(definition.AllowedOwners))
			for _, owner := range definition.AllowedOwners {
				if uid, exists := ownerUIDs[owner]; exists {
					allowedUIDs[uid] = struct{}{}
				}
			}
			remediationUID, exists := ownerUIDs[definition.RemediationOwner]
			if !exists {
				return fmt.Errorf("%s/%s 조치 소유자 %s를 NSS에서 확인할 수 없습니다", changeSet.ID, planned.ID, definition.RemediationOwner)
			}
			expectedUID := planned.ExpectedBefore.File.UID
			if _, allowed := allowedUIDs[expectedUID]; !allowed {
				expectedUID = remediationUID
			}
			expectedMode := planned.ExpectedBefore.File.Mode & maximumMode
			if planned.Desired.File.UID != expectedUID ||
				planned.Desired.File.GID != planned.ExpectedBefore.File.GID ||
				planned.Desired.File.Mode != expectedMode {
				return fmt.Errorf("%s/%s 계획의 최소 metadata 변경이 현재 소유자·mode 정책과 다릅니다", changeSet.ID, planned.ID)
			}
			delete(byPath, definition.Path)
		}
		if len(byPath) != 0 {
			return fmt.Errorf("%s 계획에 현재 조치 정의의 일부 작업이 없습니다", changeSet.RuleID)
		}
	}
	return nil
}

func (w *Workflow) buildChangeSet(ctx context.Context, runID string, sequence int, item model.RemediationRecipe, resolved model.ResolvedRule, ownerUIDs map[string]int, handler *regularfile.Handler) (model.ChangeSet, bool, error) {
	identity, err := recipeIdentity(item)
	if err != nil {
		return model.ChangeSet{}, false, fmt.Errorf("조치 정의 identity를 계산하지 못했습니다: %w", err)
	}
	changeSet := model.ChangeSet{
		ID: item.ID, RuleID: item.RuleID, RuleIdentity: ruleIdentity(resolved), RecipeIdentity: identity, Sequence: sequence, Risk: item.Risk, State: model.ChangePlanned,
		DryRun: "", ExpectedImpact: item.ExpectedImpact,
	}
	dryRun := make([]string, 0, len(item.Operations)+3)
	for _, operation := range item.Operations {
		if operation.Type != model.RecipePreserveContentFileMetadata {
			return model.ChangeSet{}, false, fmt.Errorf("지원하지 않는 조치 유형 %s", operation.Type)
		}
		maximumMode, err := recipe.ParseMode(operation.MaximumMode)
		if err != nil {
			return model.ChangeSet{}, false, err
		}
		resource, err := handler.Normalize(ctx, model.ResourceRef{Kind: model.ResourceFile, ID: operation.Path})
		if err != nil {
			return model.ChangeSet{}, false, err
		}
		before, err := handler.Capture(ctx, resource)
		if err != nil {
			return model.ChangeSet{}, false, err
		}
		allowedUIDs := make(map[int]struct{}, len(operation.AllowedOwners))
		for _, owner := range operation.AllowedOwners {
			if uid, exists := ownerUIDs[owner]; exists {
				allowedUIDs[uid] = struct{}{}
			}
		}
		remediationUID, exists := ownerUIDs[operation.RemediationOwner]
		if !exists {
			return model.ChangeSet{}, false, fmt.Errorf("조치 소유자 %s를 NSS에서 확인할 수 없습니다", operation.RemediationOwner)
		}
		desiredUID := before.File.UID
		if _, allowed := allowedUIDs[desiredUID]; !allowed {
			desiredUID = remediationUID
		}
		desiredMode := before.File.Mode & maximumMode
		desired, err := handler.BuildDesiredMetadata(ctx, resource, regularfile.DesiredMetadata{
			UID: desiredUID, GID: before.File.GID, Mode: desiredMode, SELinuxContext: before.File.SELinuxContext,
		})
		if err != nil {
			return model.ChangeSet{}, false, err
		}
		final, err := handler.Capture(ctx, resource)
		if err != nil || !sameStableSnapshot(before, final) {
			if err == nil {
				err = fmt.Errorf("파일 상태가 desired snapshot 생성 중 변경되었습니다")
			}
			return model.ChangeSet{}, false, err
		}
		if before.Fingerprint == desired.Fingerprint {
			continue
		}
		operationIndex := len(changeSet.Operations)
		operationID := fmt.Sprintf("op-%02d", operationIndex+1)
		changeSet.Resources = append(changeSet.Resources, resource)
		changeSet.Operations = append(changeSet.Operations, model.OperationRecord{
			ID: operationID, Sequence: operationIndex + 1, RollbackSequence: 1,
			Kind: model.OperationFileMetadata, RecoveryMode: model.RecoveryStateInferable, State: model.OperationPlanned,
			Resource: resource, ExpectedBefore: before, Desired: desired,
		})
		dryRun = append(dryRun, fmt.Sprintf("%s: uid %d→%d, gid %d 유지, mode %04o→%04o(허용 비트 상한 %04o), inode·내용·확장 속성·SELinux context 유지",
			operation.Path, before.File.UID, desiredUID, before.File.GID,
			before.File.Mode, desiredMode, maximumMode))
	}
	if len(changeSet.Operations) == 0 {
		return model.ChangeSet{}, true, nil
	}
	for index := range changeSet.Operations {
		changeSet.Operations[index].RollbackSequence = len(changeSet.Operations) - index
	}
	backupNamespace := filepath.ToSlash(filepath.Join(w.stateRoot, runID, "backups", changeSet.ID, "<generated-artifact>"))
	dryRun = append(dryRun,
		"백업 정책: 각 항목을 적용하기 직전에 변경 전 상태를 다시 수집하고 content 및 metadata.json 백업을 생성합니다. 저장 바이트 재읽기, SHA-256 및 메타데이터 검증이 모두 성공한 경우에만 변경합니다.",
		fmt.Sprintf("백업 예정 위치 패턴(artifact 이름은 적용 시 무작위 생성): %s/{content,metadata.json}", backupNamespace),
		"롤백 가능 여부(계획): 적용 전 백업 검증이 성공한 항목은 항목별 롤백과 전체 실행 롤백이 가능합니다. 의존성 또는 충돌 관계가 있으면 항목별 롤백 범위가 연쇄 확장될 수 있으며 실행 전 롤백 미리보기를 다시 확인합니다.",
	)
	changeSet.DryRun = strings.Join(dryRun, "\n")
	return changeSet, false, nil
}

func normalizeRuleSelection(values []string) (map[string]struct{}, bool, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !ruleIDPattern.MatchString(value) {
			return nil, false, fmt.Errorf("잘못된 점검 항목 코드입니다: %s", value)
		}
		if _, duplicate := result[value]; duplicate {
			return nil, false, fmt.Errorf("점검 항목 %s가 중복되었습니다", value)
		}
		result[value] = struct{}{}
	}
	return result, len(result) > 0, nil
}

func sameStableSnapshot(left, right model.ResourceSnapshot) bool {
	if left.File == nil || right.File == nil {
		return false
	}
	return left.Fingerprint == right.Fingerprint && left.Reference.Key == right.Reference.Key &&
		left.File.Device == right.File.Device && left.File.Inode == right.File.Inode && left.File.NLink == right.File.NLink &&
		left.File.ParentDevice == right.File.ParentDevice && left.File.ParentInode == right.File.ParentInode
}
