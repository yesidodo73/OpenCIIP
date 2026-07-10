package filecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorRootPath        = "unix.file.root_path"
	EvaluatorUmask           = "unix.file.umask"
	maxStartupProfileScripts = 512
	maxStartupContentBytes   = 16 << 20
)

type startupShellKind string

const (
	startupShellBash startupShellKind = "bash"
	startupShellSH   startupShellKind = "sh"
)

type startupFile struct {
	Path     string
	Exists   bool
	Unknown  string
	Metadata system.FileMetadata
	Analysis support.StaticShellAnalysis
	Actions  []startupAction
}

type startupAction struct {
	Line              int
	Sequence          int
	Operation         support.StaticShellOperation
	ProfileDLoop      bool
	ConditionalTarget string
	ConditionalSource string
}

type startupConditionalSource struct {
	Line   int
	Target string
	Source string
}

type startupVariableOrigin struct {
	Path string
	Line int
}

// StartupVariableState is the final statically proven state of a shell
// variable after one startup context has been evaluated.
type StartupVariableState struct {
	Value    string
	Defined  bool
	Exported bool
	ReadOnly bool
	Path     string
	Line     int
}

// StartupContextAnalysis exposes the shared startup graph result used by
// account and file checks without exposing file contents.
type StartupContextAnalysis struct {
	Account   string
	Name      string
	Paths     []string
	Variables map[string]StartupVariableState
	Unknowns  []string
}

type startupInspector struct {
	ctx              context.Context
	environment      evaluator.Environment
	files            map[string]startupFile
	evidence         []model.Evidence
	profileDLoaded   bool
	profileDPaths    []string
	profileDUnknowns []string
	contentBytes     int64
}

type startupContext struct {
	Account         support.PasswdEntry
	Name            string
	Paths           []string
	InitialVars     map[string]string
	InitialExported map[string]bool
	InitialOrigins  map[string]startupVariableOrigin
	InitialUmask    *uint32
	Unknowns        []string
}

type startupContextResult struct {
	Account   string
	Name      string
	Paths     []string
	Variables map[string]string
	Exported  map[string]bool
	ReadOnly  map[string]bool
	Origins   map[string]startupVariableOrigin
	Umask     *uint32
	Unknowns  []string
}

type startupState struct {
	variables     map[string]string
	exported      map[string]bool
	readOnly      map[string]bool
	origins       map[string]startupVariableOrigin
	umask         *uint32
	unknowns      []string
	appliedPaths  []string
	activeSources map[string]bool
	planPositions map[string]int
	planApplied   map[string]bool
	planCursor    int
}

type rootPathFinding struct {
	Context string
	Reason  string
}

type umaskFinding struct {
	Account string
	Context string
	Value   string
	Reason  string
}

func evaluateRootPath(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.Family != "rhel" {
		return unsupportedStartupPlatform(environment.Platform, "root PATH")
	}
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return startupSettingsError("root_account_inventory_failed", "root 계정 정보를 확인하지 못했습니다.", err)
	}
	rootAccounts := make([]support.PasswdEntry, 0, 1)
	for _, account := range accounts {
		if account.Name == "root" {
			rootAccounts = append(rootAccounts, account)
		}
	}
	if len(rootAccounts) != 1 || rootAccounts[0].UID != 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "root 계정의 유일한 실효 항목을 확정할 수 없습니다.",
			Expected:      "UID 0인 root 계정의 시작 파일 우선순위와 최종 PATH를 정적으로 확정할 수 있어야 합니다.",
			Observed:      fmt.Sprintf("root 이름의 항목 %d개", len(rootAccounts)),
			Evidence:      []model.Evidence{accountEvidence},
		}
	}
	root := rootAccounts[0]
	policy, policyEvidence, err := collectLoginShellPolicy(ctx, environment.Files)
	if err != nil {
		return startupSettingsError("login_shell_policy_failed", "로그인 셸 정책을 확인하지 못했습니다.", err)
	}
	capable, capabilityKnown := loginCapability(root, policy)
	if !capabilityKnown || !capable {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "root 계정에 적용되는 대화형 셸을 확정할 수 없습니다.",
			Expected:      "지원되는 root 로그인 셸의 시작 파일 우선순위와 최종 PATH를 정적으로 확정할 수 있어야 합니다.",
			Observed:      "shell=" + root.Shell,
			Evidence:      append([]model.Evidence{accountEvidence}, policyEvidence...),
		}
	}
	shellKind, supported := supportedStartupShell(root.Shell)
	if !supported {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "root 계정의 셸 시작 규칙을 지원하지 않습니다.",
			Expected:      "Rocky Linux 9.8에서 지원되는 bash 또는 sh 시작 파일 우선순위를 정적으로 해석할 수 있어야 합니다.",
			Observed:      "shell=" + root.Shell,
			Evidence:      append([]model.Evidence{accountEvidence}, policyEvidence...),
		}
	}
	if err := validateAbsoluteSystemPath(root.Home); err != nil {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "root 홈 경로가 정적 분석에 안전한 절대 경로가 아닙니다.",
			Expected:      "root 홈과 시작 파일 경로가 정규화된 절대 경로여야 합니다.",
			Observed:      "getent passwd의 root 홈 경로 형식이 올바르지 않음",
			Evidence:      append([]model.Evidence{accountEvidence}, policyEvidence...),
		}
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		return startupSettingsError("mount_inventory_failed", "root 홈이 위치한 파일 시스템을 확인하지 못했습니다.", err)
	}
	mountKind, _, found := mounts.classify(root.Home)
	if !found || mountKind != homeMountLocal {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "root 시작 파일을 로컬 정적 파일로 확정할 수 없습니다.",
			Expected:      "root 홈의 시작 파일을 동일한 시스템 스냅샷에서 정적으로 읽을 수 있어야 합니다.",
			Observed:      fmt.Sprintf("root 홈 마운트 분류=%s", mountKind),
			Evidence:      append(append([]model.Evidence{accountEvidence}, policyEvidence...), mountEvidence),
		}
	}

	inspector := newStartupInspector(ctx, environment)
	contexts, err := inspector.contexts(root, shellKind, nil, nil)
	if err != nil {
		return startupSettingsError("startup_context_failed", "root 시작 파일의 우선순위를 구성하지 못했습니다.", err)
	}
	results, err := inspector.evaluateContexts(contexts)
	if err != nil {
		return startupSettingsError("root_path_analysis_failed", "root PATH 설정을 정적으로 분석하지 못했습니다.", err)
	}

	violations := make([]rootPathFinding, 0)
	unknowns := make([]rootPathFinding, 0)
	warnings := make([]rootPathFinding, 0)
	for _, result := range results {
		if len(result.Unknowns) > 0 {
			unknowns = append(unknowns, rootPathFinding{Context: result.Name, Reason: summarizeStrings(result.Unknowns, 8)})
			continue
		}
		value, known := result.Variables["PATH"]
		if !known {
			unknowns = append(unknowns, rootPathFinding{Context: result.Name, Reason: "최종 PATH 값 없음"})
			continue
		}
		pathViolations, trailingCurrentDirectory := inspectRootPath(value)
		for _, reason := range pathViolations {
			violations = append(violations, rootPathFinding{Context: result.Name, Reason: reason})
		}
		if trailingCurrentDirectory {
			warnings = append(warnings, rootPathFinding{Context: result.Name, Reason: "마지막 구성요소가 현재 디렉터리(.)임"})
		}
	}
	sortRootPathFindings(violations)
	sortRootPathFindings(unknowns)
	sortRootPathFindings(warnings)
	evidence := append(append([]model.Evidence{accountEvidence}, policyEvidence...), mountEvidence)
	evidence = append(evidence, inspector.evidence...)
	evidence = append(evidence, rootPathEvidence(results, violations, unknowns, warnings))
	expected := "지원되는 모든 root 로그인·대화형 시작 경로의 최종 PATH에 빈 구성요소가 없어야 하며, 현재 디렉터리(.)가 맨 앞이나 중간에 없어야 합니다."
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "root PATH에서 현재 디렉터리가 안전한 명령 경로보다 먼저 검색될 수 있습니다.",
			Expected: expected,
			Observed: formatRootPathFindings(violations, 8),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "root의 최종 PATH를 정적으로 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      formatRootPathFindings(unknowns, 8),
			Evidence:      evidence,
		}
	}
	observed := fmt.Sprintf("%d개 시작 컨텍스트에서 빈 구성요소와 앞·중간의 현재 디렉터리 항목이 없음", len(results))
	if len(warnings) > 0 {
		observed += "; 참고: " + formatRootPathFindings(warnings, 8)
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "정적으로 확정된 root PATH가 가이드 기준을 충족합니다.",
		Expected: expected,
		Observed: observed,
		Evidence: evidence,
	}
}

func evaluateUmask(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.Family != "rhel" {
		return unsupportedStartupPlatform(environment.Platform, "UMASK")
	}
	accounts, accountEvidence, err := support.ReadEffectivePasswd(ctx, environment.Commands)
	if err != nil {
		return startupSettingsError("umask_account_inventory_failed", "UMASK 적용 계정을 확인하지 못했습니다.", err)
	}
	policy, policyEvidence, err := collectLoginShellPolicy(ctx, environment.Files)
	if err != nil {
		return startupSettingsError("login_shell_policy_failed", "로그인 셸 정책을 확인하지 못했습니다.", err)
	}
	mounts, mountEvidence, err := collectHomeMounts(ctx, environment)
	if err != nil {
		return startupSettingsError("mount_inventory_failed", "계정 홈이 위치한 파일 시스템을 확인하지 못했습니다.", err)
	}
	inspector := newStartupInspector(ctx, environment)
	initialUmask, initialUnknowns, err := inspector.loginDefsUmask()
	if err != nil {
		return startupSettingsError("login_defs_umask_failed", "/etc/login.defs의 UMASK를 확인하지 못했습니다.", err)
	}

	results := make([]startupContextResult, 0)
	unknowns := make([]umaskFinding, 0)
	applicableAccounts := 0
	orderedAccounts := append([]support.PasswdEntry(nil), accounts...)
	sort.Slice(orderedAccounts, func(i, j int) bool {
		if orderedAccounts[i].Name != orderedAccounts[j].Name {
			return orderedAccounts[i].Name < orderedAccounts[j].Name
		}
		if orderedAccounts[i].UID != orderedAccounts[j].UID {
			return orderedAccounts[i].UID < orderedAccounts[j].UID
		}
		if orderedAccounts[i].Home != orderedAccounts[j].Home {
			return orderedAccounts[i].Home < orderedAccounts[j].Home
		}
		return orderedAccounts[i].Shell < orderedAccounts[j].Shell
	})
	accountNameCounts := make(map[string]int, len(orderedAccounts))
	for _, account := range orderedAccounts {
		accountNameCounts[account.Name]++
	}
	for _, account := range orderedAccounts {
		if accountNameCounts[account.Name] != 1 {
			if accountNameCounts[account.Name] > 0 {
				unknowns = append(unknowns, umaskFinding{Account: account.Name, Reason: "NSS에 같은 이름의 계정 항목이 중복됨"})
				accountNameCounts[account.Name] = 0
			}
			continue
		}
		capable, capabilityKnown := loginCapability(account, policy)
		if !capabilityKnown {
			unknowns = append(unknowns, umaskFinding{Account: account.Name, Reason: "로그인 셸 적용 여부를 확정할 수 없음"})
			continue
		}
		if !capable {
			continue
		}
		applicableAccounts++
		shellKind, supported := supportedStartupShell(account.Shell)
		if !supported {
			unknowns = append(unknowns, umaskFinding{Account: account.Name, Reason: "지원하지 않는 로그인 셸: " + account.Shell})
			continue
		}
		if err := validateAbsoluteSystemPath(account.Home); err != nil {
			unknowns = append(unknowns, umaskFinding{Account: account.Name, Reason: "홈 경로를 정적으로 해석할 수 없음"})
			continue
		}
		mountKind, _, found := mounts.classify(account.Home)
		if !found || mountKind != homeMountLocal {
			unknowns = append(unknowns, umaskFinding{Account: account.Name, Reason: fmt.Sprintf("홈 마운트 분류=%s", mountKind)})
			continue
		}
		contexts, contextErr := inspector.contexts(account, shellKind, initialUmask, initialUnknowns)
		if contextErr != nil {
			return startupSettingsError("startup_context_failed", "계정 시작 파일의 우선순위를 구성하지 못했습니다.", contextErr)
		}
		accountResults, evaluateErr := inspector.evaluateContexts(contexts)
		if evaluateErr != nil {
			return startupSettingsError("umask_analysis_failed", "UMASK 설정을 정적으로 분석하지 못했습니다.", evaluateErr)
		}
		results = append(results, accountResults...)
	}

	violations := make([]umaskFinding, 0)
	for _, result := range results {
		if len(result.Unknowns) > 0 {
			unknowns = append(unknowns, umaskFinding{
				Account: result.Account,
				Context: result.Name,
				Reason:  summarizeStrings(result.Unknowns, 8),
			})
			continue
		}
		if result.Umask == nil {
			unknowns = append(unknowns, umaskFinding{Account: result.Account, Context: result.Name, Reason: "최종 UMASK 값 없음"})
			continue
		}
		value := *result.Umask
		if value&0o022 != 0o022 {
			violations = append(violations, umaskFinding{
				Account: result.Account,
				Context: result.Name,
				Value:   fmt.Sprintf("%04o", value),
				Reason:  "group 또는 other 쓰기 권한을 차단하는 비트가 부족함",
			})
		}
	}
	sortUmaskFindings(violations)
	sortUmaskFindings(unknowns)
	evidence := append(append([]model.Evidence{accountEvidence}, policyEvidence...), mountEvidence)
	evidence = append(evidence, inspector.evidence...)
	evidence = append(evidence, umaskEvidence(applicableAccounts, results, violations, unknowns))
	expected := "모든 적용 계정의 로그인 및 대화형 셸 최종 UMASK에 0022 비트가 모두 포함되어야 합니다."
	if len(violations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "정적으로 확정된 계정 컨텍스트에 0022보다 약한 UMASK가 적용됩니다.",
			Expected: expected,
			Observed: formatUmaskFindings(violations, 12),
			Evidence: evidence,
		}
	}
	if len(unknowns) > 0 || applicableAccounts == 0 {
		observed := formatUmaskFindings(unknowns, 12)
		if applicableAccounts == 0 {
			if observed == "" {
				observed = "적용 가능한 로그인 계정을 확정할 수 없음"
			} else {
				observed = "적용 가능한 로그인 계정을 확정할 수 없음; " + observed
			}
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "모든 적용 계정의 최종 UMASK를 정적으로 확정할 수 없습니다.",
			Expected:      expected,
			Observed:      observed,
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "정적으로 확정된 모든 적용 계정의 UMASK가 가이드 기준을 충족합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("%d개 적용 계정의 %d개 시작 컨텍스트에서 최종 UMASK가 0022 비트를 모두 포함함", applicableAccounts, len(results)),
		Evidence: evidence,
	}
}

func newStartupInspector(ctx context.Context, environment evaluator.Environment) *startupInspector {
	return &startupInspector{
		ctx:         ctx,
		environment: environment,
		files:       make(map[string]startupFile),
	}
}

// AnalyzeAccountStartup evaluates the same implicit and explicitly sourced
// shell startup graph used by the root PATH and UMASK checks. The supported
// return value is false for shells whose startup rules are not implemented.
func AnalyzeAccountStartup(ctx context.Context, environment evaluator.Environment, account support.PasswdEntry) ([]StartupContextAnalysis, []model.Evidence, bool, error) {
	shellKind, supported := supportedStartupShell(account.Shell)
	if !supported {
		return nil, nil, false, nil
	}
	if err := validateAbsoluteSystemPath(account.Home); err != nil {
		unknown := "홈 경로를 정적으로 해석할 수 없음"
		return []StartupContextAnalysis{{Account: account.Name, Name: "unsupported-home", Unknowns: []string{unknown}}},
			[]model.Evidence{support.FactEvidence("startup-account", map[string]any{
				"account": account.Name, "shell": account.Shell, "deterministic": false, "reason": unknown,
			})}, true, nil
	}
	inspector := newStartupInspector(ctx, environment)
	contexts, err := inspector.contexts(account, shellKind, nil, nil)
	if err != nil {
		return nil, nil, true, err
	}
	results, err := inspector.evaluateContexts(contexts)
	if err != nil {
		return nil, nil, true, err
	}
	analyses := make([]StartupContextAnalysis, 0, len(results))
	for _, result := range results {
		variables := make(map[string]StartupVariableState, len(result.Variables)+len(result.Exported)+len(result.ReadOnly))
		names := make(map[string]struct{}, len(result.Variables)+len(result.Exported)+len(result.ReadOnly))
		for name := range result.Variables {
			names[name] = struct{}{}
		}
		for name := range result.Exported {
			names[name] = struct{}{}
		}
		for name := range result.ReadOnly {
			names[name] = struct{}{}
		}
		for name := range names {
			value, defined := result.Variables[name]
			state := StartupVariableState{Value: value, Defined: defined, Exported: result.Exported[name], ReadOnly: result.ReadOnly[name]}
			if origin, exists := result.Origins[name]; exists {
				state.Path = origin.Path
				state.Line = origin.Line
			}
			variables[name] = state
		}
		analyses = append(analyses, StartupContextAnalysis{
			Account: result.Account, Name: result.Name, Paths: append([]string(nil), result.Paths...),
			Variables: variables, Unknowns: append([]string(nil), result.Unknowns...),
		})
	}
	return analyses, append([]model.Evidence(nil), inspector.evidence...), true, nil
}

func (inspector *startupInspector) load(systemPath string) (startupFile, error) {
	if cached, exists := inspector.files[systemPath]; exists {
		return cached, nil
	}
	if err := validateAbsoluteSystemPath(systemPath); err != nil {
		return startupFile{}, err
	}
	inspected, err := inspectPathWithoutSymlinks(inspector.environment.Files, systemPath)
	if err != nil {
		return startupFile{}, err
	}
	loaded := startupFile{Path: systemPath, Exists: inspected.Exists, Unknown: inspected.Unknown, Metadata: inspected.Metadata}
	inspector.evidence = append(inspector.evidence, inspected.Evidence...)
	if !inspected.Exists {
		inspector.evidence = append(inspector.evidence, support.FactEvidence(systemPath, map[string]any{"exists": false}))
		inspector.files[systemPath] = loaded
		return loaded, nil
	}
	if inspected.Unknown != "" {
		inspector.evidence = append(inspector.evidence, support.FactEvidence(systemPath, map[string]any{
			"exists": true, "content_redacted": true, "unknown": inspected.Unknown,
		}))
		inspector.files[systemPath] = loaded
		return loaded, nil
	}
	if inspected.Metadata.FileType != "regular" {
		loaded.Unknown = "시작 경로가 일반 파일이 아님"
		inspector.evidence = append(inspector.evidence, support.FactEvidence(systemPath, map[string]any{
			"exists": true, "content_redacted": true, "unknown": loaded.Unknown,
		}))
		inspector.files[systemPath] = loaded
		return loaded, nil
	}
	if inspected.Metadata.Size < 0 || inspected.Metadata.Size > maxStartupContentBytes-inspector.contentBytes {
		loaded.Unknown = fmt.Sprintf("시작 파일 누적 분석 크기가 %d바이트 한도를 초과함", maxStartupContentBytes)
		inspector.evidence = append(inspector.evidence, support.FactEvidence(systemPath, map[string]any{
			"exists": true, "content_redacted": true, "unknown": loaded.Unknown, "size": inspected.Metadata.Size,
		}))
		inspector.files[systemPath] = loaded
		return loaded, nil
	}
	data, metadata, err := inspector.environment.Files.ReadFile(inspector.ctx, systemPath, 2<<20)
	if err != nil {
		return startupFile{}, err
	}
	if metadata.Device != inspected.Metadata.Device || metadata.Inode != inspected.Metadata.Inode || metadata.FileType != inspected.Metadata.FileType {
		loaded.Unknown = "검사와 읽기 사이에 시작 파일 대상이 변경됨"
		inspector.evidence = append(inspector.evidence, support.FileMetadataEvidence(metadata))
		inspector.evidence = append(inspector.evidence, support.FactEvidence(systemPath, map[string]any{
			"exists": true, "content_redacted": true, "unknown": loaded.Unknown,
		}))
		inspector.files[systemPath] = loaded
		return loaded, nil
	}
	if int64(len(data)) > maxStartupContentBytes-inspector.contentBytes {
		loaded.Unknown = fmt.Sprintf("시작 파일 누적 분석 크기가 %d바이트 한도를 초과함", maxStartupContentBytes)
		inspector.evidence = append(inspector.evidence, support.FactEvidence(systemPath, map[string]any{
			"exists": true, "content_redacted": true, "unknown": loaded.Unknown, "size": len(data),
		}))
		inspector.files[systemPath] = loaded
		return loaded, nil
	}
	inspector.contentBytes += int64(len(data))
	staticData, profileLoops := extractRockyProfileDLoops(data)
	staticData, conditionalSources := extractStaticConditionalSources(staticData)
	loaded.Analysis = support.AnalyzeStaticShell(systemPath, staticData)
	loaded.Actions = make([]startupAction, 0, len(loaded.Analysis.Operations)+len(profileLoops)+len(conditionalSources))
	for sequence, operation := range loaded.Analysis.Operations {
		loaded.Actions = append(loaded.Actions, startupAction{
			Line:      operation.Line,
			Sequence:  sequence,
			Operation: operation,
		})
	}
	for sequence, line := range profileLoops {
		loaded.Actions = append(loaded.Actions, startupAction{
			Line:         line,
			Sequence:     len(loaded.Analysis.Operations) + sequence,
			ProfileDLoop: true,
		})
	}
	for sequence, source := range conditionalSources {
		loaded.Actions = append(loaded.Actions, startupAction{
			Line: source.Line, Sequence: len(loaded.Analysis.Operations) + len(profileLoops) + sequence,
			ConditionalTarget: source.Target, ConditionalSource: source.Source,
		})
	}
	sort.SliceStable(loaded.Actions, func(i, j int) bool {
		if loaded.Actions[i].Line != loaded.Actions[j].Line {
			return loaded.Actions[i].Line < loaded.Actions[j].Line
		}
		return loaded.Actions[i].Sequence < loaded.Actions[j].Sequence
	})
	issueLimit := minInt(len(loaded.Analysis.Issues), 128)
	issueFacts := make([]map[string]any, 0, issueLimit)
	for _, issue := range loaded.Analysis.Issues[:issueLimit] {
		issueFacts = append(issueFacts, map[string]any{"line": issue.Line, "reason": issue.Reason})
	}
	operationCounts := make(map[string]int)
	for _, operation := range loaded.Analysis.Operations {
		operationCounts[string(operation.Kind)]++
	}
	if len(profileLoops) > 0 {
		operationCounts["rocky_profile_d_loop"] = len(profileLoops)
	}
	if len(conditionalSources) > 0 {
		operationCounts["fixed_file_conditional_source"] = len(conditionalSources)
	}
	inspector.evidence = append(inspector.evidence, support.FactEvidence(systemPath, map[string]any{
		"exists":           true,
		"content_redacted": true,
		"operation_counts": operationCounts,
		"issue_count":      len(loaded.Analysis.Issues),
		"issues":           issueFacts,
		"issues_truncated": len(loaded.Analysis.Issues) > issueLimit,
	}))
	inspector.files[systemPath] = loaded
	return loaded, nil
}

var rockyProfileDLoopPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^for[ \t]+i[ \t]+in[ \t]+/etc/profile\.d/\*\.sh[ \t]+/etc/profile\.d/sh\.local[ \t]*;[ \t]*do$`),
	regexp.MustCompile(`^if[ \t]+\[[ \t]+-r[ \t]+"\$i"[ \t]+\][ \t]*;[ \t]*then$`),
	regexp.MustCompile(`^if[ \t]+\[[ \t]+"\$\{-#\*i\}"[ \t]+!=[ \t]+"\$-"[ \t]+\][ \t]*;[ \t]*then$`),
	regexp.MustCompile(`^\.[ \t]+"\$i"$`),
	regexp.MustCompile(`^else$`),
	regexp.MustCompile(`^\.[ \t]+"\$i"[ \t]*>[ \t]*/dev/null$`),
	regexp.MustCompile(`^fi$`),
	regexp.MustCompile(`^fi$`),
	regexp.MustCompile(`^done$`),
}

// extractRockyProfileDLoops recognizes only the verified Rocky Linux 9.8
// profile.d loop. The two branches source the same readable file and differ
// only in output redirection, so the resulting source order is deterministic.
// Any structural or target difference is left untouched and is therefore
// reported as an unsupported shell flow by AnalyzeStaticShell.
func extractRockyProfileDLoops(data []byte) ([]byte, []int) {
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return data, nil
	}
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		return data, nil
	}
	lines := strings.Split(normalized, "\n")
	loopLines := make([]int, 0, 1)
	for index := 0; index < len(lines); index++ {
		if !rockyProfileDLoopPatterns[0].MatchString(strings.TrimSpace(lines[index])) {
			continue
		}
		matched := make([]int, 0, len(rockyProfileDLoopPatterns))
		cursor := index
		for patternIndex, pattern := range rockyProfileDLoopPatterns {
			for cursor < len(lines) {
				trimmed := strings.TrimSpace(lines[cursor])
				if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					break
				}
				cursor++
			}
			if cursor >= len(lines) || !pattern.MatchString(strings.TrimSpace(lines[cursor])) {
				matched = nil
				break
			}
			matched = append(matched, cursor)
			cursor++
			if patternIndex == 0 {
				index = matched[0]
			}
		}
		if len(matched) != len(rockyProfileDLoopPatterns) {
			continue
		}
		for _, lineIndex := range matched {
			lines[lineIndex] = ""
		}
		loopLines = append(loopLines, matched[0]+1)
		index = matched[len(matched)-1]
	}
	return []byte(strings.Join(lines, "\n")), loopLines
}

var (
	fixedFileConditionalStart = regexp.MustCompile(`^if[ \t]+\[[ \t]+-f[ \t]+("[^"]*"|'[^']*'|[^ \t;]+)[ \t]+\][ \t]*;[ \t]*then$`)
	fixedFileSourceLine       = regexp.MustCompile(`^(\.|source)[ \t]+("[^"]*"|'[^']*'|[^ \t;]+)[ \t]*$`)
	fixedFileConditionalOne   = regexp.MustCompile(`^if[ \t]+\[[ \t]+-f[ \t]+("[^"]*"|'[^']*'|[^ \t;]+)[ \t]+\][ \t]*;[ \t]*then[ \t]+(\.|source)[ \t]+("[^"]*"|'[^']*'|[^ \t;]+)[ \t]*;[ \t]*fi$`)
)

// extractStaticConditionalSources recognizes only a fixed-file -f guard
// whose source operand is textually identical to the tested operand. Missing
// files are then a deterministic skipped edge; every other condition remains
// visible to AnalyzeStaticShell and therefore makes the context UNKNOWN.
func extractStaticConditionalSources(data []byte) ([]byte, []startupConditionalSource) {
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return data, nil
	}
	lines := strings.Split(string(data), "\n")
	sources := make([]startupConditionalSource, 0, 2)
	for index := 0; index < len(lines); index++ {
		trimmed := strings.TrimSpace(lines[index])
		if matches := fixedFileConditionalOne.FindStringSubmatch(trimmed); len(matches) == 4 {
			if matches[1] == matches[3] {
				sources = append(sources, startupConditionalSource{Line: index + 1, Target: matches[1], Source: matches[3]})
				lines[index] = ""
			}
			continue
		}
		matches := fixedFileConditionalStart.FindStringSubmatch(trimmed)
		if len(matches) != 2 {
			continue
		}
		matchedLines := []int{index}
		cursor := index + 1
		for cursor < len(lines) && (strings.TrimSpace(lines[cursor]) == "" || strings.HasPrefix(strings.TrimSpace(lines[cursor]), "#")) {
			cursor++
		}
		if cursor >= len(lines) {
			continue
		}
		sourceMatches := fixedFileSourceLine.FindStringSubmatch(strings.TrimSpace(lines[cursor]))
		if len(sourceMatches) != 3 || sourceMatches[2] != matches[1] {
			continue
		}
		matchedLines = append(matchedLines, cursor)
		cursor++
		for cursor < len(lines) && (strings.TrimSpace(lines[cursor]) == "" || strings.HasPrefix(strings.TrimSpace(lines[cursor]), "#")) {
			cursor++
		}
		if cursor >= len(lines) || strings.TrimSpace(lines[cursor]) != "fi" {
			continue
		}
		matchedLines = append(matchedLines, cursor)
		for _, lineIndex := range matchedLines {
			lines[lineIndex] = ""
		}
		sources = append(sources, startupConditionalSource{Line: index + 1, Target: matches[1], Source: sourceMatches[2]})
		index = cursor
	}
	return []byte(strings.Join(lines, "\n")), sources
}

func (inspector *startupInspector) profilePaths() ([]string, []string, error) {
	if inspector.profileDLoaded {
		return append([]string(nil), inspector.profileDPaths...), append([]string(nil), inspector.profileDUnknowns...), nil
	}
	inspector.profileDLoaded = true
	inspected, err := inspectPathWithoutSymlinks(inspector.environment.Files, "/etc/profile.d")
	if err != nil {
		return nil, nil, err
	}
	inspector.evidence = append(inspector.evidence, inspected.Evidence...)
	if !inspected.Exists {
		inspector.evidence = append(inspector.evidence, support.FactEvidence("/etc/profile.d", map[string]any{"exists": false, "files": []string{}}))
		return nil, nil, nil
	}
	if inspected.Unknown != "" {
		inspector.profileDUnknowns = append(inspector.profileDUnknowns, inspected.Unknown)
		inspector.evidence = append(inspector.evidence, support.FactEvidence("/etc/profile.d", map[string]any{
			"exists": true, "unknowns": append([]string(nil), inspector.profileDUnknowns...),
		}))
		return nil, append([]string(nil), inspector.profileDUnknowns...), nil
	}
	if inspected.Metadata.FileType != "directory" {
		inspector.profileDUnknowns = append(inspector.profileDUnknowns, "/etc/profile.d가 디렉터리가 아님")
		inspector.evidence = append(inspector.evidence, support.FactEvidence("/etc/profile.d", map[string]any{
			"exists": true, "unknowns": append([]string(nil), inspector.profileDUnknowns...),
		}))
		return nil, append([]string(nil), inspector.profileDUnknowns...), nil
	}
	entries, err := inspector.environment.Files.ReadDir("/etc/profile.d")
	if err != nil {
		return nil, nil, err
	}
	afterRead, err := inspector.environment.Files.Stat("/etc/profile.d")
	if err != nil {
		return nil, nil, err
	}
	if afterRead.Device != inspected.Metadata.Device || afterRead.Inode != inspected.Metadata.Inode || afterRead.FileType != inspected.Metadata.FileType {
		inspector.profileDUnknowns = append(inspector.profileDUnknowns, "/etc/profile.d 대상이 디렉터리 열람 중 변경됨")
		inspector.evidence = append(inspector.evidence, support.FileMetadataEvidence(afterRead))
		inspector.evidence = append(inspector.evidence, support.FactEvidence("/etc/profile.d", map[string]any{
			"exists": true, "unknowns": append([]string(nil), inspector.profileDUnknowns...),
		}))
		return nil, append([]string(nil), inspector.profileDUnknowns...), nil
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".sh") {
			continue
		}
		profilePath, pathErr := fixedChildPath("/etc/profile.d", entry.Name())
		if pathErr != nil {
			return nil, nil, pathErr
		}
		paths = append(paths, profilePath)
	}
	sort.Strings(paths)
	if len(paths) > maxStartupProfileScripts {
		inspector.profileDUnknowns = append(inspector.profileDUnknowns, fmt.Sprintf("/etc/profile.d의 .sh 파일이 분석 한도 %d개를 초과함", maxStartupProfileScripts))
		inspector.evidence = append(inspector.evidence, support.FactEvidence("/etc/profile.d", map[string]any{
			"exists": true, "file_count": len(paths), "files": append([]string(nil), paths[:maxStartupProfileScripts]...),
			"files_truncated": true, "sort": "lexical_ascending", "unknowns": append([]string(nil), inspector.profileDUnknowns...),
		}))
		return nil, append([]string(nil), inspector.profileDUnknowns...), nil
	}
	inspector.profileDPaths = paths
	evidencePathLimit := minInt(len(paths), 256)
	inspector.evidence = append(inspector.evidence, support.FactEvidence("/etc/profile.d", map[string]any{
		"exists": true, "file_count": len(paths), "files": append([]string(nil), paths[:evidencePathLimit]...),
		"files_truncated": len(paths) > evidencePathLimit, "sort": "lexical_ascending",
	}))
	return append([]string(nil), paths...), append([]string(nil), inspector.profileDUnknowns...), nil
}

func (inspector *startupInspector) contexts(account support.PasswdEntry, shellKind startupShellKind, initialUmask *uint32, initialUnknowns []string) ([]startupContext, error) {
	unknowns := append([]string(nil), initialUnknowns...)
	loginPaths := []string{"/etc/profile"}
	switch shellKind {
	case startupShellBash:
		loginFile, err := inspector.firstExisting(account.Home, []string{".bash_profile", ".bash_login", ".profile"})
		if err != nil {
			return nil, err
		}
		if loginFile != "" {
			loginPaths = append(loginPaths, loginFile)
		}
		bashrc, err := fixedChildPath(account.Home, ".bashrc")
		if err != nil {
			return nil, err
		}
		nonLoginPaths := []string{bashrc}
		return []startupContext{
			{Account: account, Name: "bash-login", Paths: loginPaths, InitialUmask: cloneUmask(initialUmask), Unknowns: append([]string(nil), unknowns...)},
			{Account: account, Name: "bash-interactive", Paths: nonLoginPaths, InitialUmask: cloneUmask(initialUmask), Unknowns: append([]string(nil), unknowns...)},
		}, nil
	case startupShellSH:
		profile, err := inspector.firstExisting(account.Home, []string{".profile"})
		if err != nil {
			return nil, err
		}
		if profile != "" {
			loginPaths = append(loginPaths, profile)
		}
		return []startupContext{{Account: account, Name: "sh-login", Paths: loginPaths, InitialUmask: cloneUmask(initialUmask), Unknowns: unknowns}}, nil
	default:
		return nil, fmt.Errorf("unsupported startup shell %q", shellKind)
	}
}

func (inspector *startupInspector) firstExisting(home string, names []string) (string, error) {
	for _, name := range names {
		candidate, err := fixedChildPath(home, name)
		if err != nil {
			return "", err
		}
		loaded, err := inspector.load(candidate)
		if err != nil {
			return "", err
		}
		if loaded.Exists {
			return candidate, nil
		}
	}
	return "", nil
}

func (inspector *startupInspector) evaluate(context startupContext) (startupContextResult, error) {
	shellValue := context.Account.Shell
	if strings.TrimSpace(shellValue) == "" {
		shellValue = "/bin/sh"
	}
	variables := map[string]string{
		"HOME":    context.Account.Home,
		"USER":    context.Account.Name,
		"LOGNAME": context.Account.Name,
		"SHELL":   shellValue,
		"UID":     strconv.FormatUint(uint64(context.Account.UID), 10),
		"EUID":    strconv.FormatUint(uint64(context.Account.UID), 10),
	}
	for name, value := range context.InitialVars {
		variables[name] = value
	}
	exported := map[string]bool{
		"HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	}
	for name, value := range context.InitialExported {
		if value {
			exported[name] = true
		}
	}
	state := startupState{
		variables:     variables,
		exported:      exported,
		readOnly:      make(map[string]bool),
		origins:       cloneStartupOrigins(context.InitialOrigins),
		umask:         cloneUmask(context.InitialUmask),
		unknowns:      append([]string(nil), context.Unknowns...),
		activeSources: make(map[string]bool),
		planPositions: make(map[string]int, len(context.Paths)),
		planApplied:   make(map[string]bool, len(context.Paths)),
		planCursor:    -1,
	}
	for index, systemPath := range context.Paths {
		state.planPositions[systemPath] = index
	}
	for index, systemPath := range context.Paths {
		if state.planApplied[systemPath] {
			continue
		}
		state.planCursor = index
		state.planApplied[systemPath] = true
		if err := inspector.applyFile(&state, systemPath, true); err != nil {
			return startupContextResult{}, err
		}
	}
	state.unknowns = uniqueSortedStrings(state.unknowns)
	return startupContextResult{
		Account:   context.Account.Name,
		Name:      context.Name,
		Paths:     append([]string(nil), state.appliedPaths...),
		Variables: cloneStringMap(state.variables),
		Exported:  cloneBoolMap(state.exported),
		ReadOnly:  cloneBoolMap(state.readOnly),
		Origins:   cloneStartupOrigins(state.origins),
		Umask:     cloneUmask(state.umask),
		Unknowns:  state.unknowns,
	}, nil
}

func (inspector *startupInspector) evaluateContexts(contexts []startupContext) ([]startupContextResult, error) {
	results := make([]startupContextResult, 0, len(contexts))
	for index, context := range contexts {
		if index > 0 && context.Name == "bash-interactive" && len(results) > 0 {
			login := results[0]
			context.InitialVars = make(map[string]string)
			context.InitialExported = make(map[string]bool)
			context.InitialOrigins = make(map[string]startupVariableOrigin)
			for name, exported := range login.Exported {
				if !exported {
					continue
				}
				value, exists := login.Variables[name]
				if !exists {
					continue
				}
				context.InitialVars[name] = value
				context.InitialExported[name] = true
				if origin, exists := login.Origins[name]; exists {
					context.InitialOrigins[name] = origin
				}
			}
			context.InitialUmask = cloneUmask(login.Umask)
			if len(login.Unknowns) > 0 {
				context.Unknowns = append(context.Unknowns, "bash-login에서 상속되는 초기 셸 상태를 확정할 수 없음")
			}
			if inheritedHome, exists := login.Variables["HOME"]; exists && inheritedHome != context.Account.Home {
				context.Unknowns = append(context.Unknowns, "bash-login에서 HOME이 변경되어 비로그인 시작 파일 경로를 확정할 수 없음")
			}
		}
		result, err := inspector.evaluate(context)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (inspector *startupInspector) applyFile(state *startupState, systemPath string, planned bool) error {
	if state.activeSources[systemPath] {
		state.unknowns = append(state.unknowns, systemPath+": 순환 source 관계")
		return nil
	}
	loaded, err := inspector.load(systemPath)
	if err != nil {
		return err
	}
	if !loaded.Exists {
		if !planned {
			state.unknowns = append(state.unknowns, systemPath+": source 대상 없음")
		}
		return nil
	}
	state.appliedPaths = append(state.appliedPaths, systemPath)
	if loaded.Unknown != "" {
		state.unknowns = append(state.unknowns, systemPath+": "+loaded.Unknown)
		return nil
	}
	state.activeSources[systemPath] = true
	defer delete(state.activeSources, systemPath)
	for _, issue := range loaded.Analysis.Issues {
		state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d %s", systemPath, issue.Line, issue.Reason))
	}
	for _, action := range loaded.Actions {
		if action.ProfileDLoop {
			if err := inspector.applyRockyProfileDLoop(state, systemPath, action.Line); err != nil {
				return err
			}
			continue
		}
		if action.ConditionalTarget != "" {
			if err := inspector.applyFixedFileConditionalSource(state, systemPath, action); err != nil {
				return err
			}
			continue
		}
		operation := action.Operation
		switch operation.Kind {
		case support.StaticShellAssign:
			if state.readOnly[operation.Name] {
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d readonly 변수 %s 재할당의 셸 제어 흐름", systemPath, operation.Line, operation.Name))
				continue
			}
			value, expandErr := support.ExpandStaticShellWord(operation.Value, state.variables)
			if expandErr != nil {
				delete(state.variables, operation.Name)
				delete(state.origins, operation.Name)
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d %s 할당을 확정할 수 없음", systemPath, operation.Line, operation.Name))
				continue
			}
			state.variables[operation.Name] = value
			state.origins[operation.Name] = startupVariableOrigin{Path: systemPath, Line: operation.Line}
		case support.StaticShellUnset:
			if state.readOnly[operation.Name] {
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d readonly 변수 %s 해제의 셸 제어 흐름", systemPath, operation.Line, operation.Name))
				continue
			}
			delete(state.variables, operation.Name)
			delete(state.exported, operation.Name)
			delete(state.origins, operation.Name)
		case support.StaticShellExport:
			state.exported[operation.Name] = true
		case support.StaticShellReadOnly:
			state.readOnly[operation.Name] = true
		case support.StaticShellUmask:
			value, expandErr := support.ExpandStaticShellWord(operation.Value, state.variables)
			if expandErr != nil {
				state.umask = nil
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d UMASK 인수를 확정할 수 없음", systemPath, operation.Line))
				continue
			}
			parsed, parseErr := parseOctalUmask(value)
			if parseErr != nil {
				state.umask = nil
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 숫자형 UMASK를 확정할 수 없음", systemPath, operation.Line))
				continue
			}
			state.umask = &parsed
		case support.StaticShellSource:
			if !sourceUsesOnlyStaticHome(operation.Value) {
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 동적 source 변수", systemPath, operation.Line))
				continue
			}
			sourcePath, expandErr := support.ExpandStaticShellWord(operation.Value, state.variables)
			if expandErr != nil || strings.ContainsAny(sourcePath, " \t\r\n\v\f*?[") || validateAbsoluteSystemPath(sourcePath) != nil {
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 동적 또는 상대 source 경로", systemPath, operation.Line))
				continue
			}
			if state.activeSources[sourcePath] {
				state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 순환 source 관계", systemPath, operation.Line))
				continue
			}
			if position, exists := state.planPositions[sourcePath]; exists && position > state.planCursor && !state.planApplied[sourcePath] {
				if position != nextPlannedPosition(state) {
					state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d source 우선순위가 고정 순서와 충돌함", systemPath, operation.Line))
					continue
				}
				state.planApplied[sourcePath] = true
				if err := inspector.applyFile(state, sourcePath, false); err != nil {
					return err
				}
				continue
			}
			if err := inspector.applyFile(state, sourcePath, false); err != nil {
				return err
			}
		default:
			state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 지원하지 않는 정적 연산", systemPath, operation.Line))
		}
	}
	return nil
}

func (inspector *startupInspector) applyFixedFileConditionalSource(state *startupState, sourcePath string, action startupAction) error {
	if action.ConditionalTarget != action.ConditionalSource || !sourceUsesOnlyStaticHome(action.ConditionalSource) {
		state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 고정 파일 조건과 source 대상을 확정할 수 없음", sourcePath, action.Line))
		return nil
	}
	target, targetErr := support.ExpandStaticShellWord(action.ConditionalTarget, state.variables)
	sourced, sourceErr := support.ExpandStaticShellWord(action.ConditionalSource, state.variables)
	if targetErr != nil || sourceErr != nil || target != sourced || strings.ContainsAny(sourced, " \t\r\n\v\f*?[") || validateAbsoluteSystemPath(sourced) != nil {
		state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 동적 또는 상대 고정 파일 source 경로", sourcePath, action.Line))
		return nil
	}
	inspected, err := inspectPathWithoutSymlinks(inspector.environment.Files, sourced)
	if err != nil {
		return err
	}
	inspector.evidence = append(inspector.evidence, inspected.Evidence...)
	if !inspected.Exists {
		inspector.evidence = append(inspector.evidence, support.FactEvidence(sourced, map[string]any{
			"exists": false, "condition": "-f", "source_skipped": true,
		}))
		return nil
	}
	if inspected.Metadata.FileType != "regular" && inspected.Unknown == "" {
		inspector.evidence = append(inspector.evidence, support.FactEvidence(sourced, map[string]any{
			"exists": true, "file_type": inspected.Metadata.FileType, "condition": "-f", "source_skipped": true,
		}))
		return nil
	}
	if inspected.Unknown != "" {
		state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d 조건부 source 대상 %s: %s", sourcePath, action.Line, sourced, inspected.Unknown))
		return nil
	}
	return inspector.applyFile(state, sourced, false)
}

func (inspector *startupInspector) applyRockyProfileDLoop(state *startupState, sourcePath string, line int) error {
	paths, unknowns, err := inspector.profilePaths()
	if err != nil {
		return err
	}
	for _, reason := range unknowns {
		state.unknowns = append(state.unknowns, fmt.Sprintf("%s:%d profile.d glob을 확정할 수 없음: %s", sourcePath, line, reason))
	}
	for _, profilePath := range paths {
		if err := inspector.applyFile(state, profilePath, false); err != nil {
			return err
		}
	}
	localPath, err := fixedChildPath("/etc/profile.d", "sh.local")
	if err != nil {
		return err
	}
	local, err := inspector.load(localPath)
	if err != nil {
		return err
	}
	if local.Exists {
		if err := inspector.applyFile(state, localPath, false); err != nil {
			return err
		}
	}
	return nil
}

func nextPlannedPosition(state *startupState) int {
	next := len(state.planPositions)
	for systemPath, position := range state.planPositions {
		if position <= state.planCursor || state.planApplied[systemPath] {
			continue
		}
		if position < next {
			next = position
		}
	}
	return next
}

func sourceUsesOnlyStaticHome(value string) bool {
	for index := 0; index < len(value); {
		if value[index] != '$' {
			index++
			continue
		}
		if strings.HasPrefix(value[index:], "${HOME}") {
			index += len("${HOME}")
			continue
		}
		if strings.HasPrefix(value[index:], "$HOME") {
			next := index + len("$HOME")
			if next < len(value) && (value[next] == '_' || value[next] >= '0' && value[next] <= '9' || value[next] >= 'A' && value[next] <= 'Z' || value[next] >= 'a' && value[next] <= 'z') {
				return false
			}
			index = next
			continue
		}
		return false
	}
	return true
}

func (inspector *startupInspector) loginDefsUmask() (*uint32, []string, error) {
	const loginDefsPath = "/etc/login.defs"
	inspected, err := inspectPathWithoutSymlinks(inspector.environment.Files, loginDefsPath)
	if err != nil {
		return nil, nil, err
	}
	inspector.evidence = append(inspector.evidence, inspected.Evidence...)
	if !inspected.Exists {
		unknowns := []string{"/etc/login.defs 없음"}
		inspector.evidence = append(inspector.evidence, support.FactEvidence(loginDefsPath, map[string]any{
			"exists": false, "content_redacted": true, "unknowns": unknowns,
		}))
		return nil, unknowns, nil
	}
	if inspected.Unknown != "" || inspected.Metadata.FileType != "regular" {
		reason := inspected.Unknown
		if reason == "" {
			reason = "/etc/login.defs가 일반 파일이 아님"
		}
		inspector.evidence = append(inspector.evidence, support.FactEvidence(loginDefsPath, map[string]any{
			"exists": true, "content_redacted": true, "unknowns": []string{reason},
		}))
		return nil, []string{reason}, nil
	}
	data, metadata, err := inspector.environment.Files.ReadFile(inspector.ctx, loginDefsPath, 2<<20)
	if err != nil {
		return nil, nil, err
	}
	if metadata.Device != inspected.Metadata.Device || metadata.Inode != inspected.Metadata.Inode || metadata.FileType != inspected.Metadata.FileType {
		unknowns := []string{"/etc/login.defs 대상이 검사 중 변경됨"}
		inspector.evidence = append(inspector.evidence, support.FileMetadataEvidence(metadata))
		inspector.evidence = append(inspector.evidence, support.FactEvidence(loginDefsPath, map[string]any{
			"exists": true, "content_redacted": true, "unknowns": unknowns,
		}))
		return nil, unknowns, nil
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		unknowns := []string{"/etc/login.defs 문자 인코딩 또는 NUL 바이트를 해석할 수 없음"}
		inspector.evidence = append(inspector.evidence, support.FactEvidence(loginDefsPath, map[string]any{
			"exists": true, "content_redacted": true, "unknowns": unknowns,
		}))
		return nil, unknowns, nil
	}
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		unknowns := []string{"/etc/login.defs의 단독 CR 줄바꿈을 지원하지 않음"}
		inspector.evidence = append(inspector.evidence, support.FactEvidence(loginDefsPath, map[string]any{
			"exists": true, "content_redacted": true, "unknowns": unknowns,
		}))
		return nil, unknowns, nil
	}
	values := make([]uint32, 0, 1)
	unknowns := make([]string, 0)
	for index, raw := range strings.Split(normalized, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "UMASK" {
			continue
		}
		if len(fields) != 2 {
			unknowns = append(unknowns, fmt.Sprintf("/etc/login.defs:%d UMASK 구문을 확정할 수 없음", index+1))
			continue
		}
		value, parseErr := parseOctalUmask(fields[1])
		if parseErr != nil {
			unknowns = append(unknowns, fmt.Sprintf("/etc/login.defs:%d 숫자형 UMASK가 아님", index+1))
			continue
		}
		values = append(values, value)
	}
	var selected *uint32
	origin := "directive"
	if len(values) == 0 && len(unknowns) == 0 {
		value := uint32(0o022)
		selected = &value
		origin = "login_defs_documented_default"
	} else if len(values) > 0 {
		value := values[0]
		selected = &value
		for _, candidate := range values[1:] {
			if candidate != value {
				unknowns = append(unknowns, "/etc/login.defs의 UMASK 지시문이 충돌함")
				selected = nil
				break
			}
		}
	}
	unknowns = uniqueSortedStrings(unknowns)
	facts := map[string]any{
		"exists": true, "content_redacted": true, "directive_count": len(values), "origin": origin,
		"unknowns": unknowns,
	}
	if selected != nil {
		facts["umask"] = fmt.Sprintf("%04o", *selected)
	}
	inspector.evidence = append(inspector.evidence, support.FactEvidence(loginDefsPath, facts))
	return cloneUmask(selected), unknowns, nil
}

func supportedStartupShell(shell string) (startupShellKind, bool) {
	switch strings.TrimSpace(shell) {
	case "", "/bin/sh", "/usr/bin/sh":
		return startupShellSH, true
	case "/bin/bash", "/usr/bin/bash":
		return startupShellBash, true
	default:
		return "", false
	}
}

func unsupportedStartupPlatform(platform model.PlatformInfo, subject string) evaluator.Outcome {
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       subject + " 정적 시작 파일 분석은 현재 RHEL 계열에만 구현되어 있습니다.",
		Expected:      "운영체제 계열별 시작 파일 경로와 우선순위가 검증되어야 합니다.",
		Observed:      fmt.Sprintf("id=%s version=%s family=%s", platform.ID, platform.VersionID, platform.Family),
		Evidence: []model.Evidence{support.FactEvidence("startup-platform", map[string]any{
			"id": platform.ID, "version_id": platform.VersionID, "family": platform.Family,
		})},
	}
}

func parseOctalUmask(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 4 {
		return 0, fmt.Errorf("invalid umask length")
	}
	for _, character := range value {
		if character < '0' || character > '7' {
			return 0, fmt.Errorf("umask is not octal")
		}
	}
	parsed, err := strconv.ParseUint(value, 8, 16)
	if err != nil || parsed > 0o777 {
		return 0, fmt.Errorf("umask is outside 0000-0777")
	}
	return uint32(parsed), nil
}

func inspectRootPath(value string) ([]string, bool) {
	components := strings.Split(value, ":")
	violations := make([]string, 0)
	trailingCurrentDirectory := false
	for index, component := range components {
		position := index + 1
		if component == "" {
			violations = append(violations, fmt.Sprintf("PATH 구성요소 %d가 비어 있어 현재 디렉터리를 뜻함", position))
			continue
		}
		if component != "." {
			continue
		}
		if index == len(components)-1 && len(components) > 1 {
			trailingCurrentDirectory = true
			continue
		}
		violations = append(violations, fmt.Sprintf("PATH 구성요소 %d에 현재 디렉터리(.)가 앞 또는 중간에 있음", position))
	}
	return violations, trailingCurrentDirectory
}

func rootPathEvidence(results []startupContextResult, violations, unknowns, warnings []rootPathFinding) model.Evidence {
	contexts := make([]map[string]any, 0, len(results))
	for _, result := range results {
		value, known := result.Variables["PATH"]
		fact := map[string]any{
			"account": result.Account, "context": result.Name, "file_count": len(result.Paths),
			"files":         limitedStrings(result.Paths, 256),
			"deterministic": len(result.Unknowns) == 0 && known,
			"unknown_count": len(result.Unknowns),
			"unknowns":      limitedStrings(result.Unknowns, 32),
		}
		if known {
			fact["component_count"] = len(strings.Split(value, ":"))
		}
		contexts = append(contexts, fact)
	}
	return support.FactEvidence("root-path-static-analysis", map[string]any{
		"content_redacted": true,
		"contexts":         contexts,
		"violations":       rootPathFindingFacts(violations),
		"unknowns":         rootPathFindingFacts(unknowns),
		"warnings":         rootPathFindingFacts(warnings),
	})
}

func umaskEvidence(applicableAccounts int, results []startupContextResult, violations, unknowns []umaskFinding) model.Evidence {
	contextLimit := minInt(len(results), 512)
	contexts := make([]map[string]any, 0, contextLimit)
	for _, result := range results[:contextLimit] {
		fact := map[string]any{
			"account": result.Account, "context": result.Name, "file_count": len(result.Paths),
			"files":         limitedStrings(result.Paths, 256),
			"deterministic": len(result.Unknowns) == 0 && result.Umask != nil,
			"unknown_count": len(result.Unknowns),
			"unknowns":      limitedStrings(result.Unknowns, 32),
		}
		if result.Umask != nil {
			fact["umask"] = fmt.Sprintf("%04o", *result.Umask)
			fact["contains_0022_bits"] = *result.Umask&0o022 == 0o022
		}
		contexts = append(contexts, fact)
	}
	return support.FactEvidence("umask-static-analysis", map[string]any{
		"content_redacted":          true,
		"applicable_account_count":  applicableAccounts,
		"context_count":             len(results),
		"contexts":                  contexts,
		"contexts_truncated":        len(results) > contextLimit,
		"violation_count":           len(violations),
		"violations":                umaskFindingFacts(violations),
		"unknown_count":             len(unknowns),
		"unknowns":                  umaskFindingFacts(unknowns),
		"comparison":                "bit_inclusion",
		"required_umask_write_bits": "0022",
	})
}

func sortRootPathFindings(findings []rootPathFinding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Context != findings[j].Context {
			return findings[i].Context < findings[j].Context
		}
		return findings[i].Reason < findings[j].Reason
	})
}

func rootPathFindingFacts(findings []rootPathFinding) []map[string]any {
	limit := minInt(len(findings), 128)
	facts := make([]map[string]any, 0, limit)
	for _, finding := range findings[:limit] {
		facts = append(facts, map[string]any{"context": finding.Context, "reason": finding.Reason})
	}
	return facts
}

func formatRootPathFindings(findings []rootPathFinding, limit int) string {
	values := make([]string, 0, minInt(len(findings), limit)+1)
	for index, finding := range findings {
		if index >= limit {
			values = append(values, fmt.Sprintf("외 %d건", len(findings)-limit))
			break
		}
		values = append(values, finding.Context+"("+finding.Reason+")")
	}
	return strings.Join(values, "; ")
}

func sortUmaskFindings(findings []umaskFinding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Account != findings[j].Account {
			return findings[i].Account < findings[j].Account
		}
		if findings[i].Context != findings[j].Context {
			return findings[i].Context < findings[j].Context
		}
		return findings[i].Reason < findings[j].Reason
	})
}

func umaskFindingFacts(findings []umaskFinding) []map[string]any {
	limit := minInt(len(findings), 512)
	facts := make([]map[string]any, 0, limit)
	for _, finding := range findings[:limit] {
		fact := map[string]any{"account": finding.Account, "context": finding.Context, "reason": finding.Reason}
		if finding.Value != "" {
			fact["umask"] = finding.Value
		}
		facts = append(facts, fact)
	}
	return facts
}

func formatUmaskFindings(findings []umaskFinding, limit int) string {
	values := make([]string, 0, minInt(len(findings), limit)+1)
	for index, finding := range findings {
		if index >= limit {
			values = append(values, fmt.Sprintf("외 %d건", len(findings)-limit))
			break
		}
		label := finding.Account
		if finding.Context != "" {
			label += "/" + finding.Context
		}
		if finding.Value != "" {
			label += "=" + finding.Value
		}
		values = append(values, label+"("+finding.Reason+")")
	}
	return strings.Join(values, "; ")
}

func cloneUmask(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneStringMap(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func cloneBoolMap(values map[string]bool) map[string]bool {
	copy := make(map[string]bool, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func cloneStartupOrigins(values map[string]startupVariableOrigin) map[string]startupVariableOrigin {
	copy := make(map[string]startupVariableOrigin, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func limitedStrings(values []string, limit int) []string {
	if limit < 0 {
		limit = 0
	}
	if len(values) <= limit {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:limit]...)
}

func summarizeStrings(values []string, limit int) string {
	selected := limitedStrings(values, limit)
	result := strings.Join(selected, ", ")
	if len(values) > len(selected) {
		result += fmt.Sprintf(", 외 %d건", len(values)-len(selected))
	}
	return result
}

func startupSettingsError(code, summary string, err error) evaluator.Outcome {
	if errors.Is(err, os.ErrNotExist) {
		return evaluator.Outcome{
			Status:       model.StatusError,
			Summary:      summary,
			ErrorCode:    code,
			ErrorMessage: "필수 파일 또는 경로가 검사 중 사라졌습니다.",
		}
	}
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      summary,
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
