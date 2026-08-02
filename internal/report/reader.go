package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
)

const maximumReportJSONSize int64 = 64 << 20

var (
	checkIDPattern       = regexp.MustCompile(`^U-(0[1-9]|[1-5][0-9]|6[0-7])$`)
	ruleSetDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sha256DigestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func ReadScan(directory string) (model.ScanRun, error) {
	if strings.TrimSpace(directory) == "" {
		return model.ScanRun{}, fmt.Errorf("보고서 디렉터리가 필요합니다")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return model.ScanRun{}, fmt.Errorf("보고서 경로를 확인하지 못했습니다: %w", err)
	}
	absolute = filepath.Clean(absolute)
	baseName := filepath.Base(absolute)
	if strings.HasPrefix(baseName, ".") && strings.HasSuffix(baseName, ".partial") {
		return model.ScanRun{}, fmt.Errorf("작성 중인 partial 보고서는 자동 조치 입력으로 사용할 수 없습니다")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return model.ScanRun{}, fmt.Errorf("보고서 디렉터리를 확인하지 못했습니다: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return model.ScanRun{}, fmt.Errorf("보고서 경로는 심볼릭 링크가 아닌 디렉터리여야 합니다")
	}
	if err := validateReportInputDirectorySecurity(info); err != nil {
		return model.ScanRun{}, fmt.Errorf("보고서 디렉터리 보호 상태가 안전하지 않습니다: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != absolute {
		if err == nil {
			err = fmt.Errorf("경로 구성요소에 심볼릭 링크가 있습니다")
		}
		return model.ScanRun{}, fmt.Errorf("보고서 경로를 안전하게 확인하지 못했습니다: %w", err)
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return model.ScanRun{}, fmt.Errorf("보고서 디렉터리를 열지 못했습니다: %w", err)
	}
	defer root.Close()
	openedDirectory, err := root.Stat(".")
	if err != nil || !openedDirectory.IsDir() || !os.SameFile(info, openedDirectory) {
		if err == nil {
			err = fmt.Errorf("보고서 디렉터리가 여는 동안 교체되었습니다")
		}
		return model.ScanRun{}, fmt.Errorf("보고서 디렉터리를 고정하지 못했습니다: %w", err)
	}

	var metadata model.RunMetadata
	if err := readStrictReportJSON(root, absolute, "metadata.json", &metadata); err != nil {
		return model.ScanRun{}, err
	}
	var results []model.CheckResult
	if err := readStrictReportJSON(root, absolute, "results.json", &results); err != nil {
		return model.ScanRun{}, err
	}
	run := model.ScanRun{Metadata: metadata, Results: results}
	if err := validateLoadedScan(run); err != nil {
		return model.ScanRun{}, fmt.Errorf("보고서 일관성 검증에 실패했습니다: %w", err)
	}
	return run, nil
}

func readStrictReportJSON(root *os.Root, absoluteDirectory, name string, destination any) error {
	absolutePath := filepath.Join(absoluteDirectory, name)
	info, err := os.Lstat(absolutePath)
	if err != nil {
		return fmt.Errorf("%s 파일을 확인하지 못했습니다: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s 파일은 심볼릭 링크가 아닌 일반 파일이어야 합니다", name)
	}
	if err := validateReportInputFileSecurity(info); err != nil {
		return fmt.Errorf("%s 파일 보호 상태가 안전하지 않습니다: %w", name, err)
	}
	if info.Size() < 1 || info.Size() > maximumReportJSONSize {
		return fmt.Errorf("%s 파일 크기가 허용 범위를 벗어났습니다", name)
	}
	file, err := openStrictReportFile(root, name)
	if err != nil {
		return fmt.Errorf("%s 파일을 열지 못했습니다: %w", name, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%s 열린 파일을 확인하지 못했습니다: %w", name, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return fmt.Errorf("%s 파일이 여는 동안 교체되었습니다", name)
	}
	if err := validateReportInputFileSecurity(openedInfo); err != nil {
		return fmt.Errorf("%s 열린 파일 보호 상태가 안전하지 않습니다: %w", name, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumReportJSONSize+1))
	if err != nil {
		return fmt.Errorf("%s 파일을 읽지 못했습니다: %w", name, err)
	}
	if int64(len(data)) > maximumReportJSONSize || int64(len(data)) != openedInfo.Size() {
		return fmt.Errorf("%s 파일이 읽는 동안 크기가 변경되었습니다", name)
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%s 파일의 읽기 후 상태를 확인하지 못했습니다: %w", name, err)
	}
	if !afterInfo.Mode().IsRegular() || !os.SameFile(openedInfo, afterInfo) ||
		afterInfo.Size() != openedInfo.Size() || !afterInfo.ModTime().Equal(openedInfo.ModTime()) {
		return fmt.Errorf("%s 파일이 읽는 동안 변경되었습니다", name)
	}
	if err := validateReportInputFileSecurity(afterInfo); err != nil {
		return fmt.Errorf("%s 파일 보호 상태가 읽는 동안 변경되었습니다: %w", name, err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return fmt.Errorf("%s 파일의 JSON key가 안전하지 않습니다: %w", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%s 파일을 해석하지 못했습니다: %w", name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("추가 JSON 문서가 있습니다")
		}
		return fmt.Errorf("%s 파일 뒤에 잘못된 데이터가 있습니다: %w", name, err)
	}
	return nil
}

func validateLoadedScan(run model.ScanRun) error {
	metadata := run.Metadata
	if len(run.Results) == 0 {
		return fmt.Errorf("점검 결과가 비어 있습니다")
	}
	if metadata.SchemaVersion != model.RunMetadataSchemaVersion || !canonicalIdentityString(metadata.RunID) || metadata.GuideYear != 2026 {
		return fmt.Errorf("지원하지 않는 schema, 실행 ID 또는 가이드 연도입니다")
	}
	if !canonicalIdentityString(metadata.ToolVersion) || !canonicalIdentityString(metadata.ToolCommit) {
		return fmt.Errorf("점검 도구 identity가 비어 있거나 정규화되지 않았습니다")
	}
	if !sha256DigestPattern.MatchString(metadata.ToolExecutableSHA256) {
		return fmt.Errorf("점검 실행 바이너리 무결성 값이 잘못되었습니다")
	}
	if !metadata.Complete || metadata.StartedAt.IsZero() || metadata.CompletedAt.IsZero() || metadata.CompletedAt.Before(metadata.StartedAt) {
		return fmt.Errorf("완료되지 않았거나 시각 정보가 잘못된 점검 실행입니다")
	}
	if metadata.DurationMS < 0 || metadata.DurationMS != metadata.CompletedAt.Sub(metadata.StartedAt).Milliseconds() {
		return fmt.Errorf("점검 실행 시간 정보가 실제 시작·완료 시각과 일치하지 않습니다")
	}
	if !ruleSetDigestPattern.MatchString(metadata.RuleSetVersion) {
		return fmt.Errorf("규칙 세트 무결성 값이 잘못되었습니다")
	}
	if metadata.EvidenceMode != "problems" && metadata.EvidenceMode != "all" && metadata.EvidenceMode != "none" {
		return fmt.Errorf("증적 저장 범위가 잘못되었습니다")
	}
	if err := validateReportPlatform(metadata.Platform); err != nil {
		return err
	}
	if err := validateReportSelection(metadata.Selection); err != nil {
		return err
	}
	expectedRuleIDs, err := expectedReportRuleIDs(metadata.Selection)
	if err != nil {
		return err
	}
	if metadata.Redaction != true {
		return fmt.Errorf("민감정보 마스킹을 해제한 보고서는 자동 조치 입력으로 사용할 수 없습니다")
	}
	if metadata.TargetIdentity == nil {
		return fmt.Errorf("호스트 식별 정보가 없어 자동 조치 대상을 안전하게 고정할 수 없습니다")
	}
	if err := metadata.TargetIdentity.Validate(); err != nil {
		return fmt.Errorf("호스트 식별 정보가 잘못되었습니다: %w", err)
	}
	totalMetadataCount := 0
	for status, count := range metadata.Counts {
		if !status.Valid() || count < 0 {
			return fmt.Errorf("metadata에 잘못된 상태 합계 %q=%d가 있습니다", status, count)
		}
		totalMetadataCount += count
	}
	if totalMetadataCount != len(run.Results) {
		return fmt.Errorf("metadata 상태 합계와 결과 항목 수가 일치하지 않습니다")
	}
	seen := make(map[string]struct{}, len(run.Results))
	counts := make(map[model.Status]int)
	for _, result := range run.Results {
		if !checkIDPattern.MatchString(result.RuleID) || !result.Status.Valid() || !result.Category.Valid() || !result.Severity.Valid() {
			return fmt.Errorf("항목 %q의 식별자 또는 판정 필드가 잘못되었습니다", result.RuleID)
		}
		if _, exists := seen[result.RuleID]; exists {
			return fmt.Errorf("항목 %s가 중복되었습니다", result.RuleID)
		}
		seen[result.RuleID] = struct{}{}
		if result.StartedAt.IsZero() || result.CompletedAt.IsZero() || result.CompletedAt.Before(result.StartedAt) ||
			result.DurationMS < 0 || result.DurationMS != result.CompletedAt.Sub(result.StartedAt).Milliseconds() {
			return fmt.Errorf("항목 %s의 시각 정보가 잘못되었습니다", result.RuleID)
		}
		if err := validateResultContract(result); err != nil {
			return fmt.Errorf("항목 %s: %w", result.RuleID, err)
		}
		if metadata.EvidenceMode == "all" && len(result.Evidence) == 0 {
			return fmt.Errorf("모든 증적 저장을 요청한 보고서의 항목 %s에 증적이 없습니다", result.RuleID)
		}
		counts[result.Status]++
	}
	if len(seen) != len(expectedRuleIDs) {
		return fmt.Errorf("점검 선택 항목 수와 결과 항목 수가 일치하지 않습니다")
	}
	for ruleID := range expectedRuleIDs {
		if _, exists := seen[ruleID]; !exists {
			return fmt.Errorf("점검 선택 항목 %s의 결과가 없습니다", ruleID)
		}
	}
	for _, status := range orderedStatuses() {
		if counts[status] != metadata.Counts[status] {
			return fmt.Errorf("상태 %s 합계가 metadata와 일치하지 않습니다", status)
		}
	}
	if exitcode.ForResults(run.Results) != metadata.ExitCode {
		return fmt.Errorf("종료 코드가 결과와 일치하지 않습니다")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkUniqueJSONValue(decoder); err != nil {
		return err
	}
	return nil
}

func walkUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key가 문자열이 아닙니다")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("중복 object key %q가 있습니다", key)
			}
			seen[key] = struct{}{}
			if err := walkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("object가 올바르게 닫히지 않았습니다")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := walkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("array가 올바르게 닫히지 않았습니다")
		}
		return nil
	default:
		return fmt.Errorf("잘못된 JSON delimiter %q입니다", delimiter)
	}
}

func validateReportPlatform(platform model.PlatformInfo) error {
	values := []string{
		platform.Hostname,
		platform.OS,
		platform.ID,
		platform.Name,
		platform.VersionID,
		platform.Family,
		platform.Architecture,
		platform.KernelRelease,
		platform.InitSystem,
		platform.PackageManager,
		platform.Privilege,
	}
	for _, value := range values {
		if !canonicalIdentityString(value) {
			return fmt.Errorf("플랫폼 identity가 비어 있거나 정규화되지 않았습니다")
		}
	}
	if !platform.ScanSupport.Valid() {
		return fmt.Errorf("플랫폼 점검 지원 상태가 잘못되었습니다")
	}
	if platform.ScanSupport == model.ScanSupportUnsupported {
		return fmt.Errorf("지원되지 않는 플랫폼의 점검 보고서입니다")
	}
	if !platform.RemediationSupport.Valid() {
		return fmt.Errorf("플랫폼 자동 조치 지원 상태가 잘못되었습니다")
	}
	if platform.RemediationSupport == model.RemediationSupportVerified && platform.ScanSupport != model.ScanSupportTested {
		return fmt.Errorf("점검 테스트를 완료하지 않은 플랫폼에 자동 조치가 허용되어 있습니다")
	}
	return nil
}

func validateReportSelection(selection model.Selection) error {
	for _, profile := range selection.Profiles {
		if !canonicalIdentityString(profile) {
			return fmt.Errorf("점검 프로필 선택값이 정규화되지 않았습니다")
		}
	}
	for _, ruleID := range selection.RuleIDs {
		if !checkIDPattern.MatchString(ruleID) {
			return fmt.Errorf("점검 항목 선택값 %q가 잘못되었습니다", ruleID)
		}
	}
	for _, category := range selection.Categories {
		if !category.Valid() {
			return fmt.Errorf("점검 분류 선택값 %q가 잘못되었습니다", category)
		}
	}
	for _, severity := range selection.Severities {
		if !severity.Valid() {
			return fmt.Errorf("중요도 선택값 %q가 잘못되었습니다", severity)
		}
	}
	return nil
}

func expectedReportRuleIDs(selection model.Selection) (map[string]struct{}, error) {
	bundle, err := rules.LoadDefaults()
	if err != nil {
		return nil, fmt.Errorf("내장 점검 항목을 불러오지 못했습니다: %w", err)
	}

	definitions := make(map[string]model.RuleDefinition, len(bundle.Catalog.Rules))
	for _, rule := range bundle.Catalog.Rules {
		definitions[rule.ID] = rule
	}
	profiles := make(map[string]model.Profile, len(bundle.Profiles.Profiles))
	for _, profile := range bundle.Profiles.Profiles {
		profiles[profile.ID] = profile
	}

	selected := make(map[string]struct{})
	for _, profileID := range selection.Profiles {
		profile, exists := profiles[profileID]
		if !exists {
			return nil, fmt.Errorf("알 수 없는 점검 프로필 %q가 선택되어 있습니다", profileID)
		}
		for _, ruleID := range profile.RuleIDs {
			selected[ruleID] = struct{}{}
		}
	}
	for _, ruleID := range selection.RuleIDs {
		if _, exists := definitions[ruleID]; !exists {
			return nil, fmt.Errorf("알 수 없는 점검 항목 %q가 선택되어 있습니다", ruleID)
		}
		selected[ruleID] = struct{}{}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("점검 선택 항목이 비어 있습니다")
	}

	for ruleID := range selected {
		rule := definitions[ruleID]
		if !reportSelectionContainsCategory(selection.Categories, rule.Category) ||
			!reportSelectionContainsSeverity(selection.Severities, rule.Severity) {
			delete(selected, ruleID)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("점검 선택 조건에 해당하는 항목이 없습니다")
	}
	return selected, nil
}

func reportSelectionContainsCategory(values []model.Category, wanted model.Category) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func reportSelectionContainsSeverity(values []model.Severity, wanted model.Severity) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func canonicalIdentityString(value string) bool {
	return strings.TrimSpace(value) != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validateResultContract(result model.CheckResult) error {
	if !canonicalIdentityString(result.Title) || strings.TrimSpace(result.Summary) == "" ||
		!canonicalIdentityString(result.Evaluator) || !canonicalIdentityString(result.Reference.Guide) ||
		!canonicalIdentityString(result.Reference.Section) || result.Reference.Item != result.RuleID || len(result.Reference.Pages) == 0 {
		return fmt.Errorf("필수 설명, evaluator 또는 가이드 근거가 잘못되었습니다")
	}
	for _, page := range result.Reference.Pages {
		if page < 1 {
			return fmt.Errorf("가이드 페이지 번호가 잘못되었습니다")
		}
	}
	if err := result.Verification.Validate(); err != nil {
		return fmt.Errorf("검증 provenance가 잘못되었습니다: %w", err)
	}
	seenBindingSource := make(map[string]struct{}, len(result.BindingSources))
	for _, source := range result.BindingSources {
		if !canonicalIdentityString(source) {
			return fmt.Errorf("binding provenance가 정규화되지 않았습니다")
		}
		if _, duplicate := seenBindingSource[source]; duplicate {
			return fmt.Errorf("binding provenance가 중복되었습니다")
		}
		seenBindingSource[source] = struct{}{}
	}
	if result.Status == model.StatusUnknown {
		if !result.UnknownReason.Valid() {
			return fmt.Errorf("UNKNOWN 사유가 잘못되었습니다")
		}
	} else if result.UnknownReason != "" {
		return fmt.Errorf("UNKNOWN이 아닌 결과에 unknown_reason이 있습니다")
	}
	if result.Status == model.StatusError {
		if strings.TrimSpace(result.ErrorCode) == "" {
			return fmt.Errorf("ERROR 결과에 오류 코드가 없습니다")
		}
	} else if result.ErrorCode != "" || result.ErrorMessage != "" {
		return fmt.Errorf("ERROR가 아닌 결과에 오류 필드가 있습니다")
	}
	for index, evidence := range result.Evidence {
		if err := validateEvidenceContract(evidence); err != nil {
			return fmt.Errorf("증적 %d: %w", index+1, err)
		}
	}
	return nil
}

func validateEvidenceContract(evidence model.Evidence) error {
	if strings.TrimSpace(evidence.Source) == "" || evidence.CapturedAt.IsZero() || !evidence.Redacted {
		return fmt.Errorf("출처, 수집 시각 또는 마스킹 상태가 잘못되었습니다")
	}
	present := 0
	if evidence.Command != nil {
		present++
		if evidence.Kind != model.EvidenceCommand || strings.TrimSpace(evidence.Command.Executable) == "" || evidence.Command.DurationMS < 0 {
			return fmt.Errorf("명령 증적 구조가 잘못되었습니다")
		}
	}
	if evidence.File != nil {
		present++
		if evidence.Kind != model.EvidenceFile || strings.TrimSpace(evidence.File.Path) == "" ||
			evidence.File.LineStart < 0 || evidence.File.LineEnd < 0 ||
			(evidence.File.LineEnd > 0 && evidence.File.LineStart > evidence.File.LineEnd) {
			return fmt.Errorf("파일 증적 구조가 잘못되었습니다")
		}
	}
	if evidence.Fact != nil {
		present++
		if evidence.Kind != model.EvidenceFact {
			return fmt.Errorf("파생 증적 구조가 잘못되었습니다")
		}
	}
	if present != 1 {
		return fmt.Errorf("증적 payload는 종류와 일치하는 하나만 있어야 합니다")
	}
	return nil
}
