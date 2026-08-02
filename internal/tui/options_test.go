package tui

import (
	"slices"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestScanSettingsEngineOptions(t *testing.T) {
	t.Parallel()
	settings := defaultScanSettings()
	settings.profiles = "account, service"
	settings.checks = "u-01,U-02"
	settings.categories = "account,file-directory"
	settings.severities = "high,medium"
	settings.evidence = "all"
	settings.noRedact = true

	options, err := settings.engineOptions()
	if err != nil {
		t.Fatalf("engineOptions() error = %v", err)
	}
	if !slices.Equal(options.Selection.Profiles, []string{"account", "service"}) ||
		!slices.Equal(options.Selection.RuleIDs, []string{"U-01", "U-02"}) ||
		!slices.Equal(options.Selection.Categories, []model.Category{model.CategoryAccount, model.CategoryFileDirectory}) ||
		!slices.Equal(options.Selection.Severities, []model.Severity{model.SeverityHigh, model.SeverityMedium}) ||
		options.EvidenceMode != "all" || !options.NoRedact {
		t.Fatalf("engine options = %#v", options)
	}
}

func TestScanSettingsRejectsInvalidCategoryAndEmptyReportPath(t *testing.T) {
	t.Parallel()
	tests := []scanSettings{
		{profiles: "all", categories: "unknown", evidence: "problems", reportDir: "reports"},
		{profiles: "all", evidence: "problems", reportDir: " "},
	}
	for _, settings := range tests {
		if _, err := settings.engineOptions(); err == nil {
			t.Fatalf("engineOptions() accepted invalid settings: %#v", settings)
		}
	}
}

func TestEnteringChecksClearsDefaultAllProfile(t *testing.T) {
	t.Parallel()
	view := &Model{scanSettings: defaultScanSettings()}
	view.setRawOptionValue(optionChecks, "U-01,U-02")
	if view.scanSettings.profiles != "" {
		t.Fatalf("profiles = %q, want empty after entering explicit checks", view.scanSettings.profiles)
	}
	if view.scanSettings.checks != "U-01,U-02" {
		t.Fatalf("checks = %q", view.scanSettings.checks)
	}
}

func TestAllChecksRestoresDefaultFullScan(t *testing.T) {
	t.Parallel()
	view := &Model{scanSettings: defaultScanSettings()}
	view.openOptionPicker(optionChecks)
	if !view.optionPicker.selected["all"] || view.optionPicker.choices[0].label != "전체" {
		t.Fatalf("default check picker = %#v, want 전체 selected first", view.optionPicker)
	}

	view.togglePickerChoice("U-01")
	if view.optionPicker.selected["all"] || !view.optionPicker.selected["U-01"] {
		t.Fatalf("specific check selection = %#v", view.optionPicker.selected)
	}
	if !view.applyOptionPicker() || view.scanSettings.checks != "U-01" || view.scanSettings.profiles != "" {
		t.Fatalf("specific checks = %#v", view.scanSettings)
	}

	view.openOptionPicker(optionChecks)
	view.togglePickerChoice("all")
	if !view.applyOptionPicker() || view.scanSettings.checks != "" || view.scanSettings.profiles != "all" {
		t.Fatalf("all checks = %#v, want default full scan", view.scanSettings)
	}
}

func TestSelectingAllScopeClearsRedundantIndividualChecks(t *testing.T) {
	t.Parallel()
	view := &Model{scanSettings: defaultScanSettings()}
	view.setRawOptionValue(optionChecks, "U-01")
	view.setRawOptionValue(optionProfiles, "all")
	if view.scanSettings.profiles != "all" || view.scanSettings.checks != "" {
		t.Fatalf("full scope settings = %#v", view.scanSettings)
	}
}

func TestTruncateStartKeepsPathOnOneLine(t *testing.T) {
	t.Parallel()
	path := "/srv/example/reports/2026-07-12_052105_host.example_c36638ed7494/reports"
	got := truncateStart(path, 40)
	if lipgloss.Width(got) > 40 {
		t.Fatalf("display width = %d, want at most 40: %q", lipgloss.Width(got), got)
	}
	if !strings.HasPrefix(got, "...") || !strings.HasSuffix(got, "/reports") {
		t.Fatalf("truncateStart() = %q, want omitted prefix and recognizable suffix", got)
	}
}

func TestTruncateStartLeavesShortValueUnchanged(t *testing.T) {
	t.Parallel()
	const path = "/home/rocky/reports"
	if got := truncateStart(path, 40); got != path {
		t.Fatalf("truncateStart() = %q, want %q", got, path)
	}
}

func TestOptionsViewKeepsOnlyUserFacingScanSelectors(t *testing.T) {
	t.Parallel()
	view := &Model{width: 100, scanSettings: defaultScanSettings()}
	content := view.optionsView()
	for _, label := range []string{"점검 범위", "점검", "증적 저장", "보고서 경로", "결과 표시", "민감정보", "자동 조치"} {
		if !strings.Contains(content, label) {
			t.Fatalf("options view is missing %q: %q", label, content)
		}
	}
	for _, label := range []string{"점검 분류", "중요도"} {
		if strings.Contains(content, label) {
			t.Fatalf("options view still contains %q: %q", label, content)
		}
	}
	for _, section := range []string{"점검", "출력", "보안", "조치", "설명"} {
		if !strings.Contains(content, section) {
			t.Fatalf("options view is missing section %q: %q", section, content)
		}
	}
	if strings.Contains(content, "전체 점검") {
		t.Fatalf("options view still contains old full-scan label: %q", content)
	}
}

func TestUnsupportedRemediationOptionIsVisibleAndFixed(t *testing.T) {
	t.Parallel()
	view := &Model{
		width:        100,
		height:       36,
		platform:     model.PlatformInfo{RemediationSupport: model.RemediationSupportTargeted},
		scanSettings: defaultScanSettings(),
		optionIndex:  optionRemediation,
	}
	content := view.optionsView()
	if !strings.Contains(content, "자동 조치") || !strings.Contains(content, "지원되지 않음") ||
		!strings.Contains(content, "현재 OS와 버전에서 자동 조치가 지원되지 않습니다.") {
		t.Fatalf("unsupported remediation option = %q", content)
	}
	view.changeOption(1)
	if view.scanSettings.remediationEnabled {
		t.Fatal("unsupported remediation option was enabled")
	}
}

func TestUnredactedReportsDisableRemediationOption(t *testing.T) {
	t.Parallel()
	view := &Model{
		platform:     model.PlatformInfo{RemediationSupport: model.RemediationSupportVerified, Privilege: "root"},
		scanSettings: scanSettings{remediationEnabled: true},
	}
	view.setRawOptionValue(optionRedaction, "unredacted")
	if !view.scanSettings.noRedact || view.scanSettings.remediationEnabled {
		t.Fatalf("unredacted settings = %#v", view.scanSettings)
	}
	view.optionIndex = optionRemediation
	view.changeOption(1)
	if view.scanSettings.remediationEnabled {
		t.Fatal("remediation was enabled for an unredacted report")
	}
}

func TestNoRedactConfirmationIsCentered(t *testing.T) {
	t.Parallel()
	view := &Model{width: 100, height: 40, scanSettings: defaultScanSettings()}
	content := view.confirmNoRedactView()
	if !strings.Contains(content, "민감정보 마스킹 해제") || !strings.Contains(content, "보고서에 민감정보") {
		t.Fatalf("confirmation content = %q", content)
	}
	lines := strings.Split(content, "\n")
	firstContentLine := -1
	for index, line := range lines {
		if strings.TrimSpace(line) != "" {
			firstContentLine = index
			break
		}
	}
	if firstContentLine <= 0 {
		t.Fatalf("confirmation is not vertically centered: first content line %d", firstContentLine)
	}
}
