package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
)

func printableKey(value string) tea.KeyPressMsg {
	runes := []rune(value)
	return tea.KeyPressMsg(tea.Key{Text: value, Code: runes[0]})
}

func specialKey(code rune) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: code})
}

func TestObservedDetailTextSplitsFindingsAndWrapsContinuation(t *testing.T) {
	value := "PASS_MAX_DAYS=99999; PASS_MIN_DAYS=0; password-auth에서 pwquality보다 pam_unix가 먼저 실행됨"
	got := observedDetailText(value, 34)
	for _, expected := range []string{"- PASS_MAX_DAYS=99999", "- PASS_MIN_DAYS=0", "- password-auth에서"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("observedDetailText() is missing %q: %q", expected, got)
		}
	}
	if strings.Contains(got, "; ") || !strings.Contains(got, "\n  ") {
		t.Fatalf("observedDetailText() did not split or indent wrapped findings: %q", got)
	}
	if preserved := observedDetailText("value=a;b", 40); preserved != "value=a;b" {
		t.Fatalf("observedDetailText() split a semicolon inside a value: %q", preserved)
	}
}

func TestDetailContentFormatsU02FindingsWithinViewport(t *testing.T) {
	result := model.CheckResult{
		RuleID:  "U-02",
		Title:   "비밀번호 관리정책 설정",
		Status:  model.StatusFail,
		Summary: "비밀번호 관리 정책이 가이드 기준을 충족하지 않습니다.",
		Expected: "길이 8자 이상, 문자 종류 4개, 이력 4회, 사용 기간 1~90일 정책이 " +
			"모든 적용 계정에 유효해야 합니다.",
		Observed: "PASS_MAX_DAYS=99999; PASS_MIN_DAYS=0; authselect with-pwhistory 기능이 활성화되지 않음; " +
			"password-auth /etc/pam.d/password-auth:20 pam_unix.so가 pwquality/pwhistory보다 먼저 실행됨",
	}
	content := detailContent(result, 52)
	if strings.Contains(content, "; ") {
		t.Fatalf("detailContent() kept semicolon-separated findings: %q", content)
	}
	for _, line := range strings.Split(content, "\n") {
		if width := ansi.StringWidth(line); width > 52 {
			t.Fatalf("detailContent() line width = %d, want <= 52: %q", width, line)
		}
	}
}

func TestDetailContentPrefersStructuredResultDetails(t *testing.T) {
	result := model.CheckResult{
		RuleID:   "U-02",
		Title:    "비밀번호 관리정책 설정",
		Status:   model.StatusFail,
		Summary:  "비밀번호 관리 정책이 기준을 충족하지 않습니다.",
		Expected: "비밀번호 정책 기준",
		Observed: "PASS_MAX_DAYS=99999; raw fallback text",
		DisplayDetails: []model.ResultDetail{{
			Label: "사용 기간", Current: "최소 0일 / 최대 99999일",
			Expected: "최소 1일 / 최대 90일", Source: "/etc/login.defs",
		}},
	}
	content := ansi.Strip(detailContent(result, 60))
	for _, expected := range []string{"사용 기간", "현재", "최소 0일 / 최대 99999일", "기준", "최소 1일 / 최대 90일", "위치", "/etc/login.defs"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("structured detail is missing %q: %q", expected, content)
		}
	}
	if strings.Contains(content, "raw fallback text") {
		t.Fatalf("structured detail rendered the legacy fallback: %q", content)
	}
	if strings.Index(content, "기준") > strings.Index(content, "현재") {
		t.Fatalf("structured detail renders current before expected: %q", content)
	}
}

func TestRegistryFallbackDetailsUseSemanticFormatterWithoutChangingObserved(t *testing.T) {
	registry := evaluator.NewRegistry()
	if err := registry.Register("fixture.details", func(context.Context, model.ResolvedRule, evaluator.Environment) evaluator.Outcome {
		return evaluator.Outcome{
			Status: model.StatusFail, Summary: "fixture failure", Expected: "expected value",
			Observed: "first finding; second finding; value=a;b",
		}
	}); err != nil {
		t.Fatal(err)
	}
	result := registry.Evaluate(context.Background(), model.ResolvedRule{
		RuleDefinition: model.RuleDefinition{
			ID: "U-02", Title: "비밀번호 관리정책 설정", Evaluator: "fixture.details",
			Severity: model.SeverityHigh, Category: model.CategoryAccount,
		},
		Applicable: true,
	}, evaluator.Environment{})
	if result.Observed != "first finding; second finding; value=a;b" {
		t.Fatalf("registry changed the report-compatible observed value: %q", result.Observed)
	}
	if len(result.DisplayDetails) != 1 {
		t.Fatalf("registry display details = %#v, want one fallback detail", result.DisplayDetails)
	}
	content := ansi.Strip(detailContent(result, 52))
	if strings.Contains(content, "first finding; second finding") {
		t.Fatalf("semantic formatter kept findings on one line: %q", content)
	}
	for _, expected := range []string{"- first finding", "- second finding", "- value=a;b"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("semantic formatter is missing %q: %q", expected, content)
		}
	}
}

func TestFailDetailColorsExpectedGreenAndCurrentRed(t *testing.T) {
	details := []model.ResultDetail{{Label: "사용 기간", Current: "99999일", Expected: "90일"}}
	rendered := resultDetailText(details, 60, model.StatusFail)
	if !strings.Contains(rendered, successStyle.Render("90일")) || !strings.Contains(rendered, errorStyle.Render("99999일")) {
		t.Fatalf("FAIL detail does not color expected/current distinctly: %q", rendered)
	}
}

func TestFilterInputOwnsShortcutKeysWhileEditing(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.screen = screenResults
	view.run.Results = []model.CheckResult{{RuleID: "U-01", Title: "root 계정", Status: model.StatusFail}}
	view.updateItems()

	view.Update(printableKey("/"))
	if !view.list.SettingFilter() {
		t.Fatal("slash did not open the list filter")
	}
	for _, value := range []string{"a", "r", "q"} {
		view.Update(printableKey(value))
	}
	if got := view.list.FilterValue(); got != "arq" {
		t.Fatalf("filter value = %q, want shortcut letters as input", got)
	}
	if view.showAll {
		t.Fatal("filter input triggered the A shortcut")
	}
}

func TestResultItemTitleAndFilterValueRemainPlainAndIdentical(t *testing.T) {
	item := resultItem{result: model.CheckResult{RuleID: "U-01", Title: "root 계정", Status: model.StatusFail}}
	title := item.Title()
	if title != ansi.Strip(title) {
		t.Fatalf("result title contains ANSI styling: %q", title)
	}
	if item.FilterValue() != title || item.FilterValue() != "취약  U-01  root 계정" {
		t.Fatalf("filter value %q does not match plain title %q", item.FilterValue(), title)
	}
}

func TestFilteredResultViewKeepsANSISequencesWellFormed(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width = 100
	view.height = 34
	view.resize()
	view.screen = screenResults
	view.run.Results = []model.CheckResult{{RuleID: "U-01", Title: "root 계정", Summary: "원격 접속 제한", Status: model.StatusFail}}
	view.updateItems()
	view.Update(printableKey("/"))
	view.Update(printableKey("U-01"))
	rendered := view.list.View()
	plain := ansi.Strip(rendered)
	for _, fragment := range []string{"[38;", "[39m", "[0m"} {
		if strings.Contains(plain, fragment) {
			t.Fatalf("filtered view exposed ANSI fragment %q: %q", fragment, plain)
		}
	}
}

func TestResultsListShowsAtLeastFourItemsInShortTerminal(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width = 100
	view.height = 20
	view.resize()
	view.screen = screenResults
	for index := 1; index <= 8; index++ {
		view.run.Results = append(view.run.Results, model.CheckResult{
			RuleID:  fmt.Sprintf("U-%02d", index),
			Title:   "점검 항목",
			Summary: "판정 요약",
			Status:  model.StatusFail,
		})
	}
	view.updateItems()
	plain := ansi.Strip(view.list.View())
	visible := 0
	for index := 1; index <= 8; index++ {
		if strings.Contains(plain, fmt.Sprintf("U-%02d", index)) {
			visible++
		}
	}
	if visible < 4 {
		t.Fatalf("short terminal shows %d result items, want at least 4: %q", visible, plain)
	}
}

func TestReportPathEditorSupportsCursorMovement(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.screen = screenOptions
	view.optionIndex = optionReportDir
	view.optionInput.SetValue("abcdef")
	view.optionInput.CursorEnd()
	view.optionInput.Focus()
	view.editingOption = true

	view.Update(specialKey(tea.KeyLeft))
	view.Update(specialKey(tea.KeyLeft))
	view.Update(printableKey("X"))
	if got := view.optionInput.Value(); got != "abcdXef" {
		t.Fatalf("report path input = %q, want insertion at moved cursor", got)
	}
}

func TestScanCompleteStoresRedactedCopyForTUIDetail(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	run := model.ScanRun{
		Metadata: model.RunMetadata{Redaction: true},
		Results: []model.CheckResult{{
			RuleID:   "U-02",
			Title:    "fixture",
			Status:   model.StatusFail,
			Observed: "password=tui-secret",
			DisplayDetails: []model.ResultDetail{{
				Label:   "설정",
				Current: "token=detail-secret",
			}},
		}},
	}

	view.Update(scanCompleteMsg{run: run, reportPath: "/reports/fixture"})
	stored := view.run.Results[0]
	if strings.Contains(stored.Observed, "tui-secret") ||
		strings.Contains(stored.DisplayDetails[0].Current, "detail-secret") {
		t.Fatalf("TUI model retained an unredacted secret: %#v", stored)
	}
	if !strings.Contains(stored.Observed, "[REDACTED]") ||
		!strings.Contains(stored.DisplayDetails[0].Current, "[REDACTED]") {
		t.Fatalf("TUI model does not contain redaction markers: %#v", stored)
	}
	if !strings.Contains(run.Results[0].Observed, "tui-secret") ||
		!strings.Contains(run.Results[0].DisplayDetails[0].Current, "detail-secret") {
		t.Fatalf("scanCompleteMsg input was mutated: %#v", run.Results[0])
	}
	if detail := ansi.Strip(detailContent(stored, 60)); strings.Contains(detail, "detail-secret") ||
		!strings.Contains(detail, "[REDACTED]") {
		t.Fatalf("TUI detail did not use the redacted copy: %q", detail)
	}
}

func TestScanCompleteKeepsUnredactedTUIWhenDisabled(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	run := model.ScanRun{
		Metadata: model.RunMetadata{Redaction: false},
		Results: []model.CheckResult{{
			RuleID:   "U-02",
			Title:    "fixture",
			Status:   model.StatusFail,
			Observed: "password=explicit-no-redact",
		}},
	}

	view.Update(scanCompleteMsg{run: run})
	if got := view.run.Results[0].Observed; got != "password=explicit-no-redact" {
		t.Fatalf("no-redact TUI value = %q, want original", got)
	}
}

func TestTUIErrorScreensProtectSensitiveAndControlContent(t *testing.T) {
	for _, target := range []screen{screenError, screenRemediationError} {
		view := newModel(context.Background(), nil, nil, nil)
		view.screen = target
		injected := errors.New("password=tui-error-secret\x1b[2J\u202e")
		if target == screenError {
			view.err = injected
		} else {
			view.remediationErr = injected
		}

		output := ansi.Strip(view.View().Content)
		if strings.Contains(output, "tui-error-secret") ||
			strings.ContainsAny(output, "\x1b\u202e") {
			t.Fatalf("screen %d retained sensitive/control content: %q", target, output)
		}
		if !strings.Contains(output, "[REDACTED]") {
			t.Fatalf("screen %d output = %q, want redaction marker", target, output)
		}
	}
}

func TestTUIErrorScreenHonorsExplicitNoRedact(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.screen = screenError
	view.scanSettings.noRedact = true
	view.err = errors.New("password=explicit-error-secret\x1b[2J")

	output := ansi.Strip(view.View().Content)
	if !strings.Contains(output, "explicit-error-secret") {
		t.Fatalf("no-redact error output = %q, want original secret", output)
	}
	if strings.Contains(output, "\x1b") || !strings.Contains(output, "<U+001B>") {
		t.Fatalf("no-redact error output did not neutralize control content: %q", output)
	}
}

func TestTUIResultAndFilterNeutralizeControlCharacters(t *testing.T) {
	result := model.CheckResult{
		RuleID:   "U-\x1b[2J01",
		Title:    "제목\u202e",
		Status:   model.StatusFail,
		Severity: model.SeverityHigh,
		Category: model.CategoryAccount,
		Summary:  "요약\x00\u2066숨김\u2069",
		Expected: "기준\u0085",
		Observed: "현재\x07",
		Reference: model.Reference{
			Section: "절\u009b31m",
			Pages:   []int{12},
		},
	}
	item := resultItem{result: result}
	for name, value := range map[string]string{
		"title":       item.Title(),
		"description": item.Description(),
	} {
		if sanitized := presentation.Sanitize(value); sanitized != value {
			t.Fatalf("%s retained a control character: %q", name, value)
		}
		if !strings.Contains(value, "<U+") {
			t.Fatalf("%s does not contain a neutralized marker: %q", name, value)
		}
	}

	detail := ansi.Strip(detailContent(result, 60))
	for _, forbidden := range []string{"\x1b[2J", "\u202e", "\x00", "\u2066", "\u2069", "\u0085", "\x07", "\u009b"} {
		if strings.Contains(detail, forbidden) {
			t.Fatalf("detail retained %q: %q", forbidden, detail)
		}
	}
	for _, expected := range []string{"<U+001B>[2J", "<U+202E>", "<U+0000>", "<U+2066>", "<U+0085>", "<U+0007>", "<U+009B>31m"} {
		if !strings.Contains(detail, expected) {
			t.Fatalf("detail lacks %q: %q", expected, detail)
		}
	}

	view := newModel(context.Background(), nil, nil, nil)
	view.screen = screenResults
	view.run.Results = []model.CheckResult{{RuleID: "U-01", Title: "fixture", Status: model.StatusFail}}
	view.updateItems()
	view.Update(printableKey("/"))
	view.Update(printableKey("U-\x1b[2J\u202e01"))
	filter := view.list.FilterValue()
	if strings.Contains(filter, "\x1b") || strings.Contains(filter, "\u202e") {
		t.Fatalf("filter retained terminal controls: %q", filter)
	}
	for _, expected := range []string{"<U+001B>[2J", "<U+202E>"} {
		if !strings.Contains(filter, expected) {
			t.Fatalf("filter lacks %q: %q", expected, filter)
		}
	}
}
