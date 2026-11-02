package tui

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestKeyLegendWrapsBetweenCompleteHints(t *testing.T) {
	legend := optionKeyLegend(24, "↑↓", "이동", "Enter", "상세", "Esc", "종료")
	for _, line := range strings.Split(legend, "\n") {
		if got := ansi.StringWidth(line); got > 24 {
			t.Fatalf("legend line width = %d, want <= 24: %q", got, line)
		}
	}
	for _, hint := range []string{"↑↓ 이동", "Enter 상세", "Esc 종료"} {
		if !strings.Contains(ansi.Strip(legend), hint) {
			t.Fatalf("legend split or lost %q: %q", hint, legend)
		}
	}
}

func TestMainScreenHelpNamesTheActions(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 100, 30
	view.resize()
	for _, screen := range []struct {
		current screen
		want    []string
	}{
		{screenReady, []string{"메뉴 이동", "메뉴 선택", "종료 확인"}},
		{screenOptions, []string{"옵션 이동", "설정값 변경", "점검 시작", "기본값 복원", "시작 화면으로"}},
	} {
		view.screen = screen.current
		content := ansi.Strip(view.View().Content)
		for _, text := range screen.want {
			if !strings.Contains(content, text) {
				t.Fatalf("screen %d is missing action %q: %q", screen.current, text, content)
			}
		}
	}
	view.openOptionPicker(optionChecks)
	picker := ansi.Strip(view.View().Content)
	for _, text := range []string{"항목 이동", "항목 선택·해제", "선택 적용", "실행 옵션으로"} {
		if !strings.Contains(picker, text) {
			t.Fatalf("multi-select help is missing %q: %q", text, picker)
		}
	}
	if single := ansi.Strip(pickerKeyLegend(80, optionEvidence)); strings.Contains(single, "선택·해제") {
		t.Fatalf("single-select picker implies that a selection can be cleared: %q", single)
	}
}

func TestResultsFooterFitsAndKeepsControlsVisible(t *testing.T) {
	for _, size := range []struct{ width, height int }{{80, 24}, {100, 20}, {140, 27}} {
		t.Run(fmt.Sprintf("%dx%d", size.width, size.height), func(t *testing.T) {
			view := newModel(context.Background(), nil, nil, nil)
			view.width, view.height = size.width, size.height
			view.resize()
			view.screen = screenResults
			view.reportPath = "/home/사용자/reports/2026-11-01_example"
			view.run.Metadata.Counts = map[model.Status]int{model.StatusFail: 1, model.StatusUnknown: 1}
			view.run.Results = []model.CheckResult{
				{RuleID: "U-01", Title: "root 계정", Status: model.StatusFail},
				{RuleID: "U-02", Title: "비밀번호 정책", Status: model.StatusUnknown},
			}
			view.updateItems()
			content := view.View().Content
			if got := lipgloss.Height(content); got > size.height {
				t.Fatalf("result view height = %d, want <= %d:\n%s", got, size.height, ansi.Strip(content))
			}
			for _, line := range strings.Split(content, "\n") {
				if got := ansi.StringWidth(line); got > size.width {
					t.Fatalf("result line width = %d, want <= %d: %q", got, size.width, ansi.Strip(line))
				}
			}
			for _, label := range []string{"U-01", "취약 1", "수동 확인 필요 1", "보고서", "자동 조치", "상세 확인", "Esc 종료 확인", "항목 이동", "전체 항목 보기", "시작 화면으로"} {
				if !strings.Contains(ansi.Strip(content), label) {
					t.Errorf("result view lost %q:\n%s", label, ansi.Strip(content))
				}
			}
		})
	}
}

func hasPanelMarker(content, marker string) bool {
	for _, line := range strings.Split(ansi.Strip(content), "\n") {
		cells := strings.Split(line, "│")
		if len(cells) >= 3 && strings.TrimSpace(cells[len(cells)-2]) == marker {
			return true
		}
	}
	return false
}

func assertPanelMarkersAt(t *testing.T, content, title string, above, below bool, footerRows int) {
	t.Helper()
	var rows []string
	inside := false
	for _, line := range strings.Split(ansi.Strip(content), "\n") {
		if strings.Contains(line, "╭─ "+title) {
			inside = true
			continue
		}
		if inside && strings.Contains(line, "╰") {
			break
		}
		if inside {
			cells := strings.Split(line, "│")
			if len(cells) >= 3 {
				rows = append(rows, strings.TrimSpace(cells[len(cells)-2]))
			}
		}
	}
	if len(rows) <= footerRows {
		t.Fatalf("could not read panel %q: %q", title, content)
	}
	for index, row := range rows {
		want := (above && index == 0) || (below && index == len(rows)-1-footerRows)
		if (row == scrollContinuationMarker) != want {
			t.Fatalf("panel %q marker at row %d: got %q, above=%t below=%t: %#v", title, index, row, above, below, rows)
		}
	}
}

func assertCenteredPanelMarkers(t *testing.T, content, marker string, want int) {
	t.Helper()
	count := 0
	for _, line := range strings.Split(ansi.Strip(content), "\n") {
		for _, cell := range strings.Split(line, "│") {
			if strings.TrimSpace(cell) != marker {
				continue
			}
			index := strings.Index(cell, marker)
			left := ansi.StringWidth(cell[:index])
			right := ansi.StringWidth(cell[index+len(marker):])
			if left-right < -1 || left-right > 1 {
				t.Fatalf("marker %q is off center: left=%d right=%d in %q", marker, left, right, line)
			}
			count++
		}
	}
	if count != want {
		t.Fatalf("found %d centered %q markers, want %d: %q", count, marker, want, content)
	}
}

func TestScrollMarkersAreInsideThePanel(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	items := strings.Split(strings.Repeat("내용\n", 30), "\n")
	for _, offset := range []int{0, 5} {
		view.previewOffset = offset
		content := view.previewWithAction(items, 43, 10)
		rendered := ansi.Strip(framedPanel("선택한 항목", content, 47, 12))
		lines := strings.Split(rendered, "\n")
		if strings.Contains(lines[0]+lines[len(lines)-1], scrollContinuationMarker) {
			t.Fatalf("scroll marker appeared on the border: %q", rendered)
		}
		assertPanelMarkersAt(t, rendered, "선택한 항목", offset > 0, true, 1)
		for _, line := range lines {
			if got := ansi.StringWidth(line); got != 47 {
				t.Fatalf("panel rendered a %d-column line: %q", got, rendered)
			}
		}
	}
}

func TestResultScrollMarkersAreCenteredInTheirOwnPanels(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 26
	view.resize()
	view.screen = screenResults
	view.run.Results = []model.CheckResult{{
		RuleID: "U-01", Title: "긴 항목", Status: model.StatusFail,
		DisplayDetails: []model.ResultDetail{{Label: "설정", Current: strings.Repeat("자세한 확인 내용 ", 100)}},
	}}
	for index := 2; index <= 25; index++ {
		view.run.Results = append(view.run.Results, model.CheckResult{
			RuleID: fmt.Sprintf("U-%02d", index), Title: "다른 항목", Status: model.StatusFail,
		})
	}
	view.updateItems()
	initial := view.View().Content
	assertCenteredPanelMarkers(t, initial, scrollContinuationMarker, 2)
	view.Update(specialKey(tea.KeyPgDown))
	scrolled := view.View().Content
	assertCenteredPanelMarkers(t, scrolled, scrollContinuationMarker, 3)
	view.list.Select(20)
	listScrolled := view.View().Content
	assertCenteredPanelMarkers(t, listScrolled, scrollContinuationMarker, 2)
}

func TestScrollWindowKeepsEveryLineReachable(t *testing.T) {
	for capacity := 1; capacity <= 10; capacity++ {
		for total := 1; total <= 35; total++ {
			seen := make([]bool, total)
			offset := 0
			for page := 0; page < total+2; page++ {
				window := scrollWindowFor(total, offset, capacity)
				for index := window.offset; index < window.offset+window.height && index < total; index++ {
					seen[index] = true
				}
				if window.offset == window.maxOffset {
					break
				}
				step := window.height - 1
				if step < 1 {
					step = 1
				}
				offset = window.offset + step
			}
			for index, visible := range seen {
				if !visible {
					t.Fatalf("capacity %d, total %d: line %d is unreachable", capacity, total, index)
				}
			}
		}
	}
}

func TestResultRowsAlignRuleNumbersWithDifferentStatuses(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 100, 24
	view.resize()
	view.screen = screenResults
	view.run.Results = []model.CheckResult{
		{RuleID: "U-01", Title: "첫 항목", Status: model.StatusFail},
		{RuleID: "U-02", Title: "둘째 항목", Status: model.StatusUnknown},
	}
	view.updateItems()
	content := ansi.Strip(view.View().Content)
	columns := make(map[string]int)
	for _, line := range strings.Split(content, "\n") {
		for _, id := range []string{"U-01", "U-02"} {
			if index := strings.Index(line, id); index >= 0 {
				columns[id] = ansi.StringWidth(line[:index])
			}
		}
	}
	if len(columns) != 2 || columns["U-01"] != columns["U-02"] {
		t.Fatalf("rule columns are not aligned: %v\n%s", columns, content)
	}
}

func TestDetailUsesReadableModelLabels(t *testing.T) {
	result := model.CheckResult{
		Severity: model.SeverityHigh, Category: model.CategoryAccount,
		UnknownReason: model.UnknownManualVerification,
	}
	content := ansi.Strip(detailContent(result, 80))
	for _, label := range []string{"중요도  상", "분류  계정 관리", "직접 확인이 필요합니다."} {
		if !strings.Contains(content, label) {
			t.Errorf("detail missing %q: %q", label, content)
		}
	}
}

func TestDetailIndicatesAdditionalContentWithinViewport(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 80, 24
	view.resize()
	view.screen = screenDetail
	view.viewport.SetContent(strings.Repeat("상세 내용\n", 40))
	content := view.View().Content
	if got := lipgloss.Height(content); got > view.height {
		t.Fatalf("detail view height = %d, want <= %d", got, view.height)
	}
	for _, line := range strings.Split(content, "\n") {
		if got := ansi.StringWidth(line); got > view.width {
			t.Fatalf("detail line width = %d, want <= %d: %q", got, view.width, ansi.Strip(line))
		}
	}
	if !hasPanelMarker(content, scrollContinuationMarker) {
		t.Fatalf("detail view did not indicate more content: %q", ansi.Strip(content))
	}
}

func TestWideResultsShowSelectedItemInSeparatePanel(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 30
	view.resize()
	view.screen = screenResults
	view.run.Results = []model.CheckResult{
		{RuleID: "U-01", Title: "첫 항목", Status: model.StatusFail, DisplayDetails: []model.ResultDetail{{Label: "설정", Current: "첫 현재값", Expected: "첫 기준", Source: "/etc/first"}}},
		{RuleID: "U-02", Title: "둘째 항목", Status: model.StatusFail, DisplayDetails: []model.ResultDetail{{Label: "설정", Current: "둘째 현재값", Expected: "둘째 기준", Source: "/etc/second"}}},
	}
	view.updateItems()
	content := ansi.Strip(view.View().Content)
	for _, expected := range []string{"╭─ 문제 항목", "╭─ 선택한 항목", "첫 현재값", "첫 기준", "/etc/first"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("wide result view missing %q:\n%s", expected, content)
		}
	}
	view.Update(specialKey(tea.KeyDown))
	if got := ansi.Strip(view.resultPreview(40, 16)); !strings.Contains(got, "둘째 현재값") {
		t.Fatalf("preview did not follow list selection: %q", got)
	}
}

func TestDetailShowsAvailableSettingsEvenWithoutObservedSummary(t *testing.T) {
	result := model.CheckResult{
		Summary: "요약", DisplayDetails: []model.ResultDetail{{
			Label: "사용 기간", Current: "PASS_MAX_DAYS=99999",
			Expected: "90일 이하", Source: "/etc/login.defs",
		}},
	}
	content := ansi.Strip(detailContent(result, 80))
	for _, value := range []string{"확인한 설정", "PASS_MAX_DAYS=99999", "90일 이하", "/etc/login.defs"} {
		if !strings.Contains(content, value) {
			t.Fatalf("detail lost %q: %q", value, content)
		}
	}
	if strings.Index(content, "PASS_MAX_DAYS=99999") > strings.Index(content, "판정 이유") {
		t.Fatalf("actual settings appear after the summary: %q", content)
	}
}

func TestPreviewDoesNotInventValuesWhenNoSettingWasCollected(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.run.Results = []model.CheckResult{{RuleID: "U-01", Title: "미확인", Summary: "확인 필요", Status: model.StatusUnknown}}
	view.updateItems()
	got := ansi.Strip(view.resultPreview(40, 16))
	if !strings.Contains(got, "표시할 확인 결과가 없습니다") || strings.Contains(got, "현재  ") {
		t.Fatalf("preview suggests a value was collected: %q", got)
	}
}

func TestWideOptionsShowSelectedOptionInSeparatePanel(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 26
	view.resize()
	view.screen = screenOptions
	content := view.View().Content
	if got := lipgloss.Height(content); got > view.height {
		t.Fatalf("options view height = %d, want <= %d", got, view.height)
	}
	for _, line := range strings.Split(content, "\n") {
		if got := ansi.StringWidth(line); got > view.width {
			t.Fatalf("options line width = %d, want <= %d: %q", got, view.width, ansi.Strip(line))
		}
	}
	for _, expected := range []string{"╭─ 설정", "╭─ 선택한 옵션", "점검 범위", "Esc 종료"} {
		if !strings.Contains(ansi.Strip(content), expected) {
			t.Fatalf("wide options view missing %q:\n%s", expected, ansi.Strip(content))
		}
	}
}

func TestSelectedOptionTruncatesLongValueWithoutBreakingRowWidth(t *testing.T) {
	view := &Model{scanSettings: defaultScanSettings(), optionIndex: optionChecks}
	view.scanSettings.checks = strings.Repeat("U-01,", 30)
	row := view.optionRow(optionChecks, optionLabels[optionChecks], 50)
	if got := ansi.StringWidth(row); got > 50 {
		t.Fatalf("selected option row width = %d, want <= 50: %q", got, ansi.Strip(row))
	}
}

func TestNarrowOptionsAndPickerKeepSelectionAndHelpVisible(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 80, 24
	view.resize()
	view.screen = screenOptions
	view.optionIndex = optionRedaction
	options := ansi.Strip(view.View().Content)
	for _, expected := range []string{"╭─ 설정", "민감정보", "자동 조치", "설명", "Esc 종료"} {
		if !strings.Contains(options, expected) {
			t.Fatalf("narrow options missing %q:\n%s", expected, options)
		}
	}
	view.openOptionPicker(optionChecks)
	view.optionPicker.index = len(view.optionPicker.choices) - 1
	picker := view.View().Content
	if got := lipgloss.Height(picker); got > view.height {
		t.Fatalf("picker height = %d, want <= %d", got, view.height)
	}
	for _, expected := range []string{"╭─ 선택 항목", "U-67", "이전", "Esc 종료"} {
		if !strings.Contains(ansi.Strip(picker), expected) {
			t.Fatalf("picker missing %q:\n%s", expected, ansi.Strip(picker))
		}
	}
}

func TestSelectedLongResultFitsWithinListRow(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.list.SetSize(66, 15)
	item := resultItem{result: model.CheckResult{
		RuleID: "U-21", Status: model.StatusFail,
		Title:   "/etc/(r)syslog.conf 파일 소유자 및 권한 설정",
		Summary: "설정 파일의 소유자 또는 권한이 기준을 충족하지 않습니다.",
	}}
	var output bytes.Buffer
	newResultDelegate(true).Render(&output, view.list, 0, item)
	if got := lipgloss.Height(output.String()); got != 2 {
		t.Fatalf("result rendered %d lines, want 2: %q", got, ansi.Strip(output.String()))
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if got := ansi.StringWidth(line); got > view.list.Width() {
			t.Fatalf("result row width = %d, want <= %d: %q", got, view.list.Width(), ansi.Strip(line))
		}
	}
}

func TestResultsListOmitsRepeatedDescriptionsAndTitles(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 36
	view.resize()
	view.screen = screenResults
	view.run.Results = []model.CheckResult{{
		RuleID: "U-01", Title: "점검 항목", Summary: "목록에 반복할 필요가 없는 설명", Status: model.StatusFail,
		DisplayDetails: []model.ResultDetail{{Label: "실제 설정", Current: "value=1"}},
	}}
	view.updateItems()
	content := ansi.Strip(view.View().Content)
	if strings.Count(content, "목록에 반복할 필요가 없는 설명") != 1 || strings.Count(content, "문제 항목") != 1 {
		t.Fatalf("result list still repeats descriptions or title:\n%s", content)
	}
}

func TestResultsListWrapsLongTitlesAndKeepsSelectionVisible(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 24
	view.resize()
	view.screen = screenResults
	view.run.Results = []model.CheckResult{{
		RuleID: "U-01", Status: model.StatusFail,
		Title: strings.Repeat("긴 점검 항목 ", 7) + "이름끝",
	}}
	for index := 2; index <= 25; index++ {
		view.run.Results = append(view.run.Results, model.CheckResult{
			RuleID: fmt.Sprintf("U-%02d", index), Title: "다른 항목", Status: model.StatusFail,
		})
	}
	view.updateItems()
	view.View() // Establish the list width from the dashboard layout.
	content := ansi.Strip(view.resultListView(14))
	if !strings.Contains(content, "이름끝") || strings.Contains(content, "…") {
		t.Fatalf("long result title was not shown in full: %q", content)
	}
	listRows := strings.Split(content, "\n")
	if strings.TrimSpace(listRows[0]) == scrollContinuationMarker || strings.TrimSpace(listRows[len(listRows)-1]) != scrollContinuationMarker {
		t.Fatalf("initial list indicators are incorrect: %q", content)
	}
	for index := 1; index < len(view.run.Results); index++ {
		view.Update(specialKey(tea.KeyDown))
		content = ansi.Strip(view.resultListView(14))
		selected := view.list.SelectedItem().(resultItem)
		if !strings.Contains(content, selected.result.RuleID) {
			t.Fatalf("selected result %q is outside the visible list: %q", selected.result.RuleID, content)
		}
	}
	listRows = strings.Split(content, "\n")
	if strings.TrimSpace(listRows[0]) != scrollContinuationMarker || strings.TrimSpace(listRows[len(listRows)-1]) == scrollContinuationMarker {
		t.Fatalf("bottom list indicators are incorrect: %q", content)
	}
	view.Update(specialKey(tea.KeyUp))
	content = ansi.Strip(view.resultListView(14))
	if selected := view.list.SelectedItem().(resultItem); selected.result.RuleID != "U-24" || !strings.Contains(content, selected.result.RuleID) {
		t.Fatalf("moving back did not keep the selected result visible: %q", content)
	}
}

func TestResultPreviewPrioritizesMultipleActualValues(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.run.Results = []model.CheckResult{{
		RuleID: "U-02", Title: "비밀번호 정책", Status: model.StatusFail,
		DisplayDetails: []model.ResultDetail{
			{Label: "최소 길이", Current: "minlen=7", Source: "/etc/security/pwquality.conf", Expected: strings.Repeat("기준 설명 ", 15)},
			{Label: "사용 기간", Current: "PASS_MAX_DAYS=99999", Source: "/etc/login.defs"},
		},
	}}
	view.updateItems()
	content := ansi.Strip(view.resultPreview(48, 17))
	for _, value := range []string{"minlen=7", "PASS_MAX_DAYS=99999", "/etc/login.defs", "기준 설명"} {
		if !strings.Contains(content, value) {
			t.Fatalf("preview missing %q: %q", value, content)
		}
	}
	if strings.Contains(content, "…") {
		t.Fatalf("preview shortened the criterion: %q", content)
	}
	if got := lipgloss.Height(content); got > 17 {
		t.Fatalf("preview height = %d, want <= 17: %q", got, content)
	}
}

func TestResultPreviewDoesNotAttachAnotherSettingsCriterion(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.run.Results = []model.CheckResult{{
		RuleID: "U-02", Title: "비밀번호 정책", Status: model.StatusFail,
		DisplayDetails: []model.ResultDetail{
			{Label: "첫 설정", Current: "first=1"},
			{Label: "둘째 설정", Current: "second=2", Expected: "둘째 설정의 기준"},
		},
	}}
	view.updateItems()
	content := ansi.Strip(view.resultPreview(48, 17))
	if strings.Index(content, "둘째 설정의 기준") < strings.Index(content, "second=2") {
		t.Fatalf("another setting's criterion was attached to the first: %q", content)
	}
	if !strings.Contains(content, "first=1") || !strings.Contains(content, "second=2") {
		t.Fatalf("actual settings are missing: %q", content)
	}
}

func TestPreviewKeepsDetailActionAtBottom(t *testing.T) {
	for _, height := range []int{7, 12, 20} {
		for _, details := range [][]model.ResultDetail{
			nil,
			{{Label: "파일 권한", Current: "UID=0 GID=42 권한=0640", Source: "/etc/shadow"}},
		} {
			view := newModel(context.Background(), nil, nil, nil)
			view.run.Results = []model.CheckResult{{RuleID: "U-18", Title: "파일 권한", Status: model.StatusFail, DisplayDetails: details}}
			view.updateItems()
			lines := strings.Split(ansi.Strip(view.resultPreview(48, height)), "\n")
			if len(lines) != height || !strings.HasSuffix(lines[len(lines)-1], "Enter 상세 확인") {
				t.Fatalf("height %d: action is not at the bottom: %#v", height, lines)
			}
		}
	}
}

func TestPreviewShowsFullCriteriaAndScrollsWithoutChangingSelection(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 26
	view.resize()
	view.screen = screenResults
	criterion := "기준시작 " + strings.Repeat("긴 점검 기준을 자세하게 확인합니다 ", 40) + "기준마지막"
	view.run.Results = []model.CheckResult{
		{RuleID: "U-01", Title: "긴 기준", Status: model.StatusFail, Summary: "구체적인 판정 이유입니다.",
			DisplayDetails: []model.ResultDetail{{Label: "설정", Current: "actual=1", Source: "/etc/config", Expected: criterion}}},
		{RuleID: "U-02", Title: "다른 항목", Status: model.StatusFail, DisplayDetails: []model.ResultDetail{{Label: "설정", Current: "actual=2"}}},
	}
	view.updateItems()
	first := ansi.Strip(view.View().Content)
	for _, value := range []string{"actual=1", "기준시작", "PgUp/PgDn"} {
		if !strings.Contains(first, value) {
			t.Fatalf("initial preview is missing %q: %q", value, first)
		}
	}
	if strings.Contains(first, "…") {
		t.Fatalf("criterion was shortened with an ellipsis: %q", first)
	}
	foundEnd, foundSummary := false, false
	for page := 0; page < 30 && !(foundEnd && foundSummary); page++ {
		view.Update(specialKey(tea.KeyPgDown))
		if item := view.list.SelectedItem().(resultItem); item.result.RuleID != "U-01" {
			t.Fatalf("scrolling preview changed the selected item: %q", item.result.RuleID)
		}
		pageContent := ansi.Strip(view.View().Content)
		foundEnd = foundEnd || strings.Contains(pageContent, "기준마지막")
		foundSummary = foundSummary || strings.Contains(pageContent, "구체적인 판정 이유입니다")
	}
	if !foundEnd || !foundSummary {
		t.Fatal("could not scroll to the end of the criterion and the explanation")
	}
	lastOffset := view.previewOffset
	view.Update(specialKey(tea.KeyPgUp))
	view.View()
	if view.previewOffset >= lastOffset {
		t.Fatal("PgUp did not scroll the preview back")
	}
	view.Update(specialKey(tea.KeyDown))
	other := ansi.Strip(view.View().Content)
	if !strings.Contains(other, "actual=2") || view.previewOffset != 0 {
		t.Fatalf("preview did not return to the start for the new selection: %q", other)
	}
}

func TestPreviewScrollIndicatorsFollowPositionAndSelection(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 26
	view.resize()
	view.screen = screenResults
	view.run.Results = []model.CheckResult{
		{RuleID: "U-01", Title: "긴 항목", Status: model.StatusFail,
			DisplayDetails: []model.ResultDetail{{Label: "확인", Current: strings.Repeat("확인한 내용을 자세히 표시합니다. ", 120)}}},
		{RuleID: "U-02", Title: "짧은 항목", Status: model.StatusFail,
			DisplayDetails: []model.ResultDetail{{Label: "확인", Current: "정상"}}},
	}
	view.updateItems()
	initial := ansi.Strip(view.View().Content)
	assertPanelMarkersAt(t, initial, "선택한 항목", false, true, 1)
	view.Update(specialKey(tea.KeyPgDown))
	middle := ansi.Strip(view.View().Content)
	assertPanelMarkersAt(t, middle, "선택한 항목", true, true, 1)
	for page := 0; page < 100 && view.previewOffset < view.previewScrollMax; page++ {
		view.Update(specialKey(tea.KeyPgDown))
		view.View()
	}
	if view.previewOffset != view.previewScrollMax {
		t.Fatal("could not reach the bottom of the preview")
	}
	bottom := ansi.Strip(view.View().Content)
	assertPanelMarkersAt(t, bottom, "선택한 항목", true, false, 1)
	view.Update(specialKey(tea.KeyDown))
	short := ansi.Strip(view.View().Content)
	assertPanelMarkersAt(t, short, "선택한 항목", false, false, 1)
}

func TestDetailScrollIndicatorsFollowViewportPosition(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 100, 26
	view.resize()
	view.screen = screenDetail
	view.viewport.SetContent(strings.Repeat("점검 내용\n", 60))
	initial := ansi.Strip(view.View().Content)
	assertPanelMarkersAt(t, initial, "점검 상세", false, true, 0)
	assertCenteredPanelMarkers(t, initial, scrollContinuationMarker, 1)
	view.Update(specialKey(tea.KeyPgDown))
	middle := ansi.Strip(view.View().Content)
	assertPanelMarkersAt(t, middle, "점검 상세", true, true, 0)
	assertCenteredPanelMarkers(t, middle, scrollContinuationMarker, 2)
	view.viewport.GotoBottom()
	bottom := ansi.Strip(view.View().Content)
	assertPanelMarkersAt(t, bottom, "점검 상세", true, false, 0)
}

func TestPreviewDoesNotShortenLongResultFields(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 140, 24
	view.resize()
	view.screen = screenResults
	long := strings.Repeat("실제 확인 내용을 자세히 표시합니다 ", 20)
	view.run.Results = []model.CheckResult{{
		RuleID: "U-01", Title: "설정 점검", Status: model.StatusFail,
		Summary: long + "설명끝", Solution: long + "조치끝",
		DisplayDetails: []model.ResultDetail{{
			Label: "확인 항목", Current: long + "결과끝", Source: long + "위치끝", Expected: long + "기준끝",
		}},
	}}
	view.updateItems()
	remaining := map[string]bool{"결과끝": true, "위치끝": true, "기준끝": true, "설명끝": true, "조치끝": true}
	for page := 0; page < 80 && len(remaining) > 0; page++ {
		content := ansi.Strip(view.View().Content)
		if strings.Contains(content, "…") {
			t.Fatalf("preview shortened a field: %q", content)
		}
		for value := range remaining {
			if strings.Contains(content, value) {
				delete(remaining, value)
			}
		}
		view.Update(specialKey(tea.KeyPgDown))
	}
	if len(remaining) != 0 {
		t.Fatalf("long fields were not reachable: %v", remaining)
	}
}

func TestPreviewUpdatesAfterResizeAndNewScan(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.run.Results = []model.CheckResult{{
		RuleID: "U-01", Title: "점검", Status: model.StatusFail,
		DisplayDetails: []model.ResultDetail{{Label: "설정", Current: strings.Repeat("긴 설정 내용 ", 12)}},
	}}
	view.updateItems()
	view.resultPreview(60, 12)
	resized := ansi.Strip(view.resultPreview(35, 12))
	for _, line := range strings.Split(resized, "\n") {
		if ansi.StringWidth(line) > 35 {
			t.Fatalf("preview did not reflow after resize: %q", line)
		}
	}
	view.run.Results[0].DisplayDetails[0].Current = "새 점검 결과"
	view.updateItems()
	if content := ansi.Strip(view.resultPreview(35, 12)); !strings.Contains(content, "새 점검 결과") {
		t.Fatalf("preview retained the previous scan: %q", content)
	}
}

func TestDetailValueKeepsPermissionTokenTogether(t *testing.T) {
	value := "소유자 UID=0, 그룹 GID=42\n기본 권한=0640 (-rw-r-----)"
	for _, width := range []int{30, 36, 40, 45, 52} {
		rendered := ansi.Strip(detailValueLine("확인 결과", value, width, nil))
		if !strings.Contains(rendered, "(-rw-r-----)") {
			t.Errorf("width %d split a permission token: %q", width, rendered)
		}
		for _, line := range strings.Split(rendered, "\n") {
			if ansi.StringWidth(line) > width {
				t.Errorf("width %d overflowed: %q", width, line)
			}
			if strings.TrimSpace(line) == ")" {
				t.Errorf("width %d left a closing parenthesis alone: %q", width, rendered)
			}
		}
	}
}

func TestPermissionPreviewShowsOwnerAndPermissions(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.run.Results = []model.CheckResult{{
		RuleID: "U-18", Title: "/etc/shadow", Status: model.StatusFail,
		DisplayDetails: []model.ResultDetail{{
			Label: "파일 권한", Current: "소유자 UID=0, 그룹 GID=42\n기본 권한=0640 (-rw-r-----)",
			Source: "/etc/shadow", Expected: "root 소유, 권한 0400 이하",
		}},
	}}
	view.updateItems()
	content := ansi.Strip(view.resultPreview(43, 20))
	for _, value := range []string{"소유자 UID=0", "그룹 GID=42", "기본 권한=0640", "(-rw-r-----)", "/etc/shadow", "Enter 상세 확인"} {
		if !strings.Contains(content, value) {
			t.Fatalf("preview missing %q: %q", value, content)
		}
	}
}

func TestDetailValueWrapsLongTokensWithoutLosingCharacters(t *testing.T) {
	value := "/etc/abcdefghijklmnopqrstuvwxyz/한글설정파일-1234567890"
	rendered := ansi.Strip(detailValueLine("확인한 곳", value, 29, nil))
	lines := strings.Split(rendered, "\n")
	var joined strings.Builder
	for i, line := range lines {
		if ansi.StringWidth(line) > 29 {
			t.Fatalf("wrapped line exceeds width: %q", line)
		}
		if i == 0 {
			line = strings.TrimPrefix(line, "확인한 곳")
		}
		joined.WriteString(strings.TrimSpace(line))
	}
	if joined.String() != value {
		t.Fatalf("wrapping changed the value: %q", rendered)
	}
}

func TestDetailDoesNotRepeatTheSameCriterion(t *testing.T) {
	result := model.CheckResult{
		Expected: "소유자 root, 권한 0640 이하",
		DisplayDetails: []model.ResultDetail{
			{Label: "첫 파일 권한", Current: "0644", Expected: "소유자 root, 권한 0640 이하"},
			{Label: "둘째 파일 권한", Current: "0600", Expected: "소유자 root, 권한 0640 이하"},
		},
	}
	content := ansi.Strip(detailContent(result, 80))
	if count := strings.Count(content, result.Expected); count != 1 {
		t.Fatalf("same criterion appears %d times: %q", count, content)
	}
}
