package tui

import (
	"bytes"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
)

// framedPanel keeps panel borders, padding and Korean character widths aligned.
func framedPanel(title, content string, width, height int) string {
	if width < 8 {
		width = 8
	}
	if height < 2 {
		height = 2
	}
	innerWidth := width - 4
	title = ansi.Truncate(presentation.Sanitize(title), width-6, "…")
	remaining := width - lipgloss.Width(title) - 5
	top := statusRuleStyle.Render("╭─ ") + keyStyle.Render(title) + statusRuleStyle.Render(" "+strings.Repeat("─", remaining)+"╮")
	bottom := statusRuleStyle.Render("╰" + strings.Repeat("─", width-2) + "╯")
	lines := strings.Split(content, "\n")
	output := make([]string, 0, height)
	output = append(output, top)
	for index := 0; index < height-2; index++ {
		line := ""
		if index < len(lines) {
			line = ansi.Truncate(lines[index], innerWidth, "…")
		}
		padding := innerWidth - lipgloss.Width(line)
		if padding < 0 {
			padding = 0
		}
		output = append(output, statusRuleStyle.Render("│")+" "+line+strings.Repeat(" ", padding)+" "+statusRuleStyle.Render("│"))
	}
	output = append(output, bottom)
	return strings.Join(output, "\n")
}

func contentWidth(width int) int {
	width -= 4
	if width < 40 {
		return 40
	}
	return width
}

func headerWithRule(section string, width int) string {
	return screenHeader(section) + "\n" + statusRuleStyle.Render(strings.Repeat("─", width))
}

const scrollContinuationMarker = "..."

func scrollMarker(width int) string {
	marker := scrollContinuationMarker
	padding := (width - lipgloss.Width(marker)) / 2
	if padding < 0 {
		padding = 0
	}
	return strings.Repeat(" ", padding) + helpStyle.Render(marker)
}

func (m *Model) optionsDashboardView() string {
	width := contentWidth(m.width)
	header := headerWithRule("실행 옵션", width)
	split := width >= 114 && m.height >= 24
	help := optionsKeyLegend(width, m.editingOption)
	footer := help
	if !split && !m.editingOption {
		hint := labelStyle.Render("설명") + "  " + wrapDetailText(m.optionHint(m.optionIndex), width-8)
		if m.optionErr != nil {
			hint += "\n" + errorStyle.Render(wrapDetailText(m.optionErr.Error(), width))
		}
		footer = hint + "\n" + help
	}
	panelHeight := m.height - 2 - lipgloss.Height(header) - lipgloss.Height(footer)
	leftWidth := width
	if split {
		leftWidth = width * 60 / 100
	}
	innerLeft := leftWidth - 4
	var rows strings.Builder
	if m.editingOption && !split {
		m.optionInput.SetWidth(innerLeft - 4)
		rows.WriteString(labelStyle.Render("보고서 경로") + "\n\n")
		rows.WriteString(accentStyle.Render("│ ") + sanitizedTextInputView(m.optionInput))
	} else {
		for sectionIndex, section := range optionSections {
			if sectionIndex > 0 && panelHeight >= 18 {
				rows.WriteByte('\n')
			}
			rows.WriteString(optionSectionDivider(section.title, innerLeft))
			rows.WriteByte('\n')
			for _, index := range section.rows {
				rows.WriteString(m.optionRow(index, optionLabels[index], innerLeft))
				rows.WriteByte('\n')
			}
		}
		if m.editingOption {
			m.optionInput.SetWidth(innerLeft - 4)
			rows.WriteString("\n" + labelStyle.Render("경로 입력") + "\n")
			rows.WriteString(accentStyle.Render("│ ") + sanitizedTextInputView(m.optionInput))
		}
	}
	left := framedPanel("설정", strings.TrimSuffix(rows.String(), "\n"), leftWidth, panelHeight)
	if !split {
		return strings.Join([]string{header, left, footer}, "\n")
	}
	rightWidth := width - leftWidth - 1
	previewWidth := rightWidth - 4
	preview := []string{
		keyStyle.Render(optionLabels[m.optionIndex]),
		m.displayOptionValue(m.optionIndex, previewWidth),
		"",
		statusRuleStyle.Render(strings.Repeat("─", previewWidth)),
		"",
		labelStyle.Render("설명"),
		wrapDetailText(m.optionHint(m.optionIndex), previewWidth),
	}
	if m.optionErr != nil {
		preview = append(preview, "", errorStyle.Render(wrapDetailText(m.optionErr.Error(), previewWidth)))
	}
	right := framedPanel("선택한 옵션", strings.Join(preview, "\n"), rightWidth, panelHeight)
	return strings.Join([]string{header, lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right), help}, "\n")
}

func (m *Model) optionPickerDashboardView() string {
	width := contentWidth(m.width)
	state := m.optionPicker
	titles := map[int]string{
		optionProfiles: "점검 범위 선택", optionChecks: "점검 선택",
		optionEvidence: "증적 저장 선택", optionShowAll: "결과 표시 선택",
		optionRedaction: "민감정보 마스킹 선택",
	}
	selectedCount := 0
	for _, selected := range state.selected {
		if selected {
			selectedCount++
		}
	}
	position := state.index + 1
	if len(state.choices) == 0 {
		position = 0
	}
	header := headerWithRule(titles[state.option], width)
	summary := helpStyle.Render(fmt.Sprintf("선택 %d개  ·  %d / %d", selectedCount, position, len(state.choices)))
	help := pickerKeyLegend(width, state.option)
	panelHeight := m.height - 2 - lipgloss.Height(header) - lipgloss.Height(summary) - lipgloss.Height(help)
	innerWidth := width - 4
	visible := panelHeight - 4 // Reserve one line for each scroll indicator.
	if visible < 1 {
		visible = 1
	}
	start := state.index - visible/2
	if start < 0 {
		start = 0
	}
	if start+visible > len(state.choices) {
		start = len(state.choices) - visible
		if start < 0 {
			start = 0
		}
	}
	end := start + visible
	if end > len(state.choices) {
		end = len(state.choices)
	}
	var rows []string
	if start > 0 {
		rows = append(rows, helpStyle.Render(fmt.Sprintf("  ↑ 이전 %d개", start)))
	} else {
		rows = append(rows, "")
	}
	for index := start; index < end; index++ {
		choice := state.choices[index]
		selected := index == state.index
		marker := "  "
		labelStyle := lipgloss.NewStyle().Foreground(textColor)
		checkbox := "[ ]"
		space := "  "
		if selected {
			marker = accentStyle.Copy().Background(selectedColor).Render("│ ")
			labelStyle = keyStyle.Copy().Background(selectedColor)
			checkbox = selectedRowStyle.Render(checkbox)
			space = selectedRowStyle.Render(space)
		}
		if state.selected[choice.value] {
			style := successStyle
			if selected {
				style = style.Background(selectedColor)
			}
			checkbox = style.Render("[✓]")
		}
		label := ansi.Truncate(presentation.Sanitize(choice.label), innerWidth-7, "…")
		row := marker + checkbox + space + labelStyle.Render(label)
		if selected {
			row = fillSelectedRow(row, innerWidth)
		}
		rows = append(rows, row)
	}
	if end < len(state.choices) {
		rows = append(rows, helpStyle.Render(fmt.Sprintf("  ↓ 다음 %d개", len(state.choices)-end)))
	}
	return strings.Join([]string{header, summary, framedPanel("선택 항목", strings.Join(rows, "\n"), width, panelHeight), help}, "\n")
}

func (m *Model) resultsView() string {
	width := contentWidth(m.width)
	header := "문제 항목"
	if m.showAll {
		header = "전체 항목"
	}
	m.list.Title = header

	helpValues := []string{"↑↓", "항목 이동"}
	if width < 114 {
		helpValues = append(helpValues, "Enter", "선택 항목 상세 확인")
	}
	toggleLabel := "전체 항목 보기"
	if m.showAll {
		toggleLabel = "문제 항목만 보기"
	}
	helpValues = append(helpValues, "A", toggleLabel, "/", "항목 검색", "R", "다시 점검")
	if m.list.SettingFilter() {
		helpValues = []string{"Enter", "검색 적용", "Ctrl+G", "검색 취소"}
	}
	availability := m.remediationAvailability()
	if availability.enabled && !m.list.SettingFilter() {
		helpValues = append(helpValues, "M", "조치 계획")
	}
	if !m.list.SettingFilter() {
		helpValues = append(helpValues, "Q", "시작 화면으로")
	}
	helpValues = append(helpValues, "Esc", "종료 확인")

	summary := resultSummaryWidth(m.run.Metadata.Counts, width)
	footer := make([]string, 0, 3)
	if m.reportPath != "" {
		pathWidth := width - lipgloss.Width("보고서  ")
		footer = append(footer, labelStyle.Render("보고서")+"  "+helpStyle.Render(truncateStart(m.reportPath, pathWidth)))
	}
	footer = append(footer, ansi.Wrap(remediationAvailabilityView(availability), width, ""))
	footer = append(footer, optionKeyLegend(width, helpValues...))
	footerText := strings.Join(footer, "\n")
	headerText := headerWithRule("점검 결과", width)
	panelHeight := m.height - 2 - lipgloss.Height(headerText) - lipgloss.Height(summary) - lipgloss.Height(footerText)
	if panelHeight < 7 {
		panelHeight = 7
	}

	leftWidth := width
	if width >= 114 {
		leftWidth = width * 58 / 100
	}
	m.list.SetSize(leftWidth-4, panelHeight-2)
	left := framedPanel(header, m.resultListView(panelHeight-2), leftWidth, panelHeight)
	panels := left
	if leftWidth != width {
		rightWidth := width - leftWidth - 1
		preview := m.resultPreview(rightWidth-4, panelHeight-2)
		right := framedPanel("선택한 항목", preview, rightWidth, panelHeight)
		panels = lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	}
	return strings.Join([]string{headerText, summary, panels, footerText}, "\n")
}

// resultListView uses the list model for filtering and selection, while sizing
// each visible row according to its wrapped title rather than a fixed height.
func (m *Model) resultListView(height int) string {
	if height < 1 {
		return ""
	}
	var prefix []string
	if m.list.SettingFilter() {
		prefix = append(prefix, m.list.FilterInput.View())
	}
	items := m.list.VisibleItems()
	if len(items) == 0 {
		message := "표시할 항목이 없습니다."
		if m.list.FilterValue() != "" {
			message = "일치하는 항목이 없습니다."
		}
		return strings.Join(append(prefix, helpStyle.Render(message)), "\n")
	}
	selected := m.list.Index()
	if selected < 0 || selected >= len(items) {
		selected = 0
	}
	rows := make([][]string, len(items))
	delegate := newResultDelegate(false)
	for index, item := range items {
		var rendered bytes.Buffer
		delegate.Render(&rendered, m.list, index, item)
		rows[index] = strings.Split(rendered.String(), "\n")
	}
	if m.resultListOffset < 0 || m.resultListOffset >= len(rows) || selected < m.resultListOffset {
		m.resultListOffset = selected
	}
	available := 0
	for {
		available = height - len(prefix) - 1 // Keep the bottom line for a continuation marker.
		if m.resultListOffset > 0 {
			available-- // The top marker belongs above the first visible item.
		}
		if available < 1 {
			available = 1
		}
		used := 0
		for index := m.resultListOffset; index <= selected; index++ {
			used += len(rows[index])
		}
		if used <= available || m.resultListOffset >= selected {
			break
		}
		m.resultListOffset++
	}
	visible := append([]string(nil), prefix...)
	if m.resultListOffset > 0 {
		visible = append(visible, scrollMarker(m.list.Width()))
	}
	end := m.resultListOffset
	remaining := available
	for end < len(rows) && remaining > 0 {
		row := rows[end]
		if len(row) > remaining && end != m.resultListOffset {
			break
		}
		if len(row) > remaining {
			row = row[:remaining]
		}
		visible = append(visible, row...)
		remaining -= len(row)
		end++
	}
	for remaining > 0 {
		visible = append(visible, "")
		remaining--
	}
	indicator := ""
	if end < len(rows) {
		indicator = scrollMarker(m.list.Width())
	}
	visible = append(visible, indicator)
	return strings.Join(visible, "\n")
}

func (m *Model) resultPreview(width, height int) string {
	selected, ok := m.list.SelectedItem().(resultItem)
	if !ok {
		m.previewSelection = ""
		m.previewOffset = 0
		m.previewScrollMax = 0
		m.previewLines = nil
		return helpStyle.Render("선택할 수 있는 항목이 없습니다.")
	}
	result := selected.result
	if m.previewSelection != result.RuleID {
		m.previewSelection = result.RuleID
		m.previewOffset = 0
		m.previewLines = nil
	}
	if m.previewLines != nil && m.previewWidth == width {
		return m.previewWithAction(m.previewLines, width, height)
	}
	lines := []string{statusBadge(result.Status) + "  " + codeStyle.Render(presentation.Sanitize(result.RuleID))}
	appendText := func(value string) {
		lines = append(lines, strings.Split(value, "\n")...)
	}
	appendText(detailTitleStyle.Render(wrapDetailText(result.Title, width)))
	appendSummary := func() {
		if strings.TrimSpace(result.Summary) != "" {
			lines = append(lines, "", keyStyle.Render("판정 이유"))
			appendText(wrapDetailText(result.Summary, width))
		}
	}
	details := result.DisplayDetails
	if len(details) == 0 && strings.TrimSpace(result.Observed) != "" {
		details = []model.ResultDetail{{Label: "확인 내용", Current: result.Observed, Expected: result.Expected}}
	}
	if len(details) == 0 {
		appendSummary()
		lines = append(lines, "", helpStyle.Render("표시할 확인 결과가 없습니다."))
	}
	seenCriteria := make(map[string]struct{})
	for index, detail := range details {
		lines = append(lines, "")
		appendText(keyStyle.Render(wrapDetailText(detail.Label, width)))
		if strings.TrimSpace(detail.Current) != "" {
			appendText(detailValueLine("확인 결과", detail.Current, width, nil))
		}
		if strings.TrimSpace(detail.Source) != "" {
			appendText(detailValueLine("확인한 곳", detail.Source, width, nil))
		}
		criterion := strings.TrimSpace(detail.Expected)
		if criterion != "" {
			if _, seen := seenCriteria[criterion]; !seen {
				appendText(detailValueLine("점검 기준", criterion, width, nil))
				seenCriteria[criterion] = struct{}{}
			}
		}
		if index == 0 {
			appendSummary()
		}
	}
	criterion := strings.TrimSpace(result.Expected)
	if criterion != "" {
		if _, seen := seenCriteria[criterion]; !seen {
			lines = append(lines, "", keyStyle.Render("전체 점검 기준"))
			appendText(wrapDetailText(criterion, width))
		}
	}
	if strings.TrimSpace(result.Solution) != "" {
		lines = append(lines, "", keyStyle.Render("조치 방법"))
		appendText(wrapDetailText(result.Solution, width))
	}
	m.previewWidth = width
	m.previewLines = lines
	return m.previewWithAction(lines, width, height)
}

type scrollWindow struct {
	offset, height, maxOffset int
	above, below              bool
}

// scrollWindowFor reserves a line inside the panel only for each visible
// continuation marker, keeping at least one line of content when possible.
func scrollWindowFor(total, offset, capacity int) scrollWindow {
	if capacity < 1 {
		return scrollWindow{}
	}
	if total <= capacity {
		return scrollWindow{height: capacity}
	}
	bottomHeight := capacity
	if bottomHeight > 1 {
		bottomHeight-- // The bottom view needs a marker for content above.
	}
	maxOffset := total - bottomHeight
	if offset < 0 {
		offset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}
	window := scrollWindow{offset: offset, height: capacity, maxOffset: maxOffset}
	if offset > 0 && window.height > 1 {
		window.above = true
		window.height--
	}
	if offset+window.height < total && window.height > 1 {
		window.below = true
		window.height--
	}
	return window
}

func (m *Model) previewWithAction(lines []string, width, height int) string {
	if height < 1 {
		height = 1
	}
	action := optionKeyLegend(width, "Enter", "상세 확인")
	if len(lines) > height-1 {
		action = optionKeyLegend(width, "PgUp/PgDn", "내용 스크롤", "Enter", "상세 확인")
	}
	actionLines := strings.Split(action, "\n")
	if len(actionLines) > height {
		actionLines = actionLines[len(actionLines)-height:]
	}
	window := scrollWindowFor(len(lines), m.previewOffset, height-len(actionLines))
	m.previewOffset = window.offset
	m.previewScrollMax = window.maxOffset
	m.previewPageSize = window.height - 1
	if m.previewPageSize < 1 {
		m.previewPageSize = 1
	}
	end := window.offset + window.height
	if end > len(lines) {
		end = len(lines)
	}
	visible := make([]string, 0, height)
	if window.above {
		visible = append(visible, scrollMarker(width))
	}
	body := append([]string(nil), lines[window.offset:end]...)
	for len(body) < window.height {
		body = append(body, "")
	}
	visible = append(visible, body...)
	if window.below {
		visible = append(visible, scrollMarker(width))
	}
	for len(visible)+len(actionLines) < height {
		visible = append(visible, "")
	}
	return strings.Join(append(visible, actionLines...), "\n")
}

func (m *Model) detailView() string {
	width := contentWidth(m.width)
	header := headerWithRule("항목 상세", width)
	helpValues := []string{"↑↓", "내용 스크롤", "q", "결과 목록으로", "Esc", "종료 확인"}
	help := optionKeyLegend(width, helpValues...)
	panelHeight := m.height - 2 - lipgloss.Height(header) - lipgloss.Height(help)
	if panelHeight < 6 {
		panelHeight = 6
	}
	m.viewport.SetWidth(width - 4)
	window := scrollWindowFor(m.viewport.TotalLineCount(), m.viewport.YOffset(), panelHeight-2)
	m.viewport.SetHeight(window.height)
	m.viewport.SetYOffset(window.offset)
	lines := make([]string, 0, panelHeight-2)
	if window.above {
		lines = append(lines, scrollMarker(width-4))
	}
	lines = append(lines, strings.Split(m.viewport.View(), "\n")...)
	if window.below {
		lines = append(lines, scrollMarker(width-4))
	}
	return fmt.Sprintf("%s\n%s\n%s", header, framedPanel("점검 상세", strings.Join(lines, "\n"), width, panelHeight), help)
}
