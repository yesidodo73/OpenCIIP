package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/yesidodo73/OpenCIIP/internal/engine"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
	"github.com/yesidodo73/OpenCIIP/internal/report"
)

const (
	optionProfiles = iota
	optionChecks
	optionEvidence
	optionReportDir
	optionShowAll
	optionRedaction
	optionRemediation
	optionCount
)

type scanSettings struct {
	profiles           string
	checks             string
	categories         string
	severities         string
	evidence           string
	reportDir          string
	showAll            bool
	noRedact           bool
	remediationEnabled bool
}

type optionChoice struct {
	value string
	label string
}

type optionPickerState struct {
	option   int
	index    int
	choices  []optionChoice
	selected map[string]bool
}

func defaultScanSettings() scanSettings {
	return scanSettings{
		profiles:  "all",
		evidence:  "problems",
		reportDir: report.DefaultDirectory(),
	}
}

func (settings scanSettings) engineOptions() (engine.Options, error) {
	if strings.TrimSpace(settings.reportDir) == "" {
		return engine.Options{}, fmt.Errorf("보고서 경로를 입력하세요")
	}
	if !filepath.IsAbs(settings.reportDir) {
		return engine.Options{}, fmt.Errorf("보고서 경로는 절대경로로 입력하세요: %s", settings.reportDir)
	}
	if settings.evidence != "problems" && settings.evidence != "all" && settings.evidence != "none" {
		return engine.Options{}, fmt.Errorf("증적 저장 범위가 올바르지 않습니다: %s", settings.evidence)
	}

	selection := model.Selection{
		Profiles: splitOptionValues(settings.profiles),
		RuleIDs:  splitOptionValues(strings.ToUpper(settings.checks)),
	}
	for _, value := range splitOptionValues(settings.categories) {
		category := model.Category(strings.ReplaceAll(strings.ToLower(value), "-", "_"))
		if !category.Valid() {
			return engine.Options{}, fmt.Errorf("지원하지 않는 점검 분류입니다: %s", value)
		}
		selection.Categories = append(selection.Categories, category)
	}
	for _, value := range splitOptionValues(settings.severities) {
		severity := model.Severity(strings.ToLower(value))
		if !severity.Valid() {
			return engine.Options{}, fmt.Errorf("지원하지 않는 중요도입니다: %s", value)
		}
		selection.Severities = append(selection.Severities, severity)
	}

	return engine.Options{
		Selection:    selection,
		EvidenceMode: settings.evidence,
		NoRedact:     settings.noRedact,
	}, nil
}

func splitOptionValues(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		values = append(values, part)
	}
	return values
}

func (settings scanSettings) scopeLabel() string {
	parts := make([]string, 0, 4)
	profiles := splitOptionValues(settings.profiles)
	checks := splitOptionValues(settings.checks)
	categories := splitOptionValues(settings.categories)
	severities := splitOptionValues(settings.severities)
	if len(profiles) == 1 && profiles[0] == "all" && len(checks) == 0 && len(categories) == 0 && len(severities) == 0 {
		return "전체 항목"
	}
	if len(profiles) > 0 {
		parts = append(parts, fmt.Sprintf("프로필 %d개", len(profiles)))
	}
	if len(checks) > 0 {
		parts = append(parts, fmt.Sprintf("항목 %d개", len(checks)))
	}
	if len(categories) > 0 {
		parts = append(parts, fmt.Sprintf("분류 %d개", len(categories)))
	}
	if len(severities) > 0 {
		parts = append(parts, fmt.Sprintf("중요도 %d개", len(severities)))
	}
	if len(parts) == 0 {
		return "전체 항목"
	}
	return strings.Join(parts, " · ")
}

func (m *Model) updateOptions(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.optionIndex = (m.optionIndex + optionCount - 1) % optionCount
	case "down", "j":
		m.optionIndex = (m.optionIndex + 1) % optionCount
	case "enter":
		if selectableOption(m.optionIndex) {
			m.openOptionPicker(m.optionIndex)
		} else if editableOption(m.optionIndex) {
			m.editingOption = true
			m.optionInput.SetValue(m.rawOptionValue(m.optionIndex))
			m.optionInput.CursorEnd()
			m.optionInput.SetWidth(m.optionContentWidth() - 6)
			m.optionInput.Focus()
			m.optionErr = nil
		} else {
			m.changeOption(1)
		}
	case "left", "h":
		m.changeOption(-1)
	case "right", "l", "space":
		m.changeOption(1)
	case "r":
		m.scanSettings = defaultScanSettings()
		m.optionErr = nil
	case "s":
		if _, err := m.scanSettings.engineOptions(); err != nil {
			m.optionErr = err
			return m, nil
		}
		m.optionErr = nil
		return m, m.startScan()
	case "esc", "backspace":
		m.optionErr = nil
		m.screen = screenReady
	}
	return m, nil
}

func (m *Model) updateOptionEditor(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch message.String() {
	case "enter":
		m.setRawOptionValue(m.optionIndex, strings.TrimSpace(m.optionInput.Value()))
		m.editingOption = false
		m.optionInput.Blur()
		m.optionInput.SetValue("")
		_, m.optionErr = m.scanSettings.engineOptions()
		return m, nil
	case "esc":
		m.editingOption = false
		m.optionInput.Blur()
		m.optionInput.SetValue("")
		return m, nil
	case "ctrl+u":
		m.optionInput.SetValue("")
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	}
	updated, command := m.optionInput.Update(message)
	m.optionInput = updated
	return m, command
}

func (m *Model) changeOption(direction int) {
	m.optionErr = nil
	if m.optionIndex == optionReportDir {
		m.scanSettings.reportDir = cycleStringValue(m.scanSettings.reportDir, reportPathPresets(), direction)
		return
	}
	if m.optionIndex == optionRemediation {
		if m.remediationOptionAvailable() {
			m.scanSettings.remediationEnabled = !m.scanSettings.remediationEnabled
		}
		return
	}
	choices := quickChoicesForOption(m.optionIndex)
	if len(choices) == 0 {
		return
	}
	values := make([]string, 0, len(choices))
	for _, choice := range choices {
		values = append(values, choice.value)
	}
	current := m.rawOptionValue(m.optionIndex)
	if m.optionIndex == optionChecks && current == "" && m.scanSettings.profiles == "all" {
		current = "all"
	}
	if len(splitOptionValues(current)) > 1 {
		current = values[0]
	}
	next := cycleStringValue(current, values, direction)
	if m.optionIndex == optionRedaction && next == "unredacted" && !m.scanSettings.noRedact {
		m.screen = screenConfirmNoRedact
		return
	}
	m.setRawOptionValue(m.optionIndex, next)
}

func quickChoicesForOption(option int) []optionChoice {
	choices := choicesForOption(option)
	return choices
}

func cycleStringValue(current string, values []string, direction int) string {
	if len(values) == 0 {
		return current
	}
	index := 0
	for candidate, value := range values {
		if value == current {
			index = candidate
			break
		}
	}
	index = (index + direction + len(values)) % len(values)
	return values[index]
}

func reportPathPresets() []string {
	values := []string{report.DefaultDirectory()}
	if runtime.GOOS == "linux" {
		values = append(values, "/var/lib/openciip/reports")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		values = append(values, filepath.Join(home, ".local", "share", "openciip", "reports"))
	}
	unique := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = filepath.Clean(value)
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func editableOption(index int) bool {
	return index == optionReportDir
}

func selectableOption(index int) bool {
	return (index >= optionProfiles && index <= optionEvidence) || index == optionShowAll || index == optionRedaction
}

func (m *Model) rawOptionValue(index int) string {
	switch index {
	case optionProfiles:
		return m.scanSettings.profiles
	case optionChecks:
		return m.scanSettings.checks
	case optionEvidence:
		return m.scanSettings.evidence
	case optionReportDir:
		return m.scanSettings.reportDir
	case optionShowAll:
		if m.scanSettings.showAll {
			return "all"
		}
		return "problems"
	case optionRedaction:
		if m.scanSettings.noRedact {
			return "unredacted"
		}
		return "redacted"
	case optionRemediation:
		if m.scanSettings.remediationEnabled {
			return "enabled"
		}
		return "disabled"
	default:
		return ""
	}
}

func (m *Model) setRawOptionValue(index int, value string) {
	switch index {
	case optionProfiles:
		m.scanSettings.profiles = value
		if value == "all" {
			m.scanSettings.checks = ""
		}
	case optionChecks:
		if value == "all" {
			m.scanSettings.checks = ""
			m.scanSettings.profiles = "all"
			return
		}
		m.scanSettings.checks = value
		if value != "" && strings.TrimSpace(m.scanSettings.profiles) == "all" {
			m.scanSettings.profiles = ""
		}
	case optionEvidence:
		m.scanSettings.evidence = value
	case optionReportDir:
		m.scanSettings.reportDir = value
	case optionShowAll:
		m.scanSettings.showAll = value == "all"
	case optionRedaction:
		m.scanSettings.noRedact = value == "unredacted"
		if m.scanSettings.noRedact {
			m.scanSettings.remediationEnabled = false
		}
	case optionRemediation:
		m.scanSettings.remediationEnabled = value == "enabled" && m.remediationOptionAvailable()
	}
}

func (m *Model) openOptionPicker(option int) {
	choices := choicesForOption(option)
	selected := make(map[string]bool, len(choices))
	for _, value := range splitOptionValues(m.rawOptionValue(option)) {
		selected[value] = true
	}
	if option == optionChecks && m.scanSettings.checks == "" && m.scanSettings.profiles == "all" {
		selected["all"] = true
	}
	m.optionPicker = optionPickerState{
		option:   option,
		choices:  choices,
		selected: selected,
	}
	m.screen = screenOptionPicker
}

func choicesForOption(option int) []optionChoice {
	switch option {
	case optionProfiles:
		return []optionChoice{
			{value: "all", label: "전체"},
			{value: "account", label: "계정 관리"},
			{value: "file-directory", label: "파일 및 디렉터리 관리"},
			{value: "service", label: "서비스 관리"},
			{value: "patch", label: "패치 관리"},
			{value: "logging", label: "로그 관리"},
		}
	case optionChecks:
		choices := make([]optionChoice, 0, 68)
		choices = append(choices, optionChoice{value: "all", label: "전체"})
		for number := 1; number <= 67; number++ {
			value := fmt.Sprintf("U-%02d", number)
			choices = append(choices, optionChoice{value: value, label: value})
		}
		return choices
	case optionEvidence:
		return []optionChoice{
			{value: "problems", label: "문제 항목"},
			{value: "all", label: "전체 항목"},
			{value: "none", label: "저장 안 함"},
		}
	case optionShowAll:
		return []optionChoice{
			{value: "problems", label: "문제 항목만"},
			{value: "all", label: "전체 항목"},
		}
	case optionRedaction:
		return []optionChoice{
			{value: "redacted", label: "마스킹"},
			{value: "unredacted", label: "마스킹 해제"},
		}
	default:
		return nil
	}
}

func (m *Model) updateOptionPicker(key string) (tea.Model, tea.Cmd) {
	choices := m.optionPicker.choices
	if len(choices) == 0 {
		m.screen = screenOptions
		return m, nil
	}
	switch key {
	case "up", "k":
		m.optionPicker.index = (m.optionPicker.index + len(choices) - 1) % len(choices)
	case "down", "j":
		m.optionPicker.index = (m.optionPicker.index + 1) % len(choices)
	case "pgup":
		m.optionPicker.index -= 10
		if m.optionPicker.index < 0 {
			m.optionPicker.index = 0
		}
	case "pgdown":
		m.optionPicker.index += 10
		if m.optionPicker.index >= len(choices) {
			m.optionPicker.index = len(choices) - 1
		}
	case "space":
		m.togglePickerChoice(choices[m.optionPicker.index].value)
	case "enter":
		if m.applyOptionPicker() {
			m.screen = screenOptions
		}
	case "esc", "backspace":
		m.screen = screenOptions
	}
	return m, nil
}

func (m *Model) togglePickerChoice(value string) {
	selected := m.optionPicker.selected
	if selected == nil {
		selected = make(map[string]bool)
		m.optionPicker.selected = selected
	}
	if !multiSelectOption(m.optionPicker.option) {
		clear(selected)
		selected[value] = true
		return
	}
	if m.optionPicker.option == optionProfiles || m.optionPicker.option == optionChecks {
		if value == "all" {
			clear(selected)
			selected[value] = true
			return
		}
		delete(selected, "all")
	}
	if selected[value] {
		delete(selected, value)
	} else {
		selected[value] = true
	}
}

func multiSelectOption(option int) bool {
	return option == optionProfiles || option == optionChecks
}

func (m *Model) applyOptionPicker() bool {
	values := make([]string, 0, len(m.optionPicker.selected))
	for _, choice := range m.optionPicker.choices {
		if m.optionPicker.selected[choice.value] {
			values = append(values, choice.value)
		}
	}
	value := strings.Join(values, ",")
	if m.optionPicker.option == optionRedaction && value == "unredacted" && !m.scanSettings.noRedact {
		m.screen = screenConfirmNoRedact
		return false
	}
	m.setRawOptionValue(m.optionPicker.option, value)
	m.optionErr = nil
	return true
}

func (m *Model) optionPickerView() string {
	state := m.optionPicker
	titles := map[int]string{
		optionProfiles:  "점검 범위 선택",
		optionChecks:    "점검 선택",
		optionEvidence:  "증적 저장 선택",
		optionShowAll:   "결과 표시 선택",
		optionRedaction: "민감정보 마스킹 선택",
	}
	selectedCount := 0
	for _, selected := range state.selected {
		if selected {
			selectedCount++
		}
	}
	contentWidth := m.optionContentWidth()
	var builder strings.Builder
	builder.WriteString(screenHeader(titles[state.option]))
	builder.WriteString("\n")
	builder.WriteString(helpStyle.Render(fmt.Sprintf("선택 %d개  ·  %d / %d", selectedCount, state.index+1, len(state.choices))))
	builder.WriteString("\n\n")
	builder.WriteString(optionSectionDivider("선택 항목", contentWidth))
	builder.WriteByte('\n')

	visible := m.height - 17
	if visible < 6 {
		visible = 6
	}
	if visible > 18 {
		visible = 18
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
	if start > 0 {
		builder.WriteString(helpStyle.Render(fmt.Sprintf("  ↑ 이전 %d개", start)))
		builder.WriteByte('\n')
	}
	for index := start; index < end; index++ {
		choice := state.choices[index]
		marker := "  "
		style := lipgloss.NewStyle().Foreground(textColor)
		if index == state.index {
			marker = accentStyle.Render("› ")
			style = keyStyle
		}
		checkbox := "[ ]"
		if state.selected[choice.value] {
			checkbox = successStyle.Render("[✓]")
		}
		row := marker + checkbox + "  " + style.Render(presentation.Sanitize(choice.label))
		if index == state.index {
			row = selectedRowStyle.Copy().Width(contentWidth).Render(row)
		}
		builder.WriteString(row)
		builder.WriteByte('\n')
	}
	if end < len(state.choices) {
		builder.WriteString(helpStyle.Render(fmt.Sprintf("  ↓ 다음 %d개", len(state.choices)-end)))
		builder.WriteByte('\n')
	}
	builder.WriteString("\n")
	builder.WriteString(optionSectionDivider("조작", contentWidth))
	builder.WriteString("\n")
	builder.WriteString(optionKeyLegend("↑↓", "이동", "Space", "선택", "Enter", "적용", "Esc", "취소"))
	return m.centerOptionContent(builder.String(), contentWidth)
}

func (m *Model) optionsView() string {
	sections := []struct {
		title string
		rows  []int
	}{
		{title: "점검", rows: []int{optionProfiles, optionChecks}},
		{title: "출력", rows: []int{optionEvidence, optionReportDir, optionShowAll}},
		{title: "보안", rows: []int{optionRedaction}},
		{title: "조치", rows: []int{optionRemediation}},
	}
	labels := map[int]string{
		optionProfiles:    "점검 범위",
		optionChecks:      "점검",
		optionEvidence:    "증적 저장",
		optionReportDir:   "보고서 경로",
		optionShowAll:     "결과 표시",
		optionRedaction:   "민감정보",
		optionRemediation: "자동 조치",
	}
	contentWidth := m.optionContentWidth()
	var builder strings.Builder
	builder.WriteString(screenHeader("실행 옵션"))
	builder.WriteString("\n")
	builder.WriteString(helpStyle.Render("점검 범위와 결과 저장 방식을 설정합니다."))
	builder.WriteString("\n\n")
	for sectionIndex, section := range sections {
		if sectionIndex > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(optionSectionDivider(section.title, contentWidth))
		builder.WriteByte('\n')
		for _, index := range section.rows {
			builder.WriteString(m.optionRow(index, labels[index], contentWidth))
			builder.WriteByte('\n')
		}
	}

	if m.editingOption {
		builder.WriteString("\n")
		builder.WriteString(optionSectionDivider("경로 입력", contentWidth))
		builder.WriteString("\n")
		builder.WriteString(selectedRowStyle.Copy().Width(contentWidth).Render(accentStyle.Render("› ") + sanitizedTextInputView(m.optionInput)))
		builder.WriteString("\n\n")
		builder.WriteString(optionKeyLegend("Enter", "저장", "Esc", "취소", "Ctrl+U", "지우기"))
	} else {
		builder.WriteString("\n")
		builder.WriteString(optionSectionDivider("설명", contentWidth))
		builder.WriteString("\n")
		builder.WriteString(helpStyle.Render(presentation.Sanitize(m.optionHint(m.optionIndex))))
		if m.optionErr != nil {
			builder.WriteString("\n")
			builder.WriteString(errorStyle.Render("! " + presentation.Sanitize(m.optionErr.Error())))
		}
		builder.WriteString("\n\n")
		builder.WriteString(optionKeyLegend("↑↓", "이동", "←→", "변경", "Enter", "상세", "S", "점검", "R", "기본값", "Esc", "뒤로"))
	}
	return m.centerOptionContent(builder.String(), contentWidth)
}

func (m *Model) optionRow(index int, label string, contentWidth int) string {
	label = presentation.Sanitize(label)
	labelWidth := 14
	if contentWidth < 58 {
		labelWidth = 11
	}
	valueWidth := contentWidth - labelWidth - 4
	if valueWidth < 16 {
		valueWidth = 16
	}
	selected := index == m.optionIndex
	marker := "  "
	labelStyleForRow := labelStyle
	if selected {
		marker = accentStyle.Render("› ")
		labelStyleForRow = keyStyle
	}
	value := m.displayOptionValue(index, valueWidth-4)
	valueCell := "  " + value + "  "
	if selected && index != optionReportDir && m.optionHasControls(index) {
		valueCell = accentStyle.Render("<") + " " + value + " " + accentStyle.Render(">")
	}
	row := marker + labelStyleForRow.Copy().Width(labelWidth).Render(label) + "  " +
		lipgloss.NewStyle().Width(valueWidth).MaxWidth(valueWidth).Render(valueCell)
	if selected {
		return selectedRowStyle.Copy().Width(contentWidth).Render(row)
	}
	return lipgloss.NewStyle().Width(contentWidth).Render(row)
}

func (m *Model) optionContentWidth() int {
	width := m.width - 8
	if m.width <= 0 {
		width = 76
	}
	if width > 82 {
		width = 82
	}
	if width < 46 {
		width = 46
	}
	return width
}

func (m *Model) centerOptionContent(content string, contentWidth int) string {
	available := m.width - 4
	if available < contentWidth {
		available = contentWidth
	}
	fixedWidth := lipgloss.NewStyle().Width(contentWidth).MaxWidth(contentWidth).Render(content)
	availableHeight := m.height - 4
	if availableHeight < lipgloss.Height(fixedWidth) {
		availableHeight = lipgloss.Height(fixedWidth)
	}
	return lipgloss.Place(available, availableHeight, lipgloss.Center, lipgloss.Center, fixedWidth)
}

func (m *Model) optionHasControls(index int) bool {
	if index == optionRemediation {
		return m.remediationOptionAvailable()
	}
	return true
}

func (m *Model) remediationOptionAvailable() bool {
	return m.platform.RemediationSupport == model.RemediationSupportVerified &&
		m.platform.Privilege == "root" && !m.scanSettings.noRedact
}

func optionSectionDivider(title string, width int) string {
	title = presentation.Sanitize(title)
	lineWidth := width - lipgloss.Width(title) - 2
	if lineWidth < 1 {
		lineWidth = 1
	}
	return sectionStyle.Render(title) + "  " + statusRuleStyle.Render(strings.Repeat("─", lineWidth))
}

func optionKeyLegend(values ...string) string {
	parts := make([]string, 0, len(values)/2)
	for index := 0; index+1 < len(values); index += 2 {
		parts = append(
			parts,
			keyCapStyle.Render(presentation.Sanitize(values[index]))+" "+
				helpStyle.Render(presentation.Sanitize(values[index+1])),
		)
	}
	return strings.Join(parts, "   ")
}

func (m *Model) displayOptionValue(index int, maxValueWidth int) string {
	switch index {
	case optionProfiles:
		if strings.TrimSpace(m.scanSettings.profiles) == "" {
			if strings.TrimSpace(m.scanSettings.checks) == "" {
				return helpStyle.Render("전체 (기본값)")
			}
			return helpStyle.Render("선택 안 함")
		}
		return accentStyle.Render(selectedOptionLabel(optionProfiles, m.scanSettings.profiles))
	case optionChecks:
		if strings.TrimSpace(m.scanSettings.checks) == "" {
			if strings.TrimSpace(m.scanSettings.profiles) == "all" {
				return accentStyle.Render("전체")
			}
			return helpStyle.Render("선택 안 함")
		}
		return accentStyle.Render(selectedOptionLabel(optionChecks, m.scanSettings.checks))
	case optionEvidence:
		labels := map[string]string{"problems": "문제 항목", "all": "전체 항목", "none": "저장 안 함"}
		return accentStyle.Render(labels[m.scanSettings.evidence])
	case optionReportDir:
		return accentStyle.Render(truncateStart(m.scanSettings.reportDir, maxValueWidth))
	case optionShowAll:
		if m.scanSettings.showAll {
			return accentStyle.Render("전체 항목")
		}
		return helpStyle.Render("문제 항목만")
	case optionRedaction:
		if m.scanSettings.noRedact {
			return warningStyle.Render("마스킹 해제")
		}
		return successStyle.Render("마스킹")
	case optionRemediation:
		if m.platform.RemediationSupport != model.RemediationSupportVerified {
			return disabledStyle.Render("지원되지 않음")
		}
		if m.platform.Privilege != "root" {
			return disabledStyle.Render("root 권한 필요")
		}
		if m.scanSettings.noRedact {
			return disabledStyle.Render("마스킹 필요")
		}
		if m.scanSettings.remediationEnabled {
			return successStyle.Render("사용")
		}
		return helpStyle.Render("사용 안 함")
	default:
		return ""
	}
}

func sanitizedTextInputView(input textinput.Model) string {
	value := input.Value()
	sanitized := presentation.Sanitize(value)
	if sanitized == value {
		return input.View()
	}

	characters := []rune(value)
	position := input.Position()
	if position < 0 {
		position = 0
	}
	if position > len(characters) {
		position = len(characters)
	}
	sanitizedPosition := len([]rune(presentation.Sanitize(string(characters[:position]))))
	input.SetValue(sanitized)
	input.SetCursor(sanitizedPosition)
	return input.View()
}

func truncateStart(value string, maxWidth int) string {
	value = presentation.Sanitize(value)
	if maxWidth <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= maxWidth {
		return value
	}
	if maxWidth <= 3 {
		return strings.Repeat(".", maxWidth)
	}

	return "..." + widthSuffix(value, maxWidth-3)
}

func widthSuffix(value string, maxWidth int) string {
	characters := []rune(value)
	start := len(characters)
	width := 0
	for start > 0 {
		characterWidth := lipgloss.Width(string(characters[start-1]))
		if width+characterWidth > maxWidth {
			break
		}
		start--
		width += characterWidth
	}
	return string(characters[start:])
}

func selectedOptionLabel(option int, raw string) string {
	selected := splitOptionValues(raw)
	labelsByValue := make(map[string]string)
	for _, choice := range choicesForOption(option) {
		labelsByValue[choice.value] = choice.label
	}
	labels := make([]string, 0, len(selected))
	for _, value := range selected {
		label := labelsByValue[value]
		if label == "" {
			label = value
		}
		labels = append(labels, label)
	}
	if len(labels) > 3 {
		return presentation.Sanitize(fmt.Sprintf("%s 외 %d개", strings.Join(labels[:2], ", "), len(labels)-2))
	}
	return presentation.Sanitize(strings.Join(labels, ", "))
}

func (m *Model) optionHint(index int) string {
	switch index {
	case optionProfiles:
		return "계정, 파일 및 디렉터리, 서비스 등 점검할 관리 영역을 선택합니다."
	case optionChecks:
		return "실행할 점검 항목을 직접 지정합니다. 전체를 선택하면 개별 항목 선택을 해제합니다."
	case optionEvidence:
		return "보고서에 별도 증적 파일을 저장할 판정 범위를 정합니다."
	case optionReportDir:
		return "점검 결과와 항목별 증적을 저장할 디렉터리입니다."
	case optionShowAll:
		return "점검 완료 후 문제 항목만 볼지 모든 판정 결과를 볼지 정합니다."
	case optionRedaction:
		return "보고서에 기록되는 비밀번호, 토큰 등 민감정보를 가립니다."
	case optionRemediation:
		if m.platform.RemediationSupport != model.RemediationSupportVerified {
			return "현재 OS와 버전에서 자동 조치가 지원되지 않습니다."
		}
		if m.platform.Privilege != "root" {
			return "자동 조치를 사용하려면 root 권한으로 실행해야 합니다."
		}
		if m.scanSettings.noRedact {
			return "자동 조치에는 민감정보가 마스킹된 점검 보고서가 필요합니다."
		}
		return "점검 후 조치 가능한 취약 항목의 변경 계획을 확인할 수 있습니다. 실제 변경 전에는 별도 승인이 필요합니다."
	default:
		return ""
	}
}

func (m *Model) confirmNoRedactView() string {
	contentWidth := m.optionContentWidth()
	content := screenHeader("민감정보 마스킹 해제") + "\n\n" +
		errorPanelStyle.Copy().Width(contentWidth-4).Render(
			warningStyle.Render("보고서에 민감정보가 포함될 수 있습니다.")+"\n\n"+
				"비밀번호 해시, 토큰, community string, 설정 원문 등이 마스킹되지 않을 수 있습니다.\n"+
				"안전한 저장 경로와 접근 권한을 확인하세요.",
		) + "\n\n" + optionKeyLegend("Y", "마스킹 해제", "N", "유지", "Esc", "뒤로")
	return m.centerOptionContent(content, contentWidth)
}
