package tui

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"io"
	"strings"
	"time"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/yesidodo73/OpenCIIP/internal/buildinfo"
	"github.com/yesidodo73/OpenCIIP/internal/engine"
	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
	"github.com/yesidodo73/OpenCIIP/internal/redact"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/orchestrator"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/recipe"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/workflow"
)

type Scanner interface {
	Scan(context.Context, engine.Options) (model.ScanRun, error)
}

type PlatformProvider interface {
	PlatformInfo() model.PlatformInfo
}

type ScanWriter interface {
	WriteScan(context.Context, model.ScanRun) (string, error)
}

type ScanWriterFactory func(string) (ScanWriter, error)

type Remediator interface {
	PlanFromReport(context.Context, string, workflow.PlanOptions) (workflow.PlanResult, error)
	Approve(context.Context, string, string, string, string) error
	Cancel(context.Context, string) error
	Apply(context.Context, string) error
	Load(context.Context, string) (*model.RemediationJournal, error)
	PreviewRollbackItem(context.Context, string, string) (orchestrator.RollbackPreview, error)
	RollbackItem(context.Context, string, string, bool, string) (model.RollbackAttempt, error)
	PreviewRollbackRun(context.Context, string) (orchestrator.RollbackPreview, error)
	RollbackRun(context.Context, string, string) (model.RollbackAttempt, error)
}

type RemediatorFactory func(context.Context) (Remediator, error)

type remediationCandidateEvaluator func(model.ScanRun, model.PlatformInfo) (verified bool, pending bool, err error)

type screen int

const (
	screenReady screen = iota
	screenOptions
	screenOptionPicker
	screenConfirmNoRedact
	screenScanning
	screenResults
	screenDetail
	screenRemediationFailurePolicy
	screenRemediationPlanning
	screenRemediationPlan
	screenRemediationConfirmApproval
	screenRemediationApproving
	screenRemediationApproved
	screenRemediationConfirmApply
	screenRemediationApplying
	screenRemediationStatus
	screenRemediationConfirmCancel
	screenRemediationCanceling
	screenRemediationRollbackPreviewing
	screenRemediationRollbackPreview
	screenRemediationConfirmRollback
	screenRemediationRollingBack
	screenRemediationError
	screenError
)

type scanCompleteMsg struct {
	run        model.ScanRun
	reportPath string
	err        error
}

type scanProgressMsg struct {
	progress engine.Progress
	source   <-chan engine.Progress
	open     bool
}

type scanTickMsg time.Time

type remediationPlanMsg struct {
	remediator Remediator
	plan       workflow.PlanResult
	err        error
}

type remediationJournalMsg struct {
	journal *model.RemediationJournal
	err     error
}

type remediationRollbackMsg struct {
	attempt model.RollbackAttempt
	journal *model.RemediationJournal
	err     error
}

type remediationRollbackPreviewMsg struct {
	preview     orchestrator.RollbackPreview
	runScope    bool
	changeSetID string
	err         error
}

type resultItem struct {
	result model.CheckResult
}

type remediationAvailability struct {
	enabled bool
	label   string
	reason  string
}

func (i resultItem) Title() string {
	return fmt.Sprintf(
		"%s  %s  %s",
		statusLabel(i.result.Status),
		presentation.Sanitize(i.result.RuleID),
		presentation.Sanitize(i.result.Title),
	)
}

func (i resultItem) Description() string { return presentation.Sanitize(i.result.Summary) }
func (i resultItem) FilterValue() string { return i.Title() }

type Model struct {
	ctx                   context.Context
	scanner               Scanner
	writerFactory         ScanWriterFactory
	remediatorFactory     RemediatorFactory
	remediator            Remediator
	cancelScan            context.CancelFunc
	cancelAction          context.CancelFunc
	screen                screen
	width                 int
	height                int
	showAll               bool
	run                   model.ScanRun
	reportPath            string
	list                  list.Model
	viewport              viewport.Model
	err                   error
	remediationErr        error
	plan                  workflow.PlanResult
	journal               *model.RemediationJournal
	rollback              model.RollbackAttempt
	rollbackPreview       orchestrator.RollbackPreview
	rollbackRunScope      bool
	rollbackChangeSet     string
	failurePolicy         model.FailurePolicy
	cancelReturn          screen
	selectedChangeSet     int
	exitCode              int
	platform              model.PlatformInfo
	scanProgress          engine.Progress
	scanProgressCh        <-chan engine.Progress
	scanStarted           time.Time
	scanTicks             int
	now                   func() time.Time
	scanSettings          scanSettings
	optionIndex           int
	editingOption         bool
	optionInput           textinput.Model
	optionErr             error
	optionPicker          optionPickerState
	readySelection        int
	quitConfirmation      bool
	quitSelection         int
	quitAfterAction       bool
	quitAfterPlanCancel   bool
	scanBackRequested     bool
	remediationCandidates remediationCandidateEvaluator
}

func NewModel(ctx context.Context, scanner Scanner, writer ScanWriter) *Model {
	return NewModelWithRemediation(ctx, scanner, writer, nil)
}

func NewModelWithRemediation(ctx context.Context, scanner Scanner, writer ScanWriter, factory RemediatorFactory) *Model {
	return newModel(ctx, scanner, func(string) (ScanWriter, error) { return writer, nil }, factory)
}

func NewModelWithWriterFactory(ctx context.Context, scanner Scanner, writerFactory ScanWriterFactory, factory RemediatorFactory) *Model {
	return newModel(ctx, scanner, writerFactory, factory)
}

func newModel(ctx context.Context, scanner Scanner, writerFactory ScanWriterFactory, factory RemediatorFactory) *Model {
	delegate := newResultDelegate(true)
	resultList := list.New(nil, delegate, 80, 20)
	resultList.Title = "점검 결과"
	resultList.SetFilteringEnabled(true)
	resultList.SetShowStatusBar(true)
	resultList.SetShowHelp(false)
	resultList.SetStatusBarItemName("항목", "항목")
	resultList.KeyMap.CancelWhileFiltering.SetKeys("ctrl+g")
	resultList.KeyMap.CancelWhileFiltering.SetHelp("ctrl+g", "검색 취소")
	resultList.KeyMap.ClearFilter.SetKeys("ctrl+g")
	resultList.KeyMap.ClearFilter.SetHelp("ctrl+g", "검색 해제")
	detail := viewport.New()
	detail.SoftWrap = true
	pathInput := textinput.New()
	pathInput.Prompt = ""
	pathInput.CharLimit = 4096
	platformInfo := model.PlatformInfo{}
	if provider, ok := scanner.(PlatformProvider); ok {
		platformInfo = provider.PlatformInfo()
	}
	return &Model{
		ctx:                   ctx,
		scanner:               scanner,
		writerFactory:         writerFactory,
		remediatorFactory:     factory,
		screen:                screenReady,
		list:                  resultList,
		viewport:              detail,
		optionInput:           pathInput,
		failurePolicy:         model.FailureRollbackItem,
		exitCode:              exitcode.OK,
		platform:              platformInfo,
		now:                   time.Now,
		scanSettings:          defaultScanSettings(),
		remediationCandidates: builtInRemediationCandidates,
	}
}

type resultDelegate struct {
	list.DefaultDelegate
}

func newResultDelegate(showDescription bool) resultDelegate {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = showDescription
	delegate.SetSpacing(0)
	delegate.Styles.NormalTitle = delegate.Styles.NormalTitle.Foreground(textColor)
	delegate.Styles.NormalDesc = delegate.Styles.NormalDesc.Foreground(mutedColor)
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.BorderForeground(accentColor).Foreground(accentColor)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.BorderForeground(accentColor).Foreground(textColor)
	delegate.Styles.FilterMatch = delegate.Styles.FilterMatch.Foreground(warningColor)
	return resultDelegate{DefaultDelegate: delegate}
}

func (d resultDelegate) Render(writer io.Writer, view list.Model, index int, item list.Item) {
	result, ok := item.(resultItem)
	if !ok || view.Width() <= 0 {
		return
	}
	styles := &d.Styles
	isSelected := index == view.Index()
	emptyFilter := view.FilterState() == list.Filtering && view.FilterValue() == ""
	isFiltered := view.FilterState() == list.Filtering || view.FilterState() == list.FilterApplied

	containerStyle := styles.NormalTitle
	descriptionStyle := styles.NormalDesc
	if emptyFilter {
		containerStyle = styles.DimmedTitle
		descriptionStyle = styles.DimmedDesc
	} else if isSelected && view.FilterState() != list.Filtering {
		containerStyle = styles.SelectedTitle
		descriptionStyle = styles.SelectedDesc
	}
	textWidth := view.Width() - containerStyle.GetPaddingLeft() - containerStyle.GetPaddingRight()
	if textWidth <= 0 {
		return
	}

	title := ansi.Truncate(result.Title(), textWidth, "…")
	matchedRunes := []int(nil)
	if isFiltered {
		matchedRunes = view.MatchesForItem(index)
	}
	baseStyle := containerStyle.Inline(true)
	styledTitle := renderResultTitle(result, title, baseStyle, styles.FilterMatch, matchedRunes, emptyFilter)
	titleContainer := containerStyle.UnsetForeground().UnsetBold()
	title = titleContainer.Render(styledTitle)

	description := ""
	if d.ShowDescription {
		lines := make([]string, 0, d.Height()-1)
		for lineIndex, line := range strings.Split(result.Description(), "\n") {
			if lineIndex >= d.Height()-1 {
				break
			}
			lines = append(lines, ansi.Truncate(line, textWidth, "…"))
		}
		description = descriptionStyle.Render(strings.Join(lines, "\n"))
	}
	if d.ShowDescription {
		_, _ = fmt.Fprintf(writer, "%s\n%s", title, description)
		return
	}
	_, _ = fmt.Fprint(writer, title)
}

func renderResultTitle(item resultItem, title string, baseStyle, filterMatch lipgloss.Style, matchedRunes []int, dimmed bool) string {
	runes := []rune(title)
	if len(runes) == 0 {
		return ""
	}
	matched := make(map[int]struct{}, len(matchedRunes))
	for _, index := range matchedRunes {
		matched[index] = struct{}{}
	}
	statusEnd := len([]rune(statusLabel(item.result.Status)))
	ruleStart := statusEnd + 2
	ruleEnd := ruleStart + len([]rune(presentation.Sanitize(item.result.RuleID)))

	var builder strings.Builder
	for index, value := range runes {
		style := baseStyle
		if !dimmed {
			switch {
			case index < statusEnd:
				style = statusStyle.Copy().Foreground(statusColor(item.result.Status)).Inline(true)
			case index >= ruleStart && index < ruleEnd:
				style = codeStyle.Inline(true)
			}
		}
		if _, exists := matched[index]; exists {
			style = style.Inherit(filterMatch)
		}
		builder.WriteString(style.Render(string(value)))
	}
	return builder.String()
}

func (m *Model) Init() tea.Cmd { return nil }

func sanitizeTUIInputMessage(message tea.Msg) tea.Msg {
	switch value := message.(type) {
	case tea.PasteMsg:
		value.Content = presentation.Sanitize(value.Content)
		return value
	case tea.KeyPressMsg:
		key := tea.Key(value)
		if key.Text != "" {
			key.Text = presentation.Sanitize(key.Text)
			return tea.KeyPressMsg(key)
		}
	}
	return message
}

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	message = sanitizeTUIInputMessage(message)
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		m.resize()
		return m, nil
	case scanProgressMsg:
		if message.source != m.scanProgressCh || !message.open || m.screen != screenScanning {
			return m, nil
		}
		m.scanProgress = message.progress
		return m, waitForScanProgress(message.source)
	case scanTickMsg:
		if m.screen != screenScanning {
			return m, nil
		}
		m.scanTicks++
		return m, scanTick()
	case scanCompleteMsg:
		m.cancelScan = nil
		m.scanProgressCh = nil
		if m.quitAfterAction {
			m.quitAfterAction = false
			return m, tea.Quit
		}
		if m.scanBackRequested {
			m.scanBackRequested = false
			m.err = nil
			m.screen = screenOptions
			return m, nil
		}
		if message.err != nil {
			m.err = message.err
			m.exitCode = exitcode.Error
			m.screen = screenError
			return m, nil
		}
		m.run = message.run
		if message.run.Metadata.Redaction {
			m.run = redact.ScanRun(message.run)
		}
		m.reportPath = message.reportPath
		m.showAll = m.scanSettings.showAll
		m.exitCode = message.run.Metadata.ExitCode
		m.screen = screenResults
		m.updateItems()
		return m, nil
	case remediationPlanMsg:
		m.cancelAction = nil
		if message.remediator != nil {
			if err := m.replaceRemediator(message.remediator); err != nil {
				message.err = errors.Join(message.err, fmt.Errorf("이전 조치 workflow를 닫지 못했습니다: %w", err))
			}
		}
		if message.plan.Journal != nil {
			m.plan = message.plan
			m.journal = message.plan.Journal
			m.selectedChangeSet = 0
		}
		if message.err != nil {
			if m.journal != nil && m.journal.State == model.RunCanceled {
				m.remediationErr = nil
				m.screen = screenRemediationStatus
				return m.finishQuitAfterAction()
			}
			m.remediationErr = message.err
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m.finishQuitAfterAction()
		}
		m.viewport.SetContent(remediationPlanContent(message.plan, false))
		m.viewport.GotoTop()
		m.screen = screenRemediationPlan
		return m.finishQuitAfterAction()
	case remediationJournalMsg:
		completedScreen := m.screen
		m.cancelAction = nil
		if message.journal != nil {
			m.journal = message.journal
		}
		if message.err != nil {
			m.quitAfterPlanCancel = false
			m.remediationErr = message.err
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m.finishQuitAfterAction()
		}
		if m.quitAfterPlanCancel && completedScreen == screenRemediationCanceling {
			m.quitAfterPlanCancel = false
			return m, tea.Quit
		}
		if completedScreen == screenRemediationApproving {
			m.viewport.SetContent(remediationPlanContent(m.plan, true))
			m.viewport.GotoTop()
			m.screen = screenRemediationApproved
		} else {
			m.screen = screenRemediationStatus
		}
		return m.finishQuitAfterAction()
	case remediationRollbackPreviewMsg:
		m.cancelAction = nil
		if message.err != nil {
			m.remediationErr = message.err
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m.finishQuitAfterAction()
		}
		m.rollbackPreview = message.preview
		m.rollbackRunScope = message.runScope
		m.rollbackChangeSet = message.changeSetID
		m.viewport.SetContent(remediationRollbackPreviewContent(message.preview, message.runScope))
		m.viewport.GotoTop()
		m.screen = screenRemediationRollbackPreview
		return m.finishQuitAfterAction()
	case remediationRollbackMsg:
		m.cancelAction = nil
		m.rollback = message.attempt
		if message.journal != nil {
			m.journal = message.journal
		}
		if message.err != nil {
			m.remediationErr = message.err
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m.finishQuitAfterAction()
		}
		m.screen = screenRemediationStatus
		return m.finishQuitAfterAction()
	case tea.KeyPressMsg:
		key := message.String()
		if m.quitConfirmation {
			return m.updateQuitConfirmation(key)
		}
		if m.screen == screenOptions && m.editingOption {
			return m.updateOptionEditor(message)
		}
		if m.screen == screenResults && m.list.SettingFilter() {
			if key == "esc" {
				m.openQuitConfirmation()
				return m, nil
			}
			updated, command := m.list.Update(message)
			m.list = updated
			return m, command
		}
		if key == "ctrl+c" {
			if m.cancelAction != nil {
				m.cancelAction()
				return m, nil
			}
			if m.cancelScan != nil {
				m.cancelScan()
			}
			return m, tea.Quit
		}
		if key == "esc" {
			m.openQuitConfirmation()
			return m, nil
		}
		if key == "q" {
			return m.navigateBack()
		}
		switch m.screen {
		case screenReady:
			switch key {
			case "up", "k":
				m.readySelection = (m.readySelection + readyMenuCount - 1) % readyMenuCount
				return m, nil
			case "down", "j":
				m.readySelection = (m.readySelection + 1) % readyMenuCount
				return m, nil
			case "enter":
				switch m.readySelection {
				case readyMenuScan:
					return m, m.startScan()
				case readyMenuOptions:
					m.optionErr = nil
					m.screen = screenOptions
					return m, nil
				case readyMenuQuit:
					m.openQuitConfirmation()
					return m, nil
				}
			case "s":
				return m, m.startScan()
			case "o":
				m.optionErr = nil
				m.screen = screenOptions
				return m, nil
			}
		case screenOptions:
			return m.updateOptions(key)
		case screenOptionPicker:
			return m.updateOptionPicker(key)
		case screenConfirmNoRedact:
			switch key {
			case "y":
				m.scanSettings.noRedact = true
				m.scanSettings.remediationEnabled = false
				m.screen = screenOptions
			case "n", "backspace":
				m.screen = screenOptions
			}
			return m, nil
		case screenResults:
			switch key {
			case "a":
				m.showAll = !m.showAll
				m.updateItems()
				return m, nil
			case "enter":
				selected, ok := m.list.SelectedItem().(resultItem)
				if ok {
					m.viewport.SetContent(detailContent(selected.result, m.viewport.Width()))
					m.viewport.GotoTop()
					m.screen = screenDetail
				}
				return m, nil
			case "r":
				return m, m.startScan()
			case "m":
				if m.canPlanRemediation() {
					m.failurePolicy = model.FailureRollbackItem
					m.screen = screenRemediationFailurePolicy
				}
			}
		case screenDetail:
			if key == "backspace" {
				m.screen = screenResults
				return m, nil
			}
		case screenRemediationFailurePolicy:
			switch key {
			case "i":
				m.failurePolicy = model.FailureRollbackItem
				return m.startRemediationPlan()
			case "r":
				m.failurePolicy = model.FailureRollbackRun
				return m.startRemediationPlan()
			case "backspace":
				m.screen = screenResults
				return m, nil
			}
		case screenRemediationPlan:
			switch key {
			case "a":
				m.screen = screenRemediationConfirmApproval
				return m, nil
			case "c", "backspace":
				m.cancelReturn = screenRemediationPlan
				m.screen = screenRemediationConfirmCancel
				return m, nil
			}
		case screenRemediationConfirmApproval:
			switch key {
			case "y":
				return m.startRemediationApproval()
			case "n", "backspace":
				m.screen = screenRemediationPlan
				return m, nil
			}
		case screenRemediationApproved:
			switch key {
			case "x":
				m.screen = screenRemediationConfirmApply
				return m, nil
			case "c", "backspace":
				m.cancelReturn = screenRemediationApproved
				m.screen = screenRemediationConfirmCancel
				return m, nil
			}
		case screenRemediationConfirmApply:
			switch key {
			case "y":
				return m.startRemediationApply()
			case "n", "backspace":
				m.screen = screenRemediationApproved
				return m, nil
			}
		case screenRemediationStatus:
			switch key {
			case "j", "down":
				m.moveChangeSetSelection(1)
				return m, nil
			case "k", "up":
				m.moveChangeSetSelection(-1)
				return m, nil
			case "b":
				if m.canPreviewSelectedRollback() {
					return m.startRollbackPreview(false)
				}
				return m, nil
			case "u":
				if m.canPreviewRunRollback() {
					return m.startRollbackPreview(true)
				}
				return m, nil
			case "c":
				if m.hasUnusedRemediationPlan() {
					m.cancelReturn = screenRemediationStatus
					m.screen = screenRemediationConfirmCancel
				}
				return m, nil
			case "backspace":
				m.screen = screenResults
				return m, nil
			}
		case screenRemediationRollbackPreview:
			switch key {
			case "r":
				m.screen = screenRemediationConfirmRollback
				return m, nil
			case "backspace":
				m.screen = screenRemediationStatus
				return m, nil
			}
		case screenRemediationConfirmRollback:
			switch key {
			case "y":
				return m.startApprovedRollback()
			case "n", "backspace":
				m.screen = screenRemediationRollbackPreview
				return m, nil
			}
		case screenRemediationConfirmCancel:
			switch key {
			case "y":
				return m.startRemediationCancel()
			case "n", "backspace":
				m.quitAfterPlanCancel = false
				m.screen = m.cancelReturn
				return m, nil
			}
		case screenRemediationError:
			if key == "backspace" {
				if m.journal != nil {
					m.screen = screenRemediationStatus
				} else {
					m.screen = screenResults
				}
				return m, nil
			}
		case screenError:
			if key == "r" {
				return m, m.startScan()
			}
			if key == "backspace" {
				m.screen = screenOptions
				return m, nil
			}
		}
	}

	switch m.screen {
	case screenResults:
		updated, command := m.list.Update(message)
		m.list = updated
		return m, command
	case screenDetail, screenRemediationPlan, screenRemediationApproved, screenRemediationRollbackPreview:
		updated, command := m.viewport.Update(message)
		m.viewport = updated
		return m, command
	default:
		return m, nil
	}
}

func (m *Model) openQuitConfirmation() {
	if m.quitAfterAction {
		return
	}
	m.quitConfirmation = true
	m.quitSelection = 0
}

func (m *Model) updateQuitConfirmation(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "left", "h":
		m.quitSelection = 0
	case "right", "l":
		m.quitSelection = 1
	case "tab", "shift+tab":
		m.quitSelection = (m.quitSelection + 1) % 2
	case "q", "esc", "backspace":
		m.quitConfirmation = false
		m.quitSelection = 0
		return m, tea.ClearScreen
	case "enter":
		if m.quitSelection == 0 {
			m.quitConfirmation = false
			return m, tea.ClearScreen
		}
		return m.confirmQuit()
	}
	return m, nil
}

func (m *Model) confirmQuit() (tea.Model, tea.Cmd) {
	if m.cancelAction != nil {
		m.quitConfirmation = false
		m.quitSelection = 0
		m.quitAfterAction = true
		m.cancelAction()
		return m, nil
	}
	if m.cancelScan != nil {
		m.quitConfirmation = false
		m.quitSelection = 0
		m.quitAfterAction = true
		m.cancelScan()
		return m, nil
	}
	if m.hasUnusedRemediationPlan() {
		m.quitConfirmation = false
		m.quitSelection = 0
		m.quitAfterPlanCancel = true
		if m.screen != screenRemediationConfirmCancel {
			m.cancelReturn = m.screen
			m.screen = screenRemediationConfirmCancel
		}
		return m, nil
	}
	return m, tea.Quit
}

func (m *Model) finishQuitAfterAction() (tea.Model, tea.Cmd) {
	if !m.quitAfterAction {
		return m, nil
	}
	m.quitAfterAction = false
	if m.hasUnusedRemediationPlan() {
		m.quitAfterPlanCancel = true
		if m.screen != screenRemediationConfirmCancel {
			m.cancelReturn = m.screen
			m.screen = screenRemediationConfirmCancel
		}
		return m, nil
	}
	return m, tea.Quit
}

func (m *Model) navigateBack() (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenReady:
		return m, nil
	case screenOptions:
		m.optionErr = nil
		m.screen = screenReady
	case screenOptionPicker, screenConfirmNoRedact:
		m.screen = screenOptions
	case screenScanning:
		if m.cancelScan != nil {
			m.scanBackRequested = true
			m.cancelScan()
		}
	case screenResults:
		m.screen = screenReady
	case screenDetail, screenRemediationFailurePolicy:
		m.screen = screenResults
	case screenRemediationPlanning,
		screenRemediationApproving,
		screenRemediationApplying,
		screenRemediationCanceling,
		screenRemediationRollbackPreviewing,
		screenRemediationRollingBack:
		if m.cancelAction != nil {
			m.cancelAction()
		}
	case screenRemediationPlan:
		m.cancelReturn = screenRemediationPlan
		m.screen = screenRemediationConfirmCancel
	case screenRemediationConfirmApproval:
		m.screen = screenRemediationPlan
	case screenRemediationApproved:
		m.cancelReturn = screenRemediationApproved
		m.screen = screenRemediationConfirmCancel
	case screenRemediationConfirmApply:
		m.screen = screenRemediationApproved
	case screenRemediationStatus:
		m.screen = screenResults
	case screenRemediationConfirmCancel:
		m.quitAfterPlanCancel = false
		m.screen = m.cancelReturn
	case screenRemediationRollbackPreview:
		m.screen = screenRemediationStatus
	case screenRemediationConfirmRollback:
		m.screen = screenRemediationRollbackPreview
	case screenRemediationError:
		if m.journal != nil {
			m.screen = screenRemediationStatus
		} else {
			m.screen = screenResults
		}
	case screenError:
		m.screen = screenOptions
	}
	return m, nil
}

func (m *Model) View() tea.View {
	var content string
	switch m.screen {
	case screenReady:
		content = m.readyView()
	case screenOptions:
		content = m.optionsView()
	case screenOptionPicker:
		content = m.optionPickerView()
	case screenConfirmNoRedact:
		content = m.confirmNoRedactView()
	case screenScanning:
		content = m.scanningView()
	case screenResults:
		header := "문제 항목"
		if m.showAll {
			header = "전체 항목"
		}
		m.list.Title = header
		helpValues := []string{"Enter", "상세", "A", "전체/문제", "/", "검색", "R", "다시 점검"}
		if m.list.SettingFilter() {
			helpValues = []string{"Enter", "검색 적용", "Ctrl+G", "검색 취소"}
		}
		availability := m.remediationAvailability()
		if availability.enabled && !m.list.SettingFilter() {
			helpValues = append(helpValues, "M", "조치 계획")
		}
		if !m.list.SettingFilter() {
			helpValues = append(helpValues, "Q", "뒤로")
		}
		helpValues = append(helpValues, "Esc", "종료")
		content = screenHeader("점검 결과") + "\n\n" + m.list.View()
		if m.reportPath != "" {
			pathWidth := m.width - 18
			if pathWidth < 24 {
				pathWidth = 24
			}
			content += "\n\n" + labelStyle.Render("보고서") + "  " + helpStyle.Render(truncateStart(m.reportPath, pathWidth))
		}
		content += "\n\n" + resultSummary(m.run.Metadata.Counts)
		content += "\n\n" + remediationAvailabilityView(availability)
		content += "\n\n" + optionKeyLegend(helpValues...)
	case screenDetail:
		content = screenHeader("항목 상세") + "\n\n" + m.viewport.View() + "\n\n" + helpStyle.Render("q: 결과 목록   Esc: 종료")
	case screenRemediationFailurePolicy:
		content = titleStyle.Render("조치 실패 정책 선택") + "\n\n" +
			"변경 세트 적용 또는 검증이 실패했을 때의 자동 롤백 범위를 선택해주세요.\n\n" +
			"i  rollback_item: 실패한 항목 변경 세트만 복원합니다.\n" +
			"r  rollback_run: 실패한 항목을 복원한 뒤 앞서 적용한 실행 전체를 역순으로 복원합니다.\n\n" +
			helpStyle.Render("i: 항목 단위   r: 실행 전체   q: 돌아가기   Esc: 종료")
	case screenRemediationPlanning:
		content = titleStyle.Render("조치 dry-run 생성") + "\n\n점검 보고서와 현재 호스트를 재검증하고 변경 계획을 만들고 있습니다.\n시스템 파일은 변경하지 않습니다.\n\n" + helpStyle.Render("q: 안전한 작업 취소 요청   Esc: 종료")
	case screenRemediationPlan:
		content = m.viewport.View() + "\n" + helpStyle.Render("a: plan digest 확인 및 승인 단계   c 또는 q: 계획 폐기   Esc: 종료")
	case screenRemediationConfirmApproval:
		content = remediationApprovalConfirmation(m.plan) + "\n\n" + helpStyle.Render("y: 이 계획 승인   n 또는 q: 돌아가기   Esc: 종료")
	case screenRemediationApproving:
		content = titleStyle.Render("조치 계획 승인") + "\n\n승인 정보를 내구성 저널에 기록하고 있습니다.\n아직 시스템 파일은 변경하지 않습니다.\n\n" + helpStyle.Render("q: 안전한 작업 취소 요청   Esc: 종료")
	case screenRemediationApproved:
		content = m.viewport.View() + "\n" + helpStyle.Render("x: 실제 적용 단계   c 또는 q: 승인 계획 폐기   Esc: 종료")
	case screenRemediationConfirmApply:
		content = remediationApplyConfirmation(m.plan) + "\n\n" + helpStyle.Render("y: 백업 후 실제 적용·검증   n 또는 q: 돌아가기   Esc: 종료")
	case screenRemediationApplying:
		content = titleStyle.Render("조치 적용 및 검증") + "\n\n변경 전 백업, write-ahead 저널 기록, 변경 후 검증을 순차 실행하고 있습니다.\n실패하면 선택한 실패 정책에 따라 롤백합니다.\n\n" + helpStyle.Render("q: 안전한 중단 요청   Esc: 종료")
	case screenRemediationStatus:
		help := "j/k: 항목 선택"
		if m.canPreviewSelectedRollback() {
			help += "   b: 선택 항목 롤백 미리보기"
		}
		if m.canPreviewRunRollback() {
			help += "   u: 실행 전체 롤백 미리보기"
		}
		if m.hasUnusedRemediationPlan() {
			help += "   c: 계획 폐기"
		}
		content = remediationStatusContent(m.journal, m.rollback, m.selectedChangeSet) + "\n" + helpStyle.Render(help+"   q: 점검 결과   Esc: 종료")
	case screenRemediationConfirmCancel:
		content = remediationCancelConfirmation(m.journal) + "\n\n" + helpStyle.Render("y: 계획과 미사용 payload 폐기   n 또는 q: 돌아가기   Esc: 종료")
	case screenRemediationCanceling:
		content = titleStyle.Render("조치 계획 폐기") + "\n\n적용되지 않은 desired payload를 격리·삭제하고 취소 상태를 저널에 기록하고 있습니다.\n\n" + helpStyle.Render("q: 안전한 작업 취소 요청   Esc: 종료")
	case screenRemediationRollbackPreviewing:
		content = titleStyle.Render("롤백 범위 계산") + "\n\n현재 저널 revision에서 공유 자원과 의존 관계를 다시 계산하고 있습니다.\n아직 시스템 파일은 변경하지 않습니다.\n\n" + helpStyle.Render("q: 안전한 작업 취소 요청   Esc: 종료")
	case screenRemediationRollbackPreview:
		content = m.viewport.View() + "\n\n" + helpStyle.Render("r: 표시 범위 승인 단계   q: 현재 상태로 돌아가기   Esc: 종료")
	case screenRemediationConfirmRollback:
		content = remediationRollbackConfirmation(m.rollbackPreview, m.rollbackRunScope) + "\n\n" + helpStyle.Render("y: digest에 고정된 범위 롤백   n 또는 q: 돌아가기   Esc: 종료")
	case screenRemediationRollingBack:
		content = titleStyle.Render("롤백 실행") + "\n\n백업과 현재 상태를 재검증한 뒤 승인된 역순으로 복원하고 있습니다.\n독립적인 분기는 다른 분기의 실패와 관계없이 계속 시도합니다.\n\n" + helpStyle.Render("q: 안전한 중단 요청   Esc: 종료")
	case screenRemediationError:
		content = remediationErrorContent(m.journal, m.remediationErr, !m.scanSettings.noRedact) + "\n\n" + helpStyle.Render("q: 현재 저널 또는 점검 결과로 돌아가기   Esc: 종료")
	case screenError:
		content = errorPanelStyle.Render(errorStyle.Render("점검을 완료하지 못했습니다.")+"\n\n"+protectedDisplayText(fmt.Sprint(m.err), !m.scanSettings.noRedact)) + "\n\n" + helpStyle.Render("r: 다시 시도   q: 실행 옵션   Esc: 종료")
	}
	if m.quitConfirmation {
		content = m.quitConfirmationView()
	}
	content = frameStyle.Render(content)
	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "OpenCIIP"
	return view
}

func (m *Model) readyView() string {
	brand := titleStyle.Render(openCIIPLogo)
	if m.width > 0 && m.width < openCIIPLogoWidth+10 {
		brand = titleStyle.Render(">_ OpenCIIP")
	}

	menu := readyMenuView(m.readySelection)
	main := lipgloss.JoinVertical(lipgloss.Center,
		brand,
		subtitleStyle.Render("주요정보통신기반시설 보안 점검"),
		"",
		menu,
		"",
		helpStyle.Render("↑/↓  이동     Enter  선택     Esc  종료"),
	)

	if m.platform.Privilege != "root" {
		main = lipgloss.JoinVertical(lipgloss.Center, main, "", warningStyle.Render("! 보호된 설정을 확인하려면 sudo openciip으로 실행하세요."))
	}

	width := m.width - 4
	if width < 50 {
		width = 50
	}
	height := m.height - 6
	if height < lipgloss.Height(main) {
		height = lipgloss.Height(main)
	}
	centered := lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, main)
	return centered + "\n" + lipgloss.PlaceHorizontal(width, lipgloss.Center, readyFooter())
}

func (m *Model) quitConfirmationView() string {
	contentWidth := m.optionContentWidth()
	if contentWidth > 58 {
		contentWidth = 58
	}
	button := func(label string, selected bool, destructive bool) string {
		text := label
		if selected {
			text = "‹ " + label + " ›"
		}
		style := lipgloss.NewStyle().
			Width(14).
			Align(lipgloss.Center).
			Foreground(mutedColor)
		if selected {
			foreground := accentColor
			if destructive {
				foreground = errorColor
			}
			style = style.Bold(true).Foreground(foreground).Background(selectedColor)
		}
		return style.Render(text)
	}
	buttons := lipgloss.JoinHorizontal(
		lipgloss.Center,
		button("취소", m.quitSelection == 0, false),
		"    ",
		button("종료", m.quitSelection == 1, true),
	)
	panel := quitPanelStyle.Copy().Width(contentWidth - 4).Render(
		detailTitleStyle.Render("정말 종료할까요?") + "\n\n" +
			lipgloss.PlaceHorizontal(contentWidth-10, lipgloss.Center, buttons),
	)
	content := screenHeader("종료") + "\n\n" + panel + "\n\n" +
		optionKeyLegend("←/→", "이동", "Enter", "선택", "q 또는 Esc", "취소")
	return m.centerOptionContent(content, contentWidth)
}

const (
	readyMenuScan = iota
	readyMenuOptions
	readyMenuQuit
	readyMenuCount
)

func readyMenuView(selected int) string {
	items := []string{"점검 시작", "실행 옵션", "종료"}
	lines := make([]string, 0, len(items))
	const rowWidth = 34
	for index, item := range items {
		marker := "  "
		style := lipgloss.NewStyle().Foreground(textColor)
		if index == selected {
			marker = accentStyle.Render("› ")
			style = keyStyle
		}
		row := marker + style.Render(item)
		if index == selected {
			row = selectedRowStyle.Copy().Width(rowWidth).Render(row)
		} else {
			row = lipgloss.NewStyle().Width(rowWidth).Render(row)
		}
		lines = append(lines, row)
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func readyFooter() string {
	info := buildinfo.Current()
	version := strings.TrimSpace(info.Version)
	if version == "" {
		version = "dev"
	}
	if info.Modified && !strings.Contains(version, "dirty") {
		version += "+dirty"
	}
	version = presentation.Sanitize(version)
	return helpStyle.Render("OpenCIIP " + version + "\n© 2026 yesidodo73  ·  Apache License 2.0")
}

func (m *Model) scanningView() string {
	progress := m.scanProgress
	spinner := spinnerFrames[m.scanTicks%len(spinnerFrames)]
	contentWidth := m.scanningContentWidth()
	if progress.Total <= 0 {
		content := screenHeader("Linux 서버 보안 점검") + "\n\n" +
			accentStyle.Render(spinner+" 점검 항목을 준비하고 있습니다") + "\n\n" +
			statusRuleStyle.Render("─ 준비 중") + "\n" + helpStyle.Render("q  점검 취소     Esc  종료")
		return m.centerScanningContent(content, contentWidth)
	}

	completed := progress.Completed
	if completed < 0 {
		completed = 0
	}
	if completed > progress.Total {
		completed = progress.Total
	}
	percent := completed * 100 / progress.Total
	barWidth := contentWidth - 8
	if barWidth < 24 {
		barWidth = 24
	}
	if barWidth > 64 {
		barWidth = 64
	}
	filled := completed * barWidth / progress.Total
	bar := progressDoneStyle.Render(strings.Repeat("━", filled)) + progressPendingStyle.Render(strings.Repeat("━", barWidth-filled))

	elapsed := m.now().Sub(m.scanStarted)
	if elapsed < 0 {
		elapsed = 0
	}
	current := strings.TrimSpace(presentation.Sanitize(progress.RuleID) + "  " + presentation.Sanitize(progress.Title))
	if current == "" {
		current = "점검 항목 준비 중"
	}

	content := screenHeader("Linux 서버 보안 점검") + "\n\n" +
		fmt.Sprintf("%s  %s\n\n", accentStyle.Render(spinner+" 점검 중"), counterStyle.Render(fmt.Sprintf("%d / %d", completed, progress.Total))) +
		bar + "  " + percentStyle.Render(fmt.Sprintf("%3d%%", percent)) + "\n\n" +
		labelStyle.Render("현재") + "  " + current + "\n" +
		labelStyle.Render("경과") + "  " + durationLabel(elapsed) + "\n\n" +
		statusRuleStyle.Render(strings.Repeat("─", contentWidth)) + "\n" +
		helpStyle.Render("q  점검 취소     Esc  종료")
	return m.centerScanningContent(content, contentWidth)
}

func (m *Model) scanningContentWidth() int {
	width := m.width - 12
	if m.width <= 0 {
		width = 72
	}
	if width > 72 {
		width = 72
	}
	if width < 44 {
		width = 44
	}
	return width
}

func (m *Model) centerScanningContent(content string, contentWidth int) string {
	availableWidth := m.width - 4
	if availableWidth < contentWidth {
		availableWidth = contentWidth
	}
	fixedWidth := lipgloss.NewStyle().Width(contentWidth).MaxWidth(contentWidth).Render(content)
	availableHeight := m.height - 4
	if availableHeight < lipgloss.Height(fixedWidth) {
		availableHeight = lipgloss.Height(fixedWidth)
	}
	return lipgloss.Place(availableWidth, availableHeight, lipgloss.Center, lipgloss.Center, fixedWidth)
}

func screenHeader(section string) string {
	return titleStyle.Render(">_ OpenCIIP") + "  " + subtitleStyle.Render(presentation.Sanitize(section))
}

func statusSeparator() string {
	return statusRuleStyle.Render("  │  ")
}

func durationLabel(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	value = value.Round(time.Second)
	hours := int(value / time.Hour)
	minutes := int(value/time.Minute) % 60
	seconds := int(value/time.Second) % 60
	if hours > 0 {
		return fmt.Sprintf("%d시간 %02d분 %02d초", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%d분 %02d초", minutes, seconds)
	}
	return fmt.Sprintf("%d초", seconds)
}

func resultSummary(counts map[model.Status]int) string {
	values := []model.Status{
		model.StatusFail,
		model.StatusUnknown,
		model.StatusError,
		model.StatusPass,
		model.StatusNotApplicable,
		model.StatusSkipped,
	}
	parts := make([]string, 0, len(values))
	for _, status := range values {
		parts = append(parts, statusStyle.Copy().Foreground(statusColor(status)).Render(fmt.Sprintf("%s %d", statusLabel(status), counts[status])))
	}
	return statusRuleStyle.Render("─ ") + strings.Join(parts, statusSeparator())
}

func statusBadge(status model.Status) string {
	return statusStyle.Copy().Foreground(statusColor(status)).Render(statusLabel(status))
}

func statusLabel(status model.Status) string {
	switch status {
	case model.StatusFail:
		return "취약"
	case model.StatusUnknown:
		return "수동 확인 필요"
	case model.StatusError:
		return "확인 실패"
	case model.StatusPass:
		return "양호"
	case model.StatusNotApplicable:
		return "해당 없음"
	case model.StatusSkipped:
		return "점검하지 않음"
	default:
		return presentation.Sanitize(string(status))
	}
}

func statusColor(status model.Status) color.Color {
	switch status {
	case model.StatusPass:
		return successColor
	case model.StatusFail, model.StatusError:
		return errorColor
	case model.StatusUnknown:
		return warningColor
	case model.StatusNotApplicable, model.StatusSkipped:
		return mutedColor
	default:
		return textColor
	}
}

func (m *Model) startScan() tea.Cmd {
	if m.cancelScan != nil {
		return nil
	}
	options, err := m.scanSettings.engineOptions()
	if err != nil {
		m.optionErr = err
		m.screen = screenOptions
		return nil
	}
	if m.writerFactory == nil {
		m.optionErr = fmt.Errorf("보고서 작성기가 설정되지 않았습니다")
		m.screen = screenOptions
		return nil
	}
	settings := m.scanSettings
	scanContext, cancel := context.WithCancel(m.ctx)
	m.cancelScan = cancel
	m.screen = screenScanning
	m.err = nil
	m.scanStarted = m.now()
	m.scanProgress = engine.Progress{}
	m.scanTicks = 0
	progress := make(chan engine.Progress, 1)
	m.scanProgressCh = progress
	runScan := func() tea.Msg {
		defer close(progress)
		writer, err := m.writerFactory(settings.reportDir)
		if err != nil {
			return scanCompleteMsg{err: fmt.Errorf("보고서 저장 경로를 준비하지 못했습니다: %w", err)}
		}
		options.Progress = func(update engine.Progress) {
			publishScanProgress(progress, update)
		}
		run, err := m.scanner.Scan(scanContext, options)
		if err != nil {
			return scanCompleteMsg{err: err}
		}
		path, err := writer.WriteScan(scanContext, run)
		return scanCompleteMsg{run: run, reportPath: path, err: err}
	}
	return tea.Batch(runScan, waitForScanProgress(progress), scanTick())
}

func publishScanProgress(channel chan engine.Progress, progress engine.Progress) {
	select {
	case channel <- progress:
		return
	default:
	}
	select {
	case <-channel:
	default:
	}
	select {
	case channel <- progress:
	default:
	}
}

func waitForScanProgress(channel <-chan engine.Progress) tea.Cmd {
	return func() tea.Msg {
		progress, open := <-channel
		return scanProgressMsg{progress: progress, source: channel, open: open}
	}
}

func scanTick() tea.Cmd {
	return tea.Tick(time.Second, func(value time.Time) tea.Msg {
		return scanTickMsg(value)
	})
}

func (m *Model) startRemediationPlan() (tea.Model, tea.Cmd) {
	if !m.canPlanRemediation() {
		return m, nil
	}
	m.remediationErr = nil
	m.plan = workflow.PlanResult{}
	m.journal = nil
	m.rollback = model.RollbackAttempt{}
	m.rollbackPreview = orchestrator.RollbackPreview{}
	m.screen = screenRemediationPlanning
	actionContext, cancel := context.WithCancel(m.ctx)
	m.cancelAction = cancel
	factory := m.remediatorFactory
	reportPath := m.reportPath
	failurePolicy := m.failurePolicy
	return m, func() tea.Msg {
		defer cancel()
		remediator, err := factory(actionContext)
		if err != nil {
			return remediationPlanMsg{err: err}
		}
		planned, err := remediator.PlanFromReport(actionContext, reportPath, workflow.PlanOptions{FailurePolicy: failurePolicy})
		if err != nil {
			if closeErr := closeRemediator(remediator); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("실패한 조치 workflow를 닫지 못했습니다: %w", closeErr))
			}
			return remediationPlanMsg{err: err}
		}
		return remediationPlanMsg{remediator: remediator, plan: planned}
	}
}

func (m *Model) startRemediationApproval() (tea.Model, tea.Cmd) {
	if m.remediator == nil || m.plan.Journal == nil {
		m.remediationErr = fmt.Errorf("승인할 조치 계획이 없습니다")
		m.exitCode = exitcode.Error
		m.screen = screenRemediationError
		return m, nil
	}
	m.screen = screenRemediationApproving
	actionContext, cancel := context.WithCancel(m.ctx)
	m.cancelAction = cancel
	runID := m.plan.Journal.RunID
	digest := m.plan.Journal.PlanDigest
	remediator := m.remediator
	return m, func() tea.Msg {
		defer cancel()
		err := remediator.Approve(actionContext, runID, digest, "tui-explicit", "")
		journal, loadErr := remediator.Load(context.WithoutCancel(actionContext), runID)
		if err == nil {
			err = loadErr
		}
		return remediationJournalMsg{journal: journal, err: err}
	}
}

func (m *Model) startRemediationApply() (tea.Model, tea.Cmd) {
	if m.remediator == nil || m.plan.Journal == nil {
		m.remediationErr = fmt.Errorf("적용할 승인 계획이 없습니다")
		m.exitCode = exitcode.Error
		m.screen = screenRemediationError
		return m, nil
	}
	m.screen = screenRemediationApplying
	actionContext, cancel := context.WithCancel(m.ctx)
	m.cancelAction = cancel
	runID := m.plan.Journal.RunID
	remediator := m.remediator
	return m, func() tea.Msg {
		defer cancel()
		err := remediator.Apply(actionContext, runID)
		journal, loadErr := remediator.Load(context.WithoutCancel(actionContext), runID)
		if err == nil {
			err = loadErr
		}
		return remediationJournalMsg{journal: journal, err: err}
	}
}

func (m *Model) startRemediationCancel() (tea.Model, tea.Cmd) {
	if m.remediator == nil || m.journal == nil || !m.hasUnusedRemediationPlan() {
		m.remediationErr = fmt.Errorf("폐기할 적용 전 조치 계획이 없습니다")
		m.exitCode = exitcode.Error
		m.screen = screenRemediationError
		return m, nil
	}
	m.screen = screenRemediationCanceling
	actionContext, cancel := context.WithCancel(m.ctx)
	m.cancelAction = cancel
	runID := m.journal.RunID
	remediator := m.remediator
	return m, func() tea.Msg {
		defer cancel()
		err := remediator.Cancel(actionContext, runID)
		journal, loadErr := remediator.Load(context.WithoutCancel(actionContext), runID)
		if err == nil {
			err = loadErr
		}
		return remediationJournalMsg{journal: journal, err: err}
	}
}

func (m *Model) startRollbackPreview(runScope bool) (tea.Model, tea.Cmd) {
	if m.remediator == nil || m.journal == nil {
		m.remediationErr = fmt.Errorf("롤백 범위를 계산할 조치 실행이 없습니다")
		m.exitCode = exitcode.Error
		m.screen = screenRemediationError
		return m, nil
	}
	changeSetID := ""
	if !runScope {
		changeSetID = m.selectedChangeSetID()
		if changeSetID == "" {
			m.remediationErr = fmt.Errorf("롤백할 항목 변경 세트가 없습니다")
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m, nil
		}
	}
	m.rollbackPreview = orchestrator.RollbackPreview{}
	m.rollbackRunScope = runScope
	m.rollbackChangeSet = changeSetID
	m.screen = screenRemediationRollbackPreviewing
	actionContext, cancel := context.WithCancel(m.ctx)
	m.cancelAction = cancel
	runID := m.journal.RunID
	remediator := m.remediator
	return m, func() tea.Msg {
		defer cancel()
		var preview orchestrator.RollbackPreview
		var err error
		if runScope {
			preview, err = remediator.PreviewRollbackRun(actionContext, runID)
		} else {
			preview, err = remediator.PreviewRollbackItem(actionContext, runID, changeSetID)
		}
		return remediationRollbackPreviewMsg{preview: preview, runScope: runScope, changeSetID: changeSetID, err: err}
	}
}

func (m *Model) startApprovedRollback() (tea.Model, tea.Cmd) {
	preview := m.rollbackPreview
	if m.remediator == nil || m.journal == nil || preview.RunID != m.journal.RunID || preview.PreviewDigest == "" {
		m.remediationErr = fmt.Errorf("승인할 롤백 미리보기가 없습니다")
		m.exitCode = exitcode.Error
		m.screen = screenRemediationError
		return m, nil
	}
	m.screen = screenRemediationRollingBack
	actionContext, cancel := context.WithCancel(m.ctx)
	m.cancelAction = cancel
	runID := m.journal.RunID
	runScope := m.rollbackRunScope
	changeSetID := m.rollbackChangeSet
	remediator := m.remediator
	return m, func() tea.Msg {
		defer cancel()
		var attempt model.RollbackAttempt
		var err error
		if runScope {
			attempt, err = remediator.RollbackRun(actionContext, runID, preview.PreviewDigest)
		} else {
			attempt, err = remediator.RollbackItem(actionContext, runID, changeSetID, preview.CascadeRequired, preview.PreviewDigest)
		}
		journal, loadErr := remediator.Load(context.WithoutCancel(actionContext), runID)
		if err == nil {
			err = loadErr
		}
		return remediationRollbackMsg{attempt: attempt, journal: journal, err: err}
	}
}

func (m *Model) canPlanRemediation() bool {
	return m.remediationAvailability().enabled
}

func (m *Model) remediationAvailability() remediationAvailability {
	if m.remediatorFactory == nil {
		return remediationAvailability{label: "지원되지 않음", reason: "현재 실행 환경에서 자동 조치가 지원되지 않습니다."}
	}
	platform := m.platform
	if m.reportPath != "" {
		platform = m.run.Metadata.Platform
	}
	switch platform.RemediationSupport {
	case model.RemediationSupportVerified:
		// Continue with report and result gates.
	default:
		return remediationAvailability{label: "지원되지 않음", reason: "현재 OS와 버전에서 자동 조치가 지원되지 않습니다."}
	}
	if m.reportPath == "" {
		return remediationAvailability{label: "점검 필요", reason: "점검을 완료한 뒤 조치 가능한 항목을 확인합니다."}
	}
	if platform.ScanSupport != model.ScanSupportTested {
		return remediationAvailability{label: "지원되지 않음", reason: "현재 OS와 버전에서 자동 조치가 지원되지 않습니다."}
	}
	if platform.Privilege != "root" {
		return remediationAvailability{label: "root 권한 필요", reason: "자동 조치를 사용하려면 root 권한으로 실행해야 합니다."}
	}
	if m.scanSettings.noRedact {
		return remediationAvailability{label: "마스킹 필요", reason: "자동 조치에는 민감정보가 마스킹된 점검 보고서가 필요합니다."}
	}
	if !m.scanSettings.remediationEnabled {
		return remediationAvailability{label: "사용 안 함", reason: "실행 옵션에서 자동 조치를 활성화할 수 있습니다."}
	}
	evaluator := m.remediationCandidates
	if evaluator == nil {
		evaluator = builtInRemediationCandidates
	}
	verified, pending, err := evaluator(m.run, platform)
	if err != nil {
		return remediationAvailability{label: "사용 불가", reason: "내장 자동 조치 정의를 확인할 수 없습니다."}
	}
	if verified {
		return remediationAvailability{enabled: true, label: "사용 가능", reason: "검증된 취약 항목의 변경 계획을 먼저 확인합니다."}
	}
	if pending {
		return remediationAvailability{label: "지원되지 않음", reason: "현재 OS와 버전에서 자동 조치가 지원되지 않습니다."}
	}
	return remediationAvailability{label: "대상 없음", reason: "자동 조치 대상으로 확정된 취약 항목이 없습니다."}
}

func builtInRemediationCandidates(run model.ScanRun, platform model.PlatformInfo) (bool, bool, error) {
	registry, err := recipe.LoadDefaults()
	if err != nil {
		return false, false, err
	}
	pending := false
	for _, result := range run.Results {
		if result.Status != model.StatusFail || result.Verification.State != model.VerificationVerified {
			continue
		}
		item, exists := registry.Match(result.RuleID, platform)
		if !exists || item.GuideYear != run.Metadata.GuideYear {
			continue
		}
		switch item.Verification.State {
		case model.RemediationRecipeVerificationVerified:
			return true, pending, nil
		case model.RemediationRecipeVerificationPending:
			pending = true
		}
	}
	return false, pending, nil
}

func remediationAvailabilityView(availability remediationAvailability) string {
	label := presentation.Sanitize(availability.label)
	reason := presentation.Sanitize(availability.reason)
	status := disabledStyle.Render(label)
	marker := disabledStyle.Render("○")
	if availability.enabled {
		status = successStyle.Render(label)
		marker = successStyle.Render("●")
	}
	return marker + "  " + labelStyle.Render("자동 조치") + "  " + status + "\n" +
		"   " + helpStyle.Render(reason)
}

func (m *Model) hasUnusedRemediationPlan() bool {
	if m.journal == nil {
		return false
	}
	switch m.journal.State {
	case model.RunPlanned, model.RunApproved, model.RunCancelFailed:
		return true
	default:
		return false
	}
}

func (m *Model) canPreviewSelectedRollback() bool {
	if m.journal == nil || m.selectedChangeSet < 0 || m.selectedChangeSet >= len(m.journal.ChangeSets) {
		return false
	}
	changeSet := m.journal.ChangeSets[m.selectedChangeSet]
	switch changeSet.State {
	case model.ChangeApplied,
		model.ChangeVerified,
		model.ChangeApplyFailed,
		model.ChangeRollbackBlocked,
		model.ChangeRollbackFailed,
		model.ChangePartiallyRolledBack,
		model.ChangeRecoveryRequired:
		return changeSetHasRollbackWork(changeSet)
	default:
		return false
	}
}

func (m *Model) canPreviewRunRollback() bool {
	if m.journal == nil {
		return false
	}
	for _, changeSet := range m.journal.ChangeSets {
		if changeSetHasRollbackWork(changeSet) {
			return true
		}
	}
	return false
}

func changeSetHasRollbackWork(changeSet model.ChangeSet) bool {
	for _, operation := range changeSet.Operations {
		if operation.Before.IsZero() || operation.Backup == nil {
			continue
		}
		switch operation.State {
		case model.OperationApplyIntentDurable,
			model.OperationApplied,
			model.OperationVerified,
			model.OperationFailed,
			model.OperationRollbackIntentDurable,
			model.OperationAmbiguous:
			return true
		}
	}
	return false
}

func (m *Model) moveChangeSetSelection(delta int) {
	if m.journal == nil || len(m.journal.ChangeSets) == 0 {
		m.selectedChangeSet = 0
		return
	}
	m.selectedChangeSet += delta
	if m.selectedChangeSet < 0 {
		m.selectedChangeSet = 0
	}
	if m.selectedChangeSet >= len(m.journal.ChangeSets) {
		m.selectedChangeSet = len(m.journal.ChangeSets) - 1
	}
}

func (m *Model) selectedChangeSetID() string {
	if m.journal == nil || m.selectedChangeSet < 0 || m.selectedChangeSet >= len(m.journal.ChangeSets) {
		return ""
	}
	return m.journal.ChangeSets[m.selectedChangeSet].ID
}

func (m *Model) resize() {
	width := m.width - 4
	if width < 40 {
		width = 40
	}
	listHeight := m.height - 12
	if listHeight < 8 {
		listHeight = 8
	}
	viewportHeight := m.height - 7
	if viewportHeight < 8 {
		viewportHeight = 8
	}
	m.list.SetSize(width, listHeight)
	compactResults := m.height < 28
	m.list.SetDelegate(newResultDelegate(!compactResults))
	m.list.SetShowStatusBar(!compactResults)
	m.viewport.SetWidth(width)
	m.viewport.SetHeight(viewportHeight)
	m.optionInput.SetWidth(m.optionContentWidth() - 6)
}

func (m *Model) updateItems() {
	items := make([]list.Item, 0, len(m.run.Results))
	for _, result := range model.SortedResultsByStatus(m.run.Results) {
		if !m.showAll && result.Status != model.StatusFail && result.Status != model.StatusUnknown && result.Status != model.StatusError {
			continue
		}
		items = append(items, resultItem{result: result})
	}
	m.list.SetItems(items)
}

func detailContent(result model.CheckResult, width int) string {
	if width < 40 {
		width = 40
	}
	var builder strings.Builder
	fmt.Fprintf(
		&builder,
		"%s  %s\n%s\n\n",
		statusBadge(result.Status),
		codeStyle.Render(presentation.Sanitize(result.RuleID)),
		detailTitleStyle.Render(presentation.Sanitize(result.Title)),
	)
	fmt.Fprintf(
		&builder,
		"%s  %s    %s  %s\n\n",
		labelStyle.Render("중요도"),
		presentation.Sanitize(string(result.Severity)),
		labelStyle.Render("분류"),
		presentation.Sanitize(string(result.Category)),
	)
	fmt.Fprintf(&builder, "%s\n%s\n\n", labelStyle.Render("판정 이유"), wrapDetailText(result.Summary, width))
	if result.Expected != "" {
		fmt.Fprintf(&builder, "%s\n%s\n\n", labelStyle.Render("기준"), wrapDetailText(result.Expected, width))
	}
	if result.Observed != "" {
		fmt.Fprintf(&builder, "%s\n", labelStyle.Render("확인 결과"))
		if len(result.DisplayDetails) > 0 {
			builder.WriteString(resultDetailText(result.DisplayDetails, width, result.Status))
		} else {
			builder.WriteString(observedDetailText(result.Observed, width))
		}
		builder.WriteString("\n\n")
	}
	if result.UnknownReason != "" {
		fmt.Fprintf(&builder, "%s  %s\n\n", labelStyle.Render("확정 불가 사유"), presentation.Sanitize(string(result.UnknownReason)))
	}
	fmt.Fprintf(&builder, "%s\n%s, %v쪽\n", labelStyle.Render("가이드 근거"), presentation.Sanitize(result.Reference.Section), result.Reference.Pages)
	return builder.String()
}

func resultDetailText(details []model.ResultDetail, width int, status model.Status) string {
	sections := make([]string, 0, len(details))
	for _, detail := range details {
		var section strings.Builder
		section.WriteString(keyStyle.Render(presentation.Sanitize(detail.Label)))
		section.WriteByte('\n')
		if detail.Expected != "" {
			section.WriteByte('\n')
			section.WriteString(detailValueLine("기준", detail.Expected, width, detailLineStyle(status, true)))
		}
		if detail.Current != "" {
			section.WriteByte('\n')
			section.WriteString(detailValueLine("현재", detail.Current, width, detailLineStyle(status, false)))
		}
		if detail.Source != "" {
			section.WriteByte('\n')
			section.WriteString(detailValueLine("위치", detail.Source, width, nil))
		}
		sections = append(sections, section.String())
	}
	return strings.Join(sections, "\n\n")
}

func detailLineStyle(status model.Status, expected bool) *lipgloss.Style {
	if status != model.StatusFail {
		return nil
	}
	style := errorStyle
	if expected {
		style = successStyle
	}
	return &style
}

func detailValueLine(label, value string, width int, emphasis *lipgloss.Style) string {
	const labelWidth = 6
	wrapped := semanticDetailText(value, width-labelWidth)
	wrapped = strings.ReplaceAll(wrapped, "\n", "\n"+strings.Repeat(" ", labelWidth))
	label = presentation.Sanitize(label)
	labelText := labelStyle.Render(label)
	if emphasis != nil {
		labelText = emphasis.Copy().Bold(true).Render(label)
		wrapped = emphasis.Render(wrapped)
	}
	return labelText + strings.Repeat(" ", labelWidth-lipgloss.Width(labelText)) + wrapped
}

func observedDetailText(value string, width int) string {
	return semanticDetailText(value, width)
}

func semanticDetailText(value string, width int) string {
	items := splitDetailItems(value)
	if len(items) <= 1 {
		return wrapDetailText(value, width)
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		wrapped := wrapDetailText(item, width-2)
		wrapped = strings.ReplaceAll(wrapped, "\n", "\n  ")
		lines = append(lines, "- "+wrapped)
	}
	return strings.Join(lines, "\n")
}

func splitDetailItems(value string) []string {
	lines := strings.Split(presentation.Sanitize(value), "\n")
	items := make([]string, 0, len(lines))
	for _, line := range lines {
		for _, item := range strings.Split(line, "; ") {
			if item = strings.TrimSpace(item); item != "" {
				items = append(items, item)
			}
		}
	}
	return items
}

func wrapDetailText(value string, width int) string {
	if width < 20 {
		width = 20
	}
	return ansi.Wrap(strings.TrimSpace(presentation.Sanitize(value)), width, "")
}

func remediationPlanContent(planned workflow.PlanResult, approved bool) string {
	if planned.Journal == nil {
		return "조치 계획이 없습니다."
	}
	value := planned.Journal
	var builder strings.Builder
	stateLabel := "승인 전 dry-run"
	if approved {
		stateLabel = "승인 완료, 적용 전"
	}
	fmt.Fprintf(&builder, "조치 계획 (%s)\n\n", stateLabel)
	fmt.Fprintf(&builder, "실행 ID: %s\n점검 실행 ID: %s\n실패 정책: %s\nplan digest: %s\n\n", value.RunID, value.ScanRunID, value.FailurePolicy, value.PlanDigest)
	for _, changeSet := range value.ChangeSets {
		fmt.Fprintf(&builder, "[%s] %s (%s)\n", changeSet.RuleID, changeSet.ID, changeSet.Risk)
		fmt.Fprintf(&builder, "예상 영향: %s\n", changeSet.ExpectedImpact)
		fmt.Fprintf(&builder, "dry-run:\n%s\n", changeSet.DryRun)
		if changeSet.RollbackGroup != "" {
			fmt.Fprintf(&builder, "롤백 그룹: %s\n", changeSet.RollbackGroup)
		}
		builder.WriteString("\n")
	}
	if len(planned.Skipped) > 0 {
		builder.WriteString("제외 항목\n")
		for _, item := range planned.Skipped {
			fmt.Fprintf(&builder, "- %s\n", item)
		}
	}
	if !approved {
		builder.WriteString("\n이 화면은 dry-run이며 시스템을 변경하지 않았습니다.\n")
	} else {
		builder.WriteString("\n승인 정보만 저널에 기록했으며 시스템 파일은 아직 변경하지 않았습니다.\n")
	}
	return presentation.Sanitize(builder.String())
}

func remediationApprovalConfirmation(planned workflow.PlanResult) string {
	if planned.Journal == nil {
		return errorStyle.Render("승인할 계획이 없습니다.")
	}
	details := fmt.Sprintf(
		"변경 세트: %d개\n실패 정책: %s\nplan digest:\n%s\n\n이 승인은 digest에 고정된 dry-run과 예상 영향을 승인 저널에 기록합니다.\n아직 실제 변경은 수행하지 않습니다.",
		len(planned.Journal.ChangeSets),
		planned.Journal.FailurePolicy,
		planned.Journal.PlanDigest,
	)
	return titleStyle.Render("조치 계획 승인 확인") + "\n\n" + presentation.Sanitize(details)
}

func remediationApplyConfirmation(planned workflow.PlanResult) string {
	if planned.Journal == nil {
		return errorStyle.Render("적용할 승인 계획이 없습니다.")
	}
	details := fmt.Sprintf(
		"실행 ID: %s\n변경 세트: %d개\n실패 정책: %s\n\n변경 직전에 현재 상태를 다시 확인하고 내구성 백업과 WAL intent를 기록합니다.\n각 변경 후 검증하며 실패 시 지정된 범위로 롤백합니다.",
		planned.Journal.RunID,
		len(planned.Journal.ChangeSets),
		planned.Journal.FailurePolicy,
	)
	return titleStyle.Render("실제 조치 적용 확인") + "\n\n" + presentation.Sanitize(details)
}

func remediationStatusContent(value *model.RemediationJournal, attempt model.RollbackAttempt, selected int) string {
	if value == nil {
		return errorStyle.Render("표시할 조치 저널이 없습니다.")
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "조치 실행 상태\n\n실행 ID: %s\nrevision: %d\n상태: %s\n실패 정책: %s\n\n", value.RunID, value.Revision, value.State, value.FailurePolicy)
	for index, changeSet := range value.ChangeSets {
		marker := "  "
		if index == selected {
			marker = "> "
		}
		fmt.Fprintf(&builder, "%s%s %s: %s\n", marker, changeSet.RuleID, changeSet.ID, changeSet.State)
	}
	if len(value.UnresolvedChangeSets) > 0 {
		fmt.Fprintf(&builder, "\n미해결 변경 세트: %s\n", strings.Join(value.UnresolvedChangeSets, ", "))
	}
	if value.Error != nil {
		fmt.Fprintf(&builder, "\n저널 오류: %s\n%s\n", value.Error.Code, value.Error.Message)
	}
	if len(value.Warnings) > 0 {
		fmt.Fprintf(&builder, "\n주의 사항\n- %s\n", strings.Join(value.Warnings, "\n- "))
	}
	if attempt.ID != "" {
		fmt.Fprintf(&builder, "\n최근 롤백 시도: %s\n범위: %s\n결과: %s\n확장 범위: %s\n", attempt.ID, attempt.Scope, attempt.Outcome, strings.Join(attempt.ExpandedChangeSets, ", "))
	}
	return presentation.Sanitize(builder.String())
}

func remediationErrorContent(value *model.RemediationJournal, remediationErr error, redactSensitive bool) string {
	content := errorStyle.Render("조치 또는 롤백을 완료하지 못했습니다.") + "\n\n" + protectedDisplayText(fmt.Sprint(remediationErr), redactSensitive)
	if value == nil {
		return content
	}
	content += protectedDisplayText(fmt.Sprintf("\n\n실행 ID: %s\n현재 상태: %s", value.RunID, value.State), redactSensitive)
	if value.State == model.RunPlanned || value.State == model.RunApproved || value.State == model.RunCancelFailed {
		content += protectedDisplayText(fmt.Sprintf("\n\n상태 확인: openciip remediate status %s\n계획 폐기 재시도: openciip remediate cancel %s --yes", value.RunID, value.RunID), redactSensitive)
	} else if value.State.NeedsOperatorAction() || value.State == model.RunApplying || value.State == model.RunVerifying || value.State == model.RunRollingBack || value.State == model.RunCanceling {
		content += protectedDisplayText(fmt.Sprintf("\n\n상태 확인: openciip remediate status %s\n복구 판정: openciip remediate recover %s --yes", value.RunID, value.RunID), redactSensitive)
	}
	return content
}

func protectedDisplayText(value string, redactSensitive bool) string {
	if redactSensitive {
		value = redact.Text(value)
	}
	return presentation.Sanitize(value)
}

func remediationCancelConfirmation(value *model.RemediationJournal) string {
	if value == nil {
		return errorStyle.Render("폐기할 조치 계획이 없습니다.")
	}
	details := fmt.Sprintf(
		"실행 ID: %s\n현재 상태: %s\nplan digest: %s\n\n시스템 파일을 적용한 적이 없는 planned/approved 계획만 폐기합니다.\n저널은 canceled 증적으로 보존하고 미사용 desired payload만 내구성 있게 삭제합니다.",
		value.RunID,
		value.State,
		value.PlanDigest,
	)
	return titleStyle.Render("적용 전 조치 계획 폐기 확인") + "\n\n" + presentation.Sanitize(details)
}

func remediationRollbackPreviewContent(value orchestrator.RollbackPreview, runScope bool) string {
	if value.RunID == "" || value.PreviewDigest == "" {
		return errorStyle.Render("표시할 롤백 미리보기가 없습니다.")
	}
	scope := "항목별"
	if runScope {
		scope = "실행 전체"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s 롤백 미리보기\n\n", scope)
	fmt.Fprintf(&builder, "실행 ID: %s\nrevision: %d\ncascade 필요: %t\npreview digest: %s\n\n", value.RunID, value.Revision, value.CascadeRequired, value.PreviewDigest)
	writeTUIList(&builder, "요청 변경 세트", value.RequestedChangeSets, false)
	writeTUIList(&builder, "실제 롤백 범위", value.ExpandedChangeSets, false)
	writeTUIList(&builder, "롤백 실행 순서", value.ExecutionOrder, true)
	builder.WriteString("\n이 화면은 읽기 전용 미리보기이며 아직 시스템을 변경하지 않았습니다.")
	return presentation.Sanitize(builder.String())
}

func remediationRollbackConfirmation(value orchestrator.RollbackPreview, runScope bool) string {
	if value.RunID == "" || value.PreviewDigest == "" {
		return errorStyle.Render("승인할 롤백 미리보기가 없습니다.")
	}
	scope := "항목별"
	if runScope {
		scope = "실행 전체"
	}
	details := fmt.Sprintf(
		"실행 ID: %s\nrevision: %d\n실제 범위: %d개\ncascade 필요: %t\npreview digest:\n%s\n\n현재 revision에서 범위와 순서를 다시 계산하여 digest가 일치할 때만 실행합니다. 범위가 달라지면 새 미리보기를 요구합니다.",
		value.RunID,
		value.Revision,
		len(value.ExpandedChangeSets),
		value.CascadeRequired,
		value.PreviewDigest,
	)
	return titleStyle.Render(scope+" 롤백 승인 확인") + "\n\n" + presentation.Sanitize(details)
}

func writeTUIList(builder *strings.Builder, title string, values []string, ordered bool) {
	if len(values) == 0 {
		return
	}
	builder.WriteString(title + "\n")
	for index, value := range values {
		if ordered {
			fmt.Fprintf(builder, "%d. %s\n", index+1, value)
		} else {
			fmt.Fprintf(builder, "- %s\n", value)
		}
	}
	builder.WriteString("\n")
}

func Run(ctx context.Context, input io.Reader, output io.Writer, scanner Scanner, writer ScanWriter) (int, error) {
	return RunWithRemediation(ctx, input, output, scanner, writer, nil)
}

func RunWithRemediation(ctx context.Context, input io.Reader, output io.Writer, scanner Scanner, writer ScanWriter, factory RemediatorFactory) (code int, runErr error) {
	initial := NewModelWithRemediation(ctx, scanner, writer, factory)
	return runProgram(ctx, input, output, initial)
}

func RunWithWriterFactory(ctx context.Context, input io.Reader, output io.Writer, scanner Scanner, writerFactory ScanWriterFactory, factory RemediatorFactory) (code int, runErr error) {
	initial := NewModelWithWriterFactory(ctx, scanner, writerFactory, factory)
	return runProgram(ctx, input, output, initial)
}

func runProgram(ctx context.Context, input io.Reader, output io.Writer, initial *Model) (code int, runErr error) {
	defer func() {
		if err := initial.closeRemediator(); err != nil {
			code = exitcode.Error
			runErr = errors.Join(runErr, fmt.Errorf("조치 workflow를 닫지 못했습니다: %w", err))
		}
	}()
	program := tea.NewProgram(
		initial,
		tea.WithContext(ctx),
		tea.WithInput(input),
		tea.WithOutput(output),
	)
	final, err := program.Run()
	if err != nil {
		return exitcode.Error, err
	}
	model, ok := final.(*Model)
	if !ok {
		return exitcode.Error, fmt.Errorf("TUI가 알 수 없는 최종 상태를 반환했습니다")
	}
	return model.exitCode, nil
}

func (m *Model) replaceRemediator(next Remediator) error {
	if m == nil {
		return closeRemediator(next)
	}
	previous := m.remediator
	m.remediator = next
	return closeRemediator(previous)
}

func (m *Model) closeRemediator() error {
	if m == nil {
		return nil
	}
	current := m.remediator
	m.remediator = nil
	return closeRemediator(current)
}

func closeRemediator(remediator Remediator) error {
	closer, ok := remediator.(interface{ Close() error })
	if !ok || closer == nil {
		return nil
	}
	return closer.Close()
}

var (
	accentColor   = lipgloss.Color("#58A6FF")
	textColor     = lipgloss.Color("#E6EDF3")
	mutedColor    = lipgloss.Color("#7D8590")
	borderColor   = lipgloss.Color("#30363D")
	selectedColor = lipgloss.Color("#161B22")
	successColor  = lipgloss.Color("#3FB950")
	warningColor  = lipgloss.Color("#D29922")
	errorColor    = lipgloss.Color("#F85149")

	frameStyle           = lipgloss.NewStyle().Padding(1, 2)
	titleStyle           = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	subtitleStyle        = lipgloss.NewStyle().Foreground(mutedColor)
	detailTitleStyle     = lipgloss.NewStyle().Bold(true).Foreground(textColor)
	labelStyle           = lipgloss.NewStyle().Bold(true).Foreground(mutedColor)
	codeStyle            = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	helpStyle            = lipgloss.NewStyle().Foreground(mutedColor)
	errorStyle           = lipgloss.NewStyle().Bold(true).Foreground(errorColor)
	warningStyle         = lipgloss.NewStyle().Bold(true).Foreground(warningColor)
	accentStyle          = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	successStyle         = lipgloss.NewStyle().Bold(true).Foreground(successColor)
	keyStyle             = lipgloss.NewStyle().Bold(true).Foreground(textColor)
	sectionStyle         = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	selectedRowStyle     = lipgloss.NewStyle().Background(selectedColor)
	keyCapStyle          = lipgloss.NewStyle().Bold(true).Foreground(textColor).Background(borderColor).Padding(0, 1)
	disabledStyle        = lipgloss.NewStyle().Foreground(mutedColor)
	statusRuleStyle      = lipgloss.NewStyle().Foreground(borderColor)
	counterStyle         = lipgloss.NewStyle().Bold(true).Foreground(textColor)
	percentStyle         = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	progressDoneStyle    = lipgloss.NewStyle().Foreground(accentColor)
	progressPendingStyle = lipgloss.NewStyle().Foreground(borderColor)

	statusStyle     = lipgloss.NewStyle().Bold(true)
	errorPanelStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(errorColor).
			Padding(1, 2)
	quitPanelStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Padding(1, 2)

	spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
)

const (
	openCIIPLogoWidth = 45
	openCIIPLogo      = `   ____                   __________________
  / __ \____  ___  ____  / ____/  _/  _/ __ \
 / / / / __ \/ _ \/ __ \/ /    / / / // /_/ /
/ /_/ / /_/ /  __/ / / / /____/ /_/ // ____/
\____/ .___/\___/_/ /_/\____/___/___/_/
    /_/`
)
