package tui

import (
	"context"
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/yesidodo73/OpenCIIP/internal/engine"
	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/orchestrator"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/workflow"
)

type Scanner interface {
	Scan(context.Context, engine.Options) (model.ScanRun, error)
}

type ScanWriter interface {
	WriteScan(context.Context, model.ScanRun) (string, error)
}

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

type screen int

const (
	screenReady screen = iota
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

func (i resultItem) Title() string {
	return fmt.Sprintf("%-18s %s  %s", i.result.Status, i.result.RuleID, i.result.Title)
}

func (i resultItem) Description() string { return i.result.Summary }
func (i resultItem) FilterValue() string {
	return i.result.RuleID + " " + i.result.Title + " " + string(i.result.Status)
}

type Model struct {
	ctx               context.Context
	scanner           Scanner
	writer            ScanWriter
	remediatorFactory RemediatorFactory
	remediator        Remediator
	cancelScan        context.CancelFunc
	cancelAction      context.CancelFunc
	screen            screen
	width             int
	height            int
	showAll           bool
	run               model.ScanRun
	reportPath        string
	list              list.Model
	viewport          viewport.Model
	err               error
	remediationErr    error
	plan              workflow.PlanResult
	journal           *model.RemediationJournal
	rollback          model.RollbackAttempt
	rollbackPreview   orchestrator.RollbackPreview
	rollbackRunScope  bool
	rollbackChangeSet string
	failurePolicy     model.FailurePolicy
	cancelReturn      screen
	selectedChangeSet int
	exitCode          int
}

func NewModel(ctx context.Context, scanner Scanner, writer ScanWriter) *Model {
	return NewModelWithRemediation(ctx, scanner, writer, nil)
}

func NewModelWithRemediation(ctx context.Context, scanner Scanner, writer ScanWriter, factory RemediatorFactory) *Model {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	resultList := list.New(nil, delegate, 80, 20)
	resultList.Title = "점검 결과"
	resultList.SetFilteringEnabled(true)
	resultList.SetShowStatusBar(true)
	resultList.SetStatusBarItemName("항목", "항목")
	detail := viewport.New()
	detail.SoftWrap = true
	return &Model{
		ctx:               ctx,
		scanner:           scanner,
		writer:            writer,
		remediatorFactory: factory,
		screen:            screenReady,
		list:              resultList,
		viewport:          detail,
		failurePolicy:     model.FailureRollbackItem,
		exitCode:          exitcode.OK,
	}
}

func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		m.resize()
		return m, nil
	case scanCompleteMsg:
		m.cancelScan = nil
		if message.err != nil {
			m.err = message.err
			m.exitCode = exitcode.Error
			m.screen = screenError
			return m, nil
		}
		m.run = message.run
		m.reportPath = message.reportPath
		m.exitCode = message.run.Metadata.ExitCode
		m.screen = screenResults
		m.updateItems()
		return m, nil
	case remediationPlanMsg:
		m.cancelAction = nil
		if message.remediator != nil {
			m.remediator = message.remediator
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
				return m, nil
			}
			m.remediationErr = message.err
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m, nil
		}
		m.viewport.SetContent(remediationPlanContent(message.plan, false))
		m.viewport.GotoTop()
		m.screen = screenRemediationPlan
		return m, nil
	case remediationJournalMsg:
		completedScreen := m.screen
		m.cancelAction = nil
		if message.journal != nil {
			m.journal = message.journal
		}
		if message.err != nil {
			m.remediationErr = message.err
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m, nil
		}
		if completedScreen == screenRemediationApproving {
			m.viewport.SetContent(remediationPlanContent(m.plan, true))
			m.viewport.GotoTop()
			m.screen = screenRemediationApproved
		} else {
			m.screen = screenRemediationStatus
		}
		return m, nil
	case remediationRollbackPreviewMsg:
		m.cancelAction = nil
		if message.err != nil {
			m.remediationErr = message.err
			m.exitCode = exitcode.Error
			m.screen = screenRemediationError
			return m, nil
		}
		m.rollbackPreview = message.preview
		m.rollbackRunScope = message.runScope
		m.rollbackChangeSet = message.changeSetID
		m.viewport.SetContent(remediationRollbackPreviewContent(message.preview, message.runScope))
		m.viewport.GotoTop()
		m.screen = screenRemediationRollbackPreview
		return m, nil
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
			return m, nil
		}
		m.screen = screenRemediationStatus
		return m, nil
	case tea.KeyPressMsg:
		key := message.String()
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
		if key == "q" {
			if m.cancelScan != nil {
				m.cancelScan()
				return m, tea.Quit
			}
			if m.cancelAction != nil {
				m.cancelAction()
				return m, nil
			}
			if m.hasUnusedRemediationPlan() {
				if m.screen != screenRemediationConfirmCancel {
					m.cancelReturn = m.screen
					m.screen = screenRemediationConfirmCancel
				}
				return m, nil
			}
			return m, tea.Quit
		}
		switch m.screen {
		case screenReady:
			if key == "enter" || key == "s" {
				return m.startScan()
			}
		case screenResults:
			switch key {
			case "a":
				m.showAll = !m.showAll
				m.updateItems()
				return m, nil
			case "enter":
				selected, ok := m.list.SelectedItem().(resultItem)
				if ok {
					m.viewport.SetContent(detailContent(selected.result))
					m.viewport.GotoTop()
					m.screen = screenDetail
				}
				return m, nil
			case "r":
				return m.startScan()
			case "m":
				if m.canPlanRemediation() {
					m.failurePolicy = model.FailureRollbackItem
					m.screen = screenRemediationFailurePolicy
				}
			}
		case screenDetail:
			if key == "esc" || key == "backspace" {
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
			case "esc", "backspace":
				m.screen = screenResults
				return m, nil
			}
		case screenRemediationPlan:
			switch key {
			case "a":
				m.screen = screenRemediationConfirmApproval
				return m, nil
			case "c", "esc", "backspace":
				m.cancelReturn = screenRemediationPlan
				m.screen = screenRemediationConfirmCancel
				return m, nil
			}
		case screenRemediationConfirmApproval:
			switch key {
			case "y":
				return m.startRemediationApproval()
			case "n", "esc", "backspace":
				m.screen = screenRemediationPlan
				return m, nil
			}
		case screenRemediationApproved:
			switch key {
			case "x":
				m.screen = screenRemediationConfirmApply
				return m, nil
			case "c", "esc", "backspace":
				m.cancelReturn = screenRemediationApproved
				m.screen = screenRemediationConfirmCancel
				return m, nil
			}
		case screenRemediationConfirmApply:
			switch key {
			case "y":
				return m.startRemediationApply()
			case "n", "esc", "backspace":
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
			case "esc", "backspace":
				m.screen = screenResults
				return m, nil
			}
		case screenRemediationRollbackPreview:
			switch key {
			case "r":
				m.screen = screenRemediationConfirmRollback
				return m, nil
			case "esc", "backspace":
				m.screen = screenRemediationStatus
				return m, nil
			}
		case screenRemediationConfirmRollback:
			switch key {
			case "y":
				return m.startApprovedRollback()
			case "n", "esc", "backspace":
				m.screen = screenRemediationRollbackPreview
				return m, nil
			}
		case screenRemediationConfirmCancel:
			switch key {
			case "y":
				return m.startRemediationCancel()
			case "n", "esc", "backspace":
				m.screen = m.cancelReturn
				return m, nil
			}
		case screenRemediationError:
			if key == "esc" || key == "backspace" {
				if m.journal != nil {
					m.screen = screenRemediationStatus
				} else {
					m.screen = screenResults
				}
				return m, nil
			}
		case screenError:
			if key == "r" {
				return m.startScan()
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

func (m *Model) View() tea.View {
	var content string
	switch m.screen {
	case screenReady:
		content = titleStyle.Render("OpenCIIP") + "\n\n" +
			"Rocky Linux 9.8 대상 2026 Unix 서버 취약점 점검을 시작합니다.\n" +
			"점검은 기본적으로 시스템을 변경하지 않습니다.\n\n" +
			helpStyle.Render("Enter 또는 s: 점검 시작   q: 종료")
	case screenScanning:
		content = titleStyle.Render("OpenCIIP") + "\n\n시스템을 점검하고 있습니다. 완료될 때까지 기다려 주십시오.\n\n" + helpStyle.Render("q: 점검 취소 및 종료")
	case screenResults:
		header := "문제 항목"
		if m.showAll {
			header = "전체 항목"
		}
		m.list.Title = "점검 결과 - " + header
		help := "Enter: 상세   a: 전체/문제 전환   /: 검색   r: 다시 점검"
		if m.canPlanRemediation() {
			help += "   m: 조치 dry-run"
		}
		help += "   q: 종료"
		content = m.list.View() + "\n" + helpStyle.Render(help)
		if m.reportPath != "" {
			content += "\n" + helpStyle.Render("보고서: "+m.reportPath)
		}
	case screenDetail:
		content = m.viewport.View() + "\n" + helpStyle.Render("Esc: 결과 목록   q: 종료")
	case screenRemediationFailurePolicy:
		content = titleStyle.Render("조치 실패 정책 선택") + "\n\n" +
			"변경 세트 적용 또는 검증이 실패했을 때의 자동 롤백 범위를 선택해 주십시오.\n\n" +
			"i  rollback_item: 실패한 항목 변경 세트만 복원합니다.\n" +
			"r  rollback_run: 실패한 항목을 복원한 뒤 앞서 적용한 실행 전체를 역순으로 복원합니다.\n\n" +
			helpStyle.Render("i: 항목 단위   r: 실행 전체   Esc: 돌아가기   q: 종료")
	case screenRemediationPlanning:
		content = titleStyle.Render("조치 dry-run 생성") + "\n\n점검 보고서와 현재 호스트를 재검증하고 변경 계획을 만들고 있습니다.\n시스템 파일은 변경하지 않습니다.\n\n" + helpStyle.Render("q 또는 Ctrl+C: 안전한 작업 취소 요청")
	case screenRemediationPlan:
		content = m.viewport.View() + "\n" + helpStyle.Render("a: plan digest 확인 및 승인 단계   c 또는 Esc: 계획 폐기   q: 계획 폐기 확인")
	case screenRemediationConfirmApproval:
		content = remediationApprovalConfirmation(m.plan) + "\n\n" + helpStyle.Render("y: 이 계획 승인   n 또는 Esc: 돌아가기")
	case screenRemediationApproving:
		content = titleStyle.Render("조치 계획 승인") + "\n\n승인 정보를 내구성 저널에 기록하고 있습니다.\n아직 시스템 파일은 변경하지 않습니다.\n\n" + helpStyle.Render("q 또는 Ctrl+C: 안전한 작업 취소 요청")
	case screenRemediationApproved:
		content = m.viewport.View() + "\n" + helpStyle.Render("x: 실제 적용 단계   c 또는 Esc: 승인 계획 폐기   q: 계획 폐기 확인")
	case screenRemediationConfirmApply:
		content = remediationApplyConfirmation(m.plan) + "\n\n" + helpStyle.Render("y: 백업 후 실제 적용·검증   n 또는 Esc: 돌아가기")
	case screenRemediationApplying:
		content = titleStyle.Render("조치 적용 및 검증") + "\n\n변경 전 백업, write-ahead 저널 기록, 변경 후 검증을 순차 실행하고 있습니다.\n실패하면 선택한 실패 정책에 따라 롤백합니다.\n\n" + helpStyle.Render("q 또는 Ctrl+C: 안전한 중단 요청 후 저널 기록 완료 대기")
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
		content = remediationStatusContent(m.journal, m.rollback, m.selectedChangeSet) + "\n" + helpStyle.Render(help+"   Esc: 점검 결과   q: 종료")
	case screenRemediationConfirmCancel:
		content = remediationCancelConfirmation(m.journal) + "\n\n" + helpStyle.Render("y: 계획과 미사용 payload 폐기   n 또는 Esc: 돌아가기")
	case screenRemediationCanceling:
		content = titleStyle.Render("조치 계획 폐기") + "\n\n적용되지 않은 desired payload를 격리·삭제하고 취소 상태를 저널에 기록하고 있습니다.\n\n" + helpStyle.Render("q 또는 Ctrl+C: 안전한 작업 취소 요청")
	case screenRemediationRollbackPreviewing:
		content = titleStyle.Render("롤백 범위 계산") + "\n\n현재 저널 revision에서 공유 자원과 의존 관계를 다시 계산하고 있습니다.\n아직 시스템 파일은 변경하지 않습니다.\n\n" + helpStyle.Render("q 또는 Ctrl+C: 안전한 작업 취소 요청")
	case screenRemediationRollbackPreview:
		content = m.viewport.View() + "\n\n" + helpStyle.Render("r: 표시 범위 승인 단계   Esc: 현재 상태로 돌아가기   q: 종료")
	case screenRemediationConfirmRollback:
		content = remediationRollbackConfirmation(m.rollbackPreview, m.rollbackRunScope) + "\n\n" + helpStyle.Render("y: digest에 고정된 범위 롤백   n 또는 Esc: 돌아가기")
	case screenRemediationRollingBack:
		content = titleStyle.Render("롤백 실행") + "\n\n백업과 현재 상태를 재검증한 뒤 승인된 역순으로 복원하고 있습니다.\n독립적인 분기는 다른 분기의 실패와 관계없이 계속 시도합니다.\n\n" + helpStyle.Render("q 또는 Ctrl+C: 안전한 중단 요청 후 저널 기록 완료 대기")
	case screenRemediationError:
		content = remediationErrorContent(m.journal, m.remediationErr) + "\n\n" + helpStyle.Render("Esc: 현재 저널 또는 점검 결과로 돌아가기   q: 종료")
	case screenError:
		content = errorStyle.Render("점검을 완료하지 못했습니다.") + "\n\n" + fmt.Sprint(m.err) + "\n\n" + helpStyle.Render("r: 다시 시도   q: 종료")
	}
	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "OpenCIIP"
	return view
}

func (m *Model) startScan() tea.Cmd {
	if m.cancelScan != nil {
		return nil
	}
	scanContext, cancel := context.WithCancel(m.ctx)
	m.cancelScan = cancel
	m.screen = screenScanning
	m.err = nil
	return func() tea.Msg {
		run, err := m.scanner.Scan(scanContext, engine.Options{EvidenceMode: "problems"})
		if err != nil {
			return scanCompleteMsg{err: err}
		}
		path, err := m.writer.WriteScan(scanContext, run)
		return scanCompleteMsg{run: run, reportPath: path, err: err}
	}
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
		return remediationPlanMsg{remediator: remediator, plan: planned, err: err}
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
	if m.remediatorFactory == nil || m.reportPath == "" || m.run.Metadata.Platform.Support != model.SupportVerified {
		return false
	}
	for _, result := range m.run.Results {
		if result.Status == model.StatusFail && result.Verification.State == model.VerificationVerified {
			return true
		}
	}
	return false
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
	width := m.width
	if width < 40 {
		width = 40
	}
	height := m.height - 4
	if height < 8 {
		height = 8
	}
	m.list.SetSize(width, height)
	m.viewport.SetWidth(width)
	m.viewport.SetHeight(height)
}

func (m *Model) updateItems() {
	items := make([]list.Item, 0, len(m.run.Results))
	for _, result := range m.run.Results {
		if !m.showAll && result.Status != model.StatusFail && result.Status != model.StatusUnknown && result.Status != model.StatusError {
			continue
		}
		items = append(items, resultItem{result: result})
	}
	m.list.SetItems(items)
}

func detailContent(result model.CheckResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s %s\n\n", result.RuleID, result.Title)
	fmt.Fprintf(&builder, "상태: %s\n중요도: %s\n분류: %s\n\n", result.Status, result.Severity, result.Category)
	fmt.Fprintf(&builder, "플랫폼 검증 상태: %s\n", result.Verification.State)
	if len(result.BindingSources) > 0 {
		fmt.Fprintf(&builder, "규칙 계층: %s\n", strings.Join(result.BindingSources, " → "))
	}
	builder.WriteString("\n")
	fmt.Fprintf(&builder, "판정 이유\n%s\n\n", result.Summary)
	if result.Expected != "" {
		fmt.Fprintf(&builder, "기준\n%s\n\n", result.Expected)
	}
	if result.Observed != "" {
		fmt.Fprintf(&builder, "확인 결과\n%s\n\n", result.Observed)
	}
	if result.UnknownReason != "" {
		fmt.Fprintf(&builder, "확정 불가 사유: %s\n\n", result.UnknownReason)
	}
	fmt.Fprintf(&builder, "가이드 근거\n%s, %v쪽\n", result.Reference.Section, result.Reference.Pages)
	return builder.String()
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
	return builder.String()
}

func remediationApprovalConfirmation(planned workflow.PlanResult) string {
	if planned.Journal == nil {
		return errorStyle.Render("승인할 계획이 없습니다.")
	}
	return titleStyle.Render("조치 계획 승인 확인") + "\n\n" +
		fmt.Sprintf("변경 세트: %d개\n실패 정책: %s\nplan digest:\n%s\n\n이 승인은 digest에 고정된 dry-run과 예상 영향을 승인 저널에 기록합니다.\n아직 실제 변경은 수행하지 않습니다.",
			len(planned.Journal.ChangeSets), planned.Journal.FailurePolicy, planned.Journal.PlanDigest)
}

func remediationApplyConfirmation(planned workflow.PlanResult) string {
	if planned.Journal == nil {
		return errorStyle.Render("적용할 승인 계획이 없습니다.")
	}
	return titleStyle.Render("실제 조치 적용 확인") + "\n\n" +
		fmt.Sprintf("실행 ID: %s\n변경 세트: %d개\n실패 정책: %s\n\n변경 직전에 현재 상태를 다시 확인하고 내구성 백업과 WAL intent를 기록합니다.\n각 변경 후 검증하며 실패 시 지정된 범위로 롤백합니다.",
			planned.Journal.RunID, len(planned.Journal.ChangeSets), planned.Journal.FailurePolicy)
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
	return builder.String()
}

func remediationErrorContent(value *model.RemediationJournal, remediationErr error) string {
	content := errorStyle.Render("조치 또는 롤백을 완료하지 못했습니다.") + "\n\n" + fmt.Sprint(remediationErr)
	if value == nil {
		return content
	}
	content += fmt.Sprintf("\n\n실행 ID: %s\n현재 상태: %s", value.RunID, value.State)
	if value.State == model.RunPlanned || value.State == model.RunApproved || value.State == model.RunCancelFailed {
		content += fmt.Sprintf("\n\n상태 확인: openciip remediate status %s\n계획 폐기 재시도: openciip remediate cancel %s --yes", value.RunID, value.RunID)
	} else if value.State.NeedsOperatorAction() || value.State == model.RunApplying || value.State == model.RunVerifying || value.State == model.RunRollingBack || value.State == model.RunCanceling {
		content += fmt.Sprintf("\n\n상태 확인: openciip remediate status %s\n복구 판정: openciip remediate recover %s --yes", value.RunID, value.RunID)
	}
	return content
}

func remediationCancelConfirmation(value *model.RemediationJournal) string {
	if value == nil {
		return errorStyle.Render("폐기할 조치 계획이 없습니다.")
	}
	return titleStyle.Render("적용 전 조치 계획 폐기 확인") + "\n\n" +
		fmt.Sprintf("실행 ID: %s\n현재 상태: %s\nplan digest: %s\n\n시스템 파일을 적용한 적이 없는 planned/approved 계획만 폐기합니다.\n저널은 canceled 증적으로 보존하고 미사용 desired payload만 내구성 있게 삭제합니다.",
			value.RunID, value.State, value.PlanDigest)
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
	return builder.String()
}

func remediationRollbackConfirmation(value orchestrator.RollbackPreview, runScope bool) string {
	if value.RunID == "" || value.PreviewDigest == "" {
		return errorStyle.Render("승인할 롤백 미리보기가 없습니다.")
	}
	scope := "항목별"
	if runScope {
		scope = "실행 전체"
	}
	return titleStyle.Render(scope+" 롤백 승인 확인") + "\n\n" +
		fmt.Sprintf("실행 ID: %s\nrevision: %d\n실제 범위: %d개\ncascade 필요: %t\npreview digest:\n%s\n\n현재 revision에서 범위와 순서를 다시 계산하여 digest가 일치할 때만 실행합니다. 범위가 달라지면 새 미리보기를 요구합니다.",
			value.RunID, value.Revision, len(value.ExpandedChangeSets), value.CascadeRequired, value.PreviewDigest)
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

func RunWithRemediation(ctx context.Context, input io.Reader, output io.Writer, scanner Scanner, writer ScanWriter, factory RemediatorFactory) (int, error) {
	program := tea.NewProgram(
		NewModelWithRemediation(ctx, scanner, writer, factory),
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

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5FAFFF"))
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#808080"))
	errorStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5F5F"))
)
