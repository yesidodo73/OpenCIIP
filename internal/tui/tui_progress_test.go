package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/yesidodo73/OpenCIIP/internal/engine"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestDurationLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value time.Duration
		want  string
	}{
		{value: 9 * time.Second, want: "9초"},
		{value: time.Minute + 5*time.Second, want: "1분 05초"},
		{value: time.Hour + 2*time.Minute + 3*time.Second, want: "1시간 02분 03초"},
	}
	for _, test := range tests {
		if got := durationLabel(test.value); got != test.want {
			t.Errorf("durationLabel(%s) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestScanningPanelDoesNotJumpBetweenPreparationAndProgress(t *testing.T) {
	started := time.Date(2026, time.July, 12, 0, 0, 0, 0, time.UTC)
	view := &Model{width: 100, height: 36, scanStarted: started, now: func() time.Time { return started.Add(time.Second) }}
	preparation := ansi.Strip(view.scanningView())
	view.scanProgress = engine.Progress{Completed: 1, Total: 20, RuleID: "U-01", Title: "root 계정"}
	progress := ansi.Strip(view.scanningView())
	positions := func(content string) (int, int) {
		top, bottom := -1, -1
		for i, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "╭─ 점검 진행") {
				top = i
			}
			if strings.Contains(line, "╰") {
				bottom = i
			}
		}
		return top, bottom
	}
	prepTop, prepBottom := positions(preparation)
	runTop, runBottom := positions(progress)
	if prepTop < 0 || prepTop != runTop || prepBottom != runBottom {
		t.Fatalf("panel moved: preparing %d..%d, running %d..%d", prepTop, prepBottom, runTop, runBottom)
	}
	if !strings.Contains(preparation, "준비") || !strings.Contains(progress, "1 / 20") {
		t.Fatalf("progress states missing: preparing=%q running=%q", preparation, progress)
	}
}

func TestScanCompletionWaitsForResultConfirmation(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 100, 30
	view.screen = screenScanning
	view.scanStarted = time.Now()
	view.scanProgress = engine.Progress{Completed: 1, Total: 2}
	run := model.ScanRun{Metadata: model.RunMetadata{Complete: true}, Results: []model.CheckResult{
		{RuleID: "U-01", Status: model.StatusFail}, {RuleID: "U-02", Status: model.StatusPass},
	}}
	view.Update(scanCompleteMsg{run: run, reportPath: "/reports/fixture"})
	if view.screen != screenScanning {
		t.Fatalf("scan jumped directly to screen %d", view.screen)
	}
	content := ansi.Strip(view.scanningView())
	for _, expected := range []string{"점검 완료", "2 / 2", "100%", "Enter", "결과 보기"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("completion view is missing %q: %q", expected, content)
		}
	}
	view.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	if view.screen != screenResults {
		t.Fatalf("enter after completion did not open results: %d", view.screen)
	}
}

func TestIncompleteScanIsNotPresentedAsComplete(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.width, view.height = 100, 30
	view.screen = screenScanning
	view.scanStarted = time.Now()
	view.scanProgress = engine.Progress{Completed: 1, Total: 2}
	view.Update(scanCompleteMsg{run: model.ScanRun{Metadata: model.RunMetadata{Complete: false}}})
	content := ansi.Strip(view.scanningView())
	if strings.Contains(content, "점검 완료") || strings.Contains(content, "100%") {
		t.Fatalf("incomplete scan shown as complete: %q", content)
	}
	if !strings.Contains(content, "점검 중단") {
		t.Fatalf("incomplete scan status missing: %q", content)
	}
}

func TestScanningViewShowsCenteredProgressWithoutETA(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, time.July, 12, 0, 0, 0, 0, time.UTC)
	view := &Model{
		width:        100,
		height:       36,
		scanStarted:  started,
		scanProgress: engine.Progress{Completed: 10, Total: 20, RuleID: "U-11", Title: "불필요 계정 shell 제한"},
		now:          func() time.Time { return started.Add(20 * time.Second) },
	}
	content := view.scanningView()
	for _, expected := range []string{"10 / 20", "50%", "U-11", "경과", "20초"} {
		if !strings.Contains(content, expected) {
			t.Errorf("scanning view is missing %q: %q", expected, content)
		}
	}
	for _, unexpected := range []string{"ETA", "예상 남은 시간"} {
		if strings.Contains(content, unexpected) {
			t.Errorf("scanning view still contains %q: %q", unexpected, content)
		}
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
		t.Fatalf("scanning view is not vertically centered: first content line %d", firstContentLine)
	}
}

func TestReadyViewWarnsWhenNotRoot(t *testing.T) {
	t.Parallel()
	view := &Model{platform: model.PlatformInfo{Name: "Rocky Linux 9.8", Privilege: "user"}}
	content := view.readyView()
	if !strings.Contains(content, "보호된 설정") || !strings.Contains(content, "sudo openciip") {
		t.Fatalf("ready view did not show the non-root warning: %q", content)
	}
}

func TestReadyViewLeavesRemediationInExecutionOptions(t *testing.T) {
	t.Parallel()
	view := &Model{platform: model.PlatformInfo{RemediationSupport: model.RemediationSupportTargeted}}
	content := view.readyView()
	if strings.Contains(content, "자동 조치") {
		t.Fatalf("ready view still shows remediation outside execution options: %q", content)
	}
}

func TestReadyFooterUsesProjectCopyrightHolder(t *testing.T) {
	t.Parallel()
	footer := readyFooter()
	if !strings.Contains(footer, "© 2026 yellowcape") || strings.Contains(footer, "yesidodo73") {
		t.Fatalf("ready footer copyright = %q", footer)
	}
}

func TestReadyViewSeparatesLogoFromSubtitle(t *testing.T) {
	view := &Model{width: 100, height: 30, platform: model.PlatformInfo{Privilege: "root"}}
	lines := strings.Split(ansi.Strip(view.readyView()), "\n")
	logoEnd, subtitle := -1, -1
	for i, line := range lines {
		if strings.Contains(line, "/_/") {
			logoEnd = i
		}
		if strings.Contains(line, "주요정보통신기반시설 기술적 취약점 점검 도구") {
			subtitle = i
		}
	}
	if logoEnd < 0 || subtitle-logoEnd < 2 || strings.TrimSpace(lines[logoEnd+1]) != "" {
		t.Fatalf("logo and subtitle are not separated: %#v", lines)
	}
}

func TestOldScanTicksCannotAnimateNewOrFinishedScan(t *testing.T) {
	view := newModel(context.Background(), nil, nil, nil)
	view.screen = screenScanning
	view.scanGeneration = 2
	_, command := view.Update(scanTickMsg{generation: 1})
	if command != nil || view.scanTicks != 0 {
		t.Fatalf("old tick affected current scan: %d, %v", view.scanTicks, command)
	}
	view.scanFinished = true
	_, command = view.Update(scanTickMsg{generation: 2})
	if command != nil || view.scanTicks != 0 {
		t.Fatalf("finished scan is still animating: %d, %v", view.scanTicks, command)
	}
}

func TestResultSummaryUsesUserFacingPriority(t *testing.T) {
	t.Parallel()
	summary := resultSummary(map[model.Status]int{
		model.StatusFail:    1,
		model.StatusUnknown: 2,
		model.StatusError:   3,
	})
	failIndex := strings.Index(summary, "취약")
	unknownIndex := strings.Index(summary, "수동 확인 필요")
	errorIndex := strings.Index(summary, "확인 실패")
	if failIndex < 0 || !(failIndex < unknownIndex && unknownIndex < errorIndex) {
		t.Fatalf("result summary order = %q", summary)
	}
}

func TestTUIUsesUserFacingStatusLabels(t *testing.T) {
	t.Parallel()
	tests := map[model.Status]string{
		model.StatusFail: "취약", model.StatusUnknown: "수동 확인 필요",
		model.StatusError: "확인 실패", model.StatusPass: "양호",
		model.StatusNotApplicable: "해당 없음", model.StatusSkipped: "점검하지 않음",
	}
	for status, want := range tests {
		if got := statusLabel(status); got != want {
			t.Errorf("statusLabel(%s) = %q, want %q", status, got, want)
		}
	}
}

func TestTUIUsesKoreanNotApplicableLabel(t *testing.T) {
	t.Parallel()
	summary := resultSummary(map[model.Status]int{model.StatusNotApplicable: 3})
	if !strings.Contains(summary, "해당 없음 3") || strings.Contains(summary, "N/A") {
		t.Fatalf("result summary not-applicable label = %q", summary)
	}
	badge := statusBadge(model.StatusNotApplicable)
	if !strings.Contains(badge, "해당 없음") || strings.Contains(badge, "NOT_APPLICABLE") {
		t.Fatalf("status badge not-applicable label = %q", badge)
	}
}
