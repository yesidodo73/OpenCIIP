package tui

import (
	"strings"
	"testing"
	"time"

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

func TestScanningViewShowsProgressAndETA(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, time.July, 12, 0, 0, 0, 0, time.UTC)
	view := &Model{
		width:        100,
		scanStarted:  started,
		scanProgress: engine.Progress{Completed: 10, Total: 20, RuleID: "U-11", Title: "불필요 계정 shell 제한"},
		now:          func() time.Time { return started.Add(20 * time.Second) },
	}
	content := view.scanningView()
	for _, expected := range []string{"10 / 20", "50%", "U-11", "예상 남은 시간", "20초"} {
		if !strings.Contains(content, expected) {
			t.Errorf("scanning view is missing %q: %q", expected, content)
		}
	}
}

func TestReadyViewWarnsWhenNotRoot(t *testing.T) {
	t.Parallel()
	view := &Model{platform: model.PlatformInfo{Name: "Rocky Linux 9.8", Privilege: "user"}}
	content := view.readyView()
	if !strings.Contains(content, "권한 경고") || !strings.Contains(content, "sudo openciip") {
		t.Fatalf("ready view did not show the non-root warning: %q", content)
	}
}
