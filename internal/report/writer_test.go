package report

import (
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestSanitizeComponent(t *testing.T) {
	t.Parallel()
	if got, want := sanitizeComponent("..host name/한글.."), "host_name_한글"; got != want {
		t.Fatalf("sanitizeComponent() = %q, want %q", got, want)
	}
}

func TestRenderProblemsIncludesOnlyProblemStates(t *testing.T) {
	t.Parallel()
	run := model.ScanRun{Results: []model.CheckResult{
		{RuleID: "U-01", Title: "pass", Status: model.StatusPass},
		{RuleID: "U-02", Title: "fail", Status: model.StatusFail, Severity: model.SeverityHigh, Summary: "취약"},
		{RuleID: "U-03", Title: "unknown", Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "수동 확인"},
		{RuleID: "U-04", Title: "error", Status: model.StatusError, ErrorCode: "read_failed", Summary: "오류"},
	}}
	output := renderProblems(run)
	if strings.Contains(output, "U-01") {
		t.Fatalf("pass result appeared in problems: %q", output)
	}
	for _, expected := range []string{"U-02", "U-03", "U-04", "read_failed", string(model.UnknownManualVerification)} {
		if !strings.Contains(output, expected) {
			t.Fatalf("problems output lacks %q: %q", expected, output)
		}
	}
}

func TestRenderProblemsUsesStatusPriority(t *testing.T) {
	t.Parallel()
	run := model.ScanRun{Results: []model.CheckResult{
		{RuleID: "U-01", Title: "unknown", Status: model.StatusUnknown},
		{RuleID: "U-02", Title: "fail", Status: model.StatusFail},
		{RuleID: "U-03", Title: "error", Status: model.StatusError},
	}}

	output := renderProblems(run)
	failIndex := strings.Index(output, "U-02")
	unknownIndex := strings.Index(output, "U-01")
	errorIndex := strings.Index(output, "U-03")
	if failIndex < 0 || !(failIndex < unknownIndex && unknownIndex < errorIndex) {
		t.Fatalf("problem status order is incorrect: %q", output)
	}
}

func TestOrderedStatusesUsesUserFacingPriority(t *testing.T) {
	t.Parallel()
	statuses := orderedStatuses()
	want := []model.Status{model.StatusFail, model.StatusUnknown, model.StatusError}
	for index, status := range want {
		if statuses[index] != status {
			t.Fatalf("orderedStatuses()[%d] = %s, want %s", index, statuses[index], status)
		}
	}
}

func TestNotApplicableUsesKoreanUserFacingLabel(t *testing.T) {
	t.Parallel()
	if got := statusDisplayLabel(model.StatusNotApplicable); got != "해당 없음" {
		t.Fatalf("statusDisplayLabel(NOT_APPLICABLE) = %q", got)
	}
	if got := colorStatus(model.StatusNotApplicable, false); got != "해당 없음" {
		t.Fatalf("colorStatus(NOT_APPLICABLE) = %q", got)
	}
	run := model.ScanRun{Metadata: model.RunMetadata{Counts: map[model.Status]int{model.StatusNotApplicable: 2}}}
	if summary := renderSummary(run); !strings.Contains(summary, "해당 없음: 2") || strings.Contains(summary, "NOT_APPLICABLE") {
		t.Fatalf("summary not-applicable label = %q", summary)
	}
}

func TestReportDirectoryNameSanitizesHostAndBoundsRunID(t *testing.T) {
	t.Parallel()
	metadata := model.RunMetadata{
		RunID:     "scan-1234567890abcdef",
		StartedAt: time.Date(2026, 7, 11, 1, 2, 3, 0, time.Local),
		Platform:  model.PlatformInfo{Hostname: "host/name"},
	}
	name := reportDirectoryName(metadata)
	if strings.ContainsAny(name, `/\\ `) || !strings.Contains(name, "host_name") || !strings.HasSuffix(name, "567890abcdef") {
		t.Fatalf("reportDirectoryName() = %q", name)
	}
}

func TestMarshalJSONEndsWithSingleNewline(t *testing.T) {
	t.Parallel()
	data, err := marshalJSON(map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("marshalJSON() error = %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") || strings.HasSuffix(string(data), "\n\n") {
		t.Fatalf("marshalJSON() newline = %q", data)
	}
}
