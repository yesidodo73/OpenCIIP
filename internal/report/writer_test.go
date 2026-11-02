package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
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
	for _, expected := range []string{"U-02", "U-03", "U-04", "read_failed"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("problems output lacks %q: %q", expected, output)
		}
	}
	if strings.Contains(output, string(model.UnknownManualVerification)) {
		t.Fatalf("problems output exposes machine UNKNOWN reason: %q", output)
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

func TestHumanReportsRenderCriteriaAndStructuredFindings(t *testing.T) {
	t.Parallel()

	result := model.CheckResult{
		RuleID:   "U-12",
		Title:    "세션 종료 시간 설정",
		Status:   model.StatusUnknown,
		Severity: model.SeverityLow,
		Summary:  "최종 세션 종료 시간을 정적으로 확정할 수 없습니다.",
		Expected: "모든 대화형 shell에서 TMOUT이 기준을 충족해야 합니다.",
		Observed: "legacy finding that must not be rendered",
		DisplayDetails: []model.ResultDetail{{
			Label:    "root/bash-login",
			Expected: "TMOUT 1~600초",
			Current:  "조건부 구문; 동적 source; value=a;b; " + strings.Repeat("긴 확인값 ", 30),
			Source:   "/etc/profile, /root/.bash_profile",
		}},
		Evidence: []model.Evidence{{
			Kind: model.EvidenceFact, Source: "session-timeout-startup-analysis",
			Fact: map[string]any{"context_count": 2},
		}},
	}

	for name, output := range map[string]string{
		"failures": renderProblems(model.ScanRun{Results: []model.CheckResult{result}}),
		"evidence": renderEvidence(result),
	} {
		for _, expected := range []string{
			"판정 이유:", "기준:", "확인 결과:", "root/bash-login",
			"현재:", "조건부 구문", "동적 source", "value=a;b", "위치:", "/etc/profile",
		} {
			if !strings.Contains(output, expected) {
				t.Fatalf("%s report lacks %q: %q", name, expected, output)
			}
		}
		if strings.Contains(output, "legacy finding") || strings.Contains(output, "; ") {
			t.Fatalf("%s report did not prefer structured, line-separated findings: %q", name, output)
		}
		if strings.Index(output, "기준:") > strings.Index(output, "확인 결과:") {
			t.Fatalf("%s report renders current values before criteria: %q", name, output)
		}
		for _, line := range strings.Split(output, "\n") {
			if width := ansi.StringWidth(line); width > humanReportWidth {
				t.Fatalf("%s report line width = %d, want <= %d: %q", name, width, humanReportWidth, line)
			}
		}
	}
	if evidence := renderEvidence(result); !strings.Contains(evidence, "[증적 1]") ||
		!strings.Contains(evidence, `"context_count": 2`) {
		t.Fatalf("evidence report lost raw evidence: %q", evidence)
	}
}

func TestHumanReportFallbackSplitsFindingDelimitersOnly(t *testing.T) {
	t.Parallel()

	output := renderProblems(model.ScanRun{Results: []model.CheckResult{{
		RuleID: "U-02", Title: "fixture", Status: model.StatusFail,
		Observed: "first finding; second finding; value=a;b",
	}}})
	for _, expected := range []string{"  - first finding", "  - second finding", "  - value=a;b"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("fallback output lacks %q: %q", expected, output)
		}
	}
	if strings.Contains(output, "; ") {
		t.Fatalf("fallback output retained finding delimiters: %q", output)
	}
}

func TestRenderProblemsIncludesSolutionOnlyWhenPresent(t *testing.T) {
	t.Parallel()
	run := model.ScanRun{Results: []model.CheckResult{
		{
			RuleID:   "U-01",
			Title:    "root 계정 원격 접속 제한",
			Status:   model.StatusFail,
			Summary:  "SSH에서 root 직접 로그인이 허용되는 실효 구성이 있습니다.",
			Expected: "root 직접 접속을 차단한 경우 양호합니다.",
			Solution: "원격 접속 시 root 계정으로 접속할 수 없도록 파일 내용 설정",
		},
		{
			RuleID:   "U-02",
			Title:    "비밀번호 관리정책 설정",
			Status:   model.StatusFail,
			Summary:  "비밀번호 관리 정책이 가이드 기준을 충족하지 않습니다.",
			Expected: "비밀번호 관리 정책이 설정된 경우 양호합니다.",
		},
	}}

	output := renderProblems(run)
	if !strings.Contains(output, "조치 방법: 원격 접속 시 root 계정으로 접속할 수 없도록 파일 내용 설정") {
		t.Fatalf("problems output lacks solution section: %q", output)
	}
	if count := strings.Count(output, "조치 방법"); count != 1 {
		t.Fatalf("solution section count = %d, want exactly one for the result that defines it", count)
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
	wantLabels := map[model.Status]string{
		model.StatusFail:          "취약",
		model.StatusUnknown:       "수동 확인 필요",
		model.StatusError:         "확인 실패",
		model.StatusPass:          "양호",
		model.StatusNotApplicable: "해당 없음",
		model.StatusSkipped:       "점검하지 않음",
	}
	for status, want := range wantLabels {
		if got := statusDisplayLabel(status); got != want {
			t.Fatalf("statusDisplayLabel(%s) = %q, want %q", status, got, want)
		}
	}
	if got := colorStatus(model.StatusNotApplicable, false); got != "해당 없음" {
		t.Fatalf("colorStatus(NOT_APPLICABLE) = %q", got)
	}
	run := model.ScanRun{Metadata: model.RunMetadata{Counts: map[model.Status]int{model.StatusNotApplicable: 2}}}
	if summary := renderSummary(run); !strings.Contains(summary, "해당 없음: 2") || strings.Contains(summary, "NOT_APPLICABLE") {
		t.Fatalf("summary not-applicable label = %q", summary)
	}
}

func TestRenderProblemsUsesKoreanUserFacingStatusLabels(t *testing.T) {
	t.Parallel()
	run := model.ScanRun{Results: []model.CheckResult{
		{RuleID: "U-01", Title: "fail", Status: model.StatusFail},
		{RuleID: "U-02", Title: "unknown", Status: model.StatusUnknown},
		{RuleID: "U-03", Title: "error", Status: model.StatusError},
	}}

	output := renderProblems(run)
	for _, label := range []string{"[취약]", "[수동 확인 필요]", "[확인 실패]"} {
		if !strings.Contains(output, label) {
			t.Fatalf("problems output lacks %q: %q", label, output)
		}
	}
	for _, internal := range []string{"[FAIL]", "[UNKNOWN]", "[ERROR]"} {
		if strings.Contains(output, internal) {
			t.Fatalf("problems output exposes internal status %q: %q", internal, output)
		}
	}
}

func TestHumanReadableReportsHideMachineRuleProvenance(t *testing.T) {
	t.Parallel()
	result := model.CheckResult{
		RuleID:         "U-01",
		Title:          "root 계정 원격 접속 제한",
		Status:         model.StatusUnknown,
		Severity:       model.SeverityHigh,
		Summary:        "실효 설정을 수동으로 확인해야 합니다.",
		Verification:   model.Verification{State: model.VerificationPending},
		BindingSources: []string{"linux-common", "rocky-linux-9.8"},
	}

	for name, output := range map[string]string{
		"failures": renderProblems(model.ScanRun{Results: []model.CheckResult{result}}),
		"evidence": renderEvidence(result),
	} {
		for _, internal := range []string{"플랫폼 검증 상태", "규칙 계층", "pending", "linux-common", "rocky-linux-9.8"} {
			if strings.Contains(output, internal) {
				t.Fatalf("%s report exposes machine provenance %q: %q", name, internal, output)
			}
		}
	}

	machine, err := marshalJSON([]model.CheckResult{result})
	if err != nil {
		t.Fatalf("marshalJSON() error = %v", err)
	}
	for _, required := range []string{`"verification"`, `"binding_sources"`, `"linux-common"`} {
		if !strings.Contains(string(machine), required) {
			t.Fatalf("machine report lacks %q: %s", required, machine)
		}
	}
}

func TestPlatformDisplayNameUsesOneNaturalVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		platform model.PlatformInfo
		want     string
	}{
		{
			name:     "Rocky pretty name already contains exact version",
			platform: model.PlatformInfo{Name: "Rocky Linux 9.8 (Blue Onyx)", VersionID: "9.8"},
			want:     "Rocky Linux 9.8 (Blue Onyx)",
		},
		{
			name:     "Ubuntu pretty name is more specific",
			platform: model.PlatformInfo{Name: "Ubuntu 24.04.4 LTS", VersionID: "24.04"},
			want:     "Ubuntu 24.04.4 LTS",
		},
		{
			name:     "CentOS major name is refined to point release",
			platform: model.PlatformInfo{Name: "CentOS Linux 8", VersionID: "8.5.2111"},
			want:     "CentOS Linux 8.5.2111",
		},
		{
			name:     "generic name receives missing version",
			platform: model.PlatformInfo{Name: "Example Linux", VersionID: "1.2"},
			want:     "Example Linux 1.2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := platformDisplayName(test.platform); got != test.want {
				t.Fatalf("platformDisplayName() = %q, want %q", got, test.want)
			}
		})
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

func TestHumanReadableReportsNeutralizeDynamicControlCharacters(t *testing.T) {
	t.Parallel()

	hostile := "\x1b[2J\u202e"
	run := model.ScanRun{
		Metadata: model.RunMetadata{
			RunID:        "run-" + hostile,
			GuideYear:    2021,
			Platform:     model.PlatformInfo{Hostname: "host-" + hostile, Name: "Linux\x00", Architecture: "x86_64\u009b31m"},
			Counts:       map[model.Status]int{model.StatusFail: 1},
			Warnings:     []string{"첫 열\t둘째 열\n다음 줄\x07"},
			Complete:     true,
			EvidenceMode: "all",
		},
		Results: []model.CheckResult{{
			RuleID:   "U-01" + hostile,
			Title:    "제목\x00",
			Status:   model.StatusFail,
			Severity: model.SeverityHigh,
			Summary:  "요약\t값\n다음 줄\u2066숨김\u2069",
			Expected: "기준\u0085",
			Observed: "현재\x07",
			Reference: model.Reference{
				Section: "절\u202e",
				Pages:   []int{12},
			},
			Evidence: []model.Evidence{{
				Kind:   model.EvidenceCommand,
				Source: "수집\x1b[31m",
				Command: &model.CommandEvidence{
					Executable: "fixture\x00",
					Arguments:  []string{"--value", "arg\u202e"},
					Stdout:     "첫 열\t둘째 열\nstdout\x1b[2J",
					Stderr:     "stderr\u009b31m",
				},
			}},
		}},
	}

	outputs := map[string]string{
		"summary":  renderSummary(run),
		"failures": renderProblems(run),
		"evidence": renderEvidence(run.Results[0]),
	}
	for name, output := range outputs {
		if sanitized := presentation.Sanitize(output); sanitized != output {
			t.Fatalf("%s retained a control character: %q", name, output)
		}
		if !strings.Contains(output, "<U+") {
			t.Fatalf("%s does not expose a neutralized control marker: %q", name, output)
		}
	}
	if summary := outputs["summary"]; !strings.Contains(summary, "첫 열\t둘째 열\n") {
		t.Fatalf("summary lost intended tab/newline structure: %q", summary)
	}
	if evidence := outputs["evidence"]; !strings.Contains(evidence, "첫 열\t둘째 열\nstdout") {
		t.Fatalf("evidence lost intended tab/newline structure: %q", evidence)
	}
}

func TestWriteScanHonorsRedactionMetadataWithoutMutatingInput(t *testing.T) {
	tests := []struct {
		name       string
		redaction  bool
		wantSecret bool
	}{
		{name: "redacted", redaction: true, wantSecret: false},
		{name: "explicit no-redact", redaction: false, wantSecret: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reportRoot := t.TempDir()
			if err := os.Chmod(reportRoot, 0o700); err != nil {
				t.Fatalf("make report root private: %v", err)
			}
			reportRootInfo, err := os.Stat(reportRoot)
			if err != nil {
				t.Fatalf("stat report root: %v", err)
			}
			writer := &Writer{basePath: reportRoot, baseInfo: reportRootInfo}
			run := model.ScanRun{
				Metadata: model.RunMetadata{
					RunID:                "scan-redaction-fixture",
					ToolExecutableSHA256: strings.Repeat("d", 64),
					StartedAt:            time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
					Redaction:            test.redaction,
					Platform:             model.PlatformInfo{Hostname: "fixture"},
					Counts:               map[model.Status]int{model.StatusFail: 1},
					Complete:             true,
				},
				Results: []model.CheckResult{{
					RuleID:   "U-02",
					Title:    "fixture",
					Category: model.CategoryAccount,
					Status:   model.StatusFail,
					Observed: "password=writer-secret",
					Evidence: []model.Evidence{{
						Kind:   model.EvidenceCommand,
						Source: "fixture",
						Command: &model.CommandEvidence{
							Executable: "fixture",
							Stdout:     "token=evidence-secret",
						},
					}},
				}},
			}

			path, err := writer.WriteScan(context.Background(), run)
			if err != nil {
				t.Fatalf("WriteScan() error = %v", err)
			}
			results, err := os.ReadFile(filepath.Join(path, "results.json"))
			if err != nil {
				t.Fatalf("read results.json: %v", err)
			}
			hasSecret := strings.Contains(string(results), "writer-secret") ||
				strings.Contains(string(results), "evidence-secret")
			if hasSecret != test.wantSecret {
				t.Fatalf("results.json secret presence = %t, want %t: %s", hasSecret, test.wantSecret, results)
			}
			if test.redaction && !strings.Contains(string(results), "[REDACTED]") {
				t.Fatalf("results.json lacks redaction marker: %s", results)
			}
			metadata, err := os.ReadFile(filepath.Join(path, "metadata.json"))
			if err != nil {
				t.Fatalf("read metadata.json: %v", err)
			}
			if !strings.Contains(string(metadata), strings.Repeat("d", 64)) {
				t.Fatalf("metadata.json lost executable digest: %s", metadata)
			}
			if run.Results[0].Observed != "password=writer-secret" ||
				run.Results[0].Evidence[0].Command.Stdout != "token=evidence-secret" {
				t.Fatalf("WriteScan() mutated its input: %#v", run.Results[0])
			}
		})
	}
}
