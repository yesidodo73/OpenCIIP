package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
)

func TestWriteTerminalNeutralizesDynamicControlCharacters(t *testing.T) {
	t.Parallel()

	run := model.ScanRun{
		Metadata: model.RunMetadata{
			Platform: model.PlatformInfo{
				Hostname:    "host\x1b[2J\u202e",
				Name:        "Rocky\x00 Linux",
				VersionID:   "9.8\u009b31m",
				ScanSupport: model.ScanSupportTested,
			},
			Counts: map[model.Status]int{model.StatusFail: 1},
			Warnings: []string{
				"첫 열\t둘째 열\n다음 줄\x07\u2066숨김\u2069",
			},
		},
		Results: []model.CheckResult{{
			RuleID: "U-\x1b[2J01",
			Title:  "제목\u202e",
			Status: model.StatusFail,
			Summary: "설명\x00\u0085" +
				"\n두 번째 줄",
		}},
	}

	var output bytes.Buffer
	if err := WriteTerminal(&output, run, TerminalOptions{All: true}); err != nil {
		t.Fatalf("WriteTerminal() error = %v", err)
	}
	rendered := output.String()
	if sanitized := presentation.Sanitize(rendered); sanitized != rendered {
		t.Fatalf("terminal output retained a control character: %q", rendered)
	}
	for _, expected := range []string{
		"<U+001B>[2J",
		"<U+202E>",
		"<U+0000>",
		"<U+0085>",
		"<U+009B>31m",
		"<U+0007>",
		"<U+2066>숨김<U+2069>",
		"첫 열\t둘째 열\n다음 줄",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("terminal output lacks %q: %q", expected, rendered)
		}
	}
}

func TestWriteTerminalHonorsRunRedactionPolicy(t *testing.T) {
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
			run := model.ScanRun{
				Metadata: model.RunMetadata{
					Redaction: test.redaction,
					Platform: model.PlatformInfo{
						Hostname:    "fixture",
						ScanSupport: model.ScanSupportTested,
					},
					Counts: map[model.Status]int{model.StatusFail: 1},
				},
				Results: []model.CheckResult{{
					RuleID:  "U-02",
					Title:   "fixture",
					Status:  model.StatusFail,
					Summary: "password=terminal-secret",
				}},
			}

			var output bytes.Buffer
			if err := WriteTerminal(&output, run, TerminalOptions{All: true}); err != nil {
				t.Fatalf("WriteTerminal() error = %v", err)
			}
			hasSecret := strings.Contains(output.String(), "terminal-secret")
			if hasSecret != test.wantSecret {
				t.Fatalf("terminal secret presence = %t, want %t: %q", hasSecret, test.wantSecret, output.String())
			}
			if test.redaction && !strings.Contains(output.String(), "[REDACTED]") {
				t.Fatalf("redacted terminal output lacks marker: %q", output.String())
			}
			if run.Results[0].Summary != "password=terminal-secret" {
				t.Fatalf("WriteTerminal() mutated input: %#v", run.Results[0])
			}
		})
	}
}
