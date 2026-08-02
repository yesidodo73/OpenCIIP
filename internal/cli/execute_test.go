package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestDestructiveCommandsRequireExplicitConfirmationBeforeOpeningState(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		arguments  []string
		wantOutput string
	}{
		{
			name:       "approve requires yes",
			arguments:  []string{"remediate", "approve", "run-a", "--plan-digest", digest},
			wantOutput: "--yes",
		},
		{
			name:       "approve requires plan digest",
			arguments:  []string{"remediate", "approve", "run-a", "--yes"},
			wantOutput: "--plan-digest",
		},
		{
			name:       "cancel requires yes",
			arguments:  []string{"remediate", "cancel", "run-a"},
			wantOutput: "--yes",
		},
		{
			name:       "item rollback requires preview digest",
			arguments:  []string{"remediate", "rollback", "item", "run-a", "change-a", "--yes"},
			wantOutput: "--preview-digest",
		},
		{
			name:       "run rollback requires yes",
			arguments:  []string{"remediate", "rollback", "run", "run-a", "--preview-digest", digest},
			wantOutput: "--yes",
		},
		{
			name:       "recover requires yes",
			arguments:  []string{"remediate", "recover", "run-a"},
			wantOutput: "--yes",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Execute(context.Background(), test.arguments, strings.NewReader(""), &stdout, &stderr)
			if code != exitcode.Usage {
				t.Fatalf("Execute() code = %d, want %d; stdout=%q stderr=%q", code, exitcode.Usage, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty output before confirmation", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantOutput) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.wantOutput)
			}
		})
	}
}

func TestExecuteProtectsFinalErrorOutput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(
		context.Background(),
		[]string{"password=cli-secret\x1b[2J\u202e"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != exitcode.Usage {
		t.Fatalf("Execute() code = %d, want %d", code, exitcode.Usage)
	}
	output := stderr.String()
	if strings.Contains(output, "cli-secret") ||
		strings.ContainsAny(output, "\x1b\u202e") {
		t.Fatalf("final error output retained sensitive/control content: %q", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("final error output = %q, want redaction marker", output)
	}
}

func TestParseSelectionNormalizesSupportedFilters(t *testing.T) {
	t.Parallel()

	selection, err := parseSelection(scanOptions{
		profiles:   []string{"account"},
		checks:     []string{"U-01"},
		categories: []string{"File-Directory", "service"},
		severities: []string{"HIGH", " low "},
	})
	if err != nil {
		t.Fatalf("parseSelection() error = %v", err)
	}
	if len(selection.Profiles) != 1 || selection.Profiles[0] != "account" {
		t.Fatalf("Profiles = %#v", selection.Profiles)
	}
	if len(selection.RuleIDs) != 1 || selection.RuleIDs[0] != "U-01" {
		t.Fatalf("RuleIDs = %#v", selection.RuleIDs)
	}
	wantCategories := []model.Category{model.CategoryFileDirectory, model.CategoryService}
	if len(selection.Categories) != len(wantCategories) {
		t.Fatalf("Categories = %#v", selection.Categories)
	}
	for index := range wantCategories {
		if selection.Categories[index] != wantCategories[index] {
			t.Fatalf("Categories[%d] = %q, want %q", index, selection.Categories[index], wantCategories[index])
		}
	}
	wantSeverities := []model.Severity{model.SeverityHigh, model.SeverityLow}
	if len(selection.Severities) != len(wantSeverities) {
		t.Fatalf("Severities = %#v", selection.Severities)
	}
	for index := range wantSeverities {
		if selection.Severities[index] != wantSeverities[index] {
			t.Fatalf("Severities[%d] = %q, want %q", index, selection.Severities[index], wantSeverities[index])
		}
	}
}

func TestParseSelectionRejectsUnknownFilters(t *testing.T) {
	t.Parallel()

	if _, err := parseSelection(scanOptions{categories: []string{"database"}}); err == nil {
		t.Fatal("parseSelection() accepted an unknown category")
	}
	if _, err := parseSelection(scanOptions{severities: []string{"critical"}}); err == nil {
		t.Fatal("parseSelection() accepted an unknown severity")
	}
}
