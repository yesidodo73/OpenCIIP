package engine

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestScanProducesDeterministicSelectionCountsAndEvidenceBoundary(t *testing.T) {
	t.Parallel()

	engine := newFixtureEngine(t)
	progress := make([]Progress, 0, 4)
	run, err := engine.Scan(context.Background(), Options{
		EvidenceMode: "problems",
		Progress: func(update Progress) {
			progress = append(progress, update)
		},
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(run.Results) != 2 || run.Results[0].RuleID != "U-01" || run.Results[1].RuleID != "U-02" {
		t.Fatalf("results = %#v, want U-01 and U-02 in rule order", run.Results)
	}
	if run.Results[0].Status != model.StatusPass || len(run.Results[0].Evidence) != 0 {
		t.Fatalf("U-01 = %s evidence=%d, want PASS without problem-only evidence", run.Results[0].Status, len(run.Results[0].Evidence))
	}
	if run.Results[1].Status != model.StatusFail || len(run.Results[1].Evidence) != 1 {
		t.Fatalf("U-02 = %s evidence=%d, want FAIL with evidence", run.Results[1].Status, len(run.Results[1].Evidence))
	}
	if run.Metadata.Counts[model.StatusPass] != 1 || run.Metadata.Counts[model.StatusFail] != 1 {
		t.Fatalf("counts = %#v", run.Metadata.Counts)
	}
	if run.Metadata.ExitCode != exitcode.Failed || !run.Metadata.Complete || run.Metadata.EvidenceMode != "problems" {
		t.Fatalf("metadata = %#v", run.Metadata)
	}
	if run.Metadata.SchemaVersion != model.RunMetadataSchemaVersion {
		t.Fatalf("schema version = %d, want %d", run.Metadata.SchemaVersion, model.RunMetadataSchemaVersion)
	}
	if matched := regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(run.Metadata.ToolExecutableSHA256); !matched {
		t.Fatalf("tool executable digest = %q, want lowercase SHA-256", run.Metadata.ToolExecutableSHA256)
	}
	if len(progress) != 4 || progress[0].Completed != 0 || progress[0].Total != 2 || progress[len(progress)-1].Completed != 2 {
		t.Fatalf("progress = %#v, want start and completion updates for two rules", progress)
	}
}

func TestScanCancellationCreatesSkippedResultsAndIncompleteRun(t *testing.T) {
	t.Parallel()

	engine := newFixtureEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run, err := engine.Scan(ctx, Options{EvidenceMode: "all"})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if run.Metadata.Complete {
		t.Fatal("canceled scan was marked complete")
	}
	if run.Metadata.ExitCode != exitcode.Error || run.Metadata.Counts[model.StatusSkipped] != 2 {
		t.Fatalf("canceled metadata = %#v", run.Metadata)
	}
	for _, result := range run.Results {
		if result.Status != model.StatusSkipped {
			t.Fatalf("result %s status = %s, want SKIPPED", result.RuleID, result.Status)
		}
	}
}

func TestScanRejectsUnknownSelectionBeforeEvaluation(t *testing.T) {
	t.Parallel()

	engine := newFixtureEngine(t)
	_, err := engine.Scan(context.Background(), Options{
		Selection: model.Selection{RuleIDs: []string{"U-67"}},
	})
	if !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("Scan() error = %v, want ErrInvalidSelection", err)
	}
	_, err = engine.Scan(context.Background(), Options{
		Selection: model.Selection{Profiles: []string{"missing"}},
	})
	if !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("Scan() profile error = %v, want ErrInvalidSelection", err)
	}
}

func TestNormalizeEvidenceMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "", want: "problems"},
		{input: " ALL ", want: "all"},
		{input: "none", want: "none"},
		{input: "standard", wantErr: true},
	}
	for _, test := range tests {
		got, err := normalizeEvidenceMode(test.input)
		if (err != nil) != test.wantErr || got != test.want {
			t.Errorf("normalizeEvidenceMode(%q) = %q, %v; want %q, wantErr %t", test.input, got, err, test.want, test.wantErr)
		}
	}
}

func newFixtureEngine(t *testing.T) *Engine {
	t.Helper()

	verified := model.Verification{
		State:        model.VerificationVerified,
		Environments: []string{"Rocky Linux 9.8 test fixture"},
		VerifiedAt:   "2026-07-11T12:00:00Z",
	}
	bundle := rules.Bundle{
		Catalog: model.Catalog{
			SchemaVersion: 1,
			Guide: model.Guide{
				Year: 2026, Title: "Test guide", Domain: "Unix 서버",
			},
			Rules: []model.RuleDefinition{
				fixtureRule("U-02", "fixture.fail", model.SeverityHigh),
				fixtureRule("U-01", "fixture.pass", model.SeverityMedium),
			},
		},
		Profiles: model.ProfileSet{
			SchemaVersion: 1,
			Profiles: []model.Profile{{
				ID: "all", Title: "All", RuleIDs: []string{"U-01", "U-02"},
			}},
		},
		Layers: []model.BindingLayer{{
			SchemaVersion: 1,
			ID:            "verified-fixture",
			Priority:      100,
			Selector:      model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
			Bindings: []model.RuleBinding{
				{RuleID: "U-01", Verification: &verified},
				{RuleID: "U-02", Verification: &verified},
			},
		}},
		Version: "sha256:" + strings.Repeat("a", 64),
	}
	registry := evaluator.NewRegistry()
	evidence := func() []model.Evidence {
		return []model.Evidence{{
			Kind: model.EvidenceFact, Source: "fixture", CapturedAt: time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC), Redacted: true,
			Fact: map[string]any{"fixture": true},
		}}
	}
	if err := registry.Register("fixture.pass", func(context.Context, model.ResolvedRule, evaluator.Environment) evaluator.Outcome {
		return evaluator.Outcome{Status: model.StatusPass, Summary: "fixture pass", Evidence: evidence()}
	}); err != nil {
		t.Fatalf("Register(pass) error = %v", err)
	}
	if err := registry.Register("fixture.fail", func(context.Context, model.ResolvedRule, evaluator.Environment) evaluator.Outcome {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "fixture fail", Evidence: evidence()}
	}); err != nil {
		t.Fatalf("Register(fail) error = %v", err)
	}
	files, err := system.NewOSReader(t.TempDir())
	if err != nil {
		t.Fatalf("NewOSReader() error = %v", err)
	}
	t.Cleanup(func() {
		if err := files.Close(); err != nil {
			t.Errorf("OSReader.Close() error = %v", err)
		}
	})
	instance, err := New(bundle, registry, evaluator.Environment{
		Files:    files,
		Commands: inertCommandRunner{},
		Platform: model.PlatformInfo{
			OS: "linux", ID: "rocky", VersionID: "9.8", Family: "rhel", Architecture: "amd64",
			ScanSupport: model.ScanSupportTested, RemediationSupport: model.RemediationSupportVerified,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	base := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	index := 0
	instance.now = func() time.Time {
		value := base.Add(time.Duration(index) * time.Second)
		index++
		return value
	}
	return instance
}

func fixtureRule(id, evaluatorID string, severity model.Severity) model.RuleDefinition {
	return model.RuleDefinition{
		ID: id, Title: id + " fixture", Category: model.CategoryAccount, Severity: severity, Evaluator: evaluatorID,
		Criteria:  model.Criteria{Summary: "fixture", Pass: "pass", Fail: "fail"},
		Reference: model.Reference{Guide: "Test guide", Section: "Unix", Item: id, Pages: []int{1}},
	}
}

type inertCommandRunner struct{}

func (inertCommandRunner) Run(context.Context, executor.Spec) (executor.Result, error) {
	return executor.Result{}, errors.New("unexpected command execution")
}

func (inertCommandRunner) Available(string) bool { return false }
