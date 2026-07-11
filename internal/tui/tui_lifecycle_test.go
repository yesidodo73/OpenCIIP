package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/orchestrator"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/workflow"
)

func TestModelClosesReplacedAndFinalRemediatorsOnce(t *testing.T) {
	first := &lifecycleRemediator{}
	second := &lifecycleRemediator{}
	view := NewModelWithRemediation(context.Background(), nil, nil, nil)
	view.remediator = first

	if err := view.replaceRemediator(second); err != nil {
		t.Fatalf("replaceRemediator() error = %v", err)
	}
	if first.closeCount != 1 {
		t.Fatalf("first close count = %d, want 1", first.closeCount)
	}
	if err := view.closeRemediator(); err != nil {
		t.Fatalf("closeRemediator(first) error = %v", err)
	}
	if err := view.closeRemediator(); err != nil {
		t.Fatalf("closeRemediator(second) error = %v", err)
	}
	if second.closeCount != 1 {
		t.Fatalf("second close count = %d, want 1", second.closeCount)
	}
}

func TestFailedRemediationPlanClosesNewRemediator(t *testing.T) {
	planErr := errors.New("plan failed")
	remediator := &lifecycleRemediator{planErr: planErr}
	view := NewModelWithRemediation(context.Background(), nil, nil, func(context.Context) (Remediator, error) {
		return remediator, nil
	})
	view.remediationCandidates = func(model.ScanRun, model.PlatformInfo) (bool, bool, error) {
		return true, false, nil
	}
	view.scanSettings.remediationEnabled = true
	view.reportPath = "/report"
	view.run.Metadata.Platform.ScanSupport = model.ScanSupportTested
	view.run.Metadata.Platform.RemediationSupport = model.RemediationSupportVerified
	view.run.Metadata.Platform.Privilege = "root"
	view.run.Results = []model.CheckResult{{
		Status:       model.StatusFail,
		Verification: model.Verification{State: model.VerificationVerified},
	}}

	_, command := view.startRemediationPlan()
	if command == nil {
		t.Fatal("startRemediationPlan() did not return a command")
	}
	rawMessage := command()
	message, ok := rawMessage.(remediationPlanMsg)
	if !ok {
		t.Fatalf("command message type = %T", rawMessage)
	}
	if !errors.Is(message.err, planErr) {
		t.Fatalf("plan error = %v, want %v", message.err, planErr)
	}
	if message.remediator != nil {
		t.Fatal("failed plan transferred ownership of its remediator")
	}
	if remediator.closeCount != 1 {
		t.Fatalf("close count = %d, want 1", remediator.closeCount)
	}
}

func TestRemediationAvailabilityFailsClosedWithVisibleReason(t *testing.T) {
	view := &Model{
		remediatorFactory: func(context.Context) (Remediator, error) { return &lifecycleRemediator{}, nil },
		platform: model.PlatformInfo{
			ScanSupport:        model.ScanSupportTested,
			RemediationSupport: model.RemediationSupportTargeted,
		},
	}
	availability := view.remediationAvailability()
	if availability.enabled || availability.label != "지원되지 않음" || availability.reason != "현재 OS와 버전에서 자동 조치가 지원되지 않습니다." {
		t.Fatalf("pending platform availability = %#v", availability)
	}
	if rendered := remediationAvailabilityView(availability); !strings.Contains(rendered, "자동 조치") || !strings.Contains(rendered, "지원되지 않음") {
		t.Fatalf("disabled remediation status is not visible: %q", rendered)
	}
}

func TestRemediationAvailabilityRequiresVerifiedFail(t *testing.T) {
	view := &Model{
		remediatorFactory: func(context.Context) (Remediator, error) { return &lifecycleRemediator{}, nil },
		reportPath:        "/report",
		remediationCandidates: func(model.ScanRun, model.PlatformInfo) (bool, bool, error) {
			return true, false, nil
		},
		scanSettings: scanSettings{remediationEnabled: true},
	}
	view.run.Metadata.Platform.ScanSupport = model.ScanSupportTested
	view.run.Metadata.Platform.RemediationSupport = model.RemediationSupportVerified
	view.run.Metadata.Platform.Privilege = "root"
	view.run.Results = []model.CheckResult{{
		Status:       model.StatusFail,
		Verification: model.Verification{State: model.VerificationVerified},
	}}
	availability := view.remediationAvailability()
	if !availability.enabled || availability.label != "사용 가능" {
		t.Fatalf("verified FAIL availability = %#v", availability)
	}
}

func TestRemediationAvailabilityRequiresRootAndMaskedReport(t *testing.T) {
	t.Parallel()
	base := Model{
		remediatorFactory: func(context.Context) (Remediator, error) { return &lifecycleRemediator{}, nil },
		reportPath:        "/report",
		remediationCandidates: func(model.ScanRun, model.PlatformInfo) (bool, bool, error) {
			return true, false, nil
		},
		scanSettings: scanSettings{remediationEnabled: true},
	}
	base.run.Metadata.Platform.ScanSupport = model.ScanSupportTested
	base.run.Metadata.Platform.RemediationSupport = model.RemediationSupportVerified
	if availability := base.remediationAvailability(); availability.enabled || availability.label != "root 권한 필요" {
		t.Fatalf("non-root availability = %#v", availability)
	}
	base.run.Metadata.Platform.Privilege = "root"
	base.scanSettings.noRedact = true
	if availability := base.remediationAvailability(); availability.enabled || availability.label != "마스킹 필요" {
		t.Fatalf("unredacted availability = %#v", availability)
	}
}

func TestBuiltInPendingRecipeDoesNotEnableRemediation(t *testing.T) {
	t.Parallel()
	platform := model.PlatformInfo{
		ID:                 "rocky",
		VersionID:          "9.8",
		Architecture:       "amd64",
		ScanSupport:        model.ScanSupportTested,
		RemediationSupport: model.RemediationSupportVerified,
	}
	run := model.ScanRun{
		Metadata: model.RunMetadata{GuideYear: 2026, Platform: platform},
		Results: []model.CheckResult{{
			RuleID:       "U-19",
			Status:       model.StatusFail,
			Verification: model.Verification{State: model.VerificationVerified},
		}},
	}
	verified, pending, err := builtInRemediationCandidates(run, platform)
	if err != nil || verified || !pending {
		t.Fatalf("built-in U-19 candidate = verified %t, pending %t, err %v", verified, pending, err)
	}
}

type lifecycleRemediator struct {
	closeCount int
	planErr    error
}

func (r *lifecycleRemediator) Close() error {
	r.closeCount++
	return nil
}

func (r *lifecycleRemediator) PlanFromReport(context.Context, string, workflow.PlanOptions) (workflow.PlanResult, error) {
	return workflow.PlanResult{}, r.planErr
}

func (*lifecycleRemediator) Approve(context.Context, string, string, string, string) error {
	return nil
}

func (*lifecycleRemediator) Cancel(context.Context, string) error { return nil }
func (*lifecycleRemediator) Apply(context.Context, string) error  { return nil }

func (*lifecycleRemediator) Load(context.Context, string) (*model.RemediationJournal, error) {
	return nil, nil
}

func (*lifecycleRemediator) PreviewRollbackItem(context.Context, string, string) (orchestrator.RollbackPreview, error) {
	return orchestrator.RollbackPreview{}, nil
}

func (*lifecycleRemediator) RollbackItem(context.Context, string, string, bool, string) (model.RollbackAttempt, error) {
	return model.RollbackAttempt{}, nil
}

func (*lifecycleRemediator) PreviewRollbackRun(context.Context, string) (orchestrator.RollbackPreview, error) {
	return orchestrator.RollbackPreview{}, nil
}

func (*lifecycleRemediator) RollbackRun(context.Context, string, string) (model.RollbackAttempt, error) {
	return model.RollbackAttempt{}, nil
}
