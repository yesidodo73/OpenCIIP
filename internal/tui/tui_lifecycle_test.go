package tui

import (
	"context"
	"errors"
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
	view.reportPath = "/report"
	view.run.Metadata.Platform.Support = model.SupportVerified
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
