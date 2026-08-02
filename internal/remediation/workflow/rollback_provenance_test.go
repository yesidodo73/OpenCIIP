package workflow

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/orchestrator"
)

func TestRollbackAndRecoveryPassCurrentBuildIdentity(t *testing.T) {
	executor := model.RemediationBuildIdentity{
		Version:          "1.2.3",
		Commit:           strings.Repeat("a", 40),
		ExecutableSHA256: strings.Repeat("b", 64),
	}
	observer := model.RemediationBuildIdentity{
		Version:          "1.2.4-alpha.1",
		Commit:           strings.Repeat("c", 40),
		ExecutableSHA256: strings.Repeat("d", 64),
		Modified:         true,
	}
	manager := &provenanceCaptureManager{}
	var requireReleaseCalls []bool
	workflow := &Workflow{
		manager: manager,
		buildID: func(_ context.Context, requireRelease bool) (model.RemediationBuildIdentity, error) {
			requireReleaseCalls = append(requireReleaseCalls, requireRelease)
			if requireRelease {
				return executor, nil
			}
			return observer, nil
		},
	}

	if _, err := workflow.RollbackItem(context.Background(), "run-a", "change-a", true, strings.Repeat("e", 64)); err != nil {
		t.Fatalf("RollbackItem() error = %v", err)
	}
	if _, err := workflow.RollbackRun(context.Background(), "run-a", strings.Repeat("f", 64)); err != nil {
		t.Fatalf("RollbackRun() error = %v", err)
	}
	if _, err := workflow.Recover(context.Background(), "run-a"); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}

	if !reflect.DeepEqual(requireReleaseCalls, []bool{true, true, false}) {
		t.Fatalf("current build identity release requirements = %v, want [true true false]", requireReleaseCalls)
	}
	if manager.itemExecutor != executor {
		t.Fatalf("RollbackItem() executor = %#v, want %#v", manager.itemExecutor, executor)
	}
	if manager.runExecutor != executor {
		t.Fatalf("RollbackRun() executor = %#v, want %#v", manager.runExecutor, executor)
	}
	if manager.recoveryObserver != observer {
		t.Fatalf("Recover() observer = %#v, want %#v", manager.recoveryObserver, observer)
	}
}

func TestRollbackDoesNotCallManagerWhenBuildIdentityFails(t *testing.T) {
	identityErr := errors.New("build identity unavailable")
	manager := &provenanceCaptureManager{}
	workflow := &Workflow{
		manager: manager,
		buildID: func(context.Context, bool) (model.RemediationBuildIdentity, error) {
			return model.RemediationBuildIdentity{}, identityErr
		},
	}

	if _, err := workflow.RollbackRun(context.Background(), "run-a", strings.Repeat("a", 64)); !errors.Is(err, identityErr) {
		t.Fatalf("RollbackRun() error = %v, want %v", err, identityErr)
	}
	if manager.rollbackCalls != 0 {
		t.Fatalf("manager rollback calls = %d, want 0", manager.rollbackCalls)
	}
}

type provenanceCaptureManager struct {
	rollbackCalls    int
	itemExecutor     model.RemediationBuildIdentity
	runExecutor      model.RemediationBuildIdentity
	recoveryObserver model.RemediationBuildIdentity
}

func (*provenanceCaptureManager) Plan(context.Context, orchestrator.PlanRequest) (*model.RemediationJournal, error) {
	panic("unexpected Plan call")
}

func (*provenanceCaptureManager) Approve(context.Context, string, model.Approval) error {
	panic("unexpected Approve call")
}

func (*provenanceCaptureManager) Cancel(context.Context, string) error {
	panic("unexpected Cancel call")
}

func (*provenanceCaptureManager) ApplyWithVerifier(
	context.Context,
	string,
	orchestrator.ApplyRunGuard,
	orchestrator.ApplyEffectGuard,
	orchestrator.ApplyVerifier,
) error {
	panic("unexpected ApplyWithVerifier call")
}

func (*provenanceCaptureManager) PreviewRollbackItem(context.Context, string, string) (orchestrator.RollbackPreview, error) {
	panic("unexpected PreviewRollbackItem call")
}

func (m *provenanceCaptureManager) RollbackItem(
	_ context.Context,
	_, _ string,
	_ bool,
	_ string,
	executorBuild model.RemediationBuildIdentity,
) (model.RollbackAttempt, error) {
	m.rollbackCalls++
	m.itemExecutor = executorBuild
	return model.RollbackAttempt{}, nil
}

func (*provenanceCaptureManager) PreviewRollbackRun(context.Context, string) (orchestrator.RollbackPreview, error) {
	panic("unexpected PreviewRollbackRun call")
}

func (m *provenanceCaptureManager) RollbackRun(
	_ context.Context,
	_, _ string,
	executorBuild model.RemediationBuildIdentity,
) (model.RollbackAttempt, error) {
	m.rollbackCalls++
	m.runExecutor = executorBuild
	return model.RollbackAttempt{}, nil
}

func (m *provenanceCaptureManager) Recover(
	_ context.Context,
	_ string,
	observedByBuild model.RemediationBuildIdentity,
) (orchestrator.RecoveryAssessment, error) {
	m.recoveryObserver = observedByBuild
	return orchestrator.RecoveryAssessment{}, nil
}

var _ orchestrator.RemediationManager = (*provenanceCaptureManager)(nil)
