package service

import (
	"context"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type unavailableServiceCommandRunner struct{}

func (unavailableServiceCommandRunner) Run(context.Context, executor.Spec) (executor.Result, error) {
	panic("Run must not be called for an unavailable command")
}

func (unavailableServiceCommandRunner) Available(string) bool { return false }

func TestNFSAccessControlDoesNotAssumeNotApplicableWhenExportfsIsMissing(t *testing.T) {
	outcome := evaluateNFSAccessControl(context.Background(), model.ResolvedRule{}, evaluator.Environment{Commands: unavailableServiceCommandRunner{}})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("evaluateNFSAccessControl() = %s, %s, want UNKNOWN unsupported_configuration", outcome.Status, outcome.UnknownReason)
	}
}
