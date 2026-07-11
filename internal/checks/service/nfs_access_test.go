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

func TestNFSAccessControlIsNotApplicableWhenIndependentInspectionFindsNoServer(t *testing.T) {
	presence := evaluator.Outcome{
		Status:   model.StatusNotApplicable,
		Observed: "NFS server unit, process, thread, export 없음",
		Evidence: []model.Evidence{{Kind: model.EvidenceFact, Source: "nfs-presence"}},
	}
	outcome := nfsAccessWithoutExportfs(presence)
	if outcome.Status != model.StatusNotApplicable || len(outcome.Evidence) != 1 {
		t.Fatalf("nfsAccessWithoutExportfs() = %s evidence=%d, want NOT_APPLICABLE with evidence", outcome.Status, len(outcome.Evidence))
	}
}
