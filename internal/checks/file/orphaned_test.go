package filecheck

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type orphanedOwnerFixtureRunner struct {
	spec   executor.Spec
	result *executor.Result
}

func (*orphanedOwnerFixtureRunner) Available(string) bool {
	return true
}

func (runner *orphanedOwnerFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "findmnt" {
		return executor.Result{}, errors.New("unexpected fixture command")
	}
	runner.spec = spec
	if runner.result != nil {
		result := *runner.result
		result.Executable = "/usr/bin/findmnt"
		result.Arguments = append([]string(nil), spec.Arguments...)
		return result, nil
	}
	return executor.Result{
		Executable: "/usr/bin/findmnt",
		Arguments:  append([]string(nil), spec.Arguments...),
		ExitCode:   0,
		Stdout:     []byte(`{"filesystems":[{"target":"/","fstype":"tmpfs","options":"rw"}]}`),
	}, nil
}

func TestEvaluateOrphanedOwnerUsesPortableFindmntOptions(t *testing.T) {
	runner := &orphanedOwnerFixtureRunner{}
	outcome := evaluateOrphanedOwner(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: runner,
	})

	if outcome.Status != model.StatusNotApplicable {
		t.Fatalf("status = %q, want %q", outcome.Status, model.StatusNotApplicable)
	}
	want := []string{"--json", "--list", "--output", "TARGET,FSTYPE,OPTIONS"}
	if !reflect.DeepEqual(runner.spec.Arguments, want) {
		t.Fatalf("findmnt arguments = %#v, want %#v", runner.spec.Arguments, want)
	}
	if len(outcome.Evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(outcome.Evidence))
	}
}

func TestEvaluateOrphanedOwnerPreservesFailedFindmntEvidence(t *testing.T) {
	runner := &orphanedOwnerFixtureRunner{result: &executor.Result{
		ExitCode: 1,
		Stderr:   []byte("findmnt: unsupported option\n"),
	}}
	outcome := evaluateOrphanedOwner(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: runner,
	})

	if outcome.Status != model.StatusError || outcome.ErrorCode != "findmnt_failed" {
		t.Fatalf("outcome = %#v, want findmnt_failed ERROR", outcome)
	}
	if len(outcome.Evidence) != 1 || outcome.Evidence[0].Command == nil {
		t.Fatalf("evidence = %#v, want failed findmnt command", outcome.Evidence)
	}
	if got := outcome.Evidence[0].Command.Stderr; got != "findmnt: unsupported option\n" {
		t.Fatalf("command stderr = %q", got)
	}
}
