package filecheck

import (
	"context"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
)

type rpmOwnershipRunner struct {
	result executor.Result
}

func (r rpmOwnershipRunner) Available(name string) bool { return name == "rpm" }

func (r rpmOwnershipRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "rpm" {
		panic("unexpected command: " + spec.Name)
	}
	return r.result, nil
}

func TestInspectRPMOwnershipTreatsMultipleDirectoryOwnersAsIncompleteContext(t *testing.T) {
	environment := evaluator.Environment{Commands: rpmOwnershipRunner{result: executor.Result{
		ExitCode: 0,
		Stdout: []byte("package-a-1-1.x86_64\tRSA/SHA256, key ID 00000000\n" +
			"package-b-1-1.x86_64\tRSA/SHA256, key ID 00000000\n"),
	}}}

	ownership, err := inspectRPMOwnership(context.Background(), environment, "/usr/lib/.build-id")
	if err != nil {
		t.Fatalf("inspectRPMOwnership() error = %v", err)
	}
	if !ownership.Owned || ownership.Complete {
		t.Fatalf("ownership = %#v, want owned with incomplete singular package context", ownership)
	}
}
