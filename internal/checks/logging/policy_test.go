package logging

import (
	"context"
	"errors"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type journaldConfigFixtureRunner struct {
	result executor.Result
	err    error
}

func (journaldConfigFixtureRunner) Available(string) bool {
	return true
}

func (runner journaldConfigFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "systemd-analyze" {
		return executor.Result{}, errors.New("unexpected fixture command")
	}
	result := runner.result
	result.Executable = "/usr/bin/systemd-analyze"
	result.Arguments = append([]string(nil), spec.Arguments...)
	return result, runner.err
}

func TestInspectJournaldEffectiveConfigTreatsUnsupportedCatConfigAsIncomplete(t *testing.T) {
	evidence := make([]model.Evidence, 0, 1)
	settings, complete, err := inspectJournaldEffectiveConfig(context.Background(), evaluator.Environment{
		Commands: journaldConfigFixtureRunner{result: executor.Result{
			ExitCode: 1,
			Stderr:   []byte("Unknown operation cat-config.\n"),
		}},
	}, &evidence)

	if err != nil {
		t.Fatalf("inspectJournaldEffectiveConfig() error = %v", err)
	}
	if complete {
		t.Fatal("complete = true, want false for unsupported cat-config")
	}
	if settings != nil {
		t.Fatalf("settings = %#v, want nil rather than a guessed default", settings)
	}
	if len(evidence) != 1 || evidence[0].Command == nil || evidence[0].Command.ExitCode != 1 {
		t.Fatalf("evidence = %#v, want one failed command record", evidence)
	}
}

func TestInspectJournaldEffectiveConfigKeepsOtherFailuresAsErrors(t *testing.T) {
	evidence := make([]model.Evidence, 0, 1)
	_, _, err := inspectJournaldEffectiveConfig(context.Background(), evaluator.Environment{
		Commands: journaldConfigFixtureRunner{result: executor.Result{
			ExitCode: 1,
			Stderr:   []byte("permission denied\n"),
		}},
	}, &evidence)

	if err == nil {
		t.Fatal("inspectJournaldEffectiveConfig() error = nil, want failure")
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(evidence))
	}
}

func TestStandardLoggingUnitAcceptsVendorDropIns(t *testing.T) {
	t.Parallel()

	unit := support.UnitState{
		FragmentPath: "/usr/lib/systemd/system/systemd-journald.service",
		DropInPaths:  "/usr/lib/systemd/system/systemd-journald.service.d/nice.conf /lib/systemd/system/systemd-journald.service.d/legacy.conf",
	}
	if !standardLoggingUnit(unit) {
		t.Fatal("standardLoggingUnit() = false, want true for vendor fragment and drop-ins")
	}
}

func TestStandardLoggingUnitRejectsAdministratorAndRuntimeOverrides(t *testing.T) {
	t.Parallel()

	for _, dropInPath := range []string{
		"/etc/systemd/system/systemd-journald.service.d/override.conf",
		"/run/systemd/system/systemd-journald.service.d/runtime.conf",
		"relative/systemd-journald.service.d/override.conf",
	} {
		unit := support.UnitState{
			FragmentPath: "/usr/lib/systemd/system/systemd-journald.service",
			DropInPaths:  dropInPath,
		}
		if standardLoggingUnit(unit) {
			t.Errorf("standardLoggingUnit() = true for %q, want false", dropInPath)
		}
	}
}
