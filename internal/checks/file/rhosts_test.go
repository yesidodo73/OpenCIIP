package filecheck

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestRHostsTrustClassifiesMountInventoryLimitAsInsufficientEvidence(t *testing.T) {
	t.Parallel()

	outcome := evaluateRHostsTrust(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{
			Commands: rhostsMountLimitRunner{},
			Files:    startupFixtureReader{files: fstest.MapFS{}},
			Platform: model.PlatformInfo{InitSystem: "systemd"},
		},
	)
	if outcome.Status != model.StatusUnknown ||
		outcome.UnknownReason != model.UnknownInsufficientEvidence ||
		outcome.ErrorCode != "" {
		t.Fatalf("outcome = %#v, want UNKNOWN insufficient_evidence", outcome)
	}
	if !containsEvidenceSource(outcome.Evidence, "home-mount-inventory-limit") {
		t.Fatalf("evidence = %#v, want mount inventory limit fact", outcome.Evidence)
	}
}

type rhostsMountLimitRunner struct{}

func (rhostsMountLimitRunner) Available(string) bool {
	return true
}

func (rhostsMountLimitRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	switch spec.Name {
	case "systemctl":
		if len(spec.Arguments) == 0 {
			return executor.Result{}, errors.New("missing systemctl operation")
		}
		switch spec.Arguments[0] {
		case "show":
			unit := spec.Arguments[len(spec.Arguments)-1]
			activeState := "inactive"
			unitFileState := "disabled"
			loadState := "not-found"
			if unit == "rexec.service" {
				activeState = "active"
				unitFileState = "enabled"
				loadState = "loaded"
			}
			return executor.Result{Stdout: []byte(strings.Join([]string{
				"Id=" + unit,
				"LoadState=" + loadState,
				"ActiveState=" + activeState,
				"SubState=dead",
				"UnitFileState=" + unitFileState,
				"FragmentPath=",
				"DropInPaths=",
			}, "\n") + "\n")}, nil
		case "list-unit-files":
			return executor.Result{ExitCode: 1}, nil
		default:
			return executor.Result{}, errors.New("unexpected systemctl operation")
		}
	case "ss", "ps":
		return executor.Result{}, nil
	case "getent":
		return executor.Result{Stdout: []byte(
			"root:x:0:0::/root:/bin/bash\n",
		)}, nil
	case "findmnt":
		return executor.Result{Stdout: []byte(
			findmntFixtureWithMountCount(maximumHomeMountEntries + 1),
		)}, nil
	default:
		return executor.Result{}, errors.New("unexpected fixture command: " + spec.Name)
	}
}
