package service

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type ftpComponentRunner struct {
	dpkgOutput string
}

func (runner ftpComponentRunner) Available(name string) bool {
	return name == "systemctl" || name == "dpkg-query"
}

func (runner ftpComponentRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	switch spec.Name {
	case "systemctl":
		if len(spec.Arguments) < 1 {
			return executor.Result{}, fmt.Errorf("unexpected systemctl arguments: %v", spec.Arguments)
		}
		unit := spec.Arguments[len(spec.Arguments)-1]
		return executor.Result{ExitCode: 0, Stdout: []byte(strings.Join([]string{
			"Id=" + unit,
			"LoadState=not-found",
			"ActiveState=inactive",
			"SubState=dead",
			"UnitFileState=",
			"FragmentPath=",
			"DropInPaths=",
			"",
		}, "\n"))}, nil
	case "dpkg-query":
		return executor.Result{ExitCode: 0, Stdout: []byte(runner.dpkgOutput)}, nil
	default:
		return executor.Result{}, fmt.Errorf("unexpected command: %s %v", spec.Name, spec.Arguments)
	}
}

func TestInspectFTPComponentsUsesCompleteDPKGInventoryForAbsence(t *testing.T) {
	present, known, disabled, evidence, err := inspectFTPComponents(context.Background(), evaluator.Environment{
		Commands: ftpComponentRunner{dpkgOutput: "base-files\t13ubuntu10.2\tamd64\tii \n"},
		Platform: model.PlatformInfo{Family: "debian", PackageManager: "apt"},
	})
	if err != nil {
		t.Fatalf("inspectFTPComponents() error = %v", err)
	}
	if present || !known || disabled {
		t.Fatalf("inspectFTPComponents() = present=%t known=%t disabled=%t", present, known, disabled)
	}
	if len(evidence) == 0 {
		t.Fatal("inspectFTPComponents() returned no evidence")
	}
}

func TestInspectFTPComponentsDoesNotTreatInstalledPackageAsDisabledWithoutUnit(t *testing.T) {
	present, known, disabled, _, err := inspectFTPComponents(context.Background(), evaluator.Environment{
		Commands: ftpComponentRunner{dpkgOutput: "vsftpd\t3.0.5-0ubuntu1\tamd64\tii \n"},
		Platform: model.PlatformInfo{Family: "debian", PackageManager: "apt"},
	})
	if err != nil {
		t.Fatalf("inspectFTPComponents() error = %v", err)
	}
	if !present || !known || disabled {
		t.Fatalf("inspectFTPComponents() = present=%t known=%t disabled=%t", present, known, disabled)
	}
}
