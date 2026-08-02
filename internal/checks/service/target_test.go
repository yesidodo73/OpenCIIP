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

type dnsStubTargetRunner struct{}

func (dnsStubTargetRunner) Available(name string) bool {
	return name == "systemctl" || name == "ps" || name == "ss"
}

func (dnsStubTargetRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	switch spec.Name {
	case "systemctl":
		unit := spec.Arguments[len(spec.Arguments)-1]
		if unit == "systemd-resolved.service" {
			return executor.Result{ExitCode: 0, Stdout: []byte(
				"Id=systemd-resolved.service\n" +
					"LoadState=loaded\n" +
					"ActiveState=active\n" +
					"SubState=running\n" +
					"MainPID=753\n" +
					"FragmentPath=/usr/lib/systemd/system/systemd-resolved.service\n" +
					"DropInPaths=\n",
			)}, nil
		}
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
	case "ps":
		return executor.Result{ExitCode: 0}, nil
	case "ss":
		return executor.Result{ExitCode: 0, Stdout: []byte(
			"udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=753,fd=13))\n" +
				"udp UNCONN 0 0 127.0.0.54:53 0.0.0.0:* users:((\"systemd-resolve\",pid=753,fd=15))\n" +
				"tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=753,fd=14))\n" +
				"tcp LISTEN 0 4096 127.0.0.54:53 0.0.0.0:* users:((\"systemd-resolve\",pid=753,fd=16))\n",
		)}, nil
	default:
		return executor.Result{}, fmt.Errorf("unexpected command: %s %v", spec.Name, spec.Arguments)
	}
}

func TestInspectServiceTargetIgnoresConfirmedSystemdResolvedLocalStub(t *testing.T) {
	_, terminal := inspectServiceTarget(
		context.Background(),
		evaluator.Environment{
			Commands: dnsStubTargetRunner{},
			Platform: model.PlatformInfo{Family: "debian", InitSystem: "systemd", PackageManager: "apt"},
		},
		"DNS 서비스",
		bindProducts,
		[]int{53},
		"",
		withSystemdResolvedStubExclusion(),
	)
	if terminal == nil || terminal.Status != model.StatusNotApplicable {
		t.Fatalf("terminal = %#v, want NOT_APPLICABLE", terminal)
	}
	if !strings.Contains(terminal.Observed, "systemd-resolved") {
		t.Fatalf("observed = %q", terminal.Observed)
	}
}
