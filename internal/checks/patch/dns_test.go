package patchcheck

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type dnsStubPatchRunner struct{}

func (dnsStubPatchRunner) Available(name string) bool {
	return name == "systemctl" || name == "ps" || name == "ss"
}

func (dnsStubPatchRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
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

type dnsDebianPatchRunner struct {
	specs []executor.Spec
}

func (runner *dnsDebianPatchRunner) Available(name string) bool {
	return name == "named" || name == "dpkg-query" || name == "apt-get"
}

func (runner *dnsDebianPatchRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	runner.specs = append(runner.specs, spec)
	switch spec.Name {
	case "named":
		return executor.Result{ExitCode: 0, Stdout: []byte("BIND 9.18.30-0ubuntu0.24.04.2-Ubuntu\n")}, nil
	case "dpkg-query":
		return executor.Result{ExitCode: 0, Stdout: []byte(
			"bind9\t1:9.18.30-0ubuntu0.24.04.2\tamd64\tii \n" +
				"base-files\t13ubuntu10.2\tamd64\tii \n",
		)}, nil
	case "apt-get":
		return executor.Result{ExitCode: 0, Stdout: []byte(
			"Inst bind9 [1:9.18.30-0ubuntu0.24.04.2] (1:9.18.30-0ubuntu0.24.04.3 Ubuntu:24.04/noble-updates [amd64])\n",
		)}, nil
	default:
		return executor.Result{}, fmt.Errorf("unexpected command: %s %v", spec.Name, spec.Arguments)
	}
}

func TestEvaluateDNSPatchLevelIgnoresConfirmedSystemdResolvedLocalStub(t *testing.T) {
	outcome := evaluateDNSPatchLevel(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: dnsStubPatchRunner{},
		Platform: model.PlatformInfo{Family: "debian", InitSystem: "systemd", PackageManager: "apt"},
	})
	if outcome.Status != model.StatusNotApplicable {
		t.Fatalf("status = %q, want %q; outcome=%#v", outcome.Status, model.StatusNotApplicable, outcome)
	}
	if !strings.Contains(outcome.Observed, "systemd-resolved") {
		t.Fatalf("observed = %q", outcome.Observed)
	}
	foundStubEvidence := false
	for _, evidence := range outcome.Evidence {
		if evidence.Source == "systemd-resolved-stub-summary" {
			foundStubEvidence = true
		}
	}
	if !foundStubEvidence {
		t.Fatal("systemd-resolved stub evidence is missing")
	}
}

func TestEvaluateDebianDNSPatchLevelCollectsPackageAndReadOnlyAPTPlan(t *testing.T) {
	runner := &dnsDebianPatchRunner{}
	outcome := evaluateDebianDNSPatchLevel(
		context.Background(),
		evaluator.Environment{
			Commands: runner,
			Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04", PackageManager: "apt"},
		},
		nil,
	)
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownManualVerification {
		t.Fatalf("outcome = status=%q reason=%q", outcome.Status, outcome.UnknownReason)
	}
	if len(runner.specs) != 3 ||
		runner.specs[0].Name != "named" ||
		runner.specs[1].Name != "dpkg-query" ||
		runner.specs[2].Name != "apt-get" {
		t.Fatalf("specs = %#v", runner.specs)
	}
	aptArguments := strings.Join(runner.specs[2].Arguments, " ")
	if !strings.Contains(aptArguments, "--simulate") || !strings.Contains(aptArguments, "Debug::NoLocking=1") {
		t.Fatalf("apt-get arguments are not read-only: %q", aptArguments)
	}
	if !strings.Contains(outcome.Observed, "bind9=1:9.18.30-0ubuntu0.24.04.2") {
		t.Fatalf("observed = %q", outcome.Observed)
	}
}
