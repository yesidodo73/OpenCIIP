package support

import (
	"context"
	"fmt"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
)

type resolvedStubRunner struct {
	result executor.Result
}

func (runner resolvedStubRunner) Available(name string) bool {
	return name == "systemctl"
}

func (runner resolvedStubRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "systemctl" || len(spec.Arguments) != 5 ||
		spec.Arguments[3] != "--" || spec.Arguments[4] != "systemd-resolved.service" {
		return executor.Result{}, fmt.Errorf("unexpected command: %s %v", spec.Name, spec.Arguments)
	}
	return runner.result, nil
}

func TestInspectSystemdResolvedStubRequiresUnitPIDAndStandardAddresses(t *testing.T) {
	runner := resolvedStubRunner{result: executor.Result{ExitCode: 0, Stdout: []byte(
		"Id=systemd-resolved.service\n" +
			"LoadState=loaded\n" +
			"ActiveState=active\n" +
			"SubState=running\n" +
			"MainPID=753\n" +
			"FragmentPath=/usr/lib/systemd/system/systemd-resolved.service\n" +
			"DropInPaths=\n",
	)}}
	listeners := []string{
		`udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=753,fd=13))`,
		`udp UNCONN 0 0 127.0.0.54:53 0.0.0.0:* users:(("systemd-resolve",pid=753,fd=15))`,
		`tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=753,fd=14))`,
		`tcp LISTEN 0 4096 127.0.0.54:53 0.0.0.0:* users:(("systemd-resolve",pid=753,fd=16))`,
	}
	assessment, err := InspectSystemdResolvedStub(context.Background(), evaluator.Environment{Commands: runner}, listeners)
	if err != nil {
		t.Fatalf("InspectSystemdResolvedStub() error = %v", err)
	}
	if !assessment.Confirmed {
		t.Fatalf("assessment = %#v, want confirmed", assessment)
	}
	if len(assessment.Evidence) != 2 {
		t.Fatalf("evidence count = %d, want 2", len(assessment.Evidence))
	}
}

func TestInspectSystemdResolvedStubDoesNotIgnoreUnattributedOrNonstandardListeners(t *testing.T) {
	runner := resolvedStubRunner{result: executor.Result{ExitCode: 0, Stdout: []byte(
		"Id=systemd-resolved.service\n" +
			"LoadState=loaded\n" +
			"ActiveState=active\n" +
			"SubState=running\n" +
			"MainPID=753\n" +
			"FragmentPath=/lib/systemd/system/systemd-resolved.service\n" +
			"DropInPaths=\n",
	)}}
	for _, listener := range []string{
		`udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*`,
		`udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=999,fd=13))`,
		`udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("systemd-resolve",pid=753,fd=13))`,
		`udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("systemd-resolve",pid=753,fd=13))`,
	} {
		assessment, err := InspectSystemdResolvedStub(
			context.Background(),
			evaluator.Environment{Commands: runner},
			[]string{listener},
		)
		if err != nil {
			t.Fatalf("InspectSystemdResolvedStub(%q) error = %v", listener, err)
		}
		if assessment.Confirmed {
			t.Fatalf("InspectSystemdResolvedStub(%q) confirmed an ambiguous listener", listener)
		}
	}
}

func TestInspectSystemdResolvedStubRejectsUnitDropIn(t *testing.T) {
	runner := resolvedStubRunner{result: executor.Result{ExitCode: 0, Stdout: []byte(
		"Id=systemd-resolved.service\n" +
			"LoadState=loaded\n" +
			"ActiveState=active\n" +
			"SubState=running\n" +
			"MainPID=753\n" +
			"FragmentPath=/usr/lib/systemd/system/systemd-resolved.service\n" +
			"DropInPaths=/etc/systemd/system/systemd-resolved.service.d/override.conf\n",
	)}}
	assessment, err := InspectSystemdResolvedStub(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{`udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=753,fd=13))`},
	)
	if err != nil {
		t.Fatalf("InspectSystemdResolvedStub() error = %v", err)
	}
	if assessment.Confirmed {
		t.Fatal("custom systemd-resolved drop-in was treated as the standard local stub")
	}
}

func TestInspectSystemdResolvedStubLeavesOtherDNSListenerUnclassifiedWhenUnitIsAbsent(t *testing.T) {
	runner := resolvedStubRunner{result: executor.Result{
		ExitCode: 4,
		Stderr:   []byte("Unit systemd-resolved.service could not be found.\n"),
	}}
	assessment, err := InspectSystemdResolvedStub(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{`udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("dnsmasq",pid=753,fd=13))`},
	)
	if err != nil {
		t.Fatalf("InspectSystemdResolvedStub() error = %v", err)
	}
	if assessment.Confirmed {
		t.Fatal("listener was confirmed despite absent systemd-resolved unit")
	}
}
