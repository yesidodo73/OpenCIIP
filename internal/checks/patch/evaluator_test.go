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

type patchPolicyRunner struct {
	results []executor.Result
	index   int
}

func (runner *patchPolicyRunner) Available(name string) bool {
	return name == "rpm" || name == "dnf"
}

func (runner *patchPolicyRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if runner.index >= len(runner.results) {
		return executor.Result{}, fmt.Errorf("unexpected command: %s %v", spec.Name, spec.Arguments)
	}
	result := runner.results[runner.index]
	runner.index++
	result.Executable = "/usr/bin/" + spec.Name
	return result, nil
}

type aptPatchPolicyRunner struct {
	results []executor.Result
	specs   []executor.Spec
}

func (runner *aptPatchPolicyRunner) Available(name string) bool {
	return name == "dpkg-query" || name == "apt-get"
}

func (runner *aptPatchPolicyRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if len(runner.specs) >= len(runner.results) {
		return executor.Result{}, fmt.Errorf("unexpected command: %s %v", spec.Name, spec.Arguments)
	}
	runner.specs = append(runner.specs, spec)
	result := runner.results[len(runner.specs)-1]
	result.Executable = "/usr/bin/" + spec.Name
	return result, nil
}

func TestEvaluatePatchPolicyCollectsDebianEvidenceWithoutChangingState(t *testing.T) {
	runner := &aptPatchPolicyRunner{results: []executor.Result{
		{ExitCode: 0, Stdout: []byte(
			"base-files\t13ubuntu10.2\tamd64\tii \n" +
				"openssl\t3.0.13-0ubuntu3.5\tamd64\tii \n",
		)},
		{ExitCode: 0, Stdout: []byte(
			"Inst openssl [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates [amd64])\n" +
				"Conf openssl (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates [amd64])\n",
		)},
	}}
	outcome := evaluatePatchPolicy(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: runner,
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04", PackageManager: "apt"},
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownManualVerification {
		t.Fatalf("outcome = status=%q reason=%q", outcome.Status, outcome.UnknownReason)
	}
	if len(runner.specs) != 2 || runner.specs[0].Name != "dpkg-query" || runner.specs[1].Name != "apt-get" {
		t.Fatalf("specs = %#v", runner.specs)
	}
	aptArguments := strings.Join(runner.specs[1].Arguments, " ")
	if !strings.Contains(aptArguments, "--simulate") || !strings.Contains(aptArguments, "Debug::NoLocking=1") ||
		strings.Contains(aptArguments, " update") || strings.Contains(aptArguments, " install") {
		t.Fatalf("apt-get arguments are not read-only: %q", aptArguments)
	}
	if !strings.Contains(outcome.Observed, "업그레이드 후보 1개") {
		t.Fatalf("observed = %q", outcome.Observed)
	}
}

func TestEvaluatePatchPolicyKeepsAPTCollectionFailureAsError(t *testing.T) {
	runner := &aptPatchPolicyRunner{results: []executor.Result{
		{ExitCode: 0, Stdout: []byte("base-files\t13ubuntu10.2\tamd64\tii \n")},
		{ExitCode: 100, Stderr: []byte("E: The package cache file is corrupted\n")},
	}}
	outcome := evaluatePatchPolicy(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: runner,
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04", PackageManager: "apt"},
	})
	if outcome.Status != model.StatusError || outcome.ErrorCode != "patch_apt_simulation_failed" {
		t.Fatalf("outcome = status=%q code=%q", outcome.Status, outcome.ErrorCode)
	}
}

func TestEvaluatePatchPolicyTreatsMissingDNFCacheAsInsufficientEvidence(t *testing.T) {
	runner := &patchPolicyRunner{results: []executor.Result{
		{ExitCode: 0, Stdout: []byte("bash\t0:5.1.8-9.el9.x86_64\n")},
		{ExitCode: 1, Stderr: []byte("Error: Cache-only enabled but no cache for 'baseos'\n")},
	}}

	outcome := evaluatePatchPolicy(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: runner,
		Platform: model.PlatformInfo{Family: "rhel", ID: "rocky", VersionID: "9.8", PackageManager: "dnf"},
	})

	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %q, want %q", outcome.Status, model.StatusUnknown)
	}
	if outcome.UnknownReason != model.UnknownInsufficientEvidence {
		t.Fatalf("unknown reason = %q, want %q", outcome.UnknownReason, model.UnknownInsufficientEvidence)
	}
	if outcome.ErrorCode != "" || outcome.ErrorMessage != "" {
		t.Fatalf("unexpected error outcome: code=%q message=%q", outcome.ErrorCode, outcome.ErrorMessage)
	}
	if runner.index != 2 {
		t.Fatalf("command count = %d, want 2", runner.index)
	}
	if len(outcome.Evidence) != 3 {
		t.Fatalf("evidence count = %d, want 3", len(outcome.Evidence))
	}
}

func TestEvaluatePatchPolicyKeepsOtherDNFFailuresAsErrors(t *testing.T) {
	tests := []struct {
		name   string
		result executor.Result
	}{
		{
			name:   "ordinary command failure",
			result: executor.Result{ExitCode: 1, Stderr: []byte("Error: rpmdb is damaged\n")},
		},
		{
			name: "truncated cache diagnostic",
			result: executor.Result{
				ExitCode:  1,
				Stderr:    []byte("Error: Cache-only enabled but no cache for 'baseos'\n"),
				Truncated: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &patchPolicyRunner{results: []executor.Result{
				{ExitCode: 0, Stdout: []byte("bash\t0:5.1.8-9.el9.x86_64\n")},
				test.result,
			}}
			outcome := evaluatePatchPolicy(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Commands: runner,
				Platform: model.PlatformInfo{Family: "rhel", ID: "rocky", VersionID: "9.8", PackageManager: "dnf"},
			})

			if outcome.Status != model.StatusError {
				t.Fatalf("status = %q, want %q", outcome.Status, model.StatusError)
			}
			if outcome.ErrorCode != "patch_evidence_command_failed" {
				t.Fatalf("error code = %q", outcome.ErrorCode)
			}
		})
	}
}
