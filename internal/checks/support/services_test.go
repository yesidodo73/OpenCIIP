package support

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
)

type unitCommandRunner struct {
	results map[string]executor.Result
}

func (r unitCommandRunner) Available(name string) bool { return name == "systemctl" }

func (r unitCommandRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	result, exists := r.results[strings.Join(spec.Arguments, "\x00")]
	if !exists {
		return executor.Result{}, fmt.Errorf("unexpected systemctl arguments: %q", spec.Arguments)
	}
	return result, nil
}

func TestSystemdUnitQueryUsesConcreteProbeForTemplates(t *testing.T) {
	show, pattern := systemdUnitQuery("finger@.service")
	if show != "finger@openciip-probe.service" || pattern != "finger@*.service" {
		t.Fatalf("systemdUnitQuery() = %q, %q", show, pattern)
	}

	show, pattern = systemdUnitQuery("sshd.service")
	if show != "sshd.service" || pattern != "" {
		t.Fatalf("systemdUnitQuery(normal unit) = %q, %q", show, pattern)
	}
}

func TestParseTemplateUnitFileState(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantState  string
		wantExists bool
		wantError  bool
	}{
		{
			name:       "template state",
			output:     "example@.service enabled enabled\n",
			wantState:  "enabled",
			wantExists: true,
		},
		{
			name:       "enabled instance wins over disabled template",
			output:     "example@.service disabled disabled\nexample@tenant.service enabled enabled\n",
			wantState:  "enabled",
			wantExists: true,
		},
		{name: "missing template"},
		{
			name:      "foreign record",
			output:    "other@.service disabled disabled\n",
			wantError: true,
		},
		{
			name:      "duplicate record",
			output:    "example@.service disabled disabled\nexample@.service disabled disabled\n",
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, exists, err := parseTemplateUnitFileState(test.output, "example@.service")
			if (err != nil) != test.wantError {
				t.Fatalf("parseTemplateUnitFileState() error = %v", err)
			}
			if test.wantError {
				return
			}
			if state != test.wantState || exists != test.wantExists {
				t.Fatalf("parseTemplateUnitFileState() = %q, %t", state, exists)
			}
		})
	}
}

func TestInspectUnitsTreatsAbsentTemplateAsNotInstalled(t *testing.T) {
	showArguments := []string{
		"show",
		"--no-pager",
		"--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths",
		"--",
		"finger@openciip-probe.service",
	}
	listArguments := []string{"list-unit-files", "--no-pager", "--no-legend", "--", "finger@*.service"}
	runner := unitCommandRunner{results: map[string]executor.Result{
		strings.Join(showArguments, "\x00"): {
			ExitCode: 0,
			Stdout:   []byte("Id=finger@openciip-probe.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nFragmentPath=\nDropInPaths=\n"),
		},
		strings.Join(listArguments, "\x00"): {ExitCode: 1},
	}}

	states, evidence, err := InspectUnits(context.Background(), evaluator.Environment{Commands: runner}, []string{"finger@.service"})
	if err != nil {
		t.Fatalf("InspectUnits() error = %v", err)
	}
	if len(states) != 1 || states[0].Name != "finger@.service" || states[0].InspectionName != "finger@openciip-probe.service" || UnitInstalled(states[0]) {
		t.Fatalf("states = %#v", states)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence count = %d, want 2", len(evidence))
	}
}
