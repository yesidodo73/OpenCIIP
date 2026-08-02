package filecheck

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestStartupUnitPathsIncludesGeneratedAndTransientFragments(t *testing.T) {
	t.Parallel()

	for _, fragment := range []string{
		"/run/systemd/generator/boot.mount",
		"/run/systemd/transient/example.service",
	} {
		paths, reason := startupUnitPaths(support.UnitState{FragmentPath: fragment})
		if reason != "" || !slices.Equal(paths, []string{fragment}) {
			t.Errorf("startupUnitPaths(%q) = %#v, %q, want fragment path without an unknown reason", fragment, paths, reason)
		}
	}
}

func TestStartupUnitPathsNormalizesAbsoluteFragmentWithinRoot(t *testing.T) {
	t.Parallel()

	const fragment = "/usr/lib/systemd/system/../../dracut/modules.d/98dracut-systemd/dracut-shutdown.service"
	paths, reason := startupUnitPaths(support.UnitState{FragmentPath: fragment})
	want := []string{"/usr/lib/dracut/modules.d/98dracut-systemd/dracut-shutdown.service"}
	if reason != "" || !slices.Equal(paths, want) {
		t.Fatalf("startupUnitPaths() = %#v, %q, want %#v without an unknown reason", paths, reason, want)
	}
}

func TestStartupUnitPathsAcceptsLiteralSystemdHexEscapes(t *testing.T) {
	t.Parallel()

	const fragment = `/run/systemd/generator/dev-mapper-data\x2dswap.swap`
	paths, reason := startupUnitPaths(support.UnitState{FragmentPath: fragment})
	if reason != "" || !slices.Equal(paths, []string{fragment}) {
		t.Fatalf("startupUnitPaths() = %#v, %q, want literal systemd hex escape", paths, reason)
	}
}

func TestStartupUnitPathsRejectsNonSystemdBackslashEscapes(t *testing.T) {
	t.Parallel()

	for _, fragment := range []string{
		`/run/systemd/generator/dev-mapper-data\y2dswap.swap`,
		`/run/systemd/generator/dev-mapper-data\x2swap.swap`,
		`/run/systemd/generator/dev-mapper-data\..\swap.swap`,
	} {
		if paths, reason := startupUnitPaths(support.UnitState{FragmentPath: fragment}); reason == "" || len(paths) != 0 {
			t.Errorf("startupUnitPaths(%q) = %#v, %q, want invalid fragment", fragment, paths, reason)
		}
	}
}

func TestStartupUnitPathsAllowsLoadedRuntimeUnitWithoutFragment(t *testing.T) {
	t.Parallel()

	paths, reason := startupUnitPaths(support.UnitState{
		LoadState:   "loaded",
		DropInPaths: "/usr/lib/systemd/system/user-.slice.d/10-defaults.conf",
	})
	if reason != "" || !slices.Equal(paths, []string{"/usr/lib/systemd/system/user-.slice.d/10-defaults.conf"}) {
		t.Fatalf("startupUnitPaths() = %#v, %q, want the drop-in without a fragment error", paths, reason)
	}
}

func TestStartupUnitPathsRejectsUnitThatCannotBeLoaded(t *testing.T) {
	t.Parallel()

	paths, reason := startupUnitPaths(support.UnitState{LoadState: "not-found"})
	if len(paths) != 0 || reason == "" {
		t.Fatalf("startupUnitPaths() = %#v, %q, want an unknown reason", paths, reason)
	}
}

func TestStartupUnitAbsentRequiresDefinitiveEmptyNotFoundState(t *testing.T) {
	t.Parallel()

	if !startupUnitAbsent(support.UnitState{LoadState: "not-found", ActiveState: "inactive"}) {
		t.Fatal("definitively absent inactive unit was not accepted")
	}
	for _, state := range []support.UnitState{
		{LoadState: "not-found", ActiveState: "active"},
		{LoadState: "not-found", ActiveState: "inactive", SubState: "running"},
		{LoadState: "not-found", ActiveState: "inactive", UnitFileState: "enabled"},
		{LoadState: "not-found", ActiveState: "inactive", FragmentPath: "/etc/systemd/system/example.service"},
		{LoadState: "not-found", ActiveState: "inactive", DropInPaths: "/etc/systemd/system/example.service.d/override.conf"},
		{LoadState: "loaded", ActiveState: "inactive"},
	} {
		if startupUnitAbsent(state) {
			t.Errorf("startupUnitAbsent(%#v) = true, want retained for inspection", state)
		}
	}
}

func TestStartupUnitStateDigestUsesScopeMeaningInsteadOfRuntimeSubstate(t *testing.T) {
	t.Parallel()

	initial := support.UnitState{
		Name:           "example.service",
		InspectionName: "example.service",
		LoadState:      "loaded",
		ActiveState:    "activating",
		SubState:       "start",
		UnitFileState:  "enabled",
		FragmentPath:   "/usr/lib/systemd/system/example.service",
		DropInPaths: strings.Join([]string{
			"/etc/systemd/system/example.service.d/20-local.conf",
			"/etc/systemd/system/example.service.d/10-base.conf",
		}, " "),
	}
	stillInScope := initial
	stillInScope.ActiveState = "active"
	stillInScope.SubState = "running"
	stillInScope.UnitFileState = "linked-runtime"
	stillInScope.DropInPaths = strings.Join([]string{
		"/etc/systemd/system/example.service.d/10-base.conf",
		"/etc/systemd/system/example.service.d/20-local.conf",
	}, " ")
	if startupUnitStateDigest(initial) != startupUnitStateDigest(stillInScope) {
		t.Fatal("runtime-only state and drop-in ordering changes invalidated an in-scope unit")
	}
	equivalentPath := stillInScope
	equivalentPath.FragmentPath = "/usr/lib/systemd/system/../system/example.service"
	if startupUnitStateDigest(initial) != startupUnitStateDigest(equivalentPath) {
		t.Fatal("equivalent normalized fragment path invalidated an in-scope unit")
	}

	leftScope := stillInScope
	leftScope.ActiveState = "inactive"
	leftScope.SubState = "dead"
	leftScope.UnitFileState = "disabled"
	if startupUnitStateDigest(initial) == startupUnitStateDigest(leftScope) {
		t.Fatal("unit leaving the active/enabled scope was not detected")
	}

	absent := support.UnitState{
		Name:           "missing.service",
		InspectionName: "missing.service",
		LoadState:      "not-found",
		ActiveState:    "inactive",
	}
	notDefinitivelyAbsent := absent
	notDefinitivelyAbsent.UnitFileState = "disabled"
	if startupUnitStateDigest(absent) == startupUnitStateDigest(notDefinitivelyAbsent) {
		t.Fatal("definitively absent unit changing inspection meaning was not detected")
	}
}

func TestRevalidateStartupSystemdUnitGuardIgnoresExecRuntimeFields(t *testing.T) {
	t.Parallel()

	initialState := support.UnitState{
		Name:           "example.service",
		InspectionName: "example.service",
		LoadState:      "loaded",
		ActiveState:    "active",
		SubState:       "running",
		UnitFileState:  "enabled",
		FragmentPath:   "/usr/lib/systemd/system/example.service",
	}
	initialProperties := map[string]string{
		"LoadState": "loaded",
		"ExecStart": "{ path=/usr/bin/example ; argv[]=/usr/bin/example --serve ; ignore_errors=no ; pid=10 ; code=(null) ; status=0/0 }",
	}
	guard := &startupSystemdUnitGuard{
		UnitName:                  "example.service",
		InspectionName:            "example.service",
		InitialStateDigest:        startupUnitStateDigest(initialState),
		CheckExecutableProperties: true,
		InitialExecutableDigest:   startupExecutablePropertiesDigest(initialProperties, true),
	}
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(strings.Join([]string{
		"Id=example.service",
		"LoadState=loaded",
		"ActiveState=active",
		"SubState=running",
		"UnitFileState=enabled",
		"FragmentPath=/usr/lib/systemd/system/example.service",
		"DropInPaths=",
		"ExecStart={ path=/usr/bin/example ; argv[]=/usr/bin/example --serve ; ignore_errors=no ; pid=999 ; code=exited ; status=0/0 }",
		"",
	}, "\n"))}}

	validations, evidence := revalidateStartupSystemdUnitGuards(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]*startupSystemdUnitGuard{guard},
	)
	if !validations[guard] {
		t.Fatalf("unit guard validation = false, evidence=%#v, want runtime-only Exec fields ignored", evidence)
	}
	for _, item := range evidence {
		if item.Command != nil {
			t.Fatalf("unit guard revalidation retained raw command output: %#v", item)
		}
	}
	guardEvidence := evidence[len(evidence)-1]
	if guardEvidence.Source != "systemd-start-unit-snapshot-guard" ||
		guardEvidence.Fact["all_stable"] != true ||
		guardEvidence.Fact["initial_executable_sha256"] != guardEvidence.Fact["current_executable_sha256"] {
		t.Fatalf("unit guard evidence = %#v, want stable masked digests", guardEvidence)
	}
	if _, exists := guardEvidence.Fact["unit_name"]; exists {
		t.Fatalf("unit guard evidence retained a raw unit name: %#v", guardEvidence)
	}
}

func TestRevalidateStartupSystemdUnitGuardRejectsStateOrExecChanges(t *testing.T) {
	t.Parallel()

	initialState := support.UnitState{
		Name:           "example.service",
		InspectionName: "example.service",
		LoadState:      "loaded",
		ActiveState:    "active",
		SubState:       "running",
		UnitFileState:  "enabled",
		FragmentPath:   "/usr/lib/systemd/system/example.service",
	}
	initialProperties := map[string]string{
		"LoadState": "loaded",
		"ExecStart": "{ path=/usr/bin/example ; argv[]=/usr/bin/example --serve ; ignore_errors=no ; }",
	}
	tests := []struct {
		name   string
		output string
	}{
		{
			name: "state",
			output: strings.Join([]string{
				"Id=example.service",
				"LoadState=loaded",
				"ActiveState=inactive",
				"SubState=dead",
				"UnitFileState=disabled",
				"FragmentPath=/usr/lib/systemd/system/example.service",
				"DropInPaths=",
				"ExecStart={ path=/usr/bin/example ; argv[]=/usr/bin/example --serve ; ignore_errors=no ; }",
				"",
			}, "\n"),
		},
		{
			name: "exec",
			output: strings.Join([]string{
				"Id=example.service",
				"LoadState=loaded",
				"ActiveState=active",
				"SubState=running",
				"UnitFileState=enabled",
				"FragmentPath=/usr/lib/systemd/system/example.service",
				"DropInPaths=",
				"ExecStart={ path=/usr/bin/other ; argv[]=/usr/bin/other --serve ; ignore_errors=no ; }",
				"",
			}, "\n"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard := &startupSystemdUnitGuard{
				UnitName:                  "example.service",
				InspectionName:            "example.service",
				InitialStateDigest:        startupUnitStateDigest(initialState),
				CheckExecutableProperties: true,
				InitialExecutableDigest:   startupExecutablePropertiesDigest(initialProperties, true),
			}
			validations, evidence := revalidateStartupSystemdUnitGuards(
				context.Background(),
				evaluator.Environment{Commands: systemdCommandFixtureRunner{
					result: executor.Result{Stdout: []byte(test.output)},
				}},
				[]*startupSystemdUnitGuard{guard},
			)
			if validations[guard] {
				t.Fatalf("unit guard validation = true, evidence=%#v, want %s change rejected", evidence, test.name)
			}
			if guardEvidence := evidence[len(evidence)-1]; guardEvidence.Fact["all_stable"] != false {
				t.Fatalf("unit guard evidence = %#v, want rejected result", guardEvidence)
			}
		})
	}
}

func TestRevalidateStartupSystemdUnitGuardRejectsUnqueryableFinalState(t *testing.T) {
	t.Parallel()

	state := support.UnitState{
		Name:           "example.service",
		InspectionName: "example.service",
		LoadState:      "loaded",
		ActiveState:    "active",
		SubState:       "running",
		FragmentPath:   "/usr/lib/systemd/system/example.service",
	}
	properties := map[string]string{
		"LoadState": "loaded",
		"ExecStart": "{ path=/usr/bin/example ; argv[]=/usr/bin/example ; ignore_errors=no ; }",
	}
	guard := &startupSystemdUnitGuard{
		UnitName:                  "example.service",
		InspectionName:            "example.service",
		InitialStateDigest:        startupUnitStateDigest(state),
		CheckExecutableProperties: true,
		InitialExecutableDigest:   startupExecutablePropertiesDigest(properties, true),
	}
	validations, evidence := revalidateStartupSystemdUnitGuards(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{
			err: errors.New("systemctl query failed"),
		}},
		[]*startupSystemdUnitGuard{guard},
	)
	if validations[guard] {
		t.Fatalf("unit guard validation = true, evidence=%#v, want unqueryable final state rejected", evidence)
	}
	guardEvidence := evidence[len(evidence)-1]
	if guardEvidence.Fact["state_requery_succeeded"] != false ||
		guardEvidence.Fact["executable_requery_succeeded"] != false ||
		guardEvidence.Fact["all_stable"] != false {
		t.Fatalf("unit guard evidence = %#v, want failed final requery", guardEvidence)
	}
}

func TestAcceptStartupPermissionAssessmentsDiscardsUnstableUnitExclusivePaths(t *testing.T) {
	t.Parallel()

	stableUnit := &startupSystemdUnitGuard{UnitName: "stable.service"}
	unstableUnit := &startupSystemdUnitGuard{UnitName: "changed.service"}
	pending := []startupPendingPermissionAssessment{
		{
			Path: "/usr/bin/exclusive",
			Assessment: support.PermissionAssessment{
				Exists:     true,
				Violations: []string{"허용되지 않은 권한 비트 0020"},
			},
			GuardsStable: true,
		},
		{
			Path: "/usr/bin/shared",
			Assessment: support.PermissionAssessment{
				Exists:     true,
				Violations: []string{"허용되지 않은 권한 비트 0002"},
			},
			GuardsStable: true,
		},
	}
	violations, unknowns, err := acceptStartupPermissionAssessments(
		pending,
		map[string][]*startupSystemdUnitGuard{
			"/usr/bin/exclusive": {unstableUnit},
			"/usr/bin/shared":    {unstableUnit, stableUnit},
		},
		map[*startupSystemdUnitGuard]bool{
			unstableUnit: false,
			stableUnit:   true,
		},
		true,
		nil,
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.Equal(violations, []string{"/usr/bin/shared: 허용되지 않은 권한 비트 0002"}) {
		t.Fatalf(
			"acceptStartupPermissionAssessments() = violations=%#v unknowns=%#v err=%v, want only shared stable-unit violation",
			violations,
			unknowns,
			err,
		)
	}

	violations, unknowns, err = acceptStartupPermissionAssessments(
		pending,
		map[string][]*startupSystemdUnitGuard{
			"/usr/bin/exclusive": {stableUnit},
			"/usr/bin/shared":    {stableUnit},
		},
		map[*startupSystemdUnitGuard]bool{stableUnit: true},
		false,
		nil,
	)
	if err != nil || len(violations) != 0 || len(unknowns) != 0 {
		t.Fatalf(
			"unstable inventory accepted stale permission results: violations=%#v unknowns=%#v err=%v",
			violations,
			unknowns,
			err,
		)
	}
}

func TestEvaluateStartupPermissionsRevalidatesFilesystemAfterSystemdGuardQueries(t *testing.T) {
	t.Parallel()

	reader := &startupPermissionRaceReader{
		Reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/example": &fstest.MapFile{Mode: 0o777},
		}}},
		ParentPath: "/usr/bin",
	}
	runner := &startupEvaluatorGuardRunner{reader: reader}
	outcome := evaluateStartupPermissions(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{
			Commands: runner,
			Files:    reader,
			Platform: model.PlatformInfo{InitSystem: "systemd"},
		},
	)
	if outcome.Status != model.StatusUnknown || outcome.ErrorCode != "" {
		t.Fatalf(
			"evaluateStartupPermissions() = status=%s error=%q summary=%q, want filesystem mutation UNKNOWN",
			outcome.Status,
			outcome.ErrorCode,
			outcome.Summary,
		)
	}
	if strings.Contains(fmt.Sprint(outcome.Details), "허용되지 않은 권한 비트") {
		t.Fatalf("stale permission violation survived final filesystem guard: %#v", outcome.Details)
	}
	rejectedGuardEvidence := false
	for _, item := range outcome.Evidence {
		if item.Source == "systemd-start-permission-snapshot-guard" &&
			item.Fact["permission_result_accepted"] == false {
			rejectedGuardEvidence = true
			break
		}
	}
	if !rejectedGuardEvidence {
		t.Fatalf("final filesystem guard did not record the discarded result: %#v", outcome.Evidence)
	}
	if runner.stateQueries != 2 || !reader.parentChanged {
		t.Fatalf(
			"final systemd guard did not trigger the boundary mutation: state_queries=%d changed=%t",
			runner.stateQueries,
			reader.parentChanged,
		)
	}
}

func TestEvaluateStartupPermissionsRejectsUnitBoundaryMutations(t *testing.T) {
	t.Parallel()

	const (
		fragmentPath  = "/usr/lib/systemd/system/example.service"
		oldExecutable = "/usr/bin/old-example"
		newExecutable = "/usr/bin/new-example"
	)
	tests := []struct {
		name                    string
		mode                    string
		wantUnitQueryStable     bool
		wantConfigurationStable bool
	}{
		{
			name:                    "ExecStart changes after auxiliary requery",
			mode:                    "exec_after_auxiliary",
			wantUnitQueryStable:     false,
			wantConfigurationStable: true,
		},
		{
			name:                    "fragment changes after unit requery",
			mode:                    "fragment_after_unit",
			wantUnitQueryStable:     true,
			wantConfigurationStable: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &startupUnitBoundaryMutationReader{
				Reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
					"usr/lib/systemd/system/example.service": &fstest.MapFile{
						Data: []byte("[Service]\nExecStart=" + oldExecutable + "\n"),
						Mode: 0o644,
					},
					"usr/bin/old-example": &fstest.MapFile{Mode: 0o777},
					"usr/bin/new-example": &fstest.MapFile{Mode: 0o755},
				}}},
				FragmentPath:  fragmentPath,
				OldExecutable: oldExecutable,
			}
			runner := &startupUnitBoundaryMutationRunner{
				Reader:        reader,
				Mode:          test.mode,
				FragmentPath:  fragmentPath,
				OldExecutable: oldExecutable,
				NewExecutable: newExecutable,
			}
			outcome := evaluateStartupPermissions(
				context.Background(),
				model.ResolvedRule{},
				evaluator.Environment{
					Commands: runner,
					Files:    reader,
					Platform: model.PlatformInfo{InitSystem: "systemd"},
				},
			)
			if outcome.Status != model.StatusUnknown || outcome.ErrorCode != "" {
				t.Fatalf(
					"evaluateStartupPermissions() = status=%s error=%q details=%#v, want stale path UNKNOWN",
					outcome.Status,
					outcome.ErrorCode,
					outcome.Details,
				)
			}
			if !reader.AuxiliaryRequeryComplete || !runner.MutationTriggered {
				t.Fatalf(
					"boundary mutation was not triggered after auxiliary requery: auxiliary=%t mutation=%t",
					reader.AuxiliaryRequeryComplete,
					runner.MutationTriggered,
				)
			}
			if !reader.UnitRequeryComplete || !reader.FinalFilesystemObserved ||
				reader.CommandAfterFilesystem {
				t.Fatalf(
					"final boundary order = unit=%t filesystem=%t later_command=%t",
					reader.UnitRequeryComplete,
					reader.FinalFilesystemObserved,
					reader.CommandAfterFilesystem,
				)
			}
			if strings.Contains(fmt.Sprint(outcome.Details), "허용되지 않은 권한 비트") {
				t.Fatalf("old executable violation survived the final boundary: %#v", outcome.Details)
			}

			oldPathRejected := false
			unitFinalGuardFound := false
			for _, item := range outcome.Evidence {
				if item.Command != nil {
					for _, argument := range item.Command.Arguments {
						if strings.Contains(argument, "ExecStart") {
							t.Fatalf("raw ExecStart requery evidence was retained: %#v", item)
						}
					}
				}
				switch item.Source {
				case "systemd-start-permission-snapshot-guard":
					if item.Fact["path_sha256"] == pathDigest(oldExecutable) &&
						item.Fact["permission_result_accepted"] == false {
						oldPathRejected = true
					}
				case "systemd-start-unit-final-guard":
					if item.Fact["unit_name_sha256"] != pathDigest("example.service") {
						continue
					}
					unitFinalGuardFound = true
					if item.Fact["unit_query_stable"] != test.wantUnitQueryStable ||
						item.Fact["configuration_files_stable"] != test.wantConfigurationStable ||
						item.Fact["permission_results_acceptable"] != false {
						t.Fatalf("unit final guard = %#v", item)
					}
				}
			}
			if !oldPathRejected || !unitFinalGuardFound {
				t.Fatalf(
					"stale path rejection evidence missing: old_path=%t unit_guard=%t evidence=%#v",
					oldPathRejected,
					unitFinalGuardFound,
					outcome.Evidence,
				)
			}
		})
	}
}

func TestPermissionRevalidationGuardsFragmentAndDropInPaths(t *testing.T) {
	t.Parallel()

	for _, systemPath := range []string{
		"/usr/lib/systemd/system/example.service",
		"/etc/systemd/system/example.service.d/10-local.conf",
	} {
		t.Run(path.Base(systemPath), func(t *testing.T) {
			reader := &startupToggleMetadataReader{
				Reader: startupFixtureReader{files: fstest.MapFS{
					strings.TrimPrefix(systemPath, "/"): &fstest.MapFile{Mode: 0o644},
				}},
				Path:        systemPath,
				ChangedMode: 0o666,
			}
			runner := &startupMutableSecurityRunner{
				aclByPath: map[string]string{
					systemPath: "user::rw-\ngroup::r--\nother::r--\n",
				},
			}
			pending, _ := collectStartupPermissionPathAssessments(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: reader},
				map[string]struct{}{systemPath: {}},
				nil,
			)
			if len(pending) != 1 || !pending[0].GuardCaptureComplete ||
				len(pending[0].Guards) != 1 {
				t.Fatalf("fragment/drop-in guard was not captured: %#v", pending)
			}

			reader.Changed = true
			evidence := revalidateStartupPermissionPathAssessments(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: reader},
				pending,
				nil,
			)
			if pending[0].GuardsStable {
				t.Fatalf("changed fragment/drop-in permission was accepted: evidence=%#v", evidence)
			}
			assertRejectedStartupPermissionGuardEvidence(t, evidence, 1)
		})
	}
}

func TestPermissionSnapshotGuardRunsAfterFinalPermissionRequery(t *testing.T) {
	t.Parallel()

	const systemPath = "/usr/lib/systemd/system/example.service"
	reader := &startupPermissionRaceReader{
		Reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/lib/systemd/system/example.service": &fstest.MapFile{Mode: 0o644},
		}}},
		ParentPath:   "/usr/lib/systemd/system",
		ChangeParent: true,
		TriggerPath:  systemPath,
	}
	pending, _ := collectStartupPermissionPathAssessments(
		context.Background(),
		evaluator.Environment{Files: reader},
		map[string]struct{}{systemPath: {}},
		nil,
	)
	if len(pending) != 1 || !pending[0].GuardCaptureComplete {
		t.Fatalf("permission snapshot guard was not captured: %#v", pending)
	}

	reader.Armed = true
	evidence := revalidateStartupPermissionPathAssessments(
		context.Background(),
		evaluator.Environment{Files: reader},
		pending,
		nil,
	)
	if !reader.parentChanged || pending[0].GuardsStable {
		t.Fatalf(
			"mutation during final permission requery was accepted: changed=%t evidence=%#v",
			reader.parentChanged,
			evidence,
		)
	}
	assertRejectedStartupPermissionGuardEvidence(t, evidence, 1)
}

func TestPermissionSnapshotCapturesParentsForSystemdHexEscapedPath(t *testing.T) {
	t.Parallel()

	const systemPath = `/run/systemd/generator/dev-mapper-data\x2dswap.swap`
	reader := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		`run/systemd/generator/dev-mapper-data\x2dswap.swap`: &fstest.MapFile{Mode: 0o644},
	}}}
	snapshot, complete := captureStartupPermissionFilesystemSnapshot(reader, systemPath)
	if !complete {
		t.Fatal("systemd hex-escaped path snapshot was incomplete")
	}
	for _, expected := range []string{"/run", "/run/systemd", "/run/systemd/generator"} {
		found := false
		for _, entry := range snapshot.Entries {
			if entry.Path == expected && entry.Roles&startupSnapshotRoleParent != 0 {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("parent %s was not captured in snapshot %#v", expected, snapshot.Entries)
		}
	}
}

func TestInactiveLegacyPathBecomingExecutableInvalidatesGuard(t *testing.T) {
	t.Parallel()

	const legacyPath = "/etc/rc.local"
	reader := &startupToggleMetadataReader{
		Reader: startupFixtureReader{files: fstest.MapFS{
			"etc/rc.local": &fstest.MapFile{Mode: 0o644},
		}},
		Path:        legacyPath,
		ChangedMode: 0o755,
	}
	active, inactive, _, unknowns := inspectStartupLegacyPathGuards(reader)
	if len(active) != 0 || len(inactive) != 2 || len(unknowns) != 0 {
		t.Fatalf(
			"legacy guard setup = active=%#v inactive=%#v unknowns=%#v, want two stable inactive candidates",
			active,
			inactive,
			unknowns,
		)
	}
	reader.Changed = true
	finalUnknowns, evidence := revalidateStartupInactiveLegacyGuards(reader, inactive)
	if len(finalUnknowns) != 1 {
		t.Fatalf("legacy execution-state change = %#v, evidence=%#v, want one unknown", finalUnknowns, evidence)
	}
}

func TestStartupInventoryGuardRejectsNewUnitsAndDependencyChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		change   string
		relation string
	}{
		{name: "new unit", change: "unit", relation: "Wants"},
		{name: "same set changed Wants relation", change: "dependency", relation: "Wants"},
		{name: "same set changed BindsTo relation", change: "dependency", relation: "BindsTo"},
		{name: "same set changed Upholds relation", change: "dependency", relation: "Upholds"},
		{name: "same set changed OnFailure relation", change: "dependency", relation: "OnFailure"},
		{name: "same set changed OnSuccess relation", change: "dependency", relation: "OnSuccess"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &startupInventoryMutationRunner{Relation: test.relation}
			initial, _, err := inspectStartupUnitInventory(
				context.Background(),
				evaluator.Environment{Commands: runner},
			)
			if err != nil {
				t.Fatalf("initial inventory: %v", err)
			}
			runner.Change = test.change
			stable, evidence := revalidateStartupUnitInventory(
				context.Background(),
				evaluator.Environment{Commands: runner},
				initial,
			)
			if stable {
				t.Fatalf("changed %s inventory was accepted: %#v", test.change, evidence)
			}
			for _, item := range evidence {
				if item.Command != nil {
					t.Fatalf("final inventory retained raw systemctl output: %#v", item)
				}
			}
		})
	}
}

func TestStartupAuxiliaryGuardRejectsACLAndMountSelectionChanges(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/helper"
	tests := []struct {
		name         string
		initial      startupAuxiliarySnapshot
		acl          string
		mountOptions string
	}{
		{
			name: "acl",
			initial: startupAuxiliarySnapshot{
				Kind: startupAuxiliaryExecutionACL, Path: executable, State: "usable",
			},
			acl: "user::rwx\nuser:1000:---\ngroup::r-x\nmask::r-x\nother::r-x\n",
		},
		{
			name: "mount",
			initial: startupAuxiliarySnapshot{
				Kind: startupAuxiliaryMountExec, Path: executable, State: "skip",
			},
			acl:          "user::rwx\ngroup::r-x\nother::r-x\n",
			mountOptions: "rw,relatime",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := startupFixtureReader{files: fstest.MapFS{
				"usr/bin/helper": &fstest.MapFile{Mode: 0o755},
			}}
			snapshot, complete := captureStartupPermissionFilesystemSnapshot(reader, executable)
			if !complete || !addStartupAuxiliarySnapshot(snapshot, test.initial) {
				t.Fatal("failed to construct auxiliary startup guard")
			}
			runner := &startupMutableSecurityRunner{
				aclByPath: map[string]string{executable: test.acl},
				mountByPath: map[string]string{
					executable: test.mountOptions,
				},
			}
			pending := []startupPendingPermissionAssessment{{Guards: []*startupFilesystemSnapshot{snapshot}}}
			auxiliaryValidations, evidence := revalidateStartupPermissionAuxiliaryGuards(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: reader},
				pending,
			)
			validations := revalidateStartupPermissionFilesystemGuards(
				reader,
				pending,
				auxiliaryValidations,
			)
			if validations[snapshot].Stable {
				t.Fatalf("changed %s selection input was accepted: %#v", test.name, evidence)
			}
			for _, item := range evidence {
				if item.Command != nil {
					t.Fatalf("auxiliary guard retained raw ACL or mount output: %#v", item)
				}
			}
		})
	}
}

func TestValidSystemdUnitTokenAcceptsCanonicalEscapesAndRootSlice(t *testing.T) {
	t.Parallel()

	for _, unitName := range []string{
		`dev-dm\x2d1.swap`,
		`system-serial\x2dgetty.slice`,
		"-.slice",
	} {
		if !validSystemdUnitToken(unitName) {
			t.Errorf("validSystemdUnitToken(%q) = false, want true", unitName)
		}
	}
	for _, unitName := range []string{
		`dev-dm\x2.swap`,
		`dev-dm\y2d1.swap`,
		`dev-dm\..\evil.swap`,
		`escaped\x2d@.service`,
	} {
		if validSystemdUnitToken(unitName) {
			t.Errorf("validSystemdUnitToken(%q) = true, want false", unitName)
		}
	}
}

func TestStartupExecutablePathsTreatsOmittedEmptyPropertiesAsComplete(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("ExecStart={ path=/usr/sbin/NetworkManager ; argv[]=/usr/sbin/NetworkManager --no-daemon ; ignore_errors=no ; }\n"),
		},
	}
	files := startupFixtureReader{files: fstest.MapFS{
		"usr/sbin/NetworkManager": &fstest.MapFile{Mode: 0o755},
	}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"NetworkManager.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/usr/sbin/NetworkManager"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want one executable and complete", paths, complete, err)
	}
}

func TestStartupExecutablePathsAcceptsLiveSystemctlFields(t *testing.T) {
	t.Parallel()

	liveOutput := strings.Join([]string{
		"Type=dbus",
		"RemainAfterExit=no",
		"ExecStart={ path=/usr/sbin/NetworkManager ; argv[]=/usr/sbin/NetworkManager --no-daemon ; ignore_errors=no ; start_time=[Wed 2026-07-29 23:31:47 KST] ; stop_time=[n/a] ; pid=800 ; code=(null) ; status=0/0 }",
		"Environment=",
		"PassEnvironment=",
		"RootDirectory=",
		"RootImage=",
		"ExtensionDirectories=",
		"ExtensionImages=",
		"MountImages=",
		"InaccessiblePaths=",
		"ExecPaths=",
		"NoExecPaths=",
		"ExecSearchPath=",
		"PrivateTmp=no",
		"PrivateDevices=no",
		"ProtectHome=read-only",
		"BindPaths=",
		"BindReadOnlyPaths=",
		"TemporaryFileSystem=",
		"JoinsNamespaceOf=",
		"LoadState=loaded",
		"",
	}, "\n")
	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte(liveOutput),
		},
	}
	files := startupFixtureReader{files: fstest.MapFS{
		"usr/sbin/NetworkManager": &fstest.MapFile{Mode: 0o755},
	}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"NetworkManager.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/usr/sbin/NetworkManager"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want live systemctl fields to be complete", paths, complete, err)
	}
}

func TestParseSystemdCommandsRejectsMalformedRuntimeTail(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`{ path=/usr/bin/tool ; argv[]=/usr/bin/tool ; status=0/0`,
		`{ path=/usr/bin/tool ; argv[]=/usr/bin/tool ; status=0/0 { }`,
	} {
		if _, complete := parseSystemdCommands(value); complete {
			t.Errorf("parseSystemdCommands(%q) = complete, want malformed runtime tail rejected", value)
		}
	}
}

func TestStartupExecutablePathsAcceptsLoadedServiceWithoutExecCommands(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{Stdout: []byte("LoadState=loaded\nType=simple\nRemainAfterExit=no\n")},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner},
		"example.service",
	)
	if err != nil || !complete || len(paths) != 0 {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want no paths and complete", paths, complete, err)
	}
}

func TestStartupExecutablePathsKeepsNotFoundServiceWithoutExecCommandsIncomplete(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{Stdout: []byte("LoadState=not-found\nType=simple\n")},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner},
		"example.service",
	)
	if err != nil || complete || len(paths) != 0 {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want no paths and incomplete", paths, complete, err)
	}
}

func TestParseSystemdCommandPathsDoesNotTreatBusyBoxWrapperAsComplete(t *testing.T) {
	t.Parallel()

	value := `{ path=/usr/bin/busybox ; argv[]=/usr/bin/busybox sh /opt/start.sh ; ignore_errors=no ; }`
	paths, complete := parseSystemdCommandPaths(value)
	if complete || !slices.Equal(paths, []string{"/usr/bin/busybox"}) {
		t.Fatalf("parseSystemdCommandPaths() = %#v, %t, want busybox path and incomplete", paths, complete)
	}
}

func TestParseSystemdCommandPathsIgnoresPathOptionInArguments(t *testing.T) {
	t.Parallel()

	value := `{ path=/usr/bin/qemu-ga ; argv[]=/usr/bin/qemu-ga --method=virtio-serial --path=/dev/virtio-ports/org.qemu.guest_agent.0 ; ignore_errors=no ; }`
	paths, complete := parseSystemdCommandPaths(value)
	if !complete || !slices.Equal(paths, []string{"/usr/bin/qemu-ga"}) {
		t.Fatalf("parseSystemdCommandPaths() = %#v, %t, want only the executable path and complete", paths, complete)
	}
}

func TestParseSystemdCommandPathsTreatsCodeLaunchersAsIncomplete(t *testing.T) {
	t.Parallel()

	for _, executable := range []string{
		"/usr/bin/php",
		"/usr/bin/php8.4",
		"/usr/bin/java",
		"/usr/bin/lua5.4",
		"/usr/bin/python3.12",
		"/usr/bin/Rscript",
		"/usr/bin/dotnet",
		"/usr/bin/deno",
		"/usr/bin/systemd-run",
	} {
		value := fmt.Sprintf(
			"{ path=%s ; argv[]=%s /tmp/application.payload ; ignore_errors=no ; }",
			executable,
			executable,
		)
		paths, complete := parseSystemdCommandPaths(value)
		if complete || !slices.Equal(paths, []string{executable}) {
			t.Errorf("parseSystemdCommandPaths(%q) = %#v, %t, want launcher path and incomplete", executable, paths, complete)
		}
	}
}

func TestStartupExecutablePathsResolvesSymlinkedPythonScript(t *testing.T) {
	t.Parallel()

	const executable = "/usr/local/bin/run-app"
	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("Type=simple\nExecStart={ path=" + executable + " ; argv[]=" + executable + " /tmp/start.py ; ignore_errors=no ; }\n"),
		},
	}
	files := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/python3": &fstest.MapFile{Mode: 0o755},
			"tmp/start.py":    &fstest.MapFile{Mode: 0o755},
		}},
		links: map[string]string{executable: "/usr/bin/python3"},
	}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"example.service",
	)
	want := []string{"/tmp/start.py", "/usr/bin/python3"}
	if err != nil || !complete || !slices.Equal(paths, want) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want %#v and complete", paths, complete, err, want)
	}
	resolution := evidence[len(evidence)-1]
	if resolution.Fact["script_path_sha256"] != pathDigest("/tmp/start.py") ||
		resolution.Fact["final_script_path_sha256"] != pathDigest("/tmp/start.py") ||
		resolution.Fact["snapshot_stable"] != true {
		t.Fatalf("script resolution evidence = %#v", resolution)
	}
	for _, rawPathKey := range []string{"script_path", "final_script_path"} {
		if _, exists := resolution.Fact[rawPathKey]; exists {
			t.Fatalf("script resolution evidence retained raw path key %q: %#v", rawPathKey, resolution)
		}
	}
}

func TestStartupExecutablePathsResolvesBareExecutableFromDefaultSearchPath(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=systemd-tmpfiles ; argv[]=systemd-tmpfiles --create ; ignore_errors=no ; }\n"),
		},
		searchAvailable: true,
		searchResult:    executor.Result{Stdout: []byte("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n")},
	}
	files := startupFixtureReader{files: fstest.MapFS{
		"usr/bin/systemd-tmpfiles": &fstest.MapFile{Mode: 0o755},
	}}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"systemd-tmpfiles-setup.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/usr/bin/systemd-tmpfiles"}) || len(evidence) != 9 {
		t.Fatalf("startupExecutablePaths() = %#v, %t, evidence=%d, err=%v", paths, complete, len(evidence), err)
	}
	resolution := evidence[len(evidence)-1]
	if resolution.Source != "systemd-start-executable-resolution" ||
		resolution.Fact["configured_executable_sha256"] != pathDigest("systemd-tmpfiles") ||
		resolution.Fact["selected_path_sha256"] != pathDigest("/usr/bin/systemd-tmpfiles") ||
		resolution.Fact["final_path_sha256"] != pathDigest("/usr/bin/systemd-tmpfiles") ||
		resolution.Fact["snapshot_stable"] != true ||
		resolution.Fact["snapshot_sha256"] != resolution.Fact["current_snapshot_sha256"] {
		t.Fatalf("resolution evidence = %#v", resolution)
	}
	for _, rawPathKey := range []string{"configured_executable", "selected_path", "final_path"} {
		if _, exists := resolution.Fact[rawPathKey]; exists {
			t.Fatalf("resolution evidence retained raw path key %q: %#v", rawPathKey, resolution)
		}
	}
}

func TestStartupExecutablePathsIncludesExecStopPost(t *testing.T) {
	t.Parallel()

	const (
		startExecutable    = "/usr/bin/service-start"
		stopPostExecutable = "/usr/bin/service-cleanup"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nType=simple\n" +
			"ExecStart={ path=" + startExecutable + " ; argv[]=" +
			startExecutable + " ; ignore_errors=no ; }\n" +
			"ExecStopPost={ path=" + stopPostExecutable + " ; argv[]=" +
			stopPostExecutable + " ; ignore_errors=no ; }\n",
	)}}
	files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"usr/bin/service-start":   &fstest.MapFile{Mode: 0o755},
		"usr/bin/service-cleanup": &fstest.MapFile{Mode: 0o755},
	}}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	if err != nil || !complete ||
		!slices.Equal(paths, []string{stopPostExecutable, startExecutable}) {
		t.Fatalf(
			"ExecStopPost startup paths = %#v complete=%t err=%v",
			paths,
			complete,
			err,
		)
	}
}

func TestStartupExecutablePathsUsesFirstBareExecutableMatch(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
		},
		searchAvailable: true,
		searchResult:    executor.Result{Stdout: []byte("/usr/local/bin:/usr/bin\n")},
	}
	files := startupFixtureReader{files: fstest.MapFS{
		"usr/local/bin/helper": &fstest.MapFile{Mode: 0o755},
		"usr/bin/helper":       &fstest.MapFile{Mode: 0o755},
	}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"example.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/usr/local/bin/helper"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want the first ordered match", paths, complete, err)
	}
}

func TestStartupExecutablePathsSkipsDefinitelyUnusableBareCandidates(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "non executable regular", mode: 0o644},
		{name: "directory", mode: os.ModeDir | 0o755},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := systemdCommandFixtureRunner{
				result: executor.Result{
					Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
				},
				searchAvailable: true,
				searchResult:    executor.Result{Stdout: []byte("/first:/second\n")},
			}
			reader := startupFixtureReader{files: fstest.MapFS{
				"first/helper":  &fstest.MapFile{Mode: test.mode},
				"second/helper": &fstest.MapFile{Mode: 0o755},
			}}
			paths, complete, _, err := startupExecutablePaths(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: reader}},
				"example.service",
			)
			if err != nil || !complete || !slices.Equal(paths, []string{"/second/helper"}) {
				t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want second executable candidate", paths, complete, err)
			}
		})
	}
}

func TestStartupExecutablePathsSkipsBrokenBareSymlink(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
		},
		searchAvailable: true,
		searchResult:    executor.Result{Stdout: []byte("/first:/second\n")},
	}
	reader := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"second/helper": &fstest.MapFile{Mode: 0o755},
		}},
		links: map[string]string{"/first/helper": "/missing/helper"},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: reader}},
		"example.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/second/helper"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want second executable candidate", paths, complete, err)
	}
}

func TestStartupExecutablePathsSkipsBareCandidateOnNoexecMount(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
		},
		searchAvailable: true,
		searchResult:    executor.Result{Stdout: []byte("/first:/second\n")},
		mountOptions: map[string]string{
			"/first/helper":  "rw,noexec,relatime",
			"/second/helper": "rw,relatime",
		},
	}
	reader := startupFixtureReader{files: fstest.MapFS{
		"first/helper":  &fstest.MapFile{Mode: 0o755},
		"second/helper": &fstest.MapFile{Mode: 0o755},
	}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: reader}},
		"example.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/second/helper"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want executable candidate outside noexec mount", paths, complete, err)
	}
}

func TestStartupExecutablePathsDoesNotGuessIdentityDependentBareCandidate(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
		},
		searchAvailable: true,
		searchResult:    executor.Result{Stdout: []byte("/first:/second\n")},
	}
	reader := startupFixtureReader{files: fstest.MapFS{
		"first/helper":  &fstest.MapFile{Mode: 0o700},
		"second/helper": &fstest.MapFile{Mode: 0o755},
	}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: reader}},
		"example.service",
	)
	if err != nil || complete || len(paths) != 0 {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want unresolved identity-dependent candidate", paths, complete, err)
	}
}

func TestStartupExecutablePathsDoesNotSkipBareCandidateWithUncertainParentTraversal(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		reader system.Reader
		runner systemdCommandFixtureRunner
	}{
		{
			name: "parent mode is identity dependent",
			reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
				"first":         &fstest.MapFile{Mode: os.ModeDir | 0o700},
				"first/helper":  &fstest.MapFile{Mode: 0o755},
				"second/helper": &fstest.MapFile{Mode: 0o755},
			}}},
		},
		{
			name: "parent ACL is identity dependent",
			reader: startupFixtureReader{files: fstest.MapFS{
				"first/helper":  &fstest.MapFile{Mode: 0o755},
				"second/helper": &fstest.MapFile{Mode: 0o755},
			}},
			runner: systemdCommandFixtureRunner{aclResults: map[string]executor.Result{
				"/first": {Stdout: []byte(
					"user::rwx\nuser:1000:---\ngroup::r-x\nmask::r-x\nother::r-x\n",
				)},
			}},
		},
		{
			name: "parent ACL command is empty",
			reader: startupFixtureReader{files: fstest.MapFS{
				"first/helper":  &fstest.MapFile{Mode: 0o755},
				"second/helper": &fstest.MapFile{Mode: 0o755},
			}},
			runner: systemdCommandFixtureRunner{aclResults: map[string]executor.Result{
				"/first": {},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := test.runner
			runner.result = executor.Result{
				Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
			}
			runner.searchAvailable = true
			runner.searchResult = executor.Result{Stdout: []byte("/first:/second\n")}

			paths, complete, _, err := startupExecutablePaths(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: test.reader},
				"example.service",
			)
			if err != nil || complete || len(paths) != 0 {
				t.Fatalf(
					"startupExecutablePaths() = %#v, %t, %v, want the first candidate unresolved without selecting the second",
					paths,
					complete,
					err,
				)
			}
		})
	}
}

func TestStartupExecutablePathsKeepsBareExecutableUnknownWithoutDefaultSearchPathQuery(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
		},
	}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{
			Commands: runner,
			Files: startupFixtureReader{files: fstest.MapFS{
				"usr/bin/helper": &fstest.MapFile{Mode: 0o755},
			}},
		},
		"example.service",
	)
	if err != nil || complete || len(paths) != 0 || len(evidence) != 1 {
		t.Fatalf(
			"startupExecutablePaths() = %#v, %t, evidence=%d, err=%v, want incomplete without systemd-path search-binaries-default",
			paths,
			complete,
			len(evidence),
			err,
		)
	}
}

func TestStartupExecutablePathsKeepsBareExecutableUnknownForAmbiguousSearchInput(t *testing.T) {
	t.Parallel()

	for _, output := range []string{
		"/usr/bin:/usr/bin\n",
		"/usr/bin\n/bin\n",
		"relative:/usr/bin\n",
	} {
		runner := systemdCommandFixtureRunner{
			result: executor.Result{
				Stdout: []byte("LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
			},
			searchAvailable: true,
			searchResult:    executor.Result{Stdout: []byte(output)},
		}
		paths, complete, _, err := startupExecutablePaths(
			context.Background(),
			evaluator.Environment{
				Commands: runner,
				Files: startupFixtureReader{files: fstest.MapFS{
					"usr/bin/helper": &fstest.MapFile{Mode: 0o755},
				}},
			},
			"example.service",
		)
		if err != nil || complete || len(paths) != 0 {
			t.Errorf("startupExecutablePaths(search=%q) = %#v, %t, %v, want incomplete", output, paths, complete, err)
		}
	}
}

func TestStartupExecutablePathsKeepsBareExecutableUnknownWhenEnvironmentMaySupplyPath(t *testing.T) {
	t.Parallel()

	for _, property := range []string{
		"Environment=PATH=/opt/bin:/usr/bin\n",
		"EnvironmentFile=/etc/default/example (ignore_errors=no)\n",
		"EnvironmentFiles=/etc/default/example (ignore_errors=no)\n",
		"PassEnvironment=LANG PATH\n",
	} {
		runner := systemdCommandFixtureRunner{
			result: executor.Result{
				Stdout: []byte("LoadState=loaded\n" + property + "ExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n"),
			},
			searchAvailable: true,
			searchResult:    executor.Result{Stdout: []byte("/usr/bin\n")},
		}
		paths, complete, evidence, err := startupExecutablePaths(
			context.Background(),
			evaluator.Environment{Commands: runner, Files: startupFixtureReader{files: fstest.MapFS{}}},
			"example.service",
		)
		if err != nil || complete || len(paths) != 0 || len(evidence) != 1 {
			t.Errorf("startupExecutablePaths(%q) = %#v, %t, evidence=%d, err=%v, want incomplete without systemd-path", property, paths, complete, len(evidence), err)
		}
	}
}

func TestStartupExecutablePathsKeepsNamespaceRemappedCommandsIncomplete(t *testing.T) {
	t.Parallel()

	for _, property := range []string{
		"RootDirectory=/srv/root\n",
		"RootImage=/srv/root.raw\n",
		"RootMStack=/run/systemd/mount-rootfs/example\n",
		"BindPaths=/srv/tool:/usr/bin/tool\n",
		"BindReadOnlyPaths=/srv/tool:/usr/bin/tool\n",
		"TemporaryFileSystem=/usr\n",
		"MountImages=/srv/tools.raw:/usr\n",
		"ExtensionImages=/srv/extension.raw\n",
		"ExtensionDirectories=/srv/extension\n",
		"InaccessiblePaths=/usr/bin/tool\n",
		"ExecPaths=/opt/bin\n",
		"NoExecPaths=/usr\n",
		"JoinsNamespaceOf=namespace-owner.service\n",
	} {
		runner := systemdCommandFixtureRunner{
			result: executor.Result{
				Stdout: []byte("LoadState=loaded\n" + property + "ExecStart={ path=/usr/bin/tool ; argv[]=/usr/bin/tool ; ignore_errors=no ; }\n"),
			},
		}
		paths, complete, _, err := startupExecutablePaths(
			context.Background(),
			evaluator.Environment{Commands: runner, Files: startupFixtureReader{files: fstest.MapFS{
				"usr/bin/tool": &fstest.MapFile{Mode: 0o755},
			}}},
			"example.service",
		)
		if err != nil || complete || len(paths) != 0 {
			t.Errorf("startupExecutablePaths(%q) = %#v, %t, %v, want incomplete", property, paths, complete, err)
		}
	}
}

func TestStartupExecutablePathsScopesPrivateNamespacesToAffectedPaths(t *testing.T) {
	t.Parallel()

	for _, property := range []string{
		"PrivateTmp=yes\n",
		"PrivateTmpEx=disconnected\n",
		"PrivateDevices=yes\n",
		"ProtectHome=tmpfs\n",
	} {
		runner := systemdCommandFixtureRunner{result: executor.Result{
			Stdout: []byte("LoadState=loaded\n" + property + "ExecStart={ path=/usr/bin/tool ; argv[]=/usr/bin/tool ; ignore_errors=no ; }\n"),
		}}
		reader := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/tool": &fstest.MapFile{Mode: 0o755},
		}}}
		paths, complete, _, err := startupExecutablePaths(
			context.Background(),
			evaluator.Environment{Commands: runner, Files: reader},
			"example.service",
		)
		if err != nil || !complete || !slices.Equal(paths, []string{"/usr/bin/tool"}) {
			t.Errorf("startupExecutablePaths(%q) = %#v, %t, %v, want unaffected path complete", property, paths, complete, err)
		}
	}

	for _, test := range []struct {
		property   string
		executable string
	}{
		{property: "PrivateTmp=yes\n", executable: "/tmp/tool"},
		{property: "PrivateTmpEx=disconnected\n", executable: "/var/tmp/tool"},
		{property: "PrivateDevices=yes\n", executable: "/dev/tool"},
		{property: "ProtectHome=yes\n", executable: "/home/example/tool"},
		{property: "ProtectHome=tmpfs\n", executable: "/root/tool"},
		{property: "ProtectHome=yes\n", executable: "/run/user/1000/tool"},
	} {
		runner := systemdCommandFixtureRunner{result: executor.Result{
			Stdout: []byte("LoadState=loaded\n" + test.property +
				"ExecStart={ path=" + test.executable + " ; argv[]=" + test.executable + " ; ignore_errors=no ; }\n"),
		}}
		paths, complete, _, err := startupExecutablePaths(
			context.Background(),
			evaluator.Environment{Commands: runner, Files: startupFixtureReader{files: fstest.MapFS{}}},
			"example.service",
		)
		if err != nil || complete || len(paths) != 0 {
			t.Errorf("startupExecutablePaths(%q, %q) = %#v, %t, %v, want affected path incomplete", test.property, test.executable, paths, complete, err)
		}
	}
}

func TestStartupExecutablePathsResolvesOldSystemdUnprintableNamespaceArrays(t *testing.T) {
	t.Parallel()

	runner := systemdCommandFixtureRunner{
		result: executor.Result{Stdout: []byte(
			"LoadState=loaded\n" +
				"BindPaths=[unprintable]\n" +
				"BindReadOnlyPaths=[unprintable]\n" +
				"TemporaryFileSystem=[unprintable]\n" +
				"ExecStart={ path=/usr/bin/tool ; argv[]=/usr/bin/tool ; ignore_errors=no ; }\n",
		)},
		busctlAvailable: true,
		busctlResults: map[string]executor.Result{
			"BindPaths":           {Stdout: []byte("a(ssbt) 0\n")},
			"BindReadOnlyPaths":   {Stdout: []byte("a(ssbt) 0\n")},
			"TemporaryFileSystem": {Stdout: []byte("a(ss) 0\n")},
		},
	}
	reader := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"usr/bin/tool": &fstest.MapFile{Mode: 0o755},
	}}}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: reader},
		"example.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/usr/bin/tool"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want typed empty arrays resolved", paths, complete, err)
	}
	namespaceEvidence := 0
	for _, item := range evidence {
		if item.Source == "systemd-start-namespace-property-summary" {
			namespaceEvidence++
		}
	}
	if namespaceEvidence != 3 {
		t.Fatalf("namespace evidence count = %d, want 3", namespaceEvidence)
	}
}

func TestStartupExecutablePathsKeepsNonemptyOrFailedBusctlNamespaceUnknown(t *testing.T) {
	t.Parallel()

	for _, result := range []executor.Result{
		{Stdout: []byte(`a(ssbt) 1 "/source" "/target" false 0` + "\n")},
		{ExitCode: 1, Stderr: []byte("failed\n")},
	} {
		runner := systemdCommandFixtureRunner{
			result: executor.Result{Stdout: []byte(
				"LoadState=loaded\nBindPaths=[unprintable]\n" +
					"ExecStart={ path=/usr/bin/tool ; argv[]=/usr/bin/tool ; ignore_errors=no ; }\n",
			)},
			busctlAvailable: true,
			busctlResults:   map[string]executor.Result{"BindPaths": result},
		}
		paths, complete, _, err := startupExecutablePaths(
			context.Background(),
			evaluator.Environment{Commands: runner, Files: startupFixtureReader{files: fstest.MapFS{}}},
			"example.service",
		)
		if err != nil || complete || len(paths) != 0 {
			t.Errorf("startupExecutablePaths(busctl=%q) = %#v, %t, %v, want incomplete", result.Stdout, paths, complete, err)
		}
	}
}

func TestSystemdUnitObjectPathUsesStrictByteEscaping(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"sshd.service":        "/org/freedesktop/systemd1/unit/sshd_2eservice",
		"foo-bar@baz.service": "/org/freedesktop/systemd1/unit/foo_2dbar_40baz_2eservice",
		`dev-dm\x2d1.swap`:    "/org/freedesktop/systemd1/unit/dev_2ddm_5cx2d1_2eswap",
	}
	for unitName, want := range tests {
		got, complete := systemdUnitObjectPath(unitName)
		if !complete || got != want {
			t.Errorf("systemdUnitObjectPath(%q) = %q, %t, want %q", unitName, got, complete, want)
		}
	}
}

func TestStartupExecutablePathsResolvesNonDispatcherSymlinkToFinalTarget(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/dnf"
	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=" + executable + " ; argv[]=" + executable + " makecache ; ignore_errors=no ; }\n"),
		},
	}
	files := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/dnf-3": &fstest.MapFile{Mode: 0o755},
		}},
		links: map[string]string{executable: "dnf-3"},
	}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"dnf-makecache.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{"/usr/bin/dnf-3"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want final target and complete", paths, complete, err)
	}
	resolution := evidence[len(evidence)-1]
	if resolution.Fact["selected_path_sha256"] != pathDigest(executable) ||
		resolution.Fact["final_path_sha256"] != pathDigest("/usr/bin/dnf-3") ||
		resolution.Fact["symlink_resolved"] != true {
		t.Fatalf("resolution evidence = %#v", resolution)
	}
}

func TestStartupExecutablePathsRejectsChangedIntermediateSymlinkSnapshot(t *testing.T) {
	t.Parallel()

	const executable = "/usr/local/bin/run-app"
	base := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/tool":  &fstest.MapFile{Mode: 0o755},
			"usr/bin/other": &fstest.MapFile{Mode: 0o755},
		}},
		links: map[string]string{executable: "/usr/bin/tool"},
	}
	reader := &startupSnapshotMutationReader{
		Reader:          startupXAttrFixtureReader{Reader: base},
		MutationPath:    executable,
		MutateAfterRead: 1,
		Mutate: func(metadata system.FileMetadata, err error) (system.FileMetadata, error) {
			metadata.LinkTarget = "/usr/bin/other"
			return metadata, err
		},
	}
	runner := systemdCommandFixtureRunner{result: executor.Result{
		Stdout: []byte(
			"LoadState=loaded\nExecStart={ path=" + executable +
				" ; argv[]=" + executable + " ; ignore_errors=no ; }\n",
		),
	}}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: reader},
		"example.service",
	)
	if err != nil || complete || len(paths) != 0 {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want changed symlink snapshot to be incomplete", paths, complete, err)
	}
	assertUnstableStartupResolutionEvidence(t, evidence)
}

func TestStartupExecutablePathsRejectsChangedParentDirectorySnapshot(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/tool"
	for _, follow := range []bool{false, true} {
		follow := follow
		t.Run(fmt.Sprintf("follow=%t", follow), func(t *testing.T) {
			base := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
				"usr/bin/tool": &fstest.MapFile{Mode: 0o755},
			}}}
			mutateAfterRead := 3
			if follow {
				mutateAfterRead = 2
			}
			reader := &startupSnapshotMutationReader{
				Reader:          base,
				MutationPath:    "/usr/bin",
				MutationFollow:  follow,
				MutateAfterRead: mutateAfterRead,
				Mutate: func(metadata system.FileMetadata, err error) (system.FileMetadata, error) {
					metadata.Inode++
					return metadata, err
				},
			}
			runner := systemdCommandFixtureRunner{result: executor.Result{
				Stdout: []byte(
					"LoadState=loaded\nExecStart={ path=" + executable +
						" ; argv[]=" + executable + " ; ignore_errors=no ; }\n",
				),
			}}
			paths, complete, evidence, err := startupExecutablePaths(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: reader},
				"example.service",
			)
			if err != nil || complete || len(paths) != 0 {
				t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want changed parent snapshot to be incomplete", paths, complete, err)
			}
			assertUnstableStartupResolutionEvidence(t, evidence)
		})
	}
}

func TestStartupExecutablePathsRejectsBareCandidateAppearingBeforeSelectedPath(t *testing.T) {
	t.Parallel()

	base := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"first":         &fstest.MapFile{Mode: os.ModeDir | 0o755},
		"second/helper": &fstest.MapFile{Mode: 0o755},
	}}}
	reader := &startupSnapshotMutationReader{
		Reader:          base,
		MutationPath:    "/first/helper",
		MutateAfterRead: 1,
		Mutate: func(_ system.FileMetadata, _ error) (system.FileMetadata, error) {
			return system.FileMetadata{
				Path: "/first/helper", FileType: "regular", Mode: 0o755, UID: 0, GID: 0,
			}, nil
		},
	}
	runner := systemdCommandFixtureRunner{
		result: executor.Result{Stdout: []byte(
			"LoadState=loaded\nExecStart={ path=helper ; argv[]=helper ; ignore_errors=no ; }\n",
		)},
		searchAvailable: true,
		searchResult:    executor.Result{Stdout: []byte("/first:/second\n")},
	}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: reader},
		"example.service",
	)
	if err != nil || complete || len(paths) != 0 {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want changed bare search order to be incomplete", paths, complete, err)
	}
	assertUnstableStartupResolutionEvidence(t, evidence)
}

func TestStartupExecutablePathsRejectsChangedPythonScriptSymlinkSnapshot(t *testing.T) {
	t.Parallel()

	const scriptPath = "/opt/start.py"
	base := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/python3": &fstest.MapFile{Mode: 0o755},
			"opt/app.py":      &fstest.MapFile{Mode: 0o644},
			"opt/other.py":    &fstest.MapFile{Mode: 0o644},
		}},
		links: map[string]string{scriptPath: "/opt/app.py"},
	}
	reader := &startupSnapshotMutationReader{
		Reader:          startupXAttrFixtureReader{Reader: base},
		MutationPath:    scriptPath,
		MutateAfterRead: 1,
		Mutate: func(metadata system.FileMetadata, err error) (system.FileMetadata, error) {
			metadata.LinkTarget = "/opt/other.py"
			return metadata, err
		},
	}
	runner := systemdCommandFixtureRunner{result: executor.Result{
		Stdout: []byte(
			"LoadState=loaded\nExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 " +
				scriptPath + " ; ignore_errors=no ; }\n",
		),
	}}
	paths, complete, evidence, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: reader},
		"example.service",
	)
	if err != nil || complete || len(paths) != 0 {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want changed script symlink snapshot to be incomplete", paths, complete, err)
	}
	assertUnstableStartupResolutionEvidence(t, evidence)
}

func TestInspectStartupPermissionPathsDiscardsViolationWhenGuardChanges(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/tool"
	reader := &startupPermissionRaceReader{
		Reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/tool": &fstest.MapFile{Mode: 0o777},
		}}},
		ParentPath:   "/usr/bin",
		ChangeParent: true,
	}
	guard := captureStartupTestGuard(t, reader, executable)
	reader.Armed = true

	violations, unknowns, evidence, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{}, Files: reader},
		map[string]struct{}{executable: {}},
		map[string][]*startupFilesystemSnapshot{executable: {guard}},
	)
	if err != nil || len(violations) != 0 || len(unknowns) != 1 {
		t.Fatalf(
			"inspectStartupPermissionPaths() = violations=%#v unknowns=%#v err=%v, want one TOCTOU unknown",
			violations,
			unknowns,
			err,
		)
	}
	assertRejectedStartupPermissionGuardEvidence(t, evidence, 1)
}

func TestInspectStartupPermissionPathsChecksParentReplacementBoundary(t *testing.T) {
	t.Parallel()

	const (
		executable = "/home/alice/bin/start"
		parentPath = "/home/alice/bin"
	)
	baseFiles := func() startupFixtureReader {
		return startupFixtureReader{files: fstest.MapFS{
			"home/alice/bin/start": &fstest.MapFile{Mode: 0o755},
		}}
	}
	tests := []struct {
		name          string
		files         func() system.Reader
		commands      func() executor.CommandRunner
		wantViolation string
	}{
		{
			name: "safe root owned parent",
			files: func() system.Reader {
				return &startupParentPermissionFixtureReader{
					Reader: baseFiles(), ParentPath: parentPath,
					UID: 0, Mode: os.ModeDir | 0o755,
				}
			},
			commands: func() executor.CommandRunner {
				return systemdCommandFixtureRunner{}
			},
		},
		{
			name: "user owned parent",
			files: func() system.Reader {
				return &startupParentPermissionFixtureReader{
					Reader: baseFiles(), ParentPath: parentPath,
					UID: 1000, Mode: os.ModeDir | 0o755,
				}
			},
			commands: func() executor.CommandRunner {
				return systemdCommandFixtureRunner{}
			},
			wantViolation: "허용되지 않은 소유자 UID 1000",
		},
		{
			name: "group writable parent",
			files: func() system.Reader {
				return &startupParentPermissionFixtureReader{
					Reader: baseFiles(), ParentPath: parentPath,
					UID: 0, Mode: os.ModeDir | 0o775,
				}
			},
			commands: func() executor.CommandRunner {
				return systemdCommandFixtureRunner{}
			},
			wantViolation: "허용되지 않은 권한 비트 0020",
		},
		{
			name: "world writable parent",
			files: func() system.Reader {
				return &startupParentPermissionFixtureReader{
					Reader: baseFiles(), ParentPath: parentPath,
					UID: 0, Mode: os.ModeDir | 0o777,
				}
			},
			commands: func() executor.CommandRunner {
				return systemdCommandFixtureRunner{}
			},
			wantViolation: "허용되지 않은 권한 비트 0022",
		},
		{
			name: "named user ACL writable parent",
			files: func() system.Reader {
				return startupXAttrFixtureReader{
					Reader: baseFiles(),
					ACLByPath: map[string][]byte{
						parentPath: mustTestPOSIXACLXAttr(t,
							"user::rwx\nuser:1000:rwx\ngroup::r-x\nmask::rwx\nother::r-x\n"),
					},
				}
			},
			commands: func() executor.CommandRunner {
				return systemdCommandFixtureRunner{}
			},
			wantViolation: "ACL user:1000에 허용되지 않은 권한 002",
		},
		{
			name: "named group ACL writable parent",
			files: func() system.Reader {
				return startupXAttrFixtureReader{
					Reader: baseFiles(),
					ACLByPath: map[string][]byte{
						parentPath: mustTestPOSIXACLXAttr(t,
							"user::rwx\ngroup::r-x\ngroup:1000:rwx\nmask::rwx\nother::r-x\n"),
					},
				}
			},
			commands: func() executor.CommandRunner {
				return systemdCommandFixtureRunner{}
			},
			wantViolation: "ACL group:1000에 허용되지 않은 권한 002",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			violations, unknowns, _, err := inspectStartupPermissionPaths(
				context.Background(),
				evaluator.Environment{
					Commands: test.commands(),
					Files:    test.files(),
				},
				map[string]struct{}{executable: {}},
				nil,
			)
			if err != nil || len(unknowns) != 0 {
				t.Fatalf(
					"parent replacement boundary = violations:%#v unknowns:%#v err:%v",
					violations,
					unknowns,
					err,
				)
			}
			if test.wantViolation == "" {
				if len(violations) != 0 {
					t.Fatalf("safe parent violations = %#v", violations)
				}
				return
			}
			found := false
			for _, violation := range violations {
				if strings.Contains(violation, parentPath) &&
					strings.Contains(violation, test.wantViolation) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf(
					"parent violation = %#v, want path %s and %q",
					violations,
					parentPath,
					test.wantViolation,
				)
			}
		})
	}
}

func TestParentACLMutationInvalidatesStartupPermissionGuard(t *testing.T) {
	t.Parallel()

	const (
		executable = "/home/alice/bin/start"
		parentPath = "/home/alice/bin"
	)
	aclByPath := map[string][]byte{
		parentPath: mustTestPOSIXACLXAttr(t,
			"user::rwx\ngroup::r-x\nother::r-x\n"),
	}
	reader := startupXAttrFixtureReader{
		Reader: startupFixtureReader{files: fstest.MapFS{
			"home/alice/bin/start": &fstest.MapFile{Mode: 0o755},
		}},
		ACLByPath: aclByPath,
	}
	runner := systemdCommandFixtureRunner{}
	pending, _ := collectStartupPermissionPathAssessments(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: reader},
		map[string]struct{}{executable: {}},
		nil,
	)
	if len(pending) != 1 || len(pending[0].ParentAssessments) == 0 ||
		!pending[0].GuardCaptureComplete {
		t.Fatalf("parent permission guard setup = %#v", pending)
	}

	aclByPath[parentPath] = mustTestPOSIXACLXAttr(t,
		"user::rwx\nuser:1000:rwx\ngroup::r-x\nmask::rwx\nother::r-x\n")
	evidence := revalidateStartupPermissionPathAssessments(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: reader},
		pending,
		nil,
	)
	if pending[0].AssessmentStable || pending[0].GuardsStable {
		t.Fatalf("writable parent ACL mutation was accepted: %#v", evidence)
	}
	auxiliaryMismatchFound := false
	for _, item := range evidence {
		if item.Source == "systemd-start-auxiliary-snapshot-guard" &&
			item.Fact["kind"] == startupAuxiliaryParentPermission &&
			item.Fact["state_stable"] == false {
			auxiliaryMismatchFound = true
			break
		}
	}
	if !auxiliaryMismatchFound {
		t.Fatalf("parent ACL mutation guard evidence missing: %#v", evidence)
	}
}

func TestInspectStartupPermissionPathsRejectsIntermediateSymlinkChangedDuringInspection(t *testing.T) {
	t.Parallel()

	const (
		configuredExecutable = "/usr/local/bin/run-app"
		finalExecutable      = "/usr/bin/tool"
	)
	base := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/tool":  &fstest.MapFile{Mode: 0o777},
			"usr/bin/other": &fstest.MapFile{Mode: 0o755},
		}},
		links: map[string]string{configuredExecutable: finalExecutable},
	}
	reader := &startupPermissionRaceReader{
		Reader:            startupXAttrFixtureReader{Reader: base},
		SymlinkPath:       configuredExecutable,
		ChangedLinkTarget: "/usr/bin/other",
	}
	guard := captureStartupTestGuard(t, reader, configuredExecutable)
	reader.Armed = true

	violations, unknowns, evidence, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{}, Files: reader},
		map[string]struct{}{finalExecutable: {}},
		map[string][]*startupFilesystemSnapshot{finalExecutable: {guard}},
	)
	if err != nil || len(violations) != 0 || len(unknowns) != 1 {
		t.Fatalf(
			"inspectStartupPermissionPaths() = violations=%#v unknowns=%#v err=%v, want changed intermediate symlink unknown",
			violations,
			unknowns,
			err,
		)
	}
	assertRejectedStartupPermissionGuardEvidence(t, evidence, 1)
}

func TestInspectStartupPermissionPathsTurnsRaceErrorIntoUnknown(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/tool"
	reader := &startupPermissionRaceReader{
		Reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/tool": &fstest.MapFile{Mode: 0o755},
		}}},
		ParentPath:      "/usr/bin",
		ChangeParent:    true,
		PermissionError: true,
	}
	guard := captureStartupTestGuard(t, reader, executable)
	reader.Armed = true

	violations, unknowns, evidence, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{}, Files: reader},
		map[string]struct{}{executable: {}},
		map[string][]*startupFilesystemSnapshot{executable: {guard}},
	)
	if err != nil || len(violations) != 0 || len(unknowns) != 1 {
		t.Fatalf(
			"inspectStartupPermissionPaths() = violations=%#v unknowns=%#v err=%v, want race error converted to unknown",
			violations,
			unknowns,
			err,
		)
	}
	assertRejectedStartupPermissionGuardEvidence(t, evidence, 1)
}

func TestInspectStartupPermissionPathsKeepsStableCollectionError(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/tool"
	reader := &startupPermissionRaceReader{
		Reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/tool": &fstest.MapFile{Mode: 0o755},
		}}},
		ParentPath:      "/usr/bin",
		PermissionError: true,
	}
	guard := captureStartupTestGuard(t, reader, executable)
	reader.Armed = true

	_, unknowns, evidence, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{}, Files: reader},
		map[string]struct{}{executable: {}},
		map[string][]*startupFilesystemSnapshot{executable: {guard}},
	)
	if err == nil || len(unknowns) != 0 {
		t.Fatalf("inspectStartupPermissionPaths() = unknowns=%#v err=%v, want stable collection error", unknowns, err)
	}
	guardEvidence := evidence[len(evidence)-1]
	if guardEvidence.Source != "systemd-start-permission-snapshot-guard" ||
		guardEvidence.Fact["all_guards_stable"] != true ||
		guardEvidence.Fact["permission_result_accepted"] != false {
		t.Fatalf("guard evidence = %#v, want stable guard before error", guardEvidence)
	}
}

func TestInspectStartupPermissionPathsRequiresEveryDeduplicatedPathGuardStable(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/tool"
	reader := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"usr/bin/tool": &fstest.MapFile{Mode: 0o777},
	}}}
	stableGuard := captureStartupTestGuard(t, reader, executable)
	staleGuard := &startupFilesystemSnapshot{
		Entries: append([]startupPathSnapshot(nil), stableGuard.Entries...),
	}
	for index := range staleGuard.Entries {
		entry := &staleGuard.Entries[index]
		if entry.Exists && entry.Roles&startupSnapshotRoleParent != 0 {
			entry.Metadata.Inode++
			break
		}
	}

	violations, unknowns, evidence, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{}, Files: reader},
		map[string]struct{}{executable: {}},
		map[string][]*startupFilesystemSnapshot{
			executable: {stableGuard, stableGuard, staleGuard},
		},
	)
	if err != nil || len(violations) != 0 || len(unknowns) != 1 {
		t.Fatalf(
			"inspectStartupPermissionPaths() = violations=%#v unknowns=%#v err=%v, want one unstable guard to reject the result",
			violations,
			unknowns,
			err,
		)
	}
	assertRejectedStartupPermissionGuardEvidence(t, evidence, 2)
}

func TestInspectStartupPermissionPathsAtomicallyRejectsSharedGuardAfterLaterPathMutation(t *testing.T) {
	t.Parallel()

	const (
		firstExecutable  = "/usr/bin/a-tool"
		secondExecutable = "/usr/bin/z-tool"
	)
	reader := &startupPermissionRaceReader{
		Reader: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/a-tool": &fstest.MapFile{Mode: 0o777},
			"usr/bin/z-tool": &fstest.MapFile{Mode: 0o777},
		}}},
		ParentPath:   "/usr/bin",
		ChangeParent: true,
		TriggerPath:  secondExecutable,
	}
	sharedGuard := captureStartupTestGuard(t, reader, firstExecutable)
	reader.Armed = true

	violations, unknowns, evidence, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{}, Files: reader},
		map[string]struct{}{firstExecutable: {}, secondExecutable: {}},
		map[string][]*startupFilesystemSnapshot{
			firstExecutable:  {sharedGuard},
			secondExecutable: {sharedGuard},
		},
	)
	if err != nil || len(violations) != 0 || len(unknowns) != 2 {
		t.Fatalf(
			"inspectStartupPermissionPaths() = violations=%#v unknowns=%#v err=%v, want both shared-guard results rejected",
			violations,
			unknowns,
			err,
		)
	}
	rejectedEvidence := 0
	for _, item := range evidence {
		if item.Source != "systemd-start-permission-snapshot-guard" {
			continue
		}
		if item.Fact["permission_result_accepted"] != false {
			t.Fatalf("shared guard evidence = %#v, want every connected path rejected", item)
		}
		rejectedEvidence++
	}
	if rejectedEvidence != 2 {
		t.Fatalf("rejected shared guard evidence count = %d, want 2", rejectedEvidence)
	}
}

func captureStartupTestGuard(
	t *testing.T,
	reader system.Reader,
	executable string,
) *startupFilesystemSnapshot {
	t.Helper()
	snapshot := newStartupFilesystemSnapshot()
	finalPath, _, complete, resolutionPaths := resolveStartupExecutableSnapshot(reader, executable, snapshot)
	if !complete || !captureStartupParentSnapshots(
		reader,
		snapshot,
		append([]string{executable, finalPath}, resolutionPaths...)...,
	) {
		t.Fatalf("failed to capture startup test guard for %s", executable)
	}
	return snapshot
}

func assertRejectedStartupPermissionGuardEvidence(
	t *testing.T,
	evidence []model.Evidence,
	wantGuardCount int,
) {
	t.Helper()
	if len(evidence) == 0 {
		t.Fatal("permission guard evidence is empty")
	}
	guardEvidence := evidence[len(evidence)-1]
	if guardEvidence.Source != "systemd-start-permission-snapshot-guard" ||
		guardEvidence.Fact["permission_result_accepted"] != false ||
		guardEvidence.Fact["guard_count"] != wantGuardCount {
		t.Fatalf("permission guard evidence = %#v", guardEvidence)
	}
	if _, exists := guardEvidence.Fact["path"]; exists {
		t.Fatalf("permission guard evidence retained a raw path: %#v", guardEvidence)
	}
}

func assertUnstableStartupResolutionEvidence(t *testing.T, evidence []model.Evidence) {
	t.Helper()
	if len(evidence) == 0 {
		t.Fatal("resolution evidence is empty")
	}
	resolution := evidence[len(evidence)-1]
	if resolution.Source != "systemd-start-executable-resolution" ||
		resolution.Fact["snapshot_stable"] != false ||
		resolution.Fact["snapshot_sha256"] == resolution.Fact["current_snapshot_sha256"] {
		t.Fatalf("resolution evidence = %#v, want a hashed snapshot mismatch", resolution)
	}
	mismatches, ok := resolution.Fact["snapshot_mismatch_count"].(int)
	if !ok || mismatches < 1 {
		t.Fatalf("resolution mismatch count = %#v, want at least one", resolution.Fact["snapshot_mismatch_count"])
	}
}

func TestStartupExecutablePathsKeepsShellSymlinkCommandIncomplete(t *testing.T) {
	t.Parallel()

	const executable = "/bin/sh"
	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("LoadState=loaded\nExecStart={ path=" + executable + " ; argv[]=" + executable + " -c /opt/start ; ignore_errors=no ; }\n"),
		},
	}
	files := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/dash": &fstest.MapFile{Mode: 0o755},
		}},
		links: map[string]string{executable: "../usr/bin/dash"},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"example.service",
	)
	if err != nil || complete || !slices.Equal(paths, []string{"/usr/bin/dash"}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want final shell target and incomplete", paths, complete, err)
	}
}

func TestStartupExecutablePathsSupportsMergedUsrIntermediateSymlink(t *testing.T) {
	t.Parallel()

	const (
		configuredShell = "/bin/sh"
		finalShell      = "/usr/bin/sh"
		script          = "/opt/start.sh"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + configuredShell + " ; argv[]=" +
			configuredShell + " -eu " + script + " ; ignore_errors=no ; }\n",
	)}}
	files := &startupIntermediateSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/sh":   &fstest.MapFile{Mode: 0o755},
			"opt/start.sh": &fstest.MapFile{Mode: 0o644},
		}},
		links: map[string]string{"/bin": "usr/bin"},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	if err != nil || !complete ||
		!slices.Equal(paths, []string{script, finalShell}) {
		t.Fatalf(
			"merged-/usr startup paths = %#v, complete=%t err=%v, want %#v",
			paths,
			complete,
			err,
			[]string{script, finalShell},
		)
	}
}

func TestMergedUsrIntermediateSymlinkSnapshotsBothDirectoryPaths(t *testing.T) {
	t.Parallel()

	files := &startupIntermediateSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/sh":       &fstest.MapFile{Mode: 0o755},
			"usr/local/bin/sh": &fstest.MapFile{Mode: 0o755},
		}},
		links: map[string]string{"/bin": "usr/bin"},
	}
	snapshot := newStartupFilesystemSnapshot()
	finalPath, exists, complete, resolutionPaths := resolveStartupExecutableSnapshot(
		files,
		"/bin/sh",
		snapshot,
	)
	if !complete || !exists || finalPath != "/usr/bin/sh" {
		t.Fatalf(
			"merged-/usr resolution = %q, exists=%t complete=%t paths=%#v",
			finalPath,
			exists,
			complete,
			resolutionPaths,
		)
	}
	if !captureStartupParentSnapshots(
		files,
		snapshot,
		append([]string{"/bin/sh", finalPath}, resolutionPaths...)...,
	) {
		t.Fatal("failed to capture merged-/usr parent snapshots")
	}
	_, traversable := inspectStartupExecutableDirectories(
		context.Background(),
		evaluator.Environment{Files: files},
		resolutionPaths,
		snapshot,
	)
	if !traversable {
		t.Fatal("merged-/usr lexical and resolved directories were not traversable")
	}
	for _, expectedPath := range []string{"/bin", "/usr/bin"} {
		parentSnapshotFound := false
		for _, entry := range snapshot.Entries {
			if entry.Path == expectedPath &&
				!entry.Follow &&
				entry.Exists &&
				entry.Roles&startupSnapshotRoleParent != 0 {
				parentSnapshotFound = true
				break
			}
		}
		if !parentSnapshotFound {
			t.Fatalf(
				"parent %s missing from merged-/usr snapshot %#v",
				expectedPath,
				snapshot.Entries,
			)
		}
		aclSnapshotFound := false
		for _, auxiliary := range snapshot.Auxiliary {
			if auxiliary.Kind == startupAuxiliaryExecutionACL &&
				auxiliary.Path == expectedPath &&
				auxiliary.State == "usable" {
				aclSnapshotFound = true
				break
			}
		}
		if !aclSnapshotFound {
			t.Fatalf(
				"parent %s missing from merged-/usr ACL snapshot %#v",
				expectedPath,
				snapshot.Auxiliary,
			)
		}
	}
	pending, _ := collectStartupPermissionPathAssessments(
		context.Background(),
		evaluator.Environment{Files: files},
		map[string]struct{}{finalPath: {}},
		map[string][]*startupFilesystemSnapshot{finalPath: {snapshot}},
	)
	if len(pending) != 1 || pending[0].InspectErr != nil {
		t.Fatalf("merged-/usr parent permission assessment = %#v", pending)
	}
	parentPaths := startupPermissionAssessmentPaths(pending[0].ParentAssessments)
	for _, expectedPath := range []string{"/", "/bin", "/usr", "/usr/bin"} {
		if !slices.Contains(parentPaths, expectedPath) {
			t.Fatalf(
				"merged-/usr permission parent %s missing from %#v",
				expectedPath,
				parentPaths,
			)
		}
	}
	for _, expectedPath := range []string{"/bin", "/usr/bin"} {
		parentGuardFound := false
		for _, auxiliary := range snapshot.Auxiliary {
			if auxiliary.Kind == startupAuxiliaryParentPermission &&
				auxiliary.Path == expectedPath {
				parentGuardFound = true
				break
			}
		}
		if !parentGuardFound {
			t.Fatalf(
				"merged-/usr permission guard %s missing from %#v",
				expectedPath,
				snapshot.Auxiliary,
			)
		}
	}

	files.links["/bin"] = "usr/local/bin"
	stable, _, mismatchCount, readErrorCount :=
		revalidateStartupFilesystemSnapshot(files, snapshot)
	if stable || mismatchCount == 0 || readErrorCount != 0 {
		t.Fatalf(
			"mutated merged-/usr link guard = stable:%t mismatches:%d read_errors:%d",
			stable,
			mismatchCount,
			readErrorCount,
		)
	}
}

func TestStartupExecutablePathsIncludesDirectShebangInterpreter(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/usr/bin/python3"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
			script + " ; ignore_errors=no ; }\n",
	)}}
	files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"opt/start.sh": &fstest.MapFile{
			Data: []byte("#!" + interpreter + "\nprint('ready')\n"),
			Mode: 0o755,
		},
		"usr/bin/python3": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
	}}}

	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	want := []string{script, interpreter}
	if err != nil || !complete || !slices.Equal(paths, want) {
		t.Fatalf(
			"direct shebang paths = %#v, complete=%t err=%v, want %#v",
			paths,
			complete,
			err,
			want,
		)
	}
}

func TestInspectStartupPermissionsRejectsUnsafeDirectShebangInterpreter(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/home/alice/runner"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
			script + " ; ignore_errors=no ; }\n",
	)}}
	base := startupFixtureReader{files: fstest.MapFS{
		"opt/start.sh": &fstest.MapFile{
			Data: []byte("#!" + interpreter + "\n"),
			Mode: 0o755,
		},
		"home/alice/runner": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
	}}
	shebangReader := &startupShebangFixtureReader{
		Reader:    base,
		UIDByPath: map[string]int{interpreter: 1000},
	}
	files := startupXAttrFixtureReader{Reader: shebangReader}
	guardedPaths, complete, _, _, err := startupExecutablePathsGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	if err != nil || !complete {
		t.Fatalf(
			"direct shebang guard setup complete=%t err=%v paths=%#v",
			complete,
			err,
			guardedPaths,
		)
	}
	paths, guards := startupGuardedPermissionInputs(guardedPaths)
	violations, unknowns, _, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		paths,
		guards,
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.ContainsFunc(violations, func(value string) bool {
			return strings.Contains(value, interpreter) &&
				strings.Contains(value, "소유자 UID")
		}) {
		t.Fatalf(
			"unsafe shebang interpreter = violations:%#v unknowns:%#v err:%v",
			violations,
			unknowns,
			err,
		)
	}
}

func TestStartupExecutablePathsIncludesRootOwnedShebangPayload(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/usr/bin/python3"
		payload     = "/opt/payload.py"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
			script + " ; ignore_errors=no ; }\n",
	)}}
	files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"opt/start.sh": &fstest.MapFile{
			Data: []byte("#!" + interpreter + " " + payload + "\n"),
			Mode: 0o755,
		},
		"usr/bin/python3": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
		"opt/payload.py":  &fstest.MapFile{Data: []byte("print('ready')\n"), Mode: 0o644},
	}}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	want := []string{payload, script, interpreter}
	if err != nil || !complete || !slices.Equal(paths, want) {
		t.Fatalf(
			"root-owned shebang payload paths = %#v, complete=%t err=%v, want %#v",
			paths,
			complete,
			err,
			want,
		)
	}
}

func TestInspectStartupPermissionsRejectsUnsafeShebangPayload(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/usr/bin/python3"
		payload     = "/home/alice/payload.py"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
			script + " ; ignore_errors=no ; }\n",
	)}}
	base := startupFixtureReader{files: fstest.MapFS{
		"opt/start.sh": &fstest.MapFile{
			Data: []byte("#!" + interpreter + " " + payload + "\n"),
			Mode: 0o755,
		},
		"usr/bin/python3":       &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
		"home/alice/payload.py": &fstest.MapFile{Data: []byte("print('unsafe')\n"), Mode: 0o644},
	}}
	shebangReader := &startupShebangFixtureReader{
		Reader:    base,
		UIDByPath: map[string]int{payload: 1000},
	}
	files := startupXAttrFixtureReader{Reader: shebangReader}
	guardedPaths, complete, _, _, err := startupExecutablePathsGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	if err != nil || !complete {
		t.Fatalf("unsafe shebang payload setup complete=%t err=%v", complete, err)
	}
	paths, guards := startupGuardedPermissionInputs(guardedPaths)
	violations, unknowns, _, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		paths,
		guards,
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.ContainsFunc(violations, func(value string) bool {
			return strings.Contains(value, payload) &&
				strings.Contains(value, "소유자 UID")
		}) {
		t.Fatalf(
			"unsafe shebang payload = violations:%#v unknowns:%#v err:%v",
			violations,
			unknowns,
			err,
		)
	}
}

func TestStartupExecutablePathsRejectsAmbiguousNonEnvShebangArgument(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/usr/bin/python3"
	)
	for _, optionalArgument := range []string{
		"payload.py",
		"--config=/home/alice/config",
	} {
		t.Run(optionalArgument, func(t *testing.T) {
			t.Parallel()

			runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
				"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
					script + " ; ignore_errors=no ; }\n",
			)}}
			files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
				"opt/start.sh": &fstest.MapFile{
					Data: []byte("#!" + interpreter + " " + optionalArgument + "\n"),
					Mode: 0o755,
				},
				"usr/bin/python3": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
			}}}
			paths, complete, _, err := startupExecutablePaths(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: files},
				"example.service",
			)
			want := []string{script, interpreter}
			if err != nil || complete || !slices.Equal(paths, want) {
				t.Fatalf(
					"ambiguous non-env shebang paths = %#v, complete=%t err=%v, want %#v and incomplete",
					paths,
					complete,
					err,
					want,
				)
			}
		})
	}
}

func TestStartupExecutablePathsAllowsSimpleNonEnvShebangFlag(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/usr/bin/python3"
	)
	for _, optionalArgument := range []string{"-I", "-eu", "--"} {
		t.Run(optionalArgument, func(t *testing.T) {
			t.Parallel()

			runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
				"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
					script + " ; ignore_errors=no ; }\n",
			)}}
			files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
				"opt/start.sh": &fstest.MapFile{
					Data: []byte("#!" + interpreter + " " + optionalArgument + "\n"),
					Mode: 0o755,
				},
				"usr/bin/python3": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
			}}}
			paths, complete, _, err := startupExecutablePaths(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: files},
				"example.service",
			)
			want := []string{script, interpreter}
			if err != nil || !complete || !slices.Equal(paths, want) {
				t.Fatalf(
					"simple non-env shebang flag paths = %#v, complete=%t err=%v, want %#v and complete",
					paths,
					complete,
					err,
					want,
				)
			}
		})
	}
}

func TestDirectShebangPrefixMutationInvalidatesPermissionGuard(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/usr/bin/python3"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
			script + " ; ignore_errors=no ; }\n",
	)}}
	base := startupFixtureReader{files: fstest.MapFS{
		"opt/start.sh": &fstest.MapFile{
			Data: []byte("#!" + interpreter + "\n"),
			Mode: 0o755,
		},
		"usr/bin/python3": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
	}}
	shebangReader := &startupShebangFixtureReader{
		Reader:            base,
		ChangedPrefixPath: script,
		ChangedPrefix:     []byte("#!/home/alice/runner\n"),
	}
	files := startupXAttrFixtureReader{Reader: shebangReader}
	guardedPaths, complete, _, _, err := startupExecutablePathsGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	if err != nil || !complete {
		t.Fatalf("shebang mutation setup complete=%t err=%v", complete, err)
	}
	paths, guards := startupGuardedPermissionInputs(guardedPaths)
	violations, unknowns, evidence, err := inspectStartupPermissionPaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		paths,
		guards,
	)
	if err != nil || len(violations) != 0 || len(unknowns) == 0 {
		t.Fatalf(
			"shebang mutation = violations:%#v unknowns:%#v err:%v",
			violations,
			unknowns,
			err,
		)
	}
	mismatchFound := slices.ContainsFunc(evidence, func(item model.Evidence) bool {
		return item.Source == "systemd-start-auxiliary-snapshot-guard" &&
			item.Fact["kind"] == startupAuxiliaryExecutablePrefix &&
			item.Fact["path_sha256"] == pathDigest(script) &&
			item.Fact["state_stable"] == false
	})
	if !mismatchFound {
		t.Fatalf("shebang prefix mutation guard evidence missing: %#v", evidence)
	}
}

func TestStartupExecutablePathsRejectsAmbiguousEnvShebang(t *testing.T) {
	t.Parallel()

	const (
		script = "/opt/start.sh"
		env    = "/usr/bin/env"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
			script + " ; ignore_errors=no ; }\n",
	)}}
	files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"opt/start.sh": &fstest.MapFile{
			Data: []byte("#!" + env + " python3\n"),
			Mode: 0o755,
		},
		"usr/bin/env": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
	}}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	if err != nil || complete || !slices.Equal(paths, []string{script, env}) {
		t.Fatalf(
			"ambiguous env shebang paths = %#v, complete=%t err=%v",
			paths,
			complete,
			err,
		)
	}
}

func TestStartupExecutablePathsAllowsAbsoluteEnvShebangTarget(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		env         = "/usr/bin/env"
		interpreter = "/usr/bin/python3"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
			script + " ; ignore_errors=no ; }\n",
	)}}
	files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"opt/start.sh": &fstest.MapFile{
			Data: []byte("#!" + env + " " + interpreter + "\n"),
			Mode: 0o755,
		},
		"usr/bin/env":     &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
		"usr/bin/python3": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
	}}}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"example.service",
	)
	want := []string{script, env, interpreter}
	if err != nil || !complete || !slices.Equal(paths, want) {
		t.Fatalf(
			"absolute env shebang paths = %#v, complete=%t err=%v, want %#v",
			paths,
			complete,
			err,
			want,
		)
	}
}

func TestStartupExecutablePathsRejectsAmbiguousCustomEnvSemantics(t *testing.T) {
	t.Parallel()

	const (
		script      = "/opt/start.sh"
		interpreter = "/opt/custom/env"
	)
	for _, optionalArgument := range []string{
		"python3",
		"/home/alice/runner",
	} {
		t.Run(optionalArgument, func(t *testing.T) {
			t.Parallel()

			runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
				"LoadState=loaded\nExecStart={ path=" + script + " ; argv[]=" +
					script + " ; ignore_errors=no ; }\n",
			)}}
			files := startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
				"opt/start.sh": &fstest.MapFile{
					Data: []byte("#!" + interpreter + " " + optionalArgument + "\n"),
					Mode: 0o755,
				},
				"opt/custom/env": &fstest.MapFile{Data: []byte("\x7fELF"), Mode: 0o755},
			}}}
			paths, complete, _, err := startupExecutablePaths(
				context.Background(),
				evaluator.Environment{Commands: runner, Files: files},
				"example.service",
			)
			want := []string{interpreter, script}
			if err != nil || complete || !slices.Equal(paths, want) {
				t.Fatalf(
					"custom env-named interpreter paths = %#v, complete=%t err=%v, want %#v and incomplete",
					paths,
					complete,
					err,
					want,
				)
			}
		})
	}
}

func TestStartupExecutablePathsKeepsLargeNativeBinaryComplete(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/large-agent"
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + executable + " ; argv[]=" +
			executable + " ; ignore_errors=no ; }\n",
	)}}
	base := startupFixtureReader{files: fstest.MapFS{
		"usr/bin/.keep": &fstest.MapFile{Mode: 0o644},
	}}
	largeReader := &startupLargeExecutableReader{
		Reader: base,
		Path:   executable,
		Size:   100 << 20,
		Prefix: append([]byte("\x7fELF"), make([]byte, 252)...),
	}
	files := startupXAttrFixtureReader{Reader: largeReader}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: files},
		"large-agent.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{executable}) {
		t.Fatalf(
			"large native executable paths = %#v, complete=%t err=%v",
			paths,
			complete,
			err,
		)
	}
}

func TestParseStartupShebangHonorsPrefixBoundary(t *testing.T) {
	t.Parallel()

	const interpreter = "/usr/bin/python3"
	accepted := append(
		[]byte("#!"+interpreter+strings.Repeat(" ", 255-len(interpreter)-2)),
		'\n',
	)
	if len(accepted) != int(startupShebangPrefixReadLimit) {
		t.Fatalf("accepted shebang fixture length = %d", len(accepted))
	}
	info, complete := parseStartupShebang(accepted)
	if !complete || !info.Present || info.Interpreter != interpreter {
		t.Fatalf("last-byte newline shebang = %#v, complete=%t", info, complete)
	}

	truncated := []byte("#!" + interpreter + strings.Repeat(
		" ",
		int(startupShebangPrefixReadLimit)-len(interpreter)-2,
	))
	info, complete = parseStartupShebang(truncated)
	if complete || !info.Present {
		t.Fatalf("prefix-truncated shebang = %#v, complete=%t", info, complete)
	}
}

func startupGuardedPermissionInputs(
	guardedPaths []startupGuardedPath,
) (map[string]struct{}, map[string][]*startupFilesystemSnapshot) {
	paths := make(map[string]struct{}, len(guardedPaths))
	guards := make(map[string][]*startupFilesystemSnapshot, len(guardedPaths))
	for _, guardedPath := range guardedPaths {
		paths[guardedPath.Path] = struct{}{}
		if guardedPath.Snapshot != nil {
			guards[guardedPath.Path] = append(
				guards[guardedPath.Path],
				guardedPath.Snapshot,
			)
		}
	}
	return paths, guards
}

func TestStartupExecutablePathsIncludesStrictDirectShellScript(t *testing.T) {
	t.Parallel()

	const (
		shell      = "/bin/sh"
		finalShell = "/usr/bin/dash"
		script     = "/usr/share/lxd-installer/lxd-installer-service"
	)
	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte(
				"LoadState=loaded\nExecStart={ path=" + shell + " ; argv[]=" + shell +
					" -eux " + script + " ; ignore_errors=no ; status=0/0 }\n",
			),
		},
	}
	files := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/dash": &fstest.MapFile{Mode: 0o755},
			"usr/share/lxd-installer/lxd-installer-service": &fstest.MapFile{
				Mode: 0o644,
			},
		}},
		links: map[string]string{shell: "../usr/bin/dash"},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"lxd-installer@openciip-probe.service",
	)
	want := []string{finalShell, script}
	if err != nil || !complete || !slices.Equal(paths, want) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want %#v and complete", paths, complete, err, want)
	}
}

func TestStartupExecutablePathsAllowsConfiguredShSymlinkToBash(t *testing.T) {
	t.Parallel()

	const (
		configuredShell = "/bin/sh"
		finalShell      = "/usr/bin/bash"
		script          = "/opt/start.sh"
	)
	runner := systemdCommandFixtureRunner{result: executor.Result{Stdout: []byte(
		"LoadState=loaded\nExecStart={ path=" + configuredShell + " ; argv[]=" +
			configuredShell + " -eu " + script + " ; ignore_errors=no ; }\n",
	)}}
	files := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/bash": &fstest.MapFile{Mode: 0o755},
			"opt/start.sh": &fstest.MapFile{Mode: 0o644},
		}},
		links: map[string]string{configuredShell: "../usr/bin/bash"},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{Commands: runner, Files: startupXAttrFixtureReader{Reader: files}},
		"example.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{script, finalShell}) {
		t.Fatalf(
			"startupExecutablePaths() = %#v, %t, %v, want configured sh argv semantics with final bash target",
			paths,
			complete,
			err,
		)
	}
}

func TestStartupShellScriptPathRejectsDynamicOrSourceChangingOptions(t *testing.T) {
	t.Parallel()

	const shell = "/bin/sh"
	for _, arguments := range [][]string{
		{shell, "-c", "/opt/start.sh"},
		{shell, "-s", "/opt/start.sh"},
		{shell, "-o", "errexit", "/opt/start.sh"},
		{shell, "-euxc", "/opt/start.sh"},
		{shell, "$SCRIPT"},
		{shell, "relative.sh"},
		{shell, "--"},
	} {
		if script, complete := startupShellScriptPath(systemdCommand{
			Executable: shell,
			Arguments:  arguments,
		}); complete || script != "" {
			t.Errorf("startupShellScriptPath(%#v) = %q, %t, want unresolved", arguments, script, complete)
		}
	}
}

func TestStartupShellScriptPathOnlyAcceptsConfiguredPOSIXShellPaths(t *testing.T) {
	t.Parallel()

	const script = "/opt/start.sh"
	for _, executable := range []string{
		"/bin/sh",
		"/usr/bin/sh",
		"/bin/dash",
		"/usr/bin/dash",
	} {
		command := systemdCommand{
			Executable: executable,
			Arguments:  []string{executable, "-eux", script},
		}
		if got, complete := startupShellScriptPath(command); !complete || got != script {
			t.Errorf("startupShellScriptPath(%q) = %q, %t, want %q", executable, got, complete, script)
		}
	}
	for _, executable := range []string{
		"/bin/bash",
		"/usr/bin/bash",
		"/bin/zsh",
		"/bin/ksh",
		"/bin/ash",
		"/opt/bin/sh",
	} {
		command := systemdCommand{
			Executable: executable,
			Arguments:  []string{executable, "-eux", script},
		}
		if got, complete := startupShellScriptPath(command); complete || got != "" {
			t.Errorf("startupShellScriptPath(%q) = %q, %t, want unsupported shell", executable, got, complete)
		}
	}
}

func TestResolveStartupExecutableRejectsSymlinkCycle(t *testing.T) {
	t.Parallel()

	reader := startupSymlinkFixtureReader{
		startupFixtureReader: startupFixtureReader{files: fstest.MapFS{}},
		links: map[string]string{
			"/usr/bin/first":  "second",
			"/usr/bin/second": "first",
		},
	}
	if resolved, exists, complete := resolveStartupExecutable(reader, "/usr/bin/first"); complete || exists || resolved != "" {
		t.Fatalf("resolveStartupExecutable() = %q, %t, %t, want unresolved cycle", resolved, exists, complete)
	}
}

func TestStartupPythonScriptPathOnlyAcceptsCanonicalAbsoluteScript(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{name: "script", arguments: []string{"/usr/bin/python3", "-Es", "/opt/app/main.py"}, want: "/opt/app/main.py"},
		{name: "separator", arguments: []string{"/usr/bin/python3", "--", "/opt/app/main.py"}, want: "/opt/app/main.py"},
		{name: "inline", arguments: []string{"/usr/bin/python3", "-c", "print(1)"}},
		{name: "module", arguments: []string{"/usr/bin/python3", "-m", "application"}},
		{name: "option operand", arguments: []string{"/usr/bin/python3", "-X", "/tmp/value", "/opt/app/main.py"}},
		{name: "dynamic", arguments: []string{"/usr/bin/python3", "$SCRIPT"}},
		{name: "relative", arguments: []string{"/usr/bin/python3", "main.py"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, complete := startupPythonScriptPath(systemdCommand{
				Executable: "/usr/bin/python3",
				Arguments:  test.arguments,
			})
			if complete != (test.want != "") || got != test.want {
				t.Fatalf("startupPythonScriptPath() = %q, %t, want %q", got, complete, test.want)
			}
		})
	}
}

func TestStartupExecutablePathsKeepsUnsupportedPythonScriptFormsUnknown(t *testing.T) {
	t.Parallel()

	const interpreter = "/usr/bin/python3"
	tests := []struct {
		name       string
		scriptPath string
		reader     system.Reader
	}{
		{
			name:       "directory",
			scriptPath: "/opt/application",
			reader: startupFixtureReader{files: fstest.MapFS{
				"usr/bin/python3": &fstest.MapFile{Mode: 0o755},
				"opt/application": &fstest.MapFile{Mode: os.ModeDir | 0o755},
			}},
		},
		{
			name:       "zip application",
			scriptPath: "/opt/application.zip",
			reader: startupFixtureReader{files: fstest.MapFS{
				"usr/bin/python3":     &fstest.MapFile{Mode: 0o755},
				"opt/application.zip": &fstest.MapFile{Mode: 0o644},
			}},
		},
		{
			name:       "symlink to directory",
			scriptPath: "/opt/start.py",
			reader: startupSymlinkFixtureReader{
				startupFixtureReader: startupFixtureReader{files: fstest.MapFS{
					"usr/bin/python3": &fstest.MapFile{Mode: 0o755},
					"opt/application": &fstest.MapFile{Mode: os.ModeDir | 0o755},
				}},
				links: map[string]string{"/opt/start.py": "/opt/application"},
			},
		},
		{
			name:       "non regular file",
			scriptPath: "/opt/start.py",
			reader: startupFixtureReader{files: fstest.MapFS{
				"usr/bin/python3": &fstest.MapFile{Mode: 0o755},
				"opt/start.py":    &fstest.MapFile{Mode: os.ModeNamedPipe | 0o600},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := systemdCommandFixtureRunner{result: executor.Result{
				Stdout: []byte(
					"LoadState=loaded\nExecStart={ path=" + interpreter +
						" ; argv[]=" + interpreter + " " + test.scriptPath + " ; ignore_errors=no ; }\n",
				),
			}}
			paths, complete, _, err := startupExecutablePaths(
				context.Background(),
				evaluator.Environment{
					Commands: runner,
					Files:    startupXAttrFixtureReader{Reader: test.reader},
				},
				"example.service",
			)
			if err != nil || complete || !slices.Equal(paths, []string{interpreter}) {
				t.Fatalf(
					"startupExecutablePaths() = %#v, %t, %v, want only the interpreter and an incomplete verdict",
					paths,
					complete,
					err,
				)
			}
		})
	}
}

func TestStartupACLAllowsAllExecutionRejectsRestrictedEntry(t *testing.T) {
	t.Parallel()

	if !startupACLAllowsAllExecution("") {
		t.Fatal("absent access ACL was not accepted")
	}
	if !startupACLAllowsAllExecution("user::rwx\ngroup::r-x\nother::r-x\n") {
		t.Fatal("fully executable base ACL was not accepted")
	}
	for _, content := range []string{
		"user::rwx\nuser:1000:---\ngroup::r-x\nmask::r-x\nother::r-x\n",
		"user::rwx\nuser:1000:rwx #effective:r--\ngroup::r-x\nmask::r-x\nother::r-x\n",
		"user::rwx\ngroup::r--\nother::r-x\n",
		"user::rwx\ngroup::r-x\n",
		"user::rwx\nuser:1000:rwx\ngroup::r-x\nother::r-x\n",
		"user::rwx\nuser::rwx\ngroup::r-x\nother::r-x\n",
		"user::rwx #unexpected\ngroup::r-x\nother::r-x\n",
	} {
		if startupACLAllowsAllExecution(content) {
			t.Errorf("startupACLAllowsAllExecution(%q) = true, want false", content)
		}
	}
}

func TestInspectStartupExecutableCandidateRequiresACLEvidence(t *testing.T) {
	t.Parallel()

	reader := startupFixtureReader{files: fstest.MapFS{
		"usr/bin/helper": &fstest.MapFile{Mode: 0o755},
	}}
	state, evidence, _ := inspectStartupExecutableCandidate(
		context.Background(),
		evaluator.Environment{Commands: systemdCommandFixtureRunner{}, Files: reader},
		"/usr/bin/helper",
		false,
	)
	if state != startupExecutableUncertain || len(evidence) != 1 {
		t.Fatalf("inspectStartupExecutableCandidate() = %v, evidence=%d, want uncertain with ACL evidence", state, len(evidence))
	}
}

func TestStartupExecutablePathsLeavesMissingExecutableForPermissionAssessment(t *testing.T) {
	t.Parallel()

	const executable = "/run/lxd_agent/lxd-agent"
	runner := systemdCommandFixtureRunner{
		result: executor.Result{
			Stdout: []byte("Type=simple\nExecStart={ path=" + executable + " ; argv[]=" + executable + " ; ignore_errors=no ; }\n"),
		},
	}
	paths, complete, _, err := startupExecutablePaths(
		context.Background(),
		evaluator.Environment{
			Commands: runner,
			Files:    startupFixtureReader{files: fstest.MapFS{}},
		},
		"lxd-agent.service",
	)
	if err != nil || !complete || !slices.Equal(paths, []string{executable}) {
		t.Fatalf("startupExecutablePaths() = %#v, %t, %v, want missing path deferred without an error", paths, complete, err)
	}
}

func TestStartupExecutablePathsMarksOnlyExplicitIgnoredMissingExecutableOptional(t *testing.T) {
	t.Parallel()

	const executable = "/usr/bin/plymouth"
	tests := []struct {
		name             string
		commandFields    string
		wantComplete     bool
		wantAllowMissing bool
	}{
		{
			name:             "explicitly ignored",
			commandFields:    "ignore_errors=yes ;",
			wantComplete:     true,
			wantAllowMissing: true,
		},
		{
			name:             "required",
			commandFields:    "ignore_errors=no ;",
			wantComplete:     true,
			wantAllowMissing: false,
		},
		{
			name:             "missing field",
			commandFields:    "status=0/0 ;",
			wantComplete:     true,
			wantAllowMissing: false,
		},
		{
			name:             "invalid field",
			commandFields:    "ignore_errors=sometimes ;",
			wantComplete:     false,
			wantAllowMissing: false,
		},
		{
			name: "duplicate field",
			commandFields: "ignore_errors=yes ; " +
				"ignore_errors=yes ;",
			wantComplete:     false,
			wantAllowMissing: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runner := systemdCommandFixtureRunner{
				result: executor.Result{Stdout: []byte(
					"LoadState=loaded\nType=oneshot\nRemainAfterExit=yes\n" +
						"ExecStartPre={ path=" + executable +
						" ; argv[]=" + executable +
						" --ping ; " + test.commandFields + " }\n",
				)},
			}
			paths, complete, _, _, err := startupExecutablePathsGuarded(
				context.Background(),
				evaluator.Environment{
					Commands: runner,
					Files: startupFixtureReader{files: fstest.MapFS{
						"usr":     &fstest.MapFile{Mode: os.ModeDir | 0o755},
						"usr/bin": &fstest.MapFile{Mode: os.ModeDir | 0o755},
					}},
				},
				"example.service",
			)
			if err != nil || complete != test.wantComplete ||
				len(paths) != 1 ||
				paths[0].Path != executable ||
				paths[0].AllowMissing != test.wantAllowMissing {
				t.Fatalf(
					"guarded missing executable = %#v complete:%t err:%v",
					paths,
					complete,
					err,
				)
			}
		})
	}
}

func TestStartupExecutablePropertiesDigestIncludesIgnoreErrors(t *testing.T) {
	t.Parallel()

	properties := func(value string) map[string]string {
		return map[string]string{
			"LoadState": "loaded",
			"ExecStartPre": "{ path=/usr/bin/plymouth ; " +
				"argv[]=/usr/bin/plymouth --ping ; ignore_errors=" +
				value + " ; }",
		}
	}
	ignored := startupExecutablePropertiesDigest(properties("yes"), true)
	required := startupExecutablePropertiesDigest(properties("no"), true)
	if ignored == required {
		t.Fatalf(
			"ignore_errors digest = %q for both yes and no",
			ignored,
		)
	}
}

func TestStartupIgnoredMissingExecutableStillChecksParentPermissions(t *testing.T) {
	t.Parallel()

	item := startupPendingPermissionAssessment{
		Path:         "/usr/bin/plymouth",
		Assessment:   support.PermissionAssessment{Exists: false},
		AllowMissing: true,
		ParentAssessments: []support.PermissionAssessment{{
			Path:       "/usr/bin",
			Exists:     true,
			Violations: []string{"허용되지 않은 권한 비트 0020"},
		}},
	}
	if unknowns := startupPermissionAssessmentUnknowns(item); len(unknowns) != 0 {
		t.Fatalf("optional missing executable unknowns = %#v, want none", unknowns)
	}
	violations := startupPermissionAssessmentViolations(item)
	if !slices.Equal(
		violations,
		[]string{"/usr/bin: 허용되지 않은 권한 비트 0020"},
	) {
		t.Fatalf(
			"optional missing executable violations = %#v, want unsafe parent retained",
			violations,
		)
	}

	item.AllowMissing = false
	unknowns := startupPermissionAssessmentUnknowns(item)
	if !slices.Equal(unknowns, []string{"/usr/bin/plymouth: 파일 없음"}) {
		t.Fatalf("required missing executable unknowns = %#v", unknowns)
	}
}

func TestStartupPathMissingAllowanceRequiresEveryReferenceToBeOptional(t *testing.T) {
	t.Parallel()

	allowances := make(map[string]bool)
	recordStartupPathMissingAllowance(
		allowances,
		"/usr/bin/plymouth",
		true,
	)
	recordStartupPathMissingAllowance(
		allowances,
		"/usr/bin/plymouth",
		false,
	)
	recordStartupPathMissingAllowance(
		allowances,
		"/usr/bin/plymouth",
		true,
	)
	if allowances["/usr/bin/plymouth"] {
		t.Fatal("a required reference was overwritten by an optional reference")
	}
}

func TestEvaluateStartupPermissionsAcceptsIgnoredMissingExecutableWithSafeParents(t *testing.T) {
	t.Parallel()

	outcome := evaluateStartupPermissions(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{
			Commands: startupIgnoredMissingExecutableRunner{},
			Files:    startupIgnoredMissingExecutableFiles(0o755),
			Platform: model.PlatformInfo{InitSystem: "systemd"},
		},
	)
	if outcome.Status != model.StatusPass {
		t.Fatalf(
			"ignored missing executable outcome = %s, observed=%q",
			outcome.Status,
			outcome.Observed,
		)
	}
}

func TestEvaluateStartupPermissionsRejectsWritableIgnoredMissingExecutableParent(t *testing.T) {
	t.Parallel()

	outcome := evaluateStartupPermissions(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{
			Commands: startupIgnoredMissingExecutableRunner{},
			Files:    startupIgnoredMissingExecutableFiles(0o777),
			Platform: model.PlatformInfo{InitSystem: "systemd"},
		},
	)
	if outcome.Status != model.StatusFail {
		t.Fatalf(
			"writable ignored-missing parent outcome = %s, observed=%q",
			outcome.Status,
			outcome.Observed,
		)
	}
}

func startupIgnoredMissingExecutableFiles(
	binaryDirectoryMode os.FileMode,
) system.Reader {
	return startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
		"usr":                                    &fstest.MapFile{Mode: os.ModeDir | 0o755},
		"usr/bin":                                &fstest.MapFile{Mode: os.ModeDir | binaryDirectoryMode},
		"usr/lib":                                &fstest.MapFile{Mode: os.ModeDir | 0o755},
		"usr/lib/systemd":                        &fstest.MapFile{Mode: os.ModeDir | 0o755},
		"usr/lib/systemd/system":                 &fstest.MapFile{Mode: os.ModeDir | 0o755},
		"usr/lib/systemd/system/example.service": &fstest.MapFile{Mode: 0o644},
		"opt":                                    &fstest.MapFile{Mode: os.ModeDir | 0o755},
		"opt/example-daemon":                     &fstest.MapFile{Mode: 0o755, Data: []byte{0x7f, 'E', 'L', 'F'}},
	}}}
}

func TestExpandStartupUnitDependenciesDerivesAcceptSocketTemplate(t *testing.T) {
	t.Parallel()

	runner := systemdDependencyFixtureRunner{
		outputs: map[string]string{
			"apport-forward.socket": "Wants=\nRequires=\nBindsTo=\nUpholds=\n" +
				"Triggers=\nAccept=yes\nService=\n",
		},
		templateIDs: map[string]string{
			"apport-forward@openciip-audit.service": "apport-forward@openciip-audit.service",
		},
	}
	units, _, unknowns, err := expandStartupUnitDependencies(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{"apport-forward.socket"},
	)
	if err != nil ||
		!slices.Equal(units, []string{"apport-forward.socket"}) ||
		len(unknowns) != 1 ||
		!strings.Contains(unknowns[0], "apport-forward@.service") {
		t.Fatalf(
			"expandStartupUnitDependencies() = %#v, %#v, %v, want dynamic template boundary",
			units,
			unknowns,
			err,
		)
	}
}

func TestExpandStartupUnitDependenciesUsesConcreteTemplateInstance(t *testing.T) {
	t.Parallel()

	runner := systemdDependencyFixtureRunner{
		outputs: map[string]string{
			"getty@tty1.service": "Wants=\nRequires=\nBindsTo=\nOnFailure=\n" +
				"Upholds=\nOnSuccess=\n",
		},
		templateIDs: map[string]string{
			"getty@openciip-audit.service": "getty@openciip-audit.service",
		},
	}
	units, _, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{"getty@.service", "getty@tty1.service"},
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.Equal(units, []string{"getty@tty1.service"}) ||
		digest == "" {
		t.Fatalf(
			"concrete template coverage = units:%#v unknowns:%#v digest:%q err:%v",
			units,
			unknowns,
			digest,
			err,
		)
	}
}

func TestInspectStartupUnitInventoryUsesConcreteTemplateInstance(t *testing.T) {
	t.Parallel()

	runner := systemdDependencyFixtureRunner{
		unitFilesOutput: "getty@.service enabled enabled\n",
		unitsOutput:     "getty@tty1.service loaded active running Getty\n",
		outputs: map[string]string{
			"getty@tty1.service": "Wants=\nRequires=\nBindsTo=\nOnFailure=\n" +
				"Upholds=\nOnSuccess=\n",
		},
		templateIDs: map[string]string{
			"getty@openciip-audit.service": "getty@openciip-audit.service",
		},
	}
	inventory, evidence, err := inspectStartupUnitInventory(
		context.Background(),
		evaluator.Environment{Commands: runner},
	)
	if err != nil ||
		!slices.Equal(
			inventory.BaseUnits,
			[]string{"getty@.service", "getty@tty1.service"},
		) ||
		!slices.Equal(
			inventory.ExpandedUnits,
			[]string{"getty@tty1.service"},
		) ||
		len(inventory.DependencyUnknowns) != 0 ||
		inventory.DependencyDigest == "" ||
		len(evidence) == 0 {
		t.Fatalf(
			"startup inventory = %#v evidence:%d err:%v",
			inventory,
			len(evidence),
			err,
		)
	}
}

func TestExpandStartupUnitDependenciesMatchesAliasTemplateToCanonicalInstance(t *testing.T) {
	t.Parallel()

	runner := systemdDependencyFixtureRunner{
		outputs: map[string]string{
			"getty@tty1.service": "Wants=\nRequires=\nBindsTo=\nOnFailure=\n" +
				"Upholds=\nOnSuccess=\n",
		},
		templateIDs: map[string]string{
			"autovt@openciip-audit.service": "getty@openciip-audit.service",
		},
	}
	units, _, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{"autovt@.service", "getty@tty1.service"},
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.Equal(units, []string{"getty@tty1.service"}) ||
		digest == "" {
		t.Fatalf(
			"alias template coverage = units:%#v unknowns:%#v digest:%q err:%v",
			units,
			unknowns,
			digest,
			err,
		)
	}
}

func TestExpandStartupUnitDependenciesMatchesAliasTemplateToAliasInstance(t *testing.T) {
	t.Parallel()

	runner := systemdDependencyFixtureRunner{
		outputs: map[string]string{
			"autovt@tty1.service": "Wants=\nRequires=\nBindsTo=\nOnFailure=\n" +
				"Upholds=\nOnSuccess=\n",
		},
		templateIDs: map[string]string{
			"autovt@openciip-audit.service": "getty@openciip-audit.service",
		},
	}
	units, _, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{"autovt@.service", "autovt@tty1.service"},
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.Equal(units, []string{"autovt@tty1.service"}) ||
		digest == "" {
		t.Fatalf(
			"alias instance coverage = units:%#v unknowns:%#v digest:%q err:%v",
			units,
			unknowns,
			digest,
			err,
		)
	}
}

func TestExpandStartupUnitDependenciesLeavesUninstantiatedTemplateUnknown(t *testing.T) {
	t.Parallel()

	runner := systemdDependencyFixtureRunner{
		templateIDs: map[string]string{
			"getty@openciip-audit.service": "getty@openciip-audit.service",
		},
	}
	units, _, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{"getty@.service"},
	)
	if err != nil || len(units) != 0 ||
		len(unknowns) != 1 ||
		!strings.Contains(unknowns[0], "getty@.service") ||
		digest == "" {
		t.Fatalf(
			"uninstantiated template boundary = units:%#v unknowns:%#v digest:%q err:%v",
			units,
			unknowns,
			digest,
			err,
		)
	}
}

func TestExpandStartupUnitDependenciesDoesNotHideRealExitOne(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		initial []string
		runner  systemdDependencyFixtureRunner
	}{
		{
			name:    "concrete dependency query",
			initial: []string{"parent.service"},
			runner: systemdDependencyFixtureRunner{
				dependencyFailure: map[string]executor.Result{
					"parent.service": {
						ExitCode: 1,
						Stderr:   []byte("Failed to get properties: Access denied\n"),
					},
				},
			},
		},
		{
			name:    "template identity query",
			initial: []string{"getty@.service"},
			runner: systemdDependencyFixtureRunner{
				templateFailures: map[string]executor.Result{
					"getty@openciip-audit.service": {
						ExitCode: 1,
						Stderr:   []byte("Failed to get properties: Access denied\n"),
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			units, _, unknowns, digest, err :=
				expandStartupUnitDependenciesGuarded(
					context.Background(),
					evaluator.Environment{Commands: test.runner},
					test.initial,
				)
			if err == nil || len(units) != 0 || len(unknowns) != 0 ||
				digest != "" {
				t.Fatalf(
					"exit one result = units:%#v unknowns:%#v digest:%q err:%v",
					units,
					unknowns,
					digest,
					err,
				)
			}
		})
	}
}

func TestExpandStartupUnitDependenciesIncludesDirectActivationRelations(t *testing.T) {
	t.Parallel()

	for _, relation := range []string{"BindsTo", "Upholds", "OnFailure", "OnSuccess"} {
		t.Run(relation, func(t *testing.T) {
			t.Parallel()

			parentProperties := map[string]string{
				"Wants": "", "Requires": "", "BindsTo": "", "OnFailure": "",
				"Upholds": "", "OnSuccess": "",
			}
			parentProperties[relation] = "helper.service"
			runner := systemdDependencyFixtureRunner{outputs: map[string]string{
				"parent.service": strings.Join([]string{
					"Wants=" + parentProperties["Wants"],
					"Requires=" + parentProperties["Requires"],
					"BindsTo=" + parentProperties["BindsTo"],
					"OnFailure=" + parentProperties["OnFailure"],
					"Upholds=" + parentProperties["Upholds"],
					"OnSuccess=" + parentProperties["OnSuccess"],
					"",
				}, "\n"),
				"helper.service": "Wants=\nRequires=\nBindsTo=\nOnFailure=\n" +
					"Upholds=\nOnSuccess=\n",
			}}
			units, _, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
				context.Background(),
				evaluator.Environment{Commands: runner},
				[]string{"parent.service"},
			)
			if err != nil || len(unknowns) != 0 ||
				!slices.Equal(units, []string{"helper.service", "parent.service"}) ||
				digest == "" {
				t.Fatalf(
					"%s dependency expansion = units=%#v unknowns=%#v digest=%q err=%v",
					relation,
					units,
					unknowns,
					digest,
					err,
				)
			}
		})
	}
}

func TestExpandStartupUnitDependenciesRecordsUbuntu18MissingOptionalProperties(t *testing.T) {
	t.Parallel()

	legacyRunner := systemdDependencyFixtureRunner{outputs: map[string]string{
		"parent.service": "Wants=helper.service\nRequires=\nBindsTo=\nOnFailure=\n",
		"helper.service": "Wants=\nRequires=\nBindsTo=\nOnFailure=\n",
	}}
	legacyUnits, _, legacyUnknowns, legacyDigest, legacyErr :=
		expandStartupUnitDependenciesGuarded(
			context.Background(),
			evaluator.Environment{Commands: legacyRunner},
			[]string{"parent.service"},
		)
	if legacyErr != nil || len(legacyUnknowns) != 0 ||
		!slices.Equal(legacyUnits, []string{"helper.service", "parent.service"}) ||
		legacyDigest == "" {
		t.Fatalf(
			"Ubuntu 18.04 dependency expansion = units=%#v unknowns=%#v digest=%q err=%v",
			legacyUnits,
			legacyUnknowns,
			legacyDigest,
			legacyErr,
		)
	}

	modernRunner := systemdDependencyFixtureRunner{outputs: map[string]string{
		"parent.service": "Wants=helper.service\nRequires=\nBindsTo=\nOnFailure=\n" +
			"Upholds=\nOnSuccess=\n",
		"helper.service": "Wants=\nRequires=\nBindsTo=\nOnFailure=\n" +
			"Upholds=\nOnSuccess=\n",
	}}
	_, _, modernUnknowns, modernDigest, modernErr :=
		expandStartupUnitDependenciesGuarded(
			context.Background(),
			evaluator.Environment{Commands: modernRunner},
			[]string{"parent.service"},
		)
	if modernErr != nil || len(modernUnknowns) != 0 || modernDigest == "" ||
		modernDigest == legacyDigest {
		t.Fatalf(
			"optional dependency support digest = legacy:%q modern:%q unknowns=%#v err=%v",
			legacyDigest,
			modernDigest,
			modernUnknowns,
			modernErr,
		)
	}
}

func TestExpandStartupUnitDependenciesFallsBackWhenUpholdsIsUnsupported(t *testing.T) {
	t.Parallel()

	runner := &startupUpholdsCompatibilityRunner{}
	units, _, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{"parent.service"},
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.Equal(units, []string{"helper.service", "parent.service"}) ||
		digest == "" {
		t.Fatalf(
			"legacy dependency expansion = units=%#v unknowns=%#v digest=%q err=%v",
			units,
			unknowns,
			digest,
			err,
		)
	}
	if runner.UpholdsQueries != 2 || runner.CompatibilityQueries != 2 {
		t.Fatalf(
			"legacy dependency query counts = upholds:%d compatibility:%d, want 2 each",
			runner.UpholdsQueries,
			runner.CompatibilityQueries,
		)
	}
}

func TestExpandStartupUnitDependenciesAcceptsLegacyMissingUpholdsProperty(t *testing.T) {
	t.Parallel()

	runner := systemdDependencyFixtureRunner{outputs: map[string]string{
		"parent.service": "Wants=helper.service\nRequires=\nBindsTo=\n",
		"helper.service": "Wants=\nRequires=\nBindsTo=\n",
	}}
	units, _, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
		context.Background(),
		evaluator.Environment{Commands: runner},
		[]string{"parent.service"},
	)
	if err != nil || len(unknowns) != 0 ||
		!slices.Equal(units, []string{"helper.service", "parent.service"}) ||
		digest == "" {
		t.Fatalf(
			"legacy missing-property expansion = units=%#v unknowns=%#v digest=%q err=%v",
			units,
			unknowns,
			digest,
			err,
		)
	}
}

func TestExpandStartupUnitDependenciesRejectsInitialSetBeyondSafeLimit(t *testing.T) {
	t.Parallel()

	units := make([]string, 4097)
	for index := range units {
		units[index] = fmt.Sprintf("bounded-%04d.service", index)
	}
	expanded, evidence, unknowns, digest, err := expandStartupUnitDependenciesGuarded(
		context.Background(),
		evaluator.Environment{},
		units,
	)
	if err == nil || len(expanded) != 0 || len(evidence) != 0 ||
		len(unknowns) != 0 || digest != "" {
		t.Fatalf(
			"oversized dependency traversal = units=%d evidence=%d unknowns=%d digest=%q err=%v",
			len(expanded),
			len(evidence),
			len(unknowns),
			digest,
			err,
		)
	}
}

func TestEvaluateStartupPermissionsIncludesInactiveStaticServiceDependency(t *testing.T) {
	t.Parallel()

	const vulnerableScript = "/opt/vulnerable-start.sh"
	outcome := evaluateStartupPermissions(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{
			Commands: &startupServiceDependencyRunner{},
			Files: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
				"usr/lib/systemd/system/parent.service": &fstest.MapFile{Mode: 0o644},
				"usr/lib/systemd/system/helper.service": &fstest.MapFile{Mode: 0o644},
				"usr/bin/parent-service":                &fstest.MapFile{Mode: 0o755},
				"bin/sh":                                &fstest.MapFile{Mode: 0o755},
				"opt/vulnerable-start.sh":               &fstest.MapFile{Mode: 0o777},
			}}},
			Platform: model.PlatformInfo{InitSystem: "systemd"},
		},
	)
	if outcome.Status != model.StatusFail || outcome.ErrorCode != "" {
		t.Fatalf(
			"evaluateStartupPermissions() = status=%s error=%q summary=%q, want dependent script failure",
			outcome.Status,
			outcome.ErrorCode,
			outcome.Summary,
		)
	}
	if !strings.Contains(fmt.Sprint(outcome.Details), vulnerableScript) {
		t.Fatalf("inactive static dependency script was not inspected: %#v", outcome.Details)
	}
	summaryFound := false
	for _, item := range outcome.Evidence {
		if item.Source != "systemd 시작 파일 권한 파생 정보" {
			continue
		}
		summaryFound = true
		if item.Fact["unit_count"] != 2 {
			t.Fatalf("expanded dependency unit count = %#v, want 2", item.Fact["unit_count"])
		}
	}
	if !summaryFound {
		t.Fatal("startup permission summary evidence is missing")
	}
}

func TestEvaluateStartupPermissionsIncludesCompletionHookServices(t *testing.T) {
	t.Parallel()

	const vulnerableScript = "/opt/vulnerable-start.sh"
	for _, relation := range []string{"OnFailure", "OnSuccess"} {
		t.Run(relation, func(t *testing.T) {
			t.Parallel()

			outcome := evaluateStartupPermissions(
				context.Background(),
				model.ResolvedRule{},
				evaluator.Environment{
					Commands: &startupServiceDependencyRunner{Relation: relation},
					Files: startupXAttrFixtureReader{Reader: startupFixtureReader{files: fstest.MapFS{
						"usr/lib/systemd/system/parent.service": &fstest.MapFile{Mode: 0o644},
						"usr/lib/systemd/system/helper.service": &fstest.MapFile{Mode: 0o644},
						"usr/bin/parent-service":                &fstest.MapFile{Mode: 0o755},
						"bin/sh":                                &fstest.MapFile{Mode: 0o755},
						"opt/vulnerable-start.sh":               &fstest.MapFile{Mode: 0o777},
					}}},
					Platform: model.PlatformInfo{InitSystem: "systemd"},
				},
			)
			if outcome.Status != model.StatusFail || outcome.ErrorCode != "" ||
				!strings.Contains(fmt.Sprint(outcome.Details), vulnerableScript) {
				t.Fatalf(
					"%s hook outcome = status:%s error:%q details:%#v",
					relation,
					outcome.Status,
					outcome.ErrorCode,
					outcome.Details,
				)
			}
		})
	}
}

type systemdCommandFixtureRunner struct {
	result           executor.Result
	err              error
	searchAvailable  bool
	searchResult     executor.Result
	searchErr        error
	mountOptions     map[string]string
	mountUnavailable bool
	busctlAvailable  bool
	busctlResults    map[string]executor.Result
	aclResults       map[string]executor.Result
}

type startupEvaluatorGuardRunner struct {
	reader       *startupPermissionRaceReader
	stateQueries int
}

type startupUnitBoundaryMutationReader struct {
	system.Reader
	FragmentPath             string
	OldExecutable            string
	AuxiliaryRequeryComplete bool
	FragmentChanged          bool
	UnitRequeryComplete      bool
	FinalFilesystemObserved  bool
	CommandAfterFilesystem   bool
	oldExecutableACLReads    int
}

type startupUnitBoundaryMutationRunner struct {
	Reader            *startupUnitBoundaryMutationReader
	Mode              string
	FragmentPath      string
	OldExecutable     string
	NewExecutable     string
	MutationTriggered bool
	stateQueries      int
	execQueries       int
}

type startupToggleMetadataReader struct {
	system.Reader
	Path        string
	ChangedMode os.FileMode
	Changed     bool
}

type startupParentPermissionFixtureReader struct {
	system.Reader
	ParentPath string
	UID        int
	Mode       os.FileMode
}

func (reader *startupParentPermissionFixtureReader) Lstat(
	name string,
) (system.FileMetadata, error) {
	if name == "/" {
		return system.FileMetadata{
			Path: "/", FileType: "directory", Mode: os.ModeDir | 0o755,
			UID: 0, GID: 0,
		}, nil
	}
	metadata, err := reader.Reader.Lstat(name)
	if err == nil && name == reader.ParentPath {
		metadata.UID = reader.UID
		metadata.Mode = reader.Mode
		metadata.FileType = "directory"
	}
	return metadata, err
}

func (reader *startupParentPermissionFixtureReader) Stat(
	name string,
) (system.FileMetadata, error) {
	if name == "/" {
		return reader.Lstat(name)
	}
	metadata, err := reader.Reader.Stat(name)
	if err == nil && name == reader.ParentPath {
		metadata.UID = reader.UID
		metadata.Mode = reader.Mode
		metadata.FileType = "directory"
	}
	return metadata, err
}

func (reader *startupParentPermissionFixtureReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	var (
		metadata system.FileMetadata
		err      error
	)
	if followFinalSymlink {
		metadata, err = reader.Stat(name)
	} else {
		metadata, err = reader.Lstat(name)
	}
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	return map[string][]byte{}, metadata, nil
}

func (reader *startupToggleMetadataReader) Lstat(name string) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Lstat(name)
	if err == nil && reader.Changed && name == reader.Path {
		metadata.Mode = metadata.Mode&^os.ModePerm | reader.ChangedMode.Perm()
	}
	return metadata, err
}

func (reader *startupToggleMetadataReader) Stat(name string) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Stat(name)
	if err == nil && reader.Changed && name == reader.Path {
		metadata.Mode = metadata.Mode&^os.ModePerm | reader.ChangedMode.Perm()
	}
	return metadata, err
}

func (reader *startupUnitBoundaryMutationReader) Lstat(name string) (system.FileMetadata, error) {
	if reader.UnitRequeryComplete {
		reader.FinalFilesystemObserved = true
	}
	metadata, err := reader.Reader.Lstat(name)
	if err == nil && reader.FragmentChanged && name == reader.FragmentPath {
		metadata.Inode++
		metadata.Mode = metadata.Mode&^os.ModePerm | 0o666
	}
	return metadata, err
}

func (reader *startupUnitBoundaryMutationReader) Stat(name string) (system.FileMetadata, error) {
	if reader.UnitRequeryComplete {
		reader.FinalFilesystemObserved = true
	}
	metadata, err := reader.Reader.Stat(name)
	if err == nil && reader.FragmentChanged && name == reader.FragmentPath {
		metadata.Inode++
		metadata.Mode = metadata.Mode&^os.ModePerm | 0o666
	}
	return metadata, err
}

func (reader *startupUnitBoundaryMutationReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	var (
		metadata system.FileMetadata
		err      error
	)
	if followFinalSymlink {
		metadata, err = reader.Stat(name)
	} else {
		metadata, err = reader.Lstat(name)
	}
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	if name == reader.OldExecutable {
		reader.oldExecutableACLReads++
		if reader.oldExecutableACLReads >= 4 {
			reader.AuxiliaryRequeryComplete = true
		}
	}
	return map[string][]byte{}, metadata, nil
}

type startupMutableSecurityRunner struct {
	aclByPath   map[string]string
	mountByPath map[string]string
}

func (runner *startupMutableSecurityRunner) Available(name string) bool {
	return name == "getfacl" || name == "findmnt"
}

func (runner *startupMutableSecurityRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	if len(spec.Arguments) == 0 {
		return executor.Result{}, errors.New("missing mutable security fixture path")
	}
	target := spec.Arguments[len(spec.Arguments)-1]
	switch spec.Name {
	case "getfacl":
		acl, exists := runner.aclByPath[target]
		if !exists {
			acl = "user::rwx\ngroup::r-x\nother::r-x\n"
		}
		return executor.Result{Stdout: []byte(acl)}, nil
	case "findmnt":
		options, exists := runner.mountByPath[target]
		if !exists || options == "" {
			options = "rw,relatime,noexec"
		}
		return executor.Result{Stdout: []byte(options + "\n")}, nil
	default:
		return executor.Result{}, fmt.Errorf("unexpected mutable security fixture command %s", spec.Name)
	}
}

type startupInventoryMutationRunner struct {
	Change   string
	Relation string
}

func (runner *startupInventoryMutationRunner) Available(name string) bool {
	return name == "systemctl"
}

func (runner *startupInventoryMutationRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	if spec.Name != "systemctl" || len(spec.Arguments) == 0 {
		return executor.Result{}, errors.New("unexpected inventory fixture command")
	}
	switch spec.Arguments[0] {
	case "list-unit-files":
		lines := []string{
			"example.service enabled",
			"first.service enabled",
			"second.service enabled",
		}
		if runner.Change == "unit" {
			lines = append(lines, "new.service enabled")
		}
		return executor.Result{Stdout: []byte(strings.Join(lines, "\n") + "\n")}, nil
	case "list-units":
		return executor.Result{}, nil
	case "show":
		unitName := spec.Arguments[len(spec.Arguments)-1]
		properties := ""
		for _, argument := range spec.Arguments {
			if strings.HasPrefix(argument, "--property=") {
				properties = strings.TrimPrefix(argument, "--property=")
				break
			}
		}
		expectedProperties := strings.Join(
			startupDependencyPropertyNames(unitName, true),
			",",
		)
		if properties != expectedProperties {
			return executor.Result{}, fmt.Errorf(
				"inventory dependency properties = %q, want %q",
				properties,
				expectedProperties,
			)
		}
		values := map[string]string{
			"Wants": "", "Requires": "", "BindsTo": "", "OnFailure": "",
			"Upholds": "", "OnSuccess": "",
		}
		if unitName == "example.service" {
			dependency := "first.service"
			if runner.Change == "dependency" {
				dependency = "second.service"
			}
			values[runner.Relation] = dependency
		}
		return executor.Result{Stdout: []byte(strings.Join([]string{
			"Wants=" + values["Wants"],
			"Requires=" + values["Requires"],
			"BindsTo=" + values["BindsTo"],
			"OnFailure=" + values["OnFailure"],
			"Upholds=" + values["Upholds"],
			"OnSuccess=" + values["OnSuccess"],
			"",
		}, "\n"))}, nil
	default:
		return executor.Result{}, fmt.Errorf("unexpected inventory fixture operation %q", spec.Arguments[0])
	}
}

func (runner *startupUnitBoundaryMutationRunner) Available(name string) bool {
	return name == "systemctl"
}

func (runner *startupUnitBoundaryMutationRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	if runner.Reader.FinalFilesystemObserved {
		runner.Reader.CommandAfterFilesystem = true
	}
	if spec.Name != "systemctl" || len(spec.Arguments) == 0 {
		return executor.Result{}, fmt.Errorf(
			"unexpected boundary mutation command: %s %#v",
			spec.Name,
			spec.Arguments,
		)
	}
	switch spec.Arguments[0] {
	case "list-unit-files":
		return executor.Result{Stdout: []byte("example.service enabled\n")}, nil
	case "list-units":
		return executor.Result{}, nil
	case "show":
		properties := ""
		for _, argument := range spec.Arguments {
			if strings.HasPrefix(argument, "--property=") {
				properties = strings.TrimPrefix(argument, "--property=")
				break
			}
		}
		if properties == strings.Join(startupDependencyPropertyNames("example.service", true), ",") {
			return executor.Result{Stdout: []byte(
				"Wants=\nRequires=\nBindsTo=\nUpholds=\n",
			)}, nil
		}
		if strings.HasPrefix(properties, "Id,LoadState,ActiveState") {
			runner.stateQueries++
			return executor.Result{Stdout: []byte(strings.Join([]string{
				"Id=example.service",
				"LoadState=loaded",
				"ActiveState=active",
				"SubState=running",
				"UnitFileState=enabled",
				"FragmentPath=" + runner.FragmentPath,
				"DropInPaths=",
				"",
			}, "\n"))}, nil
		}
		if strings.Contains(properties, "ExecStart") {
			runner.execQueries++
			executable := runner.OldExecutable
			if runner.execQueries == 2 && runner.Reader.AuxiliaryRequeryComplete {
				runner.Reader.UnitRequeryComplete = true
				switch runner.Mode {
				case "exec_after_auxiliary":
					executable = runner.NewExecutable
					runner.MutationTriggered = true
				case "fragment_after_unit":
					runner.Reader.FragmentChanged = true
					runner.MutationTriggered = true
				}
			}
			return executor.Result{Stdout: []byte(
				"LoadState=loaded\nType=simple\nRemainAfterExit=no\n" +
					"ExecStart={ path=" + executable + " ; argv[]=" + executable +
					" ; ignore_errors=no ; }\n",
			)}, nil
		}
	}
	return executor.Result{}, fmt.Errorf(
		"unexpected boundary mutation systemctl operation: %#v",
		spec.Arguments,
	)
}

func (runner *startupEvaluatorGuardRunner) Available(name string) bool {
	return name == "systemctl" || name == "findmnt" || name == "getfacl"
}

func (runner *startupEvaluatorGuardRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	switch spec.Name {
	case "systemctl":
		if len(spec.Arguments) == 0 {
			return executor.Result{}, errors.New("missing systemctl fixture arguments")
		}
		switch spec.Arguments[0] {
		case "list-unit-files":
			return executor.Result{Stdout: []byte("example.service enabled\n")}, nil
		case "list-units":
			return executor.Result{}, nil
		case "show":
			properties := ""
			for _, argument := range spec.Arguments {
				if strings.HasPrefix(argument, "--property=") {
					properties = strings.TrimPrefix(argument, "--property=")
					break
				}
			}
			if properties == strings.Join(startupDependencyPropertyNames("example.service", true), ",") {
				return executor.Result{Stdout: []byte(
					"Wants=\nRequires=\nBindsTo=\nUpholds=\n",
				)}, nil
			}
			if strings.HasPrefix(properties, "Id,LoadState,ActiveState") {
				runner.stateQueries++
				if runner.stateQueries == 2 && runner.reader != nil {
					runner.reader.parentChanged = true
				}
				return executor.Result{Stdout: []byte(strings.Join([]string{
					"Id=example.service",
					"LoadState=loaded",
					"ActiveState=active",
					"SubState=running",
					"UnitFileState=enabled",
					"FragmentPath=",
					"DropInPaths=",
					"",
				}, "\n"))}, nil
			}
			if strings.Contains(properties, "ExecStart") {
				return executor.Result{Stdout: []byte(
					"LoadState=loaded\nType=simple\nRemainAfterExit=no\n" +
						"ExecStart={ path=/usr/bin/example ; argv[]=/usr/bin/example ; ignore_errors=no ; }\n",
				)}, nil
			}
		}
	case "findmnt":
		return executor.Result{Stdout: []byte("rw,relatime\n")}, nil
	case "getfacl":
		return executor.Result{Stdout: []byte("user::rwx\ngroup::rwx\nother::rwx\n")}, nil
	}
	return executor.Result{}, fmt.Errorf("unexpected startup evaluator fixture command: %s %#v", spec.Name, spec.Arguments)
}

type startupSymlinkFixtureReader struct {
	startupFixtureReader
	links map[string]string
}

type startupIntermediateSymlinkFixtureReader struct {
	startupFixtureReader
	links map[string]string
}

type startupXAttrFixtureReader struct {
	system.Reader
	ACLByPath map[string][]byte
}

type startupShebangFixtureReader struct {
	system.Reader
	UIDByPath         map[string]int
	ChangedPrefixPath string
	ChangedPrefix     []byte
	prefixReads       map[string]int
}

type startupLargeExecutableReader struct {
	system.Reader
	Path   string
	Size   int64
	Prefix []byte
}

type startupSnapshotMutationReader struct {
	system.Reader
	MutationPath    string
	MutationFollow  bool
	MutateAfterRead int
	Mutate          func(system.FileMetadata, error) (system.FileMetadata, error)
	lstatReads      int
	statReads       int
}

type startupPermissionRaceReader struct {
	system.Reader
	ParentPath        string
	Armed             bool
	ChangeParent      bool
	PermissionError   bool
	TriggerPath       string
	parentChanged     bool
	SymlinkPath       string
	ChangedLinkTarget string
	symlinkChanged    bool
}

func (reader *startupPermissionRaceReader) Lstat(name string) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Lstat(name)
	if err == nil && reader.parentChanged && name == reader.ParentPath {
		metadata.Inode++
	}
	if err == nil && reader.symlinkChanged && name == reader.SymlinkPath {
		metadata.LinkTarget = reader.ChangedLinkTarget
	}
	return metadata, err
}

func (reader *startupPermissionRaceReader) Stat(name string) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Stat(name)
	if err == nil && reader.parentChanged && name == reader.ParentPath {
		metadata.Inode++
	}
	return metadata, err
}

func (reader *startupPermissionRaceReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	_ bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	metadata, err := reader.Reader.Stat(name)
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	if reader.Armed && (reader.TriggerPath == "" || reader.TriggerPath == name) {
		if reader.ChangeParent {
			reader.parentChanged = true
		}
		if reader.SymlinkPath != "" {
			reader.symlinkChanged = true
		}
		if reader.PermissionError {
			return nil, metadata, system.ErrFileChanged
		}
	}
	return map[string][]byte{}, metadata, nil
}

func (reader *startupSnapshotMutationReader) Lstat(name string) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Lstat(name)
	if reader.MutationFollow || name != reader.MutationPath {
		return metadata, err
	}
	reader.lstatReads++
	if reader.lstatReads <= reader.MutateAfterRead || reader.Mutate == nil {
		return metadata, err
	}
	return reader.Mutate(metadata, err)
}

func (reader *startupSnapshotMutationReader) Stat(name string) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Stat(name)
	if !reader.MutationFollow || name != reader.MutationPath {
		return metadata, err
	}
	reader.statReads++
	if reader.statReads <= reader.MutateAfterRead || reader.Mutate == nil {
		return metadata, err
	}
	return reader.Mutate(metadata, err)
}

func (reader *startupSnapshotMutationReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	var (
		metadata system.FileMetadata
		err      error
	)
	if followFinalSymlink {
		metadata, err = reader.Stat(name)
	} else {
		metadata, err = reader.Lstat(name)
	}
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	return map[string][]byte{}, metadata, nil
}

func (reader startupXAttrFixtureReader) Lstat(name string) (system.FileMetadata, error) {
	if name == "/" {
		return system.FileMetadata{Path: "/", FileType: "directory", Mode: os.ModeDir | 0o755, UID: 0, GID: 0}, nil
	}
	return reader.Reader.Lstat(name)
}

func (reader startupXAttrFixtureReader) Stat(name string) (system.FileMetadata, error) {
	if name == "/" {
		return reader.Lstat(name)
	}
	return reader.Reader.Stat(name)
}

func (reader startupXAttrFixtureReader) ReadFilePrefix(
	ctx context.Context,
	name string,
	limit int64,
) ([]byte, system.FileMetadata, error) {
	if prefixReader, ok := reader.Reader.(system.BoundedFilePrefixReader); ok {
		return prefixReader.ReadFilePrefix(ctx, name, limit)
	}
	return reader.Reader.ReadFile(ctx, name, limit)
}

func (reader startupXAttrFixtureReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	var (
		metadata system.FileMetadata
		err      error
	)
	if followFinalSymlink {
		metadata, err = reader.Stat(name)
	} else {
		metadata, err = reader.Lstat(name)
	}
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	values := map[string][]byte{}
	if acl, exists := reader.ACLByPath[name]; exists {
		values["system.posix_acl_access"] = append([]byte(nil), acl...)
	}
	return values, metadata, nil
}

func mustTestPOSIXACLXAttr(t *testing.T, content string) []byte {
	t.Helper()
	const undefinedID = uint32(0xffffffff)
	type entry struct {
		tag   uint16
		perms uint16
		id    uint32
	}
	entries := make([]entry, 0, 8)
	for lineNumber, raw := range strings.Split(strings.TrimSpace(content), "\n") {
		fields := strings.Split(strings.TrimSpace(raw), ":")
		if len(fields) != 3 {
			t.Fatalf("ACL line %d has %d fields: %q", lineNumber+1, len(fields), raw)
		}
		item := entry{id: undefinedID}
		switch fields[0] {
		case "user":
			if fields[1] == "" {
				item.tag = 0x01
			} else {
				item.tag = 0x02
			}
		case "group":
			if fields[1] == "" {
				item.tag = 0x04
			} else {
				item.tag = 0x08
			}
		case "mask":
			item.tag = 0x10
		case "other":
			item.tag = 0x20
		default:
			t.Fatalf("ACL line %d has unsupported tag %q", lineNumber+1, fields[0])
		}
		if fields[1] != "" {
			identifier, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				t.Fatalf("ACL line %d identifier: %v", lineNumber+1, err)
			}
			item.id = uint32(identifier)
		}
		for _, character := range fields[2] {
			switch character {
			case 'r':
				item.perms |= 0o4
			case 'w':
				item.perms |= 0o2
			case 'x':
				item.perms |= 0o1
			case '-':
			default:
				t.Fatalf("ACL line %d has invalid permission %q", lineNumber+1, character)
			}
		}
		entries = append(entries, item)
	}
	encoded := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(encoded[:4], 2)
	for index, item := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(encoded[offset:offset+2], item.tag)
		binary.LittleEndian.PutUint16(encoded[offset+2:offset+4], item.perms)
		binary.LittleEndian.PutUint32(encoded[offset+4:offset+8], item.id)
	}
	return encoded
}

func (reader *startupShebangFixtureReader) applyMetadata(
	metadata system.FileMetadata,
) system.FileMetadata {
	if uid, exists := reader.UIDByPath[metadata.Path]; exists {
		metadata.UID = uid
	}
	return metadata
}

func (reader *startupShebangFixtureReader) Lstat(
	name string,
) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Lstat(name)
	if err == nil {
		metadata = reader.applyMetadata(metadata)
	}
	return metadata, err
}

func (reader *startupShebangFixtureReader) Stat(
	name string,
) (system.FileMetadata, error) {
	metadata, err := reader.Reader.Stat(name)
	if err == nil {
		metadata = reader.applyMetadata(metadata)
	}
	return metadata, err
}

func (reader *startupShebangFixtureReader) ReadFile(
	ctx context.Context,
	name string,
	limit int64,
) ([]byte, system.FileMetadata, error) {
	data, metadata, err := reader.Reader.ReadFile(ctx, name, limit)
	if err == nil {
		metadata = reader.applyMetadata(metadata)
	}
	return data, metadata, err
}

func (reader *startupShebangFixtureReader) ReadFilePrefix(
	ctx context.Context,
	name string,
	limit int64,
) ([]byte, system.FileMetadata, error) {
	var (
		data     []byte
		metadata system.FileMetadata
		err      error
	)
	if prefixReader, ok := reader.Reader.(system.BoundedFilePrefixReader); ok {
		data, metadata, err = prefixReader.ReadFilePrefix(ctx, name, limit)
	} else {
		data, metadata, err = reader.Reader.ReadFile(ctx, name, limit)
	}
	if err != nil {
		return data, metadata, err
	}
	metadata = reader.applyMetadata(metadata)
	if reader.prefixReads == nil {
		reader.prefixReads = make(map[string]int)
	}
	reader.prefixReads[name]++
	if name == reader.ChangedPrefixPath &&
		reader.prefixReads[name] > 1 {
		data = append([]byte(nil), reader.ChangedPrefix...)
		if int64(len(data)) > limit {
			data = data[:limit]
		}
	}
	return data, metadata, nil
}

func (reader *startupLargeExecutableReader) executableMetadata() system.FileMetadata {
	return system.FileMetadata{
		Path:     reader.Path,
		FileType: "regular",
		Mode:     0o755,
		Size:     reader.Size,
		UID:      0,
		GID:      0,
	}
}

func (reader *startupLargeExecutableReader) Lstat(
	name string,
) (system.FileMetadata, error) {
	if name == reader.Path {
		return reader.executableMetadata(), nil
	}
	return reader.Reader.Lstat(name)
}

func (reader *startupLargeExecutableReader) Stat(
	name string,
) (system.FileMetadata, error) {
	if name == reader.Path {
		return reader.executableMetadata(), nil
	}
	return reader.Reader.Stat(name)
}

func (reader *startupLargeExecutableReader) ReadFile(
	ctx context.Context,
	name string,
	limit int64,
) ([]byte, system.FileMetadata, error) {
	if name == reader.Path {
		return nil, system.FileMetadata{}, fmt.Errorf(
			"%w: %s",
			system.ErrReadLimit,
			name,
		)
	}
	return reader.Reader.ReadFile(ctx, name, limit)
}

func (reader *startupLargeExecutableReader) ReadFilePrefix(
	ctx context.Context,
	name string,
	limit int64,
) ([]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	if name != reader.Path {
		if prefixReader, ok := reader.Reader.(system.BoundedFilePrefixReader); ok {
			return prefixReader.ReadFilePrefix(ctx, name, limit)
		}
		return reader.Reader.ReadFile(ctx, name, limit)
	}
	prefix := append([]byte(nil), reader.Prefix...)
	if int64(len(prefix)) > limit {
		prefix = prefix[:limit]
	}
	return prefix, reader.executableMetadata(), nil
}

func (reader startupSymlinkFixtureReader) Lstat(name string) (system.FileMetadata, error) {
	if target, exists := reader.links[name]; exists {
		return system.FileMetadata{
			Path: name, FileType: "symlink", Mode: os.ModeSymlink | 0o777,
			UID: 0, GID: 0, LinkTarget: target,
		}, nil
	}
	metadata, err := reader.startupFixtureReader.Lstat(name)
	if err == nil {
		return metadata, nil
	}
	prefix := strings.TrimSuffix(name, "/") + "/"
	for linkPath := range reader.links {
		if strings.HasPrefix(linkPath, prefix) {
			return system.FileMetadata{
				Path: name, FileType: "directory", Mode: os.ModeDir | 0o755,
				UID: 0, GID: 0,
			}, nil
		}
	}
	return system.FileMetadata{}, err
}

func (reader startupSymlinkFixtureReader) Stat(name string) (system.FileMetadata, error) {
	const maximumSymlinkDepth = 40
	current := name
	seen := make(map[string]struct{}, maximumSymlinkDepth)
	for depth := 0; depth < maximumSymlinkDepth; depth++ {
		target, exists := reader.links[current]
		if !exists {
			metadata, err := reader.Lstat(current)
			if err == nil {
				metadata.Path = name
			}
			return metadata, err
		}
		if _, duplicate := seen[current]; duplicate {
			return system.FileMetadata{}, errors.New("fixture symlink cycle")
		}
		seen[current] = struct{}{}
		if path.IsAbs(target) {
			current = path.Clean(target)
		} else {
			current = path.Clean(path.Join(path.Dir(current), target))
		}
	}
	return system.FileMetadata{}, errors.New("fixture symlink depth exceeded")
}

func (reader *startupIntermediateSymlinkFixtureReader) resolve(
	name string,
	followFinalSymlink bool,
) (string, error) {
	const maximumSymlinkDepth = 40
	current := path.Clean(name)
	for depth := 0; depth < maximumSymlinkDepth; depth++ {
		components := strings.Split(strings.TrimPrefix(current, "/"), "/")
		parent := "/"
		rewritten := false
		for index, component := range components {
			candidate := path.Join(parent, component)
			target, exists := reader.links[candidate]
			if !exists || (index == len(components)-1 && !followFinalSymlink) {
				parent = candidate
				continue
			}
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(candidate), target)
			}
			nextParts := append(
				[]string{path.Clean(target)},
				components[index+1:]...,
			)
			current = path.Clean(path.Join(nextParts...))
			rewritten = true
			break
		}
		if !rewritten {
			return current, nil
		}
	}
	return "", errors.New("fixture symlink depth exceeded")
}

func (reader *startupIntermediateSymlinkFixtureReader) Lstat(
	name string,
) (system.FileMetadata, error) {
	if name == "/" {
		return system.FileMetadata{
			Path: "/", FileType: "directory", Mode: os.ModeDir | 0o755,
			UID: 0, GID: 0,
		}, nil
	}
	if target, exists := reader.links[name]; exists {
		return system.FileMetadata{
			Path: name, FileType: "symlink", Mode: os.ModeSymlink | 0o777,
			UID: 0, GID: 0, LinkTarget: target,
		}, nil
	}
	resolved, err := reader.resolve(name, false)
	if err != nil {
		return system.FileMetadata{}, err
	}
	metadata, err := reader.startupFixtureReader.Lstat(resolved)
	if err == nil {
		metadata.Path = name
	}
	return metadata, err
}

func (reader *startupIntermediateSymlinkFixtureReader) Stat(
	name string,
) (system.FileMetadata, error) {
	if name == "/" {
		return reader.Lstat(name)
	}
	resolved, err := reader.resolve(name, true)
	if err != nil {
		return system.FileMetadata{}, err
	}
	metadata, err := reader.startupFixtureReader.Lstat(resolved)
	if err == nil {
		metadata.Path = name
	}
	return metadata, err
}

func (reader *startupIntermediateSymlinkFixtureReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	var (
		metadata system.FileMetadata
		err      error
	)
	if followFinalSymlink {
		metadata, err = reader.Stat(name)
	} else {
		metadata, err = reader.Lstat(name)
	}
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	return map[string][]byte{}, metadata, nil
}

type systemdDependencyFixtureRunner struct {
	unitFilesOutput   string
	unitsOutput       string
	outputs           map[string]string
	templateIDs       map[string]string
	templateFailures  map[string]executor.Result
	dependencyFailure map[string]executor.Result
}

type startupIgnoredMissingExecutableRunner struct{}

type startupServiceDependencyRunner struct {
	Relation string
}

type startupUpholdsCompatibilityRunner struct {
	UpholdsQueries       int
	CompatibilityQueries int
}

func (runner systemdDependencyFixtureRunner) Available(name string) bool {
	return name == "systemctl"
}

func (startupIgnoredMissingExecutableRunner) Available(name string) bool {
	return name == "systemctl"
}

func (startupIgnoredMissingExecutableRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	if spec.Name != "systemctl" || len(spec.Arguments) == 0 {
		return executor.Result{}, fmt.Errorf(
			"unexpected ignored-missing fixture command: %s %#v",
			spec.Name,
			spec.Arguments,
		)
	}
	switch spec.Arguments[0] {
	case "list-unit-files":
		return executor.Result{
			Stdout: []byte("example.service enabled enabled\n"),
		}, nil
	case "list-units":
		return executor.Result{}, nil
	case "show":
		properties := ""
		for _, argument := range spec.Arguments {
			if strings.HasPrefix(argument, "--property=") {
				properties = strings.TrimPrefix(argument, "--property=")
				break
			}
		}
		unitName := spec.Arguments[len(spec.Arguments)-1]
		if unitName != "example.service" {
			return executor.Result{}, fmt.Errorf(
				"unexpected ignored-missing fixture unit %q",
				unitName,
			)
		}
		switch {
		case properties == strings.Join(
			startupDependencyPropertyNames(unitName, true),
			",",
		):
			return executor.Result{Stdout: []byte(
				"Wants=\nRequires=\nBindsTo=\nOnFailure=\n" +
					"Upholds=\nOnSuccess=\n",
			)}, nil
		case strings.HasPrefix(properties, "Id,LoadState,ActiveState"):
			return executor.Result{Stdout: []byte(strings.Join([]string{
				"Id=example.service",
				"LoadState=loaded",
				"ActiveState=inactive",
				"SubState=dead",
				"UnitFileState=enabled",
				"FragmentPath=/usr/lib/systemd/system/example.service",
				"DropInPaths=",
				"",
			}, "\n"))}, nil
		case strings.Contains(properties, "ExecStart"):
			return executor.Result{Stdout: []byte(
				"LoadState=loaded\nType=simple\nRemainAfterExit=no\n" +
					"ExecStartPre={ path=/usr/bin/plymouth ; " +
					"argv[]=/usr/bin/plymouth --ping ; ignore_errors=yes ; }\n" +
					"ExecStart={ path=/opt/example-daemon ; " +
					"argv[]=/opt/example-daemon ; ignore_errors=no ; }\n",
			)}, nil
		default:
			return executor.Result{}, fmt.Errorf(
				"unexpected ignored-missing fixture properties %q",
				properties,
			)
		}
	default:
		return executor.Result{}, fmt.Errorf(
			"unexpected ignored-missing fixture operation %q",
			spec.Arguments[0],
		)
	}
}

func (runner systemdDependencyFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "systemctl" || len(spec.Arguments) == 0 {
		return executor.Result{}, errors.New("unexpected fixture command")
	}
	switch spec.Arguments[0] {
	case "list-unit-files":
		return executor.Result{Stdout: []byte(runner.unitFilesOutput)}, nil
	case "list-units":
		return executor.Result{Stdout: []byte(runner.unitsOutput)}, nil
	}
	unitName := spec.Arguments[len(spec.Arguments)-1]
	properties := ""
	for _, argument := range spec.Arguments {
		if strings.HasPrefix(argument, "--property=") {
			properties = strings.TrimPrefix(argument, "--property=")
			break
		}
	}
	if properties == "Id,LoadState" {
		if result, exists := runner.templateFailures[unitName]; exists {
			return result, nil
		}
		id, exists := runner.templateIDs[unitName]
		if !exists {
			return executor.Result{}, fmt.Errorf(
				"unexpected fixture template identity unit %q",
				unitName,
			)
		}
		return executor.Result{Stdout: []byte(
			"Id=" + id + "\nLoadState=loaded\n",
		)}, nil
	}
	expectedProperties := strings.Join(startupDependencyPropertyNames(unitName, true), ",")
	if properties != expectedProperties {
		return executor.Result{}, fmt.Errorf(
			"fixture dependency properties = %q, want %q",
			properties,
			expectedProperties,
		)
	}
	if result, exists := runner.dependencyFailure[unitName]; exists {
		return result, nil
	}
	output, exists := runner.outputs[unitName]
	if !exists {
		return executor.Result{}, fmt.Errorf("unexpected fixture unit %q", unitName)
	}
	return executor.Result{Stdout: []byte(output)}, nil
}

func (runner *startupUpholdsCompatibilityRunner) Available(name string) bool {
	return name == "systemctl"
}

func (runner *startupUpholdsCompatibilityRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	if spec.Name != "systemctl" || len(spec.Arguments) == 0 ||
		spec.Arguments[0] != "show" {
		return executor.Result{}, fmt.Errorf(
			"unexpected legacy dependency command: %s %#v",
			spec.Name,
			spec.Arguments,
		)
	}
	unitName := spec.Arguments[len(spec.Arguments)-1]
	properties := ""
	for _, argument := range spec.Arguments {
		if strings.HasPrefix(argument, "--property=") {
			properties = strings.TrimPrefix(argument, "--property=")
			break
		}
	}
	switch properties {
	case strings.Join(startupDependencyPropertyNames(unitName, true), ","):
		runner.UpholdsQueries++
		return executor.Result{
			ExitCode: 1,
			Stderr:   []byte("Unknown property Upholds\n"),
		}, nil
	case strings.Join(startupDependencyPropertyNames(unitName, false), ","):
		runner.CompatibilityQueries++
		wants := ""
		if unitName == "parent.service" {
			wants = "helper.service"
		}
		return executor.Result{Stdout: []byte(
			"Wants=" + wants + "\nRequires=\nBindsTo=\n",
		)}, nil
	default:
		return executor.Result{}, fmt.Errorf(
			"unexpected legacy dependency properties %q",
			properties,
		)
	}
}

func (runner *startupServiceDependencyRunner) Available(name string) bool {
	return name == "systemctl"
}

func (runner *startupServiceDependencyRunner) Run(
	_ context.Context,
	spec executor.Spec,
) (executor.Result, error) {
	if spec.Name != "systemctl" || len(spec.Arguments) == 0 {
		return executor.Result{}, fmt.Errorf(
			"unexpected service dependency command: %s %#v",
			spec.Name,
			spec.Arguments,
		)
	}
	switch spec.Arguments[0] {
	case "list-unit-files":
		return executor.Result{Stdout: []byte("parent.service enabled\n")}, nil
	case "list-units":
		return executor.Result{}, nil
	case "show":
		unitName := spec.Arguments[len(spec.Arguments)-1]
		properties := ""
		for _, argument := range spec.Arguments {
			if strings.HasPrefix(argument, "--property=") {
				properties = strings.TrimPrefix(argument, "--property=")
				break
			}
		}
		if properties == strings.Join(startupDependencyPropertyNames(unitName, true), ",") {
			relation := runner.Relation
			if relation == "" {
				relation = "Wants"
			}
			values := map[string]string{
				"Wants": "", "Requires": "", "BindsTo": "", "OnFailure": "",
				"Upholds": "", "OnSuccess": "",
			}
			if unitName == "parent.service" {
				values[relation] = "helper.service"
			}
			return executor.Result{Stdout: []byte(strings.Join([]string{
				"Wants=" + values["Wants"],
				"Requires=" + values["Requires"],
				"BindsTo=" + values["BindsTo"],
				"OnFailure=" + values["OnFailure"],
				"Upholds=" + values["Upholds"],
				"OnSuccess=" + values["OnSuccess"],
				"",
			}, "\n"))}, nil
		}
		if strings.HasPrefix(properties, "Id,LoadState,ActiveState") {
			activeState := "inactive"
			subState := "dead"
			unitFileState := "static"
			fragmentPath := "/usr/lib/systemd/system/helper.service"
			if unitName == "parent.service" {
				activeState = "active"
				subState = "running"
				unitFileState = "enabled"
				fragmentPath = "/usr/lib/systemd/system/parent.service"
			}
			return executor.Result{Stdout: []byte(strings.Join([]string{
				"Id=" + unitName,
				"LoadState=loaded",
				"ActiveState=" + activeState,
				"SubState=" + subState,
				"UnitFileState=" + unitFileState,
				"FragmentPath=" + fragmentPath,
				"DropInPaths=",
				"",
			}, "\n"))}, nil
		}
		if strings.Contains(properties, "ExecStart") {
			executable := "/usr/bin/parent-service"
			arguments := executable
			serviceType := "simple"
			remainAfterExit := "no"
			if unitName == "helper.service" {
				executable = "/bin/sh"
				arguments = executable + " /opt/vulnerable-start.sh"
				serviceType = "oneshot"
				remainAfterExit = "yes"
			}
			return executor.Result{Stdout: []byte(
				"LoadState=loaded\nType=" + serviceType +
					"\nRemainAfterExit=" + remainAfterExit +
					"\nExecStart={ path=" + executable + " ; argv[]=" + arguments +
					" ; ignore_errors=no ; }\n",
			)}, nil
		}
	}
	return executor.Result{}, fmt.Errorf(
		"unexpected service dependency systemctl operation: %#v",
		spec.Arguments,
	)
}

func (runner systemdCommandFixtureRunner) Available(name string) bool {
	return name == "systemctl" ||
		(name == "systemd-path" && runner.searchAvailable) ||
		(name == "findmnt" && !runner.mountUnavailable) ||
		(name == "busctl" && runner.busctlAvailable) ||
		(name == "getfacl" && runner.aclResults != nil)
}

func (runner systemdCommandFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	switch spec.Name {
	case "systemctl":
		return runner.result, runner.err
	case "systemd-path":
		if !runner.searchAvailable {
			return executor.Result{}, errors.New("systemd-path is unavailable")
		}
		return runner.searchResult, runner.searchErr
	case "findmnt":
		if runner.mountUnavailable {
			return executor.Result{}, errors.New("findmnt is unavailable")
		}
		options := "rw,relatime"
		if len(spec.Arguments) > 0 {
			if configured, exists := runner.mountOptions[spec.Arguments[len(spec.Arguments)-1]]; exists {
				options = configured
			}
		}
		return executor.Result{Stdout: []byte(options + "\n")}, nil
	case "busctl":
		if !runner.busctlAvailable || len(spec.Arguments) == 0 {
			return executor.Result{}, errors.New("busctl is unavailable")
		}
		property := spec.Arguments[len(spec.Arguments)-1]
		result, exists := runner.busctlResults[property]
		if !exists {
			return executor.Result{}, fmt.Errorf("unexpected busctl property %q", property)
		}
		return result, nil
	case "getfacl":
		if runner.aclResults == nil || len(spec.Arguments) == 0 {
			return executor.Result{}, errors.New("getfacl is unavailable")
		}
		target := spec.Arguments[len(spec.Arguments)-1]
		if result, exists := runner.aclResults[target]; exists {
			return result, nil
		}
		return executor.Result{
			Stdout: []byte("user::rwx\ngroup::r-x\nother::r-x\n"),
		}, nil
	default:
		return executor.Result{}, errors.New("unexpected fixture command")
	}
}

func TestRsyslogConfigPathFromSysconfigUsesCustomFOption(t *testing.T) {
	configPath, complete, err := rsyslogConfigPathFromSysconfig("SYSLOGD_OPTIONS='-n -f /tmp/custom-rsyslog.conf'\n")
	if err != nil || !complete || configPath != "/tmp/custom-rsyslog.conf" {
		t.Fatalf("rsyslogConfigPathFromSysconfig() = %q, %t, %v", configPath, complete, err)
	}
}

func TestRsyslogConfigPathFromSysconfigRejectsDynamicOrConflictingPaths(t *testing.T) {
	for _, content := range []string{
		"SYSLOGD_OPTIONS='-f $CUSTOM_CONFIG'\n",
		"RSYSLOG_CONFIG_FILE=/etc/rsyslog.conf\nSYSLOGD_OPTIONS='-f /tmp/other.conf'\n",
	} {
		if _, complete, err := rsyslogConfigPathFromSysconfig(content); err != nil || complete {
			t.Fatalf("rsyslogConfigPathFromSysconfig(%q) = complete=%t err=%v, want incomplete", content, complete, err)
		}
	}
}

func TestStartupPermissionPolicyAllowsSetuidRootExecutable(t *testing.T) {
	assessment := inspectStartupPermissionFixture(t, 0o755|os.ModeSetuid, "user::rwx\ngroup::r-x\nother::r-x\n")
	if len(assessment.Violations) != 0 {
		t.Fatalf("violations = %#v, want none for root-owned setuid executable", assessment.Violations)
	}
}

func TestStartupPermissionPolicyRejectsGroupOrOtherWritable(t *testing.T) {
	tests := []struct {
		name          string
		mode          os.FileMode
		acl           string
		wantViolation string
	}{
		{name: "group writable", mode: 0o775, acl: "user::rwx\ngroup::rwx\nother::r-x\n", wantViolation: "허용되지 않은 권한 비트 0020"},
		{name: "other writable", mode: 0o757, acl: "user::rwx\ngroup::r-x\nother::rwx\n", wantViolation: "허용되지 않은 권한 비트 0002"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := inspectStartupPermissionFixture(t, test.mode, test.acl)
			if !slices.Contains(assessment.Violations, test.wantViolation) {
				t.Fatalf("violations = %#v, want %q", assessment.Violations, test.wantViolation)
			}
		})
	}
}

func TestStartupPermissionDetailsKeepsOneFindingPerLine(t *testing.T) {
	t.Parallel()

	findings := make([]string, 0, 22)
	for index := 1; index <= 22; index++ {
		findings = append(findings, fmt.Sprintf("unit-%02d.service: 확인 불가", index))
	}
	details := startupPermissionDetails("확인하지 못한 경로", findings, "실제 시작 경로와 권한 확인")
	if len(details) != 1 {
		t.Fatalf("details = %#v, want one grouped detail", details)
	}
	lines := strings.Split(details[0].Current, "\n")
	if len(lines) != 21 || lines[0] != findings[0] || lines[19] != findings[19] || lines[20] != "... 외 2건" {
		t.Fatalf("detail lines = %#v, want 20 findings and an omitted count", lines)
	}
}

func inspectStartupPermissionFixture(t *testing.T, mode os.FileMode, acl string) support.PermissionAssessment {
	t.Helper()
	reader := startupXAttrFixtureReader{
		Reader: startupFixtureReader{files: fstest.MapFS{
			"usr/bin/startup-tool": &fstest.MapFile{Mode: mode},
		}},
		ACLByPath: map[string][]byte{
			"/usr/bin/startup-tool": mustTestPOSIXACLXAttr(t, acl),
		},
	}
	assessment, err := support.InspectPermissions(
		context.Background(),
		reader,
		nonOwnerACLFixtureRunner{},
		"/usr/bin/startup-tool",
		startupPermissionPolicy(),
	)
	if err != nil {
		t.Fatalf("InspectPermissions() error = %v", err)
	}
	return assessment
}
