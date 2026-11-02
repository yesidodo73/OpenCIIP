package logging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestParseChronySourcesCSVPreservesOriginalRuntimeNames(t *testing.T) {
	data := []byte("^,-,2.rocky.pool.ntp.org,2,9,377,685,-0.1,-0.1,0.2\n" +
		"^,*,approved.example,2,7,377,12,0.0,0.0,0.1\n")
	sources, selected, err := parseChronySourcesCSV(data)
	if err != nil {
		t.Fatalf("parseChronySourcesCSV() error = %v", err)
	}
	if !slices.Equal(sources, []string{"2.rocky.pool.ntp.org", "approved.example"}) || !slices.Equal(selected, []string{"approved.example"}) {
		t.Fatalf("parseChronySourcesCSV() = %#v, %#v", sources, selected)
	}
}

type chronyDirectoryReader struct {
	entries map[string][]os.DirEntry
}

func (reader chronyDirectoryReader) ReadDir(name string) ([]os.DirEntry, error) {
	entries, ok := reader.entries[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func (chronyDirectoryReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("unexpected ReadFile")
}
func (chronyDirectoryReader) Stat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Stat")
}
func (chronyDirectoryReader) Lstat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Lstat")
}
func (chronyDirectoryReader) Exists(string) (bool, error) {
	return false, errors.New("unexpected Exists")
}

func TestInspectChronyIncludeDirectoryResolvesEmptyOrMissingDirectory(t *testing.T) {
	reader := chronyDirectoryReader{entries: map[string][]os.DirEntry{"/run/chrony-dhcp": {}}}
	for _, directory := range []string{"/run/chrony-dhcp", "/run/missing"} {
		count, unresolved, err := inspectChronyIncludeDirectory(evaluatorEnvironment(reader), directory, ".sources")
		if err != nil || count != 0 || unresolved {
			t.Fatalf("inspectChronyIncludeDirectory(%q) = %d, %t, %v, want resolved empty", directory, count, unresolved, err)
		}
	}
}

func evaluatorEnvironment(reader system.Reader) evaluator.Environment {
	return evaluator.Environment{Files: reader}
}

func TestParseChronySourcesCSVRejectsMalformedRows(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("^,*\n"),
		[]byte("?,*,source.example\n"),
		[]byte("^,**,source.example\n"),
	} {
		if _, _, err := parseChronySourcesCSV(data); err == nil {
			t.Fatalf("parseChronySourcesCSV(%q) accepted malformed data", data)
		}
	}
}

func TestChronyDynamicIncludeObservationShowsEffectiveSources(t *testing.T) {
	t.Parallel()

	got := chronyDynamicIncludeObservation(
		nil,
		[]string{"ntp.ubuntu.com", "time.example"},
		[]string{"ntp.ubuntu.com"},
	)
	want := "동적 include: 있음\n" +
		"정적으로 확인한 시간원: 없음\n" +
		"runtime 시간원: ntp.ubuntu.com, time.example\n" +
		"선택 시간원: ntp.ubuntu.com"
	if got != want {
		t.Fatalf("chronyDynamicIncludeObservation() = %q, want %q", got, want)
	}
}

func TestEvaluateTimeSyncDoesNotChooseOneOfTwoActiveManagers(t *testing.T) {
	t.Parallel()

	outcome := evaluateTimeSync(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{
			Commands: timeSyncUnitFixtureRunner{},
			Platform: model.PlatformInfo{InitSystem: "systemd"},
		},
	)
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("outcome = %#v, want UNKNOWN ambiguous result", outcome)
	}
	inspected := make(map[string]bool)
	for _, evidence := range outcome.Evidence {
		if evidence.Command == nil || evidence.Command.Executable != "systemctl" ||
			len(evidence.Command.Arguments) == 0 {
			continue
		}
		inspected[evidence.Command.Arguments[len(evidence.Command.Arguments)-1]] = true
	}
	for _, unit := range []string{"chronyd.service", "ntp.service", "systemd-timesyncd.service"} {
		if !inspected[unit] {
			t.Fatalf("outcome evidence does not include %s: %#v", unit, outcome.Evidence)
		}
	}
}

type timeSyncUnitFixtureRunner struct{}

func (timeSyncUnitFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "systemctl" || len(spec.Arguments) == 0 {
		return executor.Result{}, fmt.Errorf("unexpected command: %s %s", spec.Name, strings.Join(spec.Arguments, " "))
	}
	unit := spec.Arguments[len(spec.Arguments)-1]
	switch unit {
	case "chronyd.service", "systemd-timesyncd.service":
	case "ntp.service":
		return executor.Result{
			Executable: spec.Name,
			Arguments:  append([]string(nil), spec.Arguments...),
			ExitCode:   0,
			Stdout: []byte(
				"Id=ntp.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nFragmentPath=\nDropInPaths=\n",
			),
		}, nil
	default:
		return executor.Result{}, fmt.Errorf("unexpected systemd unit: %s", unit)
	}
	return executor.Result{
		Executable: spec.Name,
		Arguments:  append([]string(nil), spec.Arguments...),
		ExitCode:   0,
		Stdout: []byte(fmt.Sprintf(
			"Id=%s\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nFragmentPath=/usr/lib/systemd/system/%s\nDropInPaths=\n",
			unit,
			unit,
		)),
	}, nil
}

func (timeSyncUnitFixtureRunner) Available(name string) bool {
	return name == "systemctl"
}

func TestEvaluateSystemdTimesyncdSupportsOldAndCurrentTimedatectl(t *testing.T) {
	t.Parallel()

	unit := support.UnitState{
		Name: "systemd-timesyncd.service", LoadState: "loaded",
		ActiveState: "active", UnitFileState: "enabled",
	}
	tests := []struct {
		name       string
		rule       model.ResolvedRule
		runner     timesyncdFixtureRunner
		wantStatus model.Status
		wantReason model.UnknownReason
	}{
		{
			name: "systemd 237 without show-timesync remains a manual verification",
			runner: timesyncdFixtureRunner{
				status: executor.Result{ExitCode: 0, Stdout: []byte(
					"System clock synchronized: yes\nsystemd-timesyncd.service active: yes\n",
				)},
				show: executor.Result{ExitCode: 1, Stderr: []byte("timedatectl: unrecognized option '--all'\n")},
			},
			wantStatus: model.StatusUnknown,
			wantReason: model.UnknownInsufficientEvidence,
		},
		{
			name: "current systemd validates the effective approved source",
			rule: model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{
				"approved_sources": []string{"ntp.ubuntu.com"},
			}}},
			runner: timesyncdFixtureRunner{
				status: executor.Result{ExitCode: 0, Stdout: []byte(
					"System clock synchronized: yes\nNTP service: active\n",
				)},
				show: executor.Result{ExitCode: 0, Stdout: []byte(
					"LinkNTPServers=\nSystemNTPServers=\nRuntimeNTPServers=\n" +
						"FallbackNTPServers=ntp.ubuntu.com\nServerName=ntp.ubuntu.com\n",
				)},
			},
			wantStatus: model.StatusPass,
		},
		{
			name: "active tier sources take precedence over fallback sources",
			rule: model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{
				"approved_sources": []string{"approved.example"},
			}}},
			runner: timesyncdFixtureRunner{
				status: executor.Result{ExitCode: 0, Stdout: []byte(
					"System clock synchronized: yes\nNTP service: active\n",
				)},
				show: executor.Result{ExitCode: 0, Stdout: []byte(
					"LinkNTPServers=\nSystemNTPServers=approved.example\nRuntimeNTPServers=\n" +
						"FallbackNTPServers=unused.example\nServerName=approved.example\n",
				)},
			},
			wantStatus: model.StatusPass,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outcome := evaluateSystemdTimesyncd(
				context.Background(),
				test.rule,
				evaluator.Environment{Commands: test.runner},
				unit,
				nil,
			)
			if outcome.Status != test.wantStatus || outcome.UnknownReason != test.wantReason {
				t.Fatalf("outcome = %#v, want status=%s reason=%s", outcome, test.wantStatus, test.wantReason)
			}
			if len(outcome.Evidence) == 0 {
				t.Fatal("timesyncd outcome returned no evidence")
			}
		})
	}
}

type timesyncdFixtureRunner struct {
	status executor.Result
	show   executor.Result
}

func (r timesyncdFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	var result executor.Result
	switch strings.Join(spec.Arguments, " ") {
	case "status":
		result = r.status
	case "show-timesync --all":
		result = r.show
	default:
		return executor.Result{}, fmt.Errorf("unexpected command: %s %s", spec.Name, strings.Join(spec.Arguments, " "))
	}
	result.Executable = spec.Name
	result.Arguments = append([]string(nil), spec.Arguments...)
	return result, nil
}

func (timesyncdFixtureRunner) Available(name string) bool {
	return name == "timedatectl"
}

func TestParseTimedatectlStatusIgnoresRTCLocalTimeWarning(t *testing.T) {
	t.Parallel()

	values, err := parseTimedatectlStatus([]byte(
		"               Local time: Wed 2026-07-29 21:00:00 KST\n" +
			"System clock synchronized: yes\n" +
			"              NTP service: active\n" +
			"          RTC in local TZ: yes\n\n" +
			"Warning: The system is configured to read the RTC time in the local time zone.\n" +
			"         This mode cannot be fully supported. It will create various problems\n" +
			"         with time zone changes and daylight saving time adjustments.\n",
	))
	if err != nil {
		t.Fatalf("parseTimedatectlStatus() error = %v", err)
	}
	if !slices.Equal([]string{values["system clock synchronized"]}, []string{"yes"}) || len(values) != 1 {
		t.Fatalf("parseTimedatectlStatus() = %#v, want only synchronized=yes", values)
	}
}

func TestEvaluateSystemdTimesyncdPreservesEvidenceOnParseError(t *testing.T) {
	t.Parallel()

	unit := support.UnitState{
		Name: "systemd-timesyncd.service", LoadState: "loaded",
		ActiveState: "active", UnitFileState: "enabled",
	}
	seed := support.FactEvidence("time sync unit inventory", map[string]any{"complete": true})
	tests := []struct {
		name         string
		runner       timesyncdFixtureRunner
		wantCode     string
		wantEvidence int
	}{
		{
			name: "status parse error",
			runner: timesyncdFixtureRunner{
				status: executor.Result{ExitCode: 0, Stdout: []byte(
					"System clock synchronized: yes\nSystem clock synchronized: yes\n",
				)},
			},
			wantCode:     "timedatectl_status_parse_failed",
			wantEvidence: 2,
		},
		{
			name: "timesync property parse error",
			runner: timesyncdFixtureRunner{
				status: executor.Result{ExitCode: 0, Stdout: []byte("System clock synchronized: yes\n")},
				show:   executor.Result{ExitCode: 0, Stdout: []byte("not-a-property\n")},
			},
			wantCode:     "timedatectl_timesync_parse_failed",
			wantEvidence: 3,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outcome := evaluateSystemdTimesyncd(
				context.Background(),
				model.ResolvedRule{},
				evaluator.Environment{Commands: test.runner},
				unit,
				[]model.Evidence{seed},
			)
			if outcome.Status != model.StatusError || outcome.ErrorCode != test.wantCode {
				t.Fatalf("outcome = %#v, want ERROR %s", outcome, test.wantCode)
			}
			if len(outcome.Evidence) != test.wantEvidence || outcome.Evidence[0].Source != seed.Source {
				t.Fatalf("outcome evidence = %#v, want %d entries preserving seed", outcome.Evidence, test.wantEvidence)
			}
		})
	}
}

type chronyConfigReader struct {
	files map[string][]byte
	reads []string
}

func (reader *chronyConfigReader) ReadFile(_ context.Context, name string, _ int64) ([]byte, system.FileMetadata, error) {
	reader.reads = append(reader.reads, name)
	data, exists := reader.files[name]
	if !exists {
		return nil, system.FileMetadata{}, os.ErrNotExist
	}
	return append([]byte(nil), data...), system.FileMetadata{Path: name}, nil
}

func (*chronyConfigReader) Stat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Stat")
}

func (*chronyConfigReader) Lstat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Lstat")
}

func (*chronyConfigReader) ReadDir(string) ([]os.DirEntry, error) {
	return nil, errors.New("unexpected ReadDir")
}

func (*chronyConfigReader) Exists(string) (bool, error) {
	return false, errors.New("unexpected Exists")
}

func TestReadChronySourcesUsesPlatformConfigurationPath(t *testing.T) {
	tests := []struct {
		name       string
		family     string
		path       string
		wantSource string
	}{
		{
			name:       "Debian family",
			family:     "debian",
			path:       "/etc/chrony/chrony.conf",
			wantSource: "ntp.ubuntu.com",
		},
		{
			name:       "RHEL family",
			family:     "rhel",
			path:       "/etc/chrony.conf",
			wantSource: "2.rocky.pool.ntp.org",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &chronyConfigReader{files: map[string][]byte{
				"/etc/chrony/chrony.conf": []byte("pool ntp.ubuntu.com iburst\n"),
				"/etc/chrony.conf":        []byte("pool 2.rocky.pool.ntp.org iburst\n"),
			}}
			sources, dynamic, evidence, err := readChronySources(context.Background(), evaluator.Environment{
				Files:    reader,
				Platform: model.PlatformInfo{Family: test.family},
			})
			if err != nil {
				t.Fatalf("readChronySources() error = %v", err)
			}
			if dynamic || !slices.Equal(sources, []string{test.wantSource}) {
				t.Fatalf("readChronySources() = %#v, %t", sources, dynamic)
			}
			if !slices.Equal(reader.reads, []string{test.path}) {
				t.Fatalf("configuration reads = %#v, want %q", reader.reads, test.path)
			}
			if evidence.Source != test.path {
				t.Fatalf("evidence source = %q, want %q", evidence.Source, test.path)
			}
		})
	}
}
