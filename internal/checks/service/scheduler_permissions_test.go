package service

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestSchedulerPermissionPolicyMatchesKISABaseline(t *testing.T) {
	command := schedulerPermissionPolicy(schedulerCommand)
	if command.AllowedMode.Perm() != 0o750 {
		t.Fatalf("command allowed mode = %04o, want 0750", command.AllowedMode.Perm())
	}
	if _, rootAllowed := command.AllowedUIDs[0]; !rootAllowed || len(command.AllowedUIDs) != 1 {
		t.Fatalf("command allowed owners = %#v, want root only", command.AllowedUIDs)
	}

	for _, class := range []schedulerObjectClass{
		schedulerConfig,
		schedulerScript,
		schedulerCronSpool,
		schedulerAtSpool,
	} {
		policy := schedulerPermissionPolicy(class)
		if policy.AllowedMode.Perm() != 0o640 {
			t.Errorf("%s allowed mode = %04o, want 0640", class, policy.AllowedMode.Perm())
		}
		if _, rootAllowed := policy.AllowedUIDs[0]; !rootAllowed || len(policy.AllowedUIDs) != 1 {
			t.Errorf("%s allowed owners = %#v, want root only", class, policy.AllowedUIDs)
		}
		if extra := os.FileMode(0o640).Perm() &^ policy.AllowedMode.Perm(); extra != 0 {
			t.Errorf("%s mode 0640 extra bits = %04o, want none", class, extra)
		}
		if extra := os.FileMode(0o644).Perm() &^ policy.AllowedMode.Perm(); extra != 0o004 {
			t.Errorf("%s mode 0644 extra bits = %04o, want 0004", class, extra)
		}
	}
}

func TestSchedulerAppendRegularObjectFindingsKeepsNonRegularConservative(t *testing.T) {
	dimension := schedulerPermissionDimension{}
	schedulerAppendRegularObjectFindings(
		&dimension,
		"/var/spool/cron/crontabs/alice",
		support.PermissionAssessment{
			Metadata:   system.FileMetadata{FileType: "symlink", Mode: 0o777, UID: 1000},
			Violations: []string{"허용되지 않은 소유자 UID 1000", "허용되지 않은 권한 비트 0137"},
		},
		false,
	)

	if len(dimension.Violations) != 0 {
		t.Fatalf("non-regular violations = %#v, want none", dimension.Violations)
	}
	if len(dimension.Unknowns) != 1 || !strings.Contains(dimension.Unknowns[0], "일반 파일이 아니어서") {
		t.Fatalf("non-regular unknowns = %#v", dimension.Unknowns)
	}
}

func TestInspectSchedulerObjectDoesNotApplyRegularPolicyToSymlink(t *testing.T) {
	reader := schedulerPermissionFixtureReader{metadata: map[string]system.FileMetadata{
		"/etc/crontab": {
			Path:       "/etc/crontab",
			FileType:   "symlink",
			Mode:       os.ModeSymlink | 0o777,
			UID:        1000,
			GID:        1000,
			LinkTarget: "/tmp/crontab",
		},
	}}
	assessment, err := inspectSchedulerObject(
		context.Background(),
		evaluator.Environment{Files: reader},
		schedulerObject{Path: "/etc/crontab", Class: schedulerConfig},
	)
	if err != nil {
		t.Fatalf("inspectSchedulerObject() error = %v", err)
	}
	if !assessment.Exists || assessment.Metadata.FileType != "symlink" || len(assessment.Violations) != 0 {
		t.Fatalf("symlink assessment = %#v, want conservative non-regular evidence", assessment)
	}
}

func TestSchedulerCommandModeFindingsSeparatesSUIDAndSGID(t *testing.T) {
	violations, unknowns := schedulerCommandModeFindings(
		"/usr/bin/crontab",
		0o750|os.ModeSetuid|os.ModeSetgid,
	)
	if !schedulerFindingContains(violations, "SUID 비트가 설정됨") {
		t.Fatalf("violations = %#v, want SUID violation", violations)
	}
	if !schedulerFindingContains(unknowns, "SGID 비트의 배포판 패키지 의미") {
		t.Fatalf("unknowns = %#v, want SGID uncertainty", unknowns)
	}
}

func TestSchedulerCompoundOutcome(t *testing.T) {
	tests := map[string]struct {
		command     schedulerPermissionDimension
		files       schedulerPermissionDimension
		wantStatus  model.Status
		wantReason  model.UnknownReason
		wantSummary string
	}{
		"both complete unsafe": {
			command:     schedulerPermissionDimension{Violations: []string{"명령 위반"}},
			files:       schedulerPermissionDimension{Violations: []string{"파일 위반"}},
			wantStatus:  model.StatusFail,
			wantSummary: "모두 취약 기준",
		},
		"command only unsafe": {
			command:     schedulerPermissionDimension{Violations: []string{"명령 위반"}},
			files:       schedulerPermissionDimension{},
			wantStatus:  model.StatusUnknown,
			wantReason:  model.UnknownAmbiguousResult,
			wantSummary: "한 차원에서만",
		},
		"files only unsafe": {
			command:     schedulerPermissionDimension{},
			files:       schedulerPermissionDimension{Violations: []string{"파일 위반"}},
			wantStatus:  model.StatusUnknown,
			wantReason:  model.UnknownAmbiguousResult,
			wantSummary: "한 차원에서만",
		},
		"both complete safe": {
			command:     schedulerPermissionDimension{},
			files:       schedulerPermissionDimension{},
			wantStatus:  model.StatusPass,
			wantSummary: "모두 권한 기준을 충족",
		},
		"command uncertainty does not hide both violations": {
			command: schedulerPermissionDimension{
				Violations: []string{"명령 위반"},
				Unknowns:   []string{"명령 미확정"},
			},
			files:       schedulerPermissionDimension{Violations: []string{"파일 위반"}},
			wantStatus:  model.StatusFail,
			wantSummary: "모두 취약 기준",
		},
		"file uncertainty does not hide both violations": {
			command: schedulerPermissionDimension{Violations: []string{"명령 위반"}},
			files: schedulerPermissionDimension{
				Violations: []string{"파일 위반"},
				Unknowns:   []string{"파일 미확정"},
			},
			wantStatus:  model.StatusFail,
			wantSummary: "모두 취약 기준",
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			outcome := schedulerPermissionOutcome(
				model.ResolvedRule{},
				2,
				nil,
				testCase.command,
				testCase.files,
			)
			if outcome.Status != testCase.wantStatus {
				t.Fatalf("status = %s, want %s", outcome.Status, testCase.wantStatus)
			}
			if outcome.UnknownReason != testCase.wantReason {
				t.Fatalf("unknown reason = %s, want %s", outcome.UnknownReason, testCase.wantReason)
			}
			if !strings.Contains(outcome.Summary, testCase.wantSummary) {
				t.Fatalf("summary = %q, want text %q", outcome.Summary, testCase.wantSummary)
			}
		})
	}
}

func TestSchedulerSingleDimensionViolationIsNotFailure(t *testing.T) {
	for name, dimensions := range map[string][2]schedulerPermissionDimension{
		"command": {
			{Violations: []string{"명령 위반"}},
			{},
		},
		"related files": {
			{},
			{Violations: []string{"파일 위반"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			outcome := schedulerPermissionOutcome(model.ResolvedRule{}, 1, nil, dimensions[0], dimensions[1])
			if outcome.Status == model.StatusFail {
				t.Fatalf("single-dimension violation returned FAIL: %#v", outcome)
			}
		})
	}
}

func TestEvaluateSchedulerPermissionsRequiresBothUnsafeDimensions(t *testing.T) {
	reader := schedulerPermissionFixtureReader{metadata: map[string]system.FileMetadata{
		"/usr/bin/crontab": {
			Path:     "/usr/bin/crontab",
			FileType: "regular",
			Mode:     0o755,
			UID:      0,
			GID:      0,
		},
		"/etc/crontab": {
			Path:     "/etc/crontab",
			FileType: "regular",
			Mode:     0o644,
			UID:      0,
			GID:      0,
		},
	}}
	outcome := evaluateSchedulerPermissions(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{Files: reader, Commands: schedulerRPMUnavailableRunner{}},
	)
	if outcome.Status != model.StatusFail {
		t.Fatalf("both unsafe dimensions status = %s, want FAIL", outcome.Status)
	}

	safeFile := reader
	safeFile.metadata = make(map[string]system.FileMetadata, len(reader.metadata))
	for name, metadata := range reader.metadata {
		safeFile.metadata[name] = metadata
	}
	metadata := safeFile.metadata["/etc/crontab"]
	metadata.Mode = 0o640
	safeFile.metadata["/etc/crontab"] = metadata
	outcome = evaluateSchedulerPermissions(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{Files: safeFile, Commands: schedulerRPMUnavailableRunner{}},
	)
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("single unsafe dimension outcome = %s, %s, want UNKNOWN ambiguous_result", outcome.Status, outcome.UnknownReason)
	}

	safeBoth := safeFile
	safeBoth.metadata = make(map[string]system.FileMetadata, len(safeFile.metadata))
	for name, metadata := range safeFile.metadata {
		safeBoth.metadata[name] = metadata
	}
	metadata = safeBoth.metadata["/usr/bin/crontab"]
	metadata.Mode = 0o750
	safeBoth.metadata["/usr/bin/crontab"] = metadata
	outcome = evaluateSchedulerPermissions(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{Files: safeBoth, Commands: schedulerRPMUnavailableRunner{}},
	)
	if outcome.Status != model.StatusPass {
		t.Fatalf("both safe dimensions status = %s, want PASS", outcome.Status)
	}
}

func TestEvaluateSchedulerPermissionsRequiresRootOwnedCronAndAtJobs(t *testing.T) {
	for name, testCase := range map[string]struct {
		directory string
		job       string
		class     schedulerObjectClass
	}{
		"crontab": {
			directory: "/var/spool/cron/crontabs",
			job:       "/var/spool/cron/crontabs/alice",
			class:     schedulerCronSpool,
		},
		"atjob": {
			directory: "/var/spool/cron/atjobs",
			job:       "/var/spool/cron/atjobs/a000010",
			class:     schedulerAtSpool,
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader := schedulerPermissionFixtureReader{
				metadata: map[string]system.FileMetadata{
					"/usr/bin/crontab": {
						Path:     "/usr/bin/crontab",
						FileType: "regular",
						Mode:     0o755,
						UID:      0,
						GID:      0,
					},
					testCase.directory: {
						Path:     testCase.directory,
						FileType: "directory",
						Mode:     os.ModeDir | 0o700,
						UID:      0,
						GID:      0,
					},
					testCase.job: {
						Path:     testCase.job,
						FileType: "regular",
						Mode:     0o600,
						UID:      1000,
						GID:      1000,
					},
				},
				directories: map[string][]os.DirEntry{
					testCase.directory: {
						schedulerFixtureDirEntry{name: path.Base(testCase.job)},
					},
				},
			}
			outcome := evaluateSchedulerPermissions(
				context.Background(),
				model.ResolvedRule{},
				evaluator.Environment{Files: reader, Commands: schedulerRPMUnavailableRunner{}},
			)
			if outcome.Status != model.StatusFail {
				t.Fatalf("account-owned %s status = %s, want FAIL with unsafe command dimension", testCase.class, outcome.Status)
			}
			violations := schedulerDetailByLabel(outcome.Details, "확인된 위반")
			if !strings.Contains(violations, testCase.job+": 허용되지 않은 소유자 UID 1000") {
				t.Fatalf("violations = %q, want root-owner violation for %s", violations, testCase.job)
			}
		})
	}
}

func TestSchedulerPermissionDetailsLimitEachCategory(t *testing.T) {
	violations := make([]string, 22)
	unknowns := make([]string, 21)
	for index := range violations {
		violations[index] = "위반"
	}
	for index := range unknowns {
		unknowns[index] = "추가 확인"
	}

	details := schedulerPermissionDetails(violations, unknowns, "기준")

	if len(details) != 2 {
		t.Fatalf("details = %#v, want two categories", details)
	}
	if strings.Count(details[0].Current, "\n") != 20 || !strings.HasSuffix(details[0].Current, "... 외 2건") {
		t.Errorf("violation detail = %q, want 20 samples and omitted count", details[0].Current)
	}
	if strings.Count(details[1].Current, "\n") != 20 || !strings.HasSuffix(details[1].Current, "... 외 1건") {
		t.Errorf("uncertainty detail = %q, want 20 samples and omitted count", details[1].Current)
	}
}

func TestSchedulerObjectsInventoryOfficialSpoolDirectoriesOneLevel(t *testing.T) {
	reader := schedulerPermissionFixtureReader{
		metadata: map[string]system.FileMetadata{
			"/var/spool/cron":                 {Path: "/var/spool/cron", FileType: "directory", Mode: os.ModeDir | 0o755},
			"/var/spool/cron/crontabs":        {Path: "/var/spool/cron/crontabs", FileType: "directory", Mode: os.ModeDir | 0o730},
			"/var/spool/cron/crontabs/alice":  {Path: "/var/spool/cron/crontabs/alice", FileType: "regular", Mode: 0o600},
			"/var/spool/cron/crontabs/nested": {Path: "/var/spool/cron/crontabs/nested", FileType: "directory", Mode: os.ModeDir | 0o700},
			"/var/spool/cron/atjobs":          {Path: "/var/spool/cron/atjobs", FileType: "directory", Mode: os.ModeDir | 0o700},
			"/var/spool/cron/atjobs/a000010":  {Path: "/var/spool/cron/atjobs/a000010", FileType: "regular", Mode: 0o600},
		},
		directories: map[string][]os.DirEntry{
			"/var/spool/cron": {
				schedulerFixtureDirEntry{name: "crontabs", directory: true},
				schedulerFixtureDirEntry{name: "atjobs", directory: true},
			},
			"/var/spool/cron/crontabs": {
				schedulerFixtureDirEntry{name: "alice"},
				schedulerFixtureDirEntry{name: "nested", directory: true},
				schedulerFixtureDirEntry{name: "../escape"},
			},
			"/var/spool/cron/atjobs": {
				schedulerFixtureDirEntry{name: "a000010"},
			},
		},
	}

	objects, _, err := schedulerObjects(evaluator.Environment{Files: reader})
	if err != nil {
		t.Fatalf("schedulerObjects() error = %v", err)
	}
	classes := make(map[string]schedulerObjectClass, len(objects))
	for _, object := range objects {
		classes[object.Path] = object.Class
	}
	if classes["/var/spool/cron/crontabs/alice"] != schedulerCronSpool {
		t.Errorf("crontab class = %q, want %q", classes["/var/spool/cron/crontabs/alice"], schedulerCronSpool)
	}
	if classes["/var/spool/cron/atjobs/a000010"] != schedulerAtSpool {
		t.Errorf("atjob class = %q, want %q", classes["/var/spool/cron/atjobs/a000010"], schedulerAtSpool)
	}
	for _, directory := range []string{"/var/spool/cron/crontabs", "/var/spool/cron/atjobs"} {
		if classes[directory] != schedulerSpoolDir {
			t.Errorf("%s class = %q, want container class %q", directory, classes[directory], schedulerSpoolDir)
		}
	}
	if _, escaped := classes["/var/spool/cron/escape"]; escaped {
		t.Error("unsafe entry name escaped its inventory directory")
	}
	if _, recursed := classes["/var/spool/cron/crontabs/nested/deeper"]; recursed {
		t.Error("scheduler spool inventory recursed beyond one level")
	}
}

func TestInspectSchedulerPackagesSeparatesUnavailableQueryFromVerifyDifference(t *testing.T) {
	unavailable, err := inspectSchedulerPackages(
		context.Background(),
		evaluator.Environment{Commands: schedulerRPMUnavailableRunner{}},
	)
	if err != nil {
		t.Fatalf("unavailable inspection error = %v", err)
	}
	if !unavailable.QueryUnavailable || unavailable.VerifyDifference {
		t.Fatalf("unavailable inspection = %#v", unavailable)
	}

	difference, err := inspectSchedulerPackages(
		context.Background(),
		evaluator.Environment{Commands: schedulerRPMDifferenceRunner{}},
	)
	if err != nil {
		t.Fatalf("difference inspection error = %v", err)
	}
	if difference.QueryUnavailable || !difference.VerifyDifference {
		t.Fatalf("difference inspection = %#v", difference)
	}

	dpkg, err := inspectSchedulerPackages(
		context.Background(),
		evaluator.Environment{
			Commands: schedulerDPKGRunner{},
			Platform: model.PlatformInfo{Family: "debian", PackageManager: "apt"},
		},
	)
	if err != nil {
		t.Fatalf("DPKG inspection error = %v", err)
	}
	if dpkg.QueryUnavailable || dpkg.VerifyDifference ||
		!dpkg.Installed["cron"] || !dpkg.Installed["at"] {
		t.Fatalf("DPKG inspection = %#v", dpkg)
	}
}

func TestEvaluateSchedulerPermissionsUsesBackendNeutralUnavailableMessage(t *testing.T) {
	tests := map[string]map[string]system.FileMetadata{
		"no scheduler paths": {},
		"command only": {
			"/usr/bin/crontab": {
				Path:     "/usr/bin/crontab",
				FileType: "regular",
				Mode:     0o750,
				UID:      0,
				GID:      0,
			},
		},
		"related file only": {
			"/etc/crontab": {
				Path:     "/etc/crontab",
				FileType: "regular",
				Mode:     0o640,
				UID:      0,
				GID:      0,
			},
		},
	}

	for name, metadata := range tests {
		t.Run(name, func(t *testing.T) {
			outcome := evaluateSchedulerPermissions(
				context.Background(),
				model.ResolvedRule{},
				evaluator.Environment{
					Files:    schedulerPermissionFixtureReader{metadata: metadata},
					Commands: schedulerRPMUnavailableRunner{},
					Platform: model.PlatformInfo{Family: "debian", PackageManager: "apt"},
				},
			)
			if outcome.Status != model.StatusUnknown {
				t.Fatalf("status = %s, want UNKNOWN", outcome.Status)
			}
			resultText := outcome.Observed
			for _, detail := range outcome.Details {
				resultText += "\n" + detail.Current
			}
			if strings.Contains(resultText, "RPM") || strings.Contains(resultText, "DPKG") {
				t.Fatalf("backend-specific unavailable message = %q", resultText)
			}
			if !strings.Contains(resultText, "패키지 조회") {
				t.Fatalf("unavailable message = %q, want backend-neutral package query text", resultText)
			}
		})
	}
}

func schedulerFindingContains(findings []string, expected string) bool {
	for _, finding := range findings {
		if strings.Contains(finding, expected) {
			return true
		}
	}
	return false
}

func schedulerDetailByLabel(details []model.ResultDetail, label string) string {
	for _, detail := range details {
		if detail.Label == label {
			return detail.Current
		}
	}
	return ""
}

type schedulerPermissionFixtureReader struct {
	metadata    map[string]system.FileMetadata
	directories map[string][]os.DirEntry
}

func (schedulerPermissionFixtureReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, fs.ErrNotExist
}

func (r schedulerPermissionFixtureReader) Stat(name string) (system.FileMetadata, error) {
	return r.Lstat(name)
}

func (r schedulerPermissionFixtureReader) Lstat(name string) (system.FileMetadata, error) {
	metadata, exists := r.metadata[name]
	if !exists {
		return system.FileMetadata{}, fs.ErrNotExist
	}
	return metadata, nil
}

func (r schedulerPermissionFixtureReader) ReadDir(name string) ([]os.DirEntry, error) {
	entries, exists := r.directories[name]
	if !exists {
		return nil, fs.ErrNotExist
	}
	return entries, nil
}

func (r schedulerPermissionFixtureReader) Exists(name string) (bool, error) {
	_, exists := r.metadata[name]
	return exists, nil
}

func (r schedulerPermissionFixtureReader) ReadXAttrs(
	_ context.Context,
	name string,
	_ []string,
	_ int64,
	_ bool,
) (map[string][]byte, system.FileMetadata, error) {
	metadata, err := r.Lstat(name)
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	return map[string][]byte{}, metadata, nil
}

type schedulerFixtureDirEntry struct {
	name      string
	directory bool
}

func (entry schedulerFixtureDirEntry) Name() string { return entry.name }
func (entry schedulerFixtureDirEntry) IsDir() bool  { return entry.directory }
func (entry schedulerFixtureDirEntry) Type() os.FileMode {
	if entry.directory {
		return os.ModeDir
	}
	return 0
}
func (schedulerFixtureDirEntry) Info() (os.FileInfo, error) {
	return nil, errors.New("fixture Info must not be called")
}

type schedulerRPMUnavailableRunner struct{}

func (schedulerRPMUnavailableRunner) Run(context.Context, executor.Spec) (executor.Result, error) {
	return executor.Result{}, errors.New("unexpected command")
}

func (schedulerRPMUnavailableRunner) Available(string) bool { return false }

type schedulerRPMDifferenceRunner struct{}

func (schedulerRPMDifferenceRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "rpm" || len(spec.Arguments) < 2 {
		return executor.Result{}, errors.New("unexpected command")
	}
	switch spec.Arguments[0] {
	case "-q":
		packageName := spec.Arguments[len(spec.Arguments)-1]
		if packageName == "cronie" {
			return executor.Result{ExitCode: 0, Stdout: []byte("cronie\t0:1.0-1.x86_64\n")}, nil
		}
		return executor.Result{ExitCode: 1}, nil
	case "-V":
		return executor.Result{ExitCode: 1, Stdout: []byte(".......T. /etc/crontab\n")}, nil
	default:
		return executor.Result{}, errors.New("unexpected rpm operation")
	}
}

func (schedulerRPMDifferenceRunner) Available(name string) bool { return name == "rpm" }

type schedulerDPKGRunner struct{}

func (schedulerDPKGRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "dpkg-query" {
		return executor.Result{}, errors.New("unexpected command")
	}
	return executor.Result{ExitCode: 0, Stdout: []byte(
		"at\t3.2.5-2\tamd64\tii \n" +
			"cron\t3.0pl1-184\tamd64\tii \n",
	)}, nil
}

func (schedulerDPKGRunner) Available(name string) bool { return name == "dpkg-query" }
