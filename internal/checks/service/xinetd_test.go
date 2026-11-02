package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type inactiveServiceRunner struct{}

func (inactiveServiceRunner) Available(string) bool { return true }

func (inactiveServiceRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	result := executor.Result{Executable: "/usr/bin/" + spec.Name, Arguments: append([]string(nil), spec.Arguments...)}
	switch spec.Name {
	case "systemctl":
		if len(spec.Arguments) == 0 {
			return executor.Result{}, errorsUnexpectedCommand(spec)
		}
		switch spec.Arguments[0] {
		case "show":
			name := spec.Arguments[len(spec.Arguments)-1]
			result.Stdout = []byte(fmt.Sprintf("Id=%s\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nFragmentPath=\nDropInPaths=\n", name))
			return result, nil
		case "list-unit-files":
			result.ExitCode = 1
			return result, nil
		}
	case "ss", "ps":
		return result, nil
	}
	return executor.Result{}, errorsUnexpectedCommand(spec)
}

func errorsUnexpectedCommand(spec executor.Spec) error {
	return fmt.Errorf("unexpected command: %s %q", spec.Name, spec.Arguments)
}

func TestDisabledEvaluatorsDetectEnabledXinetdServicesFromArbitraryFileNames(t *testing.T) {
	tests := []struct {
		name      string
		evaluator string
		service   string
	}{
		{name: "U-34 finger", evaluator: EvaluatorFingerDisabled, service: "finger"},
		{name: "U-36 r commands", evaluator: EvaluatorRCommandsDisabled, service: "shell"},
		{name: "U-38 dos prone", evaluator: EvaluatorDoSProneDisabled, service: "echo"},
		{name: "U-44 tftp and talk", evaluator: EvaluatorLegacyDatagramDisabled, service: "tftp"},
		{name: "U-52 telnet", evaluator: EvaluatorTelnetDisabled, service: "telnet"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := xinetdFixture(t, map[string]string{
				"/etc/xinetd.conf":             "defaults {\n disable = yes\n}\nincludedir /etc/xinetd.d\n",
				"/etc/xinetd.d/arbitrary-name": fmt.Sprintf("service %s {\n disable = no\n}\n", test.service),
			})
			implementation := Implementations()[test.evaluator]
			outcome := implementation(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: inactiveServiceRunner{}, Platform: model.PlatformInfo{InitSystem: "systemd"},
			})
			wantStatus := model.StatusFail
			if test.evaluator == EvaluatorRCommandsDisabled {
				wantStatus = model.StatusUnknown
			}
			if outcome.Status != wantStatus {
				t.Fatalf("outcome status = %s, want %s; outcome=%#v", outcome.Status, wantStatus, outcome)
			}
			if !strings.Contains(outcome.Observed, "xinetd target service enabled (1)") {
				t.Fatalf("observed = %q, want enabled xinetd signal", outcome.Observed)
			}
			encoded, err := json.Marshal(outcome.Evidence)
			if err != nil {
				t.Fatalf("json.Marshal(evidence) error = %v", err)
			}
			for _, secret := range []string{"/etc/xinetd", "arbitrary-name", "disable = no"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("evidence contains unredacted configuration detail %q: %s", secret, encoded)
				}
			}
		})
	}
}

func TestInspectXinetdServicesAppliesDefaultsAndServiceOverrides(t *testing.T) {
	tests := []struct {
		name          string
		configuration string
		wantEnabled   int
		wantDisabled  int
	}{
		{
			name:          "default disable inherited",
			configuration: "defaults { disable = yes }\nservice finger { socket_type = stream }\n",
			wantDisabled:  1,
		},
		{
			name:          "service override enables",
			configuration: "defaults { disable = yes }\nservice finger { disable = no }\n",
			wantEnabled:   1,
		},
		{
			name:          "service override disables",
			configuration: "defaults { disable = no }\nservice finger { disable = yes }\n",
			wantDisabled:  1,
		},
		{
			name:          "disabled id control wins",
			configuration: "defaults { disabled = finger }\nservice finger { disable = no }\n",
			wantDisabled:  1,
		},
		{
			name:          "enabled allowlist omits id",
			configuration: "defaults { enabled = telnet }\nservice finger { disable = no }\n",
			wantDisabled:  1,
		},
		{
			name:          "disable flag wins",
			configuration: "service finger { disable = no\n flags = DISABLE }\n",
			wantDisabled:  1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := xinetdFixture(t, map[string]string{"/etc/xinetd.conf": test.configuration})
			inspection, err := inspectXinetdServices(context.Background(), evaluator.Environment{Files: reader}, []string{"finger"})
			if err != nil {
				t.Fatalf("inspectXinetdServices() error = %v", err)
			}
			if !inspection.Complete || inspection.Configured != 1 || inspection.Enabled != test.wantEnabled || inspection.Disabled != test.wantDisabled {
				t.Fatalf("inspection = %#v", inspection)
			}
		})
	}
}

func TestInspectXinetdServicesFollowsNestedIncludeAndIncludedir(t *testing.T) {
	reader := xinetdFixture(t, map[string]string{
		"/etc/xinetd.conf":             "include /etc/xinetd-extra\n",
		"/etc/xinetd-extra":            "includedir /etc/xinetd.d\n",
		"/etc/xinetd.d/active":         "service telnet { disable = no }\n",
		"/etc/xinetd.d/ignored.backup": "service telnet { disable = yes }\n",
		"/etc/xinetd.d/ignored~":       "service telnet { disable = yes }\n",
	})
	inspection, err := inspectXinetdServices(context.Background(), evaluator.Environment{Files: reader}, []string{"telnet"})
	if err != nil {
		t.Fatalf("inspectXinetdServices() error = %v", err)
	}
	if !inspection.Complete || inspection.Configured != 1 || inspection.Enabled != 1 {
		t.Fatalf("inspection = %#v", inspection)
	}
	if count, ok := inspection.Evidence.Fact["configuration_file_count"].(int); !ok || count != 3 {
		t.Fatalf("configuration_file_count = %#v, want 3", inspection.Evidence.Fact["configuration_file_count"])
	}
}

func TestInspectXinetdServicesLimitsAmbiguousControlToUnknown(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "duplicate service id",
			files: map[string]string{
				"/etc/xinetd.conf": "includedir /etc/xinetd.d\n",
				"/etc/xinetd.d/a":  "service finger { id = finger-stream\n disable = yes }\n",
				"/etc/xinetd.d/b":  "service finger { id = finger-stream\n disable = no }\n",
			},
		},
		{
			name: "relative include",
			files: map[string]string{
				"/etc/xinetd.conf": "include xinetd-extra\n",
			},
		},
		{
			name: "invalid service disable",
			files: map[string]string{
				"/etc/xinetd.conf": "service finger { disable = sometimes }\n",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := xinetdFixture(t, test.files)
			inspection, err := inspectXinetdServices(context.Background(), evaluator.Environment{Files: reader}, []string{"finger"})
			if err != nil {
				t.Fatalf("inspectXinetdServices() error = %v", err)
			}
			if inspection.Complete {
				t.Fatalf("inspection = %#v, want incomplete", inspection)
			}
		})
	}
}

func TestDisabledEvaluatorReturnsUnknownForAmbiguousXinetdGraph(t *testing.T) {
	reader := xinetdFixture(t, map[string]string{"/etc/xinetd.conf": "include relative-config\n"})
	outcome := Implementations()[EvaluatorFingerDisabled](context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: inactiveServiceRunner{}, Platform: model.PlatformInfo{InitSystem: "systemd"},
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want UNKNOWN unsupported_configuration", outcome)
	}
}

func xinetdFixture(t *testing.T, files map[string]string) system.Reader {
	t.Helper()
	fixture := xinetdFixtureReader{files: make(fstest.MapFS, len(files))}
	for systemPath, content := range files {
		fixture.files[strings.TrimPrefix(systemPath, "/")] = &fstest.MapFile{Data: []byte(content), Mode: 0o600}
	}
	return fixture
}

type xinetdFixtureReader struct {
	files fstest.MapFS
}

func (reader xinetdFixtureReader) ReadFile(ctx context.Context, name string, limit int64) ([]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	data, err := fs.ReadFile(reader.files, xinetdFixturePath(name))
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	if int64(len(data)) > limit {
		return nil, system.FileMetadata{}, system.ErrReadLimit
	}
	metadata, err := reader.Stat(name)
	return data, metadata, err
}

func (reader xinetdFixtureReader) Stat(name string) (system.FileMetadata, error) {
	info, err := fs.Stat(reader.files, xinetdFixturePath(name))
	if err != nil {
		return system.FileMetadata{}, err
	}
	return xinetdFixtureMetadata(name, info), nil
}

func (reader xinetdFixtureReader) Lstat(name string) (system.FileMetadata, error) {
	return reader.Stat(name)
}

func (reader xinetdFixtureReader) ReadDir(name string) ([]os.DirEntry, error) {
	return fs.ReadDir(reader.files, xinetdFixturePath(name))
}

func (reader xinetdFixtureReader) Exists(name string) (bool, error) {
	_, err := fs.Stat(reader.files, xinetdFixturePath(name))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func xinetdFixturePath(name string) string {
	return strings.TrimPrefix(name, "/")
}

func xinetdFixtureMetadata(name string, info os.FileInfo) system.FileMetadata {
	fileType := "other"
	if info.Mode().IsRegular() {
		fileType = "regular"
	} else if info.IsDir() {
		fileType = "directory"
	}
	return system.FileMetadata{Path: name, FileType: fileType, Mode: info.Mode(), Size: info.Size()}
}
