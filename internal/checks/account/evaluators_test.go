package account

import (
	"context"
	"errors"
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

const (
	validPasswd = "root:x:0:0:root:/root:/bin/bash\nservice:x:999:999:service:/nonexistent:/sbin/nologin\n"
	validShadow = "root:!:20000:0:99999:7:::\nservice:*:20000:0:99999:7:::\n"
)

func TestCoreAccountEvaluatorFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		evaluatorID      string
		files            map[string]string
		commands         executor.CommandRunner
		wantStatus       model.Status
		wantUnknown      model.UnknownReason
		wantErrorCode    string
		observedContains string
	}{
		{
			name:        "U-04 pass with matching passwd and shadow entries",
			evaluatorID: EvaluatorShadowPasswords,
			files: map[string]string{
				"/etc/passwd": validPasswd,
				"/etc/shadow": validShadow,
			},
			wantStatus:       model.StatusPass,
			observedContains: "/etc/shadow",
		},
		{
			name:        "U-04 fail when a passwd account has no shadow entry",
			evaluatorID: EvaluatorShadowPasswords,
			files: map[string]string{
				"/etc/passwd": validPasswd,
				"/etc/shadow": "root:!:20000:0:99999:7:::\n",
			},
			wantStatus:       model.StatusFail,
			observedContains: "service(shadow 항목 없음)",
		},
		{
			name:        "U-04 error when shadow is missing",
			evaluatorID: EvaluatorShadowPasswords,
			files: map[string]string{
				"/etc/passwd": validPasswd,
			},
			wantStatus:    model.StatusError,
			wantErrorCode: "shadow_read_failed",
		},
		{
			name:        "U-04 error on malformed passwd input",
			evaluatorID: EvaluatorShadowPasswords,
			files: map[string]string{
				"/etc/passwd": "root:x:not-a-uid:0:root:/root:/bin/bash\n",
				"/etc/shadow": validShadow,
			},
			wantStatus:    model.StatusError,
			wantErrorCode: "passwd_read_failed",
		},
		{
			name:             "U-05 pass with root as the only UID zero account",
			evaluatorID:      EvaluatorUIDZero,
			commands:         getentPasswdFixture(validPasswd),
			wantStatus:       model.StatusPass,
			observedContains: "root",
		},
		{
			name:        "U-05 fail with a second UID zero account",
			evaluatorID: EvaluatorUIDZero,
			commands: getentPasswdFixture(
				"root:x:0:0:root:/root:/bin/bash\noperator:x:0:1000:operator:/home/operator:/bin/bash\n",
			),
			wantStatus:       model.StatusFail,
			observedContains: "operator",
		},
		{
			name:             "U-05 error on malformed effective passwd input",
			evaluatorID:      EvaluatorUIDZero,
			commands:         getentPasswdFixture("root:x:0:0:missing-fields\n"),
			wantStatus:       model.StatusError,
			wantErrorCode:    "passwd_read_failed",
			observedContains: "",
		},
		{
			name:        "U-10 pass with unique UIDs",
			evaluatorID: EvaluatorDuplicateUID,
			commands: getentPasswdFixture(
				"root:x:0:0:root:/root:/bin/bash\nalpha:x:1000:1000:alpha:/home/alpha:/bin/bash\n",
			),
			wantStatus:       model.StatusPass,
			observedContains: "중복 UID가 없습니다.",
		},
		{
			name:        "U-10 fail with a duplicate non-root UID",
			evaluatorID: EvaluatorDuplicateUID,
			commands: getentPasswdFixture(
				"root:x:0:0:root:/root:/bin/bash\nalpha:x:1000:1000:alpha:/home/alpha:/bin/bash\nbeta:x:1000:1001:beta:/home/beta:/bin/bash\n",
			),
			wantStatus:       model.StatusFail,
			observedContains: "uid=1000:alpha/beta",
		},
		{
			name:        "U-10 error when getent collection fails",
			evaluatorID: EvaluatorDuplicateUID,
			commands: fixtureCommandRunner{
				commandKey("getent", "passwd"): {err: errors.New("fixture collection failure")},
			},
			wantStatus:    model.StatusError,
			wantErrorCode: "passwd_read_failed",
		},
		{
			name:        "U-07 remains unknown without an approved account inventory",
			evaluatorID: EvaluatorUnnecessaryAccounts,
			commands:    getentPasswdFixture(validPasswd),
			wantStatus:  model.StatusUnknown,
			wantUnknown: model.UnknownManualVerification,
		},
	}

	implementations := Implementations()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			implementation, exists := implementations[test.evaluatorID]
			if !exists {
				t.Fatalf("evaluator %q is not registered", test.evaluatorID)
			}
			environment := evaluator.Environment{
				Files:    newAccountFixtureReader(test.files),
				Commands: test.commands,
			}
			outcome := implementation(context.Background(), model.ResolvedRule{}, environment)

			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, test.wantStatus, outcome)
			}
			if outcome.UnknownReason != test.wantUnknown {
				t.Errorf("unknown reason = %q, want %q", outcome.UnknownReason, test.wantUnknown)
			}
			if outcome.ErrorCode != test.wantErrorCode {
				t.Errorf("error code = %q, want %q", outcome.ErrorCode, test.wantErrorCode)
			}
			if test.observedContains != "" && !strings.Contains(outcome.Observed, test.observedContains) {
				t.Errorf("observed = %q, want substring %q", outcome.Observed, test.observedContains)
			}
			if test.wantStatus == model.StatusError && strings.TrimSpace(outcome.ErrorMessage) == "" {
				t.Error("error outcome has an empty error message")
			}
			if test.wantStatus == model.StatusPass || test.wantStatus == model.StatusFail || test.wantStatus == model.StatusUnknown {
				if len(outcome.Evidence) == 0 {
					t.Error("decision outcome has no evidence")
				}
				for index, evidence := range outcome.Evidence {
					if !evidence.Redacted {
						t.Errorf("evidence[%d] is not marked redacted", index)
					}
				}
			}
		})
	}
}

type fixtureCommandResponse struct {
	result executor.Result
	err    error
}

type fixtureCommandRunner map[string]fixtureCommandResponse

func (r fixtureCommandRunner) Run(ctx context.Context, spec executor.Spec) (executor.Result, error) {
	if err := ctx.Err(); err != nil {
		return executor.Result{}, err
	}
	response, exists := r[commandKey(spec.Name, spec.Arguments...)]
	if !exists {
		return executor.Result{}, fmt.Errorf("unexpected fixture command: %s %q", spec.Name, spec.Arguments)
	}
	result := response.result
	if result.Executable == "" {
		result.Executable = "/usr/bin/" + spec.Name
	}
	if result.Arguments == nil {
		result.Arguments = spec.EvidenceArguments()
	}
	return result, response.err
}

func (fixtureCommandRunner) Available(string) bool {
	return false
}

func getentPasswdFixture(content string) fixtureCommandRunner {
	return fixtureCommandRunner{
		commandKey("getent", "passwd"): {
			result: executor.Result{ExitCode: 0, Stdout: []byte(content)},
		},
	}
}

func commandKey(name string, arguments ...string) string {
	return name + "\x00" + strings.Join(arguments, "\x00")
}

type accountFixtureReader struct {
	files fstest.MapFS
}

func newAccountFixtureReader(files map[string]string) system.Reader {
	source := make(fstest.MapFS, len(files))
	for name, content := range files {
		source[fixtureFSPath(name)] = &fstest.MapFile{Data: []byte(content), Mode: 0o600}
	}
	return accountFixtureReader{files: source}
}

func (r accountFixtureReader) ReadFile(ctx context.Context, name string, limit int64) ([]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	data, err := fs.ReadFile(r.files, fixtureFSPath(name))
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	if limit > 0 && int64(len(data)) > limit {
		return nil, system.FileMetadata{}, fmt.Errorf("%w: %s", system.ErrReadLimit, name)
	}
	metadata, err := r.Lstat(name)
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	return data, metadata, nil
}

func (r accountFixtureReader) Stat(name string) (system.FileMetadata, error) {
	return r.Lstat(name)
}

func (r accountFixtureReader) Lstat(name string) (system.FileMetadata, error) {
	info, err := fs.Stat(r.files, fixtureFSPath(name))
	if err != nil {
		return system.FileMetadata{}, err
	}
	fileType := "other"
	if info.Mode().IsRegular() {
		fileType = "regular"
	} else if info.IsDir() {
		fileType = "directory"
	}
	return system.FileMetadata{
		Path: name, FileType: fileType, Mode: info.Mode(), Size: info.Size(), UID: 0, GID: 0,
	}, nil
}

func (r accountFixtureReader) ReadDir(name string) ([]os.DirEntry, error) {
	return fs.ReadDir(r.files, fixtureFSPath(name))
}

func (r accountFixtureReader) Exists(name string) (bool, error) {
	_, err := r.Lstat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func fixtureFSPath(name string) string {
	return strings.TrimPrefix(name, "/")
}
