package filecheck

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestInspectNonOwnerACLTreatsMissingCollectorAsEvidencedUnavailableError(t *testing.T) {
	_, evidence, err := inspectNonOwnerACL(context.Background(), evaluator.Environment{
		Commands: nonOwnerACLFixtureRunner{},
	}, system.FileMetadata{Path: "/home/test", UID: 1000}, 0o2)
	if !support.IsACLToolUnavailable(err) {
		t.Fatalf("error = %v, want ACLToolUnavailableError", err)
	}
	if evidence.Source != "posix_acl" || evidence.Fact["getfacl_available"] != false {
		t.Fatalf("evidence = %#v, want all ACL collectors unavailable", evidence)
	}
}

func TestInspectNonOwnerACLDoesNotUseUnboundGetfaclResults(t *testing.T) {
	tests := []struct {
		name   string
		runner nonOwnerACLFixtureRunner
	}{
		{
			name:   "runner error",
			runner: nonOwnerACLFixtureRunner{available: true, err: errors.New("fixture run failure")},
		},
		{
			name:   "nonzero exit",
			runner: nonOwnerACLFixtureRunner{available: true, result: executor.Result{ExitCode: 1}},
		},
		{
			name:   "truncated output",
			runner: nonOwnerACLFixtureRunner{available: true, result: executor.Result{Truncated: true}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, evidence, err := inspectNonOwnerACL(context.Background(), evaluator.Environment{
				Commands: test.runner,
			}, system.FileMetadata{Path: "/home/test", UID: 1000}, 0o2)
			if !support.IsACLToolUnavailable(err) {
				t.Fatalf("error = %v, want ACLInspectionUnavailableError", err)
			}
			if evidence.Fact["getfacl_available"] != true ||
				evidence.Fact["getfacl_fallback_blocked"] != true {
				t.Fatalf("evidence = %#v, want available but blocked getfacl fallback", evidence)
			}
		})
	}
}

func TestInspectNonOwnerACLUsesNativeEvidenceWhenGetfaclIsUnavailable(t *testing.T) {
	violations, evidence, err := inspectNonOwnerACL(context.Background(), evaluator.Environment{
		Files:    nonOwnerACLXAttrReader{},
		Commands: nonOwnerACLFixtureRunner{},
	}, system.FileMetadata{
		Path: "/home/test", FileType: "directory", Mode: 0o700, UID: 1000, GID: 1000,
	}, 0o2)
	if err != nil {
		t.Fatalf("inspectNonOwnerACL() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("violations = %q, want none", violations)
	}
	if evidence.Source != "posix_acl_xattr" || evidence.Fact["access_acl_present"] != false {
		t.Fatalf("evidence = %#v, want absent native access ACL", evidence)
	}
}

type nonOwnerACLXAttrReader struct{}

func (nonOwnerACLXAttrReader) ReadXAttrs(
	ctx context.Context,
	path string,
	_ []string,
	_ int64,
	_ bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	return map[string][]byte{}, system.FileMetadata{
		Path: path, FileType: "directory", Mode: 0o700, UID: 1000, GID: 1000,
	}, nil
}

func (nonOwnerACLXAttrReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("unexpected file read")
}

func (nonOwnerACLXAttrReader) Stat(path string) (system.FileMetadata, error) {
	return system.FileMetadata{Path: path, FileType: "directory", Mode: 0o700, UID: 1000, GID: 1000}, nil
}

func (reader nonOwnerACLXAttrReader) Lstat(path string) (system.FileMetadata, error) {
	return reader.Stat(path)
}

func (nonOwnerACLXAttrReader) ReadDir(string) ([]os.DirEntry, error) {
	return nil, errors.New("unexpected directory read")
}

func (nonOwnerACLXAttrReader) Exists(string) (bool, error) {
	return true, nil
}

type nonOwnerACLFixtureRunner struct {
	available bool
	result    executor.Result
	err       error
}

func (runner nonOwnerACLFixtureRunner) Available(name string) bool {
	return name == "getfacl" && runner.available
}

func (runner nonOwnerACLFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "getfacl" {
		return executor.Result{}, errors.New("unexpected fixture command")
	}
	return runner.result, runner.err
}

func TestCompactFindingsLabelsMultiAccountGroups(t *testing.T) {
	t.Parallel()

	findings := []pathFinding{
		{Account: "_apt,frr,messagebus", Path: "/nonexistent", Reason: "홈 디렉터리가 없음"},
		{Account: "svc", Path: "/home/svc", Reason: "홈 디렉터리가 없음"},
	}

	got := compactFindings(findings, 10)
	want := "svc:/home/svc(홈 디렉터리가 없음), 계정 3개(_apt, frr, messagebus):/nonexistent(홈 디렉터리가 없음)"
	if got != want {
		t.Fatalf("compactFindings = %q, want %q", got, want)
	}
}
