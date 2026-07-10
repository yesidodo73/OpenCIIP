package support

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const canonical0644ACL = "user::rw-\ngroup::r--\nother::r--\n"

func TestPermissionACLViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		content           string
		ownerUID          int
		allowedMode       os.FileMode
		checkDefaults     bool
		wantNamed         bool
		wantViolations    int
		violationContains string
		wantErrorContains string
	}{
		{
			name:           "base ACL within mode is accepted",
			content:        canonical0644ACL,
			ownerUID:       0,
			allowedMode:    0o644,
			wantViolations: 0,
		},
		{
			name: "named user write permission exceeds group class",
			content: "user::rw-\n" +
				"user:1001:rw-\n" +
				"group::r--\n" +
				"mask::rw-\n" +
				"other::r--\n",
			ownerUID:          0,
			allowedMode:       0o644,
			wantNamed:         true,
			wantViolations:    1,
			violationContains: "ACL user:1001",
		},
		{
			name: "effective permission is authoritative for a named entry",
			content: "user::rw-\n" +
				"user:1001:rwx #effective:r--\n" +
				"group::r--\n" +
				"mask::r--\n" +
				"other::r--\n",
			ownerUID:       0,
			allowedMode:    0o644,
			wantNamed:      true,
			wantViolations: 0,
		},
		{
			name: "default ACL is ignored when the policy does not cover it",
			content: canonical0644ACL +
				"default:user::rwx\n" +
				"default:group::rwx\n" +
				"default:other::rwx\n",
			ownerUID:       0,
			allowedMode:    0o644,
			wantViolations: 0,
		},
		{
			name: "default ACL is enforced when requested",
			content: canonical0644ACL +
				"default:user::rw-\n" +
				"default:group::rw-\n" +
				"default:mask::rw-\n" +
				"default:other::r--\n",
			ownerUID:          0,
			allowedMode:       0o644,
			checkDefaults:     true,
			wantViolations:    2,
			violationContains: "default ACL",
		},
		{
			name: "non-numeric named user is rejected",
			content: "user::rw-\n" +
				"user:operator:r--\n" +
				"group::r--\n" +
				"mask::r--\n" +
				"other::r--\n",
			ownerUID:          0,
			allowedMode:       0o644,
			wantErrorContains: "not numeric",
		},
		{
			name:              "malformed permission token is rejected",
			content:           "user::rwq\n",
			ownerUID:          0,
			allowedMode:       0o644,
			wantErrorContains: "invalid permissions",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			violations, named, err := permissionACLViolations(
				test.content,
				test.ownerUID,
				test.allowedMode,
				test.checkDefaults,
			)
			if test.wantErrorContains != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrorContains) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErrorContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("permissionACLViolations() error = %v", err)
			}
			if named != test.wantNamed {
				t.Errorf("named access ACL = %t, want %t", named, test.wantNamed)
			}
			if len(violations) != test.wantViolations {
				t.Errorf("violations = %q, want %d entries", violations, test.wantViolations)
			}
			if test.violationContains != "" && !sliceContainsSubstring(violations, test.violationContains) {
				t.Errorf("violations = %q, want substring %q", violations, test.violationContains)
			}
		})
	}
}

func TestInspectPermissionsFixtureBoundaries(t *testing.T) {
	t.Parallel()

	policy := PermissionPolicy{
		AllowedUIDs:  map[int]struct{}{0: {}},
		AllowedMode:  0o644,
		AllowedTypes: map[string]struct{}{"regular": {}},
	}
	baseMetadata := system.FileMetadata{
		Path: "/etc/passwd", FileType: "regular", Mode: 0o644, UID: 0, GID: 0,
	}
	tests := []struct {
		name              string
		reader            system.Reader
		commands          executor.CommandRunner
		wantExists        bool
		wantViolations    int
		violationContains string
		wantUnknowns      int
		unknownContains   string
		wantErrorContains string
	}{
		{
			name:           "regular root-owned file within the policy",
			reader:         permissionFixtureReader{metadata: baseMetadata},
			commands:       permissionFixtureRunner{stdout: canonical0644ACL},
			wantExists:     true,
			wantViolations: 0,
			wantUnknowns:   0,
		},
		{
			name: "owner and mode violations are both retained",
			reader: permissionFixtureReader{metadata: system.FileMetadata{
				Path: "/etc/passwd", FileType: "regular", Mode: 0o666, UID: 1001, GID: 1001,
			}},
			commands:          permissionFixtureRunner{stdout: canonical0644ACL},
			wantExists:        true,
			wantViolations:    2,
			violationContains: "허용되지 않은 소유자 UID",
		},
		{
			name:       "missing file is a distinct non-error assessment",
			reader:     permissionFixtureReader{lstatErr: fs.ErrNotExist},
			commands:   nil,
			wantExists: false,
		},
		{
			name: "unknown owner is not converted to a pass or violation",
			reader: permissionFixtureReader{metadata: system.FileMetadata{
				Path: "/etc/passwd", FileType: "regular", Mode: 0o644, UID: -1, GID: -1,
			}},
			commands:        permissionFixtureRunner{stdout: canonical0644ACL},
			wantExists:      true,
			wantUnknowns:    1,
			unknownContains: "UID를 확인할 수 없음",
		},
		{
			name:              "malformed ACL is an inspection error",
			reader:            permissionFixtureReader{metadata: baseMetadata},
			commands:          permissionFixtureRunner{stdout: "user::rwq\n"},
			wantExists:        true,
			wantErrorContains: "invalid permissions",
		},
		{
			name:              "ACL collection failure is an inspection error",
			reader:            permissionFixtureReader{metadata: baseMetadata},
			commands:          permissionFixtureRunner{err: errors.New("fixture command failure")},
			wantExists:        true,
			wantErrorContains: "fixture command failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assessment, err := InspectPermissions(
				context.Background(),
				test.reader,
				test.commands,
				"/etc/passwd",
				policy,
			)
			if test.wantErrorContains != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrorContains) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErrorContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("InspectPermissions() error = %v", err)
			}
			if assessment.Exists != test.wantExists {
				t.Errorf("exists = %t, want %t", assessment.Exists, test.wantExists)
			}
			if len(assessment.Violations) != test.wantViolations {
				t.Errorf("violations = %q, want %d entries", assessment.Violations, test.wantViolations)
			}
			if test.violationContains != "" && !sliceContainsSubstring(assessment.Violations, test.violationContains) {
				t.Errorf("violations = %q, want substring %q", assessment.Violations, test.violationContains)
			}
			if len(assessment.Unknowns) != test.wantUnknowns {
				t.Errorf("unknowns = %q, want %d entries", assessment.Unknowns, test.wantUnknowns)
			}
			if test.unknownContains != "" && !sliceContainsSubstring(assessment.Unknowns, test.unknownContains) {
				t.Errorf("unknowns = %q, want substring %q", assessment.Unknowns, test.unknownContains)
			}
		})
	}
}

func sliceContainsSubstring(values []string, substring string) bool {
	for _, value := range values {
		if strings.Contains(value, substring) {
			return true
		}
	}
	return false
}

type permissionFixtureReader struct {
	metadata system.FileMetadata
	lstatErr error
	statErr  error
}

func (r permissionFixtureReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("unexpected fixture file read")
}

func (r permissionFixtureReader) Stat(string) (system.FileMetadata, error) {
	if r.statErr != nil {
		return system.FileMetadata{}, r.statErr
	}
	return r.metadata, nil
}

func (r permissionFixtureReader) Lstat(string) (system.FileMetadata, error) {
	if r.lstatErr != nil {
		return system.FileMetadata{}, r.lstatErr
	}
	return r.metadata, nil
}

func (permissionFixtureReader) ReadDir(string) ([]os.DirEntry, error) {
	return nil, errors.New("unexpected fixture directory read")
}

func (r permissionFixtureReader) Exists(name string) (bool, error) {
	_, err := r.Lstat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

type permissionFixtureRunner struct {
	stdout    string
	exitCode  int
	truncated bool
	err       error
}

func (r permissionFixtureRunner) Run(ctx context.Context, spec executor.Spec) (executor.Result, error) {
	if err := ctx.Err(); err != nil {
		return executor.Result{}, err
	}
	if spec.Name != "getfacl" {
		return executor.Result{}, fmt.Errorf("unexpected fixture command %q", spec.Name)
	}
	return executor.Result{
		Executable: "/usr/bin/getfacl",
		Arguments:  spec.EvidenceArguments(),
		ExitCode:   r.exitCode,
		Stdout:     []byte(r.stdout),
		Truncated:  r.truncated,
	}, r.err
}

func (permissionFixtureRunner) Available(string) bool {
	return false
}
