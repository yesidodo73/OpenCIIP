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
	baseACL := encodeTestACL(
		testACLEntry{tag: posixACLTagUserObject, permissions: 0o6, identifier: posixACLUndefinedID},
		testACLEntry{tag: posixACLTagGroupObject, permissions: 0o4, identifier: posixACLUndefinedID},
		testACLEntry{tag: posixACLTagOther, permissions: 0o4, identifier: posixACLUndefinedID},
	)
	nativeReader := func(metadata system.FileMetadata) system.Reader {
		return permissionXAttrFixtureReader{
			permissionFixtureReader: permissionFixtureReader{metadata: metadata},
			values: map[string][]byte{
				posixACLAccessXAttr: baseACL,
			},
		}
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
			reader:         nativeReader(baseMetadata),
			commands:       permissionFixtureRunner{unavailable: true},
			wantExists:     true,
			wantViolations: 0,
			wantUnknowns:   0,
		},
		{
			name: "owner and mode violations are both retained",
			reader: nativeReader(system.FileMetadata{
				Path: "/etc/passwd", FileType: "regular", Mode: 0o666, UID: 1001, GID: 1001,
			}),
			commands:          permissionFixtureRunner{unavailable: true},
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
			reader: nativeReader(system.FileMetadata{
				Path: "/etc/passwd", FileType: "regular", Mode: 0o644, UID: -1, GID: -1,
			}),
			commands:        permissionFixtureRunner{unavailable: true},
			wantExists:      true,
			wantUnknowns:    1,
			unknownContains: "UID를 확인할 수 없음",
		},
		{
			name: "unbound ACL fallback is an evidenced unknown",
			reader: permissionXAttrFixtureReader{
				permissionFixtureReader: permissionFixtureReader{metadata: baseMetadata},
				err:                     system.ErrXAttrUnsupported,
			},
			commands:        permissionFixtureRunner{},
			wantExists:      true,
			wantUnknowns:    1,
			unknownContains: "POSIX ACL",
		},
		{
			name: "malformed native ACL is an inspection error",
			reader: permissionXAttrFixtureReader{
				permissionFixtureReader: permissionFixtureReader{metadata: baseMetadata},
				values: map[string][]byte{
					posixACLAccessXAttr: encodeTestACL(
						testACLEntry{tag: posixACLTagUserObject, permissions: 0o10, identifier: posixACLUndefinedID},
						testACLEntry{tag: posixACLTagGroupObject, permissions: 0o4, identifier: posixACLUndefinedID},
						testACLEntry{tag: posixACLTagOther, permissions: 0o4, identifier: posixACLUndefinedID},
					),
				},
			},
			commands:          permissionFixtureRunner{unavailable: true},
			wantExists:        true,
			wantErrorContains: "invalid permissions",
		},
		{
			name: "native ACL collection failure is an inspection error",
			reader: permissionXAttrFixtureReader{
				permissionFixtureReader: permissionFixtureReader{metadata: baseMetadata},
				err:                     errors.New("fixture xattr failure"),
			},
			commands:          permissionFixtureRunner{unavailable: true},
			wantExists:        true,
			wantErrorContains: "fixture xattr failure",
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
			if test.unknownContains == "POSIX ACL" {
				if len(assessment.Evidence) < 2 {
					t.Fatalf("evidence = %#v, want metadata and ACL availability facts", assessment.Evidence)
				}
				availability := assessment.Evidence[len(assessment.Evidence)-1]
				if availability.Source != "posix_acl" ||
					availability.Fact["getfacl_available"] != true ||
					availability.Fact["getfacl_fallback_blocked"] != true ||
					availability.Fact["expected_metadata_bound"] != true {
					t.Fatalf("availability evidence = %#v, want unsafe path fallback blocked", availability)
				}
			}
		})
	}
}

func TestInspectPermissionsUsesNativeACLWhenGetfaclIsUnavailable(t *testing.T) {
	metadata := system.FileMetadata{
		Path: "/etc/passwd", FileType: "regular", Mode: 0o644, UID: 0, GID: 0,
		Device: 7, Inode: 42,
	}
	reader := permissionXAttrFixtureReader{
		permissionFixtureReader: permissionFixtureReader{metadata: metadata},
		values: map[string][]byte{
			posixACLAccessXAttr: encodeTestACL(
				testACLEntry{tag: posixACLTagUserObject, permissions: 0o6, identifier: posixACLUndefinedID},
				testACLEntry{tag: posixACLTagGroupObject, permissions: 0o4, identifier: posixACLUndefinedID},
				testACLEntry{tag: posixACLTagOther, permissions: 0o4, identifier: posixACLUndefinedID},
			),
		},
	}
	assessment, err := InspectPermissions(
		context.Background(),
		reader,
		permissionFixtureRunner{unavailable: true},
		"/etc/passwd",
		PermissionPolicy{
			AllowedUIDs:        map[int]struct{}{0: {}},
			AllowedMode:        0o644,
			AllowedTypes:       map[string]struct{}{"regular": {}},
			FollowFinalSymlink: true,
		},
	)
	if err != nil {
		t.Fatalf("InspectPermissions() error = %v", err)
	}
	if len(assessment.Unknowns) != 0 || len(assessment.Violations) != 0 {
		t.Fatalf("assessment = %#v, want a complete passing assessment", assessment)
	}
	if got := assessment.Evidence[len(assessment.Evidence)-1].Source; got != "posix_acl_xattr" {
		t.Fatalf("ACL evidence source = %q, want posix_acl_xattr", got)
	}
}

func TestInspectPermissionsRejectsChangedNativeACLTarget(t *testing.T) {
	before := system.FileMetadata{
		Path: "/etc/passwd", FileType: "regular", Mode: 0o644, UID: 0, GID: 0,
		Device: 7, Inode: 42,
	}
	after := before
	after.Inode = 43
	reader := permissionXAttrFixtureReader{
		permissionFixtureReader: permissionFixtureReader{metadata: before},
		snapshot:                &after,
	}
	_, err := InspectPermissions(
		context.Background(),
		reader,
		permissionFixtureRunner{unavailable: true},
		"/etc/passwd",
		PermissionPolicy{
			AllowedUIDs:        map[int]struct{}{0: {}},
			AllowedMode:        0o644,
			AllowedTypes:       map[string]struct{}{"regular": {}},
			FollowFinalSymlink: true,
		},
	)
	if !errors.Is(err, system.ErrFileChanged) {
		t.Fatalf("InspectPermissions() error = %v, want ErrFileChanged", err)
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

type permissionXAttrFixtureReader struct {
	permissionFixtureReader
	values   map[string][]byte
	snapshot *system.FileMetadata
	err      error
}

func (r permissionXAttrFixtureReader) ReadXAttrs(
	ctx context.Context,
	path string,
	names []string,
	_ int64,
	_ bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	if r.err != nil {
		return nil, system.FileMetadata{}, r.err
	}
	values := make(map[string][]byte)
	for _, name := range names {
		if value, exists := r.values[name]; exists {
			values[name] = append([]byte(nil), value...)
		}
	}
	metadata, err := r.Stat(path)
	if r.snapshot != nil {
		metadata = *r.snapshot
	}
	return values, metadata, err
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
	unavailable bool
}

func (permissionFixtureRunner) Run(ctx context.Context, spec executor.Spec) (executor.Result, error) {
	if err := ctx.Err(); err != nil {
		return executor.Result{}, err
	}
	return executor.Result{}, fmt.Errorf("unexpected fixture command %q", spec.Name)
}

func (r permissionFixtureRunner) Available(name string) bool {
	return name == "getfacl" && !r.unavailable
}
