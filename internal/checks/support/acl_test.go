package support

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type testACLEntry struct {
	tag         uint16
	permissions uint16
	identifier  uint32
}

func TestDecodePOSIXACLXAttr(t *testing.T) {
	t.Parallel()

	extended := encodeTestACL(
		testACLEntry{tag: posixACLTagUserObject, permissions: 0o6, identifier: posixACLUndefinedID},
		testACLEntry{tag: posixACLTagUser, permissions: 0o6, identifier: 1001},
		testACLEntry{tag: posixACLTagGroupObject, permissions: 0o4, identifier: posixACLUndefinedID},
		testACLEntry{tag: posixACLTagMask, permissions: 0o4, identifier: posixACLUndefinedID},
		testACLEntry{tag: posixACLTagOther, permissions: 0o4, identifier: posixACLUndefinedID},
	)
	lines, err := decodePOSIXACLXAttr(extended, false, true)
	if err != nil {
		t.Fatalf("decodePOSIXACLXAttr() error = %v", err)
	}
	want := []string{
		"user::rw-",
		"user:1001:rw-",
		"group::r--",
		"mask::r--",
		"other::r--",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines = %q, want %q", lines, want)
	}

	defaultLines, err := decodePOSIXACLXAttr(extended, true, true)
	if err != nil {
		t.Fatalf("decode default ACL error = %v", err)
	}
	for _, line := range defaultLines {
		if !strings.HasPrefix(line, "default:") {
			t.Fatalf("default line = %q, want default prefix", line)
		}
	}

	absent, err := decodePOSIXACLXAttr(nil, false, false)
	if err != nil || len(absent) != 0 {
		t.Fatalf("absent ACL = %q, %v; want empty successful result", absent, err)
	}
}

func TestDecodePOSIXACLXAttrRejectsUntrustworthyPayloads(t *testing.T) {
	t.Parallel()

	base := []testACLEntry{
		{tag: posixACLTagUserObject, permissions: 0o6, identifier: posixACLUndefinedID},
		{tag: posixACLTagGroupObject, permissions: 0o4, identifier: posixACLUndefinedID},
		{tag: posixACLTagOther, permissions: 0o4, identifier: posixACLUndefinedID},
	}
	tests := []struct {
		name              string
		value             []byte
		wantErrorContains string
	}{
		{
			name:              "short payload",
			value:             []byte{2, 0, 0},
			wantErrorContains: "payload length",
		},
		{
			name: "unsupported version",
			value: func() []byte {
				value := encodeTestACL(base...)
				binary.LittleEndian.PutUint32(value[:4], 3)
				return value
			}(),
			wantErrorContains: "version",
		},
		{
			name: "invalid permission bits",
			value: encodeTestACL(
				testACLEntry{tag: posixACLTagUserObject, permissions: 0o10, identifier: posixACLUndefinedID},
				base[1],
				base[2],
			),
			wantErrorContains: "permissions",
		},
		{
			name: "missing required base entry",
			value: encodeTestACL(
				base[0],
				base[1],
			),
			wantErrorContains: "required ACL entry",
		},
		{
			name: "named entry without mask",
			value: encodeTestACL(
				base[0],
				testACLEntry{tag: posixACLTagUser, permissions: 0o4, identifier: 1001},
				base[1],
				base[2],
			),
			wantErrorContains: "no mask",
		},
		{
			name: "duplicate named entry",
			value: encodeTestACL(
				base[0],
				testACLEntry{tag: posixACLTagUser, permissions: 0o4, identifier: 1001},
				testACLEntry{tag: posixACLTagUser, permissions: 0o4, identifier: 1001},
				base[1],
				testACLEntry{tag: posixACLTagMask, permissions: 0o4, identifier: posixACLUndefinedID},
				base[2],
			),
			wantErrorContains: "duplicate user:1001",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodePOSIXACLXAttr(test.value, false, true)
			if err == nil || !strings.Contains(err.Error(), test.wantErrorContains) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErrorContains)
			}
		})
	}
}

func TestInspectPOSIXACLBlocksPathFallbackForExpectedMetadata(t *testing.T) {
	t.Parallel()

	expected := system.FileMetadata{
		Path:     "/home/user/.profile",
		FileType: "regular",
		Mode:     0o600,
		UID:      1000,
		GID:      1000,
		Device:   1,
		Inode:    2,
	}
	tests := []struct {
		name   string
		reader system.Reader
	}{
		{
			name:   "reader has no native xattr capability",
			reader: aclReaderWithoutXAttrs{},
		},
		{
			name:   "native xattr is unsupported",
			reader: &aclUnsupportedXAttrReader{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runner := &aclGetfaclRunner{available: true}
			inspection, err := InspectPOSIXACL(
				context.Background(),
				test.reader,
				runner,
				expected.Path,
				true,
				false,
				&expected,
			)
			if !IsACLToolUnavailable(err) {
				t.Fatalf("InspectPOSIXACL() error = %v, want ACLInspectionUnavailableError", err)
			}
			if runner.runCalls != 0 {
				t.Fatalf("getfacl Run() calls = %d, want 0", runner.runCalls)
			}
			if inspection.Evidence.Fact["getfacl_available"] != true {
				t.Fatalf("getfacl_available = %#v, want true", inspection.Evidence.Fact["getfacl_available"])
			}
			if inspection.Evidence.Fact["getfacl_fallback_blocked"] != true {
				t.Fatalf("getfacl_fallback_blocked = %#v, want true", inspection.Evidence.Fact["getfacl_fallback_blocked"])
			}
			if inspection.Evidence.Fact["expected_metadata_bound"] != true {
				t.Fatalf("expected_metadata_bound = %#v, want true", inspection.Evidence.Fact["expected_metadata_bound"])
			}
		})
	}
}

func TestSameACLTargetBindsCompleteSecuritySnapshot(t *testing.T) {
	t.Parallel()

	base := system.FileMetadata{
		Path:       "/home/user/.profile",
		FileType:   "regular",
		Mode:       0o600,
		Size:       12,
		UID:        1000,
		GID:        1000,
		Device:     1,
		Inode:      2,
		ModTime:    time.Unix(10, 20).UTC(),
		ChangeTime: time.Unix(30, 40).UTC(),
	}
	if !sameACLTarget(base, base) {
		t.Fatal("identical ACL target snapshots did not match")
	}
	tests := []struct {
		name   string
		mutate func(*system.FileMetadata)
	}{
		{name: "path", mutate: func(value *system.FileMetadata) { value.Path = "/other" }},
		{name: "type", mutate: func(value *system.FileMetadata) { value.FileType = "directory" }},
		{name: "mode", mutate: func(value *system.FileMetadata) { value.Mode = 0o622 }},
		{name: "size", mutate: func(value *system.FileMetadata) { value.Size++ }},
		{name: "owner", mutate: func(value *system.FileMetadata) { value.UID++ }},
		{name: "group", mutate: func(value *system.FileMetadata) { value.GID++ }},
		{name: "device", mutate: func(value *system.FileMetadata) { value.Device++ }},
		{name: "inode", mutate: func(value *system.FileMetadata) { value.Inode++ }},
		{name: "mtime", mutate: func(value *system.FileMetadata) { value.ModTime = value.ModTime.Add(time.Second) }},
		{name: "ctime", mutate: func(value *system.FileMetadata) { value.ChangeTime = value.ChangeTime.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			if sameACLTarget(base, changed) {
				t.Fatalf("%s change was accepted", test.name)
			}
		})
	}
}

func TestInspectPOSIXACLRetainsGetfaclFallbackWithoutExpectedMetadata(t *testing.T) {
	t.Parallel()

	reader := &aclUnsupportedXAttrReader{}
	runner := &aclGetfaclRunner{
		available: true,
		result: executor.Result{
			Executable: "/usr/bin/getfacl",
			Arguments:  []string{"-c", "-p", "-n", "-L", "--absolute-names", "--", "/home/user/.profile"},
			Stdout:     []byte("user::rw-\ngroup::r--\nother::r--\n"),
		},
	}
	inspection, err := InspectPOSIXACL(
		context.Background(),
		reader,
		runner,
		"/home/user/.profile",
		true,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("InspectPOSIXACL() error = %v", err)
	}
	if runner.runCalls != 1 {
		t.Fatalf("getfacl Run() calls = %d, want 1", runner.runCalls)
	}
	if inspection.Content != string(runner.result.Stdout) {
		t.Fatalf("content = %q, want %q", inspection.Content, runner.result.Stdout)
	}
}

func TestInspectPOSIXACLReportsGetfaclFailuresWithoutExpectedMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		runner            *aclGetfaclRunner
		wantErrorContains string
	}{
		{
			name: "runner error",
			runner: &aclGetfaclRunner{
				available: true,
				err:       errors.New("fixture command failure"),
			},
			wantErrorContains: "fixture command failure",
		},
		{
			name: "nonzero exit",
			runner: &aclGetfaclRunner{
				available: true,
				result: executor.Result{
					Executable: "/usr/bin/getfacl",
					ExitCode:   1,
				},
			},
			wantErrorContains: "exit=1 truncated=false",
		},
		{
			name: "truncated output",
			runner: &aclGetfaclRunner{
				available: true,
				result: executor.Result{
					Executable: "/usr/bin/getfacl",
					Stdout:     []byte("user::rw-\ngroup::r--\nother::r--\n"),
					Truncated:  true,
				},
			},
			wantErrorContains: "exit=0 truncated=true",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := InspectPOSIXACL(
				context.Background(),
				aclReaderWithoutXAttrs{},
				test.runner,
				"/home/user/.profile",
				true,
				false,
				nil,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantErrorContains) {
				t.Fatalf("InspectPOSIXACL() error = %v, want substring %q", err, test.wantErrorContains)
			}
			if test.runner.runCalls != 1 {
				t.Fatalf("getfacl Run() calls = %d, want 1", test.runner.runCalls)
			}
		})
	}
}

type aclReaderWithoutXAttrs struct{}

func (aclReaderWithoutXAttrs) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("unexpected ReadFile call")
}

func (aclReaderWithoutXAttrs) Stat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Stat call")
}

func (aclReaderWithoutXAttrs) Lstat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Lstat call")
}

func (aclReaderWithoutXAttrs) ReadDir(string) ([]os.DirEntry, error) {
	return nil, errors.New("unexpected ReadDir call")
}

func (aclReaderWithoutXAttrs) Exists(string) (bool, error) {
	return false, errors.New("unexpected Exists call")
}

type aclUnsupportedXAttrReader struct {
	aclReaderWithoutXAttrs
}

func (*aclUnsupportedXAttrReader) ReadXAttrs(
	context.Context,
	string,
	[]string,
	int64,
	bool,
) (map[string][]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, system.ErrXAttrUnsupported
}

type aclGetfaclRunner struct {
	available bool
	result    executor.Result
	err       error
	runCalls  int
}

func (runner *aclGetfaclRunner) Available(name string) bool {
	return runner.available && name == "getfacl"
}

func (runner *aclGetfaclRunner) Run(_ context.Context, _ executor.Spec) (executor.Result, error) {
	runner.runCalls++
	return runner.result, runner.err
}

func encodeTestACL(entries ...testACLEntry) []byte {
	value := make([]byte, 4+len(entries)*8)
	binary.LittleEndian.PutUint32(value[:4], posixACLXAttrVersion)
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(value[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(value[offset+2:offset+4], entry.permissions)
		binary.LittleEndian.PutUint32(value[offset+4:offset+8], entry.identifier)
	}
	return value
}
