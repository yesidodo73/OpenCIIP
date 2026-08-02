package logging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestAssessLogFileTreatsNonRootOwnerAsClearViolation(t *testing.T) {
	clear, ambiguous := assessLogFile(system.FileMetadata{Path: "/var/log/test.log", UID: 1234, Mode: 0o644}, aclAssessment{})
	if len(clear) != 1 || len(ambiguous) != 0 {
		t.Fatalf("assessLogFile() = %#v, %#v, want one clear owner violation", clear, ambiguous)
	}
}

func TestAssessLogFileTreatsGroupWriteAsClearViolation(t *testing.T) {
	clear, ambiguous := assessLogFile(system.FileMetadata{Path: "/var/log/test.log", UID: 0, Mode: os.FileMode(0o660)}, aclAssessment{})
	if len(clear) != 1 || len(ambiguous) != 0 {
		t.Fatalf("assessLogFile() = %#v, %#v, want one clear mode violation", clear, ambiguous)
	}
}

func TestAssessACLDocumentTreatsNamedWriteAsClearViolation(t *testing.T) {
	assessment, err := assessACLDocument([]string{"user::rw-", "user:1000:rw-", "group::r--", "mask::rw-", "other::r--"})
	if err != nil {
		t.Fatalf("assessACLDocument() error = %v", err)
	}
	if len(assessment.clearReasons) != 1 || len(assessment.ambiguousReasons) != 0 {
		t.Fatalf("assessACLDocument() = %#v, want one clear named-user violation", assessment)
	}
}

func TestAssessACLDocumentTreatsOtherWriteAsClearViolation(t *testing.T) {
	assessment, err := assessACLDocument([]string{"user::rw-", "group::r--", "other::rw-"})
	if err != nil {
		t.Fatalf("assessACLDocument() error = %v", err)
	}
	if len(assessment.clearReasons) != 1 || len(assessment.ambiguousReasons) != 0 {
		t.Fatalf("assessACLDocument() = %#v, want one clear other-write violation", assessment)
	}
}

func TestAssessLogFileAcceptsRootOwnedModeAndReadOnlyACL(t *testing.T) {
	assessment, err := assessACLDocument([]string{
		"user::rw-",
		"user:1000:r--",
		"group::r--",
		"mask::r--",
		"other::r--",
	})
	if err != nil {
		t.Fatalf("assessACLDocument() error = %v", err)
	}
	clear, ambiguous := assessLogFile(system.FileMetadata{
		Path: "/var/log/test.log", UID: 0, Mode: 0o644,
	}, assessment)
	if len(clear) != 0 || len(ambiguous) != 0 {
		t.Fatalf("assessLogFile() = %#v, %#v, want no finding", clear, ambiguous)
	}
}

func TestInspectLogACLsTreatsMissingCollectorAsEvidencedIncompleteResult(t *testing.T) {
	paths := []string{"/var/log/a.log", "/var/log/b.log"}
	assessments, evidence, complete, err := inspectLogACLs(context.Background(), evaluator.Environment{
		Commands: logACLFixtureRunner{},
	}, paths)
	if err != nil {
		t.Fatalf("inspectLogACLs() error = %v", err)
	}
	if complete {
		t.Fatal("inspectLogACLs() complete = true, want false")
	}
	if len(evidence) != 1 || evidence[0].Source != "getfacl" || evidence[0].Fact["available"] != false {
		t.Fatalf("evidence = %#v, want getfacl fallback unavailable", evidence)
	}
	for _, filePath := range paths {
		assessment, exists := assessments[filePath]
		if !exists || len(assessment.ambiguousReasons) != 1 || !strings.Contains(assessment.ambiguousReasons[0], "POSIX ACL") {
			t.Fatalf("assessment[%q] = %#v, want ACL collection ambiguity", filePath, assessment)
		}
	}
}

func TestInspectLogACLsUsesNativeEvidenceWhenGetfaclIsUnavailable(t *testing.T) {
	paths := []string{"/var/log/a.log", "/var/log/b.log"}
	assessments, evidence, complete, err := inspectLogACLs(context.Background(), evaluator.Environment{
		Files:    logACLXAttrReader{},
		Commands: logACLFixtureRunner{},
	}, paths)
	if err != nil {
		t.Fatalf("inspectLogACLs() error = %v", err)
	}
	if !complete {
		t.Fatal("inspectLogACLs() complete = false, want native ACL inspection to complete")
	}
	if len(assessments) != len(paths) {
		t.Fatalf("assessment count = %d, want %d", len(assessments), len(paths))
	}
	if len(evidence) != 1 || evidence[0].Source != "posix_acl_xattr_batch" {
		t.Fatalf("evidence = %#v, want one native ACL batch fact", evidence)
	}
	if evidence[0].Fact["access_acl_absent"] != len(paths) {
		t.Fatalf("batch evidence = %#v, want all access ACLs absent", evidence[0].Fact)
	}
}

func TestInspectLogACLsKeepsExecutionFailuresAsErrors(t *testing.T) {
	tests := []struct {
		name              string
		runner            logACLFixtureRunner
		wantErrorContains string
	}{
		{
			name:              "runner error",
			runner:            logACLFixtureRunner{available: true, err: errors.New("fixture run failure")},
			wantErrorContains: "fixture run failure",
		},
		{
			name:              "nonzero exit",
			runner:            logACLFixtureRunner{available: true, result: executor.Result{ExitCode: 1}},
			wantErrorContains: "exit=1 truncated=false",
		},
		{
			name:              "truncated output",
			runner:            logACLFixtureRunner{available: true, result: executor.Result{Truncated: true}},
			wantErrorContains: "exit=0 truncated=true",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := inspectLogACLs(context.Background(), evaluator.Environment{Commands: test.runner}, []string{"/var/log/a.log"})
			if err == nil || !strings.Contains(err.Error(), test.wantErrorContains) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErrorContains)
			}
		})
	}
}

func TestEvaluateLogFilePermissionsDoesNotDependOnInitSystemOrMountType(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addRegular("/var/log/auth.log", 2, 10, 1000, 0o644)

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files:    reader,
		Commands: logUnexpectedCommandRunner{},
		Platform: model.PlatformInfo{InitSystem: "sysv"},
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "비-root") {
		t.Fatalf("observed = %q, want non-root owner violation", outcome.Observed)
	}
}

func TestEvaluateLogFilePermissionsPassesSafeVisibleFilesAndOnlyEmptyInventoryIsNotApplicable(t *testing.T) {
	safe := newLogPermissionFixtureReader()
	safe.addRegular("/var/log/auth.log", 2, 10, 0, 0o640)
	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: safe,
	})
	if outcome.Status != model.StatusPass {
		t.Fatalf("safe status = %s, summary=%q observed=%q", outcome.Status, outcome.Summary, outcome.Observed)
	}

	empty := newLogPermissionFixtureReader()
	outcome = evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: empty,
	})
	if outcome.Status != model.StatusNotApplicable {
		t.Fatalf("empty status = %s, summary=%q observed=%q", outcome.Status, outcome.Summary, outcome.Observed)
	}
}

func TestEvaluateLogFilePermissionsScansCrossDeviceRegularSymlink(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addSymlink("/var/log/current", 1, 11, system.FileMetadata{
		Path: "/var/log/current", FileType: "regular", Mode: 0o666,
		UID: 1000, GID: 1000, Device: 2, Inode: 20,
	})

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	fact := requireLogInventoryFact(t, outcome)
	if fact["inventory_complete"] != true ||
		fact["symlink_regular_files"] != 1 ||
		fact["cross_device_regular_files"] != 1 {
		t.Fatalf("inventory fact = %#v, want scanned cross-device regular symlink", fact)
	}
}

func TestEvaluateLogFilePermissionsMarksUnresolvedSymlinkTargetsIncomplete(t *testing.T) {
	tests := []struct {
		name         string
		configure    func(*logPermissionFixtureReader)
		wantKind     string
		wantContains string
	}{
		{
			name: "directory target",
			configure: func(reader *logPermissionFixtureReader) {
				reader.addSymlink("/var/log/archive", 1, 11, logDirectoryMetadata("/var/log/archive", 1, 20))
			},
			wantKind:     "symlink_directory",
			wantContains: "디렉터리",
		},
		{
			name: "broken target",
			configure: func(reader *logPermissionFixtureReader) {
				reader.addBrokenSymlink("/var/log/current", 1, 11)
			},
			wantKind:     "broken_symlink",
			wantContains: "존재하지 않음",
		},
		{
			name: "symlink cycle",
			configure: func(reader *logPermissionFixtureReader) {
				reader.addSymlinkError("/var/log/loop", 1, 11, syscall.ELOOP)
			},
			wantKind:     "symlink_cycle",
			wantContains: "순환",
		},
		{
			name: "unsupported target",
			configure: func(reader *logPermissionFixtureReader) {
				reader.addSymlink("/var/log/stream", 1, 11, system.FileMetadata{
					Path: "/var/log/stream", FileType: "pipe", Mode: os.ModeNamedPipe | 0o600,
					UID: 0, GID: 0, Device: 1, Inode: 20,
				})
			},
			wantKind:     "unsupported_symlink_target",
			wantContains: "pipe",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newLogPermissionFixtureReader()
			test.configure(reader)
			outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader,
			})
			if outcome.Status != model.StatusUnknown {
				t.Fatalf("status = %s, summary=%q observed=%q, want UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
			}
			if !strings.Contains(outcome.Observed, test.wantContains) {
				t.Fatalf("observed = %q, want %q", outcome.Observed, test.wantContains)
			}
			fact := requireLogInventoryFact(t, outcome)
			if fact["inventory_complete"] != false || fact["boundary_count"] != 1 {
				t.Fatalf("inventory fact = %#v, want one incomplete boundary", fact)
			}
			requireLogBoundaryKind(t, fact, test.wantKind)
		})
	}
}

func TestEvaluateLogFilePermissionsScansCrossDeviceDirectory(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addDirectory("/var/log/archive", 2, 20)
	reader.addRegular("/var/log/archive/bad.log", 2, 21, 1000, 0o666)

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want scanned FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	fact := requireLogInventoryFact(t, outcome)
	if fact["cross_device_mounts"] != 1 || fact["inventory_complete"] != true ||
		fact["regular_files"] != 1 {
		t.Fatalf("inventory fact = %#v, want complete cross-device directory scan", fact)
	}
}

func TestInventoryLogFilesStopsBindMountDirectoryCycles(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.lstat["/var/log/loop"] = logDirectoryMetadata("/var/log/loop", 1, 1)
	reader.stat["/var/log/loop"] = logDirectoryMetadata("/var/log/loop", 1, 1)
	reader.directories["/var/log"] = append(
		reader.directories["/var/log"],
		logFixtureDirEntry{name: "loop"},
	)

	inventory, err := inventoryLogFiles(context.Background(), reader)
	if err != nil {
		t.Fatalf("inventoryLogFiles() error = %v", err)
	}
	if inventory.incomplete {
		t.Fatalf("inventory = %#v, duplicate directory identity should be safely deduplicated", inventory)
	}
	if inventory.directoryAliases != 1 || inventory.directoriesScanned != 1 {
		t.Fatalf("aliases=%d scanned=%d, want one alias and only root scan", inventory.directoryAliases, inventory.directoriesScanned)
	}
}

func TestInventoryLogFilesMarksMissingDirectoryIdentityIncomplete(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addDirectory("/var/log/archive", 0, 0)

	inventory, err := inventoryLogFiles(context.Background(), reader)
	if err != nil {
		t.Fatalf("inventoryLogFiles() error = %v", err)
	}
	if !inventory.incomplete || len(inventory.boundaries) != 1 {
		t.Fatalf("inventory = %#v, want one incomplete identity boundary", inventory)
	}
	if inventory.boundaries[0].Kind != "directory_identity_unavailable" {
		t.Fatalf("boundary = %#v, want directory_identity_unavailable", inventory.boundaries[0])
	}
}

func TestInventoryLogFilesBoundsDirectoryTraversal(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	for index := 0; index < maxLogDirectories; index++ {
		reader.addDirectory(
			fmt.Sprintf("/var/log/d%04d", index),
			1,
			uint64(index+2),
		)
	}

	inventory, err := inventoryLogFiles(context.Background(), reader)
	if err != nil {
		t.Fatalf("inventoryLogFiles() error = %v", err)
	}
	if !inventory.incomplete {
		t.Fatal("directory limit must make inventory incomplete")
	}
	found := false
	for _, boundary := range inventory.boundaries {
		if boundary.Kind == "directory_limit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("boundaries = %#v, want directory_limit", inventory.boundaries)
	}
}

func TestInventoryLogFilesDoesNotAcceptMissingFileIdentity(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addRegular("/var/log/unknown.log", 0, 0, 0, 0o640)

	inventory, err := inventoryLogFiles(context.Background(), reader)
	if err != nil {
		t.Fatalf("inventoryLogFiles() error = %v", err)
	}
	if !inventory.incomplete || len(inventory.files) != 0 {
		t.Fatalf("inventory = %#v, want incomplete inventory without unidentified file", inventory)
	}
	if inventory.boundaries[0].Kind != "file_identity_unavailable" {
		t.Fatalf("boundary = %#v, want file_identity_unavailable", inventory.boundaries[0])
	}
}

func TestEvaluateLogFilePermissionsDoesNotPassWhenDirectoryEntriesChange(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addRegular("/var/log/safe.log", 1, 10, 0, 0o640)
	reader.directorySequences["/var/log"] = [][]os.DirEntry{
		{logFixtureDirEntry{name: "safe.log"}},
		{
			logFixtureDirEntry{name: "safe.log"},
			logFixtureDirEntry{name: "new.log"},
		},
	}

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s, summary=%q observed=%q, want UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "디렉터리 항목이 변경") {
		t.Fatalf("observed = %q, want entry-set mutation reason", outcome.Observed)
	}
	fact := requireLogInventoryFact(t, outcome)
	requireLogBoundaryKind(t, fact, "directory_entries_changed")
}

func TestInventoryLogFilesTreatsVanishedEntryAsSnapshotBoundary(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.directories["/var/log"] = []os.DirEntry{logFixtureDirEntry{name: "rotated.log"}}

	inventory, err := inventoryLogFiles(context.Background(), reader)
	if err != nil {
		t.Fatalf("inventoryLogFiles() error = %v, want bounded path_changed", err)
	}
	if !inventory.incomplete || inventory.boundaryCount != 1 {
		t.Fatalf("inventory = %#v, want one incomplete boundary", inventory)
	}
	if inventory.boundaries[0].Kind != "path_changed" {
		t.Fatalf("boundary = %#v, want path_changed", inventory.boundaries[0])
	}
}

func TestLogInventoryBoundariesAreMemoryBounded(t *testing.T) {
	inventory := logInventory{}
	for index := 0; index < maxLogInventoryBoundaries+25; index++ {
		addLogInventoryBoundary(
			&inventory,
			fmt.Sprintf("/var/log/unsafe-%d", index),
			"fixture",
			"fixture",
		)
	}
	if inventory.boundaryCount != maxLogInventoryBoundaries+25 {
		t.Fatalf("boundaryCount = %d, want complete aggregate count", inventory.boundaryCount)
	}
	if len(inventory.boundaries) != maxLogInventoryBoundaries {
		t.Fatalf("stored boundaries = %d, want cap %d", len(inventory.boundaries), maxLogInventoryBoundaries)
	}
}

func TestEvaluateLogFilePermissionsKeepsKnownViolationWhenInventoryIsIncomplete(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addRegular("/var/log/bad.log", 1, 10, 1000, 0o666)
	reader.addSymlink("/var/log/archive", 1, 11, logDirectoryMetadata("/var/log/archive", 1, 20))

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if len(outcome.Details) != 2 || outcome.Details[1].Label != "추가 확인 필요" {
		t.Fatalf("details = %#v, want violation and incomplete-boundary details", outcome.Details)
	}
	fact := requireLogInventoryFact(t, outcome)
	if fact["inventory_complete"] != false || fact["boundary_count"] != 1 {
		t.Fatalf("inventory fact = %#v, want preserved incomplete boundary", fact)
	}
}

func TestEvaluateLogFilePermissionsDoesNotExposeUnsafeEntryNames(t *testing.T) {
	tests := []struct {
		name      string
		entryName string
	}{
		{name: "ANSI escape", entryName: "auth\x1b[2J.log"},
		{name: "C1 control", entryName: "auth\u009b31m.log"},
		{name: "bidi override", entryName: "auth\u202egol.log"},
		{name: "line separator", entryName: "auth\u2028hidden.log"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newLogPermissionFixtureReader()
			reader.directories["/var/log"] = append(
				reader.directories["/var/log"],
				logFixtureDirEntry{name: test.entryName},
			)

			outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader,
			})
			if outcome.Status != model.StatusUnknown {
				t.Fatalf("status = %s, summary=%q observed=%q, want UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
			}
			rendered := fmt.Sprintf("%v", outcome)
			if strings.Contains(rendered, test.entryName) {
				t.Fatalf("unsafe entry name escaped into outcome: %q", rendered)
			}
			if strings.ContainsAny(rendered, "\x1b\u009b\u202e\u2028") {
				t.Fatalf("terminal control escaped into outcome: %q", rendered)
			}
			fact := requireLogInventoryFact(t, outcome)
			requireLogBoundaryKind(t, fact, "unsupported_name")
			boundaries := fact["boundaries"].([]map[string]string)
			if !strings.Contains(boundaries[0]["path"], "sha256=") {
				t.Fatalf("boundary path = %q, want non-reversible digest label", boundaries[0]["path"])
			}
		})
	}
}

func TestEvaluateLogFilePermissionsDoesNotPassWithPathBasedACLFallback(t *testing.T) {
	base := newLogPermissionFixtureReader()
	base.addRegular("/var/log/safe.log", 1, 10, 0, 0o640)
	runner := logACLFixtureRunner{
		available: true,
		result: executor.Result{
			Executable: "/usr/bin/getfacl",
			Stdout: []byte(strings.Join([]string{
				"# file: /var/log/safe.log",
				"user::rw-",
				"group::r--",
				"other::---",
				"",
			}, "\n")),
		},
	}

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files:    logPermissionBasicReader{reader: base},
		Commands: runner,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s, summary=%q observed=%q, want fail-closed UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "동일 파일 스냅샷") {
		t.Fatalf("observed = %q, want snapshot-boundary reason", outcome.Observed)
	}
}

func TestEvaluateLogFilePermissionsRejectsChangedNativeACLSnapshot(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addRegular("/var/log/safe.log", 1, 10, 0, 0o640)
	reader.xattrMetadata["/var/log/safe.log"] = system.FileMetadata{
		Path: "/var/log/safe.log", FileType: "regular", Mode: 0o640,
		UID: 0, GID: 0, Device: 1, Inode: 11,
	}

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s, summary=%q observed=%q, want UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "경로 대상이 변경") {
		t.Fatalf("observed = %q, want changed-target reason", outcome.Observed)
	}
}

func TestInventoryLogFilesAllowsExactFileLimitAndRejectsConfirmedOverflow(t *testing.T) {
	tests := []struct {
		name           string
		fileCount      int
		wantIncomplete bool
	}{
		{name: "exact limit", fileCount: maxLogFiles},
		{name: "confirmed overflow", fileCount: maxLogFiles + 1, wantIncomplete: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newLogPermissionFixtureReader()
			for index := 0; index < test.fileCount; index++ {
				reader.addRegular(
					fmt.Sprintf("/var/log/file-%05d.log", index),
					1,
					uint64(index+10),
					0,
					0o640,
				)
			}

			inventory, err := inventoryLogFiles(context.Background(), reader)
			if err != nil {
				t.Fatalf("inventoryLogFiles() error = %v", err)
			}
			if inventory.incomplete != test.wantIncomplete {
				t.Fatalf("inventory incomplete = %t, want %t", inventory.incomplete, test.wantIncomplete)
			}
			if len(inventory.files) != maxLogFiles {
				t.Fatalf("regular files = %d, want %d", len(inventory.files), maxLogFiles)
			}
			if test.wantIncomplete {
				requireLogInventoryBoundary(t, inventory, "file_limit")
			}
		})
	}
}

func TestInventoryLogFilesBoundsTotalDirectoryEntries(t *testing.T) {
	tests := []struct {
		name           string
		entryCount     int
		wantIncomplete bool
	}{
		{name: "exact limit", entryCount: maxLogEntries},
		{name: "confirmed overflow", entryCount: maxLogEntries + 1, wantIncomplete: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newLogPermissionFixtureReader()
			for index := 0; index < test.entryCount; index++ {
				reader.addSpecial(
					fmt.Sprintf("/var/log/entry-%05d", index),
					1,
					uint64(index+10),
					"pipe",
					os.ModeNamedPipe|0o600,
				)
			}

			inventory, err := inventoryLogFiles(context.Background(), reader)
			if err != nil {
				t.Fatalf("inventoryLogFiles() error = %v", err)
			}
			if inventory.incomplete != test.wantIncomplete {
				t.Fatalf("inventory incomplete = %t, want %t", inventory.incomplete, test.wantIncomplete)
			}
			if inventory.entriesScanned != maxLogEntries {
				t.Fatalf("entries scanned = %d, want %d", inventory.entriesScanned, maxLogEntries)
			}
			if test.wantIncomplete {
				requireLogInventoryBoundary(t, inventory, "entry_limit")
			}
		})
	}
}

func TestEvaluateLogFilePermissionsTreatsACLRotationAsSnapshotBoundary(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "removed by logrotate", err: os.ErrNotExist},
		{name: "changed while reading ACL", err: system.ErrFileChanged},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newLogPermissionFixtureReader()
			reader.addRegular("/var/log/rotated.log", 1, 10, 0, 0o640)
			reader.xattrErrors["/var/log/rotated.log"] = test.err

			outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader,
			})
			if outcome.Status != model.StatusUnknown || outcome.ErrorCode != "" {
				t.Fatalf("outcome = %#v, want snapshot-boundary UNKNOWN", outcome)
			}
			if !strings.Contains(outcome.Observed, "ACL 수집 중") {
				t.Fatalf("observed = %q, want ACL snapshot boundary", outcome.Observed)
			}
		})
	}
}

func TestEvaluateLogFilePermissionsKeepsModeFailureWhenACLPathRotates(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addRegular("/var/log/insecure.log", 1, 10, 0, 0o666)
	reader.xattrErrors["/var/log/insecure.log"] = os.ErrNotExist

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("outcome = %#v, want preserved mode FAIL", outcome)
	}
	if !strings.Contains(outcome.Observed, "쓰기 권한") {
		t.Fatalf("observed = %q, want stable mode violation", outcome.Observed)
	}
	if len(outcome.Details) != 2 || outcome.Details[1].Label != "추가 확인 필요" {
		t.Fatalf("details = %#v, want ACL rotation boundary next to violation", outcome.Details)
	}
}

func TestEvaluateLogFilePermissionsRevalidatesFileIdentityAfterACL(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	initial := system.FileMetadata{
		Path: "/var/log/safe.log", FileType: "regular", Mode: 0o640,
		UID: 0, GID: 0, Device: 1, Inode: 10,
	}
	changed := initial
	changed.Inode = 11
	reader.addRegular(initial.Path, initial.Device, initial.Inode, initial.UID, initial.Mode)
	reader.statSequences[initial.Path] = []system.FileMetadata{initial, initial, changed}

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("outcome = %#v, want final identity UNKNOWN", outcome)
	}
	fact := requireLogInventoryFact(t, outcome)
	requireLogBoundaryKind(t, fact, "file_changed_after_acl")
}

func TestEvaluateLogFilePermissionsDropsStaleModeFailureWhenFinalTargetChanges(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	initial := system.FileMetadata{
		Path: "/var/log/insecure.log", FileType: "regular", Mode: 0o666,
		UID: 0, GID: 0, Device: 1, Inode: 10,
	}
	changed := initial
	changed.Mode = 0o640
	changed.Inode = 11
	reader.addRegular(initial.Path, initial.Device, initial.Inode, initial.UID, initial.Mode)
	reader.statSequences[initial.Path] = []system.FileMetadata{initial, initial, changed}

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("outcome = %#v, want changed stale violation UNKNOWN", outcome)
	}
	if strings.Contains(outcome.Observed, "쓰기 권한") {
		t.Fatalf("observed = %q, must not retain the initial mode violation", outcome.Observed)
	}
	fact := requireLogInventoryFact(t, outcome)
	requireLogBoundaryKind(t, fact, "file_changed_after_acl")
}

func TestEvaluateLogFilePermissionsKeepsOtherStableFailureWhenOneFinalTargetChanges(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	changedInitial := system.FileMetadata{
		Path: "/var/log/changed.log", FileType: "regular", Mode: 0o666,
		UID: 0, GID: 0, Device: 1, Inode: 10,
	}
	changedFinal := changedInitial
	changedFinal.Mode = 0o640
	changedFinal.Inode = 11
	reader.addRegular(
		changedInitial.Path,
		changedInitial.Device,
		changedInitial.Inode,
		changedInitial.UID,
		changedInitial.Mode,
	)
	reader.statSequences[changedInitial.Path] = []system.FileMetadata{
		changedInitial,
		changedInitial,
		changedFinal,
	}
	reader.addRegular("/var/log/stable.log", 1, 20, 0, 0o666)

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("outcome = %#v, want other stable violation FAIL", outcome)
	}
	if !strings.Contains(outcome.Observed, "/var/log/stable.log") {
		t.Fatalf("observed = %q, want the stable violation", outcome.Observed)
	}
	if strings.Contains(outcome.Observed, "/var/log/changed.log") {
		t.Fatalf("observed = %q, must not retain the changed target violation", outcome.Observed)
	}
}

func TestEvaluateLogFilePermissionsRevalidatesDirectoryEntriesAfterACL(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.addRegular("/var/log/safe.log", 1, 10, 0, 0o640)
	reader.directorySequences["/var/log"] = [][]os.DirEntry{
		{logFixtureDirEntry{name: "safe.log"}},
		{logFixtureDirEntry{name: "safe.log"}},
		{
			logFixtureDirEntry{name: "safe.log"},
			logFixtureDirEntry{name: "new.log"},
		},
	}

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("outcome = %#v, want final entry-set UNKNOWN", outcome)
	}
	fact := requireLogInventoryFact(t, outcome)
	requireLogBoundaryKind(t, fact, "directory_entries_changed_after_acl")
}

func TestEvaluateLogFilePermissionsRevalidatesEmptyDirectoryBeforeNotApplicable(t *testing.T) {
	reader := newLogPermissionFixtureReader()
	reader.directorySequences["/var/log"] = [][]os.DirEntry{
		{},
		{},
		{logFixtureDirEntry{name: "new.log"}},
	}

	outcome := evaluateLogFilePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("outcome = %#v, want changed empty inventory UNKNOWN", outcome)
	}
	fact := requireLogInventoryFact(t, outcome)
	requireLogBoundaryKind(t, fact, "directory_entries_changed_after_acl")
}

func requireLogInventoryFact(t *testing.T, outcome evaluator.Outcome) map[string]any {
	t.Helper()
	for _, evidence := range outcome.Evidence {
		if evidence.Source == "/var/log" && evidence.Fact != nil {
			return evidence.Fact
		}
	}
	t.Fatal("/var/log inventory fact is missing")
	return nil
}

func requireLogBoundaryKind(t *testing.T, fact map[string]any, want string) {
	t.Helper()
	boundaries, ok := fact["boundaries"].([]map[string]string)
	if !ok {
		t.Fatalf("boundaries = %#v, want []map[string]string", fact["boundaries"])
	}
	for _, boundary := range boundaries {
		if boundary["kind"] == want {
			return
		}
	}
	t.Fatalf("boundaries = %#v, want kind %q", boundaries, want)
}

func requireLogInventoryBoundary(t *testing.T, inventory logInventory, want string) {
	t.Helper()
	for _, boundary := range inventory.boundaries {
		if boundary.Kind == want {
			return
		}
	}
	t.Fatalf("boundaries = %#v, want kind %q", inventory.boundaries, want)
}

type logACLXAttrReader struct{}

func (logACLXAttrReader) ReadXAttrs(
	ctx context.Context,
	path string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	if !followFinalSymlink {
		return nil, system.FileMetadata{}, errors.New("log ACL inspection must follow an inventoried final symlink")
	}
	return map[string][]byte{}, system.FileMetadata{
		Path: path, FileType: "regular", Mode: 0o640, UID: 0, GID: 0,
	}, nil
}

func (logACLXAttrReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("unexpected file read")
}

func (logACLXAttrReader) Stat(path string) (system.FileMetadata, error) {
	return system.FileMetadata{Path: path, FileType: "regular", Mode: 0o640, UID: 0, GID: 0}, nil
}

func (reader logACLXAttrReader) Lstat(path string) (system.FileMetadata, error) {
	return reader.Stat(path)
}

func (logACLXAttrReader) ReadDir(string) ([]os.DirEntry, error) {
	return nil, errors.New("unexpected directory read")
}

func (logACLXAttrReader) Exists(string) (bool, error) {
	return true, nil
}

type logACLFixtureRunner struct {
	available bool
	result    executor.Result
	err       error
}

func (runner logACLFixtureRunner) Available(name string) bool {
	return name == "getfacl" && runner.available
}

func (runner logACLFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "getfacl" {
		return executor.Result{}, errors.New("unexpected fixture command")
	}
	return runner.result, runner.err
}

type logUnexpectedCommandRunner struct{}

func (logUnexpectedCommandRunner) Available(string) bool {
	return false
}

func (logUnexpectedCommandRunner) Run(context.Context, executor.Spec) (executor.Result, error) {
	return executor.Result{}, errors.New("unexpected command")
}

type logPermissionFixtureReader struct {
	directories        map[string][]os.DirEntry
	directorySequences map[string][][]os.DirEntry
	directoryReads     map[string]int
	lstat              map[string]system.FileMetadata
	stat               map[string]system.FileMetadata
	statSequences      map[string][]system.FileMetadata
	statReads          map[string]int
	statErrors         map[string]error
	xattrMetadata      map[string]system.FileMetadata
	xattrErrors        map[string]error
}

func newLogPermissionFixtureReader() *logPermissionFixtureReader {
	return &logPermissionFixtureReader{
		directories:        map[string][]os.DirEntry{"/var/log": {}},
		directorySequences: make(map[string][][]os.DirEntry),
		directoryReads:     make(map[string]int),
		lstat: map[string]system.FileMetadata{
			"/var/log": logDirectoryMetadata("/var/log", 1, 1),
		},
		stat: map[string]system.FileMetadata{
			"/var/log": logDirectoryMetadata("/var/log", 1, 1),
		},
		statSequences: make(map[string][]system.FileMetadata),
		statReads:     make(map[string]int),
		statErrors:    make(map[string]error),
		xattrMetadata: make(map[string]system.FileMetadata),
		xattrErrors:   make(map[string]error),
	}
}

func (reader *logPermissionFixtureReader) addRegular(path string, device, inode uint64, uid int, mode os.FileMode) {
	metadata := system.FileMetadata{
		Path: path, FileType: "regular", Mode: mode,
		UID: uid, GID: uid, Device: device, Inode: inode,
	}
	reader.lstat[path] = metadata
	reader.stat[path] = metadata
	reader.addEntry(path)
}

func (reader *logPermissionFixtureReader) addDirectory(path string, device, inode uint64) {
	metadata := logDirectoryMetadata(path, device, inode)
	reader.lstat[path] = metadata
	reader.stat[path] = metadata
	reader.directories[path] = nil
	reader.addEntry(path)
}

func (reader *logPermissionFixtureReader) addSpecial(
	path string,
	device, inode uint64,
	fileType string,
	mode os.FileMode,
) {
	metadata := system.FileMetadata{
		Path: path, FileType: fileType, Mode: mode,
		UID: 0, GID: 0, Device: device, Inode: inode,
	}
	reader.lstat[path] = metadata
	reader.stat[path] = metadata
	reader.addEntry(path)
}

func (reader *logPermissionFixtureReader) addSymlink(path string, device, inode uint64, target system.FileMetadata) {
	reader.lstat[path] = system.FileMetadata{
		Path: path, FileType: "symlink", Mode: os.ModeSymlink | 0o777,
		UID: 0, GID: 0, Device: device, Inode: inode, LinkTarget: "/target",
	}
	reader.stat[path] = target
	reader.addEntry(path)
}

func (reader *logPermissionFixtureReader) addBrokenSymlink(path string, device, inode uint64) {
	reader.lstat[path] = system.FileMetadata{
		Path: path, FileType: "symlink", Mode: os.ModeSymlink | 0o777,
		UID: 0, GID: 0, Device: device, Inode: inode, LinkTarget: "/missing",
	}
	reader.addEntry(path)
}

func (reader *logPermissionFixtureReader) addSymlinkError(path string, device, inode uint64, err error) {
	reader.lstat[path] = system.FileMetadata{
		Path: path, FileType: "symlink", Mode: os.ModeSymlink | 0o777,
		UID: 0, GID: 0, Device: device, Inode: inode, LinkTarget: path,
	}
	reader.statErrors[path] = &os.PathError{Op: "stat", Path: path, Err: err}
	reader.addEntry(path)
}

func (reader *logPermissionFixtureReader) addEntry(filePath string) {
	directory := path.Dir(filePath)
	reader.directories[directory] = append(reader.directories[directory], logFixtureDirEntry{name: path.Base(filePath)})
}

func (reader *logPermissionFixtureReader) ReadXAttrs(
	ctx context.Context,
	filePath string,
	_ []string,
	_ int64,
	_ bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	if err, exists := reader.xattrErrors[filePath]; exists {
		return nil, system.FileMetadata{}, err
	}
	if metadata, exists := reader.xattrMetadata[filePath]; exists {
		return map[string][]byte{}, metadata, nil
	}
	metadata, err := reader.Stat(filePath)
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	return map[string][]byte{}, metadata, nil
}

func (*logPermissionFixtureReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("unexpected file read")
}

func (reader *logPermissionFixtureReader) Stat(filePath string) (system.FileMetadata, error) {
	if err, exists := reader.statErrors[filePath]; exists {
		return system.FileMetadata{}, err
	}
	if sequence, exists := reader.statSequences[filePath]; exists && len(sequence) > 0 {
		index := reader.statReads[filePath]
		reader.statReads[filePath] = index + 1
		if index >= len(sequence) {
			index = len(sequence) - 1
		}
		return sequence[index], nil
	}
	metadata, exists := reader.stat[filePath]
	if !exists {
		return system.FileMetadata{}, os.ErrNotExist
	}
	return metadata, nil
}

func (reader *logPermissionFixtureReader) Lstat(filePath string) (system.FileMetadata, error) {
	metadata, exists := reader.lstat[filePath]
	if !exists {
		return system.FileMetadata{}, os.ErrNotExist
	}
	return metadata, nil
}

func (reader *logPermissionFixtureReader) ReadDir(directory string) ([]os.DirEntry, error) {
	if sequence, exists := reader.directorySequences[directory]; exists && len(sequence) > 0 {
		index := reader.directoryReads[directory]
		reader.directoryReads[directory] = index + 1
		if index >= len(sequence) {
			index = len(sequence) - 1
		}
		return append([]os.DirEntry(nil), sequence[index]...), nil
	}
	entries, exists := reader.directories[directory]
	if !exists {
		return nil, os.ErrNotExist
	}
	return append([]os.DirEntry(nil), entries...), nil
}

func (reader *logPermissionFixtureReader) ReadDirBounded(
	directory string,
	limit int,
) ([]os.DirEntry, bool, error) {
	entries, err := reader.ReadDir(directory)
	if err != nil {
		return nil, false, err
	}
	if len(entries) <= limit {
		return entries, false, nil
	}
	return entries[:limit], true, nil
}

func (reader *logPermissionFixtureReader) Exists(filePath string) (bool, error) {
	_, err := reader.Lstat(filePath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

type logPermissionBasicReader struct {
	reader *logPermissionFixtureReader
}

func (reader logPermissionBasicReader) ReadFile(ctx context.Context, path string, limit int64) ([]byte, system.FileMetadata, error) {
	return reader.reader.ReadFile(ctx, path, limit)
}

func (reader logPermissionBasicReader) Stat(path string) (system.FileMetadata, error) {
	return reader.reader.Stat(path)
}

func (reader logPermissionBasicReader) Lstat(path string) (system.FileMetadata, error) {
	return reader.reader.Lstat(path)
}

func (reader logPermissionBasicReader) ReadDir(path string) ([]os.DirEntry, error) {
	return reader.reader.ReadDir(path)
}

func (reader logPermissionBasicReader) Exists(path string) (bool, error) {
	return reader.reader.Exists(path)
}

type logFixtureDirEntry struct {
	name string
}

func (entry logFixtureDirEntry) Name() string         { return entry.name }
func (logFixtureDirEntry) IsDir() bool                { return false }
func (logFixtureDirEntry) Type() os.FileMode          { return 0 }
func (logFixtureDirEntry) Info() (os.FileInfo, error) { return nil, errors.New("unexpected info") }

func logDirectoryMetadata(path string, device, inode uint64) system.FileMetadata {
	return system.FileMetadata{
		Path: path, FileType: "directory", Mode: os.ModeDir | 0o755,
		UID: 0, GID: 0, Device: device, Inode: inode,
	}
}
