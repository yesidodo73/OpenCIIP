package filecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestInspectPathFollowingSymlinksAcceptsStableRootedTarget(t *testing.T) {
	target := directoryMetadata("/usr/bin", 1, 20)
	reader := newHomePathFixtureReader()
	reader.lstat["/bin"] = []system.FileMetadata{symlinkMetadata("/bin", "/usr/bin", 1, 10)}
	reader.lstat["/usr"] = []system.FileMetadata{directoryMetadata("/usr", 1, 19)}
	reader.lstat["/usr/bin"] = []system.FileMetadata{target}
	reader.stat["/bin"] = []system.FileMetadata{withPath(target, "/bin")}

	inspected, err := inspectPathFollowingSymlinks(reader, "/bin")
	if err != nil {
		t.Fatalf("inspectPathFollowingSymlinks() error = %v", err)
	}
	if !inspected.Exists || inspected.Unknown != "" || inspected.ResolvedPath != "/usr/bin" {
		t.Fatalf("inspection = %#v, want stable /usr/bin target", inspected)
	}
	if inspected.Metadata.FileType != "directory" {
		t.Fatalf("metadata = %#v, want directory", inspected.Metadata)
	}
}

func TestInspectPathFollowingSymlinksRejectsMutatedChain(t *testing.T) {
	target := directoryMetadata("/usr/bin", 1, 20)
	reader := newHomePathFixtureReader()
	reader.lstat["/bin"] = []system.FileMetadata{
		symlinkMetadata("/bin", "/usr/bin", 1, 10),
		symlinkMetadata("/bin", "/opt/bin", 1, 11),
	}
	reader.lstat["/usr"] = []system.FileMetadata{directoryMetadata("/usr", 1, 19)}
	reader.lstat["/usr/bin"] = []system.FileMetadata{target}
	reader.stat["/bin"] = []system.FileMetadata{withPath(target, "/bin")}

	inspected, err := inspectPathFollowingSymlinks(reader, "/bin")
	if err != nil {
		t.Fatalf("inspectPathFollowingSymlinks() error = %v", err)
	}
	if inspected.Unknown == "" || !strings.Contains(inspected.Unknown, "변경") {
		t.Fatalf("inspection = %#v, want mutation ambiguity", inspected)
	}
}

func TestInspectPathFollowingSymlinksLimitsCycles(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/loop"] = []system.FileMetadata{symlinkMetadata("/loop", "/loop", 1, 10)}

	inspected, err := inspectPathFollowingSymlinks(reader, "/loop")
	if err != nil {
		t.Fatalf("inspectPathFollowingSymlinks() error = %v", err)
	}
	if inspected.Unknown == "" || !strings.Contains(inspected.Unknown, "40개") {
		t.Fatalf("inspection = %#v, want bounded symlink ambiguity", inspected)
	}
}

func TestEvaluateHomePermissionsChecksEveryAccountSharingAHome(t *testing.T) {
	reader := newHomePathFixtureReader()
	shared := directoryMetadata("/shared", 1, 30)
	shared.UID = 1000
	shared.GID = 1000
	shared.Mode = os.ModeDir | 0o750
	reader.lstat["/shared"] = []system.FileMetadata{shared}
	reader.stat["/shared"] = []system.FileMetadata{shared}
	runner := homeExistsFixtureRunner{
		passwd: strings.Join([]string{
			"first:x:1000:1000::/shared:/bin/bash",
			"service:x:999:999::/shared:/sbin/nologin",
		}, "\n"),
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "service:/shared") ||
		!strings.Contains(outcome.Observed, "소유자 UID 1000, 계정 UID 999") {
		t.Fatalf("observed = %q, want the mismatched shared-home account", outcome.Observed)
	}
	if strings.Contains(outcome.Observed, "여러 계정이 같은 홈") ||
		strings.Contains(outcome.Observed, "비로그인 계정") {
		t.Fatalf("observed = %q, want evidence-based ownership verdict", outcome.Observed)
	}
}

func TestEvaluateHomePermissionsAllowsSharedHomeWhenEffectiveUIDMatches(t *testing.T) {
	reader := newHomePathFixtureReader()
	shared := directoryMetadata("/shared", 1, 30)
	shared.UID = 1000
	shared.GID = 1000
	shared.Mode = os.ModeDir | 0o750
	reader.lstat["/shared"] = []system.FileMetadata{shared}
	reader.stat["/shared"] = []system.FileMetadata{shared}
	runner := homeExistsFixtureRunner{
		passwd: strings.Join([]string{
			"first:x:1000:1000::/shared:/bin/bash",
			"alias:x:1000:1000::/shared:/sbin/nologin",
		}, "\n"),
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %s, summary=%q observed=%q, want PASS", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if outcome.Observed != "계정별 홈 소유권 및 권한 2건 확인" {
		t.Fatalf("observed = %q, want two checked account-home mappings", outcome.Observed)
	}
}

func TestEvaluateHomePermissionsChecksStandaloneNonLoginAccount(t *testing.T) {
	reader := newHomePathFixtureReader()
	home := directoryMetadata("/service-home", 1, 30)
	home.UID = 999
	home.GID = 999
	home.Mode = os.ModeDir | 0o750
	reader.lstat["/service-home"] = []system.FileMetadata{home}
	reader.stat["/service-home"] = []system.FileMetadata{home}
	runner := homeExistsFixtureRunner{
		passwd:  "service:x:999:999::/service-home:/sbin/nologin",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %s summary=%q observed=%q, want PASS", outcome.Status, outcome.Summary, outcome.Observed)
	}
}

func TestEvaluateHomePermissionsRejectsChangedAccountInventory(t *testing.T) {
	reader := newHomePathFixtureReader()
	home := directoryMetadata("/shared", 1, 30)
	home.UID = 1000
	home.GID = 1000
	home.Mode = os.ModeDir | 0o750
	reader.lstat["/shared"] = []system.FileMetadata{home}
	reader.stat["/shared"] = []system.FileMetadata{home}
	runner := &sequencedUserEnvironmentRunner{
		passwd: []string{
			"first:x:1000:1000::/shared:/bin/bash",
			"first:x:1001:1000::/shared:/bin/bash",
		},
		findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
	}

	outcome := evaluateHomePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown ||
		outcome.UnknownReason != model.UnknownAmbiguousResult ||
		!strings.Contains(outcome.Observed, "계정") {
		t.Fatalf("outcome = %#v, want account-inventory UNKNOWN", outcome)
	}
}

func TestEvaluateHomePermissionsRejectsChangedPathSnapshot(t *testing.T) {
	reader := newHomePathFixtureReader()
	before := directoryMetadata("/shared", 1, 30)
	before.UID = 1000
	before.GID = 1000
	before.Mode = os.ModeDir | 0o750
	after := before
	after.Inode = 31
	reader.lstat["/shared"] = []system.FileMetadata{before, after}
	reader.stat["/shared"] = []system.FileMetadata{before, after}
	runner := homeExistsFixtureRunner{
		passwd:  "first:x:1000:1000::/shared:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown ||
		outcome.UnknownReason != model.UnknownAmbiguousResult ||
		!strings.Contains(outcome.Summary, "경로") {
		t.Fatalf("outcome = %#v, want changed-path UNKNOWN", outcome)
	}
}

func TestEvaluateHomePermissionsRejectsChangedACLSnapshot(t *testing.T) {
	base := newHomePathFixtureReader()
	home := directoryMetadata("/shared", 1, 30)
	home.UID = 1000
	home.GID = 1000
	home.Mode = os.ModeDir | 0o750
	base.lstat["/shared"] = []system.FileMetadata{home}
	base.stat["/shared"] = []system.FileMetadata{home}
	reader := &sequencedACLHomePathReader{
		homePathFixtureReader: base,
		acl: [][]byte{
			mustTestPOSIXACLXAttr(t, "user::rwx\ngroup::r-x\nother::---\n"),
			mustTestPOSIXACLXAttr(t, "user::rwx\ngroup::r-x\nother::r--\n"),
		},
	}
	runner := homeExistsFixtureRunner{
		passwd:  "first:x:1000:1000::/shared:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomePermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown ||
		outcome.UnknownReason != model.UnknownAmbiguousResult ||
		!strings.Contains(outcome.Summary, "ACL") {
		t.Fatalf("outcome = %#v, want changed-ACL UNKNOWN", outcome)
	}
	if reader.aclCalls != 2 {
		t.Fatalf("ACL snapshot calls = %d, want 2", reader.aclCalls)
	}
	for _, follow := range reader.followFinal {
		if follow {
			t.Fatalf("ACL follow modes = %#v, want no symlink following", reader.followFinal)
		}
	}
}

func TestEvaluateHomePermissionsFailsClosedAtResourceLimits(t *testing.T) {
	reader := newHomePathFixtureReader()
	home := directoryMetadata("/shared", 1, 30)
	home.UID = 1000
	home.GID = 1000
	home.Mode = os.ModeDir | 0o750
	reader.lstat["/shared"] = []system.FileMetadata{home}
	reader.stat["/shared"] = []system.FileMetadata{home}
	runner := homeExistsFixtureRunner{
		passwd: strings.Join([]string{
			"first:x:1000:1000::/shared:/bin/bash",
			"second:x:1001:1001::/shared:/bin/bash",
		}, "\n"),
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	accountLimited := evaluateHomePermissionsWithLimits(
		context.Background(),
		evaluator.Environment{Files: reader, Commands: runner},
		1,
		10,
		100,
		1<<20,
		1_000,
	)
	if accountLimited.Status != model.StatusUnknown ||
		accountLimited.UnknownReason != model.UnknownInsufficientEvidence {
		t.Fatalf("account-limited outcome = %#v, want insufficient-evidence UNKNOWN", accountLimited)
	}

	pathLimited := evaluateHomePermissionsWithLimits(
		context.Background(),
		evaluator.Environment{Files: reader, Commands: runner},
		10,
		10,
		1,
		1<<20,
		1_000,
	)
	if pathLimited.Status != model.StatusUnknown ||
		pathLimited.UnknownReason != model.UnknownInsufficientEvidence ||
		!strings.Contains(pathLimited.Summary, "상한") {
		t.Fatalf("path-limited outcome = %#v, want insufficient-evidence UNKNOWN", pathLimited)
	}
}

func TestEvaluateHomeExistsChecksSharedHomeOnce(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/shared"] = []system.FileMetadata{directoryMetadata("/shared", 1, 30)}
	reader.stat["/shared"] = []system.FileMetadata{directoryMetadata("/shared", 1, 30)}
	runner := homeExistsFixtureRunner{
		passwd: strings.Join([]string{
			"first:x:1000:1000::/shared:/bin/bash",
			"service:x:999:999::/shared:/sbin/nologin",
		}, "\n"),
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %s, summary=%q observed=%q", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "1개") {
		t.Fatalf("observed = %q, want one canonical home check", outcome.Observed)
	}
}

func TestEvaluateHomeExistsFailsMissingNonLoginHome(t *testing.T) {
	reader := newHomePathFixtureReader()
	runner := homeExistsFixtureRunner{
		passwd:  "service:x:999:999::/missing:/sbin/nologin",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "홈 디렉터리가 없음") {
		t.Fatalf("observed = %q, want missing-home violation", outcome.Observed)
	}
}

func TestEvaluateHomeExistsFailsNonDirectoryHome(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/dev"] = []system.FileMetadata{directoryMetadata("/dev", 1, 40)}
	device := system.FileMetadata{
		Path: "/dev/null", FileType: "device", Mode: os.ModeDevice | 0o666,
		UID: 0, GID: 0, Device: 1, Inode: 41,
	}
	reader.lstat["/dev/null"] = []system.FileMetadata{device}
	reader.stat["/dev/null"] = []system.FileMetadata{device}
	runner := homeExistsFixtureRunner{
		passwd:  "service:x:999:999::/dev/null:/sbin/nologin",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "디렉터리가 아님") {
		t.Fatalf("observed = %q, want non-directory violation", outcome.Observed)
	}
}

func TestEvaluateHomeExistsKeepsRemoteHomeUnknown(t *testing.T) {
	reader := newHomePathFixtureReader()
	runner := homeExistsFixtureRunner{
		passwd:  "remote:x:1000:1000::/remote/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"},{"target":"/remote","fstype":"nfs4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s, summary=%q observed=%q", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "remote") {
		t.Fatalf("observed = %q, want remote-mount ambiguity", outcome.Observed)
	}
}

func TestEvaluateHomeExistsReclassifiesSymlinkTargetMount(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 50)}
	reader.lstat["/home/remote"] = []system.FileMetadata{symlinkMetadata("/home/remote", "/remote/user", 1, 51)}
	reader.lstat["/remote"] = []system.FileMetadata{directoryMetadata("/remote", 2, 60)}
	target := directoryMetadata("/remote/user", 2, 61)
	reader.lstat["/remote/user"] = []system.FileMetadata{target}
	reader.stat["/home/remote"] = []system.FileMetadata{withPath(target, "/home/remote")}
	runner := homeExistsFixtureRunner{
		passwd:  "remote:x:1000:1000::/home/remote:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"},{"target":"/remote","fstype":"nfs4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s, summary=%q observed=%q", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "심볼릭 링크 대상") || !strings.Contains(outcome.Observed, "remote") {
		t.Fatalf("observed = %q, want resolved remote-mount ambiguity", outcome.Observed)
	}
}

func TestEvaluateHomeExistsFailsEmptyConfiguredHome(t *testing.T) {
	reader := newHomePathFixtureReader()
	runner := homeExistsFixtureRunner{
		passwd:  "service:x:999:999:::/sbin/nologin",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "홈 경로가 지정되지 않음") {
		t.Fatalf("observed = %q, want empty-home violation", outcome.Observed)
	}
}

func TestEvaluateHomeExistsKeepsEmptyHomeFailureWhenMountInventoryFails(t *testing.T) {
	reader := newHomePathFixtureReader()
	runner := homeExistsFixtureRunner{
		passwd: strings.Join([]string{
			"empty:x:999:999:::/sbin/nologin",
			"user:x:1000:1000::/home/user:/bin/bash",
		}, "\n"),
		findmntErr: errors.New("findmnt failed"),
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "홈 경로가 지정되지 않음") {
		t.Fatalf("observed = %q, want empty-home violation", outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "/home/user") ||
		!strings.Contains(outcome.Observed, "점검하지 못함") {
		t.Fatalf("observed = %q, want unverified other home", outcome.Observed)
	}
	foundMountError := false
	for _, evidence := range outcome.Evidence {
		if evidence.Source == "home-mount-inventory-error" &&
			evidence.Fact["unverified_home_count"] == 1 {
			foundMountError = true
		}
	}
	if !foundMountError {
		t.Fatal("home-mount-inventory-error evidence is missing")
	}
}

func TestEvaluateHomeExistsKeepsDefiniteFailureWhenMountInventoryExceedsLimit(t *testing.T) {
	runner := homeExistsFixtureRunner{
		passwd: strings.Join([]string{
			"empty:x:999:999:::/sbin/nologin",
			"user:x:1000:1000::/home/user:/bin/bash",
		}, "\n"),
		findmnt: findmntFixtureWithMountCount(maximumHomeMountEntries + 1),
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: runner,
	})
	if outcome.Status != model.StatusFail || outcome.ErrorCode != "" {
		t.Fatalf("outcome = %#v, want definite empty-home FAIL", outcome)
	}
	if !strings.Contains(outcome.Observed, "홈 경로가 지정되지 않음") ||
		!strings.Contains(outcome.Observed, "마운트 목록이 안전한 점검 한도를 초과함") {
		t.Fatalf("observed = %q, want failure and bounded unknown", outcome.Observed)
	}
	if !containsEvidenceSource(outcome.Evidence, "home-mount-inventory-limit") {
		t.Fatalf("evidence = %#v, want mount inventory limit fact", outcome.Evidence)
	}
}

func TestEvaluateHomeExistsKeepsMountInventoryErrorWithoutEmptyHome(t *testing.T) {
	reader := newHomePathFixtureReader()
	runner := homeExistsFixtureRunner{
		passwd:     "user:x:1000:1000::/home/user:/bin/bash",
		findmntErr: errors.New("findmnt failed"),
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusError || outcome.ErrorCode != "home_mounts_failed" {
		t.Fatalf("outcome = %#v, want existing home_mounts_failed ERROR", outcome)
	}
}

func TestEvaluateHomeExistsNormalizesEquivalentAbsolutePath(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	target := directoryMetadata("/home/user", 1, 21)
	reader.lstat["/home/user"] = []system.FileMetadata{target}
	reader.stat["/home/user"] = []system.FileMetadata{target}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/./user/:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %s, summary=%q observed=%q, want PASS", outcome.Status, outcome.Summary, outcome.Observed)
	}
	foundNormalization := false
	for _, evidence := range outcome.Evidence {
		if evidence.Source == "home-path-normalization" &&
			evidence.Fact["normalization_count"] == 1 {
			foundNormalization = true
		}
	}
	if !foundNormalization {
		t.Fatal("home-path-normalization evidence is missing")
	}
}

func TestEvaluateHomeExistsDoesNotLexicallyCollapseParentComponents(t *testing.T) {
	reader := newHomePathFixtureReader()
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/link/../user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s, summary=%q observed=%q, want UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "상위 경로 구성요소") {
		t.Fatalf("observed = %q, want unsafe-normalization reason", outcome.Observed)
	}
}

func TestEvaluateHomeExistsDoesNotExposeUnsafeConfiguredPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "ANSI escape", path: "/home/\x1b[2Juser"},
		{name: "C1 control", path: "/home/\u009b31muser"},
		{name: "bidi override", path: "/home/\u202eresu"},
		{name: "line separator", path: "/home/\u2028user"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := homeExistsFixtureRunner{
				passwd:  "user:x:1000:1000::" + test.path + ":/bin/bash",
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: newHomePathFixtureReader(), Commands: runner,
			})
			if outcome.Status != model.StatusUnknown {
				t.Fatalf("status = %s, summary=%q observed=%q, want UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
			}
			rendered := fmt.Sprintf("%v", outcome)
			if strings.Contains(rendered, test.path) {
				t.Fatalf("unsafe configured path escaped into outcome: %q", rendered)
			}
			if strings.ContainsAny(rendered, "\x1b\u009b\u202e\u2028") {
				t.Fatalf("terminal control escaped into outcome: %q", rendered)
			}
			if !strings.Contains(outcome.Observed, "(유효하지 않은 경로)") {
				t.Fatalf("observed = %q, want safe placeholder", outcome.Observed)
			}
		})
	}
}

func TestEvaluateHomeExistsBoundsConfiguredPathBeforeTraversal(t *testing.T) {
	oversized := "/" + strings.Repeat("a", maximumAbsoluteSystemPathBytes)
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::" + oversized + ":/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: newHomePathFixtureReader(), Commands: runner,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s, summary=%q observed=%q, want UNKNOWN", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if strings.Contains(outcome.Observed, oversized) ||
		!strings.Contains(outcome.Observed, "(유효하지 않은 경로)") {
		t.Fatalf("observed = %q, want bounded safe placeholder", outcome.Observed)
	}
}

func TestEvaluateHomeExistsDoesNotPassWhenAccountInventoryChanges(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	target := directoryMetadata("/home/user", 1, 21)
	reader.lstat["/home/user"] = []system.FileMetadata{target}
	reader.stat["/home/user"] = []system.FileMetadata{target}
	runner := &changingHomeSnapshotRunner{
		passwd: []string{
			"user:x:1000:1000::/home/user:/bin/bash",
			strings.Join([]string{
				"user:x:1000:1000::/home/user:/bin/bash",
				"new-user:x:1001:1001::/home/new-user:/bin/bash",
			}, "\n"),
		},
		findmnt: []string{
			`{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			`{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
		},
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("outcome = %#v, want account-change UNKNOWN", outcome)
	}
	if !strings.Contains(outcome.Observed, "실효 계정") {
		t.Fatalf("observed = %q, want account inventory change", outcome.Observed)
	}
}

func TestEvaluateHomeExistsDoesNotPassWhenMountInventoryChanges(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	target := directoryMetadata("/home/user", 1, 21)
	reader.lstat["/home/user"] = []system.FileMetadata{target}
	reader.stat["/home/user"] = []system.FileMetadata{target}
	runner := &changingHomeSnapshotRunner{
		passwd: []string{
			"user:x:1000:1000::/home/user:/bin/bash",
			"user:x:1000:1000::/home/user:/bin/bash",
		},
		findmnt: []string{
			`{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			`{"filesystems":[{"target":"/","fstype":"ext4"},{"target":"/home","fstype":"nfs4"}]}`,
		},
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("outcome = %#v, want mount-change UNKNOWN", outcome)
	}
	if !strings.Contains(outcome.Observed, "마운트 목록") {
		t.Fatalf("observed = %q, want mount inventory change", outcome.Observed)
	}
}

func TestEvaluateHomeExistsDoesNotPassWhenHomeTargetChangesBeforeVerdict(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	before := directoryMetadata("/home/user", 1, 21)
	after := directoryMetadata("/home/user", 1, 22)
	reader.lstat["/home/user"] = []system.FileMetadata{before}
	reader.stat["/home/user"] = []system.FileMetadata{before, before, after}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("outcome = %#v, want final home-target mutation UNKNOWN", outcome)
	}
	if !strings.Contains(outcome.Observed, "최종 홈 경로 스냅샷 변경") {
		t.Fatalf("observed = %q, want final path snapshot change", outcome.Observed)
	}
	foundSnapshot := false
	for _, evidence := range outcome.Evidence {
		if evidence.Source == "home-existence-path-snapshot-revalidation" &&
			evidence.Fact["all_stable"] == false {
			foundSnapshot = true
		}
	}
	if !foundSnapshot {
		t.Fatal("unstable final home-path snapshot evidence is missing")
	}
}

func TestEvaluateHomeExistsFailsDanglingSymlinkHome(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/link"] = []system.FileMetadata{symlinkMetadata("/home/link", "/missing", 1, 21)}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/link:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "홈 디렉터리가 없음") {
		t.Fatalf("observed = %q, want dangling-home violation", outcome.Observed)
	}
}

func TestInspectPathFollowingSymlinksResolvesRelativeNestedTarget(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	reader.lstat["/home/link"] = []system.FileMetadata{symlinkMetadata("/home/link", "../srv/users", 1, 11)}
	reader.lstat["/srv"] = []system.FileMetadata{directoryMetadata("/srv", 1, 20)}
	target := directoryMetadata("/srv/users", 1, 21)
	reader.lstat["/srv/users"] = []system.FileMetadata{target}
	reader.stat["/home/link"] = []system.FileMetadata{withPath(target, "/home/link")}

	inspected, err := inspectPathFollowingSymlinks(reader, "/home/link")
	if err != nil {
		t.Fatalf("inspectPathFollowingSymlinks() error = %v", err)
	}
	if !inspected.Exists || inspected.Unknown != "" || inspected.ResolvedPath != "/srv/users" {
		t.Fatalf("inspection = %#v, want stable /srv/users target", inspected)
	}
}

func TestInspectPathFollowingSymlinksHonorsLinuxTraversalLimit(t *testing.T) {
	tests := []struct {
		name        string
		linkCount   int
		wantUnknown bool
	}{
		{name: "forty links", linkCount: 40},
		{name: "forty one links", linkCount: 41, wantUnknown: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			for index := 0; index < test.linkCount; index++ {
				current := fmt.Sprintf("/link%d", index)
				target := "/target"
				if index+1 < test.linkCount {
					target = fmt.Sprintf("/link%d", index+1)
				}
				reader.lstat[current] = []system.FileMetadata{
					symlinkMetadata(current, target, 1, uint64(100+index)),
				}
			}
			target := directoryMetadata("/target", 1, 1000)
			reader.lstat["/target"] = []system.FileMetadata{target}
			reader.stat["/link0"] = []system.FileMetadata{withPath(target, "/link0")}

			inspected, err := inspectPathFollowingSymlinks(reader, "/link0")
			if err != nil {
				t.Fatalf("inspectPathFollowingSymlinks() error = %v", err)
			}
			if test.wantUnknown {
				if inspected.Unknown == "" || !strings.Contains(inspected.Unknown, "40개") {
					t.Fatalf("inspection = %#v, want link-limit UNKNOWN", inspected)
				}
				return
			}
			if inspected.Unknown != "" || !inspected.Exists || inspected.ResolvedPath != "/target" {
				t.Fatalf("inspection = %#v, want accepted forty-link target", inspected)
			}
		})
	}
}

func TestInspectPathFollowingSymlinksRejectsMutatedFinalTarget(t *testing.T) {
	reader := newHomePathFixtureReader()
	before := directoryMetadata("/home/user", 1, 20)
	after := directoryMetadata("/home/user", 1, 21)
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	reader.lstat["/home/user"] = []system.FileMetadata{before, after}
	reader.stat["/home/user"] = []system.FileMetadata{before}

	inspected, err := inspectPathFollowingSymlinks(reader, "/home/user")
	if err != nil {
		t.Fatalf("inspectPathFollowingSymlinks() error = %v", err)
	}
	if inspected.Unknown == "" || !strings.Contains(inspected.Unknown, "변경") {
		t.Fatalf("inspection = %#v, want final-target mutation UNKNOWN", inspected)
	}
}

func TestInspectPathWithoutSymlinksClassifiesFinalStatDisappearanceAsUnknown(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 20)}

	inspected, err := inspectPathWithoutSymlinks(reader, "/home/user")
	if err != nil {
		t.Fatalf("inspectPathWithoutSymlinks() error = %v", err)
	}
	if !inspected.Exists || inspected.Unknown == "" || !strings.Contains(inspected.Unknown, "변경") {
		t.Fatalf("inspection = %#v, want final Stat disappearance UNKNOWN", inspected)
	}
}

func TestInspectPathFollowingSymlinksDoesNotExposeUnsafeTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "ANSI escape", target: "/srv/\x1b[2Juser"},
		{name: "C1 control", target: "/srv/\u009b31muser"},
		{name: "bidi override", target: "/srv/\u202eresu"},
		{name: "line separator", target: "/srv/\u2028user"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
			reader.lstat["/home/link"] = []system.FileMetadata{
				symlinkMetadata("/home/link", test.target, 1, 11),
			}

			inspected, err := inspectPathFollowingSymlinks(reader, "/home/link")
			if err != nil {
				t.Fatalf("inspectPathFollowingSymlinks() error = %v", err)
			}
			if inspected.Unknown == "" {
				t.Fatalf("inspection = %#v, want unsupported-target UNKNOWN", inspected)
			}
			encoded, err := json.Marshal(inspected)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if strings.Contains(string(encoded), test.target) ||
				strings.ContainsAny(string(encoded), "\x1b\u009b\u202e\u2028") {
				t.Fatalf("unsafe target escaped into inspection: %q", encoded)
			}
			foundDigest := false
			for _, evidence := range inspected.Evidence {
				if evidence.Source == "home-path-resolution-unsupported-target" &&
					evidence.Fact["target_sha256"] == pathDigest(test.target) &&
					evidence.Fact["target_not_exposed"] == true {
					foundDigest = true
				}
			}
			if !foundDigest {
				t.Fatal("unsupported target digest evidence is missing")
			}
		})
	}
}

func TestUserEnvironmentPermissionsChecksStableSymlinkTargets(t *testing.T) {
	tests := []struct {
		name       string
		profile    system.FileMetadata
		target     *system.FileMetadata
		wantStatus model.Status
	}{
		{
			name: "regular profile",
			profile: system.FileMetadata{
				Path: "/home/user/.profile", FileType: "regular", Mode: 0o644,
				UID: 1000, GID: 1000, Device: 1, Inode: 31,
			},
			wantStatus: model.StatusPass,
		},
		{
			name:    "safe symlink profile",
			profile: symlinkMetadata("/home/user/.profile", "/etc/profile", 1, 31),
			target: metadataPointer(system.FileMetadata{
				Path: "/etc/profile", FileType: "regular", Mode: 0o644,
				UID: 0, GID: 0, Device: 1, Inode: 41,
			}),
			wantStatus: model.StatusPass,
		},
		{
			name:    "writable symlink target",
			profile: symlinkMetadata("/home/user/.profile", "/etc/profile", 1, 31),
			target: metadataPointer(system.FileMetadata{
				Path: "/etc/profile", FileType: "regular", Mode: 0o666,
				UID: 0, GID: 0, Device: 1, Inode: 41,
			}),
			wantStatus: model.StatusFail,
		},
		{
			name:       "missing symlink target stays unconfirmed",
			profile:    symlinkMetadata("/home/user/.profile", "/etc/profile", 1, 31),
			wantStatus: model.StatusUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			reader.lstat["/etc"] = []system.FileMetadata{directoryMetadata("/etc", 1, 10)}
			reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
			reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
			reader.lstat["/home/user/.profile"] = []system.FileMetadata{test.profile}
			if test.profile.FileType == "regular" {
				reader.stat["/home/user/.profile"] = []system.FileMetadata{test.profile}
			}
			if test.target != nil {
				reader.lstat[test.target.Path] = []system.FileMetadata{*test.target}
				reader.stat["/home/user/.profile"] = []system.FileMetadata{
					withPath(*test.target, "/home/user/.profile"),
				}
			}
			runner := homeExistsFixtureRunner{
				passwd:  "user:x:1000:1000::/home/user:/bin/bash",
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %s, summary=%q observed=%q, want %s", outcome.Status, outcome.Summary, outcome.Observed, test.wantStatus)
			}
		})
	}
}

func TestUserEnvironmentCandidatesCoverKISAAndKnownShellPaths(t *testing.T) {
	required := []string{
		".profile",
		".bash_profile",
		".bash_login",
		".bashrc",
		".bash_logout",
		".kshrc",
		".mkshrc",
		".cshrc",
		".tcshrc",
		".login",
		".logout",
		".zshenv",
		".zshenv.zwc",
		".zprofile",
		".zprofile.zwc",
		".zshrc",
		".zshrc.zwc",
		".zlogin",
		".zlogin.zwc",
		".zlogout",
		".zlogout.zwc",
		".exrc",
		".netrc",
		".config/fish/config.fish",
		".config/fish/conf.d",
	}
	for _, name := range required {
		if !slices.Contains(userEnvironmentCandidates, name) {
			t.Errorf("userEnvironmentCandidates does not include %s", name)
		}
	}
}

func TestUserEnvironmentPermissionsDoesNotAssumeDefaultFishConfigRoot(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/usr/bin/fish",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown ||
		outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf(
			"status = %s reason=%s summary=%q, want UNKNOWN unsupported_configuration",
			outcome.Status,
			outcome.UnknownReason,
			outcome.Summary,
		)
	}
	if !strings.Contains(outcome.Observed, "XDG_CONFIG_HOME") {
		t.Fatalf("observed = %q, want XDG_CONFIG_HOME uncertainty", outcome.Observed)
	}
}

func TestUserEnvironmentPermissionsEvaluatesBashLoginFile(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	bashLogin := system.FileMetadata{
		Path: "/home/user/.bash_login", FileType: "regular", Mode: 0o666,
		UID: 1000, GID: 1000, Device: 1, Inode: 22,
	}
	reader.lstat[bashLogin.Path] = []system.FileMetadata{bashLogin}
	reader.stat[bashLogin.Path] = []system.FileMetadata{bashLogin}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, ".bash_login") {
		t.Fatalf("observed = %q, want .bash_login finding", outcome.Observed)
	}
}

func TestUserEnvironmentPermissionsEvaluatesFishConfigurationPath(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	reader.lstat["/home/user/.config"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config", 1, 22),
	}
	reader.lstat["/home/user/.config/fish"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config/fish", 1, 23),
	}
	config := system.FileMetadata{
		Path: "/home/user/.config/fish/config.fish", FileType: "regular", Mode: 0o666,
		UID: 1000, GID: 1000, Device: 1, Inode: 24,
	}
	reader.lstat[config.Path] = []system.FileMetadata{config}
	reader.stat[config.Path] = []system.FileMetadata{config}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "config.fish") {
		t.Fatalf("observed = %q, want fish configuration finding", outcome.Observed)
	}
}

func TestUserEnvironmentPermissionsAcceptsStableEmptyFishConfD(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	reader.lstat["/home/user/.config"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config", 1, 22),
	}
	reader.lstat["/home/user/.config/fish"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config/fish", 1, 23),
	}
	confD := directoryMetadata("/home/user/.config/fish/conf.d", 1, 24)
	reader.lstat[confD.Path] = []system.FileMetadata{confD}
	reader.stat[confD.Path] = []system.FileMetadata{confD}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusNotApplicable {
		t.Fatalf("status = %s summary=%q observed=%q, want NOT_APPLICABLE", outcome.Status, outcome.Summary, outcome.Observed)
	}
}

func TestUserEnvironmentPermissionsEvaluatesFishConfDFragments(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	reader.lstat["/home/user/.config"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config", 1, 22),
	}
	reader.lstat["/home/user/.config/fish"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config/fish", 1, 23),
	}
	confD := directoryMetadata("/home/user/.config/fish/conf.d", 1, 24)
	reader.lstat[confD.Path] = []system.FileMetadata{confD}
	reader.stat[confD.Path] = []system.FileMetadata{confD}
	reader.dirEntries[confD.Path] = [][]os.DirEntry{{
		fixtureDirEntry{name: "10-env.fish"},
	}}
	fragment := system.FileMetadata{
		Path:     "/home/user/.config/fish/conf.d/10-env.fish",
		FileType: "regular", Mode: 0o666,
		UID: 1000, GID: 1000, Device: 1, Inode: 25,
	}
	reader.lstat[fragment.Path] = []system.FileMetadata{fragment}
	reader.stat[fragment.Path] = []system.FileMetadata{fragment}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s summary=%q observed=%q, want FAIL", outcome.Status, outcome.Summary, outcome.Observed)
	}
	if !strings.Contains(outcome.Observed, "10-env.fish") {
		t.Fatalf("observed = %q, want fish fragment finding", outcome.Observed)
	}
}

func TestUserEnvironmentPermissionsDetectsFishConfDListingChanges(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	reader.lstat["/home/user/.config"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config", 1, 22),
	}
	reader.lstat["/home/user/.config/fish"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config/fish", 1, 23),
	}
	confD := directoryMetadata("/home/user/.config/fish/conf.d", 1, 24)
	reader.lstat[confD.Path] = []system.FileMetadata{confD}
	reader.stat[confD.Path] = []system.FileMetadata{confD}
	reader.dirEntries[confD.Path] = [][]os.DirEntry{
		{},
		{fixtureDirEntry{name: "appeared.fish"}},
	}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("outcome = %#v, want listing-change UNKNOWN", outcome)
	}
}

func TestUserEnvironmentPermissionsBoundsFishConfDEntries(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	reader.lstat["/home/user/.config"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config", 1, 22),
	}
	reader.lstat["/home/user/.config/fish"] = []system.FileMetadata{
		directoryMetadata("/home/user/.config/fish", 1, 23),
	}
	confD := directoryMetadata("/home/user/.config/fish/conf.d", 1, 24)
	reader.lstat[confD.Path] = []system.FileMetadata{confD}
	reader.stat[confD.Path] = []system.FileMetadata{confD}
	entries := make([]os.DirEntry, maximumFishUserConfigurationFragments+1)
	for index := range entries {
		entries[index] = fixtureDirEntry{name: fmt.Sprintf("%04d.fish", index)}
	}
	reader.dirEntries[confD.Path] = [][]os.DirEntry{entries}
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownInsufficientEvidence {
		t.Fatalf("outcome = %#v, want bounded UNKNOWN insufficient_evidence", outcome)
	}
	if reader.dirCalls[confD.Path] != 1 {
		t.Fatalf("directory reads = %d, want one bounded read", reader.dirCalls[confD.Path])
	}
}

func TestUserEnvironmentPermissionsTreatsFishConfDReopenErrorsAsUnknown(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "non-directory parent", err: syscall.ENOTDIR},
		{name: "symlink loop", err: syscall.ELOOP},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
			reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
			reader.lstat["/home/user/.config"] = []system.FileMetadata{
				directoryMetadata("/home/user/.config", 1, 22),
			}
			reader.lstat["/home/user/.config/fish"] = []system.FileMetadata{
				directoryMetadata("/home/user/.config/fish", 1, 23),
			}
			confD := directoryMetadata("/home/user/.config/fish/conf.d", 1, 24)
			reader.lstat[confD.Path] = []system.FileMetadata{confD}
			reader.stat[confD.Path] = []system.FileMetadata{confD}
			reader.dirErrors[confD.Path] = []error{
				fmt.Errorf("open directory after path change: %w", test.err),
			}
			runner := homeExistsFixtureRunner{
				passwd:  "user:x:1000:1000::/home/user:/bin/bash",
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != model.StatusUnknown ||
				outcome.UnknownReason != model.UnknownAmbiguousResult ||
				outcome.ErrorCode != "" {
				t.Fatalf("outcome = %#v, want directory reopen UNKNOWN", outcome)
			}
			if !strings.Contains(outcome.Observed, "점검 중 변경") {
				t.Fatalf("observed = %q, want directory-change explanation", outcome.Observed)
			}
		})
	}
}

func TestUserEnvironmentPermissionsClassifiesACLTargetRaces(t *testing.T) {
	tests := []struct {
		name             string
		mode             os.FileMode
		aclErr           error
		wantStatus       model.Status
		wantErrorCode    string
		wantRaceObserved bool
	}{
		{
			name:             "changed compliant target becomes unknown",
			mode:             0o600,
			aclErr:           system.ErrFileChanged,
			wantStatus:       model.StatusUnknown,
			wantRaceObserved: true,
		},
		{
			name:             "changed target with definite mode violation still fails",
			mode:             0o622,
			aclErr:           system.ErrFileChanged,
			wantStatus:       model.StatusFail,
			wantRaceObserved: true,
		},
		{
			name:             "removed compliant target becomes unknown",
			mode:             0o600,
			aclErr:           os.ErrNotExist,
			wantStatus:       model.StatusUnknown,
			wantRaceObserved: true,
		},
		{
			name:             "removed target with definite mode violation still fails",
			mode:             0o622,
			aclErr:           os.ErrNotExist,
			wantStatus:       model.StatusFail,
			wantRaceObserved: true,
		},
		{
			name:             "non-directory parent becomes unknown",
			mode:             0o600,
			aclErr:           syscall.ENOTDIR,
			wantStatus:       model.StatusUnknown,
			wantRaceObserved: true,
		},
		{
			name:             "symlink loop becomes unknown",
			mode:             0o600,
			aclErr:           syscall.ELOOP,
			wantStatus:       model.StatusUnknown,
			wantRaceObserved: true,
		},
		{
			name:          "unrelated ACL IO error stays an error",
			mode:          0o600,
			aclErr:        errors.New("ACL I/O failed"),
			wantStatus:    model.StatusError,
			wantErrorCode: "environment_file_acl_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := newHomePathFixtureReader()
			base.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
			base.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
			profile := system.FileMetadata{
				Path: "/home/user/.profile", FileType: "regular", Mode: test.mode,
				UID: 1000, GID: 1000, Device: 1, Inode: 22,
			}
			base.lstat[profile.Path] = []system.FileMetadata{profile}
			base.stat[profile.Path] = []system.FileMetadata{profile}
			reader := &changingACLHomePathReader{
				homePathFixtureReader: base,
				err:                   fmt.Errorf("%w: %s", test.aclErr, profile.Path),
			}
			runner := homeExistsFixtureRunner{
				passwd:  "user:x:1000:1000::/home/user:/bin/bash",
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %s, reason=%s summary=%q observed=%q, want %s", outcome.Status, outcome.UnknownReason, outcome.Summary, outcome.Observed, test.wantStatus)
			}
			if outcome.ErrorCode != test.wantErrorCode {
				t.Fatalf("error code = %q, want %q", outcome.ErrorCode, test.wantErrorCode)
			}
			if test.wantRaceObserved && !strings.Contains(outcome.Observed, "ACL 수집 중") {
				t.Fatalf("observed = %q, want ACL race explanation", outcome.Observed)
			}
		})
	}
}

func TestUserEnvironmentPermissionsClassifiesPathReopenErrorsAsUnknown(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "non-directory parent", err: syscall.ENOTDIR},
		{name: "symlink loop", err: syscall.ELOOP},
	}
	for _, test := range tests {
		t.Run("initial "+test.name, func(t *testing.T) {
			base := newHomePathFixtureReader()
			base.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
			base.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
			profile := system.FileMetadata{
				Path: "/home/user/.profile", FileType: "regular", Mode: 0o600,
				UID: 1000, GID: 1000, Device: 1, Inode: 22,
			}
			base.lstat[profile.Path] = []system.FileMetadata{profile}
			base.stat[profile.Path] = []system.FileMetadata{profile}
			reader := &lstatErrorHomePathReader{
				homePathFixtureReader: base,
				target:                profile.Path,
				failAt:                1,
				err:                   fmt.Errorf("open path: %w", test.err),
			}
			runner := homeExistsFixtureRunner{
				passwd:  "user:x:1000:1000::/home/user:/bin/bash",
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != model.StatusUnknown ||
				outcome.UnknownReason != model.UnknownAmbiguousResult ||
				outcome.ErrorCode != "" {
				t.Fatalf("outcome = %#v, want initial path reopen UNKNOWN", outcome)
			}
		})

		t.Run("final "+test.name, func(t *testing.T) {
			base := newHomePathFixtureReader()
			base.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
			base.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
			profile := system.FileMetadata{
				Path: "/home/user/.profile", FileType: "regular", Mode: 0o600,
				UID: 1000, GID: 1000, Device: 1, Inode: 22,
			}
			base.lstat[profile.Path] = []system.FileMetadata{profile}
			base.stat[profile.Path] = []system.FileMetadata{profile}
			reader := &lstatErrorHomePathReader{
				homePathFixtureReader: base,
				target:                profile.Path,
				failAt:                3,
				err:                   fmt.Errorf("reopen path: %w", test.err),
			}
			runner := &sequencedUserEnvironmentRunner{
				passwd:  []string{"user:x:1000:1000::/home/user:/bin/bash"},
				findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != model.StatusUnknown ||
				outcome.UnknownReason != model.UnknownAmbiguousResult ||
				outcome.ErrorCode != "" {
				t.Fatalf("outcome = %#v, want final path reopen UNKNOWN", outcome)
			}
		})
	}
}

func TestUserEnvironmentPermissionsClassifiesFinalACLReopenErrorsAsUnknown(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "non-directory parent", err: syscall.ENOTDIR},
		{name: "symlink loop", err: syscall.ELOOP},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := newHomePathFixtureReader()
			base.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
			base.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
			profile := system.FileMetadata{
				Path: "/home/user/.profile", FileType: "regular", Mode: 0o600,
				UID: 1000, GID: 1000, Device: 1, Inode: 22,
			}
			base.lstat[profile.Path] = []system.FileMetadata{profile}
			base.stat[profile.Path] = []system.FileMetadata{profile}
			reader := &sequencedACLHomePathReader{
				homePathFixtureReader: base,
				aclErrors: []error{
					nil,
					fmt.Errorf("reopen ACL target: %w", test.err),
				},
			}
			runner := &sequencedUserEnvironmentRunner{
				passwd:  []string{"user:x:1000:1000::/home/user:/bin/bash"},
				findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != model.StatusUnknown ||
				outcome.UnknownReason != model.UnknownAmbiguousResult ||
				outcome.ErrorCode != "" {
				t.Fatalf("outcome = %#v, want final ACL reopen UNKNOWN", outcome)
			}
			if reader.aclCalls != 2 {
				t.Fatalf("ACL calls = %d, want initial and final snapshots", reader.aclCalls)
			}
		})
	}
}

func metadataPointer(value system.FileMetadata) *system.FileMetadata {
	return &value
}

func TestUserEnvironmentPermissionsTreatsUnreachableChildrenAsAbsent(t *testing.T) {
	tests := []struct {
		name   string
		passwd string
		setup  func(*homePathFixtureReader)
	}{
		{
			name:   "merged usr home symlink",
			passwd: "bin:x:1:1::/bin:/sbin/nologin",
			setup: func(reader *homePathFixtureReader) {
				reader.lstat["/bin"] = []system.FileMetadata{
					symlinkMetadata("/bin", "/usr/bin", 1, 10),
				}
				reader.lstat["/usr"] = []system.FileMetadata{directoryMetadata("/usr", 1, 11)}
				reader.lstat["/usr/bin"] = []system.FileMetadata{directoryMetadata("/usr/bin", 1, 12)}
			},
		},
		{
			name:   "non directory home blocker",
			passwd: "tss:x:59:59::/dev/null:/sbin/nologin",
			setup: func(reader *homePathFixtureReader) {
				reader.lstat["/dev"] = []system.FileMetadata{directoryMetadata("/dev", 1, 20)}
				reader.lstat["/dev/null"] = []system.FileMetadata{{
					Path: "/dev/null", FileType: "character_device",
					Mode: os.ModeDevice | os.ModeCharDevice | 0o666,
					UID:  0, GID: 0, Device: 1, Inode: 21,
				}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			test.setup(reader)
			runner := homeExistsFixtureRunner{
				passwd:  test.passwd,
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != model.StatusNotApplicable {
				t.Fatalf("status = %s, summary=%q observed=%q, want NOT_APPLICABLE", outcome.Status, outcome.Summary, outcome.Observed)
			}
			foundStableSnapshot := false
			for _, evidence := range outcome.Evidence {
				if evidence.Source == "user-environment-snapshot-revalidation" &&
					evidence.Fact["all_stable"] == true {
					foundStableSnapshot = true
				}
			}
			if !foundStableSnapshot {
				t.Fatal("stable final environment snapshot evidence is missing")
			}
		})
	}
}

func TestUserEnvironmentPermissionsEvaluatesSharedHomeOwnerPolicy(t *testing.T) {
	tests := []struct {
		name       string
		ownerUID   int
		wantStatus model.Status
	}{
		{name: "root owned shared file", ownerUID: 0, wantStatus: model.StatusPass},
		{name: "one shared account owns file", ownerUID: 11, wantStatus: model.StatusFail},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			reader.lstat["/root"] = []system.FileMetadata{directoryMetadata("/root", 1, 30)}
			profile := system.FileMetadata{
				Path: "/root/.profile", FileType: "regular", Mode: 0o600,
				UID: test.ownerUID, GID: test.ownerUID, Device: 1, Inode: 31,
			}
			reader.lstat["/root/.profile"] = []system.FileMetadata{profile}
			reader.stat["/root/.profile"] = []system.FileMetadata{profile}
			runner := homeExistsFixtureRunner{
				passwd: "root:x:0:0::/root:/bin/bash\n" +
					"operator:x:11:0::/root:/sbin/nologin",
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %s, summary=%q observed=%q, want %s", outcome.Status, outcome.Summary, outcome.Observed, test.wantStatus)
			}
		})
	}
	if !userEnvironmentOwnerAllowed(1000, []support.PasswdEntry{{UID: 1000}, {UID: 1000}}) {
		t.Fatal("same effective UID shared by multiple account names should be allowed")
	}
	if userEnvironmentOwnerAllowed(1000, []support.PasswdEntry{{UID: 1000}, {UID: 1001}}) {
		t.Fatal("owner UID accepted for a different shared-home account")
	}
}

func TestUserEnvironmentPermissionsRejectsNonLocalResolvedTarget(t *testing.T) {
	for _, filesystemType := range []string{"nfs", "autofs"} {
		t.Run(filesystemType, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
			reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 11)}
			reader.lstat["/home/user/.profile"] = []system.FileMetadata{
				symlinkMetadata("/home/user/.profile", "/mnt/remote/profile", 1, 12),
			}
			reader.lstat["/mnt"] = []system.FileMetadata{directoryMetadata("/mnt", 2, 20)}
			reader.lstat["/mnt/remote"] = []system.FileMetadata{directoryMetadata("/mnt/remote", 2, 21)}
			target := system.FileMetadata{
				Path: "/mnt/remote/profile", FileType: "regular", Mode: 0o600,
				UID: 1000, GID: 1000, Device: 2, Inode: 22,
			}
			reader.lstat[target.Path] = []system.FileMetadata{target}
			reader.stat["/home/user/.profile"] = []system.FileMetadata{
				withPath(target, "/home/user/.profile"),
			}
			runner := homeExistsFixtureRunner{
				passwd: "user:x:1000:1000::/home/user:/bin/bash",
				findmnt: fmt.Sprintf(
					`{"filesystems":[{"target":"/","fstype":"ext4"},{"target":"/mnt/remote","fstype":%q}]}`,
					filesystemType,
				),
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
				t.Fatalf("status = %s reason=%s summary=%q, want UNKNOWN ambiguous_result", outcome.Status, outcome.UnknownReason, outcome.Summary)
			}
		})
	}
}

func TestUserEnvironmentPermissionsStopsBeforeNonLocalIntermediateLink(t *testing.T) {
	for _, filesystemType := range []string{"nfs4", "autofs"} {
		t.Run(filesystemType, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
			reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 11)}
			reader.lstat["/home/user/.profile"] = []system.FileMetadata{
				symlinkMetadata("/home/user/.profile", "/mnt/remote/bridge", 1, 12),
			}
			reader.lstat["/mnt"] = []system.FileMetadata{directoryMetadata("/mnt", 1, 20)}
			// If inspected, this link would return to a local, compliant target.
			reader.lstat["/mnt/remote"] = []system.FileMetadata{directoryMetadata("/mnt/remote", 2, 21)}
			reader.lstat["/mnt/remote/bridge"] = []system.FileMetadata{
				symlinkMetadata("/mnt/remote/bridge", "/etc/profile", 2, 22),
			}
			runner := homeExistsFixtureRunner{
				passwd: "user:x:1000:1000::/home/user:/bin/bash",
				findmnt: fmt.Sprintf(
					`{"filesystems":[{"target":"/","fstype":"ext4"},{"target":"/mnt/remote","fstype":%q}]}`,
					filesystemType,
				),
			}

			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: reader, Commands: runner,
			})
			if outcome.Status != model.StatusUnknown {
				t.Fatalf("status = %s reason=%s observed=%q, want UNKNOWN", outcome.Status, outcome.UnknownReason, outcome.Observed)
			}
			if reader.lstatCalls["/mnt/remote"] != 0 || reader.lstatCalls["/mnt/remote/bridge"] != 0 {
				t.Fatalf(
					"non-local Lstat calls = mount:%d bridge:%d, want zero",
					reader.lstatCalls["/mnt/remote"],
					reader.lstatCalls["/mnt/remote/bridge"],
				)
			}
		})
	}
}

func TestUserEnvironmentPermissionsRejectsRemoteParentOfNestedLocalMount(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 11)}
	reader.lstat["/home/user/.profile"] = []system.FileMetadata{
		symlinkMetadata("/home/user/.profile", "/mnt/remote/local/profile", 1, 12),
	}
	reader.lstat["/mnt"] = []system.FileMetadata{directoryMetadata("/mnt", 1, 20)}
	runner := homeExistsFixtureRunner{
		passwd: "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[
			{"target":"/","fstype":"ext4"},
			{"target":"/mnt/remote","fstype":"nfs4"},
			{"target":"/mnt/remote/local","fstype":"ext4"}
		]}`,
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s reason=%s observed=%q, want UNKNOWN", outcome.Status, outcome.UnknownReason, outcome.Observed)
	}
	if reader.lstatCalls["/mnt/remote"] != 0 {
		t.Fatalf("remote parent Lstat calls = %d, want zero", reader.lstatCalls["/mnt/remote"])
	}
}

func TestUserEnvironmentPermissionsDetectsRemoteLinkIntroducedBeforeVerdict(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 11)}
	oldProfileLink := symlinkMetadata("/home/user/.profile", "/opt/bridge", 1, 12)
	newProfileLink := symlinkMetadata("/home/user/.profile", "/mnt/remote/bridge", 1, 13)
	reader.lstat["/home/user/.profile"] = []system.FileMetadata{
		oldProfileLink,
		oldProfileLink,
		newProfileLink,
	}
	reader.lstat["/opt"] = []system.FileMetadata{directoryMetadata("/opt", 1, 20)}
	oldBridgeLink := symlinkMetadata("/opt/bridge", "/etc/profile", 1, 21)
	reader.lstat["/opt/bridge"] = []system.FileMetadata{oldBridgeLink}
	reader.lstat["/etc"] = []system.FileMetadata{directoryMetadata("/etc", 1, 30)}
	target := system.FileMetadata{
		Path: "/etc/profile", FileType: "regular", Mode: 0o600,
		UID: 0, GID: 0, Device: 1, Inode: 31,
	}
	reader.lstat[target.Path] = []system.FileMetadata{target}
	reader.stat["/home/user/.profile"] = []system.FileMetadata{
		withPath(target, "/home/user/.profile"),
	}
	reader.lstat["/mnt"] = []system.FileMetadata{directoryMetadata("/mnt", 1, 40)}
	runner := &sequencedUserEnvironmentRunner{
		passwd: []string{
			"user:x:1000:1000::/home/user:/bin/bash",
			"user:x:1000:1000::/home/user:/bin/bash",
		},
		findmnt: []string{
			`{"filesystems":[{"target":"/","fstype":"ext4"},{"target":"/mnt/remote","fstype":"nfs4"}]}`,
			`{"filesystems":[{"target":"/","fstype":"ext4"},{"target":"/mnt/remote","fstype":"nfs4"}]}`,
		},
		acl: []string{"user::rw-\ngroup::---\nother::---\n"},
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("outcome = %#v, want final remote-chain UNKNOWN", outcome)
	}
	if reader.lstatCalls["/mnt/remote"] != 0 {
		t.Fatalf("remote Lstat calls = %d, want zero", reader.lstatCalls["/mnt/remote"])
	}
}

func TestUserEnvironmentPermissionsUsesFollowingACLAndRevalidatesIt(t *testing.T) {
	base := newHomePathFixtureReader()
	base.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	base.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 11)}
	base.lstat["/home/user/.profile"] = []system.FileMetadata{
		symlinkMetadata("/home/user/.profile", "/etc/profile", 1, 12),
	}
	base.lstat["/etc"] = []system.FileMetadata{directoryMetadata("/etc", 1, 20)}
	target := system.FileMetadata{
		Path: "/etc/profile", FileType: "regular", Mode: 0o644,
		UID: 0, GID: 0, Device: 1, Inode: 21,
	}
	base.lstat[target.Path] = []system.FileMetadata{target}
	base.stat["/home/user/.profile"] = []system.FileMetadata{
		withPath(target, "/home/user/.profile"),
	}
	reader := &sequencedACLHomePathReader{
		homePathFixtureReader: base,
		acl: [][]byte{
			mustTestPOSIXACLXAttr(t, "user::rw-\ngroup::r--\nother::r--\n"),
			mustTestPOSIXACLXAttr(t, "user::rw-\ngroup::r--\nother::rw-\n"),
		},
	}
	runner := &sequencedUserEnvironmentRunner{
		passwd:  []string{"user:x:1000:1000::/home/user:/bin/bash"},
		findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("status = %s reason=%s summary=%q, want UNKNOWN after ACL change", outcome.Status, outcome.UnknownReason, outcome.Summary)
	}
	if reader.aclCalls != 2 {
		t.Fatalf("native ACL calls = %d, want 2", reader.aclCalls)
	}
	for _, follow := range reader.followFinal {
		if !follow {
			t.Fatalf("native ACL follow modes = %#v, want final-symlink following", reader.followFinal)
		}
	}
}

func TestUserEnvironmentPermissionsDetectsFinalSnapshotChanges(t *testing.T) {
	oldMetadata := system.FileMetadata{
		Path: "/home/user/.profile", FileType: "regular", Mode: 0o600,
		UID: 1000, GID: 1000, Device: 1, Inode: 31,
	}
	newMetadata := oldMetadata
	newMetadata.Mode = 0o666

	tests := []struct {
		name    string
		reader  func() *homePathFixtureReader
		passwd  []string
		findmnt []string
	}{
		{
			name: "permission metadata changed",
			reader: func() *homePathFixtureReader {
				reader := newHomePathFixtureReader()
				reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
				reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
				reader.lstat["/home/user/.profile"] = []system.FileMetadata{
					oldMetadata, oldMetadata, newMetadata, newMetadata,
				}
				reader.stat["/home/user/.profile"] = []system.FileMetadata{
					oldMetadata, oldMetadata, newMetadata, newMetadata,
				}
				return reader
			},
			passwd:  []string{"user:x:1000:1000::/home/user:/bin/bash"},
			findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
		},
		{
			name: "account inventory changed",
			reader: func() *homePathFixtureReader {
				reader := newHomePathFixtureReader()
				reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
				reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
				reader.lstat["/home/user/.profile"] = []system.FileMetadata{oldMetadata}
				reader.stat["/home/user/.profile"] = []system.FileMetadata{oldMetadata}
				return reader
			},
			passwd: []string{
				"user:x:1000:1000::/home/user:/bin/bash",
				"user:x:1001:1000::/home/user:/bin/bash",
			},
			findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
		},
		{
			name: "login shell changed",
			reader: func() *homePathFixtureReader {
				reader := newHomePathFixtureReader()
				reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
				reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
				reader.lstat["/home/user/.profile"] = []system.FileMetadata{oldMetadata}
				reader.stat["/home/user/.profile"] = []system.FileMetadata{oldMetadata}
				return reader
			},
			passwd: []string{
				"user:x:1000:1000::/home/user:/bin/bash",
				"user:x:1000:1000::/home/user:/usr/bin/fish",
			},
			findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
		},
		{
			name: "mount inventory changed",
			reader: func() *homePathFixtureReader {
				reader := newHomePathFixtureReader()
				reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
				reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
				reader.lstat["/home/user/.profile"] = []system.FileMetadata{oldMetadata}
				reader.stat["/home/user/.profile"] = []system.FileMetadata{oldMetadata}
				return reader
			},
			passwd: []string{"user:x:1000:1000::/home/user:/bin/bash"},
			findmnt: []string{
				`{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
				`{"filesystems":[{"target":"/","fstype":"xfs"}]}`,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &sequencedUserEnvironmentRunner{
				passwd:  test.passwd,
				findmnt: test.findmnt,
				acl:     []string{"user::rw-\ngroup::r--\nother::r--\n"},
			}
			outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
				Files: test.reader(), Commands: runner,
			})
			if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
				t.Fatalf("status = %s reason=%s summary=%q, want UNKNOWN ambiguous_result", outcome.Status, outcome.UnknownReason, outcome.Summary)
			}
		})
	}
}

func TestUserEnvironmentPermissionsDetectsLinkChangeBetweenSnapshots(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 11)}
	oldLink := symlinkMetadata("/home/user/.profile", "/etc/profile", 1, 12)
	newLink := symlinkMetadata("/home/user/.profile", "/opt/profile", 1, 13)
	reader.lstat["/home/user/.profile"] = []system.FileMetadata{oldLink, oldLink, newLink, newLink}
	reader.lstat["/etc"] = []system.FileMetadata{directoryMetadata("/etc", 1, 20)}
	reader.lstat["/opt"] = []system.FileMetadata{directoryMetadata("/opt", 1, 30)}
	oldTarget := system.FileMetadata{
		Path: "/etc/profile", FileType: "regular", Mode: 0o644,
		UID: 0, GID: 0, Device: 1, Inode: 21,
	}
	newTarget := system.FileMetadata{
		Path: "/opt/profile", FileType: "regular", Mode: 0o644,
		UID: 0, GID: 0, Device: 1, Inode: 31,
	}
	reader.lstat[oldTarget.Path] = []system.FileMetadata{oldTarget}
	reader.lstat[newTarget.Path] = []system.FileMetadata{newTarget}
	reader.stat["/home/user/.profile"] = []system.FileMetadata{
		withPath(oldTarget, "/home/user/.profile"),
		withPath(oldTarget, "/home/user/.profile"),
		withPath(newTarget, "/home/user/.profile"),
		withPath(newTarget, "/home/user/.profile"),
	}
	runner := &sequencedUserEnvironmentRunner{
		passwd:  []string{"user:x:1000:1000::/home/user:/bin/bash"},
		findmnt: []string{`{"filesystems":[{"target":"/","fstype":"ext4"}]}`},
		acl:     []string{"user::rw-\ngroup::r--\nother::r--\n"},
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownAmbiguousResult {
		t.Fatalf("status = %s reason=%s summary=%q, want UNKNOWN after link change", outcome.Status, outcome.UnknownReason, outcome.Summary)
	}
}

func TestUserEnvironmentCandidateLimitBoundary(t *testing.T) {
	maximumHomes := maximumUserEnvironmentCandidates / len(userEnvironmentCandidates)
	if userEnvironmentCandidateLimitExceeded(maximumHomes) {
		t.Fatalf("home count %d unexpectedly exceeds candidate limit", maximumHomes)
	}
	if !userEnvironmentCandidateLimitExceeded(maximumHomes + 1) {
		t.Fatalf("home count %d did not exceed candidate limit", maximumHomes+1)
	}
	if !userEnvironmentCandidateLimitExceeded(-1) {
		t.Fatal("negative home count did not exceed candidate limit")
	}

	var passwd strings.Builder
	for index := 0; index <= maximumHomes; index++ {
		fmt.Fprintf(
			&passwd,
			"user%d:x:%d:%d::/home/user%d:/bin/sh\n",
			index,
			1000+index,
			1000+index,
			index,
		)
	}
	runner := homeExistsFixtureRunner{
		passwd:  passwd.String(),
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}
	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Commands: runner,
	})
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownInsufficientEvidence {
		t.Fatalf(
			"status = %s reason=%s summary=%q, want UNKNOWN insufficient_evidence",
			outcome.Status,
			outcome.UnknownReason,
			outcome.Summary,
		)
	}
}

func TestCollectHomeMountsBoundsAndIndexesInventory(t *testing.T) {
	exactRunner := homeExistsFixtureRunner{findmnt: findmntFixtureWithMountCount(maximumHomeMountEntries)}
	table, evidence, err := collectHomeMounts(context.Background(), evaluator.Environment{
		Commands: exactRunner,
	})
	if err != nil {
		t.Fatalf("collectHomeMounts(exact limit) error = %v", err)
	}
	if len(table.mounts) != maximumHomeMountEntries || evidence.Command == nil {
		t.Fatalf("exact table mounts=%d evidence=%#v", len(table.mounts), evidence)
	}

	_, overflowEvidence, err := collectHomeMounts(context.Background(), evaluator.Environment{
		Commands: homeExistsFixtureRunner{
			findmnt: findmntFixtureWithMountCount(maximumHomeMountEntries + 1),
		},
	})
	if !isHomeMountInventoryLimit(err) {
		t.Fatalf("collectHomeMounts(overflow) error = %v, want typed inventory limit", err)
	}
	if overflowEvidence.Command == nil {
		t.Fatalf("overflow evidence = %#v, want bounded findmnt command evidence", overflowEvidence)
	}
}

func TestHomeEvaluatorsClassifyMountInventoryLimitAsInsufficientEvidence(t *testing.T) {
	environment := evaluator.Environment{
		Commands: homeExistsFixtureRunner{
			passwd:  "user:x:1000:1000::/home/user:/bin/bash",
			findmnt: findmntFixtureWithMountCount(maximumHomeMountEntries + 1),
		},
	}
	tests := []struct {
		name     string
		evaluate func(context.Context, model.ResolvedRule, evaluator.Environment) evaluator.Outcome
	}{
		{name: "U24 environment files", evaluate: evaluateUserEnvironmentPermissions},
		{name: "U31 home permissions", evaluate: evaluateHomePermissions},
		{name: "U32 home existence", evaluate: evaluateHomeExists},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := test.evaluate(context.Background(), model.ResolvedRule{}, environment)
			if outcome.Status != model.StatusUnknown ||
				outcome.UnknownReason != model.UnknownInsufficientEvidence ||
				outcome.ErrorCode != "" {
				t.Fatalf("outcome = %#v, want UNKNOWN insufficient_evidence", outcome)
			}
			if !containsEvidenceSource(outcome.Evidence, "home-mount-inventory-limit") {
				t.Fatalf("evidence = %#v, want mount inventory limit fact", outcome.Evidence)
			}
		})
	}
}

func TestEvaluateHomeExistsClassifiesFinalMountInventoryLimitAsInsufficientEvidence(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	home := directoryMetadata("/home/user", 1, 21)
	reader.lstat[home.Path] = []system.FileMetadata{home}
	reader.stat[home.Path] = []system.FileMetadata{home}
	runner := &changingHomeSnapshotRunner{
		passwd: []string{
			"user:x:1000:1000::/home/user:/bin/bash",
			"user:x:1000:1000::/home/user:/bin/bash",
		},
		findmnt: []string{
			`{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			findmntFixtureWithMountCount(maximumHomeMountEntries + 1),
		},
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown ||
		outcome.UnknownReason != model.UnknownInsufficientEvidence ||
		outcome.ErrorCode != "" {
		t.Fatalf("outcome = %#v, want final mount-limit UNKNOWN insufficient_evidence", outcome)
	}
	if !containsEvidenceSource(outcome.Evidence, "home-mount-inventory-limit") {
		t.Fatalf("evidence = %#v, want final mount inventory limit fact", outcome.Evidence)
	}
}

func TestUserEnvironmentPermissionsClassifiesFinalMountInventoryLimitAsInsufficientEvidence(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
	reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
	profile := system.FileMetadata{
		Path: "/home/user/.profile", FileType: "regular", Mode: 0o600,
		UID: 1000, GID: 1000, Device: 1, Inode: 22,
	}
	reader.lstat[profile.Path] = []system.FileMetadata{profile}
	reader.stat[profile.Path] = []system.FileMetadata{profile}
	runner := &sequencedUserEnvironmentRunner{
		passwd: []string{
			"user:x:1000:1000::/home/user:/bin/bash",
			"user:x:1000:1000::/home/user:/bin/bash",
		},
		findmnt: []string{
			`{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			findmntFixtureWithMountCount(maximumHomeMountEntries + 1),
		},
	}

	outcome := evaluateUserEnvironmentPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown ||
		outcome.UnknownReason != model.UnknownInsufficientEvidence ||
		outcome.ErrorCode != "" {
		t.Fatalf("outcome = %#v, want final mount-limit UNKNOWN insufficient_evidence", outcome)
	}
	if !containsEvidenceSource(outcome.Evidence, "home-mount-inventory-limit") {
		t.Fatalf("evidence = %#v, want final mount inventory limit fact", outcome.Evidence)
	}
}

func TestHomeMountTableClassificationIsDeterministicAndCacheBounded(t *testing.T) {
	runner := homeExistsFixtureRunner{findmnt: `{
		"filesystems":[
			{"target":"/","fstype":"ext4"},
			{"target":"/home","fstype":"nfs4"},
			{"target":"/home/local","fstype":"xfs"},
			{"target":"/same","fstype":"ext4"},
			{"target":"/same","fstype":"ext4"},
			{"target":"/conflict","fstype":"nfs4"},
			{"target":"/conflict","fstype":"ext4"}
		]
	}`}
	table, _, err := collectHomeMounts(context.Background(), evaluator.Environment{Commands: runner})
	if err != nil {
		t.Fatalf("collectHomeMounts() error = %v", err)
	}
	tests := []struct {
		path      string
		wantKind  homeMountKind
		wantFound bool
		wantFS    string
	}{
		{path: "/home/user", wantKind: homeMountRemote, wantFound: true, wantFS: "nfs4"},
		{path: "/home/local/user", wantKind: homeMountLocal, wantFound: true, wantFS: "xfs"},
		{path: "/same/child", wantKind: homeMountLocal, wantFound: true, wantFS: "ext4"},
		{path: "/conflict/child", wantKind: homeMountAmbiguous, wantFound: true, wantFS: "ext4"},
		{path: "", wantKind: homeMountAmbiguous, wantFound: false},
		{path: "relative", wantKind: homeMountAmbiguous, wantFound: false},
		{path: ".", wantKind: homeMountAmbiguous, wantFound: false},
	}
	for _, test := range tests {
		kind, mount, found := table.classify(test.path)
		if kind != test.wantKind || found != test.wantFound || mount.FSType != test.wantFS {
			t.Errorf(
				"classify(%q) = kind:%s mount:%#v found:%t, want %s %q %t",
				test.path,
				kind,
				mount,
				found,
				test.wantKind,
				test.wantFS,
				test.wantFound,
			)
		}
	}

	for index := 0; index < maximumHomeMountCacheEntries+256; index++ {
		kind, _, found := table.classify(fmt.Sprintf("/bounded-cache/path-%05d", index))
		if kind != homeMountLocal || !found {
			t.Fatalf("classification after cache pressure = %s, %t", kind, found)
		}
	}
	if len(table.cache) > maximumHomeMountCacheEntries {
		t.Fatalf("cache entries = %d, want at most %d", len(table.cache), maximumHomeMountCacheEntries)
	}
	latestPath := fmt.Sprintf("/bounded-cache/path-%05d", maximumHomeMountCacheEntries+255)
	if _, exists := table.cache[latestPath]; !exists {
		t.Fatalf("latest classified path %q was not retained after cache rollover", latestPath)
	}
}

func TestAccountFindingLabelsRemainBounded(t *testing.T) {
	accounts := make([]support.PasswdEntry, 128)
	for index := range accounts {
		accounts[index] = support.PasswdEntry{
			Name: strings.Repeat("계", 4_096) + fmt.Sprintf("-%03d", index),
		}
	}
	label := accountNames(accounts)
	if len(label) > maximumAccountFindingLabelBytes || !utf8.ValidString(label) {
		t.Fatalf("account label bytes=%d valid_utf8=%t", len(label), utf8.ValidString(label))
	}
	if !strings.Contains(label, "계정 128개") || !strings.Contains(label, "sha256=") {
		t.Fatalf("account label = %q, want count and digest", label)
	}
	evidence := findingEvidence("bounded-account-label", 0, nil, []pathFinding{{
		Account: label,
		Path:    "/home/shared",
		Reason:  "확정 불가",
	}})
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("json.Marshal(evidence) error = %v", err)
	}
	if len(encoded) > 4_096 {
		t.Fatalf("encoded evidence bytes = %d, want compact evidence", len(encoded))
	}
}

func TestUserEnvironmentPathBudgetIsSharedWithFinalRevalidation(t *testing.T) {
	exactLimit := 0
	for _, relative := range userEnvironmentCandidates {
		componentCount := strings.Count(relative, "/") + 1
		exactLimit += 2 * (5 + componentCount)
	}
	tests := []struct {
		name       string
		limit      int
		wantStatus model.Status
		wantReason model.UnknownReason
	}{
		{name: "exact operation budget", limit: exactLimit, wantStatus: model.StatusNotApplicable},
		{
			name:       "one operation short",
			limit:      exactLimit - 1,
			wantStatus: model.StatusUnknown,
			wantReason: model.UnknownInsufficientEvidence,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newHomePathFixtureReader()
			reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 20)}
			reader.lstat["/home/user"] = []system.FileMetadata{directoryMetadata("/home/user", 1, 21)}
			reader.lstat["/home/user/.config"] = []system.FileMetadata{
				directoryMetadata("/home/user/.config", 1, 22),
			}
			reader.lstat["/home/user/.config/fish"] = []system.FileMetadata{
				directoryMetadata("/home/user/.config/fish", 1, 23),
			}
			runner := homeExistsFixtureRunner{
				passwd:  "user:x:1000:1000::/home/user:/bin/bash",
				findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
			}

			outcome := evaluateUserEnvironmentPermissionsWithLimits(
				context.Background(),
				evaluator.Environment{Files: reader, Commands: runner},
				test.limit,
				maximumUserEnvironmentEvidenceBytes,
				maximumUserEnvironmentEvidenceItems,
			)
			if outcome.Status != test.wantStatus || outcome.UnknownReason != test.wantReason {
				t.Fatalf(
					"status = %s reason=%s summary=%q, want %s/%s",
					outcome.Status,
					outcome.UnknownReason,
					outcome.Summary,
					test.wantStatus,
					test.wantReason,
				)
			}
			if test.wantStatus == model.StatusUnknown {
				operations := 0
				for _, calls := range reader.lstatCalls {
					operations += calls
				}
				for _, calls := range reader.statCalls {
					operations += calls
				}
				if operations != test.limit {
					t.Fatalf("filesystem operations = %d, want exact exhausted limit %d", operations, test.limit)
				}
			}
		})
	}
}

func TestUserEnvironmentEvidenceBudgetBoundaries(t *testing.T) {
	item := support.FactEvidence("budget-test", map[string]any{"value": "x"})
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	exactBytes := len(encoded) + 1

	var retained []model.Evidence
	budget := newInspectionEvidenceBudget(exactBytes, 1)
	if !budget.append(&retained, item) {
		t.Fatal("exact byte and item limit was rejected")
	}
	if budget.append(&retained, item) {
		t.Fatal("item above the exact limit was accepted")
	}
	if len(retained) != 1 {
		t.Fatalf("retained evidence count = %d, want 1", len(retained))
	}

	retained = nil
	budget = newInspectionEvidenceBudget(exactBytes-1, 2)
	if budget.append(&retained, item) {
		t.Fatal("evidence one byte above the limit was accepted")
	}
	if len(retained) != 0 {
		t.Fatalf("retained evidence count = %d, want 0", len(retained))
	}
}

func TestUserEnvironmentEvidenceLimitCannotBecomePassOrNotApplicable(t *testing.T) {
	reader := newHomePathFixtureReader()
	runner := homeExistsFixtureRunner{
		passwd:  "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[{"target":"/","fstype":"ext4"}]}`,
	}
	outcome := evaluateUserEnvironmentPermissionsWithLimits(
		context.Background(),
		evaluator.Environment{Files: reader, Commands: runner},
		maximumUserEnvironmentPathOperations,
		maximumUserEnvironmentEvidenceBytes,
		1,
	)
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownInsufficientEvidence {
		t.Fatalf("outcome = %#v, want UNKNOWN insufficient_evidence", outcome)
	}
	if len(reader.lstatCalls) != 0 {
		t.Fatalf("filesystem calls continued after initial evidence limit: %#v", reader.lstatCalls)
	}
}

func TestHomeExistsStopsBeforeNonLocalIntermediateLink(t *testing.T) {
	reader := newHomePathFixtureReader()
	reader.lstat["/home"] = []system.FileMetadata{directoryMetadata("/home", 1, 10)}
	reader.lstat["/home/user"] = []system.FileMetadata{
		symlinkMetadata("/home/user", "/mnt/remote/bridge", 1, 11),
	}
	reader.lstat["/mnt"] = []system.FileMetadata{directoryMetadata("/mnt", 1, 20)}
	reader.lstat["/mnt/remote"] = []system.FileMetadata{directoryMetadata("/mnt/remote", 2, 21)}
	reader.lstat["/mnt/remote/bridge"] = []system.FileMetadata{
		symlinkMetadata("/mnt/remote/bridge", "/srv/user", 2, 22),
	}
	runner := homeExistsFixtureRunner{
		passwd: "user:x:1000:1000::/home/user:/bin/bash",
		findmnt: `{"filesystems":[
			{"target":"/","fstype":"ext4"},
			{"target":"/mnt/remote","fstype":"nfs4"}
		]}`,
	}

	outcome := evaluateHomeExists(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: runner,
	})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %s reason=%s observed=%q, want UNKNOWN", outcome.Status, outcome.UnknownReason, outcome.Observed)
	}
	if reader.lstatCalls["/mnt/remote"] != 0 || reader.lstatCalls["/mnt/remote/bridge"] != 0 {
		t.Fatalf(
			"non-local Lstat calls = mount:%d bridge:%d, want zero",
			reader.lstatCalls["/mnt/remote"],
			reader.lstatCalls["/mnt/remote/bridge"],
		)
	}
}

type homePathFixtureReader struct {
	lstat      map[string][]system.FileMetadata
	stat       map[string][]system.FileMetadata
	contents   map[string][]byte
	dirEntries map[string][][]os.DirEntry
	dirErrors  map[string][]error
	lstatCalls map[string]int
	statCalls  map[string]int
	dirCalls   map[string]int
}

type fixtureDirEntry struct {
	name string
	mode os.FileMode
}

func (entry fixtureDirEntry) Name() string      { return entry.name }
func (entry fixtureDirEntry) IsDir() bool       { return entry.mode.IsDir() }
func (entry fixtureDirEntry) Type() os.FileMode { return entry.mode.Type() }
func (fixtureDirEntry) Info() (os.FileInfo, error) {
	return nil, errors.New("fixture directory entry info is unavailable")
}

type changingACLHomePathReader struct {
	*homePathFixtureReader
	err error
}

type lstatErrorHomePathReader struct {
	*homePathFixtureReader
	target string
	failAt int
	err    error
	calls  int
}

type sequencedACLHomePathReader struct {
	*homePathFixtureReader
	acl         [][]byte
	aclErrors   []error
	aclCalls    int
	followFinal []bool
}

func (reader *changingACLHomePathReader) ReadXAttrs(
	context.Context,
	string,
	[]string,
	int64,
	bool,
) (map[string][]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, reader.err
}

func (reader *lstatErrorHomePathReader) Lstat(name string) (system.FileMetadata, error) {
	if name == reader.target {
		reader.calls++
		if reader.calls == reader.failAt {
			return system.FileMetadata{}, reader.err
		}
	}
	return reader.homePathFixtureReader.Lstat(name)
}

func (reader *sequencedACLHomePathReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	metadata, err := currentHomePathMetadata(reader.stat, reader.statCalls, name)
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	index := reader.aclCalls
	reader.aclCalls++
	reader.followFinal = append(reader.followFinal, followFinalSymlink)
	if len(reader.aclErrors) > 0 {
		errorIndex := index
		if errorIndex >= len(reader.aclErrors) {
			errorIndex = len(reader.aclErrors) - 1
		}
		if reader.aclErrors[errorIndex] != nil {
			return nil, system.FileMetadata{}, reader.aclErrors[errorIndex]
		}
	}
	if len(reader.acl) == 0 {
		return map[string][]byte{}, metadata, nil
	}
	if index >= len(reader.acl) {
		index = len(reader.acl) - 1
	}
	return map[string][]byte{
		"system.posix_acl_access": append([]byte(nil), reader.acl[index]...),
	}, metadata, nil
}

func newHomePathFixtureReader() *homePathFixtureReader {
	return &homePathFixtureReader{
		lstat:      make(map[string][]system.FileMetadata),
		stat:       make(map[string][]system.FileMetadata),
		contents:   make(map[string][]byte),
		dirEntries: make(map[string][][]os.DirEntry),
		dirErrors:  make(map[string][]error),
		lstatCalls: make(map[string]int),
		statCalls:  make(map[string]int),
		dirCalls:   make(map[string]int),
	}
}

func (reader *homePathFixtureReader) ReadFile(ctx context.Context, name string, limit int64) ([]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	content, exists := reader.contents[name]
	if !exists {
		return nil, system.FileMetadata{}, errors.New("unexpected file read")
	}
	if int64(len(content)) > limit {
		return nil, system.FileMetadata{}, system.ErrReadLimit
	}
	metadata, err := reader.Stat(name)
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	return append([]byte(nil), content...), metadata, nil
}

func (reader *homePathFixtureReader) Stat(name string) (system.FileMetadata, error) {
	return nextHomePathMetadata(reader.stat, reader.statCalls, name)
}

func (reader *homePathFixtureReader) Lstat(name string) (system.FileMetadata, error) {
	return nextHomePathMetadata(reader.lstat, reader.lstatCalls, name)
}

func (reader *homePathFixtureReader) ReadDir(name string) ([]os.DirEntry, error) {
	entries, _, err := reader.ReadDirBounded(name, int(^uint(0)>>1))
	return entries, err
}

func (reader *homePathFixtureReader) ReadDirBounded(name string, limit int) ([]os.DirEntry, bool, error) {
	entries, _, truncated, err := reader.ReadDirBoundedSnapshot(name, limit, nil)
	return entries, truncated, err
}

func (reader *homePathFixtureReader) ReadDirBoundedSnapshot(
	name string,
	limit int,
	expected *system.FileMetadata,
) ([]os.DirEntry, system.FileMetadata, bool, error) {
	if limit < 0 {
		return nil, system.FileMetadata{}, false, errors.New("negative directory limit")
	}
	metadata, err := currentHomePathMetadata(reader.stat, reader.statCalls, name)
	if err != nil {
		return nil, system.FileMetadata{}, false, err
	}
	if expected != nil && metadata != *expected {
		return nil, system.FileMetadata{}, false, system.ErrFileChanged
	}
	sequences, exists := reader.dirEntries[name]
	if !exists || len(sequences) == 0 {
		sequences = [][]os.DirEntry{{}}
	}
	index := reader.dirCalls[name]
	reader.dirCalls[name] = index + 1
	if configured := reader.dirErrors[name]; len(configured) > 0 {
		errorIndex := index
		if errorIndex >= len(configured) {
			errorIndex = len(configured) - 1
		}
		if configured[errorIndex] != nil {
			return nil, system.FileMetadata{}, false, configured[errorIndex]
		}
	}
	if index >= len(sequences) {
		index = len(sequences) - 1
	}
	entries := sequences[index]
	truncated := len(entries) > limit
	if truncated {
		entries = entries[:limit]
	}
	return append([]os.DirEntry(nil), entries...), metadata, truncated, nil
}

func (reader *homePathFixtureReader) ReadXAttrs(
	ctx context.Context,
	name string,
	_ []string,
	_ int64,
	followFinalSymlink bool,
) (map[string][]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	if followFinalSymlink {
		metadata, err := currentHomePathMetadata(reader.stat, reader.statCalls, name)
		return map[string][]byte{}, metadata, err
	}
	metadata, err := currentHomePathMetadata(reader.lstat, reader.lstatCalls, name)
	return map[string][]byte{}, metadata, err
}

func (reader *homePathFixtureReader) Exists(name string) (bool, error) {
	_, err := reader.Lstat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func nextHomePathMetadata(
	values map[string][]system.FileMetadata,
	calls map[string]int,
	name string,
) (system.FileMetadata, error) {
	index := calls[name]
	calls[name] = index + 1
	sequence, exists := values[name]
	if !exists || len(sequence) == 0 {
		return system.FileMetadata{}, os.ErrNotExist
	}
	if index >= len(sequence) {
		index = len(sequence) - 1
	}
	return sequence[index], nil
}

func currentHomePathMetadata(
	values map[string][]system.FileMetadata,
	calls map[string]int,
	name string,
) (system.FileMetadata, error) {
	sequence, exists := values[name]
	if !exists || len(sequence) == 0 {
		return system.FileMetadata{}, os.ErrNotExist
	}
	index := calls[name] - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sequence) {
		index = len(sequence) - 1
	}
	return sequence[index], nil
}

func directoryMetadata(path string, device, inode uint64) system.FileMetadata {
	return system.FileMetadata{
		Path: path, FileType: "directory", Mode: os.ModeDir | 0o755,
		UID: 0, GID: 0, Device: device, Inode: inode,
	}
}

func symlinkMetadata(path, target string, device, inode uint64) system.FileMetadata {
	return system.FileMetadata{
		Path: path, FileType: "symlink", Mode: os.ModeSymlink | 0o777,
		UID: 0, GID: 0, Device: device, Inode: inode, LinkTarget: target,
	}
}

func withPath(metadata system.FileMetadata, path string) system.FileMetadata {
	metadata.Path = path
	return metadata
}

type homeExistsFixtureRunner struct {
	passwd     string
	findmnt    string
	findmntErr error
}

type changingHomeSnapshotRunner struct {
	passwd       []string
	findmnt      []string
	passwdCalls  int
	findmntCalls int
}

type sequencedUserEnvironmentRunner struct {
	passwd           []string
	findmnt          []string
	acl              []string
	passwdCalls      int
	findmntCalls     int
	aclCalls         int
	getfaclArguments [][]string
}

func (*sequencedUserEnvironmentRunner) Available(string) bool {
	return true
}

func (runner *sequencedUserEnvironmentRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	switch spec.Name {
	case "getent":
		value := sequentialHomeFixtureValue(runner.passwd, runner.passwdCalls)
		runner.passwdCalls++
		return executor.Result{
			Executable: "/usr/bin/getent",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte(value),
		}, nil
	case "findmnt":
		value := sequentialHomeFixtureValue(runner.findmnt, runner.findmntCalls)
		runner.findmntCalls++
		return executor.Result{
			Executable: "/usr/bin/findmnt",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte(value),
		}, nil
	case "getfacl":
		value := sequentialHomeFixtureValue(runner.acl, runner.aclCalls)
		if len(runner.acl) == 0 {
			value = "user::rw-\ngroup::r--\nother::r--\n"
		}
		runner.aclCalls++
		runner.getfaclArguments = append(
			runner.getfaclArguments,
			append([]string(nil), spec.Arguments...),
		)
		return executor.Result{
			Executable: "/usr/bin/getfacl",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte(value),
		}, nil
	default:
		return executor.Result{}, errors.New("unexpected fixture command")
	}
}

func (*changingHomeSnapshotRunner) Available(string) bool {
	return true
}

func (runner *changingHomeSnapshotRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	switch spec.Name {
	case "getent":
		value := sequentialHomeFixtureValue(runner.passwd, runner.passwdCalls)
		runner.passwdCalls++
		return executor.Result{
			Executable: "/usr/bin/getent",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte(value),
		}, nil
	case "findmnt":
		value := sequentialHomeFixtureValue(runner.findmnt, runner.findmntCalls)
		runner.findmntCalls++
		return executor.Result{
			Executable: "/usr/bin/findmnt",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte(value),
		}, nil
	default:
		return executor.Result{}, errors.New("unexpected fixture command")
	}
}

func sequentialHomeFixtureValue(values []string, call int) string {
	if len(values) == 0 {
		return ""
	}
	if call >= len(values) {
		return values[len(values)-1]
	}
	return values[call]
}

func findmntFixtureWithMountCount(count int) string {
	if count < 1 {
		return `{"filesystems":[]}`
	}
	var output strings.Builder
	output.WriteString(`{"filesystems":[{"target":"/","fstype":"ext4"}`)
	for index := 1; index < count; index++ {
		fmt.Fprintf(
			&output,
			`,{"target":"/fixture/mount-%05d","fstype":"ext4"}`,
			index,
		)
	}
	output.WriteString(`]}`)
	return output.String()
}

func containsEvidenceSource(evidence []model.Evidence, source string) bool {
	for _, item := range evidence {
		if item.Source == source {
			return true
		}
	}
	return false
}

func (homeExistsFixtureRunner) Available(string) bool {
	return true
}

func (runner homeExistsFixtureRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	switch spec.Name {
	case "getent":
		return executor.Result{
			Executable: "/usr/bin/getent",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte(runner.passwd),
		}, nil
	case "findmnt":
		if runner.findmntErr != nil {
			return executor.Result{}, runner.findmntErr
		}
		return executor.Result{
			Executable: "/usr/bin/findmnt",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte(runner.findmnt),
		}, nil
	case "getfacl":
		return executor.Result{
			Executable: "/usr/bin/getfacl",
			Arguments:  append([]string(nil), spec.Arguments...),
			Stdout:     []byte("user::rw-\ngroup::r--\nother::r--\n"),
		}, nil
	default:
		return executor.Result{}, errors.New("unexpected fixture command")
	}
}
