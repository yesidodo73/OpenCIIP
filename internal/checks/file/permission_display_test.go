package filecheck

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestStaticPermissionShowsTheInspectedOwnerAndMode(t *testing.T) {
	reader := newGuideStartupReader(t, map[string]string{"/etc/passwd": "fixture"},
		map[string]os.FileMode{"/etc/passwd": 0o666}, map[string]int{"/etc/passwd": 1001})
	outcome := staticPermissionEvaluator(permissionPolicy{path: "/etc/passwd", allowedMode: 0o644})(
		context.Background(), model.ResolvedRule{}, evaluator.Environment{Files: reader, Commands: nonOwnerACLFixtureRunner{}},
	)
	if outcome.Status != model.StatusFail || len(outcome.Details) < 2 {
		t.Fatalf("unexpected outcome: %#v", outcome)
	}
	detail := outcome.Details[0]
	if detail.Source != "/etc/passwd" || !strings.Contains(detail.Current, "소유자 UID=1001") || !strings.Contains(detail.Current, "그룹 GID=") || !strings.Contains(detail.Current, "기본 권한=0666") {
		t.Fatalf("actual inspected metadata is missing: %#v", detail)
	}
	if !strings.Contains(detail.Expected, "0644에 포함된 권한만 허용") || !strings.Contains(detail.Expected, "소유 그룹 읽기") {
		t.Fatalf("the allowed permissions are not explained: %#v", detail)
	}
	if !strings.Contains(outcome.Details[1].Current, "허용되지 않은") {
		t.Fatalf("original reason is missing: %#v", outcome.Details)
	}
	for _, text := range []string{"소유 그룹 쓰기", "다른 사용자 쓰기"} {
		if !strings.Contains(outcome.Details[1].Current, text) {
			t.Fatalf("additional permission is not explained: %#v", outcome.Details[1])
		}
	}
	if !strings.Contains(outcome.Observed, "허용되지 않은 권한 비트 0022") || strings.Contains(outcome.Observed, "소유 그룹 쓰기") {
		t.Fatalf("report-compatible observed value changed: %q", outcome.Observed)
	}
}

func TestPermissionBitExplanationDistinguishesCurrentAndExtraBits(t *testing.T) {
	current := permissionModeMeaning(0o640)
	for _, text := range []string{"소유자 읽기·쓰기", "소유 그룹 읽기", "다른 사용자 권한 없음"} {
		if !strings.Contains(current, text) {
			t.Fatalf("current mode explanation missing %q: %q", text, current)
		}
	}
	extra := permissionExcessExplanation(0o240)
	if !strings.Contains(extra, "소유자 쓰기") || !strings.Contains(extra, "소유 그룹 읽기") || strings.Contains(extra, "권한 없음") {
		t.Fatalf("extra mode explanation is ambiguous: %q", extra)
	}
}

func TestConfigPermissionShowsEachInspectedFile(t *testing.T) {
	reader := newGuideStartupReader(t, map[string]string{"/etc/xinetd.conf": "fixture"},
		map[string]os.FileMode{"/etc/xinetd.conf": 0o644}, nil)
	outcome := evaluateGuideConfigPermissions(context.Background(), model.ResolvedRule{},
		evaluator.Environment{Files: reader, Commands: nonOwnerACLFixtureRunner{}},
		[]string{"/etc/xinetd.conf"}, map[int]struct{}{0: {}}, 0o600)
	if outcome.Status != model.StatusFail || len(outcome.Details) < 2 || outcome.Details[0].Source != "/etc/xinetd.conf" ||
		!strings.Contains(outcome.Details[0].Current, "기본 권한=0644") {
		t.Fatalf("actual config metadata is missing: %#v", outcome)
	}
}

func TestMissingInetdConfigsRetainAbsenceEvidence(t *testing.T) {
	reader := newStartupTestReader(t, map[string]string{})
	outcome := evaluateInetdPermissions(context.Background(), model.ResolvedRule{},
		evaluator.Environment{Files: reader, Commands: nonOwnerACLFixtureRunner{}})
	if outcome.Status != model.StatusNotApplicable || len(outcome.Evidence) != 2 || len(outcome.Details) != 2 {
		t.Fatalf("missing config outcome = %#v", outcome)
	}
	for index, path := range []string{"/etc/inetd.conf", "/etc/xinetd.conf"} {
		if outcome.Evidence[index].Source != path || outcome.Evidence[index].Fact["exists"] != false ||
			outcome.Details[index].Source != path || outcome.Details[index].Current != "없음" {
			t.Fatalf("missing-file evidence does not match %s: %#v", path, outcome)
		}
	}
}

func TestStartupPermissionDetailsIncludeAllFindings(t *testing.T) {
	findings := make([]string, 25)
	for index := range findings {
		findings[index] = fmt.Sprintf("/etc/systemd/system/example-%02d: 쓰기 권한", index)
	}
	details := startupPermissionDetails("권한 위반", findings, "root 소유")
	if len(details) != 1 || details[0].Current != strings.Join(findings, "\n") {
		t.Fatalf("startup permission findings were omitted: %#v", details)
	}
}
