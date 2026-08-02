package service

import (
	"strings"
	"testing"
)

func TestClassifyWarningContentRejectsKnownVendorDefaultIssue(t *testing.T) {
	t.Parallel()

	canonical := `Ubuntu 24.04.4 LTS \n \l`
	digest := warningDigest(canonical)
	const expectedDigest = "0f42739b4fee9ba3ea7768ddf304853467e394265dc2dfde4a9531156e57ceb8"
	if digest != expectedDigest {
		t.Fatalf("warningDigest(%q) = %q, want Ubuntu 24.04 rule digest %q", canonical, digest, expectedDigest)
	}
	knownInadequate := map[string]struct{}{digest: {}}
	state, reason := classifyWarningContent(
		canonical,
		digest,
		nil,
		false,
		true,
		knownInadequate,
	)
	if state != "fail" || !strings.Contains(reason, "기본 식별 배너") {
		t.Fatalf("state=%q reason=%q, want deterministic vendor-default failure", state, reason)
	}

	changed := `Ubuntu 24.04.5 LTS \n \l`
	state, reason = classifyWarningContent(
		changed,
		warningDigest(changed),
		nil,
		false,
		true,
		knownInadequate,
	)
	if state != "unknown" || !strings.Contains(reason, "issue escape") {
		t.Fatalf("changed state=%q reason=%q, want conservative UNKNOWN", state, reason)
	}
}

func TestConfiguredWarningHashesRejectsNonCanonicalAndDuplicateDigests(t *testing.T) {
	t.Parallel()

	digest := warningDigest("known default")
	hashes, err := configuredWarningHashes(map[string]any{
		"known": []string{digest},
	}, "known")
	if err != nil || len(hashes) != 1 {
		t.Fatalf("configuredWarningHashes() hashes=%v err=%v", hashes, err)
	}
	for _, values := range [][]string{
		{strings.ToUpper(digest)},
		{" " + digest},
		{digest, digest},
		{"not-a-digest"},
	} {
		if _, err := configuredWarningHashes(map[string]any{"known": values}, "known"); err == nil {
			t.Fatalf("configuredWarningHashes(%q) unexpectedly succeeded", values)
		}
	}
}

func TestLoginWarningDetailsSeparateFailureAndUnknownReasons(t *testing.T) {
	t.Parallel()

	failures := []string{
		"local-console-pre-auth: 경고 문구가 비어 있음",
		"ssh-pre-auth: 승인된 문구와 일치하지 않음",
	}
	unknowns := []string{
		"local-login-post-auth: 동적 MOTD 소스의 실효 문구를 확인하지 못함",
	}
	details := loginWarningDetails(failures, unknowns, "승인된 로그인 경고 문구를 표시해야 합니다.")
	if len(details) != 2 {
		t.Fatalf("details = %#v, want separate failure and unknown sections", details)
	}
	if details[0].Label != "취약 endpoint" || details[1].Label != "수동 확인 endpoint" {
		t.Fatalf("detail labels = %q, %q", details[0].Label, details[1].Label)
	}
	if strings.Contains(details[0].Current, "동적 MOTD") {
		t.Fatalf("failure detail contains an unknown reason: %#v", details[0])
	}
	if strings.Contains(details[1].Current, "경고 문구가 비어 있음") ||
		!strings.Contains(details[1].Current, "동적 MOTD") {
		t.Fatalf("unknown detail is not isolated: %#v", details[1])
	}
}
