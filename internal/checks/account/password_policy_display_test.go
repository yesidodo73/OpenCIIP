package account

import (
	"context"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestPassingPasswordPolicyRetainsConfirmedValues(t *testing.T) {
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/pwquality.conf": "minlen=12\ndcredit=-1\nucredit=-1\nlcredit=-1\nocredit=-1\nenforce_for_root\n",
			"/etc/security/pwhistory.conf": "remember=5\n",
			"/etc/login.defs":              "PASS_MIN_DAYS 2\nPASS_MAX_DAYS 60\n",
			"/etc/pam.d/common-password": "password requisite pam_pwquality.so\n" +
				"password required pam_pwhistory.so use_authtok\n" +
				"password sufficient pam_unix.so use_authtok\n",
		}),
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}
	outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)
	if outcome.Status != model.StatusPass {
		t.Fatalf("outcome = %#v, want PASS", outcome)
	}
	var all strings.Builder
	for _, detail := range outcome.Details {
		all.WriteString(detail.Current + " " + detail.Source + "\n")
	}
	for _, expected := range []string{"12자", "remember=5", "PASS_MIN_DAYS=2", "PASS_MAX_DAYS=60", "/etc/login.defs"} {
		if !strings.Contains(all.String(), expected) {
			t.Fatalf("actual value %q missing from details: %#v", expected, outcome.Details)
		}
	}
}

func TestFailingPasswordPolicyShowsLoginDefsAsDefaults(t *testing.T) {
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/pwquality.conf": "minlen=12\ndcredit=-1\nucredit=-1\nlcredit=-1\nocredit=-1\nenforce_for_root\n",
			"/etc/security/pwhistory.conf": "remember=5\n",
			"/etc/login.defs":              "PASS_MIN_DAYS 0\nPASS_MAX_DAYS 99999\n",
			"/etc/pam.d/common-password": "password requisite pam_pwquality.so\n" +
				"password required pam_pwhistory.so use_authtok\n" +
				"password sufficient pam_unix.so use_authtok\n",
		}),
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}
	outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)
	if outcome.Status != model.StatusFail {
		t.Fatalf("outcome = %#v, want FAIL", outcome)
	}
	for _, detail := range outcome.Details {
		if detail.Source == "/etc/login.defs" &&
			strings.Contains(detail.Label, "계정 생성 시") &&
			strings.Contains(detail.Current, "PASS_MIN_DAYS=0") &&
			strings.Contains(detail.Current, "PASS_MAX_DAYS=99999") {
			return
		}
	}
	t.Fatalf("login.defs defaults not shown with their actual keys and values: %#v", outcome.Details)
}

func TestMissingPasswordModulesExplainWhatWasNotFound(t *testing.T) {
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/pwquality.conf": "minlen=12\ndcredit=-1\nucredit=-1\nlcredit=-1\nocredit=-1\nenforce_for_root\n",
			"/etc/security/pwhistory.conf": "remember=5\n",
			"/etc/login.defs":              "PASS_MIN_DAYS 2\nPASS_MAX_DAYS 60\n",
			"/etc/pam.d/common-password":   "password sufficient pam_unix.so\n",
		}),
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}
	outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)
	if outcome.Status != model.StatusFail {
		t.Fatalf("outcome = %#v, want FAIL", outcome)
	}
	for _, expected := range []struct{ label, description string }{
		{"비밀번호 품질 모듈", "비밀번호 품질 검사 모듈(pam_pwquality)"},
		{"비밀번호 이력", "이전 비밀번호 재사용을 제한하는 모듈(pam_pwhistory)"},
	} {
		found := false
		for _, detail := range outcome.Details {
			if detail.Label == expected.label && strings.Contains(detail.Current, expected.description) && detail.Source == "/etc/pam.d/common-password" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing module is not explained: %#v", outcome.Details)
		}
	}
	if !strings.Contains(outcome.Observed, "common-password에 pam_pwquality가 없음") {
		t.Fatalf("report-compatible observed value changed: %q", outcome.Observed)
	}
}
