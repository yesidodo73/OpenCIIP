package account

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestEvaluateLockoutThresholdUsesPAMOverride(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/faillock.conf": "deny = 3\n",
			"/etc/pam.d/system-auth":      "auth required pam_faillock.so preauth deny=20\nauth [default=die] pam_faillock.so authfail deny=20\naccount required pam_faillock.so deny=20\n",
			"/etc/pam.d/password-auth":    "auth required pam_faillock.so preauth\nauth [default=die] pam_faillock.so authfail\naccount required pam_faillock.so\n",
		}),
		Commands: validAuthselectFixture(),
		Platform: model.PlatformInfo{Family: "rhel"},
	}
	rule := model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{"default_deny": 3}}}

	outcome := evaluateLockoutThreshold(context.Background(), rule, environment)

	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusFail, outcome)
	}
	if !strings.Contains(outcome.Observed, "deny=20") || !strings.Contains(outcome.Observed, "PAM 재정의") {
		t.Fatalf("observed = %q, want unsafe PAM deny override", outcome.Observed)
	}
}

func TestEvaluateLockoutThresholdReturnsUnknownForUnparseablePAMOverride(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/faillock.conf": "deny = 3\n",
			"/etc/pam.d/system-auth":      "auth required pam_faillock.so preauth deny=not-a-number\nauth sufficient pam_unix.so\nauth required pam_faillock.so authfail\naccount required pam_faillock.so\n",
			"/etc/pam.d/password-auth":    "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so\nauth required pam_faillock.so authfail\naccount required pam_faillock.so\n",
		}),
		Commands: validAuthselectFixture(),
		Platform: model.PlatformInfo{Family: "rhel"},
	}
	rule := model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{"default_deny": 3}}}

	outcome := evaluateLockoutThreshold(context.Background(), rule, environment)

	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
	}
	if !strings.Contains(outcome.Observed, "deny 해석 불가") {
		t.Fatalf("observed = %q, want PAM deny parse failure", outcome.Observed)
	}
}

func TestAuthselectReportsNoConfigurationRequiresExactExitAndMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result executor.Result
		want   bool
	}{
		{
			name:   "stdout",
			result: executor.Result{ExitCode: 2, Stdout: []byte("No existing configuration detected.\n")},
			want:   true,
		},
		{
			name:   "stderr",
			result: executor.Result{ExitCode: 2, Stderr: []byte("No existing configuration detected.\r\n")},
			want:   true,
		},
		{
			name:   "unexpected exit",
			result: executor.Result{ExitCode: 1, Stdout: []byte("No existing configuration detected.\n")},
		},
		{
			name:   "additional output",
			result: executor.Result{ExitCode: 2, Stdout: []byte("warning\nNo existing configuration detected.\n")},
		},
		{
			name:   "both streams",
			result: executor.Result{ExitCode: 2, Stdout: []byte("No existing configuration detected.\n"), Stderr: []byte("No existing configuration detected.\n")},
		},
		{
			name:   "truncated",
			result: executor.Result{ExitCode: 2, Stdout: []byte("No existing configuration detected.\n"), Truncated: true},
		},
		{
			name:   "timed out",
			result: executor.Result{ExitCode: 2, Stdout: []byte("No existing configuration detected.\n"), TimedOut: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := authselectReportsNoConfiguration(test.result); got != test.want {
				t.Fatalf("authselectReportsNoConfiguration() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestEvaluateLockoutThresholdFailsForExactUnmanagedRHELLocalSSHPath(t *testing.T) {
	t.Parallel()

	environment := unmanagedRHELLockoutFixture(
		"usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
		nil,
	)
	rule := model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{"default_deny": 3}}}

	outcome := evaluateLockoutThreshold(context.Background(), rule, environment)

	if outcome.Status != model.StatusFail || outcome.UnknownReason != "" {
		t.Fatalf("outcome = %#v, want definite unmanaged RHEL FAIL", outcome)
	}
	for _, expected := range []string{
		"authselect 미구성",
		"도달 가능한 SSH PAM 비밀번호 인증 조건=4개",
		"AuthenticationMethods=any → password",
		"/etc/pam.d/password-auth",
		"pam_faillock.so/pam_tally2.so 없음",
	} {
		if !strings.Contains(outcome.Observed, expected) {
			t.Fatalf("observed = %q, want %q", outcome.Observed, expected)
		}
	}
	if len(outcome.Details) != 1 ||
		outcome.Details[0].Label != "SSH 계정 잠금" ||
		!strings.Contains(outcome.Details[0].Source, "sshd.service") ||
		!strings.Contains(outcome.Details[0].Source, "/etc/pam.d/sshd") ||
		!strings.Contains(outcome.Details[0].Source, "/etc/pam.d/password-auth") {
		t.Fatalf("details = %#v, want the effective local PAM source", outcome.Details)
	}
	evidenceSources := make([]string, 0, len(outcome.Evidence))
	syntheticContextCount := 0
	for _, item := range outcome.Evidence {
		evidenceSources = append(evidenceSources, item.Source)
		if item.Source == "sshd-effective-password-pam" {
			if item.Fact["context_user"] != unmanagedRHELSSHProbeUser ||
				item.Fact["synthetic_user"] != true ||
				item.Fact["non_root"] != true {
				t.Fatalf("effective SSH evidence = %#v, want explicit synthetic non-root context", item.Fact)
			}
			syntheticContextCount++
		}
	}
	if syntheticContextCount != 4 {
		t.Fatalf("synthetic SSH evidence count = %d, want 4", syntheticContextCount)
	}
	for _, expected := range []string{
		"/usr/bin/authselect",
		"/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d/50-redhat.conf",
		"/etc/crypto-policies/back-ends/opensshserver.config",
		"sshd-effective-password-pam",
		"/etc/pam.d/sshd",
		"/etc/pam.d/password-auth",
	} {
		if !slices.Contains(evidenceSources, expected) {
			t.Fatalf("evidence sources = %#v, want %q", evidenceSources, expected)
		}
	}
}

func TestEvaluateLockoutThresholdDoesNotUseRootPasswordContextForUnmanagedRHEL(t *testing.T) {
	t.Parallel()

	environment := unmanagedRHELLockoutFixture(
		"usepam yes\npasswordauthentication no\nkbdinteractiveauthentication no\nauthenticationmethods any\n",
		nil,
	)
	commands := environment.Commands.(fixtureCommandRunner)
	for _, address := range []string{"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1"} {
		commands[commandKey(
			"sshd",
			"-T",
			"-C",
			"user=root,host=fixture,addr="+address,
		)] = fixtureCommandResponse{result: executor.Result{
			ExitCode: 0,
			Stdout: []byte(
				"usepam yes\n" +
					"passwordauthentication yes\n" +
					"authenticationmethods any\n",
			),
		}}
	}
	environment.Commands = commands

	outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want UNKNOWN from the synthetic non-root context", outcome)
	}
	if !strings.Contains(outcome.Observed, "passwordauthentication=no") {
		t.Fatalf("observed = %q, want the non-root effective setting", outcome.Observed)
	}
}

func TestEvaluateLockoutThresholdKeepsUnmanagedRHELAmbiguousPathsUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sshdSettings string
		files        map[string]string
		wantText     string
	}{
		{
			name:         "password authentication disabled",
			sshdSettings: "usepam yes\npasswordauthentication no\nauthenticationmethods any\n",
			wantText:     "passwordauthentication=no",
		},
		{
			name:         "PAM disabled",
			sshdSettings: "usepam no\npasswordauthentication yes\nauthenticationmethods any\n",
			wantText:     "usepam=no",
		},
		{
			name:         "authentication methods omit PAM password",
			sshdSettings: "usepam yes\npasswordauthentication yes\npubkeyauthentication yes\nauthenticationmethods publickey\n",
			wantText:     "authenticationmethods=publickey",
		},
		{
			name:         "PAM password follows a public key step",
			sshdSettings: "usepam yes\npasswordauthentication yes\npubkeyauthentication yes\nauthenticationmethods publickey,password\n",
			wantText:     "도달 가능한 PAM 비밀번호 인증 순서 없음",
		},
		{
			name:         "PAM password follows a disabled public key step",
			sshdSettings: "usepam yes\npasswordauthentication yes\npubkeyauthentication no\nauthenticationmethods publickey,password\n",
			wantText:     "도달 가능한 PAM 비밀번호 인증 순서 없음",
		},
		{
			name:         "authentication methods missing",
			sshdSettings: "usepam yes\npasswordauthentication yes\n",
			wantText:     "authenticationmethods 누락",
		},
		{
			name:         "global SSH deny users restriction",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\ndenyusers *\n",
			wantText:     "access_restriction=denyusers",
		},
		{
			name:         "global SSH allow users restriction",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\nallowusers operator\n",
			wantText:     "access_restriction=allowusers",
		},
		{
			name:         "global SSH deny groups restriction",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\ndenygroups locked\n",
			wantText:     "access_restriction=denygroups",
		},
		{
			name:         "global SSH allow groups restriction",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\nallowgroups operators\n",
			wantText:     "access_restriction=allowgroups",
		},
		{
			name:         "external authentication module",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth sufficient pam_sss.so\n" +
					"auth sufficient pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "pam_sss.so",
		},
		{
			name:         "bracketed control",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required pam_env.so\n" +
					"auth [success=1 default=ignore] pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "복합 PAM 제어",
		},
		{
			name:         "ignore missing prefix on auth type",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required pam_env.so\n" +
					"-auth sufficient pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "auth/account PAM type의 '-' 접두어",
		},
		{
			name:         "nonstandard PAM module path",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required pam_env.so\n" +
					"auth sufficient /tmp/pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "/tmp/pam_unix.so",
		},
		{
			name:         "PAM type case variant",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "Auth required pam_env.so\n" +
					"auth sufficient pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "알 수 없는 PAM type=Auth",
		},
		{
			name:         "PAM control case variant",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth Required pam_env.so\n" +
					"auth sufficient pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "Required pam_env.so",
		},
		{
			name:         "PAM module case variant",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required PAM_env.so\n" +
					"auth sufficient pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "PAM_env.so",
		},
		{
			name:         "custom PAM include",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/sshd": "auth substack company-auth\n" +
					"account include company-auth\n",
				"/etc/pam.d/company-auth": "auth sufficient pam_unix.so\n" +
					"auth required pam_deny.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "사용자 지정 PAM",
		},
		{
			name:         "flattened substack cannot bypass parent deny",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/sshd": "auth substack password-auth\n" +
					"auth required pam_deny.so\n" +
					"auth include postlogin\n" +
					"account required pam_sepermit.so\n" +
					"account required pam_nologin.so\n" +
					"account include password-auth\n",
			},
			wantText: "/etc/pam.d/sshd auth topology",
		},
		{
			name:         "pam unix and deny from different include boundaries",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required pam_env.so\n" +
					"auth sufficient pam_unix.so\n" +
					"account required pam_unix.so\n",
				"/etc/pam.d/postlogin": "auth required pam_deny.so\n",
			},
			wantText: "단일 pam_deny.so 인증 종료 경로가 없음",
		},
		{
			name:         "repeated password auth substack",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/sshd": "auth substack password-auth\n" +
					"auth substack password-auth\n" +
					"auth include postlogin\n" +
					"account required pam_sepermit.so\n" +
					"account required pam_nologin.so\n" +
					"account include password-auth\n",
			},
			wantText: "/etc/pam.d/sshd auth topology",
		},
		{
			name:         "include cannot substitute for standard substack",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/sshd": "auth include password-auth\n" +
					"auth include postlogin\n" +
					"account required pam_sepermit.so\n" +
					"account required pam_nologin.so\n" +
					"account include password-auth\n",
			},
			wantText: "예상=substack password-auth",
		},
		{
			name:         "recursive PAM include",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth include sshd\n" +
					"account required pam_unix.so\n",
			},
			wantText: "PAM include cycle",
		},
		{
			name:         "global PAM include is unresolved",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/sshd": "auth substack password-auth\n" +
					"auth include postlogin\n" +
					"account required pam_sepermit.so\n" +
					"account required pam_nologin.so\n" +
					"account include password-auth\n" +
					"@include password-auth\n",
			},
			wantText: "전역 @include 경계",
		},
		{
			name:         "unparseable PAM include",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/sshd": "auth include ../../company-auth\n",
			},
			wantText: "invalid PAM service name",
		},
		{
			name:         "custom SSH include",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/ssh/sshd_config": "UsePAM yes\nPasswordAuthentication yes\nInclude /srv/ssh/*.conf\n",
			},
			wantText: "match_or_include_ambiguous=true",
		},
		{
			name:         "static SSH include contains Match",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/ssh/sshd_config":  "UsePAM yes\nPasswordAuthentication yes\nInclude /etc/ssh/company.conf\n",
				"/etc/ssh/company.conf": "Match User operator\nPasswordAuthentication no\n",
			},
			wantText: "match_or_include_ambiguous=true",
		},
		{
			name:         "recursive static SSH include",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/ssh/sshd_config":  "UsePAM yes\nPasswordAuthentication yes\nInclude /etc/ssh/company.conf\n",
				"/etc/ssh/company.conf": "Include /etc/ssh/sshd_config\n",
			},
			wantText: "match_or_include_ambiguous=true",
		},
		{
			name:         "pam deny precedes local password path",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required pam_env.so\n" +
					"auth required pam_deny.so\n" +
					"auth sufficient pam_unix.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "pam_deny.so가 pam_unix.so보다 먼저",
		},
		{
			name:         "pam deny termination missing",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required pam_env.so\n" +
					"auth sufficient pam_unix.so\n" +
					"account required pam_unix.so\n",
			},
			wantText: "단일 pam_deny.so 인증 종료 경로가 없음",
		},
		{
			name:         "unmanaged faillock requires topology review",
			sshdSettings: "usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
			files: map[string]string{
				"/etc/pam.d/password-auth": "auth required pam_faillock.so preauth\n" +
					"auth sufficient pam_unix.so\n" +
					"auth required pam_faillock.so authfail\n" +
					"account required pam_faillock.so\n",
			},
			wantText: "pam_faillock.so",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			environment := unmanagedRHELLockoutFixture(test.sshdSettings, test.files)
			outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

			if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
				t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
			}
			if !strings.Contains(strings.ToLower(outcome.Observed), strings.ToLower(test.wantText)) {
				t.Fatalf("observed = %q, want %q", outcome.Observed, test.wantText)
			}
		})
	}
}

func TestInspectSSHPAMPasswordPathRequiresReachableAuthenticationSequence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		settings   map[string]string
		wantPath   string
		wantReason string
	}{
		{
			name: "default any permits password",
			settings: map[string]string{
				"authenticationmethods":  "any",
				"passwordauthentication": "yes",
			},
			wantPath: "AuthenticationMethods=any → password",
		},
		{
			name: "password first is immediately reachable",
			settings: map[string]string{
				"authenticationmethods":  "password,publickey",
				"pubkeyauthentication":   "no",
				"passwordauthentication": "yes",
			},
			wantPath: "AuthenticationMethods=password,publickey",
		},
		{
			name: "explicit PAM keyboard interactive first is immediately reachable",
			settings: map[string]string{
				"authenticationmethods":        "keyboard-interactive:pam,publickey",
				"pubkeyauthentication":         "no",
				"kbdinteractiveauthentication": "yes",
			},
			wantPath: "AuthenticationMethods=keyboard-interactive:pam,publickey",
		},
		{
			name: "public key before password does not prove credential reachability",
			settings: map[string]string{
				"authenticationmethods":  "publickey,password",
				"pubkeyauthentication":   "yes",
				"passwordauthentication": "yes",
			},
			wantReason: "도달 가능한 PAM 비밀번호 인증 순서 없음",
		},
		{
			name: "public key before PAM keyboard interactive does not prove credential reachability",
			settings: map[string]string{
				"authenticationmethods":        "publickey,keyboard-interactive:pam",
				"pubkeyauthentication":         "yes",
				"kbdinteractiveauthentication": "yes",
			},
			wantReason: "도달 가능한 PAM 비밀번호 인증 순서 없음",
		},
		{
			name: "public key only has no PAM password stage",
			settings: map[string]string{
				"authenticationmethods": "publickey",
				"pubkeyauthentication":  "yes",
			},
			wantReason: "도달 가능한 PAM 비밀번호 인증 순서 없음",
		},
		{
			name: "disabled prerequisite makes sequence unreachable",
			settings: map[string]string{
				"authenticationmethods":  "publickey,password",
				"pubkeyauthentication":   "no",
				"passwordauthentication": "yes",
			},
			wantReason: "도달 가능한 PAM 비밀번호 인증 순서 없음",
		},
		{
			name: "missing authentication methods is unresolved",
			settings: map[string]string{
				"passwordauthentication": "yes",
			},
			wantReason: "authenticationmethods 누락",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path, reason := inspectSSHPAMPasswordPath(test.settings)
			if path != test.wantPath {
				t.Fatalf("path = %q, want %q; reason = %q", path, test.wantPath, reason)
			}
			if !strings.Contains(reason, test.wantReason) {
				t.Fatalf("reason = %q, want substring %q", reason, test.wantReason)
			}
		})
	}
}

func TestEvaluateLockoutThresholdDoesNotTreatUnexpectedAuthselectFailureAsUnmanaged(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Commands: fixtureCommandRunner{
			commandKey("authselect", "current"): {
				result: executor.Result{ExitCode: 2, Stderr: []byte("profile database is unavailable\n")},
			},
		},
		Platform: model.PlatformInfo{Family: "rhel", InitSystem: "systemd"},
	}

	outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want UNKNOWN for an unexpected authselect failure", outcome)
	}
	if !strings.Contains(outcome.Observed, "authselect current exit=2") {
		t.Fatalf("observed = %q, want authselect exit evidence", outcome.Observed)
	}
}

func TestEvaluateLockoutThresholdRequiresCompleteRockyFaillockTopology(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stack      string
		wantStatus model.Status
		wantText   string
	}{
		{
			name: "Rocky hardened topology passes",
			stack: "auth required pam_env.so\n" +
				"auth required pam_faillock.so preauth silent\n" +
				"auth sufficient pam_fprintd.so\n" +
				"auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n" +
				"auth [default=1 ignore=ignore success=ok] pam_localuser.so\n" +
				"auth sufficient pam_unix.so\n" +
				"auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n" +
				"auth sufficient pam_sss.so forward_pass\n" +
				"auth required pam_faillock.so authfail\n" +
				"account required pam_faillock.so\n",
			wantStatus: model.StatusPass,
			wantText:   "deny=3",
		},
		{
			name: "preauth without authfail fails",
			stack: "auth required pam_faillock.so preauth silent\n" +
				"auth sufficient pam_unix.so\n" +
				"account required pam_faillock.so\n",
			wantStatus: model.StatusFail,
			wantText:   "authfail",
		},
		{
			name: "sufficient pam_permit before recorder is unknown",
			stack: "auth required pam_faillock.so preauth silent\n" +
				"auth sufficient pam_permit.so\n" +
				"auth required pam_faillock.so authfail\n" +
				"account required pam_faillock.so\n",
			wantStatus: model.StatusUnknown,
			wantText:   "pam_permit",
		},
		{
			name: "documented authsucc topology passes",
			stack: "auth [success=1 default=bad] pam_unix.so\n" +
				"auth [default=die] pam_faillock.so authfail\n" +
				"auth sufficient pam_faillock.so authsucc\n" +
				"auth required pam_deny.so\n",
			wantStatus: model.StatusPass,
			wantText:   "deny=3",
		},
		{
			name: "sufficient authentication bypassing authsucc is unknown",
			stack: "auth sufficient pam_unix.so\n" +
				"auth requisite pam_faillock.so authfail\n" +
				"auth sufficient pam_faillock.so authsucc\n" +
				"auth required pam_deny.so\n",
			wantStatus: model.StatusUnknown,
			wantText:   "authsucc pam_faillock.so보다 먼저 성공",
		},
		{
			name: "non terminating authfail before authsucc is unknown",
			stack: "auth [success=1 default=bad] pam_unix.so\n" +
				"auth required pam_faillock.so authfail\n" +
				"auth sufficient pam_faillock.so authsucc\n" +
				"auth required pam_deny.so\n",
			wantStatus: model.StatusUnknown,
			wantText:   "실패 횟수를 지울 수 있음",
		},
		{
			name: "account topology without successful credential exit is unknown",
			stack: "auth required pam_faillock.so preauth\n" +
				"auth required pam_unix.so\n" +
				"auth required pam_faillock.so authfail\n" +
				"auth required pam_deny.so\n" +
				"account required pam_faillock.so\n",
			wantStatus: model.StatusUnknown,
			wantText:   "정상 인증 성공 경로",
		},
		{
			name: "account success jump landing on deny is unknown",
			stack: "auth required pam_faillock.so preauth\n" +
				"auth [success=1 default=bad] pam_unix.so\n" +
				"auth [default=die] pam_faillock.so authfail\n" +
				"auth required pam_deny.so\n" +
				"account required pam_faillock.so\n",
			wantStatus: model.StatusUnknown,
			wantText:   "정상 인증 성공 경로",
		},
		{
			name: "sufficient authsucc without immediate deny is unknown",
			stack: "auth [success=1 default=bad] pam_unix.so\n" +
				"auth [default=die] pam_faillock.so authfail\n" +
				"auth sufficient pam_faillock.so authsucc\n" +
				"auth optional pam_warn.so\n" +
				"auth required pam_deny.so\n",
			wantStatus: model.StatusUnknown,
			wantText:   "확실히 거부하는 pam_deny.so가 없음",
		},
		{
			name: "required authsucc is unknown",
			stack: "auth [success=1 default=bad] pam_unix.so\n" +
				"auth [default=die] pam_faillock.so authfail\n" +
				"auth required pam_faillock.so authsucc\n" +
				"auth required pam_deny.so\n",
			wantStatus: model.StatusUnknown,
			wantText:   "문서화된 sufficient 제어",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			environment := evaluator.Environment{
				Files: newAccountFixtureReader(map[string]string{
					"/etc/security/faillock.conf": "deny = 3\n",
					"/etc/pam.d/system-auth":      test.stack,
					"/etc/pam.d/password-auth":    test.stack,
				}),
				Commands: validAuthselectFixture(),
				Platform: model.PlatformInfo{Family: "rhel"},
			}
			rule := model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{"default_deny": 3}}}
			outcome := evaluateLockoutThreshold(context.Background(), rule, environment)
			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, test.wantStatus, outcome)
			}
			if !strings.Contains(outcome.Observed, test.wantText) {
				t.Fatalf("observed = %q, want substring %q", outcome.Observed, test.wantText)
			}
		})
	}
}

func TestAssessFaillockTopologyRejectsFlattenedForeignServiceControlFlow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rules    []support.PAMRule
		wantText string
	}{
		{
			name: "nested sufficient permit is not a root-stack bypass",
			rules: []support.PAMRule{
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 1, Type: "auth", Control: "required", Module: "pam_faillock.so", Args: []string{"preauth"}},
				{Service: "nested-auth", Path: "/etc/pam.d/nested-auth", Line: 1, Type: "auth", Control: "sufficient", Module: "pam_permit.so"},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 3, Type: "auth", Control: "sufficient", Module: "pam_unix.so"},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 4, Type: "auth", Control: "required", Module: "pam_faillock.so", Args: []string{"authfail"}},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 5, Type: "account", Control: "required", Module: "pam_faillock.so"},
			},
			wantText: "pam_permit.so의 루트 스택 도달성",
		},
		{
			name: "nested numeric jump cannot prove root authsucc reachability",
			rules: []support.PAMRule{
				{Service: "nested-auth", Path: "/etc/pam.d/nested-auth", Line: 1, Type: "auth", Control: "[success=1 default=bad]", Module: "pam_unix.so"},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 2, Type: "auth", Control: "[default=die]", Module: "pam_faillock.so", Args: []string{"authfail"}},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 3, Type: "auth", Control: "sufficient", Module: "pam_faillock.so", Args: []string{"authsucc"}},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 4, Type: "auth", Control: "required", Module: "pam_deny.so"},
			},
			wantText: "성공 인증 경로",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			violations, unknowns := assessFaillockPAMTopology("system-auth", test.rules)
			if len(violations) != 0 {
				t.Fatalf("violations = %v, want none", violations)
			}
			if !strings.Contains(strings.Join(unknowns, "; "), test.wantText) {
				t.Fatalf("unknowns = %v, want substring %q", unknowns, test.wantText)
			}
		})
	}
}

func TestAssessSURestrictionPAMDoesNotIgnorePrecedingBypass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rules     []support.PAMRule
		wantState suPAMState
		wantText  string
	}{
		{
			name: "sufficient pam_permit is a definite bypass",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/su", Line: 1, Type: "auth", Control: "sufficient", Module: "pam_permit.so"},
				{Path: "/etc/pam.d/su", Line: 2, Type: "auth", Control: "required", Module: "pam_wheel.so", Args: []string{"use_uid"}},
			},
			wantState: suPAMFailed,
			wantText:  "pam_permit.so sufficient",
		},
		{
			name: "other sufficient module is ambiguous",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/su", Line: 1, Type: "auth", Control: "sufficient", Module: "pam_unix.so"},
				{Path: "/etc/pam.d/su", Line: 2, Type: "auth", Control: "required", Module: "pam_wheel.so", Args: []string{"use_uid"}},
			},
			wantState: suPAMUnknown,
			wantText:  "pam_unix.so sufficient",
		},
		{
			name: "root shortcut does not bypass general account restriction",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/su", Line: 1, Type: "auth", Control: "sufficient", Module: "pam_rootok.so"},
				{Path: "/etc/pam.d/su", Line: 2, Type: "auth", Control: "required", Module: "pam_wheel.so", Args: []string{"use_uid", "group=wheel"}},
			},
			wantState: suPAMEnforced,
			wantText:  "group=wheel",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assessment := assessSURestrictionPAM(test.rules)
			if assessment.State != test.wantState {
				t.Fatalf("state = %d, want %d; assessment = %#v", assessment.State, test.wantState, assessment)
			}
			if !strings.Contains(assessment.Observed, test.wantText) {
				t.Fatalf("observed = %q, want substring %q", assessment.Observed, test.wantText)
			}
		})
	}
}

func TestEvaluatePasswordHashUsesPAMUnixOverride(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{Files: newAccountFixtureReader(map[string]string{
		"/etc/login.defs":          "ENCRYPT_METHOD SHA512\n",
		"/etc/shadow":              "root:$6$salt$hash:20000:0:99999:7:::\n",
		"/etc/pam.d/system-auth":   "password sufficient pam_unix.so sha512 shadow use_authtok\n",
		"/etc/pam.d/password-auth": "password sufficient pam_unix.so md5 shadow use_authtok\n",
	}), Platform: model.PlatformInfo{Family: "rhel"}}
	rule := passwordHashRule()

	outcome := evaluatePasswordHash(context.Background(), rule, environment)

	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusFail, outcome)
	}
	if !strings.Contains(outcome.Observed, "password-auth pam_unix=MD5") || !strings.Contains(outcome.Observed, "PAM 재정의") {
		t.Fatalf("observed = %q, want weak pam_unix override", outcome.Observed)
	}
}

func TestEvaluatePasswordHashReturnsUnknownForConflictingPAMUnixOverrides(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{Files: newAccountFixtureReader(map[string]string{
		"/etc/login.defs":          "ENCRYPT_METHOD SHA512\n",
		"/etc/shadow":              "root:$6$salt$hash:20000:0:99999:7:::\n",
		"/etc/pam.d/system-auth":   "password sufficient pam_unix.so sha512 yescrypt shadow use_authtok\n",
		"/etc/pam.d/password-auth": "password sufficient pam_unix.so sha512 shadow use_authtok\n",
	}), Platform: model.PlatformInfo{Family: "rhel"}}

	outcome := evaluatePasswordHash(context.Background(), passwordHashRule(), environment)

	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
	}
	if !strings.Contains(outcome.Observed, "해석할 수 없음") {
		t.Fatalf("observed = %q, want ambiguous pam_unix override", outcome.Observed)
	}
}

func TestEvaluatePasswordHashUsesDebianCommonPasswordStack(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/login.defs":            "ENCRYPT_METHOD SHA512\n",
			"/etc/shadow":                "root:$6$salt$hash:20000:0:99999:7:::\n",
			"/etc/pam.d/common-password": "password required pam_unix.so sha512 shadow\n",
		}),
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}

	outcome := evaluatePasswordHash(context.Background(), passwordHashRule(), environment)

	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusPass, outcome)
	}
	if !strings.Contains(outcome.Observed, "common-password pam_unix=SHA512") {
		t.Fatalf("observed = %q, want Debian PAM stack", outcome.Observed)
	}
}

func TestEvaluatePasswordHashAcceptsStockDebianPAMControl(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/login.defs": "ENCRYPT_METHOD SHA512\n",
			"/etc/shadow":     "root:!:20000:0:99999:7:::\nopenciip:$6$salt$hash:20000:0:99999:7:::\n",
			"/etc/pam.d/common-password": "" +
				"password [success=1 default=ignore] pam_unix.so obscure yescrypt\n" +
				"password requisite pam_deny.so\n" +
				"password required pam_permit.so\n",
		}),
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}

	outcome := evaluatePasswordHash(context.Background(), passwordHashRule(), environment)

	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusPass, outcome)
	}
	if !strings.Contains(outcome.Observed, "common-password pam_unix=YESCRYPT") {
		t.Fatalf("observed = %q, want stock Debian yescrypt policy", outcome.Observed)
	}
}

func TestEvaluatePasswordHashRequiresReachablePAMUnix(t *testing.T) {
	t.Parallel()

	stockStack := "password requisite pam_pwquality.so\n" +
		"password requisite pam_pwhistory.so use_authtok\n" +
		"password sufficient pam_unix.so sha512 shadow use_authtok\n" +
		"password [success=1 default=ignore] pam_localuser.so\n" +
		"password sufficient pam_sss.so use_authtok\n" +
		"password required pam_deny.so\n"
	tests := []struct {
		name       string
		stack      string
		wantStatus model.Status
		wantText   string
	}{
		{
			name:       "Rocky hardened password stack passes",
			stack:      stockStack,
			wantStatus: model.StatusPass,
			wantText:   "pam_unix=SHA512",
		},
		{
			name: "preceding sufficient permit is unknown",
			stack: "password sufficient pam_permit.so\n" +
				"password sufficient pam_unix.so sha512 shadow use_authtok\n",
			wantStatus: model.StatusUnknown,
			wantText:   "pam_unix.so보다 먼저 성공",
		},
		{
			name: "preceding custom writer is unknown",
			stack: "password required pam_exec.so expose_authtok /usr/local/sbin/password-writer\n" +
				"password sufficient pam_unix.so sha512 shadow use_authtok\n",
			wantStatus: model.StatusUnknown,
			wantText:   "비밀번호를 변경",
		},
		{
			name: "writer after non-terminal pam_unix is unknown",
			stack: "password required pam_unix.so sha512 shadow use_authtok\n" +
				"password required pam_exec.so expose_authtok /usr/local/sbin/password-writer\n",
			wantStatus: model.StatusUnknown,
			wantText:   "pam_unix.so 뒤에서 비밀번호를 다시 변경",
		},
		{
			name: "custom writer after sufficient pam_unix is unknown",
			stack: "password sufficient pam_unix.so sha512 shadow use_authtok\n" +
				"password sufficient pam_exec.so expose_authtok /usr/local/sbin/password-writer\n",
			wantStatus: model.StatusUnknown,
			wantText:   "대체 경로",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			environment := evaluator.Environment{Files: newAccountFixtureReader(map[string]string{
				"/etc/login.defs":          "ENCRYPT_METHOD SHA512\n",
				"/etc/shadow":              "root:$6$salt$hash:20000:0:99999:7:::\n",
				"/etc/pam.d/system-auth":   test.stack,
				"/etc/pam.d/password-auth": test.stack,
			}), Platform: model.PlatformInfo{Family: "rhel"}}
			outcome := evaluatePasswordHash(context.Background(), passwordHashRule(), environment)
			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, test.wantStatus, outcome)
			}
			if !strings.Contains(outcome.Observed, test.wantText) {
				t.Fatalf("observed = %q, want substring %q", outcome.Observed, test.wantText)
			}
		})
	}
}

func TestAssessPasswordPolicyPAMFlowDoesNotIgnorePrecedingBypass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		rules         []support.PAMRule
		wantViolation string
		wantUnknown   string
	}{
		{
			name: "sufficient pam_permit bypasses both policy modules",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "sufficient", Module: "pam_permit.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
			wantViolation: "pam_permit.so",
		},
		{
			name: "general sufficient module has an indeterminate bypass",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "sufficient", Module: "pam_custom.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
			wantUnknown: "pam_custom.so",
		},
		{
			name: "nested pam_permit has an indeterminate substack boundary",
			rules: []support.PAMRule{
				{Service: "nested-password", Path: "/etc/pam.d/nested-password", Line: 1, Type: "password", Control: "sufficient", Module: "pam_permit.so"},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
			wantUnknown: "include/substack",
		},
		{
			name: "bracketed jump before history is indeterminate",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "[success=1 default=ignore]", Module: "pam_succeed_if.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
			wantUnknown: "pam_succeed_if.so",
		},
		{
			name: "standard modules before sufficient pam_unix are not bypassed",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
		},
		{
			name: "required pam_unix before policy modules is a violation",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "required", Module: "pam_unix.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
			},
			wantViolation: "pam_unix.so가 pwquality/pwhistory보다 먼저",
		},
		{
			name: "Rocky hardened full password stack remains valid",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"sha512", "shadow", "use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "[success=1 default=ignore]", Module: "pam_localuser.so"},
				{Path: "/etc/pam.d/system-auth", Line: 5, Type: "password", Control: "sufficient", Module: "pam_sss.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 6, Type: "password", Control: "required", Module: "pam_deny.so"},
			},
		},
		{
			name: "pwhistory without token handoff is unknown",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwhistory.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
			wantUnknown: "이전 정책 모듈의 비밀번호 토큰",
		},
		{
			name: "pwhistory before pwquality is unknown",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
			wantUnknown: "pam_pwhistory.so가 pam_pwquality.so보다 먼저",
		},
		{
			name: "writer between policies and pam_unix is unknown",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "required", Module: "pam_exec.so", Args: []string{"expose_authtok", "/usr/local/sbin/password-writer"}},
				{Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
			},
			wantUnknown: "검증된 pam_unix.so보다 먼저 비밀번호를 변경",
		},
		{
			name: "writer after pam_unix without token handoff is unknown",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "sufficient", Module: "pam_sss.so"},
			},
			wantUnknown: "검증되지 않은 새 비밀번호 토큰",
		},
		{
			name: "unknown module after pam_unix is unknown",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwhistory.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "sufficient", Module: "pam_unix.so", Args: []string{"use_authtok"}},
				{Path: "/etc/pam.d/system-auth", Line: 4, Type: "password", Control: "required", Module: "pam_custom_password.so"},
			},
			wantUnknown: "후속 비밀번호 변경 여부",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			violations, unknowns := assessPasswordPolicyPAMFlow("system-auth", test.rules)
			joinedViolations := strings.Join(violations, "; ")
			joinedUnknowns := strings.Join(unknowns, "; ")
			if test.wantViolation != "" && !strings.Contains(joinedViolations, test.wantViolation) {
				t.Fatalf("violations = %q, want substring %q", joinedViolations, test.wantViolation)
			}
			if test.wantViolation == "" && len(violations) != 0 {
				t.Fatalf("violations = %v, want none", violations)
			}
			if test.wantUnknown != "" && !strings.Contains(joinedUnknowns, test.wantUnknown) {
				t.Fatalf("unknowns = %q, want substring %q", joinedUnknowns, test.wantUnknown)
			}
			if test.wantUnknown == "" && len(unknowns) != 0 {
				t.Fatalf("unknowns = %v, want none", unknowns)
			}
		})
	}
}

func TestEvaluatePasswordPolicyDetailsIncludeEveryDefinitePAMViolation(t *testing.T) {
	t.Parallel()

	commands := validAuthselectFixture()
	commands[commandKey("authselect", "current")] = fixtureCommandResponse{
		result: executor.Result{ExitCode: 0, Stdout: []byte("Profile ID: sssd\nEnabled features:\n- with-pwhistory\n")},
	}
	commands[commandKey("getent", "passwd")] = fixtureCommandResponse{
		result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
	}
	stack := "password sufficient pam_permit.so\n" +
		"password optional pam_pwquality.so\n" +
		"password sufficient pam_pwhistory.so use_authtok\n" +
		"password sufficient pam_unix.so use_authtok\n"
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/pwquality.conf": "minlen=8\nminclass=4\nallowclasses=dul\n",
			"/etc/security/pwhistory.conf": "remember=2\n",
			"/etc/login.defs":              "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\n",
			"/etc/pam.d/system-auth":       stack,
			"/etc/pam.d/password-auth":     stack,
			"/etc/shadow":                  "root:$6$salt$hash:20000:1:90:7:::\n",
			"/etc/passwd":                  "root:x:0:0:root:/root:/bin/bash\n",
		}),
		Commands: commands,
		Platform: model.PlatformInfo{Family: "rhel"},
	}
	rule := model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{
		"min_password_length":        8,
		"required_character_classes": 4,
		"password_history":           4,
		"min_password_days":          1,
		"max_password_days":          90,
	}}}

	first := evaluatePasswordPolicy(context.Background(), rule, environment)
	second := evaluatePasswordPolicy(context.Background(), rule, environment)
	if first.Status != model.StatusFail {
		t.Fatalf("status = %q, want %q; outcome = %#v", first.Status, model.StatusFail, first)
	}
	if !reflect.DeepEqual(first.Details, second.Details) {
		t.Fatalf("details are not deterministic:\nfirst  %#v\nsecond %#v", first.Details, second.Details)
	}
	byLabel := make(map[string]model.ResultDetail, len(first.Details))
	for _, detail := range first.Details {
		byLabel[detail.Label] = detail
	}
	assertDetailContains := func(label string, values ...string) {
		t.Helper()
		detail, exists := byLabel[label]
		if !exists {
			t.Fatalf("detail %q is missing: %#v", label, first.Details)
		}
		serialized := detail.Current + "\n" + detail.Expected + "\n" + detail.Source
		for _, value := range values {
			if !strings.Contains(serialized, value) {
				t.Fatalf("detail %q = %#v, want substring %q", label, detail, value)
			}
		}
	}
	assertDetailContains("허용 문자 종류", "allowclasses=dul", "/etc/security/pwquality.conf:3")
	assertDetailContains("비밀번호 이력 횟수", "remember=2", "remember=4 이상", "/etc/security/pwhistory.conf:1")
	assertDetailContains("root 이력 정책", "password-auth", "system-auth", "pam_pwhistory enforce_for_root")
	assertDetailContains("PAM 제어 플래그", "pam_pwquality control=optional", "pam_pwhistory control=sufficient", "/etc/pam.d/password-auth:2", "/etc/pam.d/system-auth:3")
	assertDetailContains("PAM 적용 경로", "pam_permit.so", "비밀번호 정책", "/etc/pam.d/password-auth:1", "/etc/pam.d/system-auth:1")
}

func TestEvaluatePasswordPolicyUsesDebianCommonPasswordWithoutAuthselect(t *testing.T) {
	t.Parallel()

	commands := fixtureCommandRunner{
		commandKey("getent", "passwd"): {
			result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
		},
	}
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/login.defs":            "PASS_MIN_DAYS 0\nPASS_MAX_DAYS 99999\n",
			"/etc/pam.d/common-password": "password [success=1 default=ignore] pam_unix.so obscure yescrypt\npassword requisite pam_deny.so\npassword required pam_permit.so\n",
			"/etc/shadow":                "root:$y$j9T$hash:20000:0:99999:7:::\n",
			"/etc/passwd":                "root:x:0:0:root:/root:/bin/bash\n",
		}),
		Commands: commands,
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}
	rule := model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{
		"min_password_length":        8,
		"required_character_classes": 4,
		"password_history":           4,
		"min_password_days":          1,
		"max_password_days":          90,
	}}}

	outcome := evaluatePasswordPolicy(context.Background(), rule, environment)

	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusFail, outcome)
	}
	if outcome.ErrorCode != "" || !strings.Contains(outcome.Observed, "common-password") {
		t.Fatalf("outcome = %#v, want a Debian policy finding without an internal error", outcome)
	}
	if len(outcome.Evidence) == 0 {
		t.Fatal("Debian password policy returned no evidence")
	}
}

func TestEvaluatePasswordPolicyKeepsLocalOnlyDebianPAMFindingsDefinite(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/login.defs":            "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\n",
			"/etc/pam.d/common-password": "password [success=1 default=ignore] pam_unix.so obscure yescrypt\npassword requisite pam_deny.so\npassword required pam_permit.so\n",
			"/etc/shadow":                "root:$y$j9T$hash:20000:1:90:7:::\n",
			"/etc/passwd":                "root:x:0:0:root:/root:/bin/bash\n",
		}),
		Commands: fixtureCommandRunner{
			commandKey("getent", "passwd"): {
				result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
			},
		},
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}

	outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)

	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusFail, outcome)
	}
	if !strings.Contains(outcome.Observed, "pam_pwquality가 없음") ||
		!strings.Contains(outcome.Observed, "pam_pwhistory가 없음") {
		t.Fatalf("observed = %q, want definite local PAM module findings", outcome.Observed)
	}
}

func TestEvaluatePasswordPolicyReturnsUnknownForAlternativeDebianPAMPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		module string
	}{
		{name: "passwdqc policy", module: "pam_passwdqc.so"},
		{name: "cracklib policy", module: "pam_cracklib.so"},
		{name: "SSS writer", module: "pam_sss.so"},
		{name: "LDAP writer", module: "pam_ldap.so"},
		{name: "Winbind writer", module: "pam_winbind.so"},
		{name: "Kerberos writer", module: "pam_krb5.so"},
		{name: "external command writer", module: "pam_exec.so"},
		{name: "custom module", module: "pam_custom_password.so"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stack := "password requisite " + test.module + "\n" +
				"password [success=1 default=ignore] pam_unix.so obscure yescrypt\n" +
				"password requisite pam_deny.so\n" +
				"password required pam_permit.so\n"
			environment := evaluator.Environment{
				Files: newAccountFixtureReader(map[string]string{
					"/etc/login.defs":            "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\n",
					"/etc/pam.d/common-password": stack,
					"/etc/shadow":                "root:$y$j9T$hash:20000:1:90:7:::\n",
					"/etc/passwd":                "root:x:0:0:root:/root:/bin/bash\n",
				}),
				Commands: fixtureCommandRunner{
					commandKey("getent", "passwd"): {
						result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
					},
				},
				Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
			}

			outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)

			if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownInsufficientEvidence {
				t.Fatalf("outcome = %#v, want insufficient-evidence UNKNOWN", outcome)
			}
			if !strings.Contains(outcome.Observed, test.module) {
				t.Fatalf("observed = %q, want alternative path %q", outcome.Observed, test.module)
			}
		})
	}
}

func TestEvaluatePasswordPolicyDowngradesAllPAMFindingsWithAlternativeDebianPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		historyConfig    string
		historyControl   string
		expectedFindings []string
	}{
		{
			name:             "strong redundant history",
			historyConfig:    "remember=4\nenforce_for_root\n",
			historyControl:   "requisite",
			expectedFindings: []string{"minlen=6", "필수 문자 종류=0", "pam_unix.so가 pwquality/pwhistory보다 먼저"},
		},
		{
			name:             "weak redundant history",
			historyConfig:    "remember=1\n",
			historyControl:   "optional",
			expectedFindings: []string{"minlen=6", "remember=1", "pwhistory enforce_for_root 없음", "pam_pwhistory 제어 플래그"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stack := "password requisite pam_passwdqc.so min=disabled,disabled,8,8,8\n" +
				"password optional pam_pwquality.so\n" +
				"password [success=1 default=ignore] pam_unix.so obscure yescrypt\n" +
				"password " + test.historyControl + " pam_pwhistory.so use_authtok\n" +
				"password requisite pam_deny.so\n"
			environment := evaluator.Environment{
				Files: newAccountFixtureReader(map[string]string{
					"/etc/security/pwquality.conf": "minlen=6\nminclass=1\n",
					"/etc/security/pwhistory.conf": test.historyConfig,
					"/etc/login.defs":              "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\n",
					"/etc/pam.d/common-password":   stack,
					"/etc/shadow":                  "root:$y$j9T$hash:20000:1:90:7:::\n",
					"/etc/passwd":                  "root:x:0:0:root:/root:/bin/bash\n",
				}),
				Commands: fixtureCommandRunner{
					commandKey("getent", "passwd"): {
						result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
					},
				},
				Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
			}

			outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)

			if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownInsufficientEvidence {
				t.Fatalf("outcome = %#v, want insufficient-evidence UNKNOWN", outcome)
			}
			for _, finding := range test.expectedFindings {
				if !strings.Contains(outcome.Observed, finding) {
					t.Fatalf("observed = %q, want downgraded PAM finding %q", outcome.Observed, finding)
				}
			}
		})
	}
}

func TestEvaluatePasswordPolicyKeepsDefiniteAgeViolationWithAlternativeDebianPAM(t *testing.T) {
	t.Parallel()

	stack := "password requisite pam_passwdqc.so min=disabled,disabled,8,8,8\n" +
		"password optional pam_pwquality.so\n" +
		"password [success=1 default=ignore] pam_unix.so obscure yescrypt\n" +
		"password optional pam_pwhistory.so use_authtok\n" +
		"password requisite pam_deny.so\n"
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/pwquality.conf": "minlen=6\nminclass=1\n",
			"/etc/security/pwhistory.conf": "remember=1\n",
			"/etc/login.defs":              "PASS_MIN_DAYS 0\nPASS_MAX_DAYS 99999\n",
			"/etc/pam.d/common-password":   stack,
			"/etc/shadow":                  "root:$y$j9T$hash:20000:0:99999:7:::\n",
			"/etc/passwd":                  "root:x:0:0:root:/root:/bin/bash\n",
		}),
		Commands: fixtureCommandRunner{
			commandKey("getent", "passwd"): {
				result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
			},
		},
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}

	outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)

	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusFail, outcome)
	}
	if !strings.Contains(outcome.Observed, "PASS_MIN_DAYS=0") ||
		!strings.Contains(outcome.Observed, "root(min=0,max=99999)") {
		t.Fatalf("observed = %q, want definite age findings", outcome.Observed)
	}
	for _, pamFinding := range []string{
		"minlen=6",
		"필수 문자 종류=0",
		"remember=1",
		"enforce_for_root",
		"제어 플래그",
		"pam_unix.so가 pwquality/pwhistory보다 먼저",
	} {
		if strings.Contains(outcome.Observed, pamFinding) {
			t.Fatalf("observed = %q, unresolved PAM finding %q must not be definite", outcome.Observed, pamFinding)
		}
	}
	for _, detail := range outcome.Details {
		if detail.Label != "사용 기간" && detail.Label != "계정별 사용 기간" {
			t.Fatalf("details = %#v, unresolved PAM detail %q must not accompany the age finding", outcome.Details, detail.Label)
		}
	}
}

func TestEvaluatePasswordPolicyKeepsDefiniteAgeViolationWhenRHELPAMIsUnmanaged(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/login.defs": "PASS_MIN_DAYS 0\nPASS_MAX_DAYS 99999\n",
			"/etc/shadow":     "root:$6$salt$hash:20000:0:99999:7:::\n",
			"/etc/passwd":     "root:x:0:0:root:/root:/bin/bash\n",
		}),
		Commands: fixtureCommandRunner{
			commandKey("authselect", "current"): {
				result: executor.Result{ExitCode: 2, Stderr: []byte("No existing configuration detected.\n")},
			},
			commandKey("getent", "passwd"): {
				result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
			},
		},
		Platform: model.PlatformInfo{Family: "rhel", ID: "rocky", VersionID: "9.8"},
	}

	outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)

	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusFail, outcome)
	}
	for _, finding := range []string{"PASS_MIN_DAYS=0", "PASS_MAX_DAYS=99999", "root(min=0,max=99999)"} {
		if !strings.Contains(outcome.Observed, finding) {
			t.Fatalf("observed = %q, want definite age finding %q", outcome.Observed, finding)
		}
	}
	for _, pamFinding := range []string{"system-auth", "password-auth", "pam_pwquality", "pam_pwhistory"} {
		if strings.Contains(outcome.Observed, pamFinding) {
			t.Fatalf("observed = %q, unresolved PAM finding %q must not be definite", outcome.Observed, pamFinding)
		}
	}
	for _, detail := range outcome.Details {
		if detail.Label != "사용 기간" && detail.Label != "계정별 사용 기간" {
			t.Fatalf("details = %#v, unresolved PAM detail %q must not accompany the age finding", outcome.Details, detail.Label)
		}
	}
}

func TestEvaluatePasswordPolicyNeverPassesUnmanagedRHELPAM(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/security/pwquality.conf": "unsupported syntax must not be parsed\n",
			"/etc/login.defs":              "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\n",
			"/etc/pam.d/system-auth":       "password sufficient pam_unix.so sha512\n",
			"/etc/pam.d/password-auth":     "password sufficient pam_unix.so sha512\n",
			"/etc/shadow":                  "root:$6$salt$hash:20000:1:90:7:::\n",
			"/etc/passwd":                  "root:x:0:0:root:/root:/bin/bash\n",
		}),
		Commands: fixtureCommandRunner{
			commandKey("authselect", "current"): {
				result: executor.Result{ExitCode: 2, Stderr: []byte("No existing configuration detected.\n")},
			},
			commandKey("getent", "passwd"): {
				result: executor.Result{ExitCode: 0, Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
			},
		},
		Platform: model.PlatformInfo{Family: "rhel", ID: "centos", VersionID: "8.5.2111"},
	}

	outcome := evaluatePasswordPolicy(context.Background(), passwordPolicyRule(), environment)

	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
	}
	if !strings.Contains(outcome.Observed, "authselect") {
		t.Fatalf("observed = %q, want unresolved authselect-managed PAM path", outcome.Observed)
	}
	for _, pamFinding := range []string{"system-auth", "password-auth", "pam_pwquality", "pam_pwhistory"} {
		if strings.Contains(outcome.Observed, pamFinding) {
			t.Fatalf("observed = %q, canonical PAM finding %q must not be inferred", outcome.Observed, pamFinding)
		}
		for _, evidence := range outcome.Evidence {
			if strings.Contains(evidence.Source, pamFinding) {
				t.Fatalf("evidence = %#v, canonical PAM source %q must not be collected without an effective entrypoint", outcome.Evidence, pamFinding)
			}
		}
	}
}

func TestEvaluateDebianLockoutThresholdFailsWhenCommonPAMHasNoLockoutModule(t *testing.T) {
	t.Parallel()

	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/pam.d/common-auth":    "auth [success=1 default=ignore] pam_unix.so nullok\n",
			"/etc/pam.d/common-account": "account required pam_unix.so\n",
		}),
		Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
	}

	outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

	if outcome.Status != model.StatusFail || outcome.ErrorCode != "" {
		t.Fatalf("outcome = %#v, want a Debian lockout finding without an internal error", outcome)
	}
	if !strings.Contains(outcome.Observed, "pam_faillock.so") || len(outcome.Evidence) == 0 {
		t.Fatalf("outcome = %#v, want missing lockout modules with evidence", outcome)
	}
}

func TestEvaluateDebianLockoutThresholdReturnsUnknownForExternalOrCustomPAMPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		stack       string
		module      string
		accountPath bool
	}{
		{name: "SSS authentication", stack: "auth sufficient pam_sss.so\n", module: "pam_sss.so"},
		{name: "LDAP authentication", stack: "auth sufficient pam_ldap.so\n", module: "pam_ldap.so"},
		{name: "Winbind authentication", stack: "auth sufficient pam_winbind.so\n", module: "pam_winbind.so"},
		{name: "Kerberos authentication", stack: "auth sufficient pam_krb5.so\n", module: "pam_krb5.so"},
		{name: "custom authentication", stack: "auth sufficient pam_custom_auth.so\n", module: "pam_custom_auth.so"},
		{name: "custom account", stack: "account required pam_custom_account.so\n", module: "pam_custom_account.so", accountPath: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			commonAuth := "auth [success=1 default=ignore] pam_unix.so\n"
			commonAccount := "account required pam_unix.so\n"
			if test.accountPath {
				commonAccount += test.stack
			} else {
				commonAuth += test.stack
			}
			environment := evaluator.Environment{
				Files: newAccountFixtureReader(map[string]string{
					"/etc/pam.d/common-auth":    commonAuth,
					"/etc/pam.d/common-account": commonAccount,
				}),
				Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", VersionID: "24.04"},
			}

			outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

			if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
				t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
			}
			if !strings.Contains(outcome.Observed, test.module) {
				t.Fatalf("observed = %q, want unresolved path %q", outcome.Observed, test.module)
			}
		})
	}
}

func passwordPolicyRule() model.ResolvedRule {
	return model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{
		"min_password_length":        8,
		"required_character_classes": 4,
		"password_history":           4,
		"min_password_days":          1,
		"max_password_days":          90,
	}}}
}

func TestEvaluateUnnecessaryAccountsRequiresExactInventoryAndShadowProvenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		approved   []string
		shadow     string
		wantStatus model.Status
		wantText   string
	}{
		{
			name:       "approved account absent from NSS is not a pass",
			approved:   []string{"root", "service", "retired"},
			shadow:     validShadow,
			wantStatus: model.StatusUnknown,
			wantText:   "retired",
		},
		{
			name:       "NSS account without shadow provenance is not a pass",
			approved:   []string{"root", "service"},
			shadow:     "root:!:20000:0:99999:7:::\n",
			wantStatus: model.StatusUnknown,
			wantText:   "service",
		},
		{
			name:       "exact inventory with complete shadow provenance passes",
			approved:   []string{"root", "service"},
			shadow:     validShadow,
			wantStatus: model.StatusPass,
			wantText:   "shadow 상태 2개",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rule := model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{
				"approved_accounts": test.approved,
			}}}
			environment := evaluator.Environment{
				Files:    newAccountFixtureReader(map[string]string{"/etc/shadow": test.shadow}),
				Commands: getentPasswdFixture(validPasswd),
			}
			outcome := evaluateUnnecessaryAccounts(context.Background(), rule, environment)
			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, test.wantStatus, outcome)
			}
			if !strings.Contains(outcome.Observed, test.wantText) {
				t.Fatalf("observed = %q, want substring %q", outcome.Observed, test.wantText)
			}
		})
	}
}

const unmanagedRHELSSHDLaunchProperties = "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
	"Environment=\n" +
	"EnvironmentFiles=\n" +
	"PassEnvironment=\n" +
	"UnsetEnvironment=\n" +
	"RootDirectory=\n" +
	"RootImage=\n" +
	"RootEphemeral=no\n" +
	"RootDirectoryStartOnly=no\n" +
	"BindPaths=\n" +
	"BindReadOnlyPaths=\n" +
	"TemporaryFileSystem=\n" +
	"MountImages=\n" +
	"ExtensionImages=\n" +
	"ExtensionDirectories=\n" +
	"InaccessiblePaths=\n"

func TestEvaluateLockoutThresholdKeepsUnmanagedRHELSystemdNamespaceOverridesUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		property  string
		baseline  string
		active    string
		busOutput string
	}{
		{name: "root directory", property: "RootDirectory", active: "/srv/sshd-root"},
		{name: "root image", property: "RootImage", active: "/srv/sshd.raw"},
		{name: "ephemeral root", property: "RootEphemeral", baseline: "no", active: "yes"},
		{name: "root directory start only", property: "RootDirectoryStartOnly", baseline: "no", active: "yes"},
		{name: "bind paths", property: "BindPaths", active: "/srv/ssh-config:/etc/ssh"},
		{name: "read only bind paths", property: "BindReadOnlyPaths", active: "/srv/pam:/etc/pam.d"},
		{name: "temporary file system", property: "TemporaryFileSystem", active: "/etc:ro"},
		{name: "mount images", property: "MountImages", active: "/srv/etc.raw:/etc"},
		{name: "extension images", property: "ExtensionImages", active: "/srv/usr.raw"},
		{name: "extension directories", property: "ExtensionDirectories", active: "/srv/usr-extension"},
		{name: "inaccessible paths", property: "InaccessiblePaths", active: "/etc/pam.d"},
		{
			name:      "unprintable nonempty bind paths",
			property:  "BindPaths",
			active:    "[unprintable]",
			busOutput: `a(ssbt) 1 "/srv/ssh-config" "/etc/ssh" false false`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			environment := unmanagedRHELLockoutFixture(
				"usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
				nil,
			)
			launchProperties := strings.Replace(
				unmanagedRHELSSHDLaunchProperties,
				test.property+"="+test.baseline+"\n",
				test.property+"="+test.active+"\n",
				1,
			)
			if launchProperties == unmanagedRHELSSHDLaunchProperties {
				t.Fatalf("launch fixture does not contain property %q", test.property)
			}
			commands := environment.Commands.(fixtureCommandRunner)
			commands[commandKey(
				"systemctl",
				"show",
				"--no-pager",
				"--property="+sshdLaunchProperties,
				"--",
				"sshd.service",
			)] = fixtureCommandResponse{result: executor.Result{
				ExitCode: 0,
				Stdout:   []byte(launchProperties),
			}}
			if test.busOutput != "" {
				commands[commandKey(
					"busctl",
					"get-property",
					"org.freedesktop.systemd1",
					"/org/freedesktop/systemd1/unit/sshd_2eservice",
					"org.freedesktop.systemd1.Service",
					test.property,
				)] = fixtureCommandResponse{result: executor.Result{
					ExitCode: 0,
					Stdout:   []byte(test.busOutput + "\n"),
				}}
			}

			outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

			if outcome.Status != model.StatusUnknown ||
				outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
				t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
			}
			if !strings.Contains(outcome.Observed, test.property) {
				t.Fatalf("observed = %q, want namespace property %q", outcome.Observed, test.property)
			}
		})
	}
}

func TestEvaluateLockoutThresholdAcceptsEmptyTypedSystemdNamespaceArrays(t *testing.T) {
	t.Parallel()

	environment := unmanagedRHELLockoutFixture(
		"usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
		nil,
	)
	launchProperties := unmanagedRHELSSHDLaunchProperties
	for _, property := range []string{"BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem"} {
		launchProperties = strings.Replace(
			launchProperties,
			property+"=\n",
			property+"=[unprintable]\n",
			1,
		)
	}
	commands := environment.Commands.(fixtureCommandRunner)
	commands[commandKey(
		"systemctl",
		"show",
		"--no-pager",
		"--property="+sshdLaunchProperties,
		"--",
		"sshd.service",
	)] = fixtureCommandResponse{result: executor.Result{
		ExitCode: 0,
		Stdout:   []byte(launchProperties),
	}}
	for property, output := range map[string]string{
		"BindPaths":           "a(ssbt) 0\n",
		"BindReadOnlyPaths":   "a(ssbt) 0\n",
		"TemporaryFileSystem": "a(ss) 0\n",
	} {
		commands[commandKey(
			"busctl",
			"get-property",
			"org.freedesktop.systemd1",
			"/org/freedesktop/systemd1/unit/sshd_2eservice",
			"org.freedesktop.systemd1.Service",
			property,
		)] = fixtureCommandResponse{result: executor.Result{
			ExitCode: 0,
			Stdout:   []byte(output),
		}}
	}

	outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

	if outcome.Status != model.StatusFail {
		t.Fatalf("outcome = %#v, want definite unmanaged RHEL FAIL for empty typed arrays", outcome)
	}
	typedEvidence := 0
	for _, item := range outcome.Evidence {
		if item.Source != "systemd-sshd-namespace-property" {
			continue
		}
		typedEvidence++
		if item.Command != nil || item.File != nil || item.Fact["array_count"] != 0 {
			t.Fatalf("typed property evidence = %#v, want summary-only empty array evidence", item)
		}
	}
	if typedEvidence != 3 {
		t.Fatalf("typed property evidence count = %d, want 3", typedEvidence)
	}
}

func TestEvaluateLockoutThresholdKeepsUnmanagedRHELTypedNamespaceFailuresUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result executor.Result
		err    error
	}{
		{
			name:   "unknown property",
			result: executor.Result{ExitCode: 1, Stderr: []byte("Unknown property BindPaths\n")},
		},
		{
			name:   "wrong signature",
			result: executor.Result{ExitCode: 0, Stdout: []byte("a(ss) 0\n")},
		},
		{
			name:   "truncated output",
			result: executor.Result{ExitCode: 0, Stdout: []byte("a(ssbt) 0\n"), Truncated: true},
		},
		{
			name: "execution failure",
			err:  errors.New("bus unavailable"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			environment := unmanagedRHELLockoutFixture(
				"usepam yes\npasswordauthentication yes\nauthenticationmethods any\n",
				nil,
			)
			launchProperties := strings.Replace(
				unmanagedRHELSSHDLaunchProperties,
				"BindPaths=\n",
				"BindPaths=[unprintable]\n",
				1,
			)
			commands := environment.Commands.(fixtureCommandRunner)
			commands[commandKey(
				"systemctl",
				"show",
				"--no-pager",
				"--property="+sshdLaunchProperties,
				"--",
				"sshd.service",
			)] = fixtureCommandResponse{result: executor.Result{
				ExitCode: 0,
				Stdout:   []byte(launchProperties),
			}}
			commands[commandKey(
				"busctl",
				"get-property",
				"org.freedesktop.systemd1",
				"/org/freedesktop/systemd1/unit/sshd_2eservice",
				"org.freedesktop.systemd1.Service",
				"BindPaths",
			)] = fixtureCommandResponse{result: test.result, err: test.err}

			outcome := evaluateLockoutThreshold(context.Background(), model.ResolvedRule{}, environment)

			if outcome.Status != model.StatusUnknown ||
				outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
				t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
			}
			if !strings.Contains(outcome.Observed, "BindPaths") {
				t.Fatalf("observed = %q, want typed BindPaths failure", outcome.Observed)
			}
		})
	}
}

func TestParseBusctlArrayCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		output    string
		signature string
		wantCount int
		wantOK    bool
	}{
		{name: "empty bind array", output: "a(ssbt) 0\n", signature: "a(ssbt)", wantOK: true},
		{name: "empty temporary file system array", output: "a(ss) 0\n", signature: "a(ss)", wantOK: true},
		{
			name:      "nonempty bind array",
			output:    `a(ssbt) 1 "/srv/ssh config" "/etc/ssh" false false`,
			signature: "a(ssbt)",
			wantCount: 1,
			wantOK:    true,
		},
		{name: "wrong signature", output: "a(ss) 0", signature: "a(ssbt)"},
		{name: "negative count", output: "a(ssbt) -1", signature: "a(ssbt)"},
		{name: "noncanonical count", output: "a(ssbt) 01 payload", signature: "a(ssbt)"},
		{name: "missing nonempty payload", output: "a(ssbt) 1", signature: "a(ssbt)"},
		{name: "payload after empty count", output: "a(ssbt) 0 payload", signature: "a(ssbt)"},
		{name: "multiple lines", output: "a(ssbt) 0\nextra", signature: "a(ssbt)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			count, ok := parseBusctlArrayCount(test.output, test.signature)
			if count != test.wantCount || ok != test.wantOK {
				t.Fatalf(
					"parseBusctlArrayCount(%q, %q) = (%d, %t), want (%d, %t)",
					test.output,
					test.signature,
					count,
					ok,
					test.wantCount,
					test.wantOK,
				)
			}
		})
	}
}

func TestInspectSSHDLaunchProfileUsesEffectiveSysconfigOptions(t *testing.T) {
	t.Parallel()

	const properties = "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
		"Environment=\n" +
		"EnvironmentFiles=/etc/sysconfig/sshd (ignore_errors=yes)\n" +
		"PassEnvironment=\n" +
		"UnsetEnvironment=\n"
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/sysconfig/sshd": "OPTIONS=\"-f /etc/ssh/custom_sshd_config -o PermitRootLogin=no\"\n",
		}),
		Commands: fixtureCommandRunner{
			commandKey("systemctl", "show", "--no-pager", "--property="+sshdLaunchProperties, "--", "sshd.service"): {
				result: executor.Result{ExitCode: 0, Stdout: []byte(properties)},
			},
		},
	}

	profile, evidence, unknown, err := inspectSSHDLaunchProfile(context.Background(), environment, "sshd.service")
	if err != nil || unknown != "" {
		t.Fatalf("err = %v, unknown = %q", err, unknown)
	}
	wantArguments := []string{"-f", "/etc/ssh/custom_sshd_config", "-o", "PermitRootLogin=no"}
	if !slices.Equal(profile.ConfigurationArguments, wantArguments) {
		t.Fatalf("configuration arguments = %#v, want %#v", profile.ConfigurationArguments, wantArguments)
	}
	if !profile.CustomConfiguration {
		t.Fatal("custom configuration was not detected")
	}
	if len(evidence) < 2 {
		t.Fatalf("evidence count = %d, want launch and environment-file evidence", len(evidence))
	}
}

func TestInspectSSHDLaunchProfileAcceptsOmittedEmptySystemdProperties(t *testing.T) {
	t.Parallel()

	const properties = "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
		"EnvironmentFiles=/etc/default/ssh (ignore_errors=yes)\n"
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/default/ssh": "SSHD_OPTS=\n",
		}),
		Commands: fixtureCommandRunner{
			commandKey("systemctl", "show", "--no-pager", "--property="+sshdLaunchProperties, "--", "ssh.service"): {
				result: executor.Result{ExitCode: 0, Stdout: []byte(properties)},
			},
		},
	}

	profile, _, unknown, err := inspectSSHDLaunchProfile(context.Background(), environment, "ssh.service")
	if err != nil || unknown != "" {
		t.Fatalf("err = %v, unknown = %q", err, unknown)
	}
	if profile.Executable != "/usr/sbin/sshd" || len(profile.ConfigurationArguments) != 0 || profile.CustomConfiguration {
		t.Fatalf("profile = %#v, want the stock Ubuntu ssh.service launch", profile)
	}
}

func TestInspectSSHDLaunchProfileReturnsUnknownForWrapper(t *testing.T) {
	t.Parallel()

	const properties = "ExecStart={ path=/usr/bin/env ; argv[]=/usr/bin/env /usr/sbin/sshd -D ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
		"Environment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n"
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(nil),
		Commands: fixtureCommandRunner{
			commandKey("systemctl", "show", "--no-pager", "--property="+sshdLaunchProperties, "--", "sshd.service"): {
				result: executor.Result{ExitCode: 0, Stdout: []byte(properties)},
			},
		},
	}

	_, _, unknown, err := inspectSSHDLaunchProfile(context.Background(), environment, "sshd.service")
	if err != nil {
		t.Fatalf("inspectSSHDLaunchProfile() error = %v", err)
	}
	if !strings.Contains(unknown, "래퍼") {
		t.Fatalf("unknown reason = %q, want wrapper detection", unknown)
	}
}

func TestEvaluateSSHRootPolicyRunsTestWithEffectiveLaunchArguments(t *testing.T) {
	t.Parallel()

	const properties = "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n" +
		"Environment=\n" +
		"EnvironmentFiles=/etc/sysconfig/sshd (ignore_errors=yes)\n" +
		"PassEnvironment=\n" +
		"UnsetEnvironment=\n"
	commands := fixtureCommandRunner{
		commandKey("systemctl", "show", "--no-pager", "--property="+sshdLaunchProperties, "--", "sshd.service"): {
			result: executor.Result{ExitCode: 0, Stdout: []byte(properties)},
		},
	}
	for _, address := range []string{"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1"} {
		commands[commandKey("sshd", "-f", "/etc/ssh/custom_sshd_config", "-o", "PermitRootLogin=no", "-T", "-C", "user=root,host=localhost,addr="+address)] = fixtureCommandResponse{
			result: executor.Result{ExitCode: 0, Stdout: []byte("permitrootlogin no\n")},
		}
	}
	environment := evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{
			"/etc/sysconfig/sshd": "OPTIONS=\"-f /etc/ssh/custom_sshd_config -o PermitRootLogin=no\"\n",
		}),
		Commands: commands,
	}
	states := []support.UnitState{{Name: "sshd.service", InspectionName: "sshd.service", ActiveState: "active"}}

	outcome := evaluateSSHRootPolicy(context.Background(), environment, states)

	if outcome.Status != model.StatusUnknown {
		t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, model.StatusUnknown, outcome)
	}
	if !strings.Contains(outcome.Observed, "사용자 지정 SSH 설정") {
		t.Fatalf("observed = %q, want custom configuration enumeration boundary", outcome.Observed)
	}
}

func unmanagedRHELLockoutFixture(sshdSettings string, overrides map[string]string) evaluator.Environment {
	files := map[string]string{
		"/etc/ssh/sshd_config": "UsePAM yes\nPasswordAuthentication yes\n" +
			"Include /etc/ssh/sshd_config.d/*.conf\n",
		"/etc/ssh/sshd_config.d/50-redhat.conf": "Include /etc/crypto-policies/back-ends/opensshserver.config\n" +
			"ChallengeResponseAuthentication no\n" +
			"UsePAM yes\n",
		"/etc/crypto-policies/back-ends/opensshserver.config": "Ciphers aes256-gcm@openssh.com,aes256-ctr\n" +
			"MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256\n",
		"/etc/pam.d/sshd": "auth substack password-auth\n" +
			"auth include postlogin\n" +
			"account required pam_sepermit.so\n" +
			"account required pam_nologin.so\n" +
			"account include password-auth\n" +
			"password include password-auth\n" +
			"session required pam_selinux.so close\n" +
			"session required pam_loginuid.so\n" +
			"session required pam_selinux.so open env_params\n" +
			"session required pam_namespace.so\n" +
			"session optional pam_keyinit.so force revoke\n" +
			"session optional pam_motd.so\n" +
			"session include password-auth\n" +
			"session include postlogin\n",
		"/etc/pam.d/password-auth": "auth required pam_env.so\n" +
			"auth sufficient pam_unix.so try_first_pass nullok\n" +
			"auth required pam_deny.so\n" +
			"account required pam_unix.so\n" +
			"password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=\n" +
			"password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok\n" +
			"password required pam_deny.so\n" +
			"session optional pam_keyinit.so revoke\n" +
			"session required pam_limits.so\n" +
			"-session optional pam_systemd.so\n" +
			"session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid\n" +
			"session required pam_unix.so\n",
		"/etc/pam.d/postlogin": "session optional pam_umask.so silent\n" +
			"session [success=1 default=ignore] pam_succeed_if.so service !~ gdm* service !~ su* quiet\n" +
			"session [default=1] pam_lastlog.so nowtmp showfailed\n" +
			"session optional pam_lastlog.so silent noupdate showfailed\n",
	}
	for name, content := range overrides {
		files[name] = content
	}

	commands := fixtureCommandRunner{
		commandKey("authselect", "current"): {
			result: executor.Result{ExitCode: 2, Stdout: []byte("No existing configuration detected.\n")},
		},
		commandKey("ps", "-eo", "comm="): {
			result: executor.Result{ExitCode: 0},
		},
		commandKey("ss", "-H", "-lntup"): {
			result: executor.Result{ExitCode: 0},
		},
	}
	for _, unitName := range sshRemoteUnitNames() {
		loadState := "not-found"
		activeState := "inactive"
		subState := "dead"
		unitFileState := ""
		fragmentPath := ""
		if unitName == "sshd.service" {
			loadState = "loaded"
			activeState = "active"
			subState = "running"
			unitFileState = "enabled"
			fragmentPath = "/usr/lib/systemd/system/sshd.service"
		}
		output := "Id=" + unitName + "\n" +
			"LoadState=" + loadState + "\n" +
			"ActiveState=" + activeState + "\n" +
			"SubState=" + subState + "\n" +
			"FragmentPath=" + fragmentPath + "\n" +
			"DropInPaths=\n" +
			"UnitFileState=" + unitFileState + "\n"
		commands[commandKey(
			"systemctl",
			"show",
			"--no-pager",
			"--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths",
			"--",
			unitName,
		)] = fixtureCommandResponse{result: executor.Result{ExitCode: 0, Stdout: []byte(output)}}
	}
	commands[commandKey(
		"systemctl",
		"show",
		"--no-pager",
		"--property="+sshdLaunchProperties,
		"--",
		"sshd.service",
	)] = fixtureCommandResponse{result: executor.Result{
		ExitCode: 0,
		Stdout:   []byte(unmanagedRHELSSHDLaunchProperties),
	}}
	for _, address := range []string{"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1"} {
		commands[commandKey(
			"sshd",
			"-T",
			"-C",
			"user="+unmanagedRHELSSHProbeUser+",host=fixture,addr="+address,
		)] = fixtureCommandResponse{result: executor.Result{ExitCode: 0, Stdout: []byte(sshdSettings)}}
	}

	return evaluator.Environment{
		Files:    newAccountFixtureReader(files),
		Commands: commands,
		Platform: model.PlatformInfo{
			Family:     "rhel",
			ID:         "rocky",
			VersionID:  "9.8",
			Hostname:   "fixture",
			InitSystem: "systemd",
		},
	}
}

func validAuthselectFixture() fixtureCommandRunner {
	return fixtureCommandRunner{
		commandKey("authselect", "current"): {
			result: executor.Result{ExitCode: 0, Stdout: []byte("Profile ID: sssd\nEnabled features:\n- with-faillock\n")},
		},
		commandKey("authselect", "check"): {
			result: executor.Result{ExitCode: 0},
		},
	}
}

func passwordHashRule() model.ResolvedRule {
	return model.ResolvedRule{RuleDefinition: model.RuleDefinition{Parameters: map[string]any{
		"safe_login_defs_methods": []string{"SHA256", "SHA512", "YESCRYPT"},
		"safe_shadow_algorithms":  []string{"5", "6", "y", "gy"},
	}}}
}
