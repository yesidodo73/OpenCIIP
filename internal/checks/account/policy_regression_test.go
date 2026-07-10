package account

import (
	"context"
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
			"/etc/pam.d/system-auth":      "auth required pam_faillock.so preauth deny=not-a-number\n",
			"/etc/pam.d/password-auth":    "auth required pam_faillock.so preauth\n",
		}),
		Commands: validAuthselectFixture(),
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
	})}
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
	})}

	outcome := evaluatePasswordHash(context.Background(), passwordHashRule(), environment)

	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want unsupported-configuration UNKNOWN", outcome)
	}
	if !strings.Contains(outcome.Observed, "해석할 수 없음") {
		t.Fatalf("observed = %q, want ambiguous pam_unix override", outcome.Observed)
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
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so"},
			},
			wantViolation: "pam_permit.so",
		},
		{
			name: "general sufficient module has an indeterminate bypass",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "sufficient", Module: "pam_custom.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so"},
			},
			wantUnknown: "pam_custom.so",
		},
		{
			name: "nested pam_permit has an indeterminate substack boundary",
			rules: []support.PAMRule{
				{Service: "nested-password", Path: "/etc/pam.d/nested-password", Line: 1, Type: "password", Control: "sufficient", Module: "pam_permit.so"},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Service: "system-auth", Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so"},
			},
			wantUnknown: "include/substack",
		},
		{
			name: "bracketed jump before history is indeterminate",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "[success=1 default=ignore]", Module: "pam_succeed_if.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "requisite", Module: "pam_pwhistory.so"},
			},
			wantUnknown: "pam_succeed_if.so",
		},
		{
			name: "standard modules before sufficient pam_unix are not bypassed",
			rules: []support.PAMRule{
				{Path: "/etc/pam.d/system-auth", Line: 1, Type: "password", Control: "requisite", Module: "pam_pwquality.so"},
				{Path: "/etc/pam.d/system-auth", Line: 2, Type: "password", Control: "requisite", Module: "pam_pwhistory.so"},
				{Path: "/etc/pam.d/system-auth", Line: 3, Type: "password", Control: "sufficient", Module: "pam_unix.so"},
			},
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
