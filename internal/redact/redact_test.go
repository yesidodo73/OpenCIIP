package redact

import (
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestTextRedactsSupportedSecretForms(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"password=hunter2",
		"Authorization: Bearer-token",
		"root:$6$secret-hash:20000:0:99999:7:::",
		"rocommunity public 127.0.0.1",
		"-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
	}, "\n")
	redacted := Text(input)
	for _, secret := range []string{"hunter2", "Bearer-token", "$6$secret-hash", " public ", "private-material"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q remained in %q", secret, redacted)
		}
	}
	if count := strings.Count(redacted, marker); count < 5 {
		t.Fatalf("redaction markers = %d, want at least 5: %q", count, redacted)
	}
}

func TestTextPreservesColonDelimitedNetworkAndACLValues(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"sshd.service ::1=yes",
		"sshd.service 2001:db8::1=yes",
		"2001:db8:0:0:0:0:0:1",
		"endpoint=https://[2001:db8::1]:8443/health",
		"user::rw-",
		"group::r--",
		"other::r--",
		"status:",
		"status:ready",
		"release:stable:channel:2026",
		"metric:value:1:2",
		"metric:value:1:2:3",
		"metric:value:1:2:3:4",
		"partial-plain:plaintext-value:20000:0:99999:7",
		"broken:plaintext-value:a:b:c:d:e:f:g",
		"note:alpha:beta:gamma",
	}, "\n")
	if redacted := Text(input); redacted != input {
		t.Fatalf("non-secret colon-delimited values changed:\n got %q\nwant %q", redacted, input)
	}
}

func TestTextPreservesPAMAndSchedulerPathTokens(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"common-password:20 pam_unix.so가 pwquality보다 먼저 실행됨",
		"common-password /etc/pam.d/common-password:20 pam_unix.so가 pwquality보다 먼저 실행됨",
		"password-auth /etc/pam.d/password-auth:20 pam_unix.so가 pwquality보다 먼저 실행됨",
		"/etc/cron.daily/passwd: 허용되지 않은 권한 비트 0115",
		`source=C:\etc\pam.d\common-password:20`,
		`source=C:\etc\pam.d\password-auth:20`,
	}, "\n")
	if redacted := Text(input); redacted != input {
		t.Fatalf("normal path tokens changed:\n got %q\nwant %q", redacted, input)
	}
}

func TestTextStillRedactsActualSecretAssignments(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"colon":                         "password: colon-secret",
		"equals":                        "password=equals-secret",
		"case and spacing":              "PaSsWoRd \t = \t mixed-case-secret",
		"passwd":                        "passwd: passwd-secret",
		"compound key":                  "database_password=db-secret",
		"quoted spaces":                 `password = "quoted secret with spaces" suffix`,
		"single-quoted":                 "secret='single quoted secret' suffix",
		"authorization key":             "authorization=assignment-secret",
		"PAM-looking equals assignment": "common-password=common-password-secret",
		"PAM-looking colon assignment":  "common-password: common-password-colon-secret",
		"URL path assignment":           "/api/password=url-path-secret",
		"Windows path assignment":       `C:\api\password=windows-path-secret`,
		"scheduler path assignment":     "/etc/cron.daily/passwd=scheduler-path-secret",
		"URL path colon assignment":     "/api/password: url-colon-secret",
		"Windows path colon assignment": `C:\api\token: windows-colon-secret`,
		"scheduler colon assignment":    "/etc/cron.daily/passwd: scheduler-colon-secret",
		"PAM path colon assignment":     "/etc/pam.d/common-password: pam-colon-secret",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			redacted := Text(input)
			if !strings.Contains(redacted, marker) {
				t.Fatalf("secret assignment was not redacted: %q", redacted)
			}
			for _, secret := range []string{
				"colon-secret", "equals-secret", "mixed-case-secret", "passwd-secret",
				"db-secret", "quoted secret with spaces", "single quoted secret", "assignment-secret",
				"common-password-secret", "common-password-colon-secret", "url-path-secret",
				"windows-path-secret", "scheduler-path-secret", "url-colon-secret",
				"windows-colon-secret", "scheduler-colon-secret", "pam-colon-secret",
			} {
				if strings.Contains(redacted, secret) {
					t.Fatalf("secret %q remained in %q", secret, redacted)
				}
			}
		})
	}
}

func TestTextRedactsEntireHTTPAuthorizationAndCookieHeaderValues(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"Authorization: Bearer header-token",
		"proxy-authorization : Basic cHJveHktc2VjcmV0",
		"Cookie: session=secret; theme=dark",
		"Set-Cookie: session=secret; HttpOnly; Secure",
		"> Authorization: Bearer curl-request-token",
		"< Set-Cookie: session=curl-response-secret; HttpOnly; Secure",
		"[debug] Proxy-Authorization: Basic bG9nLXByb3h5LXNlY3JldA==",
		"2026-07-30T12:00:00Z request Cookie: session=log-cookie-secret; auth=second-secret",
		"X-Status: safe",
	}, "\n")
	want := strings.Join([]string{
		"Authorization: " + marker,
		"proxy-authorization : " + marker,
		"Cookie: " + marker,
		"Set-Cookie: " + marker,
		"> Authorization: " + marker,
		"< Set-Cookie: " + marker,
		"[debug] Proxy-Authorization: " + marker,
		"2026-07-30T12:00:00Z request Cookie: " + marker,
		"X-Status: safe",
	}, "\n")
	if redacted := Text(input); redacted != want {
		t.Fatalf("HTTP header redaction = %q, want %q", redacted, want)
	}
}

func TestTextRedactsPasswordFieldOfCompleteAndPartialShadowLines(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"root:$6$secret-hash:20000:0:99999:7:::",
		"partial:$6$secret:1:2:3",
		"+nis:$6$nis-secret:1:2:3",
		"12345:$y$j9T$numeric-secret:1",
		"complete-plain:plaintext-value:20000:0:99999:7:::",
		"locked:!:20000",
		"empty::20000",
		"truncated:$y$j9T$partial",
		"legacy:abCDefg123./x:20000",
		"legacy-truncated:abCDefg123./x",
		"legacy-locked-truncated:!abCDefg123./x",
	}, "\r\n") + "\n"
	want := strings.Join([]string{
		"root:" + marker + ":20000:0:99999:7:::",
		"partial:" + marker + ":1:2:3",
		"+nis:" + marker + ":1:2:3",
		"12345:" + marker + ":1",
		"complete-plain:" + marker + ":20000:0:99999:7:::",
		"locked:" + marker + ":20000",
		"empty:" + marker + ":20000",
		"truncated:" + marker,
		"legacy:" + marker + ":20000",
		"legacy-truncated:" + marker,
		"legacy-locked-truncated:" + marker,
	}, "\r\n") + "\n"
	if redacted := Text(input); redacted != want {
		t.Fatalf("shadow redaction = %q, want %q", redacted, want)
	}
}

func TestScanRunRedactsDeepCopyWithoutMutatingInput(t *testing.T) {
	t.Parallel()
	run := model.ScanRun{
		Metadata: model.RunMetadata{
			ToolExecutableSHA256: strings.Repeat("d", 64),
			Counts:               map[model.Status]int{model.StatusFail: 1},
			Warnings:             []string{"password=warning-secret"},
			Platform:             model.PlatformInfo{Hostname: "token=hostname-secret"},
			TargetIdentity: &model.HostIdentity{
				MachineIDHash: "machine-id",
				SystemRoot:    "/password=system-root-secret",
				BootID:        "boot-id",
			},
		},
		Results: []model.CheckResult{{
			Title:    "password=title-secret",
			Summary:  "token=summary-secret",
			Expected: "secret=criteria-secret",
			Solution: "secret=solution-secret",
			Observed: "token=top-secret",
			DisplayDetails: []model.ResultDetail{{
				Label: "token=label-secret", Current: "password=detail-secret",
				Expected: "secret=expected-secret", Source: "api_key=source-secret",
			}},
			ErrorMessage: "password=error-secret",
			Evidence: []model.Evidence{{
				Source: "/home/password=evidence-source-secret",
				Command: &model.CommandEvidence{Executable: "/tmp/token=executable-secret", Arguments: []string{
					"--token", "argument-secret",
					"--auth-token", "compound-argument-secret",
					"--password=inline-secret",
					"Authorization: Bearer header-secret",
					"common-password:20",
					"/etc/cron.daily/passwd: 허용되지 않은 권한",
				}, Stdout: "community=public"},
				File: &model.FileEvidence{
					Path:    "/home/password=file-path-secret",
					Content: "cookie=session-secret",
					Mode:    "token=mode-secret",
					Owner:   "password=owner-secret",
					Group:   "credential=group-secret",
				},
				Fact: map[string]any{
					"api_key":    "fact-secret",
					"password":   "plain-fact-secret",
					"credential": "credential-fact-secret",
					"nested": map[string]any{
						"password": "nested-plain-secret",
						"note":     "password=nested-secret",
					},
					"string_maps": []map[string]string{{
						"database_password":  "database-plain-value",
						"databasePassword":   "camel-password-plain-value",
						"clientSecret":       "camel-secret-plain-value",
						"auth.token":         "dotted-token-plain-value",
						"apiKey":             "camel-api-key-plain-value",
						"privateKey":         "camel-private-key-plain-value",
						"db_passwd":          "passwd-plain-value",
						"client_credentials": "credentials-plain-value",
						"tls_passphrase":     "passphrase-plain-value",
						"note":               "token=string-map-value",
					}},
				},
			}},
		}},
	}
	clone := ScanRun(run)
	if clone.Metadata.ToolExecutableSHA256 != run.Metadata.ToolExecutableSHA256 {
		t.Fatalf(
			"scan executable digest changed during redaction: got %q want %q",
			clone.Metadata.ToolExecutableSHA256,
			run.Metadata.ToolExecutableSHA256,
		)
	}
	if !strings.Contains(run.Results[0].Observed, "top-secret") ||
		!strings.Contains(run.Results[0].DisplayDetails[0].Current, "detail-secret") ||
		!strings.Contains(run.Results[0].Evidence[0].Command.Arguments[1], "argument-secret") ||
		run.Results[0].Evidence[0].Fact["password"] != "plain-fact-secret" ||
		run.Results[0].Evidence[0].Fact["api_key"] != "fact-secret" {
		t.Fatal("ScanRun mutated the input")
	}
	arguments := clone.Results[0].Evidence[0].Command.Arguments
	stringMaps := clone.Results[0].Evidence[0].Fact["string_maps"].([]map[string]string)
	serialized := strings.Join([]string{
		clone.Metadata.Warnings[0],
		clone.Metadata.Platform.Hostname,
		clone.Metadata.TargetIdentity.SystemRoot,
		clone.Results[0].Title,
		clone.Results[0].Summary,
		clone.Results[0].Expected,
		clone.Results[0].Solution,
		clone.Results[0].Observed,
		clone.Results[0].DisplayDetails[0].Label,
		clone.Results[0].DisplayDetails[0].Current,
		clone.Results[0].DisplayDetails[0].Expected,
		clone.Results[0].DisplayDetails[0].Source,
		clone.Results[0].ErrorMessage,
		clone.Results[0].Evidence[0].Source,
		clone.Results[0].Evidence[0].Command.Executable,
		clone.Results[0].Evidence[0].Command.Stdout,
		clone.Results[0].Evidence[0].File.Path,
		clone.Results[0].Evidence[0].File.Content,
		clone.Results[0].Evidence[0].File.Mode,
		clone.Results[0].Evidence[0].File.Owner,
		clone.Results[0].Evidence[0].File.Group,
		clone.Results[0].Evidence[0].Fact["api_key"].(string),
		clone.Results[0].Evidence[0].Fact["password"].(string),
		clone.Results[0].Evidence[0].Fact["credential"].(string),
		clone.Results[0].Evidence[0].Fact["nested"].(map[string]any)["password"].(string),
		clone.Results[0].Evidence[0].Fact["nested"].(map[string]any)["note"].(string),
		stringMaps[0]["database_password"],
		stringMaps[0]["databasePassword"],
		stringMaps[0]["clientSecret"],
		stringMaps[0]["auth.token"],
		stringMaps[0]["apiKey"],
		stringMaps[0]["privateKey"],
		stringMaps[0]["db_passwd"],
		stringMaps[0]["client_credentials"],
		stringMaps[0]["tls_passphrase"],
		stringMaps[0]["note"],
		strings.Join(arguments, "\n"),
	}, "\n")
	for _, secret := range []string{
		"top-secret", "label-secret", "detail-secret", "expected-secret", "source-secret",
		"error-secret", "argument-secret", "compound-argument-secret", "inline-secret",
		"header-secret", "public", "session-secret", "fact-secret", "plain-fact-secret",
		"credential-fact-secret", "nested-plain-secret", "nested-secret",
		"database-plain-value", "passwd-plain-value", "credentials-plain-value",
		"camel-password-plain-value", "camel-secret-plain-value", "dotted-token-plain-value",
		"camel-api-key-plain-value", "camel-private-key-plain-value",
		"passphrase-plain-value", "string-map-value",
		"warning-secret", "hostname-secret", "system-root-secret", "title-secret",
		"summary-secret", "criteria-secret", "evidence-source-secret", "executable-secret",
		"file-path-secret", "mode-secret", "owner-secret", "group-secret",
	} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("secret %q remained in clone: %q", secret, serialized)
		}
	}
	if arguments[0] != "--token" || arguments[1] != marker ||
		arguments[2] != "--auth-token" || arguments[3] != marker ||
		arguments[4] != "--password="+marker ||
		arguments[5] != "Authorization: "+marker {
		t.Fatalf("redacted command arguments = %#v", arguments)
	}
	if arguments[6] != "common-password:20" ||
		arguments[7] != "/etc/cron.daily/passwd: 허용되지 않은 권한" {
		t.Fatalf("diagnostic command arguments were corrupted: %#v", arguments)
	}
	clone.Results[0].DisplayDetails[0].Label = "changed"
	if run.Results[0].DisplayDetails[0].Label == "changed" {
		t.Fatal("ScanRun reused the input DisplayDetails backing array")
	}
	if !clone.Results[0].Evidence[0].Redacted {
		t.Fatal("evidence was not marked redacted")
	}
	stringMaps[0]["note"] = "changed"
	originalStringMaps := run.Results[0].Evidence[0].Fact["string_maps"].([]map[string]string)
	if originalStringMaps[0]["note"] == "changed" {
		t.Fatal("ScanRun reused a []map[string]string child map")
	}
}
