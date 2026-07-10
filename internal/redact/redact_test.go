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

func TestScanRunRedactsDeepCopyWithoutMutatingInput(t *testing.T) {
	t.Parallel()
	run := model.ScanRun{
		Metadata: model.RunMetadata{Counts: map[model.Status]int{model.StatusFail: 1}, Warnings: []string{"warning"}},
		Results: []model.CheckResult{{
			Observed:     "token=top-secret",
			ErrorMessage: "password=error-secret",
			Evidence: []model.Evidence{{
				Command: &model.CommandEvidence{Arguments: []string{"--token", "argument-secret"}, Stdout: "community=public"},
				File:    &model.FileEvidence{Content: "cookie=session-secret"},
				Fact: map[string]any{
					"api_key": "fact-secret",
					"nested":  map[string]any{"note": "password=nested-secret"},
				},
			}},
		}},
	}
	clone := ScanRun(run)
	if !strings.Contains(run.Results[0].Observed, "top-secret") || run.Results[0].Evidence[0].Fact["api_key"] != "fact-secret" {
		t.Fatal("ScanRun mutated the input")
	}
	serialized := strings.Join([]string{
		clone.Results[0].Observed,
		clone.Results[0].ErrorMessage,
		clone.Results[0].Evidence[0].Command.Stdout,
		clone.Results[0].Evidence[0].File.Content,
		clone.Results[0].Evidence[0].Fact["api_key"].(string),
		clone.Results[0].Evidence[0].Fact["nested"].(map[string]any)["note"].(string),
	}, "\n")
	for _, secret := range []string{"top-secret", "error-secret", "public", "session-secret", "fact-secret", "nested-secret"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("secret %q remained in clone: %q", secret, serialized)
		}
	}
	if !clone.Results[0].Evidence[0].Redacted {
		t.Fatal("evidence was not marked redacted")
	}
}
