package supportevidence_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/supportevidence"
)

func TestContributorEvidenceExampleNormalizesDeterministically(t *testing.T) {
	t.Parallel()

	manifest := loadScanExampleManifest(t)
	canonical, err := supportevidence.CanonicalBytes(manifest)
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.normalized.json"))
	if err != nil {
		t.Fatalf("ReadFile(normalized example) error = %v", err)
	}
	if string(canonical) != string(want) {
		t.Fatalf("canonical example differs from the committed normalized output")
	}

	digest, err := supportevidence.Digest(manifest)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	if digest != "43b836fc9ff27622b3c23fa9cc0700e798854fd1a34609297a19485493f36499" {
		t.Fatalf("Digest() = %q, want the documented semantic digest", digest)
	}
	manifestDigest, err := supportevidence.ManifestDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestDigest() error = %v", err)
	}
	if manifestDigest != "c111ef0c61987cddbccc3179ea6db7224b23d8c03ded9083f6eca1c28e75f1ca" {
		t.Fatalf("ManifestDigest() = %q, want the documented full manifest digest", manifestDigest)
	}
	path, err := supportevidence.RelativePath(manifest)
	if err != nil {
		t.Fatalf("RelativePath() error = %v", err)
	}
	if path != "evidence/os-support/example-1.0-amd64.json" {
		t.Fatalf("RelativePath() = %q", path)
	}
}

func TestCanonicalDigestIgnoresInputFormatAndEvidenceOrder(t *testing.T) {
	t.Parallel()

	manifest := loadRemediationExampleManifest(t)
	first, err := supportevidence.Digest(manifest)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	manifest.Remediation.Rules[0], manifest.Remediation.Rules[2] =
		manifest.Remediation.Rules[2], manifest.Remediation.Rules[0]
	manifest.Remediation.Archives[0], manifest.Remediation.Archives[1] =
		manifest.Remediation.Archives[1], manifest.Remediation.Archives[0]
	encoded, err := json.MarshalIndent(manifest, "", "\t")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	reformatted := strings.ReplaceAll(string(encoded), "\n", "\r\n")
	reparsed, err := supportevidence.Parse([]byte(reformatted))
	if err != nil {
		t.Fatalf("Parse(reformatted JSON) error = %v", err)
	}
	second, err := supportevidence.Digest(reparsed)
	if err != nil {
		t.Fatalf("Digest(reformatted JSON) error = %v", err)
	}
	if first != second {
		t.Fatalf("semantic digest changed from %s to %s", first, second)
	}
}

func TestEvidenceDigestSeparatesStableClaimsFromRunProvenance(t *testing.T) {
	t.Parallel()

	original := loadRemediationExampleManifest(t)
	originalEvidence, err := supportevidence.Digest(original)
	if err != nil {
		t.Fatalf("Digest(original) error = %v", err)
	}
	originalManifest, err := supportevidence.ManifestDigest(original)
	if err != nil {
		t.Fatalf("ManifestDigest(original) error = %v", err)
	}
	changed := original
	remediation := *changed.Remediation
	remediation.Rules = append([]supportevidence.RemediationRuleEvidence(nil), remediation.Rules...)
	remediation.Archives = append([]supportevidence.ArchiveEvidence(nil), remediation.Archives...)
	changed.Remediation = &remediation
	changed.ArtifactStage = supportevidence.ArtifactStageCandidate
	changed.VerifiedAt = ""
	changed.CapturedAt = "2026-01-02T05:06:07Z"
	changed.Source.ToolCommit = strings.Repeat("9", 40)
	changed.Source.BinarySHA256 = strings.Repeat("8", 64)
	changed.Scan.StatusCounts.Fail--
	changed.Scan.StatusCounts.Pass++
	changed.Scan.MetadataSHA256 = strings.Repeat("7", 64)
	changed.Scan.ResultsSHA256 = strings.Repeat("6", 64)
	changed.Scan.ArchiveSHA256 = strings.Repeat("5", 64)
	changed.Scan.ArchiveSizeBytes++
	changed.Remediation.BinarySHA256 = changed.Source.BinarySHA256
	changed.Remediation.RunnerSHA256 = strings.Repeat("3", 64)
	changed.Remediation.Archives[0].ArchiveSHA256 = strings.Repeat("2", 64)
	changed.Remediation.Archives[0].ManifestSHA256 = strings.Repeat("1", 64)
	changed.Remediation.Archives[0].SizeBytes++

	changedEvidence, err := supportevidence.Digest(changed)
	if err != nil {
		t.Fatalf("Digest(changed provenance) error = %v", err)
	}
	if changedEvidence != originalEvidence {
		t.Fatalf("stable evidence digest changed from %s to %s", originalEvidence, changedEvidence)
	}
	changedManifest, err := supportevidence.ManifestDigest(changed)
	if err != nil {
		t.Fatalf("ManifestDigest(changed provenance) error = %v", err)
	}
	if changedManifest == originalManifest {
		t.Fatal("full manifest digest did not change with run provenance")
	}

	claims, err := supportevidence.EvidenceBytes(original)
	if err != nil {
		t.Fatalf("EvidenceBytes() error = %v", err)
	}
	claimText := string(claims)
	for _, included := range []string{
		`"platform"`,
		`"read_only":true`,
		`"result_count":67`,
		`"rule_id":"U-19"`,
		`"run_rollback_verified":true`,
		`"boot_id_changed":true`,
		`"cleanup_verified":true`,
	} {
		if !strings.Contains(claimText, included) {
			t.Errorf("stable evidence claims do not contain %s", included)
		}
	}
	for _, excluded := range []string{
		`artifact_stage`,
		`verified_at`,
		`captured_at`,
		`source`,
		`status_counts`,
		`sha256`,
		`size_bytes`,
	} {
		if strings.Contains(claimText, excluded) {
			t.Errorf("stable evidence claims unexpectedly contain %s", excluded)
		}
	}

	timeChange := original
	timeChange.VerifiedAt = "2026-01-02T03:04:06Z"
	if digest, err := supportevidence.Digest(timeChange); err != nil {
		t.Fatalf("Digest(time change) error = %v", err)
	} else if digest != originalEvidence {
		t.Fatal("stable evidence digest changed with verified_at")
	}
	claimChange := original
	claimChange.Environment = "Example Linux 1.0 alternate amd64"
	if digest, err := supportevidence.Digest(claimChange); err != nil {
		t.Fatalf("Digest(claim change) error = %v", err)
	} else if digest == originalEvidence {
		t.Fatal("stable evidence digest did not change with the public environment")
	}
}

func TestEvidenceValidationFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*supportevidence.Manifest)
		want string
	}{
		{
			name: "incomplete scan",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Scan.Complete = false
			},
			want: "complete must be true",
		},
		{
			name: "candidate verification timestamp",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.ArtifactStage = supportevidence.ArtifactStageCandidate
			},
			want: "candidate evidence verified_at must be empty",
		},
		{
			name: "missing final verification timestamp",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.VerifiedAt = ""
			},
			want: "final evidence verified_at must be RFC3339",
		},
		{
			name: "wrong result count",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Scan.ResultCount = 66
			},
			want: "both be 67",
		},
		{
			name: "scan error",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Scan.ErrorCount = 1
				manifest.Scan.StatusCounts.Error = 1
				manifest.Scan.StatusCounts.Pass--
			},
			want: "must both be 0",
		},
		{
			name: "private address",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Environment = "Example Linux 192.0.2.10"
			},
			want: "without an IP address or path",
		},
		{
			name: "missing rule rollback",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Remediation.Rules[0].ItemRollbackVerified = false
			},
			want: "does not prove apply",
		},
		{
			name: "different remediation binary",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Remediation.BinarySHA256 = strings.Repeat("0", 64)
			},
			want: "same binary_sha256",
		},
		{
			name: "missing reboot",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Remediation.Reboot.BootIDChanged = false
			},
			want: "changed boot",
		},
		{
			name: "missing archive hash",
			edit: func(manifest *supportevidence.Manifest) {
				manifest.Remediation.Archives[0].ArchiveSHA256 = ""
			},
			want: "hashes must be",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			manifest := loadRemediationExampleManifest(t)
			test.edit(&manifest)
			if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseRejectsUnpublishedFieldsAndMultipleDocuments(t *testing.T) {
	t.Parallel()

	base, err := os.ReadFile(filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(example) error = %v", err)
	}
	withHost := strings.Replace(
		string(base),
		"environment: Example Linux 1.0 amd64",
		"environment: Example Linux 1.0 amd64\nhost: test-host",
		1,
	)
	if _, err := supportevidence.Parse([]byte(withHost)); err == nil || !strings.Contains(err.Error(), "field host not found") {
		t.Fatalf("Parse(unknown host field) error = %v", err)
	}
	if _, err := supportevidence.Parse(append(base, []byte("\n---\nschema_version: 1\n")...)); err == nil ||
		!strings.Contains(err.Error(), "multiple YAML or JSON documents") {
		t.Fatalf("Parse(multiple documents) error = %v", err)
	}
}

func TestValidateRelativePathRequiresThePublicEvidenceLocation(t *testing.T) {
	t.Parallel()

	manifest := loadScanExampleManifest(t)
	if err := supportevidence.ValidateRelativePath(
		"evidence/os-support/example-1.0-amd64.json",
		manifest,
	); err != nil {
		t.Fatalf("ValidateRelativePath() error = %v", err)
	}
	for _, path := range []string{
		"evidence/example-1.0-amd64.json",
		"evidence/os-support/renamed.json",
		filepath.Join(string(filepath.Separator), "evidence", "os-support", "example-1.0-amd64.json"),
	} {
		if err := supportevidence.ValidateRelativePath(path, manifest); err == nil {
			t.Fatalf("ValidateRelativePath(%q) succeeded, want rejection", path)
		}
	}
}

func TestEvidenceSchemaDeclaresTheRuntimeContract(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "os-support-evidence.schema.json"))
	if err != nil {
		t.Fatalf("ReadFile(schema) error = %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("Unmarshal(schema) error = %v", err)
	}
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("Marshal(schema) error = %v", err)
	}
	contract := string(encoded)
	for _, required := range []string{
		`"result_count":{"const":67}`,
		`"unique_rule_count":{"const":67}`,
		`"error_count":{"const":0}`,
		`"system_state_unchanged":{"const":true}`,
		`"archive_size_bytes"`,
		`"artifact_stage"`,
		`"captured_at"`,
		`"promotion_semantics_sha256"`,
		`"binary_sha256"`,
		`"runner_sha256"`,
		`"item_rollback_verified"`,
		`"run_rollback_verified"`,
		`"cleanup_verified"`,
		`"reboot_then_run_rollback"`,
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("evidence schema does not contain %s", required)
		}
	}
}

func loadScanExampleManifest(t *testing.T) supportevidence.Manifest {
	t.Helper()
	manifest, err := supportevidence.LoadFile(
		filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.yaml"),
	)
	if err != nil {
		t.Fatalf("LoadFile(example) error = %v", err)
	}
	return manifest
}

func loadRemediationExampleManifest(t *testing.T) supportevidence.Manifest {
	t.Helper()
	manifest, err := supportevidence.LoadFile(
		filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "evidence-manifest.yaml"),
	)
	if err != nil {
		t.Fatalf("LoadFile(remediation example) error = %v", err)
	}
	return manifest
}
