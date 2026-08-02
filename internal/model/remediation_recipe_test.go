package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemediationRecipeVerificationValidate(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	tests := []struct {
		name    string
		value   RemediationRecipeVerification
		wantErr bool
	}{
		{
			name:  "pending without completed verification metadata",
			value: RemediationRecipeVerification{State: RemediationRecipeVerificationPending},
		},
		{
			name: "rejected with canonical target environment",
			value: RemediationRecipeVerification{
				State:        RemediationRecipeVerificationRejected,
				Environments: []string{"Rocky Linux 9.8"},
			},
		},
		{
			name: "verified with complete provenance",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationVerified,
				Environments:   []string{"Rocky Linux 9.8 amd64", "Rocky Linux 9.8 arm64"},
				VerifiedAt:     "2026-07-11T12:34:56Z",
				EvidenceSHA256: []string{digestA, digestB},
			},
		},
		{
			name:    "missing state",
			value:   RemediationRecipeVerification{},
			wantErr: true,
		},
		{
			name:    "unknown state",
			value:   RemediationRecipeVerification{State: "approved"},
			wantErr: true,
		},
		{
			name: "empty environment",
			value: RemediationRecipeVerification{
				State:        RemediationRecipeVerificationPending,
				Environments: []string{""},
			},
			wantErr: true,
		},
		{
			name: "non-canonical environment",
			value: RemediationRecipeVerification{
				State:        RemediationRecipeVerificationPending,
				Environments: []string{"Rocky Linux 9.8 "},
			},
			wantErr: true,
		},
		{
			name: "environment containing nul",
			value: RemediationRecipeVerification{
				State:        RemediationRecipeVerificationPending,
				Environments: []string{"Rocky Linux 9.8\x00amd64"},
			},
			wantErr: true,
		},
		{
			name: "environment containing newline",
			value: RemediationRecipeVerification{
				State:        RemediationRecipeVerificationPending,
				Environments: []string{"Rocky Linux 9.8\namd64"},
			},
			wantErr: true,
		},
		{
			name: "duplicate environment",
			value: RemediationRecipeVerification{
				State:        RemediationRecipeVerificationPending,
				Environments: []string{"Rocky Linux 9.8", "Rocky Linux 9.8"},
			},
			wantErr: true,
		},
		{
			name: "verified without environment",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationVerified,
				VerifiedAt:     "2026-07-11T12:34:56Z",
				EvidenceSHA256: []string{digestA},
			},
			wantErr: true,
		},
		{
			name: "verified without timestamp",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationVerified,
				Environments:   []string{"Rocky Linux 9.8"},
				EvidenceSHA256: []string{digestA},
			},
			wantErr: true,
		},
		{
			name: "verified with invalid timestamp",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationVerified,
				Environments:   []string{"Rocky Linux 9.8"},
				VerifiedAt:     "2026-07-11",
				EvidenceSHA256: []string{digestA},
			},
			wantErr: true,
		},
		{
			name: "verified without evidence",
			value: RemediationRecipeVerification{
				State:        RemediationRecipeVerificationVerified,
				Environments: []string{"Rocky Linux 9.8"},
				VerifiedAt:   "2026-07-11T12:34:56Z",
			},
			wantErr: true,
		},
		{
			name: "verified with uppercase evidence digest",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationVerified,
				Environments:   []string{"Rocky Linux 9.8"},
				VerifiedAt:     "2026-07-11T12:34:56Z",
				EvidenceSHA256: []string{strings.Repeat("A", 64)},
			},
			wantErr: true,
		},
		{
			name: "verified with malformed evidence digest",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationVerified,
				Environments:   []string{"Rocky Linux 9.8"},
				VerifiedAt:     "2026-07-11T12:34:56Z",
				EvidenceSHA256: []string{strings.Repeat("g", 64)},
			},
			wantErr: true,
		},
		{
			name: "verified with duplicate evidence digest",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationVerified,
				Environments:   []string{"Rocky Linux 9.8"},
				VerifiedAt:     "2026-07-11T12:34:56Z",
				EvidenceSHA256: []string{digestA, digestA},
			},
			wantErr: true,
		},
		{
			name: "pending with verified timestamp",
			value: RemediationRecipeVerification{
				State:      RemediationRecipeVerificationPending,
				VerifiedAt: "2026-07-11T12:34:56Z",
			},
			wantErr: true,
		},
		{
			name: "rejected with verified evidence",
			value: RemediationRecipeVerification{
				State:          RemediationRecipeVerificationRejected,
				EvidenceSHA256: []string{digestA},
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.value.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestRemediationRecipeValidateRequiresVerification(t *testing.T) {
	recipe := validRemediationRecipeForVerificationTest()
	if err := recipe.Validate(); err != nil {
		t.Fatalf("valid recipe was rejected: %v", err)
	}

	withoutArchitecture := recipe
	withoutArchitecture.Selector.Architecture = ""
	if err := withoutArchitecture.Validate(); err == nil {
		t.Fatal("recipe without an exact architecture was accepted")
	}
	nonCanonicalSelectors := []PlatformSelector{
		{ID: "Rocky", Version: "9.8", Architecture: "amd64"},
		{ID: "Σ", Version: "9.8", Architecture: "amd64"},
		{ID: "rocky", Version: "９.８", Architecture: "amd64"},
		{ID: "rocky", Version: "9.8", Architecture: "AMD64"},
		{OS: "linux", ID: "rocky", Version: "9.8", Architecture: "amd64"},
		{Family: "rhel", ID: "rocky", Version: "9.8", Architecture: "amd64"},
	}
	for _, selector := range nonCanonicalSelectors {
		candidate := recipe
		candidate.Selector = selector
		if err := candidate.Validate(); err == nil {
			t.Errorf("recipe accepted non-canonical exact selector %#v", selector)
		}
	}

	multipleOperations := recipe
	multipleOperations.Operations = append(
		append([]FileMetadataRecipeEntry(nil), recipe.Operations...),
		FileMetadataRecipeEntry{
			Type:             RecipePreserveContentFileMetadata,
			Path:             "/etc/services",
			AllowedOwners:    []string{"root"},
			RemediationOwner: "root",
			MaximumMode:      "0644",
		},
	)
	if err := multipleOperations.Validate(); err == nil {
		t.Fatal("recipe with multiple operations was accepted")
	}

	recipe.Verification = RemediationRecipeVerification{}
	if err := recipe.Validate(); err == nil {
		t.Fatal("recipe without verification metadata was accepted")
	}
}

func TestRemediationRecipeSchemaUsesRuntimeExactSelectorPattern(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "remediation-recipe.schema.json"))
	if err != nil {
		t.Fatalf("ReadFile(remediation schema) error = %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("Unmarshal(remediation schema) error = %v", err)
	}
	defs := schema["$defs"].(map[string]any)
	exact := defs["exactSelectorString"].(map[string]any)
	if exact["pattern"] != exactRemediationSelectorTokenPattern.String() {
		t.Fatalf(
			"schema exact selector pattern = %q, want %q",
			exact["pattern"],
			exactRemediationSelectorTokenPattern.String(),
		)
	}
	exclusion, ok := exact["not"].(map[string]any)
	if !ok || exclusion["pattern"] != `[\r\n]` {
		t.Fatalf("schema exact selector line terminator exclusion = %#v", exact["not"])
	}
	selector := defs["selector"].(map[string]any)
	properties := selector["properties"].(map[string]any)
	for _, field := range []string{"id", "version", "architecture"} {
		property := properties[field].(map[string]any)
		if property["$ref"] != "#/$defs/exactSelectorString" {
			t.Fatalf("schema selector %s ref = %q, want exactSelectorString", field, property["$ref"])
		}
	}
	versionMajor := properties["version_major"].(map[string]any)
	if versionMajor["const"] != "" {
		t.Fatalf("schema version_major constraint = %#v, want empty string only", versionMajor)
	}
	for _, field := range []string{"os", "family"} {
		property := properties[field].(map[string]any)
		if property["const"] != "" {
			t.Fatalf("schema selector %s constraint = %#v, want empty string only", field, property)
		}
	}
}

func validRemediationRecipeForVerificationTest() RemediationRecipe {
	return RemediationRecipe{
		ID:        "u19-hosts-permissions-rocky-9.8",
		GuideYear: 2026,
		RuleID:    "U-19",
		Selector: PlatformSelector{
			ID:           "rocky",
			Version:      "9.8",
			Architecture: "amd64",
		},
		Verification: RemediationRecipeVerification{
			State:        RemediationRecipeVerificationPending,
			Environments: []string{"Rocky Linux 9.8"},
		},
		Risk:           RiskCaution,
		ExpectedImpact: "허용되지 않은 파일 메타데이터만 최소 변경합니다.",
		Operations: []FileMetadataRecipeEntry{
			{
				Type:             RecipePreserveContentFileMetadata,
				Path:             "/etc/hosts",
				AllowedOwners:    []string{"root"},
				RemediationOwner: "root",
				MaximumMode:      "0644",
			},
		},
	}
}
