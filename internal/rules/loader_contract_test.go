package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestContributorPlatformTemplateLoads(t *testing.T) {
	t.Parallel()

	loader := NewLoader(os.DirFS("../.."))
	layer, err := loader.LoadBinding("contrib/os-support/platform.yaml")
	if err != nil {
		t.Fatalf("load contributor platform template: %v", err)
	}
	if layer.ScanSupport == nil || *layer.ScanSupport != model.ScanSupportSupported {
		t.Fatalf("contributor platform template scan support = %#v, want supported", layer.ScanSupport)
	}
	if layer.PlatformVerification != nil {
		t.Fatalf("contributor platform template verification = %#v, want none", layer.PlatformVerification)
	}
	if len(layer.Bindings) != 0 {
		t.Fatalf("contributor platform template bindings = %#v, want only explicit contributor additions", layer.Bindings)
	}

	family, err := loader.LoadBinding("contrib/os-support/family-platform.yaml")
	if err != nil {
		t.Fatalf("load contributor family platform template: %v", err)
	}
	if family.Priority != 200 || family.Selector.Family == "" {
		t.Fatalf("contributor family template = %#v, want a priority 200 family selector", family)
	}
}

func TestLoadBindingRejectsMalformedOrAmbiguousLayers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "duplicate rule binding",
			content: validBindingHeader() +
				"  - rule_id: U-01\n    evaluator: first\n" +
				"  - rule_id: U-01\n    evaluator: second\n",
			want: "duplicate rule U-01",
		},
		{
			name: "empty evaluator override",
			content: validBindingHeader() +
				"  - rule_id: U-01\n    evaluator: \"\"\n",
			want: "empty evaluator override",
		},
		{
			name: "noncanonical rule id",
			content: validBindingHeader() +
				"  - rule_id: U-1\n    evaluator: evaluator\n",
			want: "must match U-NN",
		},
		{
			name:    "empty selector",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector: {}\nbindings: []\n",
			want:    "at least one canonical selector",
		},
		{
			name:    "noncanonical selector",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  os: \" linux\"\nbindings: []\n",
			want:    "at least one canonical selector",
		},
		{
			name:    "noncanonical major version",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  version_major: \"09\"\nbindings: []\n",
			want:    "at least one canonical selector",
		},
		{
			name:    "negative priority",
			content: "schema_version: 1\nid: test-layer\npriority: -1\nselector:\n  os: linux\nbindings: []\n",
			want:    "must not be negative",
		},
		{
			name:    "default rule verification",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  id: rocky\n  version: \"9.8\"\n  architecture: amd64\ndefaults:\n  verification:\n    state: pending\nbindings: []\n",
			want:    "field verification not found",
		},
		{
			name:    "duplicate verification environment",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  id: rocky\n  version: \"9.8\"\n  architecture: amd64\nbindings:\n  - rule_id: U-01\n    verification:\n      state: pending\n      environments: [same, same]\n",
			want:    "is duplicated",
		},
		{
			name: "broad rule verification",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  os: linux\nbindings:\n" +
				"  - rule_id: U-01\n    verification:\n      state: pending\n",
			want: "requires an exact id, version, and architecture selector",
		},
		{
			name:    "unknown yaml field",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  os: linux\nunknown: true\nbindings: []\n",
			want:    "field unknown not found",
		},
		{
			name: "multiple yaml documents",
			content: validBindingHeader() +
				"  - rule_id: U-01\n    evaluator: evaluator\n---\nschema_version: 1\n",
			want: "multiple YAML documents",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			loader := NewLoader(fstest.MapFS{
				"binding.yaml": &fstest.MapFile{Data: []byte(test.content)},
			})
			_, err := loader.LoadBinding("binding.yaml")
			if err == nil {
				t.Fatal("LoadBinding() succeeded, want fail-closed rejection")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadBinding() error = %q, want substring %q", err, test.want)
			}
		})
	}
}

func TestResolveAppliesOnlyMatchingLayersInDeterministicOrder(t *testing.T) {
	t.Parallel()

	evaluatorBase := "base"
	evaluatorA := "exact-a"
	evaluatorZ := "exact-z"
	layers := []model.BindingLayer{
		bindingLayer("z-exact", 300, model.PlatformSelector{ID: "rocky", Version: "9.8"}, model.RuleBinding{
			RuleID:    "U-01",
			Evaluator: &evaluatorZ,
			Parameters: map[string]any{
				"winner": "z",
			},
		}),
		bindingLayer("wrong-architecture", 400, model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "arm64"}, model.RuleBinding{
			RuleID: "U-01",
			Parameters: map[string]any{
				"wrong": true,
			},
		}),
		bindingLayer("linux", 100, model.PlatformSelector{OS: "linux"}, model.RuleBinding{
			RuleID:    "U-01",
			Evaluator: &evaluatorBase,
			Parameters: map[string]any{
				"base": true,
			},
		}),
		bindingLayer("a-exact", 300, model.PlatformSelector{ID: "rocky", Version: "9.8"}, model.RuleBinding{
			RuleID:    "U-01",
			Evaluator: &evaluatorA,
			Parameters: map[string]any{
				"winner": "a",
			},
		}),
		bindingLayer("rhel-9", 200, model.PlatformSelector{Family: "rhel", VersionMajor: "9"}, model.RuleBinding{
			RuleID: "U-01",
			Parameters: map[string]any{
				"family": true,
			},
		}),
	}
	catalog := singleRuleCatalog()

	resolved, err := Resolve(catalog, layers, rulesContractRockyLinux98Platform())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("resolved rule count = %d, want 1", len(resolved))
	}
	rule := resolved[0]
	if rule.Evaluator != evaluatorZ {
		t.Fatalf("evaluator = %q, want lexically last tied layer %q", rule.Evaluator, evaluatorZ)
	}
	if !reflect.DeepEqual(rule.BindingSources, []string{"linux", "rhel-9", "a-exact", "z-exact"}) {
		t.Fatalf("binding sources = %v, want deterministic priority and id order", rule.BindingSources)
	}
	if rule.Parameters["base"] != true || rule.Parameters["family"] != true || rule.Parameters["winner"] != "z" {
		t.Fatalf("merged parameters = %#v, want common, family, and exact values", rule.Parameters)
	}
	if _, exists := rule.Parameters["wrong"]; exists {
		t.Fatalf("nonmatching architecture layer affected parameters: %#v", rule.Parameters)
	}
}

func TestResolveRejectsDuplicateLayerIDsAndUnknownBindings(t *testing.T) {
	t.Parallel()

	catalog := singleRuleCatalog()
	layer := bindingLayer("duplicate", 100, model.PlatformSelector{OS: "linux"}, model.RuleBinding{RuleID: "U-01"})
	if _, err := Resolve(catalog, []model.BindingLayer{layer, layer}, rulesContractRockyLinux98Platform()); err == nil || !strings.Contains(err.Error(), "duplicate binding layer id") {
		t.Fatalf("Resolve() duplicate layer error = %v, want fail-closed duplicate rejection", err)
	}

	unknown := bindingLayer("unknown-rule", 100, model.PlatformSelector{OS: "linux"}, model.RuleBinding{RuleID: "U-67"})
	if _, err := Resolve(catalog, []model.BindingLayer{unknown}, rulesContractRockyLinux98Platform()); err == nil || !strings.Contains(err.Error(), "references unknown rule U-67") {
		t.Fatalf("Resolve() unknown binding error = %v, want fail-closed unknown rule rejection", err)
	}
}

func TestResolveRejectsOverlappingExactRuleVerificationSelectors(t *testing.T) {
	t.Parallel()

	pending := model.Verification{State: model.VerificationPending}
	first := bindingLayer(
		"rocky-plain",
		300,
		model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
		model.RuleBinding{RuleID: "U-01", Verification: &pending},
	)
	second := bindingLayer(
		"rocky-duplicate",
		400,
		model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
		model.RuleBinding{RuleID: "U-01", Verification: &pending},
	)

	_, err := Resolve(singleRuleCatalog(), []model.BindingLayer{first, second}, rulesContractRockyLinux98Platform())
	if err == nil || !strings.Contains(err.Error(), "target the same exact platform") {
		t.Fatalf("Resolve() overlap error = %v, want fail-closed exact rule selector rejection", err)
	}
}

func TestValidateRemediationRuleProvenanceRequiresExactLayer(t *testing.T) {
	t.Parallel()

	verified := model.Verification{
		State:        model.VerificationVerified,
		Environments: []string{"Rocky Linux 9.8 amd64"},
		VerifiedAt:   "2026-07-11T12:34:56Z",
	}
	exact := bindingLayer(
		"rocky-9.8-amd64",
		300,
		model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
		model.RuleBinding{RuleID: "U-01", Verification: &verified},
	)
	bundle := Bundle{Catalog: singleRuleCatalog(), Layers: []model.BindingLayer{exact}}
	resolved, err := bundle.Resolve(rulesContractRockyLinux98Platform())
	if err != nil {
		t.Fatalf("Resolve() exact provenance error = %v", err)
	}
	if err := bundle.ValidateRemediationRuleProvenance(rulesContractRockyLinux98Platform(), resolved[0]); err != nil {
		t.Fatalf("ValidateRemediationRuleProvenance() exact error = %v", err)
	}
	missingSource := resolved[0]
	missingSource.BindingSources = nil
	if err := bundle.ValidateRemediationRuleProvenance(rulesContractRockyLinux98Platform(), missingSource); err == nil ||
		!strings.Contains(err.Error(), "does not record exact verification source") {
		t.Fatalf("ValidateRemediationRuleProvenance() missing-source error = %v", err)
	}

	broad := bindingLayer(
		"linux-wide",
		100,
		model.PlatformSelector{OS: "linux"},
		model.RuleBinding{RuleID: "U-01", Verification: &verified},
	)
	broadBundle := Bundle{Catalog: singleRuleCatalog(), Layers: []model.BindingLayer{broad}}
	if err := broadBundle.ValidateRemediationRuleProvenance(
		rulesContractRockyLinux98Platform(),
		model.ResolvedRule{
			RuleDefinition: singleRuleCatalog().Rules[0],
			Applicable:     true,
			Verification:   verified,
		},
	); err == nil || !strings.Contains(err.Error(), "exact") {
		t.Fatalf("ValidateRemediationRuleProvenance() broad error = %v, want exact-source rejection", err)
	}
}

func TestResolveInvalidatesVerifiedRuleAfterLaterSemanticChange(t *testing.T) {
	t.Parallel()

	verified := model.Verification{
		State:        model.VerificationVerified,
		Environments: []string{"Rocky Linux 9.8 amd64"},
		VerifiedAt:   "2026-07-11T12:34:56Z",
	}
	verifiedEvaluator := "verified-evaluator"
	applicable := true
	source := bindingLayer(
		"rocky-9.8-amd64",
		300,
		model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
		model.RuleBinding{
			RuleID:       "U-01",
			Evaluator:    &verifiedEvaluator,
			Parameters:   map[string]any{"threshold": 3},
			Applicable:   &applicable,
			Verification: &verified,
		},
	)

	tests := []struct {
		name    string
		binding model.RuleBinding
		layer   model.BindingDefaults
	}{
		{
			name: "evaluator",
			binding: func() model.RuleBinding {
				value := "later-evaluator"
				return model.RuleBinding{RuleID: "U-01", Evaluator: &value}
			}(),
		},
		{
			name:    "parameters",
			binding: model.RuleBinding{RuleID: "U-01", Parameters: map[string]any{"threshold": 4}},
		},
		{
			name: "binding applicable",
			binding: func() model.RuleBinding {
				value := false
				return model.RuleBinding{RuleID: "U-01", Applicable: &value}
			}(),
		},
		{
			name: "default applicable",
			layer: func() model.BindingDefaults {
				value := false
				return model.BindingDefaults{Applicable: &value}
			}(),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			later := bindingLayer(
				"later-scan-layer",
				400,
				model.PlatformSelector{OS: "linux"},
				test.binding,
			)
			later.Defaults = test.layer
			if test.binding.RuleID == "" {
				later.Bindings = nil
			}
			bundle := Bundle{Catalog: singleRuleCatalog(), Layers: []model.BindingLayer{source, later}}
			resolved, err := bundle.Resolve(rulesContractRockyLinux98Platform())
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if resolved[0].Verification.State != model.VerificationPending {
				t.Fatalf("verification = %q, want pending after later semantic change", resolved[0].Verification.State)
			}

			forged := resolved[0]
			forged.Verification = verified
			if err := bundle.ValidateRemediationRuleProvenance(rulesContractRockyLinux98Platform(), forged); err == nil ||
				!strings.Contains(err.Error(), "invalidated by later semantic changes") {
				t.Fatalf("ValidateRemediationRuleProvenance() error = %v, want semantic invalidation", err)
			}
		})
	}
}

func TestResolveKeepsVerificationForLaterSemanticNoOp(t *testing.T) {
	t.Parallel()

	verified := model.Verification{
		State:        model.VerificationVerified,
		Environments: []string{"Rocky Linux 9.8 amd64"},
		VerifiedAt:   "2026-07-11T12:34:56Z",
	}
	evaluator := "same-evaluator"
	applicable := true
	binding := model.RuleBinding{
		RuleID:     "U-01",
		Evaluator:  &evaluator,
		Parameters: map[string]any{"threshold": 3},
		Applicable: &applicable,
	}
	sourceBinding := binding
	sourceBinding.Verification = &verified
	source := bindingLayer(
		"rocky-9.8-amd64",
		300,
		model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
		sourceBinding,
	)
	later := bindingLayer("later-no-op", 400, model.PlatformSelector{OS: "linux"}, binding)
	bundle := Bundle{Catalog: singleRuleCatalog(), Layers: []model.BindingLayer{source, later}}

	resolved, err := bundle.Resolve(rulesContractRockyLinux98Platform())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolved[0].Verification.State != model.VerificationVerified {
		t.Fatalf("verification = %q, want verified for semantic no-op", resolved[0].Verification.State)
	}
	if err := bundle.ValidateRemediationRuleProvenance(rulesContractRockyLinux98Platform(), resolved[0]); err != nil {
		t.Fatalf("ValidateRemediationRuleProvenance() no-op error = %v", err)
	}
}

func TestBindingLayerSchemaMatchesRemediationVerificationContract(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "binding-layer.schema.json"))
	if err != nil {
		t.Fatalf("ReadFile(binding schema) error = %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("Unmarshal(binding schema) error = %v", err)
	}
	defs := schema["$defs"].(map[string]any)
	exact := defs["exactSelectorString"].(map[string]any)
	if exact["pattern"] != exactSelectorTokenPattern.String() {
		t.Fatalf("schema exact selector pattern = %q, want %q", exact["pattern"], exactSelectorTokenPattern.String())
	}
	exclusion, ok := exact["not"].(map[string]any)
	if !ok || exclusion["pattern"] != `[\r\n]` {
		t.Fatalf("schema exact selector line terminator exclusion = %#v", exact["not"])
	}
	defaults := defs["bindingDefaults"].(map[string]any)
	defaultProperties := defaults["properties"].(map[string]any)
	if _, exists := defaultProperties["verification"]; exists {
		t.Fatal("binding schema allows defaults.verification")
	}
	ruleBinding := defs["ruleBinding"].(map[string]any)
	if _, exists := ruleBinding["properties"].(map[string]any)["verification"]; !exists {
		t.Fatal("binding schema does not expose per-rule verification")
	}

	encodedConditions, err := json.Marshal(schema["allOf"])
	if err != nil {
		t.Fatalf("Marshal(binding schema conditions) error = %v", err)
	}
	conditions := string(encodedConditions)
	if !strings.Contains(conditions, `"contains"`) ||
		!strings.Contains(conditions, `"verification"`) ||
		!strings.Contains(conditions, `#/$defs/exactSelectorString`) ||
		!strings.Contains(conditions, `"os":{"const":""}`) ||
		!strings.Contains(conditions, `"family":{"const":""}`) {
		t.Fatal("binding schema does not require an exact selector for per-rule verification")
	}
}

func TestLoadProfilesRejectsUnknownAndDuplicateRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "unknown rule",
			content: "schema_version: 1\nprofiles:\n  - id: test\n    title: Test\n    rule_ids: [U-67]\n",
			want:    "references unknown rule U-67",
		},
		{
			name:    "duplicate rule",
			content: "schema_version: 1\nprofiles:\n  - id: test\n    title: Test\n    rule_ids: [U-01, U-01]\n",
			want:    "more than once",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			loader := NewLoader(fstest.MapFS{
				"profiles.yaml": &fstest.MapFile{Data: []byte(test.content)},
			})
			_, err := loader.LoadProfiles("profiles.yaml", singleRuleCatalog())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadProfiles() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func validBindingHeader() string {
	return "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  os: linux\nbindings:\n"
}

func bindingLayer(id string, priority int, selector model.PlatformSelector, binding model.RuleBinding) model.BindingLayer {
	return model.BindingLayer{
		SchemaVersion: 1,
		ID:            id,
		Priority:      priority,
		Selector:      selector,
		Bindings:      []model.RuleBinding{binding},
	}
}

func singleRuleCatalog() model.Catalog {
	return model.Catalog{
		SchemaVersion: 1,
		Guide: model.Guide{
			Year:   2026,
			Title:  "Test guide",
			Domain: "Unix 서버",
		},
		Rules: []model.RuleDefinition{
			{
				ID:       "U-01",
				Title:    "Test rule",
				Category: model.CategoryAccount,
				Severity: model.SeverityHigh,
				Reference: model.Reference{
					Item: "U-01",
				},
			},
		},
	}
}

func rulesContractRockyLinux98Platform() model.PlatformInfo {
	return model.PlatformInfo{
		OS:           "linux",
		Family:       "rhel",
		ID:           "rocky",
		Name:         "Rocky Linux 9.8",
		VersionID:    "9.8",
		Architecture: "amd64",
	}
}
