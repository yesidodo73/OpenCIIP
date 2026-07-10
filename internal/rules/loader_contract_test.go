package rules

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

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
			name:    "verified default without provenance",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  os: linux\ndefaults:\n  verification:\n    state: verified\nbindings: []\n",
			want:    "requires at least one environment",
		},
		{
			name:    "duplicate verification environment",
			content: "schema_version: 1\nid: test-layer\npriority: 100\nselector:\n  os: linux\ndefaults:\n  verification:\n    state: pending\n    environments: [same, same]\nbindings: []\n",
			want:    "is duplicated",
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
