package supportevidence

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type promotionSemanticsV1 struct {
	SchemaVersion int                       `json:"schema_version"`
	Platform      promotionLayerSemanticsV1 `json:"platform"`
	Recipes       []promotionRecipeV1       `json:"recipes,omitempty"`
}

type promotionLayerSemanticsV1 struct {
	SchemaVersion int                           `json:"schema_version"`
	ID            string                        `json:"id"`
	Priority      int                           `json:"priority"`
	Selector      model.PlatformSelector        `json:"selector"`
	Defaults      model.BindingDefaults         `json:"defaults,omitempty"`
	Bindings      []promotionBindingSemanticsV1 `json:"bindings"`
}

type promotionBindingSemanticsV1 struct {
	RuleID     string         `json:"rule_id"`
	Evaluator  *string        `json:"evaluator,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty"`
	Applicable *bool          `json:"applicable,omitempty"`
}

type promotionRecipeV1 struct {
	ID             string                          `json:"id"`
	GuideYear      int                             `json:"guide_year"`
	RuleID         string                          `json:"rule_id"`
	Selector       model.PlatformSelector          `json:"selector"`
	Risk           model.RemediationRisk           `json:"risk"`
	ExpectedImpact string                          `json:"expected_impact"`
	Operations     []model.FileMetadataRecipeEntry `json:"operations"`
}

func PromotionSemanticsDigest(
	layer model.BindingLayer,
	recipes []model.RemediationRecipe,
) (string, error) {
	if layer.Selector.OS != "" || layer.Selector.Family != "" ||
		layer.Selector.VersionMajor != "" ||
		layer.Selector.ID == "" || layer.Selector.Version == "" ||
		layer.Selector.Architecture == "" {
		return "", fmt.Errorf("promotion semantics require only exact id, version, and architecture selectors")
	}
	semantics := promotionSemanticsV1{
		SchemaVersion: SchemaVersion,
		Platform: promotionLayerSemanticsV1{
			SchemaVersion: layer.SchemaVersion,
			ID:            layer.ID,
			Priority:      layer.Priority,
			Selector:      layer.Selector,
			Defaults:      layer.Defaults,
			Bindings:      make([]promotionBindingSemanticsV1, 0, len(layer.Bindings)),
		},
	}
	for _, binding := range layer.Bindings {
		semantics.Platform.Bindings = append(
			semantics.Platform.Bindings,
			promotionBindingSemanticsV1{
				RuleID:     binding.RuleID,
				Evaluator:  binding.Evaluator,
				Parameters: binding.Parameters,
				Applicable: binding.Applicable,
			},
		)
	}
	sort.Slice(semantics.Platform.Bindings, func(i, j int) bool {
		return semantics.Platform.Bindings[i].RuleID < semantics.Platform.Bindings[j].RuleID
	})

	for _, recipe := range recipes {
		if recipe.Selector.ID != layer.Selector.ID ||
			recipe.Selector.Version != layer.Selector.Version ||
			recipe.Selector.Architecture != layer.Selector.Architecture {
			continue
		}
		operations := append([]model.FileMetadataRecipeEntry(nil), recipe.Operations...)
		for index := range operations {
			operations[index].AllowedOwners = append([]string(nil), operations[index].AllowedOwners...)
			sort.Strings(operations[index].AllowedOwners)
		}
		semantics.Recipes = append(semantics.Recipes, promotionRecipeV1{
			ID:             recipe.ID,
			GuideYear:      recipe.GuideYear,
			RuleID:         recipe.RuleID,
			Selector:       recipe.Selector,
			Risk:           recipe.Risk,
			ExpectedImpact: recipe.ExpectedImpact,
			Operations:     operations,
		})
	}
	if len(recipes) > 0 && len(semantics.Recipes) == 0 {
		return "", fmt.Errorf("no remediation recipe matches the exact promotion platform")
	}
	sort.Slice(semantics.Recipes, func(i, j int) bool {
		return semantics.Recipes[i].ID < semantics.Recipes[j].ID
	})
	data, err := json.Marshal(semantics)
	if err != nil {
		return "", fmt.Errorf("encode promotion semantics: %w", err)
	}
	return digestBytes(append(data, '\n')), nil
}
