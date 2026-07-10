package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const maxRuleFileSize = 4 << 20

var (
	bindingRuleIDPattern = regexp.MustCompile(`^U-[0-9]{2}$`)
	versionMajorPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

type Loader struct {
	fs fs.FS
}

func NewLoader(ruleFS fs.FS) *Loader {
	return &Loader{fs: ruleFS}
}

func (l *Loader) LoadCatalog(path string) (model.Catalog, error) {
	var catalog model.Catalog
	if err := l.decodeYAML(path, &catalog); err != nil {
		return model.Catalog{}, err
	}
	if err := catalog.Validate(); err != nil {
		return model.Catalog{}, fmt.Errorf("validate rule catalog %s: %w", path, err)
	}
	return catalog, nil
}

func (l *Loader) LoadProfiles(path string, catalog model.Catalog) (model.ProfileSet, error) {
	var profiles model.ProfileSet
	if err := l.decodeYAML(path, &profiles); err != nil {
		return model.ProfileSet{}, err
	}
	if err := profiles.Validate(catalog); err != nil {
		return model.ProfileSet{}, fmt.Errorf("validate profiles %s: %w", path, err)
	}
	return profiles, nil
}

func (l *Loader) LoadBinding(path string) (model.BindingLayer, error) {
	var layer model.BindingLayer
	if err := l.decodeYAML(path, &layer); err != nil {
		return model.BindingLayer{}, err
	}
	if err := validateBindingLayer(layer); err != nil {
		return model.BindingLayer{}, fmt.Errorf("validate binding %s: %w", path, err)
	}
	return layer, nil
}

func (l *Loader) decodeYAML(path string, destination any) error {
	file, err := l.fs.Open(path)
	if err != nil {
		return fmt.Errorf("open rule data %s: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxRuleFileSize+1))
	if err != nil {
		return fmt.Errorf("read rule data %s: %w", path, err)
	}
	if len(data) > maxRuleFileSize {
		return fmt.Errorf("rule data %s exceeds the %d byte limit", path, maxRuleFileSize)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode rule data %s: %w", path, err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode rule data %s: multiple YAML documents are not allowed", path)
		}
		return fmt.Errorf("decode trailing rule data %s: %w", path, err)
	}
	return nil
}

func validateBindingLayer(layer model.BindingLayer) error {
	if layer.SchemaVersion != 1 {
		return fmt.Errorf("unsupported binding schema version %d", layer.SchemaVersion)
	}
	if strings.TrimSpace(layer.ID) == "" || strings.TrimSpace(layer.ID) != layer.ID {
		return fmt.Errorf("binding layer id is required")
	}
	if layer.Priority < 0 {
		return fmt.Errorf("binding layer priority must not be negative")
	}
	if !validSelector(layer.Selector) {
		return fmt.Errorf("binding layer %s must have at least one canonical selector", layer.ID)
	}
	if layer.PlatformVerification != nil {
		if !isExactPlatformSelector(layer.Selector) {
			return fmt.Errorf("binding layer %s platform verification requires exact id and version selectors without version_major", layer.ID)
		}
		if err := validateVerification(*layer.PlatformVerification); err != nil {
			return fmt.Errorf("binding layer %s platform verification: %w", layer.ID, err)
		}
	}
	if layer.Defaults.Verification != nil {
		if err := validateVerification(*layer.Defaults.Verification); err != nil {
			return fmt.Errorf("binding layer %s default verification: %w", layer.ID, err)
		}
	}
	seen := make(map[string]struct{}, len(layer.Bindings))
	for _, binding := range layer.Bindings {
		if !bindingRuleIDPattern.MatchString(binding.RuleID) {
			return fmt.Errorf("binding rule id %q must match U-NN", binding.RuleID)
		}
		if _, exists := seen[binding.RuleID]; exists {
			return fmt.Errorf("binding layer %s contains duplicate rule %s", layer.ID, binding.RuleID)
		}
		seen[binding.RuleID] = struct{}{}
		if binding.Evaluator != nil && strings.TrimSpace(*binding.Evaluator) == "" {
			return fmt.Errorf("binding %s has an empty evaluator override", binding.RuleID)
		}
		if binding.Verification != nil {
			if err := validateVerification(*binding.Verification); err != nil {
				return fmt.Errorf("binding %s verification: %w", binding.RuleID, err)
			}
		}
	}
	return nil
}

func validSelector(selector model.PlatformSelector) bool {
	values := []string{selector.OS, selector.Family, selector.ID, selector.Version, selector.VersionMajor, selector.Architecture}
	nonEmpty := false
	for _, value := range values {
		if value == "" {
			continue
		}
		if strings.TrimSpace(value) != value {
			return false
		}
		nonEmpty = true
	}
	if selector.VersionMajor != "" && !versionMajorPattern.MatchString(selector.VersionMajor) {
		return false
	}
	return nonEmpty
}

func isExactPlatformSelector(selector model.PlatformSelector) bool {
	return selector.ID != "" && selector.Version != "" && selector.VersionMajor == ""
}

func validateVerification(verification model.Verification) error {
	return verification.Validate()
}

// Resolve applies matching layers in ascending priority order. Layer IDs break
// priority ties so the same inputs always produce the same effective rules.
func Resolve(catalog model.Catalog, layers []model.BindingLayer, platform model.PlatformInfo) ([]model.ResolvedRule, error) {
	matching, err := matchingLayers(layers, platform)
	if err != nil {
		return nil, err
	}

	resolved := make(map[string]model.ResolvedRule, len(catalog.Rules))
	for _, definition := range catalog.Rules {
		resolved[definition.ID] = model.ResolvedRule{
			RuleDefinition: cloneDefinition(definition),
			Applicable:     true,
			Verification: model.Verification{
				State: model.VerificationPending,
			},
		}
	}

	for _, layer := range matching {
		if layer.Defaults.Applicable != nil || layer.Defaults.Verification != nil {
			for id, rule := range resolved {
				if layer.Defaults.Applicable != nil {
					rule.Applicable = *layer.Defaults.Applicable
				}
				if layer.Defaults.Verification != nil {
					rule.Verification = *layer.Defaults.Verification
					rule.Verification.Environments = append([]string(nil), layer.Defaults.Verification.Environments...)
				}
				rule.BindingSources = append(rule.BindingSources, layer.ID)
				resolved[id] = rule
			}
		}
		for _, binding := range layer.Bindings {
			rule, exists := resolved[binding.RuleID]
			if !exists {
				return nil, fmt.Errorf("binding layer %s references unknown rule %s", layer.ID, binding.RuleID)
			}
			if binding.Evaluator != nil {
				rule.Evaluator = strings.TrimSpace(*binding.Evaluator)
			}
			if binding.Parameters != nil {
				if rule.Parameters == nil {
					rule.Parameters = make(map[string]any)
				}
				for key, value := range binding.Parameters {
					rule.Parameters[key] = cloneValue(value)
				}
			}
			if binding.Applicable != nil {
				rule.Applicable = *binding.Applicable
			}
			if binding.Verification != nil {
				rule.Verification = *binding.Verification
				rule.Verification.Environments = append([]string(nil), binding.Verification.Environments...)
			}
			rule.BindingSources = append(rule.BindingSources, layer.ID)
			resolved[binding.RuleID] = rule
		}
	}

	result := make([]model.ResolvedRule, 0, len(resolved))
	for _, rule := range resolved {
		result = append(result, rule)
	}
	return model.SortedRules(result), nil
}

func matchingLayers(layers []model.BindingLayer, platform model.PlatformInfo) ([]model.BindingLayer, error) {
	matching := make([]model.BindingLayer, 0, len(layers))
	seenLayerIDs := make(map[string]struct{}, len(layers))
	for _, layer := range layers {
		if _, exists := seenLayerIDs[layer.ID]; exists {
			return nil, fmt.Errorf("duplicate binding layer id %q", layer.ID)
		}
		seenLayerIDs[layer.ID] = struct{}{}
		if selectorMatches(layer.Selector, platform) {
			matching = append(matching, layer)
		}
	}
	sort.SliceStable(matching, func(i, j int) bool {
		if matching[i].Priority == matching[j].Priority {
			return matching[i].ID < matching[j].ID
		}
		return matching[i].Priority < matching[j].Priority
	})
	return matching, nil
}

func selectorMatches(selector model.PlatformSelector, platform model.PlatformInfo) bool {
	return matches(selector.OS, platform.OS) &&
		matches(selector.Family, platform.Family) &&
		matches(selector.ID, platform.ID) &&
		matches(selector.Version, platform.VersionID) &&
		matches(selector.VersionMajor, platformVersionMajor(platform.VersionID)) &&
		matches(selector.Architecture, platform.Architecture)
}

func matches(expected, actual string) bool {
	return expected == "" || strings.EqualFold(strings.TrimSpace(expected), strings.TrimSpace(actual))
}

func platformVersionMajor(versionID string) string {
	versionID = strings.TrimSpace(versionID)
	end := 0
	for end < len(versionID) && versionID[end] >= '0' && versionID[end] <= '9' {
		end++
	}
	return versionID[:end]
}

func cloneDefinition(rule model.RuleDefinition) model.RuleDefinition {
	clone := rule
	clone.Reference.Pages = append([]int(nil), rule.Reference.Pages...)
	if rule.Parameters != nil {
		clone.Parameters = make(map[string]any, len(rule.Parameters))
		for key, value := range rule.Parameters {
			clone.Parameters[key] = cloneValue(value)
		}
	}
	return clone
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		clone := make(map[string]any, len(typed))
		for key, child := range typed {
			clone[key] = cloneValue(child)
		}
		return clone
	case []any:
		clone := make([]any, len(typed))
		for index, child := range typed {
			clone[index] = cloneValue(child)
		}
		return clone
	default:
		return value
	}
}
