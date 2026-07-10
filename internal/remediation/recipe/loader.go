package recipe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	remediationdata "github.com/yesidodo73/OpenCIIP/remediation"
)

const maximumRecipeFileSize = 2 << 20

type Registry struct {
	recipes []model.RemediationRecipe
}

func LoadDefaults() (*Registry, error) {
	return Load(remediationdata.FS, "2026/unix")
}

func Load(source fs.FS, directory string) (*Registry, error) {
	entries, err := fs.ReadDir(source, directory)
	if err != nil {
		return nil, fmt.Errorf("read remediation recipe directory: %w", err)
	}
	recipes := make([]model.RemediationRecipe, 0)
	ids := make(map[string]struct{})
	keys := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		filePath := directory + "/" + entry.Name()
		catalog, err := loadCatalog(source, filePath)
		if err != nil {
			return nil, err
		}
		for _, item := range catalog.Recipes {
			if _, duplicate := ids[item.ID]; duplicate {
				return nil, fmt.Errorf("remediation recipe id %s is duplicated across catalogs", item.ID)
			}
			ids[item.ID] = struct{}{}
			key := item.MatchKey()
			if _, duplicate := keys[key]; duplicate {
				return nil, fmt.Errorf("multiple remediation recipes target %s on the same platform", item.RuleID)
			}
			keys[key] = struct{}{}
			recipes = append(recipes, cloneRecipe(item))
		}
	}
	if len(recipes) == 0 {
		return nil, fmt.Errorf("no remediation recipes were loaded")
	}
	sort.SliceStable(recipes, func(i, j int) bool { return recipes[i].ID < recipes[j].ID })
	return &Registry{recipes: recipes}, nil
}

func loadCatalog(source fs.FS, filePath string) (model.RemediationRecipeCatalog, error) {
	file, err := source.Open(filePath)
	if err != nil {
		return model.RemediationRecipeCatalog{}, fmt.Errorf("open remediation recipe %s: %w", filePath, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximumRecipeFileSize+1))
	if err != nil {
		return model.RemediationRecipeCatalog{}, fmt.Errorf("read remediation recipe %s: %w", filePath, err)
	}
	if len(data) > maximumRecipeFileSize {
		return model.RemediationRecipeCatalog{}, fmt.Errorf("remediation recipe %s exceeds the size limit", filePath)
	}
	var catalog model.RemediationRecipeCatalog
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&catalog); err != nil {
		return model.RemediationRecipeCatalog{}, fmt.Errorf("decode remediation recipe %s: %w", filePath, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple YAML documents are not allowed")
		}
		return model.RemediationRecipeCatalog{}, fmt.Errorf("decode remediation recipe %s trailing data: %w", filePath, err)
	}
	if err := catalog.Validate(); err != nil {
		return model.RemediationRecipeCatalog{}, fmt.Errorf("validate remediation recipe %s: %w", filePath, err)
	}
	return catalog, nil
}

func (r *Registry) Match(ruleID string, platform model.PlatformInfo) (model.RemediationRecipe, bool) {
	if r == nil {
		return model.RemediationRecipe{}, false
	}
	for _, item := range r.recipes {
		if item.RuleID == ruleID && selectorMatches(item.Selector, platform) {
			return cloneRecipe(item), true
		}
	}
	return model.RemediationRecipe{}, false
}

func (r *Registry) All() []model.RemediationRecipe {
	if r == nil {
		return nil
	}
	result := make([]model.RemediationRecipe, len(r.recipes))
	for index, item := range r.recipes {
		result[index] = cloneRecipe(item)
	}
	return result
}

func ParseMode(value string) (uint32, error) {
	if len(value) < 2 || value[0] != '0' {
		return 0, fmt.Errorf("mode %q is not canonical octal", value)
	}
	parsed, err := strconv.ParseUint(value[1:], 8, 32)
	if err != nil || parsed > 0o7777 {
		return 0, fmt.Errorf("mode %q is invalid", value)
	}
	return uint32(parsed), nil
}

func selectorMatches(selector model.PlatformSelector, platform model.PlatformInfo) bool {
	return match(selector.OS, platform.OS) && match(selector.Family, platform.Family) &&
		match(selector.ID, platform.ID) && match(selector.Version, platform.VersionID) &&
		match(selector.Architecture, platform.Architecture)
}

func match(expected, actual string) bool {
	return expected == "" || strings.EqualFold(expected, actual)
}

func cloneRecipe(item model.RemediationRecipe) model.RemediationRecipe {
	clone := item
	clone.Verification.Environments = append([]string(nil), item.Verification.Environments...)
	clone.Verification.EvidenceSHA256 = append([]string(nil), item.Verification.EvidenceSHA256...)
	clone.Operations = append([]model.FileMetadataRecipeEntry(nil), item.Operations...)
	for index := range clone.Operations {
		clone.Operations[index].AllowedOwners = append([]string(nil), item.Operations[index].AllowedOwners...)
	}
	return clone
}
