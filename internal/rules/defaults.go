package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	ruledata "github.com/yesidodo73/OpenCIIP/rules"
)

var defaultCoreDataFiles = []string{
	"2026/unix/catalog.yaml",
	"profiles/2026-unix.yaml",
}

type Bundle struct {
	Catalog  model.Catalog
	Profiles model.ProfileSet
	Layers   []model.BindingLayer
	Version  string
}

func LoadDefaults() (Bundle, error) {
	loader := NewLoader(ruledata.FS)
	catalog, err := loader.LoadCatalog(defaultCoreDataFiles[0])
	if err != nil {
		return Bundle{}, err
	}
	for index := range catalog.Rules {
		catalog.Rules[index].Reference.Guide = catalog.Guide.Title
		catalog.Rules[index].Reference.Item = catalog.Rules[index].ID
	}
	if err := validateDefaultUnixCatalog(catalog); err != nil {
		return Bundle{}, err
	}
	profiles, err := loader.LoadProfiles(defaultCoreDataFiles[1], catalog)
	if err != nil {
		return Bundle{}, err
	}
	platformFiles, err := discoverDefaultPlatformFiles(ruledata.FS)
	if err != nil {
		return Bundle{}, err
	}
	layers := make([]model.BindingLayer, 0, len(platformFiles))
	for _, path := range platformFiles {
		layer, loadErr := loader.LoadBinding(path)
		if loadErr != nil {
			return Bundle{}, loadErr
		}
		layers = append(layers, layer)
	}
	if err := validateRemediationSelectorSet(layers); err != nil {
		return Bundle{}, fmt.Errorf("validate embedded remediation selectors: %w", err)
	}
	sort.SliceStable(layers, func(i, j int) bool {
		if layers[i].Priority == layers[j].Priority {
			return layers[i].ID < layers[j].ID
		}
		return layers[i].Priority < layers[j].Priority
	})
	dataFiles := append(append([]string(nil), defaultCoreDataFiles...), platformFiles...)
	version, err := dataVersion(ruledata.FS, dataFiles)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Catalog:  catalog,
		Profiles: profiles,
		Layers:   layers,
		Version:  version,
	}, nil
}

func discoverDefaultPlatformFiles(source fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(source, "platforms")
	if err != nil {
		return nil, fmt.Errorf("read embedded platform bindings: %w", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		paths = append(paths, "platforms/"+entry.Name())
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no embedded platform bindings were found")
	}
	sort.Strings(paths)
	return paths, nil
}

func (b Bundle) Resolve(platform model.PlatformInfo) ([]model.ResolvedRule, error) {
	return Resolve(b.Catalog, b.Layers, platform)
}

func (b Bundle) EvaluatorIDs() []string {
	ids := make(map[string]struct{})
	for _, rule := range b.Catalog.Rules {
		if rule.Evaluator != "" {
			ids[rule.Evaluator] = struct{}{}
		}
	}
	for _, layer := range b.Layers {
		for _, binding := range layer.Bindings {
			if binding.Evaluator != nil && *binding.Evaluator != "" {
				ids[*binding.Evaluator] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func validateDefaultUnixCatalog(catalog model.Catalog) error {
	if catalog.Guide.Year != 2026 || catalog.Guide.Domain != "Unix 서버" {
		return fmt.Errorf("embedded catalog must describe the 2026 Unix server guide")
	}
	if len(catalog.Rules) != 67 {
		return fmt.Errorf("embedded 2026 Unix catalog contains %d rules; expected 67", len(catalog.Rules))
	}
	seen := make(map[string]struct{}, len(catalog.Rules))
	for _, rule := range catalog.Rules {
		seen[rule.ID] = struct{}{}
	}
	for index := 1; index <= 67; index++ {
		id := fmt.Sprintf("U-%02d", index)
		if _, exists := seen[id]; !exists {
			return fmt.Errorf("embedded 2026 Unix catalog is missing %s", id)
		}
	}
	return nil
}

func dataVersion(source fs.FS, paths []string) (string, error) {
	sortedPaths := append([]string(nil), paths...)
	sort.Strings(sortedPaths)
	hash := sha256.New()
	for _, path := range sortedPaths {
		data, err := fs.ReadFile(source, path)
		if err != nil {
			return "", fmt.Errorf("hash embedded rule data %s: %w", path, err)
		}
		_, _ = hash.Write([]byte(path))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
