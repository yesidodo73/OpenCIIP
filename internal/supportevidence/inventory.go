package supportevidence

import (
	"fmt"
	"io/fs"
	"sort"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

// ValidateTestedEvidenceInventory verifies the repository evidence required
// when exact platform layers are promoted to tested scan support. A canonical
// manifest may remain scan-only or advance to verified remediation evidence;
// remediation manifests are validated against the supplied recipes. Callers
// may pass only the promotion set they are ready to enforce.
func ValidateTestedEvidenceInventory(
	layers []model.BindingLayer,
	recipes []model.RemediationRecipe,
	source fs.FS,
) error {
	tested := make([]model.BindingLayer, 0, len(layers))
	for _, layer := range layers {
		if layer.ScanSupport != nil && *layer.ScanSupport == model.ScanSupportTested {
			tested = append(tested, layer)
		}
	}
	sort.Slice(tested, func(i, j int) bool { return tested[i].ID < tested[j].ID })
	for _, layer := range tested {
		selector := layer.Selector
		if selector.OS != "" || selector.Family != "" || selector.VersionMajor != "" ||
			selector.ID == "" || selector.Version == "" || selector.Architecture == "" {
			return fmt.Errorf("tested platform %s must use only exact id, version, and architecture selectors", layer.ID)
		}
		path := fmt.Sprintf(
			"evidence/os-support/%s-%s-%s.json",
			selector.ID,
			selector.Version,
			selector.Architecture,
		)
		data, err := fs.ReadFile(source, path)
		if err != nil {
			return fmt.Errorf("read tested platform evidence %s: %w", path, err)
		}
		manifest, err := Parse(data)
		if err != nil {
			return fmt.Errorf("parse tested platform evidence %s: %w", path, err)
		}
		if err := ValidateRelativePath(path, manifest); err != nil {
			return err
		}
		var validationErr error
		if manifest.Remediation == nil {
			validationErr = ValidateScanPromotion(layer, &manifest)
		} else {
			if len(recipes) == 0 {
				return fmt.Errorf("validate tested platform %s: remediation evidence requires remediation recipes", layer.ID)
			}
			validationErr = ValidateVerifiedPromotion(layer, recipes, &manifest)
		}
		if validationErr != nil {
			return fmt.Errorf("validate tested platform %s: %w", layer.ID, validationErr)
		}
	}
	return nil
}
