package rules

import (
	"fmt"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

// ResolvePlatformSupport keeps read-only scan compatibility separate from the
// exact platform verification required by remediation.
func (b Bundle) ResolvePlatformSupport(platform model.PlatformInfo) (model.PlatformInfo, error) {
	resolved := platform
	resolved.ScanSupport = model.ScanSupportUnsupported
	resolved.RemediationSupport = model.RemediationSupportUnsupported

	for _, layer := range b.Layers {
		if err := validateBindingLayer(layer); err != nil {
			return model.PlatformInfo{}, fmt.Errorf("validate platform support layer %s: %w", layer.ID, err)
		}
	}

	matching, err := matchingLayers(b.Layers, platform)
	if err != nil {
		return model.PlatformInfo{}, err
	}
	var remediationVerification *model.Verification
	for index := range matching {
		layer := matching[index]
		if layer.ScanSupport != nil {
			resolved.ScanSupport = *layer.ScanSupport
		}
		if layer.PlatformVerification != nil {
			remediationVerification = layer.PlatformVerification
		}
	}
	if remediationVerification == nil {
		return resolved, nil
	}

	switch remediationVerification.State {
	case model.VerificationPending:
		resolved.RemediationSupport = model.RemediationSupportTargeted
	case model.VerificationVerified:
		resolved.RemediationSupport = model.RemediationSupportVerified
	case model.VerificationRejected:
		resolved.RemediationSupport = model.RemediationSupportUnsupported
	default:
		return model.PlatformInfo{}, fmt.Errorf("platform verification layer resolved to invalid state %q", remediationVerification.State)
	}
	return resolved, nil
}
