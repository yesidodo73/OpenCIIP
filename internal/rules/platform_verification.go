package rules

import (
	"fmt"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const unmatchedPlatformVerificationWarning = "일치하는 정확한 플랫폼 검증 정보가 없어 지원 상태를 확정할 수 없습니다."

// ResolvePlatformSupport derives support solely from the highest-precedence
// matching exact-platform verification declaration. Layers are ordered by
// ascending priority and then ID, using the same deterministic order as rule
// binding resolution; the last matching declaration wins.
func (b Bundle) ResolvePlatformSupport(platform model.PlatformInfo) (model.PlatformInfo, error) {
	resolved := platform
	resolved.Support = model.SupportUnsupported
	resolved.VerificationWarning = unmatchedPlatformVerificationWarning

	for _, layer := range b.Layers {
		if layer.PlatformVerification == nil {
			continue
		}
		if err := validateBindingLayer(layer); err != nil {
			return model.PlatformInfo{}, fmt.Errorf("validate platform verification layer %s: %w", layer.ID, err)
		}
	}

	matching, err := matchingLayers(b.Layers, platform)
	if err != nil {
		return model.PlatformInfo{}, err
	}
	var selected *model.Verification
	for index := range matching {
		if matching[index].PlatformVerification != nil {
			selected = matching[index].PlatformVerification
		}
	}
	if selected == nil {
		return resolved, nil
	}

	description := platformVerificationDescription(platform, *selected)
	switch selected.State {
	case model.VerificationPending:
		resolved.Support = model.SupportTargeted
		resolved.VerificationWarning = description + " 플랫폼 검증이 아직 완료되지 않았습니다."
	case model.VerificationVerified:
		resolved.Support = model.SupportVerified
		resolved.VerificationWarning = ""
	case model.VerificationRejected:
		resolved.Support = model.SupportUnsupported
		resolved.VerificationWarning = description + " 플랫폼 검증 결과 지원 대상에서 제외되었습니다."
	default:
		return model.PlatformInfo{}, fmt.Errorf("platform verification layer resolved to invalid state %q", selected.State)
	}
	return resolved, nil
}

func platformVerificationDescription(platform model.PlatformInfo, verification model.Verification) string {
	if len(verification.Environments) > 0 {
		return strings.Join(verification.Environments, ", ")
	}
	if name := strings.TrimSpace(platform.Name); name != "" {
		return name
	}
	if id := strings.TrimSpace(platform.ID); id != "" {
		if version := strings.TrimSpace(platform.VersionID); version != "" {
			return id + " " + version
		}
		return id
	}
	if operatingSystem := strings.TrimSpace(platform.OS); operatingSystem != "" {
		return operatingSystem
	}
	return "현재"
}
