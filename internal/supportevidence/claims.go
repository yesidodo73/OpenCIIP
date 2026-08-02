package supportevidence

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

// evidenceClaimsV1 is the stable contract referenced by recipe
// verification.evidence_sha256. Verification timestamps, stages, counts that
// describe a particular host state, and artifact provenance are deliberately
// excluded.
type evidenceClaimsV1 struct {
	SchemaVersion int                  `json:"schema_version"`
	Platform      Platform             `json:"platform"`
	Environment   string               `json:"environment"`
	Scan          scanClaimsV1         `json:"scan"`
	Remediation   *remediationClaimsV1 `json:"remediation,omitempty"`
}

type scanClaimsV1 struct {
	ReadOnly             bool `json:"read_only"`
	Complete             bool `json:"complete"`
	SystemStateUnchanged bool `json:"system_state_unchanged"`
	ResultCount          int  `json:"result_count"`
	UniqueRuleCount      int  `json:"unique_rule_count"`
	ErrorCount           int  `json:"error_count"`
}

type remediationClaimsV1 struct {
	Rules           []RemediationRuleEvidence `json:"rules"`
	Reboot          RebootEvidence            `json:"reboot"`
	CleanupVerified bool                      `json:"cleanup_verified"`
	Archives        []archiveClaimsV1         `json:"archives"`
}

type archiveClaimsV1 struct {
	Scenario string `json:"scenario"`
	Result   string `json:"result"`
}

func EvidenceBytes(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return marshalEvidenceClaims(claimsFromManifest(manifest))
}

func PrepareClaims(layer model.BindingLayer, environment string, includeRemediation bool) ([]byte, error) {
	if layer.ScanSupport == nil ||
		(*layer.ScanSupport != model.ScanSupportSupported && *layer.ScanSupport != model.ScanSupportTested) {
		return nil, fmt.Errorf("promotion claims require scan_support supported or tested")
	}
	if includeRemediation && *layer.ScanSupport != model.ScanSupportTested {
		return nil, fmt.Errorf("remediation promotion claims require scan_support tested")
	}
	if layer.Selector.OS != "" || layer.Selector.Family != "" ||
		layer.Selector.VersionMajor != "" ||
		layer.Selector.ID == "" || layer.Selector.Version == "" ||
		layer.Selector.Architecture == "" {
		return nil, fmt.Errorf("promotion claims require only exact id, version, and architecture selectors")
	}
	if !environmentPattern.MatchString(environment) || ipv4Pattern.MatchString(environment) {
		return nil, fmt.Errorf("promotion claims require one canonical public environment")
	}
	claims := evidenceClaimsV1{
		SchemaVersion: SchemaVersion,
		Platform: Platform{
			OS:           "linux",
			ID:           layer.Selector.ID,
			Version:      layer.Selector.Version,
			Architecture: layer.Selector.Architecture,
		},
		Environment: environment,
		Scan: scanClaimsV1{
			ReadOnly:             true,
			Complete:             true,
			SystemStateUnchanged: true,
			ResultCount:          67,
			UniqueRuleCount:      67,
			ErrorCount:           0,
		},
	}
	if includeRemediation {
		if layer.PlatformVerification == nil ||
			(layer.PlatformVerification.State != model.VerificationPending &&
				layer.PlatformVerification.State != model.VerificationVerified) ||
			len(layer.PlatformVerification.Environments) != 1 ||
			layer.PlatformVerification.Environments[0] != claims.Environment {
			return nil, fmt.Errorf("remediation promotion claims require one matching pending or verified platform environment")
		}
		required := map[string]bool{"U-19": false, "U-22": false, "U-29": false}
		for _, binding := range layer.Bindings {
			if _, expected := required[binding.RuleID]; !expected {
				continue
			}
			if binding.Verification == nil ||
				(binding.Verification.State != model.VerificationPending &&
					binding.Verification.State != model.VerificationVerified) ||
				len(binding.Verification.Environments) != 1 ||
				binding.Verification.Environments[0] != claims.Environment {
				return nil, fmt.Errorf("%s pending or verified environment does not match the platform claim", binding.RuleID)
			}
			required[binding.RuleID] = true
		}
		remediation := remediationClaimsV1{
			Reboot: RebootEvidence{
				Performed:        true,
				BootIDChanged:    true,
				RollbackVerified: true,
			},
			CleanupVerified: true,
			Archives: []archiveClaimsV1{
				{Scenario: "item_then_run_rollback", Result: "PASS"},
				{Scenario: "reboot_then_run_rollback", Result: "PASS"},
			},
		}
		for _, ruleID := range []string{"U-19", "U-22", "U-29"} {
			if !required[ruleID] {
				return nil, fmt.Errorf("promotion claims have no matching %s verification", ruleID)
			}
			remediation.Rules = append(remediation.Rules, RemediationRuleEvidence{
				RuleID:               ruleID,
				ApplyVerified:        true,
				RecheckStatus:        "PASS",
				ItemRollbackVerified: true,
				RunRollbackVerified:  true,
			})
		}
		claims.Remediation = &remediation
	}
	return marshalEvidenceClaims(claims)
}

func claimsFromManifest(manifest Manifest) evidenceClaimsV1 {
	claims := evidenceClaimsV1{
		SchemaVersion: manifest.SchemaVersion,
		Platform:      manifest.Platform,
		Environment:   manifest.Environment,
		Scan: scanClaimsV1{
			ReadOnly:             manifest.Scan.ReadOnly,
			Complete:             manifest.Scan.Complete,
			SystemStateUnchanged: manifest.Scan.SystemStateUnchanged,
			ResultCount:          manifest.Scan.ResultCount,
			UniqueRuleCount:      manifest.Scan.UniqueRuleCount,
			ErrorCount:           manifest.Scan.ErrorCount,
		},
	}
	if manifest.Remediation != nil {
		remediation := remediationClaimsV1{
			Rules:           append([]RemediationRuleEvidence(nil), manifest.Remediation.Rules...),
			Reboot:          manifest.Remediation.Reboot,
			CleanupVerified: manifest.Remediation.CleanupVerified,
			Archives:        make([]archiveClaimsV1, 0, len(manifest.Remediation.Archives)),
		}
		sort.Slice(remediation.Rules, func(i, j int) bool {
			return remediation.Rules[i].RuleID < remediation.Rules[j].RuleID
		})
		for _, archive := range manifest.Remediation.Archives {
			remediation.Archives = append(remediation.Archives, archiveClaimsV1{
				Scenario: archive.Scenario,
				Result:   archive.Result,
			})
		}
		sort.Slice(remediation.Archives, func(i, j int) bool {
			return remediation.Archives[i].Scenario < remediation.Archives[j].Scenario
		})
		claims.Remediation = &remediation
	}
	return claims
}

func marshalEvidenceClaims(claims evidenceClaimsV1) ([]byte, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encode canonical OS support evidence claims: %w", err)
	}
	return append(data, '\n'), nil
}
