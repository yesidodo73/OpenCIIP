package model

// ScanSupportLevel describes how broadly read-only checks can run on a platform.
type ScanSupportLevel string

const (
	ScanSupportUnsupported ScanSupportLevel = "unsupported"
	ScanSupportSupported   ScanSupportLevel = "supported"
	ScanSupportTested      ScanSupportLevel = "tested"
)

func (s ScanSupportLevel) Valid() bool {
	return s == ScanSupportUnsupported || s == ScanSupportSupported || s == ScanSupportTested
}

// RemediationSupportLevel is intentionally narrower than read-only scan support.
type RemediationSupportLevel string

const (
	RemediationSupportUnsupported RemediationSupportLevel = "unsupported"
	RemediationSupportTargeted    RemediationSupportLevel = "targeted"
	RemediationSupportVerified    RemediationSupportLevel = "verified"
)

func (s RemediationSupportLevel) Valid() bool {
	return s == RemediationSupportUnsupported || s == RemediationSupportTargeted || s == RemediationSupportVerified
}

type PlatformInfo struct {
	Hostname           string                  `json:"hostname"`
	OS                 string                  `json:"os"`
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	VersionID          string                  `json:"version_id"`
	Family             string                  `json:"family"`
	Architecture       string                  `json:"architecture"`
	KernelRelease      string                  `json:"kernel_release"`
	InitSystem         string                  `json:"init_system"`
	PackageManager     string                  `json:"package_manager"`
	Privilege          string                  `json:"privilege"`
	ScanSupport        ScanSupportLevel        `json:"scan_support"`
	RemediationSupport RemediationSupportLevel `json:"remediation_support"`
}

func SameRemediationPlatformIdentity(left, right PlatformInfo) bool {
	return left.OS == right.OS &&
		left.Family == right.Family &&
		left.ID == right.ID &&
		left.VersionID == right.VersionID &&
		left.Architecture == right.Architecture &&
		left.RemediationSupport == right.RemediationSupport
}
