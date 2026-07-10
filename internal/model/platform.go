package model

// SupportLevel distinguishes implementation targets from verified support.
type SupportLevel string

const (
	SupportUnsupported SupportLevel = "unsupported"
	SupportTargeted    SupportLevel = "targeted"
	SupportVerified    SupportLevel = "verified"
)

func (s SupportLevel) Valid() bool {
	return s == SupportUnsupported || s == SupportTargeted || s == SupportVerified
}

type PlatformInfo struct {
	Hostname            string       `json:"hostname"`
	OS                  string       `json:"os"`
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	VersionID           string       `json:"version_id"`
	Family              string       `json:"family"`
	Architecture        string       `json:"architecture"`
	KernelRelease       string       `json:"kernel_release"`
	InitSystem          string       `json:"init_system"`
	PackageManager      string       `json:"package_manager"`
	Privilege           string       `json:"privilege"`
	Support             SupportLevel `json:"support"`
	VerificationWarning string       `json:"verification_warning,omitempty"`
}

func SameRemediationPlatformIdentity(left, right PlatformInfo) bool {
	return left.OS == right.OS &&
		left.Family == right.Family &&
		left.ID == right.ID &&
		left.VersionID == right.VersionID &&
		left.Architecture == right.Architecture &&
		left.Support == right.Support
}
