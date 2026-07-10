package exitcode

import "github.com/yesidodo73/OpenCIIP/internal/model"

const (
	OK      = 0
	Failed  = 1
	Unknown = 2
	Error   = 3
	Usage   = 4
)

// ForResults returns the stable public process status for a completed scan.
// ERROR takes precedence over FAIL, and FAIL takes precedence over UNKNOWN.
func ForResults(results []model.CheckResult) int {
	hasFail := false
	hasUnknown := false
	for _, result := range results {
		switch result.Status {
		case model.StatusError:
			return Error
		case model.StatusFail:
			hasFail = true
		case model.StatusUnknown:
			hasUnknown = true
		}
	}
	if hasFail {
		return Failed
	}
	if hasUnknown {
		return Unknown
	}
	return OK
}
