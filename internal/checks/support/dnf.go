package support

import (
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
)

const dnfCacheUnavailableMessage = "Cache-only enabled but no cache for "

// DNFCacheUnavailable reports the narrow offline-cache failure emitted by DNF.
// Other command failures, timeouts, and truncated output remain execution errors.
func DNFCacheUnavailable(result executor.Result) bool {
	return result.ExitCode != 0 &&
		!result.TimedOut &&
		!result.Truncated &&
		strings.Contains(string(result.Stderr), dnfCacheUnavailableMessage)
}
