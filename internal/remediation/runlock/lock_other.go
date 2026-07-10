//go:build !linux

package runlock

import (
	"context"
	"fmt"
)

func acquirePlatform(context.Context, string, string, bool) (func() error, error) {
	return nil, &Error{Code: CodeUnsupportedPlatform, Err: fmt.Errorf("global remediation locking is currently verified only on Linux")}
}
