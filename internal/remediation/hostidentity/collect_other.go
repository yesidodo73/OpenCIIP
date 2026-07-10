//go:build !linux

package hostidentity

import (
	"context"
	"fmt"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func collectPlatform(context.Context, string) (model.HostIdentity, error) {
	return model.HostIdentity{}, &Error{Code: CodeUnsupported, Err: fmt.Errorf("host identity collection is currently verified only on Linux")}
}
