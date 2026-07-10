//go:build !linux

package journal

import (
	"os"
)

func openPrivateRegular(path string, flags int) (*os.File, error) {
	if err := validateRegularFile(path, 0o600); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flags, 0o600)
}
