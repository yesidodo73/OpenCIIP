//go:build !linux

package journal

import "os"

func validateOwner(os.FileInfo) error {
	return nil
}
