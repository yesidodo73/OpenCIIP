//go:build !linux

package report

import (
	"fmt"
	"os"
)

func validateReportDirectoryAccess(_ string, _ os.FileInfo) error {
	return nil
}

func validatePrivateReportDirectory(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("report directory must be a real directory: %s", path)
	}
	return nil
}

func validateReportDirectoryPath(_ string) error {
	return nil
}
