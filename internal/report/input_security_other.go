//go:build !linux

package report

import "os"

func validateReportInputDirectorySecurity(os.FileInfo) error { return nil }
func validateReportInputFileSecurity(os.FileInfo) error      { return nil }
