//go:build !linux

package report

import "os"

func openStrictReportFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY, 0)
}
