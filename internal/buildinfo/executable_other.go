//go:build !linux

package buildinfo

import (
	"fmt"
	"os"
	"path/filepath"
)

func runningExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate remediation executable: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve remediation executable: %w", err)
	}
	return path, nil
}
