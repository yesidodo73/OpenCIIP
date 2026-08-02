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
		return "", fmt.Errorf("locate OpenCIIP executable: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve OpenCIIP executable: %w", err)
	}
	return path, nil
}
