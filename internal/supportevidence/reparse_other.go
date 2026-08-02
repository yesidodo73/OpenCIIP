//go:build !windows

package supportevidence

import "os"

func isReparsePoint(os.FileInfo) bool {
	return false
}
