//go:build linux

package journal

import (
	"fmt"
	"os"
	"syscall"
)

func validateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read file ownership")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("path owner uid %d does not match effective uid %d", stat.Uid, os.Geteuid())
	}
	return nil
}
