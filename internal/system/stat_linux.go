//go:build linux

package system

import (
	"os"
	"syscall"
)

func statFields(info os.FileInfo) (uid, gid int, device, inode uint64) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, 0, 0
	}
	return int(stat.Uid), int(stat.Gid), uint64(stat.Dev), stat.Ino
}
