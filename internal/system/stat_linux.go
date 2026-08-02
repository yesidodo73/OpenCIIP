//go:build linux

package system

import (
	"os"
	"syscall"
	"time"
)

func statFields(info os.FileInfo) (uid, gid int, device, inode uint64) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, 0, 0
	}
	return int(stat.Uid), int(stat.Gid), uint64(stat.Dev), stat.Ino
}

func samePlatformSnapshot(left, right os.FileInfo) bool {
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK {
		return false
	}
	return leftStat.Ctim == rightStat.Ctim && leftStat.Nlink == rightStat.Nlink && leftStat.Rdev == rightStat.Rdev
}

func platformChangeTime(info os.FileInfo) time.Time {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}
	}
	return time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)).UTC()
}
