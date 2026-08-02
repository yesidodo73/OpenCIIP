//go:build !linux

package system

import (
	"os"
	"time"
)

func statFields(_ os.FileInfo) (uid, gid int, device, inode uint64) {
	return -1, -1, 0, 0
}

func samePlatformSnapshot(_, _ os.FileInfo) bool { return true }

func platformChangeTime(_ os.FileInfo) time.Time { return time.Time{} }
