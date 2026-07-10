//go:build linux

package report

import (
	"fmt"
	"os"
	"syscall"
)

func validateReportInputDirectorySecurity(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("디렉터리 소유권을 확인할 수 없습니다")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("디렉터리는 조치 실행 사용자 소유여야 합니다")
	}
	if uint32(stat.Mode)&0o7777 != 0o700 {
		return fmt.Errorf("디렉터리 권한은 정확히 0700이어야 합니다")
	}
	return nil
}

func validateReportInputFileSecurity(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("파일 소유권을 확인할 수 없습니다")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("파일은 조치 실행 사용자 소유여야 합니다")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("파일은 단일 링크 일반 파일이어야 합니다")
	}
	if uint32(stat.Mode)&0o7777 != 0o600 {
		return fmt.Errorf("파일 권한은 정확히 0600이어야 합니다")
	}
	return nil
}
