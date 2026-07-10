//go:build linux

package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openStrictReportFile(root *os.Root, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.IndexByte(name, 0) >= 0 {
		return nil, fmt.Errorf("잘못된 보고서 파일 이름입니다")
	}

	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("보고서 루트 디렉터리를 열지 못했습니다: %w", err)
	}
	defer directory.Close()

	fd, err := syscall.Openat(
		int(directory.Fd()),
		name,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("열린 보고서 파일 descriptor를 사용할 수 없습니다")
	}
	return file, nil
}
