//go:build !linux

package executor

import (
	"os"
	"os/exec"
)

func configureCommand(command *exec.Cmd) {
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return command.Process.Kill()
	}
}

func trustedExecutable(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 && info.Mode().Perm()&0o022 == 0
}

func trustedDirectory(info os.FileInfo) bool {
	return info.IsDir() && info.Mode().Perm()&0o022 == 0
}
