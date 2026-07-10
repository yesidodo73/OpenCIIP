//go:build linux

package hostidentity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const identityFileLimit = 4096

func collectPlatform(ctx context.Context, systemRoot string) (model.HostIdentity, error) {
	rootInfo, err := os.Lstat(systemRoot)
	if err != nil {
		return model.HostIdentity{}, &Error{Code: CodeInvalidSystemRoot, Path: systemRoot, Err: err}
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return model.HostIdentity{}, &Error{Code: CodeUnsafeSystemRoot, Path: systemRoot, Err: fmt.Errorf("system root must be a real directory")}
	}
	resolved, err := filepath.EvalSymlinks(systemRoot)
	if err != nil {
		return model.HostIdentity{}, &Error{Code: CodeUnsafeSystemRoot, Path: systemRoot, Err: err}
	}
	if filepath.Clean(resolved) != systemRoot {
		return model.HostIdentity{}, &Error{Code: CodeUnsafeSystemRoot, Path: systemRoot, Err: fmt.Errorf("system root contains a symbolic link")}
	}

	rootFD, err := syscall.Open(systemRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return model.HostIdentity{}, &Error{Code: CodeUnsafeSystemRoot, Path: systemRoot, Err: err}
	}
	defer syscall.Close(rootFD)
	var rootStat syscall.Stat_t
	if err := syscall.Fstat(rootFD, &rootStat); err != nil {
		return model.HostIdentity{}, &Error{Code: CodeUnsafeSystemRoot, Path: systemRoot, Err: err}
	}
	if rootStat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return model.HostIdentity{}, &Error{Code: CodeUnsafeSystemRoot, Path: systemRoot, Err: fmt.Errorf("opened system root is not a directory")}
	}

	machineID, err := readMachineID(ctx, rootFD)
	if err != nil {
		return model.HostIdentity{}, err
	}
	bootID, err := readBootID(ctx)
	if err != nil {
		return model.HostIdentity{}, err
	}
	machineDigest := sha256.Sum256([]byte(machineID))
	identity := model.HostIdentity{
		MachineIDHash: hex.EncodeToString(machineDigest[:]),
		SystemRoot:    systemRoot,
		RootDevice:    uint64(rootStat.Dev),
		RootInode:     rootStat.Ino,
		BootID:        bootID,
	}
	if err := identity.Validate(); err != nil {
		return model.HostIdentity{}, &Error{Code: CodeHostMismatch, Field: "collected", Err: err}
	}
	return identity, nil
}

func readMachineID(ctx context.Context, rootFD int) (string, error) {
	type candidate struct {
		path       string
		components []string
		value      string
		present    bool
	}
	candidates := []candidate{
		{path: "/etc/machine-id", components: []string{"etc", "machine-id"}},
		{path: "/var/lib/dbus/machine-id", components: []string{"var", "lib", "dbus", "machine-id"}},
	}
	for index := range candidates {
		data, err := readRegularAt(ctx, rootFD, candidates[index].components)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if index == 1 && candidates[0].present && errors.Is(err, syscall.ELOOP) {
			continue
		}
		if err != nil {
			return "", &Error{Code: CodeMachineIDInvalid, Path: candidates[index].path, Err: err}
		}
		value, err := normalizeMachineID(data)
		if err != nil {
			return "", &Error{Code: CodeMachineIDInvalid, Path: candidates[index].path, Err: err}
		}
		candidates[index].value = value
		candidates[index].present = true
	}
	if !candidates[0].present && !candidates[1].present {
		return "", &Error{Code: CodeMachineIDMissing, Err: fmt.Errorf("neither machine-id location exists")}
	}
	if candidates[0].present && candidates[1].present && candidates[0].value != candidates[1].value {
		return "", &Error{Code: CodeMachineIDAmbiguous, Err: fmt.Errorf("machine-id locations disagree")}
	}
	if candidates[0].present {
		return candidates[0].value, nil
	}
	return candidates[1].value, nil
}

func readBootID(ctx context.Context) (string, error) {
	hostRootFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", &Error{Code: CodeBootIDMissing, Path: "/proc/sys/kernel/random/boot_id", Err: err}
	}
	defer syscall.Close(hostRootFD)
	data, err := readRegularAt(ctx, hostRootFD, []string{"proc", "sys", "kernel", "random", "boot_id"})
	if err != nil {
		return "", &Error{Code: CodeBootIDMissing, Path: "/proc/sys/kernel/random/boot_id", Err: err}
	}
	value := strings.ToLower(strings.TrimSpace(string(data)))
	if !validUUID(value) {
		return "", &Error{Code: CodeBootIDInvalid, Path: "/proc/sys/kernel/random/boot_id", Err: fmt.Errorf("boot ID is not a UUID")}
	}
	return value, nil
}

func readRegularAt(ctx context.Context, rootFD int, components []string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, syscall.EINVAL
	}
	currentFD, err := syscall.Dup(rootFD)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(currentFD)
	defer func() {
		if currentFD >= 0 {
			_ = syscall.Close(currentFD)
		}
	}()
	for _, component := range components[:len(components)-1] {
		if component == "" || component == "." || component == ".." || strings.IndexByte(component, 0) >= 0 {
			return nil, syscall.EINVAL
		}
		nextFD, openErr := syscall.Openat(currentFD, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, openErr
		}
		_ = syscall.Close(currentFD)
		currentFD = nextFD
	}
	name := components[len(components)-1]
	if name == "" || name == "." || name == ".." || strings.IndexByte(name, 0) >= 0 {
		return nil, syscall.EINVAL
	}
	fd, err := syscall.Openat(currentFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create identity file handle")
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Size < 0 || before.Size > identityFileLimit {
		return nil, fmt.Errorf("identity source is not a bounded regular file")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, identityFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > identityFileLimit {
		return nil, fmt.Errorf("identity source exceeds safe limit")
	}
	if before.Size > 0 && int64(len(data)) != before.Size {
		return nil, fmt.Errorf("identity source size changed while reading")
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if !sameStableFile(before, after) {
		return nil, fmt.Errorf("identity source changed while reading")
	}
	return data, nil
}

func sameStableFile(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func normalizeMachineID(data []byte) (string, error) {
	value := strings.ToLower(strings.TrimSpace(string(data)))
	if len(value) != 32 {
		return "", fmt.Errorf("machine ID must contain 32 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return "", fmt.Errorf("machine ID must contain 32 hexadecimal characters")
	}
	return value, nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
