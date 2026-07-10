//go:build linux

package regularfile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"golang.org/x/sys/unix"
)

func newPlatform(systemRoot, runDirectory string, configuration config) (*Handler, error) {
	root, rootStat, err := validateDirectory(systemRoot, false)
	if err != nil {
		return nil, &Error{Code: CodeUnsafePath, Operation: "initialize", Path: systemRoot, Err: err}
	}
	run, runStat, err := validateDirectory(runDirectory, true)
	if err != nil {
		return nil, &Error{Code: CodeUnsafePath, Operation: "initialize", Path: runDirectory, Err: err}
	}
	selinuxActive, err := detectSELinux()
	if err != nil {
		return nil, &Error{Code: CodeSELinuxUnknown, Operation: "initialize", Path: "/sys/fs/selinux/enforce", Err: err}
	}
	return &Handler{
		systemRoot:    root,
		runDirectory:  run,
		maxFileSize:   configuration.maxFileSize,
		rootDevice:    uint64(rootStat.Dev),
		rootInode:     rootStat.Ino,
		runDevice:     uint64(runStat.Dev),
		runInode:      runStat.Ino,
		selinuxActive: selinuxActive,
	}, nil
}

func validateDirectory(value string, private bool) (string, syscall.Stat_t, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", syscall.Stat_t{}, err
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", syscall.Stat_t{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", syscall.Stat_t{}, fmt.Errorf("path must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", syscall.Stat_t{}, err
	}
	if filepath.Clean(resolved) != absolute {
		return "", syscall.Stat_t{}, fmt.Errorf("directory path contains a symbolic link")
	}
	fd, err := syscall.Open(absolute, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", syscall.Stat_t{}, err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return "", syscall.Stat_t{}, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return "", syscall.Stat_t{}, fmt.Errorf("opened path is not a directory")
	}
	if private {
		if uint32(stat.Mode)&0o7777 != 0o700 {
			return "", syscall.Stat_t{}, fmt.Errorf("run directory permissions must be 0700")
		}
		if stat.Uid != uint32(os.Geteuid()) {
			return "", syscall.Stat_t{}, fmt.Errorf("run directory owner does not match effective user")
		}
	}
	return absolute, stat, nil
}

func detectSELinux() (bool, error) {
	fd, err := syscall.Open("/sys/fs/selinux/enforce", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), "/sys/fs/selinux/enforce")
	if file == nil {
		_ = syscall.Close(fd)
		return false, fmt.Errorf("create SELinux state handle")
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return false, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Size < 0 {
		return false, fmt.Errorf("SELinux state is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 17))
	if err != nil {
		return false, err
	}
	if len(data) > 16 {
		return false, fmt.Errorf("SELinux state exceeds safe limit")
	}
	value := strings.TrimSpace(string(data))
	if value != "0" && value != "1" {
		return false, fmt.Errorf("unexpected SELinux state")
	}
	return true, nil
}

func (h *Handler) normalizePlatform(ctx context.Context, ref model.ResourceRef) (model.CanonicalResource, error) {
	if h == nil {
		return model.CanonicalResource{}, &Error{Code: CodeInvalidInput, Operation: "normalize", Err: fmt.Errorf("handler is nil")}
	}
	if err := ctx.Err(); err != nil {
		return model.CanonicalResource{}, err
	}
	if err := ref.Validate(); err != nil || ref.Kind != model.ResourceFile {
		if err == nil {
			err = fmt.Errorf("resource kind must be file")
		}
		return model.CanonicalResource{}, &Error{Code: CodeInvalidInput, Operation: "normalize", Path: ref.ID, Err: err}
	}
	target, err := h.cleanTarget(ref.ID)
	if err != nil {
		return model.CanonicalResource{}, err
	}
	temporary := model.CanonicalResource{
		Reference: model.ResourceRef{Kind: model.ResourceFile, ID: target},
		Key:       "file:" + target,
	}
	captured, _, err := h.captureCurrent(ctx, temporary)
	if err != nil {
		return model.CanonicalResource{}, err
	}
	temporary.AliasKeys = []string{fmt.Sprintf("inode:%d:%d", captured.File.Device, captured.File.Inode)}
	return temporary, nil
}

func (h *Handler) cleanTarget(value string) (string, error) {
	if strings.TrimSpace(value) == "" || strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) {
		return "", &Error{Code: CodeUnsafePath, Operation: "validate target", Path: value, Err: fmt.Errorf("target must be an absolute path without NUL bytes")}
	}
	target := filepath.Clean(value)
	if target == string(filepath.Separator) {
		return "", &Error{Code: CodeUnsupportedFileType, Operation: "validate target", Path: value, Err: fmt.Errorf("system root cannot be a regular-file target")}
	}
	physical := filepath.Join(h.systemRoot, strings.TrimPrefix(target, string(filepath.Separator)))
	if withinDirectory(h.runDirectory, physical) {
		return "", &Error{Code: CodeUnsafePath, Operation: "validate target", Path: target, Err: fmt.Errorf("target is inside the remediation run directory")}
	}
	return target, nil
}

func withinDirectory(directory, candidate string) bool {
	relative, err := filepath.Rel(directory, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func (h *Handler) validateResource(resource model.CanonicalResource, operation string) (string, error) {
	if err := resource.Validate(); err != nil {
		return "", &Error{Code: CodeInvalidInput, Operation: operation, Err: err}
	}
	if resource.Reference.Kind != model.ResourceFile {
		return "", &Error{Code: CodeInvalidInput, Operation: operation, Path: resource.Reference.ID, Err: fmt.Errorf("resource kind must be file")}
	}
	target, err := h.cleanTarget(resource.Reference.ID)
	if err != nil {
		return "", err
	}
	if resource.Reference.ID != target || resource.Key != "file:"+target {
		return "", &Error{Code: CodeInvalidInput, Operation: operation, Path: resource.Reference.ID, Err: fmt.Errorf("resource is not in canonical form")}
	}
	return target, nil
}

func targetComponents(target string) ([]string, error) {
	trimmed := strings.TrimPrefix(target, string(filepath.Separator))
	components := strings.Split(trimmed, string(filepath.Separator))
	if len(components) == 0 {
		return nil, fmt.Errorf("target has no path components")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.IndexByte(component, 0) >= 0 {
			return nil, fmt.Errorf("target contains an unsafe path component")
		}
	}
	return components, nil
}

func (h *Handler) openRoot() (int, error) {
	fd, err := syscall.Open(h.systemRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || uint64(stat.Dev) != h.rootDevice || stat.Ino != h.rootInode {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("system root identity changed")
	}
	return fd, nil
}

func (h *Handler) openRunRoot() (int, error) {
	fd, err := syscall.Open(h.runDirectory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || uint64(stat.Dev) != h.runDevice || stat.Ino != h.runInode || stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode)&0o7777 != 0o700 {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("run directory identity or protection changed")
	}
	return fd, nil
}

func (h *Handler) openParent(target string) (int, string, syscall.Stat_t, error) {
	components, err := targetComponents(target)
	if err != nil {
		return -1, "", syscall.Stat_t{}, err
	}
	currentFD, err := h.openRoot()
	if err != nil {
		return -1, "", syscall.Stat_t{}, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := syscall.Openat(currentFD, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			_ = syscall.Close(currentFD)
			return -1, "", syscall.Stat_t{}, openErr
		}
		_ = syscall.Close(currentFD)
		currentFD = nextFD
	}
	var parentStat syscall.Stat_t
	if err := syscall.Fstat(currentFD, &parentStat); err != nil {
		_ = syscall.Close(currentFD)
		return -1, "", syscall.Stat_t{}, err
	}
	if parentStat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(currentFD)
		return -1, "", syscall.Stat_t{}, fmt.Errorf("target parent is not a directory")
	}
	return currentFD, components[len(components)-1], parentStat, nil
}

type openedTarget struct {
	file       *os.File
	fd         int
	parentFD   int
	name       string
	stat       syscall.Stat_t
	parentStat syscall.Stat_t
}

func (o *openedTarget) close() {
	if o == nil {
		return
	}
	if o.file != nil {
		_ = o.file.Close()
		o.fd = -1
	} else if o.fd >= 0 {
		_ = syscall.Close(o.fd)
		o.fd = -1
	}
	if o.parentFD >= 0 {
		_ = syscall.Close(o.parentFD)
		o.parentFD = -1
	}
}

func (h *Handler) openCurrent(target, operation string) (*openedTarget, error) {
	return h.openCurrentWithFlags(target, operation, syscall.O_RDONLY)
}

func (h *Handler) openCurrentWritable(target, operation string) (*openedTarget, error) {
	return h.openCurrentWithFlags(target, operation, syscall.O_RDWR)
}

func (h *Handler) openCurrentWithFlags(target, operation string, accessFlags int) (*openedTarget, error) {
	parentFD, name, parentStat, err := h.openParent(target)
	if err != nil {
		return nil, classifyTargetError(operation, target, err)
	}
	before, err := statTargetAt(parentFD, name)
	if err != nil {
		_ = syscall.Close(parentFD)
		return nil, classifyTargetError(operation, target, err)
	}
	if before.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		_ = syscall.Close(parentFD)
		return nil, &Error{Code: CodeSymlinkNotAllowed, Operation: operation, Path: target, Err: fmt.Errorf("symbolic links are not regular-file targets")}
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = syscall.Close(parentFD)
		return nil, &Error{Code: CodeUnsupportedFileType, Operation: operation, Path: target, Err: fmt.Errorf("target is not a regular file")}
	}
	fd, err := syscall.Openat(parentFD, name, accessFlags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = syscall.Close(parentFD)
		return nil, classifyTargetError(operation, target, err)
	}
	file := os.NewFile(uintptr(fd), target)
	if file == nil {
		_ = syscall.Close(fd)
		_ = syscall.Close(parentFD)
		return nil, &Error{Code: CodeUnsafePath, Operation: operation, Path: target, Err: fmt.Errorf("create target file handle")}
	}
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil {
		_ = file.Close()
		_ = syscall.Close(parentFD)
		return nil, &Error{Code: CodeUnsafePath, Operation: operation, Path: target, Err: err}
	}
	if opened.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Dev != opened.Dev || before.Ino != opened.Ino {
		_ = file.Close()
		_ = syscall.Close(parentFD)
		return nil, &Error{Code: CodeFileChanged, Operation: operation, Path: target, Err: fmt.Errorf("target changed while it was opened")}
	}
	openedTarget := &openedTarget{file: file, fd: fd, parentFD: parentFD, name: name, stat: opened, parentStat: parentStat}
	if err := h.validateOpenedPathIdentity(openedTarget, operation, target); err != nil {
		openedTarget.close()
		return nil, err
	}
	return openedTarget, nil
}

func statTargetAt(parentFD int, name string) (syscall.Stat_t, error) {
	fd, err := syscall.Openat(parentFD, name, unix.O_PATH|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return syscall.Stat_t{}, err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return syscall.Stat_t{}, err
	}
	return stat, nil
}

func (h *Handler) validateOpenedPathIdentity(o *openedTarget, operation, target string) error {
	if h == nil {
		return &Error{Code: CodeInvalidInput, Operation: operation, Path: target, Err: fmt.Errorf("handler is nil")}
	}
	if o == nil || o.fd < 0 || o.parentFD < 0 || o.name == "" {
		return &Error{Code: CodeUnsafePath, Operation: operation, Path: target, Err: fmt.Errorf("opened target handles are incomplete")}
	}
	var parent syscall.Stat_t
	if err := syscall.Fstat(o.parentFD, &parent); err != nil {
		return &Error{Code: CodeUnsafePath, Operation: operation, Path: target, Err: err}
	}
	if parent.Mode&syscall.S_IFMT != syscall.S_IFDIR || parent.Dev != o.parentStat.Dev || parent.Ino != o.parentStat.Ino {
		return &Error{Code: CodeFileChanged, Operation: operation, Path: target, Err: fmt.Errorf("target parent identity changed")}
	}
	freshParentFD, freshName, freshParent, err := h.openParent(target)
	if err != nil {
		return &Error{Code: CodeFileChanged, Operation: operation, Path: target, Err: fmt.Errorf("reopen target parent: %w", err)}
	}
	defer syscall.Close(freshParentFD)
	if freshName != o.name || freshParent.Mode&syscall.S_IFMT != syscall.S_IFDIR || freshParent.Dev != o.parentStat.Dev || freshParent.Ino != o.parentStat.Ino {
		return &Error{Code: CodeFileChanged, Operation: operation, Path: target, Err: fmt.Errorf("canonical path no longer names the opened target parent")}
	}
	var opened syscall.Stat_t
	if err := syscall.Fstat(o.fd, &opened); err != nil {
		return &Error{Code: CodeUnsafePath, Operation: operation, Path: target, Err: err}
	}
	pathStat, err := statTargetAt(o.parentFD, o.name)
	if err != nil {
		return classifyTargetError(operation, target, err)
	}
	if opened.Mode&syscall.S_IFMT != syscall.S_IFREG || pathStat.Mode&syscall.S_IFMT != syscall.S_IFREG || opened.Dev != pathStat.Dev || opened.Ino != pathStat.Ino {
		return &Error{Code: CodeFileChanged, Operation: operation, Path: target, Err: fmt.Errorf("target path no longer names the opened regular file")}
	}
	freshPathStat, err := statTargetAt(freshParentFD, freshName)
	if err != nil {
		return &Error{Code: CodeFileChanged, Operation: operation, Path: target, Err: fmt.Errorf("reopen target path: %w", err)}
	}
	if freshPathStat.Mode&syscall.S_IFMT != syscall.S_IFREG || opened.Dev != freshPathStat.Dev || opened.Ino != freshPathStat.Ino {
		return &Error{Code: CodeFileChanged, Operation: operation, Path: target, Err: fmt.Errorf("canonical path no longer names the opened regular file")}
	}
	return nil
}

func classifyTargetError(operation, target string, err error) error {
	if errors.Is(err, syscall.ELOOP) {
		return &Error{Code: CodeSymlinkNotAllowed, Operation: operation, Path: target, Err: err}
	}
	if errors.Is(err, syscall.ENOENT) {
		return &Error{Code: CodeUnsupportedFileType, Operation: operation, Path: target, Err: fmt.Errorf("regular-file target does not exist: %w", err)}
	}
	return &Error{Code: CodeUnsafePath, Operation: operation, Path: target, Err: err}
}
