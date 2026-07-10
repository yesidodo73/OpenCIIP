package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultReadLimit int64 = 2 << 20

var (
	ErrPathOutsideRoot = errors.New("path is outside the configured system root")
	ErrNotRegularFile  = errors.New("path is not a regular file")
	ErrReadLimit       = errors.New("file exceeds the configured read limit")
)

type FileMetadata struct {
	Path       string
	FileType   string
	Mode       os.FileMode
	Size       int64
	UID        int
	GID        int
	Device     uint64
	Inode      uint64
	ModTime    time.Time
	LinkTarget string
}

type Reader interface {
	ReadFile(context.Context, string, int64) ([]byte, FileMetadata, error)
	Stat(string) (FileMetadata, error)
	Lstat(string) (FileMetadata, error)
	ReadDir(string) ([]os.DirEntry, error)
	Exists(string) (bool, error)
}

// OSReader exposes a rooted, read-only view of the target system.
type OSReader struct {
	root string
}

func NewOSReader(root string) (*OSReader, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("system root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve system root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve system root symlinks: %w", err)
	}
	return &OSReader{root: filepath.Clean(resolved)}, nil
}

func (r *OSReader) ReadFile(ctx context.Context, path string, limit int64) ([]byte, FileMetadata, error) {
	if limit <= 0 {
		limit = DefaultReadLimit
	}
	resolved, err := r.resolve(path, true)
	if err != nil {
		return nil, FileMetadata{}, err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, FileMetadata{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	if info.Size() > limit {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s is %d bytes", ErrReadLimit, path, info.Size())
	}

	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, limit+1))
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if int64(len(data)) > limit {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s changed while being read", ErrReadLimit, path)
	}
	return data, metadata(path, info, ""), nil
}

func (r *OSReader) Stat(path string) (FileMetadata, error) {
	resolved, err := r.resolve(path, true)
	if err != nil {
		return FileMetadata{}, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return FileMetadata{}, err
	}
	return metadata(path, info, ""), nil
}

func (r *OSReader) Lstat(path string) (FileMetadata, error) {
	resolved, err := r.resolve(path, false)
	if err != nil {
		return FileMetadata{}, err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return FileMetadata{}, err
	}
	linkTarget := ""
	if info.Mode()&os.ModeSymlink != 0 {
		linkTarget, err = os.Readlink(resolved)
		if err != nil {
			return FileMetadata{}, err
		}
	}
	return metadata(path, info, linkTarget), nil
}

func (r *OSReader) ReadDir(path string) ([]os.DirEntry, error) {
	resolved, err := r.resolve(path, true)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(resolved)
}

func (r *OSReader) Exists(path string) (bool, error) {
	_, err := r.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (r *OSReader) resolve(path string, followFinalSymlink bool) (string, error) {
	if strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("system path must be absolute: %q", path)
	}
	relative := strings.TrimLeft(filepath.Clean(path), `/\\`)
	candidate := filepath.Join(r.root, relative)
	if err := ensureWithinRoot(r.root, candidate); err != nil {
		return "", err
	}
	if !followFinalSymlink {
		return candidate, nil
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	if err := ensureWithinRoot(r.root, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func ensureWithinRoot(root, candidate string) error {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return fmt.Errorf("compare system path with root: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("%w: %s", ErrPathOutsideRoot, candidate)
	}
	return nil
}

func metadata(path string, info os.FileInfo, linkTarget string) FileMetadata {
	uid, gid, device, inode := statFields(info)
	return FileMetadata{
		Path:       path,
		FileType:   fileType(info.Mode()),
		Mode:       info.Mode(),
		Size:       info.Size(),
		UID:        uid,
		GID:        gid,
		Device:     device,
		Inode:      inode,
		ModTime:    info.ModTime().UTC(),
		LinkTarget: linkTarget,
	}
}

func fileType(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return "regular"
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode&os.ModeDevice != 0:
		return "device"
	case mode&os.ModeNamedPipe != 0:
		return "pipe"
	case mode&os.ModeSocket != 0:
		return "socket"
	default:
		return "other"
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(buffer)
	}
}
