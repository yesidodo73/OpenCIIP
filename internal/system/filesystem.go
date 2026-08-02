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
	ErrPathOutsideRoot         = errors.New("path is outside the configured system root")
	ErrNotRegularFile          = errors.New("path is not a regular file")
	ErrReadLimit               = errors.New("file exceeds the configured read limit")
	ErrFileChanged             = errors.New("file changed while being read")
	ErrRootedAccessUnsupported = errors.New("required rooted path resolution is not supported")
	ErrXAttrUnsupported        = errors.New("extended attribute inspection is not supported")
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
	ChangeTime time.Time
	LinkTarget string
}

type Reader interface {
	ReadFile(context.Context, string, int64) ([]byte, FileMetadata, error)
	Stat(string) (FileMetadata, error)
	Lstat(string) (FileMetadata, error)
	ReadDir(string) ([]os.DirEntry, error)
	Exists(string) (bool, error)
}

// BoundedFilePrefixReader is an optional capability for callers that only
// need a stable prefix of a regular file. ReadFilePrefix returns at most limit
// bytes and does not reject a file merely because the complete file is larger
// than limit. The returned metadata and bytes come from the same opened file
// descriptor.
type BoundedFilePrefixReader interface {
	ReadFilePrefix(context.Context, string, int64) ([]byte, FileMetadata, error)
}

// BoundedDirectoryReader is an optional capability for callers that must not
// materialize an unbounded directory in memory. ReadDirBounded returns at most
// limit entries. The truncated result is true only when at least one additional
// entry exists. A zero limit is valid and can be used to test whether a
// directory is empty without returning an entry.
type BoundedDirectoryReader interface {
	ReadDirBounded(string, int) (entries []os.DirEntry, truncated bool, err error)
}

// BoundedDirectorySnapshotReader extends bounded directory enumeration with a
// stable metadata snapshot. The expected metadata, when provided, must match
// the directory opened for enumeration. Implementations must compare metadata
// captured from the same opened directory before and after reading entries.
type BoundedDirectorySnapshotReader interface {
	ReadDirBoundedSnapshot(
		string,
		int,
		*FileMetadata,
	) (entries []os.DirEntry, metadata FileMetadata, truncated bool, err error)
}

// XAttrReader is an optional capability implemented by readers that can take a
// stable, rooted snapshot of extended attributes. A missing key means that the
// requested attribute did not exist at capture time.
type XAttrReader interface {
	ReadXAttrs(context.Context, string, []string, int64, bool) (map[string][]byte, FileMetadata, error)
}

// OSReader exposes a rooted, read-only view of the target system.
type OSReader struct {
	root rootedAccess
}

func (r *OSReader) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	return r.root.Close()
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
	rootHandle, err := newRootedAccess(filepath.Clean(resolved))
	if err != nil {
		return nil, fmt.Errorf("open system root: %w", err)
	}
	return &OSReader{root: rootHandle}, nil
}

func (r *OSReader) ReadFile(ctx context.Context, path string, limit int64) ([]byte, FileMetadata, error) {
	if limit <= 0 {
		limit = DefaultReadLimit
	}
	name, err := rootedName(path)
	if err != nil {
		return nil, FileMetadata{}, err
	}
	file, err := r.root.Open(name)
	if err != nil {
		return nil, FileMetadata{}, err
	}
	defer file.Close()
	return readOpenedFile(ctx, path, limit, file, nil)
}

func (r *OSReader) ReadFilePrefix(
	ctx context.Context,
	path string,
	limit int64,
) ([]byte, FileMetadata, error) {
	if limit <= 0 {
		limit = DefaultReadLimit
	}
	name, err := rootedName(path)
	if err != nil {
		return nil, FileMetadata{}, err
	}
	file, err := r.root.Open(name)
	if err != nil {
		return nil, FileMetadata{}, err
	}
	defer file.Close()
	return readOpenedFilePrefix(ctx, path, limit, file, nil)
}

func readOpenedFile(ctx context.Context, path string, limit int64, file *os.File, afterRead func() error) ([]byte, FileMetadata, error) {
	before, err := file.Stat()
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if !before.Mode().IsRegular() {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	if before.Size() > limit {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s is %d bytes", ErrReadLimit, path, before.Size())
	}

	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, limit+1))
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if int64(len(data)) > limit {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s changed while being read", ErrReadLimit, path)
	}
	if afterRead != nil {
		if err := afterRead(); err != nil {
			return nil, FileMetadata{}, err
		}
	}
	after, err := file.Stat()
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if !sameFileSnapshot(before, after) {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s", ErrFileChanged, path)
	}
	return data, metadata(path, after, ""), nil
}

func readOpenedFilePrefix(
	ctx context.Context,
	path string,
	limit int64,
	file *os.File,
	afterRead func() error,
) ([]byte, FileMetadata, error) {
	if limit <= 0 {
		limit = DefaultReadLimit
	}
	before, err := file.Stat()
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if !before.Mode().IsRegular() {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	data, err := io.ReadAll(io.LimitReader(
		&contextReader{ctx: ctx, reader: file},
		limit,
	))
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if afterRead != nil {
		if err := afterRead(); err != nil {
			return nil, FileMetadata{}, err
		}
	}
	after, err := file.Stat()
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if !sameFileSnapshot(before, after) {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s", ErrFileChanged, path)
	}
	return data, metadata(path, after, ""), nil
}

func (r *OSReader) Stat(path string) (FileMetadata, error) {
	name, err := rootedName(path)
	if err != nil {
		return FileMetadata{}, err
	}
	info, err := r.root.Stat(name)
	if err != nil {
		return FileMetadata{}, err
	}
	return metadata(path, info, ""), nil
}

func (r *OSReader) Lstat(path string) (FileMetadata, error) {
	name, err := rootedName(path)
	if err != nil {
		return FileMetadata{}, err
	}
	info, linkTarget, err := r.root.Lstat(name)
	if err != nil {
		return FileMetadata{}, err
	}
	return metadata(path, info, linkTarget), nil
}

func (r *OSReader) ReadDir(path string) ([]os.DirEntry, error) {
	name, err := rootedName(path)
	if err != nil {
		return nil, err
	}
	directory, err := r.root.OpenDir(name)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return directory.ReadDir(-1)
}

func (r *OSReader) ReadDirBounded(path string, limit int) ([]os.DirEntry, bool, error) {
	entries, _, truncated, err := r.ReadDirBoundedSnapshot(path, limit, nil)
	return entries, truncated, err
}

func (r *OSReader) ReadDirBoundedSnapshot(
	path string,
	limit int,
	expected *FileMetadata,
) ([]os.DirEntry, FileMetadata, bool, error) {
	if limit < 0 {
		return nil, FileMetadata{}, false, fmt.Errorf("directory entry limit must not be negative")
	}
	if limit == int(^uint(0)>>1) {
		return nil, FileMetadata{}, false, fmt.Errorf("directory entry limit is too large")
	}
	name, err := rootedName(path)
	if err != nil {
		return nil, FileMetadata{}, false, err
	}
	directory, err := r.root.OpenDir(name)
	if err != nil {
		return nil, FileMetadata{}, false, err
	}
	defer directory.Close()
	return readOpenedDirectoryBoundedSnapshot(path, limit, directory, expected, nil)
}

func readOpenedDirectoryBoundedSnapshot(
	path string,
	limit int,
	directory *os.File,
	expected *FileMetadata,
	afterRead func() error,
) ([]os.DirEntry, FileMetadata, bool, error) {
	before, err := directory.Stat()
	if err != nil {
		return nil, FileMetadata{}, false, err
	}
	if !before.IsDir() {
		return nil, FileMetadata{}, false, fmt.Errorf("path is not a directory: %s", path)
	}
	beforeMetadata := metadata(path, before, "")
	if expected != nil && !sameMetadataSnapshot(*expected, beforeMetadata) {
		return nil, FileMetadata{}, false, fmt.Errorf("%w: %s", ErrFileChanged, path)
	}
	entries, err := directory.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, FileMetadata{}, false, err
	}
	if afterRead != nil {
		if err := afterRead(); err != nil {
			return nil, FileMetadata{}, false, err
		}
	}
	after, err := directory.Stat()
	if err != nil {
		return nil, FileMetadata{}, false, err
	}
	if !sameFileSnapshot(before, after) {
		return nil, FileMetadata{}, false, fmt.Errorf("%w: %s", ErrFileChanged, path)
	}
	afterMetadata := metadata(path, after, "")
	if len(entries) <= limit {
		return entries, afterMetadata, false, nil
	}
	return entries[:limit], afterMetadata, true, nil
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

func rootedName(path string) (string, error) {
	if strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("system path must be absolute: %q", path)
	}
	cleaned := filepath.Clean(path)
	if cleaned != path {
		return "", fmt.Errorf("system path must be canonical: %q", path)
	}
	relative := strings.TrimPrefix(cleaned, string(filepath.Separator))
	if relative == "" {
		return ".", nil
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("%w: %s", ErrPathOutsideRoot, path)
	}
	return relative, nil
}

func sameFileSnapshot(left, right os.FileInfo) bool {
	if left == nil || right == nil || left.Mode() != right.Mode() || left.Size() != right.Size() || !left.ModTime().Equal(right.ModTime()) {
		return false
	}
	leftUID, leftGID, leftDevice, leftInode := statFields(left)
	rightUID, rightGID, rightDevice, rightInode := statFields(right)
	return leftUID == rightUID && leftGID == rightGID && leftDevice == rightDevice && leftInode == rightInode &&
		samePlatformSnapshot(left, right)
}

func sameMetadataSnapshot(left, right FileMetadata) bool {
	return left.Path == right.Path &&
		left.FileType == right.FileType &&
		left.Mode == right.Mode &&
		left.Size == right.Size &&
		left.UID == right.UID &&
		left.GID == right.GID &&
		left.Device == right.Device &&
		left.Inode == right.Inode &&
		left.ModTime.Equal(right.ModTime) &&
		left.ChangeTime.Equal(right.ChangeTime) &&
		left.LinkTarget == right.LinkTarget
}

type rootedAccess interface {
	Close() error
	Open(string) (*os.File, error)
	OpenDir(string) (*os.File, error)
	Stat(string) (os.FileInfo, error)
	Lstat(string) (os.FileInfo, string, error)
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
		ChangeTime: platformChangeTime(info),
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
