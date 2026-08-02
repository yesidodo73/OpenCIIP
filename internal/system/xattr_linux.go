//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const defaultXAttrReadLimit int64 = 1 << 20

func (r *OSReader) ReadXAttrs(
	ctx context.Context,
	path string,
	names []string,
	limit int64,
	followFinalSymlink bool,
) (map[string][]byte, FileMetadata, error) {
	if r == nil || r.root == nil {
		return nil, FileMetadata{}, os.ErrClosed
	}
	name, err := rootedName(path)
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if len(names) == 0 {
		return nil, FileMetadata{}, fmt.Errorf("at least one extended attribute name is required")
	}
	if limit <= 0 {
		limit = defaultXAttrReadLimit
	}
	for _, attribute := range names {
		if strings.TrimSpace(attribute) == "" || strings.IndexByte(attribute, 0) >= 0 {
			return nil, FileMetadata{}, fmt.Errorf("invalid extended attribute name %q", attribute)
		}
	}

	var file *os.File
	if followFinalSymlink {
		file, err = r.root.Open(name)
	} else {
		reader, supported := r.root.(interface {
			OpenNoFollow(string) (*os.File, error)
		})
		if !supported {
			return nil, FileMetadata{}, ErrRootedAccessUnsupported
		}
		file, err = reader.OpenNoFollow(name)
	}
	if err != nil {
		return nil, FileMetadata{}, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, FileMetadata{}, err
	}

	values := make(map[string][]byte, len(names))
	for _, attribute := range names {
		if err := ctx.Err(); err != nil {
			return nil, FileMetadata{}, err
		}
		value, exists, err := readOpenedXAttr(int(file.Fd()), attribute, limit)
		if err != nil {
			return nil, FileMetadata{}, &os.PathError{
				Op:   "fgetxattr " + attribute,
				Path: path,
				Err:  err,
			}
		}
		if exists {
			values[attribute] = value
		}
	}

	after, err := file.Stat()
	if err != nil {
		return nil, FileMetadata{}, err
	}
	if !sameFileSnapshot(before, after) {
		return nil, FileMetadata{}, fmt.Errorf("%w: %s", ErrFileChanged, path)
	}
	return values, metadata(path, after, ""), nil
}

func readOpenedXAttr(fd int, name string, limit int64) ([]byte, bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := unix.Fgetxattr(fd, name, nil)
		switch {
		case errors.Is(err, unix.ENODATA):
			return nil, false, nil
		case errors.Is(err, unix.ENOTSUP):
			return nil, false, ErrXAttrUnsupported
		case err != nil:
			return nil, false, err
		case int64(size) > limit:
			return nil, false, fmt.Errorf("%w: %s is %d bytes", ErrReadLimit, name, size)
		case size == 0:
			return []byte{}, true, nil
		}

		buffer := make([]byte, size)
		read, err := unix.Fgetxattr(fd, name, buffer)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if errors.Is(err, unix.ENODATA) {
			return nil, false, nil
		}
		if errors.Is(err, unix.ENOTSUP) {
			return nil, false, ErrXAttrUnsupported
		}
		if err != nil {
			return nil, false, err
		}
		return buffer[:read], true, nil
	}
	return nil, false, fmt.Errorf("%w: %s changed while being read", ErrFileChanged, name)
}
