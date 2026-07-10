package contentstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/yesidodo73/OpenCIIP/internal/remediation/stateroot"
)

const maximumContentSize int64 = 64 << 20

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Store struct {
	root string
}

func New(stateRoot string) (*Store, error) {
	absolute, err := stateroot.Prepare(stateRoot)
	if err != nil {
		return nil, err
	}
	return openStore(absolute, true)
}

func OpenExisting(stateRoot string) (*Store, error) {
	absolute, err := stateroot.Validate(stateRoot)
	if err != nil {
		return nil, err
	}
	return openStore(absolute, false)
}

func openStore(absolute string, create bool) (*Store, error) {
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("open remediation state root: %w", err)
	}
	defer root.Close()
	if create {
		if err := root.MkdirAll("payloads", 0o700); err != nil {
			return nil, fmt.Errorf("create remediation payload root: %w", err)
		}
	}
	payloadInfo, err := os.Lstat(filepath.Join(absolute, "payloads"))
	if err != nil || payloadInfo.Mode()&os.ModeSymlink != 0 || !payloadInfo.IsDir() || payloadInfo.Mode().Perm()&0o077 != 0 {
		if err == nil {
			err = fmt.Errorf("payload root is not a real directory")
		}
		return nil, fmt.Errorf("inspect remediation payload root: %w", err)
	}
	return &Store{root: absolute}, nil
}

func (s *Store) Put(ctx context.Context, runID, changeSetID, operationID string, content []byte) error {
	if s == nil {
		return fmt.Errorf("content store is nil")
	}
	if err := validateIdentifiers(runID, changeSetID, operationID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(content)) > maximumContentSize {
		return fmt.Errorf("planned content exceeds %d bytes", maximumContentSize)
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return fmt.Errorf("open content store: %w", err)
	}
	defer root.Close()
	directory := filepath.ToSlash(filepath.Join("payloads", runID, changeSetID, operationID))
	if err := root.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create content directory: %w", err)
	}
	for _, component := range []string{
		filepath.Join(s.root, "payloads", runID),
		filepath.Join(s.root, "payloads", runID, changeSetID),
		filepath.Join(s.root, "payloads", runID, changeSetID, operationID),
	} {
		info, inspectErr := os.Lstat(component)
		if inspectErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("path is not a real directory")
			}
			return fmt.Errorf("inspect content directory: %w", inspectErr)
		}
	}
	finalPath := filepath.ToSlash(filepath.Join(directory, "content.bin"))
	if _, err := root.Stat(finalPath); err == nil {
		return fmt.Errorf("planned content already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect planned content: %w", err)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generate content temporary name: %w", err)
	}
	temporary := filepath.ToSlash(filepath.Join(directory, ".content-"+hex.EncodeToString(random)+".tmp"))
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create planned content: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = root.Remove(temporary)
		}
	}()
	if err := writeContext(ctx, file, content); err != nil {
		return fmt.Errorf("write planned content: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync planned content: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close planned content: %w", err)
	}
	if err := root.Rename(temporary, finalPath); err != nil {
		return fmt.Errorf("publish planned content: %w", err)
	}
	cleanup = false
	for _, candidate := range []string{
		directory,
		filepath.ToSlash(filepath.Join("payloads", runID, changeSetID)),
		filepath.ToSlash(filepath.Join("payloads", runID)),
		"payloads",
	} {
		parent, openErr := root.Open(candidate)
		if openErr != nil {
			return fmt.Errorf("open content directory for sync: %w", openErr)
		}
		if syncErr := parent.Sync(); syncErr != nil {
			_ = parent.Close()
			return fmt.Errorf("sync content directory: %w", syncErr)
		}
		if closeErr := parent.Close(); closeErr != nil {
			return fmt.Errorf("close content directory: %w", closeErr)
		}
	}
	return nil
}

func (s *Store) Content(ctx context.Context, runID, changeSetID, operationID string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("content store is nil")
	}
	if err := validateIdentifiers(runID, changeSetID, operationID); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relative := filepath.ToSlash(filepath.Join("payloads", runID, changeSetID, operationID, "content.bin"))
	absolute := filepath.Join(s.root, filepath.FromSlash(relative))
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect planned content: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumContentSize {
		return nil, fmt.Errorf("planned content is not a bounded regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("planned content permissions are not private")
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, fmt.Errorf("open content store: %w", err)
	}
	defer root.Close()
	file, err := root.Open(relative)
	if err != nil {
		return nil, fmt.Errorf("open planned content: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() || !opened.ModTime().Equal(info.ModTime()) {
		if err == nil {
			err = fmt.Errorf("planned content changed before reading")
		}
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, maximumContentSize+1))
	if err != nil {
		return nil, fmt.Errorf("read planned content: %w", err)
	}
	if int64(len(data)) != info.Size() || int64(len(data)) > maximumContentSize {
		return nil, fmt.Errorf("planned content changed while reading")
	}
	after, err := file.Stat()
	if err != nil || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		if err == nil {
			err = fmt.Errorf("planned content changed while reading")
		}
		return nil, err
	}
	return data, nil
}

// DeleteRunContent durably removes only the unused desired payload namespace
// for runID. Journal and backup directories are outside this namespace.
func (s *Store) DeleteRunContent(ctx context.Context, runID string) error {
	if s == nil {
		return fmt.Errorf("content store is nil")
	}
	if err := validateIdentifiers(runID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return fmt.Errorf("open content store: %w", err)
	}
	defer root.Close()
	original := filepath.ToSlash(filepath.Join("payloads", runID))
	tombstone := filepath.ToSlash(filepath.Join("payloads", ".deleting-"+runID))
	originalExists, err := validateDeletionDirectory(root, original)
	if err != nil {
		return fmt.Errorf("inspect planned content before deletion: %w", err)
	}
	tombstoneExists, err := validateDeletionDirectory(root, tombstone)
	if err != nil {
		return fmt.Errorf("inspect planned content tombstone: %w", err)
	}
	if originalExists && tombstoneExists {
		return fmt.Errorf("planned content and its deletion tombstone both exist")
	}
	if originalExists {
		if err := root.Rename(original, tombstone); err != nil {
			return fmt.Errorf("isolate planned content for deletion: %w", err)
		}
		if err := syncRootDirectory(root, "payloads"); err != nil {
			return fmt.Errorf("sync isolated planned content: %w", err)
		}
		tombstoneExists = true
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if tombstoneExists {
		if err := root.RemoveAll(tombstone); err != nil {
			return fmt.Errorf("remove isolated planned content: %w", err)
		}
	}
	if err := syncRootDirectory(root, "payloads"); err != nil {
		return fmt.Errorf("sync planned content deletion: %w", err)
	}
	for _, candidate := range []string{original, tombstone} {
		if _, err := root.Lstat(candidate); err == nil {
			return fmt.Errorf("planned content deletion did not remove %s", candidate)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("verify planned content deletion: %w", err)
		}
	}
	return nil
}

func validateDeletionDirectory(root *os.Root, name string) (bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("deletion target is not a private real directory")
	}
	return true, nil
}

func syncRootDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func validateIdentifiers(values ...string) error {
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("content store identifier %q is invalid", value)
		}
	}
	return nil
}

func writeContext(ctx context.Context, writer io.Writer, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
