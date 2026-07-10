package runlock

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

type ErrorCode string

const (
	CodeInvalidRoot         ErrorCode = "invalid_state_root"
	CodeUnsafePath          ErrorCode = "unsafe_lock_path"
	CodeLockUnavailable     ErrorCode = "lock_unavailable"
	CodeUnsupportedPlatform ErrorCode = "unsupported_platform"
)

type Error struct {
	Code ErrorCode
	Path string
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	message := string(e.Code)
	if e.Path != "" {
		message += " for " + e.Path
	}
	if e.Err != nil {
		message += ": " + e.Err.Error()
	}
	return message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func CodeOf(err error) ErrorCode {
	for err != nil {
		if structured, ok := err.(*Error); ok {
			return structured.Code
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = unwrapper.Unwrap()
	}
	return ""
}

type Handle struct {
	path       string
	release    func() error
	once       sync.Once
	releaseErr error
}

func Acquire(ctx context.Context, stateRoot string) (*Handle, error) {
	return acquire(ctx, stateRoot, true)
}

// AcquireExisting locks an already initialized remediation state root without
// creating or synchronizing any persistent lock entry.
func AcquireExisting(ctx context.Context, stateRoot string) (*Handle, error) {
	return acquire(ctx, stateRoot, false)
}

func acquire(ctx context.Context, stateRoot string, create bool) (*Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, &Error{Code: CodeLockUnavailable, Path: stateRoot, Err: err}
	}
	if strings.TrimSpace(stateRoot) == "" {
		return nil, &Error{Code: CodeInvalidRoot, Err: fmt.Errorf("state root is required")}
	}
	absolute, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, &Error{Code: CodeInvalidRoot, Path: stateRoot, Err: err}
	}
	absolute = filepath.Clean(absolute)
	lockPath := filepath.Join(absolute, "remediation.lock")
	release, err := acquirePlatform(ctx, absolute, lockPath, create)
	if err != nil {
		return nil, err
	}
	return &Handle{path: lockPath, release: release}, nil
}

func (h *Handle) Path() string {
	if h == nil {
		return ""
	}
	return h.path
}

func (h *Handle) Release() error {
	if h == nil {
		return nil
	}
	h.once.Do(func() {
		if h.release != nil {
			h.releaseErr = h.release()
		}
	})
	return h.releaseErr
}

func (h *Handle) Close() error {
	return h.Release()
}
