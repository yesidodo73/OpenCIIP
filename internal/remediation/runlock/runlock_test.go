package runlock

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestAcquireRejectsInvalidRootBeforePlatformDispatch(t *testing.T) {
	t.Parallel()

	for _, acquire := range []struct {
		name string
		run  func(context.Context, string) (*Handle, error)
	}{
		{name: "create", run: Acquire},
		{name: "existing", run: AcquireExisting},
	} {
		acquire := acquire
		t.Run(acquire.name, func(t *testing.T) {
			t.Parallel()

			handle, err := acquire.run(context.Background(), " \t ")
			if handle != nil {
				_ = handle.Release()
				t.Fatalf("%s returned a handle for an empty root", acquire.name)
			}
			if code := CodeOf(err); code != CodeInvalidRoot {
				t.Fatalf("%s error = %v, code = %q, want %q", acquire.name, err, code, CodeInvalidRoot)
			}
		})
	}
}

func TestAcquireHonorsAlreadyCanceledContextBeforePlatformDispatch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, acquire := range []struct {
		name string
		run  func(context.Context, string) (*Handle, error)
	}{
		{name: "create", run: Acquire},
		{name: "existing", run: AcquireExisting},
	} {
		acquire := acquire
		t.Run(acquire.name, func(t *testing.T) {
			t.Parallel()

			handle, err := acquire.run(ctx, "unused")
			if handle != nil {
				_ = handle.Release()
				t.Fatalf("%s returned a handle for a canceled context", acquire.name)
			}
			if code := CodeOf(err); code != CodeLockUnavailable {
				t.Fatalf("%s error = %v, code = %q, want %q", acquire.name, err, code, CodeLockUnavailable)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s error = %v, want context.Canceled", acquire.name, err)
			}
		})
	}
}

func TestNilHandleIsSafe(t *testing.T) {
	t.Parallel()

	var handle *Handle
	if path := handle.Path(); path != "" {
		t.Fatalf("nil Handle.Path() = %q, want empty", path)
	}
	if err := handle.Release(); err != nil {
		t.Fatalf("nil Handle.Release() error = %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("nil Handle.Close() error = %v", err)
	}
}

func TestCodeOfFindsWrappedStructuredError(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("outer: %w", &Error{Code: CodeUnsafePath, Path: "/state", Err: errors.New("unsafe")})
	if code := CodeOf(err); code != CodeUnsafePath {
		t.Fatalf("CodeOf(wrapped error) = %q, want %q", code, CodeUnsafePath)
	}
}
