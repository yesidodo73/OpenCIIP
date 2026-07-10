package hostidentity

import (
	"context"
	"crypto/subtle"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type ErrorCode string

const (
	CodeInvalidSystemRoot  ErrorCode = "invalid_system_root"
	CodeUnsafeSystemRoot   ErrorCode = "unsafe_system_root"
	CodeMachineIDMissing   ErrorCode = "machine_id_missing"
	CodeMachineIDInvalid   ErrorCode = "machine_id_invalid"
	CodeMachineIDAmbiguous ErrorCode = "machine_id_ambiguous"
	CodeBootIDMissing      ErrorCode = "boot_id_missing"
	CodeBootIDInvalid      ErrorCode = "boot_id_invalid"
	CodeHostMismatch       ErrorCode = "host_mismatch"
	CodeBootChanged        ErrorCode = "boot_changed"
	CodeUnsupported        ErrorCode = "unsupported_platform"
)

type Error struct {
	Code  ErrorCode
	Field string
	Path  string
	Err   error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	message := string(e.Code)
	if e.Field != "" {
		message += " for " + e.Field
	}
	if e.Path != "" {
		message += " at " + e.Path
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

type Collector struct {
	systemRoot string
}

func New(systemRoot string) (*Collector, error) {
	if strings.TrimSpace(systemRoot) == "" || strings.IndexByte(systemRoot, 0) >= 0 {
		return nil, &Error{Code: CodeInvalidSystemRoot, Path: systemRoot, Err: fmt.Errorf("system root is required and must not contain a NUL byte")}
	}
	absolute, err := filepath.Abs(systemRoot)
	if err != nil {
		return nil, &Error{Code: CodeInvalidSystemRoot, Path: systemRoot, Err: err}
	}
	return &Collector{systemRoot: filepath.Clean(absolute)}, nil
}

func (c *Collector) Collect(ctx context.Context) (model.HostIdentity, error) {
	if c == nil {
		return model.HostIdentity{}, &Error{Code: CodeInvalidSystemRoot, Err: fmt.Errorf("collector is nil")}
	}
	if err := ctx.Err(); err != nil {
		return model.HostIdentity{}, err
	}
	return collectPlatform(ctx, c.systemRoot)
}

type MatchMode string

const (
	MatchHost     MatchMode = "host"
	MatchSameBoot MatchMode = "same_boot"
)

func Match(expected, actual model.HostIdentity, mode MatchMode) error {
	if err := expected.Validate(); err != nil {
		return &Error{Code: CodeHostMismatch, Field: "expected", Err: err}
	}
	if err := actual.Validate(); err != nil {
		return &Error{Code: CodeHostMismatch, Field: "actual", Err: err}
	}
	if mode != MatchHost && mode != MatchSameBoot {
		return &Error{Code: CodeHostMismatch, Field: "mode", Err: fmt.Errorf("unknown match mode %q", mode)}
	}

	machineMatches := subtle.ConstantTimeCompare([]byte(expected.MachineIDHash), []byte(actual.MachineIDHash)) == 1
	if !machineMatches || expected.SystemRoot != actual.SystemRoot || expected.RootDevice != actual.RootDevice || expected.RootInode != actual.RootInode {
		return &Error{Code: CodeHostMismatch, Field: "host", Err: fmt.Errorf("machine identity or system root does not match")}
	}
	if mode == MatchSameBoot {
		if expected.BootID == "" || actual.BootID == "" || subtle.ConstantTimeCompare([]byte(expected.BootID), []byte(actual.BootID)) != 1 {
			return &Error{Code: CodeBootChanged, Field: "boot_id", Err: fmt.Errorf("boot identity does not match")}
		}
	}
	return nil
}

func VerifyHost(expected, actual model.HostIdentity) error {
	return Match(expected, actual, MatchHost)
}

func VerifySameBoot(expected, actual model.HostIdentity) error {
	return Match(expected, actual, MatchSameBoot)
}
