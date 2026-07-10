package journal

import "fmt"

type ErrorCode string

const (
	CodeInvalidInput      ErrorCode = "invalid_input"
	CodeNotFound          ErrorCode = "not_found"
	CodeAlreadyExists     ErrorCode = "already_exists"
	CodeUnsupportedSchema ErrorCode = "unsupported_schema"
	CodeCorruptWAL        ErrorCode = "journal_corrupt"
	CodeRevisionConflict  ErrorCode = "journal_revision_conflict"
	CodeInvalidTransition ErrorCode = "invalid_transition"
	CodeUnsafePath        ErrorCode = "unsafe_path"
	CodePersistFailed     ErrorCode = "persist_failed"
)

type Error struct {
	Code             ErrorCode
	Operation        string
	RunID            string
	ExpectedRevision uint64
	ActualRevision   uint64
	Committed        bool
	Err              error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	detail := ""
	if e.Err != nil {
		detail = e.Err.Error()
	}
	context := string(e.Code)
	if e.Operation != "" {
		context += " during " + e.Operation
	}
	if e.RunID != "" {
		context += " for run " + e.RunID
	}
	if e.Code == CodeRevisionConflict {
		context += fmt.Sprintf(" (expected revision %d, actual revision %d)", e.ExpectedRevision, e.ActualRevision)
	}
	if detail == "" {
		return context
	}
	return context + ": " + detail
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

func wrap(code ErrorCode, operation, runID string, err error) error {
	return &Error{
		Code:      code,
		Operation: operation,
		RunID:     runID,
		Err:       err,
	}
}
