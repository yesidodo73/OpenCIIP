package conflict

import "fmt"

type ErrorCode string

const (
	CodeInvalidInput     ErrorCode = "invalid_input"
	CodeUnknownChangeSet ErrorCode = "unknown_change_set"
	CodeDependencyCycle  ErrorCode = "dependency_cycle"
	CodeRollbackConflict ErrorCode = "rollback_dependency_conflict"
	CodeIncompleteGroup  ErrorCode = "incomplete_rollback_group"
)

type Error struct {
	Code       ErrorCode
	ChangeSet  string
	Affected   []string
	Underlying error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	message := string(e.Code)
	if e.ChangeSet != "" {
		message += " for change set " + e.ChangeSet
	}
	if len(e.Affected) > 0 {
		message += fmt.Sprintf(" (affected: %v)", e.Affected)
	}
	if e.Underlying != nil {
		message += ": " + e.Underlying.Error()
	}
	return message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Underlying
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
