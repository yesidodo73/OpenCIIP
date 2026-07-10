package stateroot

import "fmt"

// Prepare creates a missing private state directory only below a trusted
// parent chain and returns its canonical absolute path.
func Prepare(value string) (string, error) {
	return preparePlatform(value, true)
}

// Validate opens no new path and verifies that an existing state directory is
// private and anchored below a trusted parent chain.
func Validate(value string) (string, error) {
	return preparePlatform(value, false)
}

func invalid(reason string) error {
	return fmt.Errorf("unsafe remediation state root: %s", reason)
}
