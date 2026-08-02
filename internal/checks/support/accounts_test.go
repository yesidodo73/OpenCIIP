package support

import (
	"strings"
	"testing"
)

func TestParsePasswdRejectsTerminalControlInAccountName(t *testing.T) {
	tests := []string{
		"user\x1b[2J",
		"user\u009b31m",
		"user\u202e",
		"user\u2028hidden",
		string([]byte{'u', 's', 'e', 'r', 0xff}),
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parsePasswd(
				[]byte(name+":x:1000:1000::/home/user:/bin/bash"),
				"fixture",
			)
			if err == nil || !strings.Contains(err.Error(), "invalid account name") {
				t.Fatalf("parsePasswd(%q) error = %v, want invalid account name", name, err)
			}
		})
	}
}

func TestValidIdentityNameAcceptsVisibleNSSNames(t *testing.T) {
	for _, name := range []string{"root", "domain-user", "user.name", "사용자"} {
		if !validIdentityName(name) {
			t.Fatalf("validIdentityName(%q) = false", name)
		}
	}
}
