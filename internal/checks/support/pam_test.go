package support

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestReadPAMServiceExpandsDebianAtInclude(t *testing.T) {
	files := pamFixtureReader{
		"/etc/pam.d/su":             "@include common-auth\naccount include common-account\n",
		"/etc/pam.d/common-auth":    "auth required pam_unix.so nullok\n",
		"/etc/pam.d/common-account": "account required pam_unix.so\n",
	}

	rules, evidence, err := ReadPAMService(context.Background(), files, "su")
	if err != nil {
		t.Fatalf("ReadPAMService() error = %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("ReadPAMService() returned %d rules, want 2", len(rules))
	}
	if rules[0].Service != "common-auth" || rules[0].Type != "auth" || rules[0].Module != "pam_unix.so" {
		t.Fatalf("first expanded rule = %#v", rules[0])
	}
	if rules[1].Service != "common-account" || rules[1].Type != "account" || rules[1].Module != "pam_unix.so" {
		t.Fatalf("second expanded rule = %#v", rules[1])
	}
	if len(evidence) != 3 {
		t.Fatalf("ReadPAMService() returned %d evidence records, want 3", len(evidence))
	}
}

func TestReadPAMServiceTypedIncludeKeepsOnlyMatchingStackType(t *testing.T) {
	files := pamFixtureReader{
		"/etc/pam.d/login": "auth include shared\n",
		"/etc/pam.d/shared": "auth required pam_unix.so\n" +
			"password required pam_unix.so sha512\n",
	}

	rules, _, err := ReadPAMService(context.Background(), files, "login")
	if err != nil {
		t.Fatalf("ReadPAMService() error = %v", err)
	}
	if len(rules) != 1 || rules[0].Type != "auth" {
		t.Fatalf("ReadPAMService() rules = %#v, want only the included auth stack", rules)
	}
}

func TestReadPAMServiceDebianAtIncludeKeepsAllStackTypes(t *testing.T) {
	files := pamFixtureReader{
		"/etc/pam.d/login":  "@include shared\n",
		"/etc/pam.d/shared": "auth required pam_unix.so\npassword required pam_unix.so sha512\n",
	}

	rules, _, err := ReadPAMService(context.Background(), files, "login")
	if err != nil {
		t.Fatalf("ReadPAMService() error = %v", err)
	}
	if len(rules) != 2 || rules[0].Type != "auth" || rules[1].Type != "password" {
		t.Fatalf("ReadPAMService() rules = %#v, want all @include stack types", rules)
	}
}

func TestReadPAMServiceEvidenceDoesNotExposeModuleArguments(t *testing.T) {
	const secret = "bare-secret-value"
	files := pamFixtureReader{
		"/etc/pam.d/sshd": "auth optional pam_exec.so /path/check " + secret + "\n",
	}

	rules, evidence, err := ReadPAMService(context.Background(), files, "sshd")
	if err != nil {
		t.Fatalf("ReadPAMService() error = %v", err)
	}
	if len(rules) != 1 || len(rules[0].Args) != 2 || rules[0].Args[1] != secret {
		t.Fatalf("parsed PAM rule = %#v, want evaluator arguments preserved", rules)
	}
	if strings.Contains(fmt.Sprintf("%#v", evidence), secret) {
		t.Fatalf("PAM evidence exposed a module argument: %#v", evidence)
	}
	evidenceRules, ok := evidence[0].Fact["rules"].([]map[string]any)
	if !ok || len(evidenceRules) != 1 {
		t.Fatalf("PAM evidence rules = %#v", evidence[0].Fact["rules"])
	}
	if evidenceRules[0]["argument_count"] != 2 || evidenceRules[0]["arguments_redacted"] != true {
		t.Fatalf("PAM evidence summary = %#v", evidenceRules[0])
	}
	if _, exposed := evidenceRules[0]["args"]; exposed {
		t.Fatalf("PAM evidence retained raw args: %#v", evidenceRules[0])
	}
}

func TestParsePAMLineRejectsMalformedAtInclude(t *testing.T) {
	for _, content := range []string{"@include", "@include common-auth extra"} {
		if _, err := parsePAMLine("su", "/etc/pam.d/su", 1, content); err == nil {
			t.Fatalf("parsePAMLine(%q) succeeded", content)
		}
	}
}

type pamFixtureReader map[string]string

func (r pamFixtureReader) ReadFile(ctx context.Context, name string, limit int64) ([]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	content, exists := r[name]
	if !exists {
		return nil, system.FileMetadata{}, fs.ErrNotExist
	}
	data := []byte(content)
	if limit > 0 && int64(len(data)) > limit {
		return nil, system.FileMetadata{}, system.ErrReadLimit
	}
	return data, system.FileMetadata{Path: name, FileType: "regular", Mode: 0o600, Size: int64(len(data))}, nil
}

func (pamFixtureReader) Stat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Stat call")
}

func (pamFixtureReader) Lstat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Lstat call")
}

func (pamFixtureReader) ReadDir(string) ([]os.DirEntry, error) {
	return nil, errors.New("unexpected ReadDir call")
}

func (r pamFixtureReader) Exists(name string) (bool, error) {
	_, exists := r[name]
	return exists, nil
}
