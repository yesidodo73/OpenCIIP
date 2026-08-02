package executor

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSpecEvidenceArgumentsRedactsSelectedIndexes(t *testing.T) {
	t.Parallel()
	spec := Spec{Arguments: []string{"--user", "admin", "--token", "secret"}, SensitiveArgs: map[int]struct{}{3: {}}}
	got := spec.EvidenceArguments()
	want := []string{"--user", "admin", "--token", "[REDACTED]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EvidenceArguments() = %v, want %v", got, want)
	}
	if spec.Arguments[3] != "secret" {
		t.Fatal("EvidenceArguments mutated the original arguments")
	}
}

func TestLimitedBufferCapsOutputAndReportsOriginalWriteLength(t *testing.T) {
	t.Parallel()
	buffer := newLimitedBuffer(4)
	n, err := buffer.Write([]byte("abcdef"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 6 || string(buffer.Bytes()) != "abcd" || !buffer.Truncated() {
		t.Fatalf("Write() = n:%d data:%q truncated:%t", n, buffer.Bytes(), buffer.Truncated())
	}
}

func TestRunnerRejectsInvalidAllowlistEntry(t *testing.T) {
	t.Parallel()
	if _, err := New([]string{"valid", "bad name"}); err == nil {
		t.Fatal("New() accepted an invalid command name")
	}
}

func TestRunnerLimitsSudoRSVendorPathToVisudo(t *testing.T) {
	t.Parallel()
	runner, err := New([]string{"visudo"})
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	if !reflect.DeepEqual(runner.searchPathsFor("systemctl"), base) {
		t.Fatalf("systemctl search paths = %v, want %v", runner.searchPathsFor("systemctl"), base)
	}
	wantVisudo := append(append([]string(nil), base...), "/usr/lib/cargo/bin")
	if !reflect.DeepEqual(runner.searchPathsFor("visudo"), wantVisudo) {
		t.Fatalf("visudo search paths = %v, want %v", runner.searchPathsFor("visudo"), wantVisudo)
	}
}

func TestTrustedEnvironmentIsMinimalAndSorted(t *testing.T) {
	t.Parallel()
	environment := trustedEnvironment()
	if !sort.StringsAreSorted(environment) {
		t.Fatalf("trustedEnvironment() is not sorted: %v", environment)
	}
	joined := strings.Join(environment, "\n")
	for _, required := range []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("trusted environment lacks %q: %v", required, environment)
		}
	}
	for _, forbidden := range []string{"TOKEN=", "PASSWORD=", "SSH_AUTH_SOCK="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("trusted environment contains %q: %v", forbidden, environment)
		}
	}
}
