package network

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type firewalldDefaultZoneRunner struct {
	calls []string
}

func (r *firewalldDefaultZoneRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	key := strings.Join(spec.Arguments, " ")
	r.calls = append(r.calls, key)
	switch key {
	case "--get-default-zone":
		return executor.Result{ExitCode: 0, Stdout: []byte("public\n")}, nil
	default:
		return executor.Result{}, fmt.Errorf("unexpected firewall-cmd arguments: %s", key)
	}
}

func (*firewalldDefaultZoneRunner) Available(string) bool { return true }

type firewalldConfigReader struct {
	data []byte
	err  error
}

func (r firewalldConfigReader) ReadFile(_ context.Context, path string, _ int64) ([]byte, system.FileMetadata, error) {
	if path != firewalldConfigurationPath {
		return nil, system.FileMetadata{}, os.ErrNotExist
	}
	return append([]byte(nil), r.data...), system.FileMetadata{Path: path}, r.err
}

func (firewalldConfigReader) Stat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, os.ErrNotExist
}

func (firewalldConfigReader) Lstat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, os.ErrNotExist
}

func (firewalldConfigReader) ReadDir(string) ([]os.DirEntry, error) {
	return nil, os.ErrNotExist
}

func (firewalldConfigReader) Exists(string) (bool, error) { return false, nil }

func TestCollectFirewalldDefaultZonesQueriesRuntimeAndPersistentFile(t *testing.T) {
	runner := &firewalldDefaultZoneRunner{}
	runtimeTranscript := newFirewalldTranscript()
	permanentTranscript := newFirewalldTranscript()

	runtimeZone, permanentZone, err := collectFirewalldDefaultZones(
		context.Background(),
		evaluator.Environment{
			Commands: runner,
			Files:    firewalldConfigReader{data: []byte("# firewalld configuration\nDefaultZone=drop\n")},
		},
		runtimeTranscript,
		permanentTranscript,
	)
	if err != nil {
		t.Fatalf("collectFirewalldDefaultZones() error = %v", err)
	}
	if runtimeZone != "public" || permanentZone != "drop" {
		t.Fatalf("collectFirewalldDefaultZones() = %q, %q", runtimeZone, permanentZone)
	}
	wantCalls := []string{"--get-default-zone"}
	if !slices.Equal(runner.calls, wantCalls) {
		t.Fatalf("firewall-cmd calls = %#v, want %#v", runner.calls, wantCalls)
	}
	if runtimeTranscript.commandCount != 1 || permanentTranscript.commandCount != 0 {
		t.Fatalf("transcript command counts = %d, %d, want 1, 0", runtimeTranscript.commandCount, permanentTranscript.commandCount)
	}
	if permanentTranscript.sum() == newFirewalldTranscript().sum() {
		t.Fatal("permanent transcript did not include firewalld.conf")
	}
}

func TestParsePermanentFirewalldDefaultZoneUsesDocumentedDefault(t *testing.T) {
	for name, input := range map[string]struct {
		data    []byte
		missing bool
	}{
		"missing file":        {missing: true},
		"setting absent":      {data: []byte("CleanupOnExit=yes\n")},
		"comments and blanks": {data: []byte("\n# DefaultZone=drop\n")},
	} {
		t.Run(name, func(t *testing.T) {
			zone, err := parsePermanentFirewalldDefaultZone(input.data, input.missing)
			if err != nil {
				t.Fatalf("parsePermanentFirewalldDefaultZone() error = %v", err)
			}
			if zone != "public" {
				t.Fatalf("zone = %q, want public", zone)
			}
		})
	}
}

func TestParsePermanentFirewalldDefaultZoneRejectsAmbiguousValues(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":     []byte("DefaultZone=\n"),
		"duplicate": []byte("DefaultZone=public\nDefaultZone=drop\n"),
		"invalid":   []byte("DefaultZone=public zone\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePermanentFirewalldDefaultZone(data, false); err == nil {
				t.Fatal("parsePermanentFirewalldDefaultZone() accepted ambiguous input")
			}
		})
	}
}

func TestCollectFirewalldDefaultZonesPropagatesConfigReadFailure(t *testing.T) {
	_, _, err := collectFirewalldDefaultZones(
		context.Background(),
		evaluator.Environment{
			Commands: &firewalldDefaultZoneRunner{},
			Files:    firewalldConfigReader{err: errors.New("read failed")},
		},
		newFirewalldTranscript(),
		newFirewalldTranscript(),
	)
	if err == nil || !strings.Contains(err.Error(), "read firewalld permanent default zone") {
		t.Fatalf("error = %v, want configuration read failure", err)
	}
}

func TestParseFirewalldObjectAcceptsTabIndentedContinuation(t *testing.T) {
	input := []byte("allow-host-ipv6 (active)\n" +
		"  priority: -15000\n" +
		"  rich rules:\n" +
		"\trule family=\"ipv6\" icmp-type name=\"redirect\" accept\n")

	object, err := parseFirewalldObject(input)
	if err != nil {
		t.Fatalf("parseFirewalldObject() error = %v", err)
	}
	if values := object["rich rules"]; len(values) != 1 || values[0] != "rule family=\"ipv6\" icmp-type name=\"redirect\" accept" {
		t.Fatalf("rich rules = %#v", values)
	}
}

func TestLeadingWhitespaceUsesTabStops(t *testing.T) {
	for input, expected := range map[string]int{
		"  property": 2,
		"\tchild":    8,
		" \tchild":   8,
		"\t child":   9,
	} {
		if actual := leadingWhitespace(input); actual != expected {
			t.Errorf("leadingWhitespace(%q) = %d, want %d", input, actual, expected)
		}
	}
}
