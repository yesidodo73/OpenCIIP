package logging

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestParseChronySourcesCSVPreservesOriginalRuntimeNames(t *testing.T) {
	data := []byte("^,-,2.rocky.pool.ntp.org,2,9,377,685,-0.1,-0.1,0.2\n" +
		"^,*,approved.example,2,7,377,12,0.0,0.0,0.1\n")
	sources, selected, err := parseChronySourcesCSV(data)
	if err != nil {
		t.Fatalf("parseChronySourcesCSV() error = %v", err)
	}
	if !slices.Equal(sources, []string{"2.rocky.pool.ntp.org", "approved.example"}) || !slices.Equal(selected, []string{"approved.example"}) {
		t.Fatalf("parseChronySourcesCSV() = %#v, %#v", sources, selected)
	}
}

type chronyDirectoryReader struct {
	entries map[string][]os.DirEntry
}

func (reader chronyDirectoryReader) ReadDir(name string) ([]os.DirEntry, error) {
	entries, ok := reader.entries[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func (chronyDirectoryReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("unexpected ReadFile")
}
func (chronyDirectoryReader) Stat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Stat")
}
func (chronyDirectoryReader) Lstat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("unexpected Lstat")
}
func (chronyDirectoryReader) Exists(string) (bool, error) {
	return false, errors.New("unexpected Exists")
}

func TestInspectChronyIncludeDirectoryResolvesEmptyOrMissingDirectory(t *testing.T) {
	reader := chronyDirectoryReader{entries: map[string][]os.DirEntry{"/run/chrony-dhcp": {}}}
	for _, directory := range []string{"/run/chrony-dhcp", "/run/missing"} {
		count, unresolved, err := inspectChronyIncludeDirectory(evaluatorEnvironment(reader), directory, ".sources")
		if err != nil || count != 0 || unresolved {
			t.Fatalf("inspectChronyIncludeDirectory(%q) = %d, %t, %v, want resolved empty", directory, count, unresolved, err)
		}
	}
}

func evaluatorEnvironment(reader system.Reader) evaluator.Environment {
	return evaluator.Environment{Files: reader}
}

func TestParseChronySourcesCSVRejectsMalformedRows(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("^,*\n"),
		[]byte("?,*,source.example\n"),
		[]byte("^,**,source.example\n"),
	} {
		if _, _, err := parseChronySourcesCSV(data); err == nil {
			t.Fatalf("parseChronySourcesCSV(%q) accepted malformed data", data)
		}
	}
}
