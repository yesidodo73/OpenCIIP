package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	rulecatalog "github.com/yesidodo73/OpenCIIP/internal/rules"
)

type supportFixture struct {
	SchemaVersion  int                    `yaml:"schema_version"`
	Selector       model.PlatformSelector `yaml:"selector"`
	Family         string                 `yaml:"family"`
	DisplayName    string                 `yaml:"display_name"`
	DisplayVersion string                 `yaml:"display_version"`
	OSRelease      string                 `yaml:"os_release"`
	CentOSRelease  string                 `yaml:"centos_release,omitempty"`
}

func TestContributorPlatformFixtureIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "contrib", "os-support", "platform-fixture.yaml")
	fixture := loadSupportFixture(t, path)
	validateSupportFixture(t, filepath.Base(path), fixture)
}

func TestTestedPlatformFixturesMatchDefaultBindings(t *testing.T) {
	bundle, err := rulecatalog.LoadDefaults()
	if err != nil {
		t.Fatalf("rules.LoadDefaults() error = %v", err)
	}

	tested := make(map[string]string)
	for _, layer := range bundle.Layers {
		if layer.ScanSupport == nil || *layer.ScanSupport != model.ScanSupportTested {
			continue
		}
		key := supportFixtureKey(layer.Selector)
		if previous, duplicate := tested[key]; duplicate {
			t.Fatalf("tested platform selector %q is duplicated in %s and %s", key, previous, layer.ID)
		}
		tested[key] = layer.ID
	}

	fixtureDirectory := filepath.Join("..", "..", "rules", "platforms", "testdata")
	entries, err := os.ReadDir(fixtureDirectory)
	if err != nil {
		t.Fatalf("read platform fixture directory: %v", err)
	}
	fixtures := make(map[string]string)
	expectedDocumentedRows := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(fixtureDirectory, entry.Name())
		fixture := loadSupportFixture(t, path)
		validateSupportFixture(t, entry.Name(), fixture)
		key := supportFixtureKey(fixture.Selector)
		if previous, duplicate := fixtures[key]; duplicate {
			t.Fatalf("platform fixture selector %q is duplicated in %s and %s", key, previous, entry.Name())
		}
		fixtures[key] = entry.Name()
		expectedDocumentedRows[fmt.Sprintf(
			"| %s | %s | %s | 테스트 완료 |",
			fixture.DisplayName,
			fixture.DisplayVersion,
			fixture.Selector.Architecture,
		)] = struct{}{}
	}

	for key, layerID := range tested {
		if _, exists := fixtures[key]; !exists {
			t.Errorf("tested platform layer %s has no os-release fixture for %q", layerID, key)
		}
	}
	for key, fixtureName := range fixtures {
		if _, exists := tested[key]; !exists {
			t.Errorf("platform fixture %s has no tested exact binding layer for %q", fixtureName, key)
		}
	}
	for _, document := range []string{
		filepath.Join("..", "..", "README.md"),
		filepath.Join("..", "..", "docs", "CHECKS.md"),
	} {
		content, err := os.ReadFile(document)
		if err != nil {
			t.Fatalf("read support document %s: %v", document, err)
		}
		actualRows := testedSupportRows(t, document, string(content))
		for row := range expectedDocumentedRows {
			if _, exists := actualRows[row]; !exists {
				t.Errorf("support document %s is missing row %q", document, row)
			}
		}
		for row := range actualRows {
			if _, exists := expectedDocumentedRows[row]; !exists {
				t.Errorf("support document %s claims an unverified tested row %q", document, row)
			}
		}
	}
}

func testedSupportRows(t *testing.T, document, content string) map[string]struct{} {
	t.Helper()
	rows := make(map[string]struct{})
	for _, line := range strings.Split(content, "\n") {
		row := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if !strings.HasPrefix(row, "| ") || !strings.HasSuffix(row, "| 테스트 완료 |") {
			continue
		}
		if _, duplicate := rows[row]; duplicate {
			t.Errorf("support document %s repeats tested row %q", document, row)
			continue
		}
		rows[row] = struct{}{}
	}
	return rows
}

func loadSupportFixture(t *testing.T, path string) supportFixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read platform fixture %s: %v", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var fixture supportFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode platform fixture %s: %v", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple YAML documents are not allowed")
		}
		t.Fatalf("decode trailing platform fixture %s: %v", path, err)
	}
	return fixture
}

func validateSupportFixture(t *testing.T, name string, fixture supportFixture) {
	t.Helper()
	if fixture.SchemaVersion != 1 {
		t.Fatalf("platform fixture %s has schema version %d, want 1", name, fixture.SchemaVersion)
	}
	if fixture.Selector.ID == "" || fixture.Selector.Version == "" || fixture.Selector.Architecture == "" ||
		fixture.Selector.OS != "" || fixture.Selector.Family != "" || fixture.Selector.VersionMajor != "" {
		t.Fatalf("platform fixture %s must use only exact id, version, and architecture", name)
	}
	if fixture.Family == "" || strings.TrimSpace(fixture.Family) != fixture.Family {
		t.Fatalf("platform fixture %s has no canonical family", name)
	}
	if fixture.DisplayName == "" || strings.TrimSpace(fixture.DisplayName) != fixture.DisplayName ||
		fixture.DisplayVersion == "" || strings.TrimSpace(fixture.DisplayVersion) != fixture.DisplayVersion {
		t.Fatalf("platform fixture %s has no canonical public display name or version", name)
	}

	values, err := parseOSRelease([]byte(fixture.OSRelease))
	if err != nil {
		t.Fatalf("parse os-release from platform fixture %s: %v", name, err)
	}
	files := map[string][]byte{}
	if fixture.CentOSRelease != "" {
		files["/etc/centos-release"] = []byte(fixture.CentOSRelease)
	}
	detector := NewDetector(&detectorReader{files: files})
	id := strings.ToLower(values["ID"])
	version := detector.refineCentOSVersionID(context.Background(), id, values["VERSION_ID"])
	family := detectFamily(id, values["ID_LIKE"])
	if id != fixture.Selector.ID || version != fixture.Selector.Version || family != fixture.Family {
		t.Fatalf(
			"platform fixture %s resolves to id=%q version=%q family=%q, want id=%q version=%q family=%q",
			name,
			id,
			version,
			family,
			fixture.Selector.ID,
			fixture.Selector.Version,
			fixture.Family,
		)
	}
}

func supportFixtureKey(selector model.PlatformSelector) string {
	return strings.ToLower(selector.ID) + "\x00" +
		strings.ToLower(selector.Version) + "\x00" +
		strings.ToLower(selector.Architecture)
}
