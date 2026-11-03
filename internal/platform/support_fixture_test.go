package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
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
		actualRows, err := testedSupportRows(string(content))
		if err != nil {
			t.Errorf("parse support document %s: %v", document, err)
			continue
		}
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

func testedSupportRows(content string) (map[string]struct{}, error) {
	rows := make(map[string]struct{})
	compact := false
	lastProse := ""
	addRow := func(row string) error {
		if _, duplicate := rows[row]; duplicate {
			return fmt.Errorf("repeated tested row %q", row)
		}
		rows[row] = struct{}{}
		return nil
	}
	for _, line := range strings.Split(content, "\n") {
		row := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if !strings.HasPrefix(row, "|") || !strings.HasSuffix(row, "|") {
			compact = false
			if row != "" {
				lastProse = row
			}
			continue
		}
		cells := strings.Split(strings.Trim(row, "|"), "|")
		for index := range cells {
			cells[index] = strings.TrimSpace(cells[index])
		}
		if len(cells) == 2 && cells[0] == "운영체제" && cells[1] == "테스트 버전" {
			if !strings.Contains(lastProse, "amd64") {
				return nil, fmt.Errorf("compact support table does not specify Linux amd64 scope")
			}
			compact = true
			continue
		}
		if compact {
			if len(cells) != 2 {
				return nil, fmt.Errorf("invalid compact support row %q", row)
			}
			if strings.Trim(cells[0], "-: ") == "" && strings.Trim(cells[1], "-: ") == "" {
				continue
			}
			if cells[0] == "" {
				return nil, fmt.Errorf("missing operating system in %q", row)
			}
			for _, version := range strings.Split(cells[1], ",") {
				version = strings.TrimSpace(version)
				if version == "" {
					return nil, fmt.Errorf("missing version in %q", row)
				}
				if err := addRow(fmt.Sprintf("| %s | %s | amd64 | 테스트 완료 |", cells[0], version)); err != nil {
					return nil, err
				}
			}
			continue
		}
		if strings.HasPrefix(row, "| ") && strings.HasSuffix(row, "| 테스트 완료 |") {
			if err := addRow(row); err != nil {
				return nil, err
			}
		}
	}
	return rows, nil
}

func TestTestedSupportRows(t *testing.T) {
	tested := map[string]struct{}{
		"| Ubuntu | 22.04 LTS | amd64 | 테스트 완료 |": {},
		"| Ubuntu | 26.04 LTS | amd64 | 테스트 완료 |": {},
	}
	tests := []struct {
		name    string
		content string
		want    map[string]struct{}
		wantErr bool
	}{
		{
			name: "one version per row",
			content: "| 운영체제 | 버전 | 아키텍처 | 상태 |\n" +
				"| Ubuntu | 22.04 LTS | amd64 | 테스트 완료 |\n" +
				"| Ubuntu | 26.04 LTS | amd64 | 테스트 완료 |\n",
			want: tested,
		},
		{
			name: "versions grouped by operating system",
			content: "다음 환경은 amd64에서 점검했습니다.\n\n" +
				"| 운영체제 | 테스트 버전 |\n| --- | --- |\n" +
				"| Ubuntu | 22.04 LTS, 26.04 LTS |\n",
			want: tested,
		},
		{
			name: "grouped table without architecture",
			content: "| 운영체제 | 테스트 버전 |\n| --- | --- |\n" +
				"| Ubuntu | 22.04 LTS |\n",
			wantErr: true,
		},
		{
			name: "duplicate version in grouped table",
			content: "다음 Linux amd64 환경에서 점검했습니다.\n\n" +
				"| 운영체제 | 테스트 버전 |\n| --- | --- |\n" +
				"| Ubuntu | 22.04 LTS, 22.04 LTS |\n",
			wantErr: true,
		},
		{
			name: "missing version in grouped table",
			content: "다음 Linux amd64 환경에서 점검했습니다.\n\n" +
				"| 운영체제 | 테스트 버전 |\n| --- | --- |\n" +
				"| Ubuntu | 22.04 LTS, |\n",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := testedSupportRows(test.content)
			if (err != nil) != test.wantErr {
				t.Fatalf("testedSupportRows() error = %v, want error %t", err, test.wantErr)
			}
			if !test.wantErr && !maps.Equal(got, test.want) {
				t.Fatalf("testedSupportRows() = %v, want %v", got, test.want)
			}
		})
	}
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
