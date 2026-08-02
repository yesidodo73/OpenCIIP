package supportevidence

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func TestGoBinaryBuildIdentityRequiresCanonicalCleanLinuxBuild(t *testing.T) {
	platform := Platform{OS: "linux", ID: "rocky", Version: "9.8", Architecture: "amd64"}
	source := SourceIdentity{ToolCommit: strings.Repeat("a", 40)}
	valid := GoBinaryBuildIdentity{
		GoVersion:     "go1.26.5",
		CommandPath:   openCIIPCommandPath,
		ModulePath:    openCIIPModulePath,
		ModuleVersion: "v0.1.0",
		BuildMode:     "exe",
		Compiler:      "gc",
		Trimpath:      "true",
		CGOEnabled:    "0",
		GOOS:          "linux",
		GOARCH:        "amd64",
		GOAMD64:       "v1",
		VCS:           "git",
		VCSRevision:   source.ToolCommit,
		VCSModified:   "false",
	}
	if err := valid.Validate(platform, source); err != nil {
		t.Fatalf("Validate(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*GoBinaryBuildIdentity)
	}{
		{name: "wrong command", mutate: func(value *GoBinaryBuildIdentity) { value.CommandPath = "example.invalid/openciip" }},
		{name: "dirty module", mutate: func(value *GoBinaryBuildIdentity) { value.ModuleVersion += "+dirty" }},
		{name: "no trimpath", mutate: func(value *GoBinaryBuildIdentity) { value.Trimpath = "" }},
		{name: "cgo enabled", mutate: func(value *GoBinaryBuildIdentity) { value.CGOEnabled = "1" }},
		{name: "wrong target", mutate: func(value *GoBinaryBuildIdentity) { value.GOOS = "windows" }},
		{name: "wrong amd64 level", mutate: func(value *GoBinaryBuildIdentity) { value.GOAMD64 = "v3" }},
		{name: "wrong revision", mutate: func(value *GoBinaryBuildIdentity) { value.VCSRevision = strings.Repeat("b", 40) }},
		{name: "modified", mutate: func(value *GoBinaryBuildIdentity) { value.VCSModified = "true" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := valid
			test.mutate(&changed)
			if err := changed.Validate(platform, source); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestParseGoBinaryBuildIdentityRejectsDuplicateRequiredSetting(t *testing.T) {
	_, err := parseGoBinaryBuildIdentity(&debug.BuildInfo{
		Path: openCIIPCommandPath,
		Main: debug.Module{Path: openCIIPModulePath},
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
			{Key: "GOOS", Value: "linux"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("parseGoBinaryBuildIdentity() error = %v", err)
	}
}

func TestArtifactInspectionRejectsNonGoBinaryAndLinks(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "artifact")
	if err := os.WriteFile(regular, []byte("not a Go executable"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	identity, err := InspectArtifact(regular)
	if err != nil || identity.SizeBytes != int64(len("not a Go executable")) {
		t.Fatalf("InspectArtifact() = %+v, %v", identity, err)
	}
	if _, _, err := InspectGoBinary(regular); err == nil || !strings.Contains(err.Error(), "Go build metadata") {
		t.Fatalf("InspectGoBinary(non-Go) error = %v", err)
	}

	link := filepath.Join(root, "linked-artifact")
	if err := os.Symlink(regular, link); err != nil {
		t.Skipf("symbolic links are unavailable in this environment: %v", err)
	}
	if _, err := InspectArtifact(link); err == nil || !strings.Contains(err.Error(), "non-link") {
		t.Fatalf("InspectArtifact(link) error = %v", err)
	}
}
