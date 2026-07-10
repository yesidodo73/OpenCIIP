package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestValidateLoadedScanAcceptsCanonicalFixture(t *testing.T) {
	if err := validateLoadedScan(validLoadedScanFixture()); err != nil {
		t.Fatalf("validateLoadedScan() error = %v", err)
	}
}

func TestValidateLoadedScanRejectsTamperedOrIncompleteMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.ScanRun)
	}{
		{
			name: "incomplete run",
			mutate: func(run *model.ScanRun) {
				run.Metadata.Complete = false
			},
		},
		{
			name: "duration mismatch",
			mutate: func(run *model.ScanRun) {
				run.Metadata.DurationMS++
			},
		},
		{
			name: "missing target identity",
			mutate: func(run *model.ScanRun) {
				run.Metadata.TargetIdentity = nil
			},
		},
		{
			name: "result count mismatch",
			mutate: func(run *model.ScanRun) {
				run.Metadata.Counts[model.StatusPass] = 2
			},
		},
		{
			name: "exit code mismatch",
			mutate: func(run *model.ScanRun) {
				run.Metadata.ExitCode = 1
			},
		},
		{
			name: "result timing mismatch",
			mutate: func(run *model.ScanRun) {
				run.Results[0].DurationMS++
			},
		},
		{
			name: "non hexadecimal rule set digest",
			mutate: func(run *model.ScanRun) {
				run.Metadata.RuleSetVersion = "sha256:" + strings.Repeat("g", 64)
			},
		},
		{
			name: "unknown evidence mode",
			mutate: func(run *model.ScanRun) {
				run.Metadata.EvidenceMode = "standard"
			},
		},
		{
			name: "unknown platform support",
			mutate: func(run *model.ScanRun) {
				run.Metadata.Platform.Support = "trusted"
			},
		},
		{
			name: "invalid boot id",
			mutate: func(run *model.ScanRun) {
				run.Metadata.TargetIdentity.BootID = "boot-test"
			},
		},
		{
			name: "duplicate result id",
			mutate: func(run *model.ScanRun) {
				run.Results = append(run.Results, run.Results[0])
				run.Metadata.Counts[model.StatusPass] = 2
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := validLoadedScanFixture()
			test.mutate(&run)
			if err := validateLoadedScan(run); err == nil {
				t.Fatal("validateLoadedScan() error = nil, want fail-closed rejection")
			}
		})
	}
}

func TestValidateLoadedScanRejectsInvalidVerificationProvenance(t *testing.T) {
	tests := []struct {
		name         string
		verification model.Verification
	}{
		{
			name:         "unknown verification state",
			verification: model.Verification{State: model.VerificationState("trusted")},
		},
		{
			name:         "verified without environment",
			verification: model.Verification{State: model.VerificationVerified, VerifiedAt: "2026-07-11T00:00:00Z"},
		},
		{
			name: "verified with invalid timestamp",
			verification: model.Verification{
				State:        model.VerificationVerified,
				Environments: []string{"Rocky Linux 9.8"},
				VerifiedAt:   "2026-07-11",
			},
		},
		{
			name: "pending with verified timestamp",
			verification: model.Verification{
				State:      model.VerificationPending,
				VerifiedAt: "2026-07-11T00:00:00Z",
			},
		},
		{
			name: "rejected with verified timestamp",
			verification: model.Verification{
				State:      model.VerificationRejected,
				VerifiedAt: "2026-07-11T00:00:00Z",
			},
		},
		{
			name: "duplicate environments",
			verification: model.Verification{
				State:        model.VerificationVerified,
				Environments: []string{"Rocky Linux 9.8", "Rocky Linux 9.8"},
				VerifiedAt:   "2026-07-11T00:00:00Z",
			},
		},
		{
			name: "noncanonical environment",
			verification: model.Verification{
				State:        model.VerificationVerified,
				Environments: []string{" Rocky Linux 9.8"},
				VerifiedAt:   "2026-07-11T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := validLoadedScanFixture()
			run.Results[0].Verification = test.verification
			if err := validateLoadedScan(run); err == nil {
				t.Fatal("validateLoadedScan() error = nil, want verification provenance rejection")
			}
		})
	}
}

func TestReadStrictReportJSONRejectsUnknownTrailingOrMalformedJSON(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"name":"scan","unexpected":true}`},
		{name: "second document", data: `{"name":"scan"} {"name":"other"}`},
		{name: "trailing garbage", data: `{"name":"scan"}x`},
		{name: "malformed", data: `{"name":`},
		{name: "duplicate key", data: `{"name":"scan","name":"other"}`},
		{name: "escaped duplicate key", data: `{"name":"scan","\u006eame":"other"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "metadata.json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatalf("OpenRoot() error = %v", err)
			}
			defer root.Close()

			var destination struct {
				Name string `json:"name"`
			}
			if err := readStrictReportJSON(root, directory, "metadata.json", &destination); err == nil {
				t.Fatal("readStrictReportJSON() error = nil, want strict JSON rejection")
			}
		})
	}
}

func TestReadStrictReportJSONAcceptsOneKnownDocument(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "metadata.json")
	if err := os.WriteFile(path, []byte("{\"name\":\"scan\"}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	defer root.Close()

	var destination struct {
		Name string `json:"name"`
	}
	if err := readStrictReportJSON(root, directory, "metadata.json", &destination); err != nil {
		t.Fatalf("readStrictReportJSON() error = %v", err)
	}
	if destination.Name != "scan" {
		t.Fatalf("decoded name = %q, want %q", destination.Name, "scan")
	}
}

func validLoadedScanFixture() model.ScanRun {
	startedAt := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Second)
	resultCompletedAt := startedAt.Add(100 * time.Millisecond)
	return model.ScanRun{
		Metadata: model.RunMetadata{
			SchemaVersion:  1,
			RunID:          "scan-20260711",
			ToolVersion:    "v0.1.0",
			ToolCommit:     strings.Repeat("b", 40),
			GuideYear:      2026,
			RuleSetVersion: "sha256:" + strings.Repeat("a", 64),
			StartedAt:      startedAt,
			CompletedAt:    completedAt,
			DurationMS:     completedAt.Sub(startedAt).Milliseconds(),
			Platform: model.PlatformInfo{
				Hostname:       "rocky-test",
				OS:             "linux",
				ID:             "rocky",
				Name:           "Rocky Linux 9.8",
				VersionID:      "9.8",
				Family:         "rhel",
				Architecture:   "x86_64",
				KernelRelease:  "5.14.0-test.el9.x86_64",
				InitSystem:     "systemd",
				PackageManager: "dnf",
				Privilege:      "root",
				Support:        model.SupportVerified,
			},
			Counts:       map[model.Status]int{model.StatusPass: 1},
			EvidenceMode: "problems",
			Redaction:    true,
			Complete:     true,
			ExitCode:     0,
			TargetIdentity: &model.HostIdentity{
				MachineIDHash: strings.Repeat("c", 64),
				SystemRoot:    "/",
				RootDevice:    1,
				RootInode:     2,
				BootID:        "12345678-1234-1234-1234-123456789abc",
			},
		},
		Results: []model.CheckResult{
			{
				RuleID:    "U-01",
				Title:     "root 계정 원격 접속 제한",
				Category:  model.CategoryAccount,
				Severity:  model.SeverityHigh,
				Status:    model.StatusPass,
				Summary:   "기준을 충족합니다.",
				Evaluator: "sshd_effective_config",
				Verification: model.Verification{
					State:        model.VerificationVerified,
					Environments: []string{"Rocky Linux 9.8"},
					VerifiedAt:   "2026-07-11T00:00:00Z",
				},
				Reference: model.Reference{
					Guide:   "주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드",
					Section: "Unix 서버",
					Item:    "U-01",
					Pages:   []int{1},
				},
				StartedAt:   startedAt,
				CompletedAt: resultCompletedAt,
				DurationMS:  resultCompletedAt.Sub(startedAt).Milliseconds(),
			},
		},
	}
}
