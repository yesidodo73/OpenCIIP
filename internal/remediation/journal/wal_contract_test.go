package journal

import (
	"bufio"
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestWALHashChainAcceptsCanonicalStateTransitions(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	approved := testApprovedJournal(t, initial)
	first, err := makeRecord(initial, "")
	if err != nil {
		t.Fatalf("makeRecord(initial) error = %v", err)
	}
	second, err := makeRecord(approved, first.Digest)
	if err != nil {
		t.Fatalf("makeRecord(approved) error = %v", err)
	}

	firstLine, err := CanonicalJSON(first)
	if err != nil {
		t.Fatalf("CanonicalJSON(first) error = %v", err)
	}
	decodedFirst, err := decodeAndValidateRecord(firstLine, initial.RunID, WALRecord{}, 0)
	if err != nil {
		t.Fatalf("decodeAndValidateRecord(first) error = %v", err)
	}
	secondLine, err := CanonicalJSON(second)
	if err != nil {
		t.Fatalf("CanonicalJSON(second) error = %v", err)
	}
	decodedSecond, err := decodeAndValidateRecord(secondLine, initial.RunID, decodedFirst, 1)
	if err != nil {
		t.Fatalf("decodeAndValidateRecord(second) error = %v", err)
	}
	if decodedSecond.Revision != 2 || decodedSecond.PreviousDigest != decodedFirst.Digest {
		t.Fatalf("decoded second record = revision %d previous %q, want revision 2 linked to %q", decodedSecond.Revision, decodedSecond.PreviousDigest, decodedFirst.Digest)
	}
}

func TestWALHashChainRejectsSelfConsistentRecordLinkedToWrongParent(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	approved := testApprovedJournal(t, initial)
	first, err := makeRecord(initial, "")
	if err != nil {
		t.Fatalf("makeRecord(initial) error = %v", err)
	}
	second, err := makeRecord(approved, first.Digest)
	if err != nil {
		t.Fatalf("makeRecord(approved) error = %v", err)
	}
	second.PreviousDigest = strings.Repeat("f", 64)
	second.Digest, err = recordDigest(second)
	if err != nil {
		t.Fatalf("recordDigest(second) error = %v", err)
	}
	line, err := CanonicalJSON(second)
	if err != nil {
		t.Fatalf("CanonicalJSON(second) error = %v", err)
	}

	_, err = decodeAndValidateRecord(line, initial.RunID, first, 1)
	if CodeOf(err) != CodeCorruptWAL {
		t.Fatalf("decodeAndValidateRecord() error = %v, want %s", err, CodeCorruptWAL)
	}
}

func TestWALRejectsCanonicalPayloadTamperingWithoutDigestUpdate(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	record, err := makeRecord(initial, "")
	if err != nil {
		t.Fatalf("makeRecord() error = %v", err)
	}
	record.Journal.Warnings = []string{"tampered after signing"}
	line, err := CanonicalJSON(record)
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}

	_, err = decodeAndValidateRecord(line, initial.RunID, WALRecord{}, 0)
	if CodeOf(err) != CodeCorruptWAL {
		t.Fatalf("decodeAndValidateRecord() error = %v, want %s", err, CodeCorruptWAL)
	}
}

func TestWALRejectsNonCanonicalEncodingEvenWhenJSONIsEquivalent(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	record, err := makeRecord(initial, "")
	if err != nil {
		t.Fatalf("makeRecord() error = %v", err)
	}
	canonical, err := CanonicalJSON(record)
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	nonCanonical := append([]byte(" "), canonical...)

	_, err = decodeAndValidateRecord(nonCanonical, initial.RunID, WALRecord{}, 0)
	if CodeOf(err) != CodeCorruptWAL {
		t.Fatalf("decodeAndValidateRecord() error = %v, want %s", err, CodeCorruptWAL)
	}
}

func TestReadWALLineDistinguishesCompleteRecordFromIncompleteTail(t *testing.T) {
	t.Parallel()

	reader := bufio.NewReaderSize(bytes.NewBufferString("{\"revision\":1}\n{\"revision\":"), 8)
	line, complete, consumed, err := readWALLine(reader)
	if err != nil {
		t.Fatalf("readWALLine(first) error = %v", err)
	}
	if string(line) != "{\"revision\":1}" || !complete || consumed != len("{\"revision\":1}\n") {
		t.Fatalf("first line = %q complete=%t consumed=%d, want one complete record", line, complete, consumed)
	}
	line, complete, consumed, err = readWALLine(reader)
	if err != nil {
		t.Fatalf("readWALLine(tail) error = %v", err)
	}
	if string(line) != "{\"revision\":" || complete || consumed != len("{\"revision\":") {
		t.Fatalf("tail = %q complete=%t consumed=%d, want an incomplete final record", line, complete, consumed)
	}
}

func TestValidateTransitionAllowsApprovalWithoutPlanMutation(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	approved := testApprovedJournal(t, initial)
	if err := ValidateTransition(&initial, &approved); err != nil {
		t.Fatalf("ValidateTransition() error = %v", err)
	}
}

func TestValidateTransitionRejectsUnsafeOrNonMonotonicChanges(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	tests := []struct {
		name   string
		mutate func(*model.RemediationJournal)
	}{
		{
			name: "revision gap",
			mutate: func(next *model.RemediationJournal) {
				next.Revision = 3
			},
		},
		{
			name: "timestamp does not advance",
			mutate: func(next *model.RemediationJournal) {
				next.UpdatedAt = initial.UpdatedAt
			},
		},
		{
			name: "invalid run state jump",
			mutate: func(next *model.RemediationJournal) {
				next.State = model.RunApplying
			},
		},
		{
			name: "platform identity changes",
			mutate: func(next *model.RemediationJournal) {
				next.Platform.VersionID = "9.9"
			},
		},
		{
			name: "approved desired state changes",
			mutate: func(next *model.RemediationJournal) {
				next.ChangeSets[0].Operations[0].Desired.File.Mode = 0o640
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			next := testApprovedJournal(t, initial)
			test.mutate(&next)
			if err := next.Validate(); err != nil {
				t.Fatalf("test fixture became invalid before transition validation: %v", err)
			}
			err := ValidateTransition(&initial, &next)
			if CodeOf(err) != CodeInvalidTransition {
				t.Fatalf("ValidateTransition() error = %v, want %s", err, CodeInvalidTransition)
			}
		})
	}
}

func TestValidateTransitionPreservesPreviouslyDurablePlanSlices(t *testing.T) {
	t.Parallel()

	initial := testInitialJournal(t)
	approved := testApprovedJournal(t, initial)
	aliasKeys := []string{"file:/etc/hosts-alias"}
	approved.ChangeSets[0].Resources[0].AliasKeys = append([]string(nil), aliasKeys...)
	operation := &approved.ChangeSets[0].Operations[0]
	operation.Resource.AliasKeys = append([]string(nil), aliasKeys...)
	operation.ExpectedBefore.Reference.AliasKeys = append([]string(nil), aliasKeys...)
	operation.Desired.Reference.AliasKeys = append([]string(nil), aliasKeys...)
	if err := approved.Validate(); err != nil {
		t.Fatalf("mutated fixture Validate() error = %v", err)
	}
	err := ValidateTransition(&initial, &approved)
	if CodeOf(err) != CodeInvalidTransition {
		t.Fatalf("ValidateTransition() error = %v, want %s for changed resource identity", err, CodeInvalidTransition)
	}
}

func testInitialJournal(t *testing.T) model.RemediationJournal {
	t.Helper()

	startedAt := time.Date(2026, time.July, 11, 0, 0, 0, 0, time.UTC)
	resource := model.CanonicalResource{
		Reference: model.ResourceRef{Kind: model.ResourceFile, ID: "/etc/hosts"},
		Key:       "file:/etc/hosts",
	}
	beforeFile := &model.FileSnapshot{
		Path:         "/etc/hosts",
		Exists:       true,
		FileType:     "regular",
		Mode:         0o644,
		UID:          1000,
		GID:          1000,
		Size:         16,
		SHA256:       strings.Repeat("1", 64),
		Device:       11,
		Inode:        22,
		NLink:        1,
		ParentDevice: 11,
		ParentInode:  2,
		CapturedAt:   startedAt,
	}
	desiredFile := *beforeFile
	desiredFile.Mode = 0o600
	desiredFile.UID = 0
	before := model.ResourceSnapshot{
		Reference:   resource,
		Fingerprint: strings.Repeat("2", 64),
		File:        beforeFile,
	}
	desired := model.ResourceSnapshot{
		Reference:   resource,
		Fingerprint: strings.Repeat("3", 64),
		File:        &desiredFile,
	}
	planDigest := strings.Repeat("4", 64)
	journal := model.RemediationJournal{
		SchemaVersion:   model.RemediationSchemaVersion,
		Revision:        1,
		RunID:           "run-contract-1",
		ScanRunID:       "scan-contract-1",
		ScanToolVersion: "1.0.0",
		ScanToolCommit:  "commit-1",
		RuleSetVersion:  "sha256:" + strings.Repeat("5", 64),
		Platform: model.PlatformInfo{
			OS:                 "linux",
			Family:             "rhel",
			ID:                 "rocky",
			VersionID:          "9.8",
			Architecture:       "amd64",
			ScanSupport:        model.ScanSupportTested,
			RemediationSupport: model.RemediationSupportVerified,
		},
		RemediationBuild: model.RemediationBuildIdentity{
			Version:          "1.0.0",
			Commit:           "commit-1",
			ExecutableSHA256: strings.Repeat("6", 64),
		},
		State:         model.RunPlanned,
		FailurePolicy: model.FailureRollbackItem,
		PlanDigest:    planDigest,
		Host: model.HostIdentity{
			MachineIDHash: strings.Repeat("7", 64),
			SystemRoot:    "/",
			RootDevice:    11,
			RootInode:     2,
			BootID:        "12345678-1234-1234-1234-123456789abc",
		},
		StartedAt: startedAt,
		UpdatedAt: startedAt,
		ChangeSets: []model.ChangeSet{
			{
				ID:     "change-1",
				RuleID: "U-19",
				RuleIdentity: model.RemediationRuleIdentity{
					ID:        "U-19",
					Title:     "hosts file permissions",
					Category:  model.CategoryFileDirectory,
					Severity:  model.SeverityHigh,
					Evaluator: "unix.file.hosts_permissions",
					Verification: model.Verification{
						State:        model.VerificationVerified,
						Environments: []string{"Rocky Linux 9.8 amd64"},
						VerifiedAt:   "2026-07-11T00:00:00Z",
					},
					BindingSources: []string{"linux-common", "rocky-linux-9.8-amd64"},
					Reference: model.Reference{
						Guide: "2026 test guide",
						Item:  "U-19",
						Pages: []int{1},
					},
				},
				RecipeIdentity: model.RemediationRecipeIdentity{
					ID:               "rocky-hosts-file-metadata",
					Selector:         model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
					DefinitionSHA256: strings.Repeat("8", 64),
				},
				Sequence:       1,
				Risk:           model.RiskSafe,
				State:          model.ChangePlanned,
				Resources:      []model.CanonicalResource{resource},
				DryRun:         "change file metadata",
				ExpectedImpact: "metadata only",
				Operations: []model.OperationRecord{
					{
						ID:               "operation-1",
						Sequence:         1,
						RollbackSequence: 1,
						Kind:             model.OperationFileMetadata,
						RecoveryMode:     model.RecoveryStateInferable,
						State:            model.OperationPlanned,
						Resource:         resource,
						ExpectedBefore:   before,
						Desired:          desired,
					},
				},
			},
		},
		ConflictGraph: model.ConflictGraph{
			Nodes: []string{"change-1"},
			Edges: []model.ConflictEdge{},
		},
	}
	if err := journal.Validate(); err != nil {
		t.Fatalf("test initial journal Validate() error = %v", err)
	}
	if err := validateInitialJournal(&journal); err != nil {
		t.Fatalf("test initial journal contract error = %v", err)
	}
	return journal
}

func testApprovedJournal(t *testing.T, initial model.RemediationJournal) model.RemediationJournal {
	t.Helper()

	clone, err := cloneJournal(&initial)
	if err != nil {
		t.Fatalf("cloneJournal() error = %v", err)
	}
	approvedAt := initial.UpdatedAt.Add(time.Minute)
	clone.Revision = initial.Revision + 1
	clone.UpdatedAt = approvedAt
	clone.State = model.RunApproved
	clone.ChangeSets[0].Approval = &model.Approval{
		Source:     "contract-test",
		PlanDigest: clone.PlanDigest,
		ApprovedAt: approvedAt,
	}
	if err := clone.Validate(); err != nil {
		t.Fatalf("test approved journal Validate() error = %v", err)
	}
	if reflect.DeepEqual(clone, &initial) {
		t.Fatal("approved journal fixture unexpectedly equals the initial journal")
	}
	return *clone
}
