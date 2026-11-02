package evaluator

import (
	"context"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestCollectedFileMetadataRemainsVisibleWithoutFileContents(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("test.evaluator", func(context.Context, model.ResolvedRule, Environment) Outcome {
		return Outcome{
			Status: model.StatusFail, Observed: "허용되지 않은 권한 비트 0040",
			Evidence: []model.Evidence{{Kind: model.EvidenceFile, Source: "/etc/example", File: &model.FileEvidence{
				Path: "/etc/example", Owner: "0", Group: "0", Mode: "-rw-r-----", Content: "secret file content",
			}}},
		}
	}); err != nil {
		t.Fatal(err)
	}
	result := registry.Evaluate(context.Background(), testResolvedRule(model.VerificationVerified), Environment{})
	if result.Status != model.StatusFail || len(result.DisplayDetails) != 2 {
		t.Fatalf("result = %#v", result)
	}
	file := result.DisplayDetails[1]
	for _, expected := range []string{"소유자=0", "그룹=0", "권한=-rw-r-----"} {
		if !strings.Contains(file.Current, expected) {
			t.Errorf("metadata missing %q: %#v", expected, file)
		}
	}
	if file.Source != "/etc/example" || strings.Contains(file.Current, "secret file content") {
		t.Fatalf("unexpected file details: %#v", file)
	}
}

func TestCollectedFileMetadataDeduplicatesAndBoundsOutput(t *testing.T) {
	var evidence []model.Evidence
	for index := 0; index < 40; index++ {
		path := "/etc/" + string(rune('A'+index))
		evidence = append(evidence, model.Evidence{Kind: model.EvidenceFile, File: &model.FileEvidence{Path: path, Mode: "-rw-------"}})
	}
	evidence = append(evidence, evidence[0])
	details := fileMetadataDetails(evidence)
	if len(details) != 33 || !strings.Contains(details[32].Current, "8개") {
		t.Fatalf("bounded file details = %#v", details)
	}
}
