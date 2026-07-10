package checks

import (
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
)

func TestRegisterAllRejectsCatalogEvaluatorWithoutImplementation(t *testing.T) {
	bundle, loadErr := rules.LoadDefaults()
	if loadErr != nil {
		t.Fatalf("rules.LoadDefaults() error = %v", loadErr)
	}
	evaluatorIDs := append(bundle.EvaluatorIDs(), "fixture.missing")
	err := RegisterAll(evaluator.NewRegistry(), evaluatorIDs)
	if err == nil || !strings.Contains(err.Error(), "fixture.missing") {
		t.Fatalf("RegisterAll() error = %v, want missing implementation", err)
	}
}

func TestRegisterAllCoversEveryDefaultCatalogEvaluator(t *testing.T) {
	bundle, err := rules.LoadDefaults()
	if err != nil {
		t.Fatalf("rules.LoadDefaults() error = %v", err)
	}
	if err := RegisterAll(evaluator.NewRegistry(), bundle.EvaluatorIDs()); err != nil {
		t.Fatalf("RegisterAll(defaults) error = %v", err)
	}
}
