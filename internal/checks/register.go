package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/account"
	filecheck "github.com/yesidodo73/OpenCIIP/internal/checks/file"
	"github.com/yesidodo73/OpenCIIP/internal/checks/logging"
	"github.com/yesidodo73/OpenCIIP/internal/checks/network"
	patchcheck "github.com/yesidodo73/OpenCIIP/internal/checks/patch"
	"github.com/yesidodo73/OpenCIIP/internal/checks/service"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type implementationSource struct {
	name            string
	implementations map[string]evaluator.Func
}

func RegisterAll(registry *evaluator.Registry, evaluatorIDs []string) error {
	if registry == nil {
		return fmt.Errorf("evaluator registry is required")
	}

	catalog := make(map[string]int, len(evaluatorIDs))
	for index, rawID := range evaluatorIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return fmt.Errorf("catalog evaluator id at index %d is empty", index)
		}
		if id != rawID {
			return fmt.Errorf("catalog evaluator id %q at index %d has surrounding whitespace", rawID, index)
		}
		if previousIndex, duplicate := catalog[id]; duplicate {
			return fmt.Errorf("catalog evaluator id %q is duplicated at indexes %d and %d", id, previousIndex, index)
		}
		catalog[id] = index
	}

	sources := []implementationSource{
		{name: "account", implementations: account.Implementations()},
		{name: "file", implementations: filecheck.Implementations()},
		{name: "service", implementations: service.Implementations()},
		{name: "logging", implementations: logging.Implementations()},
		{name: "network", implementations: network.Implementations()},
		{name: "patch", implementations: patchcheck.Implementations()},
	}
	implementations := make(map[string]evaluator.Func, len(catalog))
	implementationSources := make(map[string]string, len(catalog))
	for _, source := range sources {
		ids := make([]string, 0, len(source.implementations))
		for id := range source.implementations {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			implementation := source.implementations[id]
			if id == "" || strings.TrimSpace(id) != id {
				return fmt.Errorf("%s implementation has invalid evaluator id %q", source.name, id)
			}
			if implementation == nil {
				return fmt.Errorf("%s implementation for evaluator %q is nil", source.name, id)
			}
			if _, exists := catalog[id]; !exists {
				return fmt.Errorf("%s implementation has orphan evaluator id %q", source.name, id)
			}
			if previousSource, duplicate := implementationSources[id]; duplicate {
				return fmt.Errorf("evaluator id %q is implemented by both %s and %s", id, previousSource, source.name)
			}
			implementations[id] = implementation
			implementationSources[id] = source.name
		}
	}

	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
		if _, implemented := implementations[id]; !implemented {
			implementations[id] = pendingImplementation
		}
	}
	sort.Strings(ids)

	registeredIDs := registry.IDs()
	registered := make(map[string]struct{}, len(registeredIDs))
	for _, id := range registeredIDs {
		registered[id] = struct{}{}
	}
	for _, id := range ids {
		if _, duplicate := registered[id]; duplicate {
			return fmt.Errorf("register evaluator %s: evaluator is already registered", id)
		}
	}

	for _, id := range ids {
		if err := registry.Register(id, implementations[id]); err != nil {
			return fmt.Errorf("register evaluator %s: %w", id, err)
		}
	}
	return nil
}

func pendingImplementation(_ context.Context, rule model.ResolvedRule, _ evaluator.Environment) evaluator.Outcome {
	reason := model.UnknownUnsupportedConfiguration
	summary := "이 점검 항목의 자동 판정 구현이 아직 준비되지 않았습니다."
	observed := "지원되는 자동 수집 및 판정 구현이 없습니다."
	if rule.Criteria.ManualReviewRequired {
		reason = model.UnknownManualVerification
		summary = "정책과 운영 상황을 확인해야 하므로 평가자의 수동 판단이 필요합니다."
		observed = "자동 판정에 필요한 조직 정책 또는 운영 근거가 제공되지 않았습니다."
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: reason,
		Summary:       summary,
		Expected:      rule.Criteria.Pass,
		Observed:      observed,
	}
}
