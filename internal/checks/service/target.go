package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type serviceProduct struct {
	id        string
	label     string
	units     []string
	processes []string
}

type serviceTarget struct {
	product  serviceProduct
	evidence []model.Evidence
	signals  []string
}

func inspectServiceTarget(
	ctx context.Context,
	environment evaluator.Environment,
	label string,
	products []serviceProduct,
	ports []int,
	protocol string,
) (serviceTarget, *evaluator.Outcome) {
	if environment.Platform.InitSystem != "systemd" {
		outcome := evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       fmt.Sprintf("%s 적용 대상을 지원하는 방식으로 확인할 수 없습니다.", label),
			Expected:      "systemd 기반 Linux 환경이 필요합니다.",
			Observed:      environment.Platform.InitSystem,
		}
		return serviceTarget{}, &outcome
	}

	evidence := make([]model.Evidence, 0)
	active := make(map[int]struct{})
	activeUnits := make(map[int]struct{})
	runtimeProducts := make(map[int]struct{})
	signals := make(map[int][]string)
	custom := make(map[int][]string)
	installed := make([]string, 0)
	processOwners := make(map[string]int)
	processNames := make([]string, 0)

	for productIndex, product := range products {
		units, unitEvidence, err := support.InspectUnits(ctx, environment, product.units)
		if err != nil {
			outcome := serviceError("service_target_unit_inspection_failed", label, err)
			return serviceTarget{}, &outcome
		}
		evidence = append(evidence, unitEvidence...)
		for _, unit := range units {
			if support.UnitInstalled(unit) {
				installed = append(installed, unit.Name)
			}
			unitActive := support.UnitActive(unit)
			unitEnabled := support.UnitEnabled(unit)
			if !unitActive && !unitEnabled {
				continue
			}
			active[productIndex] = struct{}{}
			if unitActive {
				activeUnits[productIndex] = struct{}{}
				runtimeProducts[productIndex] = struct{}{}
				signals[productIndex] = append(signals[productIndex], unit.Name+" active")
			}
			if unitEnabled {
				signals[productIndex] = append(signals[productIndex], unit.Name+" enabled")
			}
			if reason := nonStandardUnitReason(unit); reason != "" {
				custom[productIndex] = append(custom[productIndex], reason)
			}
		}
		for _, process := range product.processes {
			if owner, exists := processOwners[process]; exists && owner != productIndex {
				processOwners[process] = -1
			} else if !exists {
				processOwners[process] = productIndex
				processNames = append(processNames, process)
			}
		}
	}

	if len(processNames) > 0 {
		processes, processEvidence, err := support.InspectProcesses(ctx, environment, processNames)
		if err != nil {
			outcome := serviceError("service_target_process_inspection_failed", label, err)
			return serviceTarget{}, &outcome
		}
		evidence = append(evidence, processEvidence)
		for _, process := range processes {
			productIndex := processOwners[process]
			if productIndex < 0 {
				outcome := unsupportedTargetOutcome(label, "여러 제품에서 사용하는 프로세스가 실행 중입니다.", evidence)
				return serviceTarget{}, &outcome
			}
			active[productIndex] = struct{}{}
			runtimeProducts[productIndex] = struct{}{}
			signals[productIndex] = append(signals[productIndex], process+" process running")
			if _, managed := activeUnits[productIndex]; !managed {
				custom[productIndex] = append(custom[productIndex], process+" 프로세스가 표준 활성 unit 밖에서 실행 중임")
			}
		}
	}

	listenerFound := false
	if len(ports) > 0 {
		var (
			listeners        map[int][]string
			listenerEvidence model.Evidence
			err              error
		)
		switch protocol {
		case "tcp":
			listeners, listenerEvidence, err = support.InspectTCPListeningPorts(ctx, environment, ports)
		case "udp":
			listeners, listenerEvidence, err = support.InspectUDPListeningPorts(ctx, environment, ports)
		default:
			listeners, listenerEvidence, err = support.InspectListeningPorts(ctx, environment, ports)
		}
		if err != nil {
			outcome := serviceError("service_target_listener_inspection_failed", label, err)
			return serviceTarget{}, &outcome
		}
		evidence = append(evidence, listenerEvidence)
		for _, lines := range listeners {
			if len(lines) > 0 {
				listenerFound = true
			}
		}
	}

	if len(active) == 0 {
		if listenerFound {
			outcome := unsupportedTargetOutcome(label, "지원 제품과 연결되지 않은 리스닝 포트가 발견되었습니다.", evidence)
			return serviceTarget{}, &outcome
		}
		sort.Strings(installed)
		observed := "활성 unit, 프로세스 및 리스닝 포트가 없습니다."
		if len(installed) > 0 {
			observed = "설치되었지만 비활성인 unit: " + strings.Join(installed, ", ")
		}
		outcome := evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  fmt.Sprintf("사용 중인 %s 구성요소가 없습니다.", label),
			Expected: fmt.Sprintf("활성 %s 서비스에만 이 점검을 적용합니다.", label),
			Observed: observed,
			Evidence: evidence,
		}
		return serviceTarget{}, &outcome
	}
	if len(active) != 1 {
		outcome := unsupportedTargetOutcome(label, "둘 이상의 제품이 동시에 활성화되어 단일 실효 설정을 확정할 수 없습니다.", evidence)
		return serviceTarget{}, &outcome
	}

	productIndex := -1
	for index := range active {
		productIndex = index
	}
	if listenerFound {
		if _, running := runtimeProducts[productIndex]; !running {
			outcome := unsupportedTargetOutcome(label, "부팅 활성 unit은 있으나 현재 리스너의 제품을 해당 unit과 연결할 수 없습니다.", evidence)
			return serviceTarget{}, &outcome
		}
	}
	if reasons := custom[productIndex]; len(reasons) > 0 {
		sort.Strings(reasons)
		outcome := unsupportedTargetOutcome(label, strings.Join(reasons, "; "), evidence)
		return serviceTarget{}, &outcome
	}
	sort.Strings(signals[productIndex])
	return serviceTarget{
		product:  products[productIndex],
		evidence: evidence,
		signals:  signals[productIndex],
	}, nil
}

func nonStandardUnitReason(unit support.UnitState) string {
	fragment := strings.ReplaceAll(strings.TrimSpace(unit.FragmentPath), "\\", "/")
	if fragment == "" || (!strings.HasPrefix(fragment, "/usr/lib/systemd/system/") && !strings.HasPrefix(fragment, "/lib/systemd/system/")) {
		return unit.Name + " unit이 표준 벤더 경로에서 로드되지 않음"
	}
	if strings.TrimSpace(unit.DropInPaths) != "" {
		return unit.Name + " unit에 drop-in 재정의가 있음"
	}
	return ""
}

func unsupportedTargetOutcome(label, observed string, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       fmt.Sprintf("%s 제품과 실행 구성을 결정적으로 식별하지 못했습니다.", label),
		Expected:      "지원하는 표준 제품의 전체 실효 설정을 확인할 수 있어야 합니다.",
		Observed:      observed,
		Evidence:      evidence,
	}
}
