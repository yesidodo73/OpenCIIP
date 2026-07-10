package conflict

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type Planner struct{}

type edgeKey struct {
	from   string
	to     string
	reason model.ConflictReason
}

type rollbackUnit struct {
	id      string
	members []string
	maxSeq  int
}

func Validate(graph model.ConflictGraph) error {
	return validateGraph(graph)
}

func (Planner) Build(changeSets []model.ChangeSet) (model.ConflictGraph, error) {
	return Build(changeSets)
}

func Build(changeSets []model.ChangeSet) (model.ConflictGraph, error) {
	if len(changeSets) == 0 {
		return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, Underlying: fmt.Errorf("at least one change set is required")}
	}
	ordered := append([]model.ChangeSet(nil), changeSets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Sequence == ordered[j].Sequence {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Sequence < ordered[j].Sequence
	})

	byID := make(map[string]model.ChangeSet, len(ordered))
	sequences := make(map[int]string, len(ordered))
	groups := make(map[string][]string)
	graph := model.ConflictGraph{Nodes: make([]string, 0, len(ordered))}
	for _, changeSet := range ordered {
		if strings.TrimSpace(changeSet.ID) == "" || changeSet.Sequence < 1 {
			return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Underlying: fmt.Errorf("change set id and positive sequence are required")}
		}
		if _, exists := byID[changeSet.ID]; exists {
			return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Underlying: fmt.Errorf("duplicate change set id")}
		}
		if previous, exists := sequences[changeSet.Sequence]; exists {
			return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Affected: []string{previous}, Underlying: fmt.Errorf("duplicate sequence %d", changeSet.Sequence)}
		}
		if len(changeSet.Resources) == 0 {
			return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Underlying: fmt.Errorf("change set has no resources")}
		}
		for _, resource := range changeSet.Resources {
			if err := resource.Validate(); err != nil {
				return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Underlying: err}
			}
		}
		byID[changeSet.ID] = changeSet
		sequences[changeSet.Sequence] = changeSet.ID
		graph.Nodes = append(graph.Nodes, changeSet.ID)
		if changeSet.RollbackGroup != "" {
			groups[changeSet.RollbackGroup] = append(groups[changeSet.RollbackGroup], changeSet.ID)
		}
	}

	edges := make(map[edgeKey]map[string]struct{})
	addEdge := func(from, to string, reason model.ConflictReason, resource string) {
		key := edgeKey{from: from, to: to, reason: reason}
		resources, exists := edges[key]
		if !exists {
			resources = make(map[string]struct{})
			edges[key] = resources
		}
		if resource != "" {
			resources[resource] = struct{}{}
		}
	}

	lastWriter := make(map[string]string)
	for _, changeSet := range ordered {
		seenKeys := make(map[string]string)
		for _, resource := range changeSet.Resources {
			for _, key := range resource.Keys() {
				if previousResource, exists := seenKeys[key]; exists {
					if previousResource != resource.Key {
						return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Affected: []string{previousResource, resource.Key}, Underlying: fmt.Errorf("resources share canonical key %s", key)}
					}
					continue
				}
				seenKeys[key] = resource.Key
				if previous, exists := lastWriter[key]; exists && previous != changeSet.ID {
					addEdge(previous, changeSet.ID, model.ConflictSharedResource, key)
				}
				lastWriter[key] = changeSet.ID
			}
		}
	}

	for _, changeSet := range ordered {
		seenDependencies := make(map[string]struct{}, len(changeSet.DependsOn))
		for _, dependency := range changeSet.DependsOn {
			if _, exists := byID[dependency]; !exists {
				return model.ConflictGraph{}, &Error{Code: CodeUnknownChangeSet, ChangeSet: changeSet.ID, Affected: []string{dependency}}
			}
			if dependency == changeSet.ID {
				return model.ConflictGraph{}, &Error{Code: CodeDependencyCycle, ChangeSet: changeSet.ID, Affected: []string{changeSet.ID}}
			}
			if byID[dependency].Sequence >= changeSet.Sequence {
				return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Affected: []string{dependency}, Underlying: fmt.Errorf("dependency must have a lower apply sequence")}
			}
			if _, exists := seenDependencies[dependency]; exists {
				return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, ChangeSet: changeSet.ID, Affected: []string{dependency}, Underlying: fmt.Errorf("duplicate dependency")}
			}
			seenDependencies[dependency] = struct{}{}
			addEdge(dependency, changeSet.ID, model.ConflictExplicitDependency, "")
		}
	}

	graph.Edges = materializeEdges(edges, sequenceMap(ordered))
	groupIDs := make([]string, 0, len(groups))
	for groupID := range groups {
		groupIDs = append(groupIDs, groupID)
	}
	sort.Strings(groupIDs)
	for _, groupID := range groupIDs {
		members := groups[groupID]
		sort.SliceStable(members, func(i, j int) bool {
			left := byID[members[i]].Sequence
			right := byID[members[j]].Sequence
			if left == right {
				return members[i] < members[j]
			}
			return left < right
		})
		graph.Groups = append(graph.Groups, model.RollbackGroupEntry{ID: groupID, ChangeSets: members})
	}
	if err := graph.Validate(); err != nil {
		return model.ConflictGraph{}, &Error{Code: CodeInvalidInput, Underlying: err}
	}
	if err := validateAcyclic(graph, false); err != nil {
		return model.ConflictGraph{}, err
	}
	if err := validateAcyclic(graph, true); err != nil {
		return model.ConflictGraph{}, err
	}
	return graph, nil
}

func (Planner) ItemRollbackClosure(graph model.ConflictGraph, target string, active map[string]bool, cascade bool) ([]string, error) {
	return ItemRollbackClosure(graph, target, active, cascade)
}

func ItemRollbackClosure(graph model.ConflictGraph, target string, active map[string]bool, cascade bool) ([]string, error) {
	if err := validateGraph(graph); err != nil {
		return nil, err
	}
	if !contains(graph.Nodes, target) {
		return nil, &Error{Code: CodeUnknownChangeSet, ChangeSet: target}
	}
	isActive := func(id string) bool {
		if active == nil {
			return true
		}
		return active[id]
	}
	if !isActive(target) {
		return nil, &Error{Code: CodeInvalidInput, ChangeSet: target, Underlying: fmt.Errorf("target change set is not active")}
	}

	groupMembers := groupMembership(graph)
	adjacency := make(map[string][]string, len(graph.Nodes))
	for _, edge := range graph.Edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}
	closure := map[string]struct{}{target: {}}
	visited := map[string]struct{}{target: {}}
	queue := []string{target}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, candidate := range groupMembers[current] {
			closure[candidate] = struct{}{}
			if _, exists := visited[candidate]; !exists {
				visited[candidate] = struct{}{}
				queue = append(queue, candidate)
			}
		}
		for _, candidate := range adjacency[current] {
			if isActive(candidate) {
				closure[candidate] = struct{}{}
			}
			if _, exists := visited[candidate]; !exists {
				visited[candidate] = struct{}{}
				queue = append(queue, candidate)
			}
		}
	}
	result := orderedSubset(graph.Nodes, closure)
	if !cascade && len(result) > 1 {
		affected := make([]string, 0, len(result)-1)
		for _, id := range result {
			if id != target {
				affected = append(affected, id)
			}
		}
		return nil, &Error{Code: CodeRollbackConflict, ChangeSet: target, Affected: affected}
	}
	return result, nil
}

func (Planner) ReverseRollbackOrder(graph model.ConflictGraph, targets []string, sequences map[string]int) ([]string, error) {
	return ReverseRollbackOrder(graph, targets, sequences)
}

func ReverseRollbackOrder(graph model.ConflictGraph, targets []string, sequences map[string]int) ([]string, error) {
	if err := validateGraph(graph); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		targets = append([]string(nil), graph.Nodes...)
	}
	targetSet := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if !contains(graph.Nodes, target) {
			return nil, &Error{Code: CodeUnknownChangeSet, ChangeSet: target}
		}
		targetSet[target] = struct{}{}
	}
	if err := requireCompleteGroups(graph, targetSet); err != nil {
		return nil, err
	}
	sequence := resolvedSequences(graph.Nodes, sequences)
	units, nodeUnit := makeRollbackUnits(graph, targetSet, sequence)
	unitByID := make(map[string]*rollbackUnit, len(units))
	outgoing := make(map[string]map[string]struct{}, len(units))
	incoming := make(map[string]map[string]struct{}, len(units))
	for index := range units {
		unit := &units[index]
		unitByID[unit.id] = unit
		outgoing[unit.id] = make(map[string]struct{})
		incoming[unit.id] = make(map[string]struct{})
	}
	for _, edge := range graph.Edges {
		if _, include := targetSet[edge.From]; !include {
			continue
		}
		if _, include := targetSet[edge.To]; !include {
			continue
		}
		from := nodeUnit[edge.From]
		to := nodeUnit[edge.To]
		if from == to {
			continue
		}
		outgoing[from][to] = struct{}{}
		incoming[to][from] = struct{}{}
	}

	ready := make([]string, 0)
	for _, unit := range units {
		if len(outgoing[unit.id]) == 0 {
			ready = append(ready, unit.id)
		}
	}
	order := make([]string, 0, len(targetSet))
	processed := 0
	for len(ready) > 0 {
		sort.SliceStable(ready, func(i, j int) bool {
			left := unitByID[ready[i]]
			right := unitByID[ready[j]]
			if left.maxSeq == right.maxSeq {
				return left.id < right.id
			}
			return left.maxSeq > right.maxSeq
		})
		currentID := ready[0]
		ready = ready[1:]
		current := unitByID[currentID]
		sort.SliceStable(current.members, func(i, j int) bool {
			if sequence[current.members[i]] == sequence[current.members[j]] {
				return current.members[i] < current.members[j]
			}
			return sequence[current.members[i]] > sequence[current.members[j]]
		})
		order = append(order, current.members...)
		processed++
		for predecessor := range incoming[currentID] {
			delete(outgoing[predecessor], currentID)
			if len(outgoing[predecessor]) == 0 {
				ready = append(ready, predecessor)
			}
		}
	}
	if processed != len(units) {
		return nil, &Error{Code: CodeDependencyCycle, Affected: append([]string(nil), targets...)}
	}
	return order, nil
}

func FullRollbackOrder(graph model.ConflictGraph, sequences map[string]int) ([]string, error) {
	return ReverseRollbackOrder(graph, graph.Nodes, sequences)
}

func (Planner) BlockedPredecessors(graph model.ConflictGraph, failed string, pending map[string]bool) []string {
	return BlockedPredecessors(graph, failed, pending)
}

func BlockedPredecessors(graph model.ConflictGraph, failed string, pending map[string]bool) []string {
	if !contains(graph.Nodes, failed) {
		return nil
	}
	reverse := make(map[string][]string, len(graph.Nodes))
	for _, edge := range graph.Edges {
		reverse[edge.To] = append(reverse[edge.To], edge.From)
	}
	groupMembers := groupMembership(graph)
	blocked := make(map[string]struct{})
	queue := []string{failed}
	seen := map[string]struct{}{failed: {}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		candidates := append([]string(nil), reverse[current]...)
		candidates = append(candidates, groupMembers[current]...)
		for _, candidate := range candidates {
			if _, exists := seen[candidate]; exists {
				continue
			}
			seen[candidate] = struct{}{}
			queue = append(queue, candidate)
			if pending == nil || pending[candidate] {
				blocked[candidate] = struct{}{}
			}
		}
	}
	return orderedSubset(graph.Nodes, blocked)
}

func materializeEdges(edges map[edgeKey]map[string]struct{}, sequences map[string]int) []model.ConflictEdge {
	result := make([]model.ConflictEdge, 0, len(edges))
	for key, resourceSet := range edges {
		resources := make([]string, 0, len(resourceSet))
		for resource := range resourceSet {
			resources = append(resources, resource)
		}
		sort.Strings(resources)
		result = append(result, model.ConflictEdge{
			From:      key.from,
			To:        key.to,
			Reason:    key.reason,
			Resources: resources,
		})
	}
	sort.SliceStable(result, func(i, j int) bool {
		left := result[i]
		right := result[j]
		if sequences[left.From] != sequences[right.From] {
			return sequences[left.From] < sequences[right.From]
		}
		if sequences[left.To] != sequences[right.To] {
			return sequences[left.To] < sequences[right.To]
		}
		if left.Reason != right.Reason {
			return left.Reason < right.Reason
		}
		return strings.Join(left.Resources, "\x00") < strings.Join(right.Resources, "\x00")
	})
	return result
}

func validateGraph(graph model.ConflictGraph) error {
	if err := graph.Validate(); err != nil {
		return &Error{Code: CodeInvalidInput, Underlying: err}
	}
	if err := validateAcyclic(graph, false); err != nil {
		return err
	}
	if err := validateAcyclic(graph, true); err != nil {
		return err
	}
	return nil
}

func validateAcyclic(graph model.ConflictGraph, collapseGroups bool) error {
	representative := make(map[string]string, len(graph.Nodes))
	for _, node := range graph.Nodes {
		representative[node] = "node:" + node
	}
	if collapseGroups {
		for _, group := range graph.Groups {
			for _, member := range group.ChangeSets {
				representative[member] = "group:" + group.ID
			}
		}
	}
	nodes := make(map[string]struct{})
	for _, rep := range representative {
		nodes[rep] = struct{}{}
	}
	adjacency := make(map[string]map[string]struct{}, len(nodes))
	indegree := make(map[string]int, len(nodes))
	for node := range nodes {
		adjacency[node] = make(map[string]struct{})
	}
	for _, edge := range graph.Edges {
		from := representative[edge.From]
		to := representative[edge.To]
		if from == to {
			continue
		}
		if _, exists := adjacency[from][to]; exists {
			continue
		}
		adjacency[from][to] = struct{}{}
		indegree[to]++
	}
	ready := make([]string, 0)
	for node := range nodes {
		if indegree[node] == 0 {
			ready = append(ready, node)
		}
	}
	visited := 0
	for len(ready) > 0 {
		current := ready[len(ready)-1]
		ready = ready[:len(ready)-1]
		visited++
		for child := range adjacency[current] {
			indegree[child]--
			if indegree[child] == 0 {
				ready = append(ready, child)
			}
		}
	}
	if visited != len(nodes) {
		return &Error{Code: CodeDependencyCycle, Affected: append([]string(nil), graph.Nodes...)}
	}
	return nil
}

func requireCompleteGroups(graph model.ConflictGraph, targets map[string]struct{}) error {
	for _, group := range graph.Groups {
		included := 0
		for _, member := range group.ChangeSets {
			if _, exists := targets[member]; exists {
				included++
			}
		}
		if included > 0 && included != len(group.ChangeSets) {
			return &Error{Code: CodeIncompleteGroup, Affected: append([]string(nil), group.ChangeSets...)}
		}
	}
	return nil
}

func makeRollbackUnits(graph model.ConflictGraph, targets map[string]struct{}, sequences map[string]int) ([]rollbackUnit, map[string]string) {
	groupForNode := make(map[string]string)
	for _, group := range graph.Groups {
		for _, member := range group.ChangeSets {
			groupForNode[member] = group.ID
		}
	}
	unitsByID := make(map[string]*rollbackUnit)
	nodeUnit := make(map[string]string, len(targets))
	for _, node := range graph.Nodes {
		if _, include := targets[node]; !include {
			continue
		}
		unitID := "node:" + node
		if groupID := groupForNode[node]; groupID != "" {
			unitID = "group:" + groupID
		}
		unit, exists := unitsByID[unitID]
		if !exists {
			unit = &rollbackUnit{id: unitID}
			unitsByID[unitID] = unit
		}
		unit.members = append(unit.members, node)
		if sequences[node] > unit.maxSeq {
			unit.maxSeq = sequences[node]
		}
		nodeUnit[node] = unitID
	}
	unitIDs := make([]string, 0, len(unitsByID))
	for unitID := range unitsByID {
		unitIDs = append(unitIDs, unitID)
	}
	sort.Strings(unitIDs)
	units := make([]rollbackUnit, 0, len(unitIDs))
	for _, unitID := range unitIDs {
		units = append(units, *unitsByID[unitID])
	}
	return units, nodeUnit
}

func groupMembership(graph model.ConflictGraph) map[string][]string {
	result := make(map[string][]string)
	for _, group := range graph.Groups {
		for _, member := range group.ChangeSets {
			for _, peer := range group.ChangeSets {
				if peer != member {
					result[member] = append(result[member], peer)
				}
			}
		}
	}
	return result
}

func sequenceMap(changeSets []model.ChangeSet) map[string]int {
	result := make(map[string]int, len(changeSets))
	for _, changeSet := range changeSets {
		result[changeSet.ID] = changeSet.Sequence
	}
	return result
}

func resolvedSequences(nodes []string, provided map[string]int) map[string]int {
	result := make(map[string]int, len(nodes))
	for index, node := range nodes {
		sequence := index + 1
		if provided != nil && provided[node] > 0 {
			sequence = provided[node]
		}
		result[node] = sequence
	}
	return result
}

func orderedSubset(order []string, selected map[string]struct{}) []string {
	result := make([]string, 0, len(selected))
	for _, id := range order {
		if _, exists := selected[id]; exists {
			result = append(result, id)
		}
	}
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
