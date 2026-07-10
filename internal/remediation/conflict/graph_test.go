package conflict

import (
	"reflect"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func testResource(path string) model.CanonicalResource {
	return model.CanonicalResource{
		Reference: model.ResourceRef{Kind: model.ResourceFile, ID: path},
		Key:       "file:" + path,
	}
}

func testChangeSet(id string, sequence int, resource string) model.ChangeSet {
	return model.ChangeSet{ID: id, Sequence: sequence, Resources: []model.CanonicalResource{testResource(resource)}}
}

func TestSharedResourceClosureAndReverseOrder(t *testing.T) {
	t.Parallel()
	a := testChangeSet("A", 1, "/etc/shared")
	b := testChangeSet("B", 2, "/etc/shared")
	c := testChangeSet("C", 3, "/etc/independent")
	graph, err := Build([]model.ChangeSet{c, b, a})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].From != "A" || graph.Edges[0].To != "B" || graph.Edges[0].Reason != model.ConflictSharedResource {
		t.Fatalf("unexpected edges: %#v", graph.Edges)
	}
	active := map[string]bool{"A": true, "B": true, "C": true}
	if _, err := ItemRollbackClosure(graph, "A", active, false); CodeOf(err) != CodeRollbackConflict {
		t.Fatalf("ItemRollbackClosure() code = %s, want %s (err=%v)", CodeOf(err), CodeRollbackConflict, err)
	}
	closure, err := ItemRollbackClosure(graph, "A", active, true)
	if err != nil {
		t.Fatalf("ItemRollbackClosure(cascade) error = %v", err)
	}
	if want := []string{"A", "B"}; !reflect.DeepEqual(closure, want) {
		t.Fatalf("closure = %v, want %v", closure, want)
	}
	order, err := ReverseRollbackOrder(graph, nil, map[string]int{"A": 1, "B": 2, "C": 3})
	if err != nil {
		t.Fatalf("ReverseRollbackOrder() error = %v", err)
	}
	if want := []string{"C", "B", "A"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	blocked := BlockedPredecessors(graph, "B", map[string]bool{"A": true, "C": true})
	if want := []string{"A"}; !reflect.DeepEqual(blocked, want) {
		t.Fatalf("blocked = %v, want %v", blocked, want)
	}
}

func TestRollbackGroupRequiresCompleteScope(t *testing.T) {
	t.Parallel()
	a := testChangeSet("A", 1, "/etc/a")
	b := testChangeSet("B", 2, "/etc/b")
	a.RollbackGroup = "group-1"
	b.RollbackGroup = "group-1"
	graph, err := Build([]model.ChangeSet{a, b})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if _, err := ReverseRollbackOrder(graph, []string{"A"}, map[string]int{"A": 1, "B": 2}); CodeOf(err) != CodeIncompleteGroup {
		t.Fatalf("ReverseRollbackOrder() code = %s, want %s (err=%v)", CodeOf(err), CodeIncompleteGroup, err)
	}
	closure, err := ItemRollbackClosure(graph, "A", map[string]bool{"A": true, "B": true}, true)
	if err != nil {
		t.Fatalf("ItemRollbackClosure() error = %v", err)
	}
	if want := []string{"A", "B"}; !reflect.DeepEqual(closure, want) {
		t.Fatalf("closure = %v, want %v", closure, want)
	}
}
