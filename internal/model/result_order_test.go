package model

import "testing"

func TestSortedResultsByStatus(t *testing.T) {
	t.Parallel()
	input := []CheckResult{
		{RuleID: "U-02", Status: StatusUnknown},
		{RuleID: "U-03", Status: StatusFail},
		{RuleID: "U-01", Status: StatusFail},
		{RuleID: "U-05", Status: StatusPass},
		{RuleID: "U-04", Status: StatusError},
	}

	ordered := SortedResultsByStatus(input)
	want := []string{"U-01", "U-03", "U-02", "U-04", "U-05"}
	for index, ruleID := range want {
		if ordered[index].RuleID != ruleID {
			t.Fatalf("ordered[%d] = %s, want %s", index, ordered[index].RuleID, ruleID)
		}
	}
	if input[0].RuleID != "U-02" {
		t.Fatal("sorting modified the input slice")
	}
}
