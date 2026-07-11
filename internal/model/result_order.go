package model

import "sort"

// SortedResultsByStatus returns a copy ordered for user-facing output.
func SortedResultsByStatus(results []CheckResult) []CheckResult {
	ordered := append([]CheckResult(nil), results...)
	sort.SliceStable(ordered, func(left, right int) bool {
		leftPriority := statusDisplayPriority(ordered[left].Status)
		rightPriority := statusDisplayPriority(ordered[right].Status)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return ordered[left].RuleID < ordered[right].RuleID
	})
	return ordered
}

func statusDisplayPriority(status Status) int {
	switch status {
	case StatusFail:
		return 0
	case StatusUnknown:
		return 1
	case StatusError:
		return 2
	case StatusPass:
		return 3
	case StatusNotApplicable:
		return 4
	case StatusSkipped:
		return 5
	default:
		return 6
	}
}
