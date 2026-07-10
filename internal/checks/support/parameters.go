package support

import (
	"fmt"
	"math"
)

func BoolParameter(parameters map[string]any, key string) (bool, bool, error) {
	value, exists := parameters[key]
	if !exists {
		return false, false, nil
	}
	typed, ok := value.(bool)
	if !ok {
		return false, true, fmt.Errorf("parameter %s must be a boolean", key)
	}
	return typed, true, nil
}

func IntParameter(parameters map[string]any, key string) (int, bool, error) {
	maxInt := int64(^uint(0) >> 1)
	minInt := -maxInt - 1
	value, exists := parameters[key]
	if !exists {
		return 0, false, nil
	}
	switch typed := value.(type) {
	case int:
		return typed, true, nil
	case int64:
		if typed < minInt || typed > maxInt {
			return 0, true, fmt.Errorf("parameter %s is outside the int range", key)
		}
		return int(typed), true, nil
	case uint64:
		if typed > uint64(maxInt) {
			return 0, true, fmt.Errorf("parameter %s is outside the int range", key)
		}
		return int(typed), true, nil
	case float64:
		if typed != math.Trunc(typed) || typed < float64(minInt) || typed > float64(maxInt) {
			return 0, true, fmt.Errorf("parameter %s is not an integer", key)
		}
		return int(typed), true, nil
	default:
		return 0, true, fmt.Errorf("parameter %s must be an integer", key)
	}
}

func StringSliceParameter(parameters map[string]any, key string) ([]string, bool, error) {
	value, exists := parameters[key]
	if !exists {
		return nil, false, nil
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...), true, nil
	case []any:
		result := make([]string, len(typed))
		for index, item := range typed {
			stringValue, ok := item.(string)
			if !ok {
				return nil, true, fmt.Errorf("parameter %s item %d must be a string", key, index)
			}
			result[index] = stringValue
		}
		return result, true, nil
	default:
		return nil, true, fmt.Errorf("parameter %s must be a string array", key)
	}
}
