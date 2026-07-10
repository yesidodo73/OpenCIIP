package support

import (
	"context"
	"testing"
)

func TestReadEffectiveGroupRejectsOptionLikeNameBeforeExecution(t *testing.T) {
	if _, _, _, err := ReadEffectiveGroup(context.Background(), nil, "--service"); err == nil {
		t.Fatal("ReadEffectiveGroup() accepted an option-like group name")
	}
}
