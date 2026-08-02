package testdata

import (
	"embed"
	"fmt"
)

//go:embed remediation-journal-v2/*.json
var legacyV2Journals embed.FS

var legacyV2JournalNames = map[string]struct{}{
	"applied.json":     {},
	"planned.json":     {},
	"recovery.json":    {},
	"rolled-back.json": {},
}

func ReadLegacyV2Journal(name string) ([]byte, error) {
	if _, ok := legacyV2JournalNames[name]; !ok {
		return nil, fmt.Errorf("unknown legacy v2 journal fixture %q", name)
	}
	return legacyV2Journals.ReadFile("remediation-journal-v2/" + name)
}
