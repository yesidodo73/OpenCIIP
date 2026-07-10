package support

import "testing"

func TestAnalyzeStaticShellPreservesVariableAttributes(t *testing.T) {
	t.Parallel()

	analysis := AnalyzeStaticShell("/etc/profile", []byte("VALUE=one\nexport VALUE\nreadonly VALUE\n"))
	if len(analysis.Issues) != 0 {
		t.Fatalf("issues = %#v, want none", analysis.Issues)
	}
	want := []StaticShellOperationKind{StaticShellAssign, StaticShellExport, StaticShellReadOnly}
	if len(analysis.Operations) != len(want) {
		t.Fatalf("operations = %#v, want %d operations", analysis.Operations, len(want))
	}
	for index, kind := range want {
		if analysis.Operations[index].Kind != kind || analysis.Operations[index].Name != "VALUE" {
			t.Errorf("operation[%d] = %#v, want kind=%q name=VALUE", index, analysis.Operations[index], kind)
		}
	}
}

func TestAnalyzeStaticShellParsesCombinedDeclareAttributes(t *testing.T) {
	t.Parallel()

	analysis := AnalyzeStaticShell("/etc/profile", []byte("declare -rx TMOUT=600\n"))
	if len(analysis.Issues) != 0 {
		t.Fatalf("issues = %#v, want none", analysis.Issues)
	}
	want := []StaticShellOperationKind{StaticShellAssign, StaticShellExport, StaticShellReadOnly}
	if len(analysis.Operations) != len(want) {
		t.Fatalf("operations = %#v, want %d operations", analysis.Operations, len(want))
	}
	for index, kind := range want {
		if analysis.Operations[index].Kind != kind {
			t.Errorf("operation[%d].Kind = %q, want %q", index, analysis.Operations[index].Kind, kind)
		}
	}
}

func TestAnalyzeStaticShellRejectsUnsupportedAttributeFlags(t *testing.T) {
	t.Parallel()

	analysis := AnalyzeStaticShell("/etc/profile", []byte("declare -p TMOUT\nreadonly -p\n"))
	if len(analysis.Operations) != 0 || len(analysis.Issues) != 2 {
		t.Fatalf("analysis = %#v, want two unsupported issues and no operations", analysis)
	}
}
