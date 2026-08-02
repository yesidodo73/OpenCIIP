package support

import (
	"context"
	"fmt"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
)

type dpkgInventoryRunner struct {
	result executor.Result
}

func (runner dpkgInventoryRunner) Available(name string) bool {
	return name == "dpkg-query"
}

func (runner dpkgInventoryRunner) Run(_ context.Context, spec executor.Spec) (executor.Result, error) {
	if spec.Name != "dpkg-query" ||
		len(spec.Arguments) != 2 ||
		spec.Arguments[0] != "--show" ||
		spec.Arguments[1] != "--showformat="+dpkgQueryFormat {
		return executor.Result{}, fmt.Errorf("unexpected command: %s %v", spec.Name, spec.Arguments)
	}
	return runner.result, nil
}

func TestParseDPKGInventoryKeepsOnlyInstalledPackages(t *testing.T) {
	packages, err := ParseDPKGInventory(
		"proftpd-core\t1.3.8+dfsg-4build3\tamd64\tii \n" +
			"vsftpd\t3.0.5-0ubuntu1\tamd64\trc \n" +
			"libc6:amd64\t2.39-0ubuntu8.5\tamd64\thi \n",
	)
	if err != nil {
		t.Fatalf("ParseDPKGInventory() error = %v", err)
	}
	if len(packages) != 2 || packages[0].Name != "libc6:amd64" || packages[1].Name != "proftpd-core" {
		t.Fatalf("packages = %#v", packages)
	}
	if !DPKGPackageInstalled(packages, "libc6") || !DPKGPackageInstalled(packages, "proftpd-core") ||
		DPKGPackageInstalled(packages, "vsftpd") {
		t.Fatalf("DPKGPackageInstalled() did not respect installed state: %#v", packages)
	}
}

func TestParseDPKGInventoryRejectsAmbiguousRecords(t *testing.T) {
	for _, output := range []string{
		"vsftpd\t3.0.5\tamd64\n",
		"VSFTPD\t3.0.5\tamd64\tii \n",
		":amd64\t3.0.5\tamd64\tii \n",
		"vsftpd\t3.0.5\tamd64\tii \nvsftpd\t3.0.5\tamd64\tii \n",
	} {
		if _, err := ParseDPKGInventory(output); err == nil {
			t.Fatalf("ParseDPKGInventory(%q) succeeded", output)
		}
	}
}

func TestInspectDPKGInventoryRejectsCommandDiagnostics(t *testing.T) {
	runner := dpkgInventoryRunner{result: executor.Result{
		ExitCode: 0,
		Stdout:   []byte("vsftpd\t3.0.5\tamd64\tii \n"),
		Stderr:   []byte("warning: database is inconsistent\n"),
	}}
	_, evidence, err := InspectDPKGInventory(context.Background(), evaluator.Environment{Commands: runner})
	if err == nil {
		t.Fatal("InspectDPKGInventory() succeeded despite diagnostics")
	}
	if evidence.Source != "dpkg-package-inventory-summary" {
		t.Fatalf("evidence source = %q", evidence.Source)
	}
}
