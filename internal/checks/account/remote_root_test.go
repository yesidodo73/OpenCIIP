package account

import (
	"context"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestInspectRemoteServiceRecognizesDebianSSHUnit(t *testing.T) {
	t.Parallel()

	commands := fixtureCommandRunner{
		commandKey("ps", "-eo", "comm="): {
			result: executor.Result{ExitCode: 0},
		},
		commandKey("ss", "-H", "-lntup"): {
			result: executor.Result{ExitCode: 0},
		},
	}
	for _, unitName := range sshRemoteUnitNames() {
		activeState := "inactive"
		subState := "dead"
		loadState := "not-found"
		fragmentPath := ""
		unitFileState := ""
		if unitName == "ssh.service" {
			activeState = "active"
			subState = "running"
			loadState = "loaded"
			fragmentPath = "/usr/lib/systemd/system/ssh.service"
			unitFileState = "enabled"
		}
		output := "Id=" + unitName + "\n" +
			"LoadState=" + loadState + "\n" +
			"ActiveState=" + activeState + "\n" +
			"SubState=" + subState + "\n" +
			"FragmentPath=" + fragmentPath + "\n" +
			"DropInPaths=\n" +
			"UnitFileState=" + unitFileState + "\n"
		commands[commandKey(
			"systemctl",
			"show",
			"--no-pager",
			"--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths",
			"--",
			unitName,
		)] = fixtureCommandResponse{result: executor.Result{ExitCode: 0, Stdout: []byte(output)}}
	}

	active, installed, states, _, err := inspectRemoteService(
		context.Background(),
		evaluator.Environment{
			Commands: commands,
			Platform: model.PlatformInfo{Family: "debian", ID: "ubuntu", InitSystem: "systemd"},
		},
		sshRemoteUnitNames(),
		[]string{"sshd"},
		22,
	)
	if err != nil {
		t.Fatalf("inspectRemoteService() error = %v", err)
	}
	if !active {
		t.Fatal("active = false, want true for active ssh.service")
	}
	if len(installed) != 1 || installed[0] != "ssh.service" {
		t.Fatalf("installed = %#v, want ssh.service", installed)
	}
	if len(states) != len(sshRemoteUnitNames()) {
		t.Fatalf("state count = %d, want %d", len(states), len(sshRemoteUnitNames()))
	}
}
