package network

import (
	"context"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
)

func TestParseListenerEndpointAcceptsSSInterfaceScopes(t *testing.T) {
	tests := []struct {
		endpoint string
		address  string
		port     int
		wildcard bool
		scope    string
	}{
		{endpoint: "127.0.0.53%lo:53", address: "127.0.0.53", port: 53, scope: "lo"},
		{endpoint: "192.0.2.20%ens18:68", address: "192.0.2.20", port: 68, scope: "ens18"},
		{endpoint: "[fe80::1]%ens18:546", address: "fe80::1", port: 546, scope: "ens18"},
		{endpoint: "[fe80::1%ens18]:546", address: "fe80::1", port: 546, scope: "ens18"},
		{endpoint: "[::]:22", address: "::", port: 22, wildcard: true},
	}
	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			address, port, wildcard, scope, err := parseListenerEndpoint(test.endpoint)
			if err != nil {
				t.Fatalf("parseListenerEndpoint() error = %v", err)
			}
			if address.String() != test.address || port != test.port || wildcard != test.wildcard || scope != test.scope {
				t.Fatalf(
					"parseListenerEndpoint() = %s, %d, %t, %q, want %s, %d, %t, %q",
					address, port, wildcard, scope, test.address, test.port, test.wildcard, test.scope,
				)
			}
		})
	}
}

func TestParseListenerEndpointRejectsInvalidScopes(t *testing.T) {
	for _, endpoint := range []string{
		"127.0.0.1%:53",
		"127.0.0.1%lo%other:53",
		"127.0.0.1%bad:scope:53",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, _, _, _, err := parseListenerEndpoint(endpoint); err == nil {
				t.Fatal("parseListenerEndpoint() accepted an invalid scope")
			}
		})
	}
}

type scopedListenerRunner struct{}

func (scopedListenerRunner) Run(context.Context, executor.Spec) (executor.Result, error) {
	return executor.Result{
		ExitCode: 0,
		Stdout: []byte(
			"udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=1,fd=1))\n" +
				"udp UNCONN 0 0 192.0.2.20%ens18:68 0.0.0.0:* users:((\"systemd-network\",pid=2,fd=2))\n",
		),
	}, nil
}

func (scopedListenerRunner) Available(string) bool { return true }

func TestInspectRemoteListenersHandlesSSInterfaceScopes(t *testing.T) {
	inventory, _, err := inspectRemoteListeners(context.Background(), evaluator.Environment{Commands: scopedListenerRunner{}})
	if err != nil {
		t.Fatalf("inspectRemoteListeners() error = %v", err)
	}
	if inventory.total != 1 || inventory.udp != 1 || inventory.specific != 1 {
		t.Fatalf("listener inventory = %#v", inventory)
	}
	want := "udp\x00192.0.2.20%ens18\x0068"
	if len(inventory.configuration) != 1 || inventory.configuration[0] != want {
		t.Fatalf("listener configuration = %q, want %q", inventory.configuration, want)
	}
}
