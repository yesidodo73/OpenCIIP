package model

import (
	"strings"
	"testing"
)

func TestHostIdentityValidate(t *testing.T) {
	t.Parallel()

	valid := HostIdentity{
		MachineIDHash: strings.Repeat("a", 64),
		SystemRoot:    "/",
		RootDevice:    1,
		RootInode:     2,
		BootID:        "12345678-1234-1234-1234-123456789abc",
	}
	tests := []struct {
		name    string
		mutate  func(*HostIdentity)
		wantErr bool
	}{
		{name: "valid"},
		{name: "invalid machine id digest", mutate: func(value *HostIdentity) { value.MachineIDHash = strings.Repeat("g", 64) }, wantErr: true},
		{name: "empty system root", mutate: func(value *HostIdentity) { value.SystemRoot = "" }, wantErr: true},
		{name: "noncanonical system root", mutate: func(value *HostIdentity) { value.SystemRoot = " /" }, wantErr: true},
		{name: "system root with nul", mutate: func(value *HostIdentity) { value.SystemRoot = "/\x00root" }, wantErr: true},
		{name: "zero root device", mutate: func(value *HostIdentity) { value.RootDevice = 0 }, wantErr: true},
		{name: "zero root inode", mutate: func(value *HostIdentity) { value.RootInode = 0 }, wantErr: true},
		{name: "missing boot id", mutate: func(value *HostIdentity) { value.BootID = "" }, wantErr: true},
		{name: "uppercase boot id", mutate: func(value *HostIdentity) { value.BootID = "12345678-1234-1234-1234-123456789ABC" }, wantErr: true},
		{name: "malformed boot id", mutate: func(value *HostIdentity) { value.BootID = "123456781234-1234-1234-123456789abc" }, wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := valid
			if test.mutate != nil {
				test.mutate(&value)
			}
			err := value.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}
