package service

import (
	"reflect"
	"testing"
)

func TestParseActiveLSMs(t *testing.T) {
	got, valid := parseActiveLSMs("lockdown,capability,landlock,yama,apparmor\n")
	want := []string{"lockdown", "capability", "landlock", "yama", "apparmor"}
	if !valid || !reflect.DeepEqual(got, want) {
		t.Fatalf("parseActiveLSMs() = %#v, %t, want %#v, true", got, valid, want)
	}
}

func TestParseActiveLSMsRejectsAmbiguousInventory(t *testing.T) {
	for _, value := range []string{"", "apparmor,,yama", "SELinux", "apparmor,apparmor"} {
		if got, valid := parseActiveLSMs(value); valid {
			t.Errorf("parseActiveLSMs(%q) = %#v, true, want invalid", value, got)
		}
	}
}

func TestSELinuxAbsentFromActiveLSMs(t *testing.T) {
	for name, testCase := range map[string]struct {
		active     []string
		valid      bool
		absent     bool
		conclusive bool
	}{
		"selinux absent":  {active: []string{"capability", "apparmor"}, valid: true, absent: true, conclusive: true},
		"selinux present": {active: []string{"capability", "selinux"}, valid: true, absent: false, conclusive: true},
		"invalid":         {active: nil, valid: false, absent: false, conclusive: false},
	} {
		t.Run(name, func(t *testing.T) {
			absent, conclusive := selinuxAbsentFromActiveLSMs(testCase.active, testCase.valid)
			if absent != testCase.absent || conclusive != testCase.conclusive {
				t.Fatalf("selinuxAbsentFromActiveLSMs() = %t, %t, want %t, %t", absent, conclusive, testCase.absent, testCase.conclusive)
			}
		})
	}
}
