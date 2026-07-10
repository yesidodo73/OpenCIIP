package service

import (
	"slices"
	"testing"
)

func TestSNMPAccessPathCountsPreservesAllGroupMembers(t *testing.T) {
	graph := newSNMPAccessGraph()
	graph.communityNames["secAllowed"] = struct{}{}
	graph.accessGroups["grp"] = struct{}{}
	graph.groupMembers["grp"] = []snmpGroupMember{
		{Model: "v2c", Security: "secAllowed"},
		{Model: "v2c", Security: "missingSec"},
		{Model: "usm", Security: "user1"},
	}
	v1v2, v3 := graph.accessPathCounts()
	if v1v2 != 1 || v3 != 1 {
		t.Fatalf("accessPathCounts() = %d, %d, want 1, 1", v1v2, v3)
	}
}

func TestParseNetSNMPConfigSearchDirectoriesAndLocalCandidates(t *testing.T) {
	directories, complete := parseNetSNMPConfigSearchDirectories("read_config: config path used:/etc/snmp:/usr/share/snmp:/var/lib/net-snmp\n")
	if !complete || !slices.Equal(directories, []string{"/etc/snmp", "/usr/share/snmp", "/var/lib/net-snmp"}) {
		t.Fatalf("parseNetSNMPConfigSearchDirectories() = %#v, %t", directories, complete)
	}
	candidates := netSNMPConfigCandidates([]string{"/etc/snmp"})
	if !slices.Equal(candidates, []string{"/etc/snmp/snmpd.conf", "/etc/snmp/snmpd.local.conf"}) {
		t.Fatalf("netSNMPConfigCandidates() = %#v", candidates)
	}
}

func TestParseNetSNMPConfigSearchDirectoriesRejectsRelativePath(t *testing.T) {
	if directories, complete := parseNetSNMPConfigSearchDirectories("read_config: config path used:/etc/snmp:relative\n"); complete || directories != nil {
		t.Fatalf("parseNetSNMPConfigSearchDirectories() = %#v, %t, want incomplete", directories, complete)
	}
}

func TestCustomSNMPViewNameIsNotACompleteScopeBaseline(t *testing.T) {
	if snmpViewPolicySelfDescribing("restricted") {
		t.Fatal("custom view name was treated as a self-describing scope baseline")
	}
	if !snmpViewPolicySelfDescribing("oid:.1.3.6.1.2.1.1") {
		t.Fatal("explicit OID scope was not treated as self-describing")
	}
}
