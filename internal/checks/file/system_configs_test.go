package filecheck

import (
	"slices"
	"testing"
)

func TestParseSystemdCommandPathsDoesNotTreatBusyBoxWrapperAsComplete(t *testing.T) {
	value := `{ path=/usr/bin/busybox ; argv[]=/usr/bin/busybox sh /opt/start.sh ; ignore_errors=no ; }`
	paths, complete := parseSystemdCommandPaths(value)
	if complete || !slices.Equal(paths, []string{"/usr/bin/busybox"}) {
		t.Fatalf("parseSystemdCommandPaths() = %#v, %t, want busybox path and incomplete", paths, complete)
	}
}

func TestRsyslogConfigPathFromSysconfigUsesCustomFOption(t *testing.T) {
	configPath, complete, err := rsyslogConfigPathFromSysconfig("SYSLOGD_OPTIONS='-n -f /tmp/custom-rsyslog.conf'\n")
	if err != nil || !complete || configPath != "/tmp/custom-rsyslog.conf" {
		t.Fatalf("rsyslogConfigPathFromSysconfig() = %q, %t, %v", configPath, complete, err)
	}
}

func TestRsyslogConfigPathFromSysconfigRejectsDynamicOrConflictingPaths(t *testing.T) {
	for _, content := range []string{
		"SYSLOGD_OPTIONS='-f $CUSTOM_CONFIG'\n",
		"RSYSLOG_CONFIG_FILE=/etc/rsyslog.conf\nSYSLOGD_OPTIONS='-f /tmp/other.conf'\n",
	} {
		if _, complete, err := rsyslogConfigPathFromSysconfig(content); err != nil || complete {
			t.Fatalf("rsyslogConfigPathFromSysconfig(%q) = complete=%t err=%v, want incomplete", content, complete, err)
		}
	}
}
