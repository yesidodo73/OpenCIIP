package service

import (
	"slices"
	"testing"
)

func TestBINDACLSelectorsExpandsCustomACLs(t *testing.T) {
	root := []bindNode{{
		Name: "acl", Args: []string{"xfr"},
		Children: []bindNode{{Name: "any"}},
	}}
	directive := bindNode{Name: "allow-transfer", Children: []bindNode{{Name: "xfr"}}}
	selectors, complete := bindACLSelectors(root, directive)
	if !complete || !slices.Equal(selectors, []string{"any"}) {
		t.Fatalf("bindACLSelectors() = %#v, %t, want [any], true", selectors, complete)
	}
}

func TestBINDACLSelectorsExpandsNestedACLs(t *testing.T) {
	root := []bindNode{
		{Name: "acl", Args: []string{"secondary"}, Children: []bindNode{{Name: "192.0.2.10"}}},
		{Name: "acl", Args: []string{"xfr"}, Children: []bindNode{{Name: "secondary"}, {Name: "key", Args: []string{"transfer-key"}}}},
	}
	directive := bindNode{Name: "allow-transfer", Children: []bindNode{{Name: "xfr"}}}
	selectors, complete := bindACLSelectors(root, directive)
	if !complete || !slices.Equal(selectors, []string{"192.0.2.10", "key:transfer-key"}) {
		t.Fatalf("bindACLSelectors() = %#v, %t", selectors, complete)
	}
}

func TestBINDACLSelectorsRejectsRecursiveACLs(t *testing.T) {
	root := []bindNode{
		{Name: "acl", Args: []string{"a"}, Children: []bindNode{{Name: "b"}}},
		{Name: "acl", Args: []string{"b"}, Children: []bindNode{{Name: "a"}}},
	}
	if selectors, complete := bindACLSelectors(root, bindNode{Name: "allow-transfer", Children: []bindNode{{Name: "a"}}}); complete || selectors != nil {
		t.Fatalf("bindACLSelectors(recursive) = %#v, %t, want incomplete", selectors, complete)
	}
}

func TestBINDDynamicZoneBackendPreventsNotApplicableConclusion(t *testing.T) {
	for _, root := range [][]bindNode{
		{{Name: "dlz", Args: []string{"example"}}},
		{{Name: "view", Args: []string{"internal"}, Children: []bindNode{{Name: "dyndb", Args: []string{"ldap"}}}}},
	} {
		if !containsBINDDynamicZoneBackend(root) {
			t.Fatalf("containsBINDDynamicZoneBackend(%#v) = false", root)
		}
	}
}

func TestNamedConfigPathUsesExpandedSysconfigOption(t *testing.T) {
	properties := map[string]string{
		"ExecStart":        `{ path=/usr/sbin/named ; argv[]=/usr/sbin/named -u named $OPTIONS ; ignore_errors=no ; }`,
		"Environment":      "",
		"EnvironmentFiles": "/etc/sysconfig/named (ignore_errors=yes)",
	}
	configPath, complete, err := namedConfigPathFromSystemdProperties(properties, "OPTIONS='-4 -c /etc/named-custom.conf'\n")
	if err != nil || !complete || configPath != "/etc/named-custom.conf" {
		t.Fatalf("namedConfigPathFromSystemdProperties() = %q, %t, %v", configPath, complete, err)
	}
}

func TestNamedConfigPathRejectsWrapperOrChroot(t *testing.T) {
	for _, execStart := range []string{
		`{ path=/usr/bin/env ; argv[]=/usr/bin/env /usr/sbin/named ; ignore_errors=no ; }`,
		`{ path=/usr/sbin/named ; argv[]=/usr/sbin/named -t /var/named/chroot ; ignore_errors=no ; }`,
	} {
		properties := map[string]string{"ExecStart": execStart, "Environment": "", "EnvironmentFiles": ""}
		if _, complete, err := namedConfigPathFromSystemdProperties(properties, ""); err != nil || complete {
			t.Fatalf("namedConfigPathFromSystemdProperties(%q) = complete=%t err=%v, want incomplete", execStart, complete, err)
		}
	}
}
