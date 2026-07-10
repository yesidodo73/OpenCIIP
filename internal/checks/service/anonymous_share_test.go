package service

import "testing"

func TestNFSSquashPolicyRequiresExplicitUnmodifiedRootSquash(t *testing.T) {
	if !nfsSquashPolicyExplicitlyKnown(map[string]string{"root_squash": ""}) {
		t.Fatal("explicit root_squash was not recognized")
	}
	for name, options := range map[string]map[string]string{
		"implicit default": {},
		"no root squash":   {"no_root_squash": ""},
		"all squash":       {"root_squash": "", "all_squash": ""},
		"custom anon uid":  {"root_squash": "", "anonuid": "65534"},
		"custom anon gid":  {"root_squash": "", "anongid": "65534"},
	} {
		if nfsSquashPolicyExplicitlyKnown(options) {
			t.Errorf("%s policy was treated as fully verified", name)
		}
	}
}
