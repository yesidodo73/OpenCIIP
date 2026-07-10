//go:build linux

package platform

import "os"

func currentPrivilege() string {
	if os.Geteuid() == 0 {
		return "root"
	}
	return "user"
}
