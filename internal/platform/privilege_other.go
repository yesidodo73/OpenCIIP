//go:build !linux

package platform

func currentPrivilege() string {
	return "unknown"
}
