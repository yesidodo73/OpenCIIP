//go:build !linux

package system

import (
	"os"
	"sync"
)

type portableRootAccess struct {
	mu   sync.RWMutex
	root *os.Root
}

func newRootedAccess(path string) (rootedAccess, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &portableRootAccess{root: root}, nil
}

func (r *portableRootAccess) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	root := r.root
	r.root = nil
	r.mu.Unlock()
	if root == nil {
		return nil
	}
	return root.Close()
}

func (r *portableRootAccess) Open(name string) (*os.File, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, os.ErrClosed
	}
	return r.root.Open(name)
}

func (r *portableRootAccess) OpenDir(name string) (*os.File, error) {
	return r.Open(name)
}

func (r *portableRootAccess) Stat(name string) (os.FileInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, os.ErrClosed
	}
	return r.root.Stat(name)
}

func (r *portableRootAccess) Lstat(name string) (os.FileInfo, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.root == nil {
		return nil, "", os.ErrClosed
	}
	info, err := r.root.Lstat(name)
	if err != nil {
		return nil, "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return info, "", nil
	}
	target, err := r.root.Readlink(name)
	if err != nil {
		return nil, "", err
	}
	return info, target, nil
}
