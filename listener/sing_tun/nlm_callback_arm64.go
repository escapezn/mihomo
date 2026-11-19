//go:build windows && arm64

package sing_tun

import "syscall"

// On Windows arm64, a 16-byte non-HFA GUID passed by value occupies two 64-bit
// registers (x1, x2), so the callback has 4 uintptr parameters.
func newNLMConnectivityChangedCallback() uintptr {
	return syscall.NewCallback(func(this, _guidLo, _guidHi, _newConnectivity uintptr) uintptr {
		nlmNotifySink(this)
		return comSOK
	})
}

func newNLMPropertyChangedCallback() uintptr {
	return syscall.NewCallback(func(_this, _guidLo, _guidHi, _flags uintptr) uintptr {
		return comSOK
	})
}