//go:build windows && 386

package sing_tun

import "syscall"

// On Windows 386 (stdcall), a 16-byte GUID passed by value occupies 4 uint32
// stack slots, so the callback has 6 uintptr parameters (24 bytes cleaned).
func newNLMConnectivityChangedCallback() uintptr {
	return syscall.NewCallback(func(this, _g0, _g1, _g2, _g3, _newConnectivity uintptr) uintptr {
		nlmNotifySink(this)
		return comSOK
	})
}

func newNLMPropertyChangedCallback() uintptr {
	return syscall.NewCallback(func(_this, _g0, _g1, _g2, _g3, _flags uintptr) uintptr {
		return comSOK
	})
}