//go:build windows && amd64

package sing_tun

import "syscall"

// On Windows amd64, a 16-byte GUID passed by value is passed by hidden pointer.
// Signature: HRESULT (this, *GUID, uint32).
func newNLMConnectivityChangedCallback() uintptr {
	return syscall.NewCallback(func(this, _guidPtr, _newConnectivity uintptr) uintptr {
		nlmNotifySink(this)
		return comSOK
	})
}

func newNLMPropertyChangedCallback() uintptr {
	return syscall.NewCallback(func(_this, _guidPtr, _flags uintptr) uintptr {
		return comSOK
	})
}