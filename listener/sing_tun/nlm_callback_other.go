//go:build windows && !amd64 && !386 && !arm64

package sing_tun

func newNLMConnectivityChangedCallback() uintptr {
	return 0
}

func newNLMPropertyChangedCallback() uintptr {
	return 0
}