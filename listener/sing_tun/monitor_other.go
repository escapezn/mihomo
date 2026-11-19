//go:build !windows

package sing_tun

import (
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/logger"
)

func newDefaultInterfaceMonitor(
	_ string,
	networkMonitor tun.NetworkUpdateMonitor,
	l logger.Logger,
	options tun.DefaultInterfaceMonitorOptions,
) (tun.DefaultInterfaceMonitor, error) {
	return tun.NewDefaultInterfaceMonitor(networkMonitor, l, options)
}