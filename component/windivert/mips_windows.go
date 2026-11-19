//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/mipstack"
	tun "github.com/metacubex/sing-tun"
)

// stackDevice adapts captured IP packets to sing-tun's device contract.
type stackDevice struct {
	tun     *Tun
	packets chan []byte
}

var _ tun.WinTun = (*stackDevice)(nil)

func (t *Tun) startMIPS() error {
	device := &stackDevice{tun: t, packets: make(chan []byte, batchSize)}
	ipStack, err := tun.NewStack("mips", tun.StackOptions{
		Context: t.ctx, Tun: device, TunOptions: tun.Options{MTU: t.options.MTU},
		UDPTimeout: t.options.UDPTimeout, Handler: t.options.Handler, Logger: log.SingLogger,
	})
	if err != nil {
		return err
	}
	t.closeStack = func() { _ = device.Close(); _ = ipStack.Close() }
	if err := ipStack.Start(); err != nil {
		return err
	}
	t.deliver = func(p []byte, info packetInfo, _ address) { device.deliver(p[:info.size]) }
	return nil
}

func (d *stackDevice) deliver(p []byte) {
	owned := pool.Get(len(p))
	copy(owned, p)
	select {
	case d.packets <- owned:
	case <-d.tun.ctx.Done():
		_ = pool.Put(owned)
	}
}

func (d *stackDevice) ReadPacket() ([]byte, func(), error) {
	if d.tun.ctx.Err() != nil {
		return nil, nil, net.ErrClosed
	}
	select {
	case p := <-d.packets:
		return p, func() { _ = pool.Put(p) }, nil
	case <-d.tun.ctx.Done():
		return nil, nil, net.ErrClosed
	}
}

func (d *stackDevice) Read(p []byte) (int, error) {
	packet, release, err := d.ReadPacket()
	if err != nil {
		return 0, err
	}
	defer release()
	if len(p) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}

func (d *stackDevice) Write(p []byte) (int, error) {
	addr, ok := d.tun.responseInterface(packetDestination(p))
	if !ok {
		return 0, net.ErrClosed
	}
	addr.Flags = flagIPChecksum | flagTCPChecksum | flagUDPChecksum
	owned := pool.Get(len(p))
	copy(owned, p)
	if err := d.tun.queuePacket(owned, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *stackDevice) Close() error {
	for {
		select {
		case p := <-d.packets:
			_ = pool.Put(p)
		default:
			return nil
		}
	}
}

// stackDevice implements tun.WinTun, so sing-tun enables mipstack RX checksum
// offload for IPv4 headers, TCP, and nonzero UDP checksums. Only IPv6 UDP
// datagrams whose wire checksum is still 0 due to hardware offload need user-mode
// completion; genuinely invalid zero-checksum IPv6 UDP (flagUDPChecksum set) is
// left intact for mipstack to reject.
func ensureMIPSChecksums(p []byte, info packetInfo, flags uint32) {
	if info.protocol != 17 || !info.source.Addr().Is6() || flags&flagUDPChecksum != 0 {
		return
	}
	payload := p[info.offset:info.size]
	length := int(binary.BigEndian.Uint16(payload[4:]))
	payload = payload[:length]
	if binary.BigEndian.Uint16(payload[6:]) != 0 {
		return
	}
	checksum, _ := mipstack.IPTransportChecksum(info.source.Addr(), info.destination.Addr(), int(info.protocol), payload)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(payload[6:], checksum)
}
