package sing_tun

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestBuildICMPPortUnreachableIPv4(t *testing.T) {
	clientAddr := netip.MustParseAddrPort("192.168.1.100:54321")
	serverAddr := netip.MustParseAddrPort("157.240.253.174:443")
	payload := []byte("QUIC ClientHello packet data with some extra payload to test truncation")

	pkt, err := BuildICMPPortUnreachable(clientAddr, serverAddr, payload)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)

	// Verify Outer IPv4 Header
	header, err := ipv4.ParseHeader(pkt[:20])
	require.NoError(t, err)
	assert.Equal(t, 4, header.Version)
	assert.Equal(t, 1, header.Protocol) // ICMP
	assert.Equal(t, net.IP(serverAddr.Addr().AsSlice()), header.Src.To4())
	assert.Equal(t, net.IP(clientAddr.Addr().AsSlice()), header.Dst.To4())

	// Verify IPv4 Header Checksum
	assert.Equal(t, uint16(0), calculateChecksum(pkt[:20]))

	// Parse ICMP layer using x/net/icmp
	icmpMsg, err := icmp.ParseMessage(1, pkt[20:])
	require.NoError(t, err)
	assert.Equal(t, ipv4.ICMPTypeDestinationUnreachable, icmpMsg.Type)
	assert.Equal(t, 3, icmpMsg.Code) // Port Unreachable

	// Verify ICMP Checksum
	assert.Equal(t, uint16(0), calculateChecksum(pkt[20:]))

	// Verify Inner IPv4 Header in ICMP Payload
	innerIPBytes := pkt[28:]
	innerHeader, err := ipv4.ParseHeader(innerIPBytes[:20])
	require.NoError(t, err)
	assert.Equal(t, 4, innerHeader.Version)
	assert.Equal(t, 17, innerHeader.Protocol) // UDP
	assert.Equal(t, net.IP(clientAddr.Addr().AsSlice()), innerHeader.Src.To4())
	assert.Equal(t, net.IP(serverAddr.Addr().AsSlice()), innerHeader.Dst.To4())
	assert.Equal(t, uint16(0), calculateChecksum(innerIPBytes[:20]))

	// Verify Inner UDP Header
	innerUDPBytes := innerIPBytes[20:]
	require.True(t, len(innerUDPBytes) >= 8)
	srcPort := binary.BigEndian.Uint16(innerUDPBytes[0:2])
	dstPort := binary.BigEndian.Uint16(innerUDPBytes[2:4])
	udpLen := binary.BigEndian.Uint16(innerUDPBytes[4:6])
	assert.Equal(t, clientAddr.Port(), srcPort)
	assert.Equal(t, serverAddr.Port(), dstPort)
	assert.Equal(t, uint16(8+len(payload)), udpLen)
}

func TestBuildICMPPortUnreachableIPv6(t *testing.T) {
	clientAddr := netip.MustParseAddrPort("[2001:db8::1]:54321")
	serverAddr := netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
	payload := []byte("IPv6 QUIC ClientHello packet data")

	pkt, err := BuildICMPPortUnreachable(clientAddr, serverAddr, payload)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)

	// Verify Outer IPv6 Header
	header, err := ipv6.ParseHeader(pkt[:40])
	require.NoError(t, err)
	assert.Equal(t, 6, header.Version)
	assert.Equal(t, 58, header.NextHeader) // ICMPv6
	assert.Equal(t, net.IP(serverAddr.Addr().AsSlice()), header.Src.To16())
	assert.Equal(t, net.IP(clientAddr.Addr().AsSlice()), header.Dst.To16())

	// Parse ICMPv6 layer using x/net/icmp
	icmpMsg, err := icmp.ParseMessage(58, pkt[40:])
	require.NoError(t, err)
	assert.Equal(t, ipv6.ICMPTypeDestinationUnreachable, icmpMsg.Type)
	assert.Equal(t, 4, icmpMsg.Code) // Port Unreachable

	// Verify ICMPv6 Checksum covering pseudo-header
	sIP6 := serverAddr.Addr().As16()
	cIP6 := clientAddr.Addr().As16()
	assert.Equal(t, uint16(0), calculateICMPv6Checksum(sIP6[:], cIP6[:], pkt[40:]))

	// Verify Inner IPv6 Header
	innerIPBytes := pkt[48:]
	innerHeader, err := ipv6.ParseHeader(innerIPBytes[:40])
	require.NoError(t, err)
	assert.Equal(t, 6, innerHeader.Version)
	assert.Equal(t, 17, innerHeader.NextHeader) // UDP
	assert.Equal(t, net.IP(clientAddr.Addr().AsSlice()), innerHeader.Src.To16())
	assert.Equal(t, net.IP(serverAddr.Addr().AsSlice()), innerHeader.Dst.To16())

	// Verify Inner UDP Header
	innerUDPBytes := innerIPBytes[40:]
	require.True(t, len(innerUDPBytes) >= 8)
	srcPort := binary.BigEndian.Uint16(innerUDPBytes[0:2])
	dstPort := binary.BigEndian.Uint16(innerUDPBytes[2:4])
	assert.Equal(t, clientAddr.Port(), srcPort)
	assert.Equal(t, serverAddr.Port(), dstPort)
}

func TestBuildICMPPortUnreachableMismatch(t *testing.T) {
	clientAddr := netip.MustParseAddrPort("192.168.1.100:54321")
	serverAddr := netip.MustParseAddrPort("[2606:4700:4700::1111]:443")

	_, err := BuildICMPPortUnreachable(clientAddr, serverAddr, []byte("data"))
	assert.Error(t, err)
}
