package sing_tun

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	errAddrFamilyMismatch = errors.New("address family mismatch")
	errInvalidAddress     = errors.New("invalid IP address")
)

// BuildICMPPortUnreachable constructs an RFC 792 (IPv4) or RFC 4443 (IPv6) ICMP Port Unreachable packet.
// clientAddr: the original sender of the UDP packet.
// serverAddr: the original destination of the UDP packet.
// origPayload: the original UDP payload.
// The resulting ICMP error packet has:
// - Outer IP: Src = serverAddr, Dst = clientAddr
// - Inner IP: Src = clientAddr, Dst = serverAddr, Protocol = UDP
// - Inner UDP: SrcPort = clientAddr.Port, DstPort = serverAddr.Port
func BuildICMPPortUnreachable(clientAddr, serverAddr netip.AddrPort, origPayload []byte) ([]byte, error) {
	cIP := clientAddr.Addr()
	sIP := serverAddr.Addr()
	if !cIP.IsValid() || !sIP.IsValid() {
		return nil, errInvalidAddress
	}

	if cIP.Is4() && sIP.Is4() {
		return buildICMPv4PortUnreachable(clientAddr, serverAddr, origPayload), nil
	} else if cIP.Is6() && sIP.Is6() {
		return buildICMPv6PortUnreachable(clientAddr, serverAddr, origPayload), nil
	}

	return nil, errAddrFamilyMismatch
}

func buildICMPv4PortUnreachable(clientAddr, serverAddr netip.AddrPort, origPayload []byte) []byte {
	// RFC 792: Original IP header + at least 64 bits (8 bytes) of the original data datagram.
	// We take up to 64 bytes of original UDP payload to aid socket lookup.
	innerPayloadLen := len(origPayload)
	if innerPayloadLen > 64 {
		innerPayloadLen = 64
	}

	innerIPLen := 20 + 8 + innerPayloadLen
	icmpPayloadLen := innerIPLen
	icmpTotalLen := 8 + icmpPayloadLen
	totalLen := 20 + icmpTotalLen

	pkt := make([]byte, totalLen)

	// --- Outer IPv4 Header (20 bytes) ---
	// Version 4, IHL 5 (20 bytes)
	pkt[0] = 0x45
	pkt[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)      // Identification
	binary.BigEndian.PutUint16(pkt[6:8], 0)      // Flags & Fragment Offset
	pkt[8] = 64                                  // TTL
	pkt[9] = 1                                   // Protocol: ICMP
	// Checksum (pkt[10:12]) will be filled later
	cIP4 := clientAddr.Addr().As4()
	sIP4 := serverAddr.Addr().As4()
	copy(pkt[12:16], sIP4[:]) // Outer Src = server
	copy(pkt[16:20], cIP4[:]) // Outer Dst = client
	ipChk := calculateChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChk)

	// --- Outer ICMPv4 Header (8 bytes) ---
	icmp := pkt[20:]
	icmp[0] = 3 // Type: Destination Unreachable
	icmp[1] = 3 // Code: Port Unreachable
	// Checksum (icmp[2:4]) will be filled later
	// Unused 4 bytes (icmp[4:8]) are already 0

	// --- Inner IPv4 Header (20 bytes) ---
	inner := icmp[8:]
	inner[0] = 0x45
	inner[1] = 0x00
	binary.BigEndian.PutUint16(inner[2:4], uint16(innerIPLen))
	binary.BigEndian.PutUint16(inner[4:6], 0)
	binary.BigEndian.PutUint16(inner[6:8], 0)
	inner[8] = 64
	inner[9] = 17 // Protocol: UDP
	copy(inner[12:16], cIP4[:]) // Inner Src = client
	copy(inner[16:20], sIP4[:]) // Inner Dst = server
	innerIPChk := calculateChecksum(inner[:20])
	binary.BigEndian.PutUint16(inner[10:12], innerIPChk)

	// --- Inner UDP Header (8 bytes) ---
	innerUDP := inner[20:]
	binary.BigEndian.PutUint16(innerUDP[0:2], clientAddr.Port())
	binary.BigEndian.PutUint16(innerUDP[2:4], serverAddr.Port())
	binary.BigEndian.PutUint16(innerUDP[4:6], uint16(8+len(origPayload)))
	binary.BigEndian.PutUint16(innerUDP[6:8], 0) // Checksum

	// --- Inner UDP Payload ---
	if innerPayloadLen > 0 {
		copy(innerUDP[8:], origPayload[:innerPayloadLen])
	}

	// Calculate outer ICMPv4 Checksum
	icmpChk := calculateChecksum(icmp)
	binary.BigEndian.PutUint16(icmp[2:4], icmpChk)

	return pkt
}

func buildICMPv6PortUnreachable(clientAddr, serverAddr netip.AddrPort, origPayload []byte) []byte {
	// RFC 4443: Include as much of the invoking packet as possible without the ICMPv6 packet exceeding 1280 bytes.
	// Outer IPv6 (40) + ICMPv6 (8) + Inner IPv6 (40) + Inner UDP (8) = 96 bytes.
	maxPayload := 1280 - 96
	innerPayloadLen := len(origPayload)
	if innerPayloadLen > maxPayload {
		innerPayloadLen = maxPayload
	}

	innerIPLen := 40 + 8 + innerPayloadLen
	icmpPayloadLen := innerIPLen
	icmpTotalLen := 8 + icmpPayloadLen
	totalLen := 40 + icmpTotalLen

	pkt := make([]byte, totalLen)

	// --- Outer IPv6 Header (40 bytes) ---
	pkt[0] = 0x60 // Version 6
	// Traffic Class & Flow Label = 0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(icmpTotalLen)) // Payload Length
	pkt[6] = 58                                               // Next Header: ICMPv6
	pkt[7] = 64                                               // Hop Limit
	cIP6 := clientAddr.Addr().As16()
	sIP6 := serverAddr.Addr().As16()
	copy(pkt[8:24], sIP6[:])  // Outer Src = server
	copy(pkt[24:40], cIP6[:]) // Outer Dst = client

	// --- Outer ICMPv6 Header (8 bytes) ---
	icmp := pkt[40:]
	icmp[0] = 1 // Type: Destination Unreachable
	icmp[1] = 4 // Code: Port Unreachable
	// Checksum (icmp[2:4]) will be filled later
	// Unused 4 bytes (icmp[4:8]) are already 0

	// --- Inner IPv6 Header (40 bytes) ---
	inner := icmp[8:]
	inner[0] = 0x60
	binary.BigEndian.PutUint16(inner[4:6], uint16(8+innerPayloadLen))
	inner[6] = 17 // Next Header: UDP
	inner[7] = 64 // Hop Limit
	copy(inner[8:24], cIP6[:])
	copy(inner[24:40], sIP6[:])

	// --- Inner UDP Header (8 bytes) ---
	innerUDP := inner[40:]
	binary.BigEndian.PutUint16(innerUDP[0:2], clientAddr.Port())
	binary.BigEndian.PutUint16(innerUDP[2:4], serverAddr.Port())
	binary.BigEndian.PutUint16(innerUDP[4:6], uint16(8+len(origPayload)))
	binary.BigEndian.PutUint16(innerUDP[6:8], 0)

	// --- Inner UDP Payload ---
	if innerPayloadLen > 0 {
		copy(innerUDP[8:], origPayload[:innerPayloadLen])
	}

	// Calculate ICMPv6 Checksum with IPv6 Pseudo-header
	icmpChk := calculateICMPv6Checksum(sIP6[:], cIP6[:], icmp)
	binary.BigEndian.PutUint16(icmp[2:4], icmpChk)

	return pkt
}

func calculateChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func calculateICMPv6Checksum(src, dst []byte, icmp []byte) uint16 {
	var sum uint32

	// Pseudo-Header: Src (16) + Dst (16)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i:]))
		sum += uint32(binary.BigEndian.Uint16(dst[i:]))
	}

	// Pseudo-Header: Upper-Layer Packet Length (uint32)
	icmpLen := uint32(len(icmp))
	sum += icmpLen >> 16
	sum += icmpLen & 0xffff

	// Pseudo-Header: Zero (3 bytes) + Next Header (1 byte, 58)
	sum += 58

	// ICMPv6 Header and Data
	b := icmp
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
