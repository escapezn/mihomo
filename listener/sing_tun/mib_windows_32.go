//go:build windows && (386 || arm)

package sing_tun

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// mibIfRow2 mirrors MIB_IF_ROW2 from netioapi.h on 32-bit Windows, where
// MSVC aligns uint64 TransmitLinkSpeed to an 8-byte boundary (offset 1192).
type mibIfRow2 struct {
	InterfaceLUID               uint64
	InterfaceIndex              uint32
	InterfaceGUID               windows.GUID
	alias                       [ifMaxStringSize + 1]uint16
	description                 [ifMaxStringSize + 1]uint16
	physicalAddressLength       uint32
	physicalAddress             [ifMaxPhysAddressLength]byte
	permanentPhysicalAddress    [ifMaxPhysAddressLength]byte
	MTU                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGUID                 windows.GUID
	ConnectionType              uint32
	_                           [4]byte
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

const mibIfRow2Size = 1352

var (
	_ [mibIfRow2Size - unsafe.Sizeof(mibIfRow2{})]byte
	_ [unsafe.Sizeof(mibIfRow2{}) - mibIfRow2Size]byte
)