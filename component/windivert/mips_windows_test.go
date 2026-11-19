//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/metacubex/mipstack"
)

func TestMIPSChecksums(t *testing.T) {
	newOffloadStack := func(t *testing.T) *mipstack.Stack {
		t.Helper()
		stack, err := mipstack.New(mipstack.Config{Promiscuous: true, MTU: 1500})
		if err != nil {
			t.Fatal(err)
		}
		var offload mipstack.RXChecksumOffload
		offload.SetIPv4Header(true).SetTCP(true).SetUDP(true)
		stack.SetRXChecksumOffload(offload)
		if err := stack.Start(); err != nil {
			_ = stack.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stack.Close() })
		return stack
	}

	for _, test := range []struct{ name, packet string }{
		{"tcp4", "4600002c0000400080060000c0000201c633640101010000c35001bb00000001000000005002ffff00000000"},
		{"udp4", "4500001d0000000040110000c0000201c6336401c35001bb0009000001"},
		{"tcp6", "60000000001c004020010db800000000000000000000000120010db80000000000000000000000020600000000000000c35001bb00000001000000005002ffff00000000"},
		{"udp6", "600000000009114020010db800000000000000000000000120010db8000000000000000000000002c35001bb0009000001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, _ := hex.DecodeString(test.packet)
			info, ok := parsePacket(p)
			if !ok {
				t.Fatal("invalid packet")
			}
			ensureMIPSChecksums(p, info, flagIPChecksum)
			stack := newOffloadStack(t)
			if _, err := stack.Write([][]byte{p}, 0); err != nil {
				t.Fatalf("mipstack Write failed: %v", err)
			}
			stats := stack.Stats()
			if stats.InboundDroppedPackets != 0 || stats.PromiscuousInboundPackets != 1 {
				t.Fatalf("MIPS rejected offloaded packet: %+v", stats)
			}
		})
	}

	t.Run("udp6_invalid_zero_checksum_rejected", func(t *testing.T) {
		p, _ := hex.DecodeString("600000000009114020010db800000000000000000000000120010db8000000000000000000000002c35001bb0009000001")
		info, ok := parsePacket(p)
		if !ok {
			t.Fatal("invalid packet")
		}
		ensureMIPSChecksums(p, info, flagUDPChecksum)
		if got := binary.BigEndian.Uint16(p[info.offset+6:]); got != 0 {
			t.Fatalf("expected zero checksum to remain untouched, got %#x", got)
		}
		stack := newOffloadStack(t)
		if _, err := stack.Write([][]byte{p}, 0); err != nil {
			t.Fatalf("mipstack Write failed: %v", err)
		}
		stats := stack.Stats()
		if stats.InboundDroppedPackets != 1 {
			t.Fatalf("expected invalid zero-checksum IPv6 UDP packet to be dropped, got %+v", stats)
		}
	})
}
