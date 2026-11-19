package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/miekg/dns"
)

func TestSelectProbeTargetsBalancedBuckets(t *testing.T) {
	targets := []resolver.ProbeTarget{
		// 4 overseas DoT/DoH (Priority 0)
		{AddrPort: netip.MustParseAddrPort("1.1.1.1:853"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("1.0.0.1:853"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("8.8.8.8:853"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("8.8.4.4:853"), Network: "tcp", Priority: 0, SourceTier: 0},
		// 2 domestic UDP 53 (Priority 2)
		{AddrPort: netip.MustParseAddrPort("223.5.5.5:53"), Network: "udp", Priority: 2, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("119.29.29.29:53"), Network: "udp", Priority: 2, SourceTier: 0},
	}

	got := selectProbeTargets(targets)
	if len(got) != 6 {
		t.Fatalf("len = %d, want 6 (%+v)", len(got), got)
	}
	// First 3 from bucket A, next 2 from bucket B, remaining 1 filled from bucket A.
	hasDomestic := false
	for _, item := range got {
		if item.AddrPort.Addr() == netip.MustParseAddr("223.5.5.5") {
			hasDomestic = true
		}
	}
	if !hasDomestic {
		t.Fatalf("expected domestic UDP 53 target not to be crowded out: %+v", got)
	}
}

func startMockUDP53(t *testing.T, handler func(req *dns.Msg, attempt int) *dns.Msg) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	var attempts atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dns.Msg
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			cur := int(attempts.Add(1))
			resp := handler(&req, cur)
			if resp == nil {
				continue
			}
			wire, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(wire, addr)
		}
	}()

	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestProbeTCPAndInterfacePassing(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	var gotIface atomic.Value
	dialFn := func(ctx context.Context, network, address, ifaceName string) (net.Conn, error) {
		gotIface.Store(ifaceName)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	ok, probed := probeInterfaceWith(context.Background(), "Wi-Fi", false, []resolver.ProbeTarget{
		{AddrPort: ap, Network: "tcp", Priority: 0},
	}, time.Second, dialFn)
	if !probed || !ok {
		t.Fatalf("probe = (%v, %v), want (true, true)", ok, probed)
	}
	if gotIface.Load() != "Wi-Fi" {
		t.Fatalf("ifaceName = %v, want Wi-Fi", gotIface.Load())
	}
}

func TestProbeUDP53ValidationAndRetry(t *testing.T) {
	dialFn := func(ctx context.Context, network, address, ifaceName string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	// 1. Valid root NS answer after dropping the first packet (tests retry).
	apValidRetry := startMockUDP53(t, func(req *dns.Msg, attempt int) *dns.Msg {
		if attempt == 1 {
			return nil
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "a.root-servers.net.",
			},
		}
		return resp
	})

	ok, probed := probeInterfaceWith(context.Background(), "eth0", false, []resolver.ProbeTarget{
		{AddrPort: apValidRetry, Network: "udp", Priority: 2},
	}, 600*time.Millisecond, dialFn)
	if !probed || !ok {
		t.Fatalf("valid retry probe = (%v, %v), want (true, true)", ok, probed)
	}

	// 2. Hijack false positives: SERVFAIL, REFUSED, NOERROR with empty Answer, NOERROR with A record.
	cases := []struct {
		name  string
		build func(req *dns.Msg) *dns.Msg
	}{
		{
			name: "SERVFAIL",
			build: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeServerFailure
				return resp
			},
		},
		{
			name: "REFUSED",
			build: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeRefused
				return resp
			},
		},
		{
			name: "NOERROR_EmptyAnswer",
			build: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeSuccess
				return resp
			},
		},
		{
			name: "NOERROR_NonNSRecord",
			build: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.IPv4(192, 168, 1, 1),
					},
				}
				return resp
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ap := startMockUDP53(t, func(req *dns.Msg, _ int) *dns.Msg {
				return tc.build(req)
			})
			ok, probed := probeInterfaceWith(context.Background(), "eth0", false, []resolver.ProbeTarget{
				{AddrPort: ap, Network: "udp", Priority: 2},
			}, 300*time.Millisecond, dialFn)
			if !probed || ok {
				t.Fatalf("%s probe = (%v, %v), want (false, true)", tc.name, ok, probed)
			}
		})
	}
}

func TestProbeImmediateCancel(t *testing.T) {
	// Blackhole UDP server that never responds.
	apBlackhole := startMockUDP53(t, func(_ *dns.Msg, _ int) *dns.Msg { return nil })
	dialFn := func(ctx context.Context, network, address, ifaceName string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(80*time.Millisecond, cancel)

	start := time.Now()
	ok, probed := probeInterfaceWith(ctx, "eth0", false, []resolver.ProbeTarget{
		{AddrPort: apBlackhole, Network: "udp", Priority: 2},
	}, 2*time.Second, dialFn)
	elapsed := time.Since(start)

	if !probed || ok {
		t.Fatalf("cancelled probe = (%v, %v), want (false, true)", ok, probed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("cancel took too long: %v", elapsed)
	}
}