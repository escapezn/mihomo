package resolver

import (
	"net/netip"
	"testing"
)

func TestBuildProbeTargets(t *testing.T) {
	inputs := []ProbeServerInput{
		// Tier 0: direct / proxy-server / default nameservers
		{Net: "", Addr: "223.5.5.5:53", SourceTier: 0},
		{Net: "tls", Addr: "1.1.1.1:853", SourceTier: 0},
		{Net: "tcp", Addr: "8.8.8.8:53", SourceTier: 0},
		{Net: "tcp", Addr: "8.8.4.4:853", SourceTier: 0},
		{Net: "https", Addr: "https://9.9.9.9:443/dns-query", SourceTier: 0},
		{Net: "https", Addr: "http://119.29.29.29:80/dns-query", ProxyName: "DIRECT", SourceTier: 0},
		{Net: "tls", Addr: "[2400:3200::1]:853", SourceTier: 0},
		{Net: "", Addr: "[2606:4700:4700::1111]:53", ProxyName: "direct", SourceTier: 0},

		// Tier 1: general nameservers (also duplicates with lower priority tier)
		{Net: "", Addr: "223.5.5.5:53", SourceTier: 1},
		{Net: "https", Addr: "https://223.6.6.6:443/dns-query", SourceTier: 1},

		// Should be skipped: proxied, respect-rules, domain, non-TCP/UDP schemes
		{Net: "tls", Addr: "1.0.0.1:853", HasProxy: true, SourceTier: 0},
		{Net: "tls", Addr: "1.0.0.2:853", ProxyName: "PROXY", SourceTier: 0},
		{Net: "tls", Addr: "1.0.0.3:853", ProxyName: "respect-rules", SourceTier: 1},
		{Net: "https", Addr: "https://doh.pub:443/dns-query", SourceTier: 1},
		{Net: "quic", Addr: "223.5.5.5:853", SourceTier: 0},
		{Net: "system", Addr: "", SourceTier: 0},
		{Net: "dhcp", Addr: "en0", SourceTier: 0},
		{Net: "rcode", Addr: "refused", SourceTier: 0},

		// Should be skipped: non-public / private / CGNAT / Fake-IP / reserved / doc ranges
		{Net: "", Addr: "127.0.0.1:53", SourceTier: 0},
		{Net: "", Addr: "10.0.0.1:53", SourceTier: 0},
		{Net: "", Addr: "192.168.1.1:53", SourceTier: 0},
		{Net: "", Addr: "100.64.0.1:53", SourceTier: 0},
		{Net: "", Addr: "198.18.0.2:53", SourceTier: 0},
		{Net: "", Addr: "192.0.2.1:53", SourceTier: 0},
		{Net: "", Addr: "198.51.100.1:53", SourceTier: 0},
		{Net: "", Addr: "203.0.113.1:53", SourceTier: 0},
		{Net: "", Addr: "0.0.0.1:53", SourceTier: 0},
		{Net: "", Addr: "240.0.0.1:53", SourceTier: 0},
		{Net: "", Addr: "[fe80::1]:53", SourceTier: 0},
		{Net: "", Addr: "[fc00::1]:53", SourceTier: 0},
		{Net: "", Addr: "[2001:db8::1]:53", SourceTier: 0},
	}

	v4, v6 := BuildProbeTargets(inputs)

	wantV4 := []ProbeTarget{
		{AddrPort: netip.MustParseAddrPort("1.1.1.1:853"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("8.8.4.4:853"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("9.9.9.9:443"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("119.29.29.29:80"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("8.8.8.8:53"), Network: "tcp", Priority: 1, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("223.5.5.5:53"), Network: "udp", Priority: 2, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("223.6.6.6:443"), Network: "tcp", Priority: 0, SourceTier: 1},
	}
	if len(v4) != len(wantV4) {
		t.Fatalf("v4 len = %d, want %d (%+v)", len(v4), len(wantV4), v4)
	}
	for i := range wantV4 {
		if v4[i] != wantV4[i] {
			t.Errorf("v4[%d] = %+v, want %+v", i, v4[i], wantV4[i])
		}
	}

	wantV6 := []ProbeTarget{
		{AddrPort: netip.MustParseAddrPort("[2400:3200::1]:853"), Network: "tcp", Priority: 0, SourceTier: 0},
		{AddrPort: netip.MustParseAddrPort("[2606:4700:4700::1111]:53"), Network: "udp", Priority: 2, SourceTier: 0},
	}
	if len(v6) != len(wantV6) {
		t.Fatalf("v6 len = %d, want %d (%+v)", len(v6), len(wantV6), v6)
	}
	for i := range wantV6 {
		if v6[i] != wantV6[i] {
			t.Errorf("v6[%d] = %+v, want %+v", i, v6[i], wantV6[i])
		}
	}
}

func TestSetAndGetProbeTargets(t *testing.T) {
	defer SetProbeTargets(nil, nil)

	v4 := []ProbeTarget{{AddrPort: netip.MustParseAddrPort("223.5.5.5:53"), Network: "udp", Priority: 2}}
	v6 := []ProbeTarget{{AddrPort: netip.MustParseAddrPort("[2400:3200::1]:853"), Network: "tcp", Priority: 0}}
	SetProbeTargets(v4, v6)

	// Mutating input slices must not affect stored snapshot.
	v4[0].Priority = 99
	gotV4 := GetProbeTargets(false)
	if len(gotV4) != 1 || gotV4[0].Priority != 2 {
		t.Fatalf("unexpected v4 snapshot: %+v", gotV4)
	}
	gotV6 := GetProbeTargets(true)
	if len(gotV6) != 1 || gotV6[0].AddrPort != netip.MustParseAddrPort("[2400:3200::1]:853") {
		t.Fatalf("unexpected v6 snapshot: %+v", gotV6)
	}

	SetProbeTargets(nil, nil)
	if GetProbeTargets(false) != nil || GetProbeTargets(true) != nil {
		t.Fatalf("expected nil after clearing probe targets")
	}
}