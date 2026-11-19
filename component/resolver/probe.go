package resolver

import (
	"cmp"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
)

// ProbeTarget represents a direct public-IP DNS server extracted from the
// user's DNS configuration for egress interface reachability probing.
type ProbeTarget struct {
	AddrPort   netip.AddrPort
	Network    string // "tcp" or "udp"
	Priority   int    // 0: non-53 TCP (853/443 etc.), 1: TCP 53, 2: UDP 53
	SourceTier int    // 0: direct/proxy-server/default-nameserver, 1: nameserver
}

// ProbeServerInput is a minimal description of a configured DNS server used to
// build ProbeTargets without introducing a dependency on the dns package.
type ProbeServerInput struct {
	Net        string
	Addr       string
	HasProxy   bool
	ProxyName  string
	SourceTier int
}

type probeTargetSet struct {
	v4 []ProbeTarget
	v6 []ProbeTarget
}

var probeTargets atomic.Pointer[probeTargetSet]

var nonPublicProbePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "This" network (RFC 1122)
	netip.MustParsePrefix("100.64.0.0/10"),  // Shared Address Space / CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF Protocol Assignments (RFC 6890)
	netip.MustParsePrefix("192.0.2.0/24"),   // TEST-NET-1 (RFC 5737)
	netip.MustParsePrefix("198.18.0.0/15"),  // Benchmarking / mihomo default Fake-IP pool
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2 (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"), // TEST-NET-3 (RFC 5737)
	netip.MustParsePrefix("240.0.0.0/4"),    // Reserved for future use (RFC 1112)
	netip.MustParsePrefix("2001:db8::/32"),  // IPv6 Documentation (RFC 3849)
}

func isPublicProbeIP(addr netip.Addr) bool {
	ip := addr.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicProbePrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func parseProbeServer(in ProbeServerInput) (ProbeTarget, bool) {
	if in.HasProxy {
		return ProbeTarget{}, false
	}
	if in.ProxyName != "" && !strings.EqualFold(in.ProxyName, "DIRECT") {
		return ProbeTarget{}, false
	}

	var (
		hostPort string
		network  string
		priority int
	)

	switch in.Net {
	case "":
		hostPort = in.Addr
		network = "udp"
		priority = 2
	case "tcp":
		hostPort = in.Addr
		network = "tcp"
	case "tls":
		hostPort = in.Addr
		network = "tcp"
		priority = 0
	case "https":
		u, err := url.Parse(in.Addr)
		if err != nil {
			return ProbeTarget{}, false
		}
		hostPort = u.Host
		network = "tcp"
		priority = 0
	default:
		// Skip quic, system, dhcp, rcode, tailscale, easytier, etc.
		return ProbeTarget{}, false
	}

	ap, err := netip.ParseAddrPort(hostPort)
	if err != nil {
		return ProbeTarget{}, false
	}

	ip := ap.Addr().Unmap()
	if !isPublicProbeIP(ip) {
		return ProbeTarget{}, false
	}
	ap = netip.AddrPortFrom(ip, ap.Port())

	if in.Net == "tcp" {
		if ap.Port() == 53 {
			priority = 1
		} else {
			priority = 0
		}
	}

	return ProbeTarget{
		AddrPort:   ap,
		Network:    network,
		Priority:   priority,
		SourceTier: in.SourceTier,
	}, true
}

// BuildProbeTargets extracts deduplicated, sorted IPv4 and IPv6 public-IP
// probe targets from configured DNS servers.
func BuildProbeTargets(inputs []ProbeServerInput) (v4, v6 []ProbeTarget) {
	type dedupKey struct {
		ap      netip.AddrPort
		network string
	}

	best := make(map[dedupKey]ProbeTarget, len(inputs))
	for _, in := range inputs {
		target, ok := parseProbeServer(in)
		if !ok {
			continue
		}
		key := dedupKey{ap: target.AddrPort, network: target.Network}
		if prev, exists := best[key]; exists {
			if target.SourceTier < prev.SourceTier ||
				(target.SourceTier == prev.SourceTier && target.Priority < prev.Priority) {
				best[key] = target
			}
			continue
		}
		best[key] = target
	}

	for _, target := range best {
		if target.AddrPort.Addr().Is6() {
			v6 = append(v6, target)
		} else {
			v4 = append(v4, target)
		}
	}

	sortTargets := func(list []ProbeTarget) {
		slices.SortFunc(list, func(a, b ProbeTarget) int {
			if c := cmp.Compare(a.SourceTier, b.SourceTier); c != 0 {
				return c
			}
			if c := cmp.Compare(a.Priority, b.Priority); c != 0 {
				return c
			}
			if c := a.AddrPort.Addr().Compare(b.AddrPort.Addr()); c != 0 {
				return c
			}
			if c := cmp.Compare(a.AddrPort.Port(), b.AddrPort.Port()); c != 0 {
				return c
			}
			return cmp.Compare(a.Network, b.Network)
		})
	}

	sortTargets(v4)
	sortTargets(v6)
	return v4, v6
}

// SetProbeTargets atomically replaces the active probe target lists.
func SetProbeTargets(v4, v6 []ProbeTarget) {
	if len(v4) == 0 && len(v6) == 0 {
		probeTargets.Store(nil)
		return
	}
	set := &probeTargetSet{
		v4: slices.Clone(v4),
		v6: slices.Clone(v6),
	}
	probeTargets.Store(set)
}

// GetProbeTargets returns the immutable slice of configured probe targets for
// IPv4 (isV6 == false) or IPv6 (isV6 == true).
func GetProbeTargets(isV6 bool) []ProbeTarget {
	set := probeTargets.Load()
	if set == nil {
		return nil
	}
	if isV6 {
		return set.v6
	}
	return set.v4
}