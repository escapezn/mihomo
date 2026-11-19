package sing_tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"

	"github.com/miekg/dns"
)

const (
	defaultProbeTimeout  = 1500 * time.Millisecond
	probeUDPRetryAfter   = 500 * time.Millisecond
	maxProbeTargets      = 6
	probeBucketQuota     = 3
	maxProbeUDPRespBytes = 1500
)

type probeDialFunc func(ctx context.Context, network, address, ifaceName string) (net.Conn, error)

func defaultProbeDial(ctx context.Context, network, address, ifaceName string) (net.Conn, error) {
	return dialer.DialContext(ctx, network, address, dialer.WithInterface(ifaceName), dialer.WithResolver(nil))
}

// selectProbeTargets chooses up to maxProbeTargets targets with distinct IPs,
// balancing non-53 TCP servers (bucket A, Priority == 0) and port-53 servers
// (bucket B, Priority >= 1) so overseas DoT/DoH servers cannot crowd out local
// direct UDP/TCP 53 servers.
func selectProbeTargets(targets []resolver.ProbeTarget) []resolver.ProbeTarget {
	if len(targets) == 0 {
		return nil
	}

	var bucketA, bucketB []resolver.ProbeTarget
	for _, t := range targets {
		if t.Priority == 0 {
			bucketA = append(bucketA, t)
		} else {
			bucketB = append(bucketB, t)
		}
	}

	capHint := len(targets)
	if capHint > maxProbeTargets {
		capHint = maxProbeTargets
	}
	selected := make([]resolver.ProbeTarget, 0, capHint)
	usedIP := make(map[netip.Addr]struct{}, maxProbeTargets)

	take := func(src []resolver.ProbeTarget, limit int) []resolver.ProbeTarget {
		var rest []resolver.ProbeTarget
		taken := 0
		for _, t := range src {
			ip := t.AddrPort.Addr()
			if _, seen := usedIP[ip]; seen {
				continue
			}
			if taken < limit {
				selected = append(selected, t)
				usedIP[ip] = struct{}{}
				taken++
			} else {
				rest = append(rest, t)
			}
		}
		return rest
	}

	restA := take(bucketA, probeBucketQuota)
	restB := take(bucketB, probeBucketQuota)

	if len(selected) < maxProbeTargets {
		take(restA, maxProbeTargets-len(selected))
	}
	if len(selected) < maxProbeTargets {
		take(restB, maxProbeTargets-len(selected))
	}
	return selected
}

func probeInterface(ctx context.Context, ifaceName string, isV6 bool, targets []resolver.ProbeTarget) (reachable bool, probed bool) {
	return probeInterfaceWith(ctx, ifaceName, isV6, targets, defaultProbeTimeout, defaultProbeDial)
}

func probeInterfaceWith(
	ctx context.Context,
	ifaceName string,
	isV6 bool,
	targets []resolver.ProbeTarget,
	timeout time.Duration,
	dialFn probeDialFunc,
) (reachable bool, probed bool) {
	selected := selectProbeTargets(targets)
	if len(selected) == 0 {
		return false, false
	}

	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	if dialFn == nil {
		dialFn = defaultProbeDial
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var ok atomic.Bool
	var wg sync.WaitGroup
	for _, target := range selected {
		wg.Add(1)
		go func(t resolver.ProbeTarget) {
			defer wg.Done()
			if probeSingleTarget(probeCtx, ifaceName, isV6, t, timeout, dialFn) {
				ok.Store(true)
				cancel()
			}
		}(target)
	}
	wg.Wait()
	return ok.Load(), true
}

func probeSingleTarget(
	ctx context.Context,
	ifaceName string,
	isV6 bool,
	target resolver.ProbeTarget,
	timeout time.Duration,
	dialFn probeDialFunc,
) bool {
	if ctx.Err() != nil {
		return false
	}

	switch target.Network {
	case "tcp":
		netName := "tcp4"
		if isV6 {
			netName = "tcp6"
		}
		conn, err := dialFn(ctx, netName, target.AddrPort.String(), ifaceName)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true

	case "udp":
		return probeUDP53(ctx, ifaceName, isV6, target.AddrPort, timeout, dialFn)

	default:
		return false
	}
}

func probeUDP53(
	ctx context.Context,
	ifaceName string,
	isV6 bool,
	addrPort netip.AddrPort,
	timeout time.Duration,
	dialFn probeDialFunc,
) bool {
	netName := "udp4"
	if isV6 {
		netName = "udp6"
	}
	conn, err := dialFn(ctx, netName, addrPort.String(), ifaceName)
	if err != nil {
		return false
	}
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{{
		Name:   ".",
		Qtype:  dns.TypeNS,
		Qclass: dns.ClassINET,
	}}
	wireReq, err := req.Pack()
	if err != nil {
		return false
	}

	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(timeout)
	}

	retryAfter := probeUDPRetryAfter
	if timeout > 0 && retryAfter > timeout/2 {
		retryAfter = timeout / 2
	}

	buf := make([]byte, maxProbeUDPRespBytes)
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		now := time.Now()
		if !now.Before(deadline) {
			return false
		}

		attemptDeadline := deadline
		if attempt == 0 && retryAfter > 0 {
			if first := now.Add(retryAfter); first.Before(deadline) {
				attemptDeadline = first
			}
		}

		if err := conn.SetDeadline(attemptDeadline); err != nil {
			return false
		}
		if _, err := conn.Write(wireReq); err != nil {
			return false
		}

		for {
			n, err := conn.Read(buf)
			if err != nil {
				var netErr net.Error
				if attempt == 0 && ctx.Err() == nil && errors.As(err, &netErr) && netErr.Timeout() {
					break // retry once on first-attempt timeout
				}
				return false
			}

			var resp dns.Msg
			if err := resp.Unpack(buf[:n]); err != nil {
				continue
			}
			if resp.Id != req.Id || !resp.Response {
				continue
			}
			if resp.Rcode == dns.RcodeSuccess && hasRootNSAnswer(resp.Answer) {
				return true
			}
			return false
		}
	}
	return false
}

func hasRootNSAnswer(answers []dns.RR) bool {
	for _, rr := range answers {
		if ns, ok := rr.(*dns.NS); ok && ns.Hdr.Name == "." {
			return true
		}
	}
	return false
}