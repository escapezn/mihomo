//go:build windows

package sing_tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/component/resolver"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/x/list"
	"golang.org/x/sys/windows"
)

func TestWindowsMIBStructOffsets(t *testing.T) {
	var fwd mibIPforwardRow2
	if unsafe.Sizeof(fwd) != 104 {
		t.Fatalf("sizeof(mibIPforwardRow2) = %d, want 104", unsafe.Sizeof(fwd))
	}
	if unsafe.Offsetof(fwd.InterfaceIndex) != 8 {
		t.Errorf("mibIPforwardRow2.InterfaceIndex offset = %d, want 8", unsafe.Offsetof(fwd.InterfaceIndex))
	}
	if unsafe.Offsetof(fwd.DestinationPrefix) != 12 {
		t.Errorf("mibIPforwardRow2.DestinationPrefix offset = %d, want 12", unsafe.Offsetof(fwd.DestinationPrefix))
	}
	if unsafe.Offsetof(fwd.NextHop) != 44 {
		t.Errorf("mibIPforwardRow2.NextHop offset = %d, want 44", unsafe.Offsetof(fwd.NextHop))
	}
	if unsafe.Offsetof(fwd.Metric) != 84 {
		t.Errorf("mibIPforwardRow2.Metric offset = %d, want 84", unsafe.Offsetof(fwd.Metric))
	}

	var fwdTab mibIPforwardTable2
	if unsafe.Sizeof(fwdTab) != 112 {
		t.Fatalf("sizeof(mibIPforwardTable2) = %d, want 112", unsafe.Sizeof(fwdTab))
	}
	if unsafe.Offsetof(fwdTab.table) != 8 {
		t.Errorf("mibIPforwardTable2.table offset = %d, want 8", unsafe.Offsetof(fwdTab.table))
	}

	var ifRow mibIfRow2
	if unsafe.Sizeof(ifRow) != 1352 {
		t.Fatalf("sizeof(mibIfRow2) = %d, want 1352", unsafe.Sizeof(ifRow))
	}
	if unsafe.Offsetof(ifRow.InterfaceIndex) != 8 {
		t.Errorf("mibIfRow2.InterfaceIndex offset = %d, want 8", unsafe.Offsetof(ifRow.InterfaceIndex))
	}
	if unsafe.Offsetof(ifRow.InterfaceGUID) != 12 {
		t.Errorf("mibIfRow2.InterfaceGUID offset = %d, want 12", unsafe.Offsetof(ifRow.InterfaceGUID))
	}
	if unsafe.Offsetof(ifRow.alias) != 28 {
		t.Errorf("mibIfRow2.alias offset = %d, want 28", unsafe.Offsetof(ifRow.alias))
	}
	if unsafe.Offsetof(ifRow.Type) != 1128 {
		t.Errorf("mibIfRow2.Type offset = %d, want 1128", unsafe.Offsetof(ifRow.Type))
	}
	if unsafe.Offsetof(ifRow.OperStatus) != 1156 {
		t.Errorf("mibIfRow2.OperStatus offset = %d, want 1156", unsafe.Offsetof(ifRow.OperStatus))
	}
	if unsafe.Offsetof(ifRow.TransmitLinkSpeed) != 1192 {
		t.Errorf("mibIfRow2.TransmitLinkSpeed offset = %d, want 1192", unsafe.Offsetof(ifRow.TransmitLinkSpeed))
	}
}

func makeCtrlIface(index int, name string, cidr string) *control.Interface {
	var addrs []netip.Prefix
	if cidr != "" {
		addrs = []netip.Prefix{netip.MustParsePrefix(cidr)}
	}
	return &control.Interface{
		Index:     index,
		MTU:       1500,
		Name:      name,
		Addresses: addrs,
	}
}

func TestSelectInterfaceStickyNeverProbesNewNIC(t *testing.T) {
	wifi := makeCtrlIface(10, "Wi-Fi", "192.168.1.10/24")
	eth2 := makeCtrlIface(20, "Ethernet 2", "192.168.50.2/24")
	targets := []resolver.ProbeTarget{
		{AddrPort: netip.MustParseAddrPort("223.5.5.5:53"), Network: "udp", Priority: 2},
	}

	var probedNames []string
	probe := func(_ context.Context, name string, _ bool, _ []resolver.ProbeTarget) (bool, bool) {
		probedNames = append(probedNames, name)
		return true, true // even if Ethernet 2 also had internet, it must never be probed
	}

	// Ethernet 2 has lower Metric (15 < 35), both offline and online new NICs must not preempt Wi-Fi.
	candidates := []routeCandidate{
		{Interface: eth2, Metric: 15, HasNLMInternet: true},
		{Interface: wifi, Metric: 35, HasNLMInternet: true},
	}

	got, reason := selectInterface(context.Background(), false, wifi, candidates, targets, probe)
	if got == nil || got.Index != wifi.Index {
		t.Fatalf("got = %+v (%s), want Wi-Fi", got, reason)
	}
	if reason != reasonStickyVerified {
		t.Fatalf("reason = %s, want %s", reason, reasonStickyVerified)
	}
	if len(probedNames) != 1 || probedNames[0] != "Wi-Fi" {
		t.Fatalf("probed = %v, want only [Wi-Fi]", probedNames)
	}
}

func TestSelectInterfaceFailoverAndStaleNLMProtection(t *testing.T) {
	wifi := makeCtrlIface(10, "Wi-Fi", "192.168.1.10/24")
	eth1 := makeCtrlIface(11, "Ethernet 1", "10.0.0.2/24")
	eth2 := makeCtrlIface(20, "Ethernet 2", "192.168.50.2/24")
	targets := []resolver.ProbeTarget{
		{AddrPort: netip.MustParseAddrPort("223.5.5.5:53"), Network: "udp", Priority: 2},
	}

	candidates := []routeCandidate{
		{Interface: eth2, Metric: 15, HasNLMInternet: true},
		{Interface: eth1, Metric: 25, HasNLMInternet: true},
		{Interface: wifi, Metric: 35, HasNLMInternet: false},
	}

	// Case 1: Wi-Fi fails DNS probe, Ethernet 1 succeeds, Ethernet 2 fails -> failover to Ethernet 1.
	got, reason := selectInterface(context.Background(), false, wifi, candidates, targets,
		func(_ context.Context, name string, _ bool, _ []resolver.ProbeTarget) (bool, bool) {
			return name == "Ethernet 1", true
		})
	if got == nil || got.Index != eth1.Index || reason != reasonFailoverDNS {
		t.Fatalf("got = %+v (%s), want Ethernet 1 (%s)", got, reason, reasonFailoverDNS)
	}

	// Case 2: All candidates fail DNS probe even though Ethernet 2 has stale NLM=true -> stay on Wi-Fi.
	got, reason = selectInterface(context.Background(), false, wifi, candidates, targets,
		func(_ context.Context, _ string, _ bool, _ []resolver.ProbeTarget) (bool, bool) {
			return false, true
		})
	if got == nil || got.Index != wifi.Index || reason != reasonStickyAllUnreachable {
		t.Fatalf("got = %+v (%s), want Wi-Fi (%s)", got, reason, reasonStickyAllUnreachable)
	}

	// Case 3: No DNS targets configured -> fall back to NLM Internet failover.
	got, reason = selectInterface(context.Background(), false, wifi, candidates, nil, nil)
	if got == nil || got.Index != eth2.Index || reason != reasonFailoverNLM {
		t.Fatalf("got = %+v (%s), want Ethernet 2 (%s)", got, reason, reasonFailoverNLM)
	}
}

func TestSelectInterfaceColdStartAndEscapeDeadFallback(t *testing.T) {
	eth2Dead := makeCtrlIface(20, "Ethernet 2", "192.168.50.2/24")
	wifiLive := makeCtrlIface(10, "Wi-Fi", "192.168.1.10/24")
	targets := []resolver.ProbeTarget{
		{AddrPort: netip.MustParseAddrPort("223.5.5.5:53"), Network: "udp", Priority: 2},
	}

	// Cold start with single dead NIC -> zero probes, select it as fallback.
	probed := false
	got, reason := selectInterface(context.Background(), false, nil, []routeCandidate{
		{Interface: eth2Dead, Metric: 15, HasNLMInternet: false},
	}, targets, func(_ context.Context, _ string, _ bool, _ []resolver.ProbeTarget) (bool, bool) {
		probed = true
		return false, true
	})
	if probed {
		t.Fatalf("expected zero probes for single candidate")
	}
	if got == nil || got.Index != eth2Dead.Index || reason != reasonSingleCandidate {
		t.Fatalf("cold start single got = %+v (%s), want Ethernet 2", got, reason)
	}

	// Later Wi-Fi comes up -> dead current fails probe, escapes to Wi-Fi.
	got, reason = selectInterface(context.Background(), false, got, []routeCandidate{
		{Interface: eth2Dead, Metric: 15, HasNLMInternet: false},
		{Interface: wifiLive, Metric: 35, HasNLMInternet: true},
	}, targets, func(_ context.Context, name string, _ bool, _ []resolver.ProbeTarget) (bool, bool) {
		return name == "Wi-Fi", true
	})
	if got == nil || got.Index != wifiLive.Index || reason != reasonFailoverDNS {
		t.Fatalf("escape dead fallback got = %+v (%s), want Wi-Fi", got, reason)
	}
}

type fakeInterfaceFinder struct {
	updates atomic.Int32
}

func (f *fakeInterfaceFinder) Update() error {
	f.updates.Add(1)
	return nil
}
func (f *fakeInterfaceFinder) Interfaces() []control.Interface           { return nil }
func (f *fakeInterfaceFinder) ByName(string) (*control.Interface, error) { return nil, errors.New("not found") }
func (f *fakeInterfaceFinder) ByIndex(int) (*control.Interface, error)   { return nil, errors.New("not found") }
func (f *fakeInterfaceFinder) ByAddr(netip.Addr) (*control.Interface, error) {
	return nil, errors.New("not found")
}

type fakeNetMonitor struct {
	mu        sync.Mutex
	callbacks list.List[tun.NetworkUpdateCallback]
}

func (f *fakeNetMonitor) Start() error { return nil }
func (f *fakeNetMonitor) Close() error { return nil }
func (f *fakeNetMonitor) RegisterCallback(cb tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callbacks.PushBack(cb)
}
func (f *fakeNetMonitor) UnregisterCallback(el *list.Element[tun.NetworkUpdateCallback]) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callbacks.Remove(el)
}
func (f *fakeNetMonitor) Trigger() {
	f.mu.Lock()
	cbs := f.callbacks.Array()
	f.mu.Unlock()
	for _, cb := range cbs {
		cb()
	}
}

type blockingFakeNLM struct {
	queryStarted chan struct{}
	closed       atomic.Bool
	unregistered atomic.Bool
}

func (b *blockingFakeNLM) Query(ctx context.Context) (map[windows.GUID]uint32, error) {
	select {
	case b.queryStarted <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (b *blockingFakeNLM) UnregisterSink() { b.unregistered.Store(true) }
func (b *blockingFakeNLM) Close()          { b.closed.Store(true) }

func TestWindowsMonitorSameIndexAddressChangeAndDualStack(t *testing.T) {
	finder := &fakeInterfaceFinder{}
	netMon := &fakeNetMonitor{}

	var mu sync.Mutex
	v4Cands := []routeCandidate{
		{Interface: makeCtrlIface(10, "Wi-Fi", "192.168.1.10/24"), Metric: 35, HasNLMInternet: true},
	}
	v6Cands := []routeCandidate{
		{Interface: makeCtrlIface(20, "Cell6", "2001:db8:1::10/64"), Metric: 20, HasNLMInternet: true},
	}
	var probedNew atomic.Bool

	env := winMonitorEnv{
		listCandidates: func(family uint16, _ string, _ control.InterfaceFinder, _ map[windows.GUID]uint32) ([]routeCandidate, error) {
			mu.Lock()
			defer mu.Unlock()
			if family == afInet6 {
				return append([]routeCandidate(nil), v6Cands...), nil
			}
			return append([]routeCandidate(nil), v4Cands...), nil
		},
		startNLM: func(func()) (nlmProvider, error) {
			return nil, errors.New("nlm disabled") // also verifies graceful degradation
		},
		getTargets: func(isV6 bool) []resolver.ProbeTarget {
			if isV6 {
				return []resolver.ProbeTarget{{AddrPort: netip.MustParseAddrPort("[2400:3200::1]:853"), Network: "tcp"}}
			}
			return []resolver.ProbeTarget{{AddrPort: netip.MustParseAddrPort("223.5.5.5:53"), Network: "udp", Priority: 2}}
		},
		probe: func(_ context.Context, name string, _ bool, _ []resolver.ProbeTarget) (bool, bool) {
			if name == "Ethernet 2" {
				probedNew.Store(true)
			}
			return name == "Wi-Fi" || name == "Cell6", true
		},
		debounce: 10 * time.Millisecond,
	}

	m := newWindowsDefaultInterfaceMonitor("Mihomo", netMon, nil, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder}, env)
	var emitCount atomic.Int32
	m.RegisterCallback(func(_ *control.Interface, _ int) {
		emitCount.Add(1)
	})

	if err := m.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Close()

	// Synchronous cold start ready immediately.
	if finder.updates.Load() < 1 {
		t.Fatalf("expected interfaceFinder.Update() to be called on Start")
	}
	if got := m.DefaultInterfaceForAddr(netip.MustParseAddr("1.1.1.1")); got == nil || got.Name != "Wi-Fi" {
		t.Fatalf("v4 addr got = %+v, want Wi-Fi", got)
	}
	if got := m.DefaultInterfaceForAddr(netip.MustParseAddr("::ffff:1.1.1.1")); got == nil || got.Name != "Wi-Fi" {
		t.Fatalf("4in6 addr got = %+v, want Wi-Fi", got)
	}
	if got := m.DefaultInterfaceForAddr(netip.MustParseAddr("2606:4700::1")); got == nil || got.Name != "Cell6" {
		t.Fatalf("v6 addr got = %+v, want Cell6", got)
	}
	if got := m.DefaultInterfaceForAddr(netip.Addr{}); got == nil || got.Name != "Wi-Fi" {
		t.Fatalf("invalid addr got = %+v, want primary Wi-Fi", got)
	}
	if list := m.DefaultInterfaces(); len(list) != 2 {
		t.Fatalf("DefaultInterfaces len = %d, want 2", len(list))
	}

	beforeEmit := emitCount.Load()

	// Wi-Fi gets a new DHCP IP (same Index=10) while Ethernet 2 (lower Metric) attaches.
	mu.Lock()
	v4Cands = []routeCandidate{
		{Interface: makeCtrlIface(30, "Ethernet 2", "192.168.50.2/24"), Metric: 15, HasNLMInternet: false},
		{Interface: makeCtrlIface(10, "Wi-Fi", "192.168.1.99/24"), Metric: 35, HasNLMInternet: true},
	}
	mu.Unlock()
	netMon.Trigger()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if emitCount.Load() > beforeEmit {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if probedNew.Load() {
		t.Fatalf("Ethernet 2 must not be probed when Wi-Fi stays reachable after IP renewal")
	}
	curV4 := m.DefaultInterfaceForAddr(netip.MustParseAddr("1.1.1.1"))
	if curV4 == nil || curV4.Index != 10 || len(curV4.Addresses) != 1 || curV4.Addresses[0] != netip.MustParsePrefix("192.168.1.99/24") {
		t.Fatalf("expected updated Wi-Fi metadata, got %+v", curV4)
	}
}

func TestWindowsMonitorCloseSafetyAndNoDeadlock(t *testing.T) {
	finder := &fakeInterfaceFinder{}
	netMon := &fakeNetMonitor{}

	// 1. Close without Start must be safe and idempotent.
	unstarted := newWindowsDefaultInterfaceMonitor("Mihomo", netMon, nil, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder}, winMonitorEnv{})
	_ = unstarted.Close()
	_ = unstarted.Close()

	// 2. Close while worker is blocked inside NLM Query must not deadlock.
	nlm := &blockingFakeNLM{queryStarted: make(chan struct{}, 2)}
	firstQuery := atomic.Bool{}
	env := winMonitorEnv{
		listCandidates: func(uint16, string, control.InterfaceFinder, map[windows.GUID]uint32) ([]routeCandidate, error) {
			return []routeCandidate{{Interface: makeCtrlIface(10, "Wi-Fi", "192.168.1.10/24"), Metric: 35}}, nil
		},
		startNLM: func(func()) (nlmProvider, error) {
			return &firstPassNLM{firstDone: &firstQuery, inner: nlm}, nil
		},
		debounce: 5 * time.Millisecond,
	}

	m := newWindowsDefaultInterfaceMonitor("Mihomo", netMon, nil, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder}, env)
	if err := m.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Trigger worker checkUpdate which will block inside nlm.Query(ctx).
	m.Wake()
	select {
	case <-nlm.queryStarted:
	case <-time.After(time.Second):
		t.Fatalf("worker did not enter NLM Query in time")
	}

	done := make(chan struct{})
	go func() {
		_ = m.Close()
		_ = m.Close() // idempotent
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Close deadlocked while worker was waiting on NLM Query")
	}
	if !nlm.unregistered.Load() || !nlm.closed.Load() {
		t.Fatalf("expected NLM UnregisterSink and Close to be called")
	}
}

type firstPassNLM struct {
	firstDone *atomic.Bool
	inner     *blockingFakeNLM
}

func (f *firstPassNLM) Query(ctx context.Context) (map[windows.GUID]uint32, error) {
	if f.firstDone.CompareAndSwap(false, true) {
		return nil, nil
	}
	return f.inner.Query(ctx)
}
func (f *firstPassNLM) UnregisterSink() { f.inner.UnregisterSink() }
func (f *firstPassNLM) Close()          { f.inner.Close() }

func TestForwardingCheckerMultiEgressTargets(t *testing.T) {
	v4If := makeCtrlIface(10, "Wi-Fi", "192.168.1.10/24")
	v6If := makeCtrlIface(20, "Cell6", "2001:db8:1::10/64")

	netMon := &fakeNetMonitor{}
	m := newWindowsDefaultInterfaceMonitor("Mihomo", netMon, nil, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: &fakeInterfaceFinder{},
	}, winMonitorEnv{})
	m.defaultV4.Store(v4If)
	m.defaultV6.Store(v6If)
	m.primary.Store(v4If)

	env := forwardingCheckEnv{
		indexToLUID: func(index int) (uint64, error) { return uint64(index * 100), nil },
		nameToLUID:  func(string) (uint64, error) { return 0, errIPInterfaceGone },
		boundInterface: func() (int, string) {
			return 0, ""
		},
	}

	c := newForwardingChecker(env, "Mihomo", true, netMon, m)
	targets := c.targets()
	if len(targets) != 2 {
		t.Fatalf("forwardingChecker targets len = %d, want 2 (%+v)", len(targets), targets)
	}
}