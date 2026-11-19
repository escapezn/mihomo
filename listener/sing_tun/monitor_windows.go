//go:build windows

package sing_tun

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/logger"
	"github.com/metacubex/sing/common/x/list"
	"golang.org/x/sys/windows"
)

const (
	ifMaxStringSize        = 256
	ifMaxPhysAddressLength = 32

	ifOperStatusUp         uint32 = 1
	ifTypeSoftwareLoopback uint32 = 24
	ifTypePropVirtual      uint32 = 53

	windowsMonitorDebounce = time.Second
)

// zeroTierFakeGatewayIp matches sing-tun's monitor_windows.go filter.
var zeroTierFakeGatewayIp = netip.MustParseAddr("25.255.255.254")

var (
	procGetIpForwardTable2 = modIPHlpAPI.NewProc("GetIpForwardTable2")
	procFreeMibTable       = modIPHlpAPI.NewProc("FreeMibTable")
	procGetIfEntry2        = modIPHlpAPI.NewProc("GetIfEntry2")
)

// rawSockaddrInet mirrors SOCKADDR_INET from ws2ipdef.h (28 bytes).
type rawSockaddrInet struct {
	Family uint16
	data   [26]byte
}

func (r *rawSockaddrInet) Addr() netip.Addr {
	switch r.Family {
	case afInet:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(r)).Addr)
	case afInet6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(r)).Addr)
	default:
		return netip.Addr{}
	}
}

// ipAddressPrefix mirrors IP_ADDRESS_PREFIX from netioapi.h (32 bytes).
type ipAddressPrefix struct {
	RawPrefix    rawSockaddrInet
	PrefixLength uint8
	_            [2]byte
}

// mibIPforwardRow2 mirrors MIB_IPFORWARD_ROW2 from netioapi.h (104 bytes).
type mibIPforwardRow2 struct {
	InterfaceLUID        uint64
	InterfaceIndex       uint32
	DestinationPrefix    ipAddressPrefix
	NextHop              rawSockaddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               uint32
}

// mibIPforwardTable2 mirrors MIB_IPFORWARD_TABLE2 from netioapi.h (112 bytes).
type mibIPforwardTable2 struct {
	numEntries uint32
	_          [4]byte
	table      [1]mibIPforwardRow2
}

const (
	mibIPforwardRow2Size   = 104
	mibIPforwardTable2Size = 112
)

var (
	_ [mibIPforwardRow2Size - unsafe.Sizeof(mibIPforwardRow2{})]byte
	_ [unsafe.Sizeof(mibIPforwardRow2{}) - mibIPforwardRow2Size]byte
	_ [mibIPforwardTable2Size - unsafe.Sizeof(mibIPforwardTable2{})]byte
	_ [unsafe.Sizeof(mibIPforwardTable2{}) - mibIPforwardTable2Size]byte
)

func (r *mibIfRow2) Alias() string {
	return windows.UTF16ToString(r.alias[:])
}

func getIPForwardTable2(family uint16) ([]mibIPforwardRow2, error) {
	if err := procGetIpForwardTable2.Find(); err != nil {
		return nil, err
	}
	if err := procFreeMibTable.Find(); err != nil {
		return nil, err
	}
	var tab *mibIPforwardTable2
	r0, _, _ := syscall.SyscallN(procGetIpForwardTable2.Addr(), uintptr(family), uintptr(unsafe.Pointer(&tab)))
	if r0 != 0 {
		return nil, syscall.Errno(r0)
	}
	if tab == nil {
		return nil, nil
	}
	defer syscall.SyscallN(procFreeMibTable.Addr(), uintptr(unsafe.Pointer(tab)))

	count := int(tab.numEntries)
	if count == 0 {
		return nil, nil
	}
	rows := unsafe.Slice(&tab.table[0], count)
	out := make([]mibIPforwardRow2, count)
	copy(out, rows)
	return out, nil
}

func getIfEntry2(luid uint64) (*mibIfRow2, error) {
	row := &mibIfRow2{InterfaceLUID: luid}
	if err := ipHlpCall(procGetIfEntry2, uintptr(unsafe.Pointer(row))); err != nil {
		return nil, err
	}
	return row, nil
}

type routeCandidate struct {
	Interface      *control.Interface
	GUID           windows.GUID
	Metric         uint32
	HasNLMInternet bool
}

type selectReason string

const (
	reasonNoRoute                selectReason = "no-route"
	reasonStickySingle           selectReason = "sticky-single"
	reasonStickyVerified         selectReason = "sticky-dns-verified"
	reasonStickyNLM              selectReason = "sticky-nlm-internet"
	reasonStickyAllUnreachable   selectReason = "sticky-all-unreachable"
	reasonFailoverDNS            selectReason = "failover-dns"
	reasonFailoverNLM            selectReason = "failover-nlm"
	reasonSingleCandidate        selectReason = "single-candidate"
	reasonSelectedDNS            selectReason = "selected-dns"
	reasonSelectedNLM            selectReason = "selected-nlm"
	reasonSelectedMetricFallback selectReason = "selected-metric-fallback"
)

type nlmProvider interface {
	Query(ctx context.Context) (map[windows.GUID]uint32, error)
	UnregisterSink()
	Close()
}

type winMonitorEnv struct {
	listCandidates func(family uint16, tunName string, finder control.InterfaceFinder, nlmConn map[windows.GUID]uint32) ([]routeCandidate, error)
	startNLM       func(onChange func()) (nlmProvider, error)
	getTargets     func(isV6 bool) []resolver.ProbeTarget
	probe          func(ctx context.Context, ifaceName string, isV6 bool, targets []resolver.ProbeTarget) (bool, bool)
	debounce       time.Duration
}

func defaultWinMonitorEnv() winMonitorEnv {
	return winMonitorEnv{
		listCandidates: enumerateDefaultRouteCandidates,
		startNLM: func(onChange func()) (nlmProvider, error) {
			return startNLMClient(onChange)
		},
		getTargets: resolver.GetProbeTargets,
		probe:      probeInterface,
		debounce:   windowsMonitorDebounce,
	}
}

func enumerateDefaultRouteCandidates(
	family uint16,
	tunName string,
	finder control.InterfaceFinder,
	nlmConn map[windows.GUID]uint32,
) ([]routeCandidate, error) {
	rows, err := getIPForwardTable2(family)
	if err != nil {
		return nil, err
	}

	internetFlag := nlmConnectivityIPv4Internet
	if family == afInet6 {
		internetFlag = nlmConnectivityIPv6Internet
	}

	byIndex := make(map[int]routeCandidate)
	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		if family == afInet && row.NextHop.Addr() == zeroTierFakeGatewayIp {
			continue
		}

		ifrow, err := getIfEntry2(row.InterfaceLUID)
		if err != nil || ifrow.OperStatus != ifOperStatusUp {
			continue
		}
		if ifrow.Type == ifTypePropVirtual || ifrow.Type == ifTypeSoftwareLoopback {
			continue
		}
		if tunName != "" && strings.EqualFold(ifrow.Alias(), tunName) {
			continue
		}

		ipIface, err := getIPInterfaceRow(row.InterfaceLUID, family)
		if err != nil || !ipIface.Connected || ipIface.DisableDefaultRoutes {
			continue
		}

		idx := int(ifrow.InterfaceIndex)
		metric := row.Metric + ipIface.Metric
		if prev, exists := byIndex[idx]; exists {
			if metric < prev.Metric {
				prev.Metric = metric
				byIndex[idx] = prev
			}
			continue
		}

		ctrlIf, err := finder.ByIndex(idx)
		if err != nil || ctrlIf == nil {
			continue
		}
		if tunName != "" && strings.EqualFold(ctrlIf.Name, tunName) {
			continue
		}

		hasInternet := false
		if nlmConn != nil {
			hasInternet = (nlmConn[ifrow.InterfaceGUID] & internetFlag) != 0
		}

		byIndex[idx] = routeCandidate{
			Interface:      ctrlIf,
			GUID:           ifrow.InterfaceGUID,
			Metric:         metric,
			HasNLMInternet: hasInternet,
		}
	}

	candidates := make([]routeCandidate, 0, len(byIndex))
	for _, cand := range byIndex {
		candidates = append(candidates, cand)
	}
	sortRouteCandidates(candidates)
	return candidates, nil
}

func sortRouteCandidates(candidates []routeCandidate) {
	slices.SortFunc(candidates, func(a, b routeCandidate) int {
		if c := cmp.Compare(a.Metric, b.Metric); c != 0 {
			return c
		}
		return cmp.Compare(a.Interface.Index, b.Interface.Index)
	})
}

type windowsDefaultInterfaceMonitor struct {
	tunName            string
	interfaceFinder    control.InterfaceFinder
	overrideAndroidVPN bool
	networkMonitor     tun.NetworkUpdateMonitor
	logger             logger.Logger
	env                winMonitorEnv

	defaultV4 atomic.Pointer[control.Interface]
	defaultV6 atomic.Pointer[control.Interface]
	primary   atomic.Pointer[control.Interface]

	startMu     sync.Mutex
	started     bool
	closeOnce   sync.Once
	closeCtx    context.Context
	closeCancel context.CancelFunc
	netElement  *list.Element[tun.NetworkUpdateCallback]
	nlm         nlmProvider
	triggerCh   chan struct{}
	workerDone  chan struct{}

	cbMu      sync.Mutex
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
}

func newDefaultInterfaceMonitor(
	tunName string,
	networkMonitor tun.NetworkUpdateMonitor,
	l logger.Logger,
	options tun.DefaultInterfaceMonitorOptions,
) (tun.DefaultInterfaceMonitor, error) {
	return newWindowsDefaultInterfaceMonitor(tunName, networkMonitor, l, options, defaultWinMonitorEnv()), nil
}

func newWindowsDefaultInterfaceMonitor(
	tunName string,
	networkMonitor tun.NetworkUpdateMonitor,
	l logger.Logger,
	options tun.DefaultInterfaceMonitorOptions,
	env winMonitorEnv,
) *windowsDefaultInterfaceMonitor {
	if env.debounce <= 0 {
		env.debounce = windowsMonitorDebounce
	}
	return &windowsDefaultInterfaceMonitor{
		tunName:            tunName,
		interfaceFinder:    options.InterfaceFinder,
		overrideAndroidVPN: options.OverrideAndroidVPN,
		networkMonitor:     networkMonitor,
		logger:             l,
		env:                env,
		triggerCh:          make(chan struct{}, 1),
	}
}

func (m *windowsDefaultInterfaceMonitor) Start() error {
	m.startMu.Lock()
	defer m.startMu.Unlock()
	if m.started {
		return nil
	}

	m.closeCtx, m.closeCancel = context.WithCancel(context.Background())
	m.workerDone = make(chan struct{})
	m.started = true

	// Start NLM before registering route callbacks and running the initial check.
	// Failures degrade gracefully to route-only + DNS probing / Metric fallback.
	if m.env.startNLM != nil {
		nlm, err := m.env.startNLM(m.Wake)
		if err != nil {
			log.Warnln("[TUN] NLM unavailable, falling back to route monitor + DNS probing: %s", err)
		} else {
			m.nlm = nlm
		}
	}

	if m.networkMonitor != nil {
		m.netElement = m.networkMonitor.RegisterCallback(m.Wake)
	}

	// Perform initial selection synchronously so DefaultInterface() is ready
	// before Start() returns.
	if err := m.checkUpdate(m.closeCtx); err != nil {
		log.Warnln("[TUN] initial default interface check failed, will retry: %s", err)
		m.Wake()
	}

	go m.workerLoop()
	return nil
}

func (m *windowsDefaultInterfaceMonitor) Wake() {
	select {
	case m.triggerCh <- struct{}{}:
	default:
	}
}

func (m *windowsDefaultInterfaceMonitor) workerLoop() {
	defer close(m.workerDone)

	var timer *time.Timer
	var timerCh <-chan time.Time
	stopTimer := func() {
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer = nil
			timerCh = nil
		}
	}
	defer stopTimer()

	for {
		select {
		case <-m.closeCtx.Done():
			return
		case <-m.triggerCh:
			if timer == nil {
				timer = time.NewTimer(m.env.debounce)
				timerCh = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(m.env.debounce)
			}
		case <-timerCh:
			timer = nil
			timerCh = nil
			if m.closeCtx.Err() != nil {
				return
			}
			if err := m.checkUpdate(m.closeCtx); err != nil && m.closeCtx.Err() == nil {
				log.Warnln("[TUN] check default interface failed, will retry: %s", err)
				m.Wake()
			}
		}
	}
}

// Close is idempotent and safe to call even if Start() was never called.
// Shutdown order strictly stops the worker before shutting down the COM thread
// so in-flight NLM queries can never deadlock.
func (m *windowsDefaultInterfaceMonitor) Close() error {
	m.closeOnce.Do(func() {
		m.startMu.Lock()
		started := m.started
		cancel := m.closeCancel
		netElem := m.netElement
		m.netElement = nil
		nlm := m.nlm
		workerDone := m.workerDone
		m.startMu.Unlock()

		if !started {
			return
		}

		// 1. Cancel any active DNS probes or NLM queries immediately.
		if cancel != nil {
			cancel()
		}
		// 2. Unregister route callbacks and NLM sink notifications without blocking.
		if netElem != nil && m.networkMonitor != nil {
			m.networkMonitor.UnregisterCallback(netElem)
		}
		if nlm != nil {
			nlm.UnregisterSink()
		}
		// 3. Wait for the worker goroutine to exit before tearing down COM.
		if workerDone != nil {
			<-workerDone
		}
		// 4. Shut down the dedicated COM thread cleanly.
		if nlm != nil {
			nlm.Close()
		}
	})
	return nil
}

func (m *windowsDefaultInterfaceMonitor) checkUpdate(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Refresh interface cache first so newly attached interfaces are visible to
	// dialer.WithInterface() instead of hitting component/iface's 20s cache.
	if err := m.interfaceFinder.Update(); err != nil {
		return err
	}

	var nlmConn map[windows.GUID]uint32
	if m.nlm != nil {
		if connMap, err := m.nlm.Query(ctx); err == nil {
			nlmConn = connMap
		}
	}

	v4Candidates, v4Err := m.env.listCandidates(afInet, m.tunName, m.interfaceFinder, nlmConn)
	v6Candidates, v6Err := m.env.listCandidates(afInet6, m.tunName, m.interfaceFinder, nlmConn)
	if v4Err != nil && v6Err != nil {
		return v4Err
	}

	oldV4 := m.defaultV4.Load()
	oldV6 := m.defaultV6.Load()

	var targetsV4, targetsV6 []resolver.ProbeTarget
	if m.env.getTargets != nil {
		targetsV4 = m.env.getTargets(false)
		targetsV6 = m.env.getTargets(true)
	}

	var (
		newV4    *control.Interface
		reasonV4 selectReason
		newV6    *control.Interface
		reasonV6 selectReason
	)

	// Evaluate IPv4 and IPv6 concurrently so worst-case latency is bounded by
	// a single probe timeout window.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if v4Err == nil {
			newV4, reasonV4 = selectInterface(ctx, false, oldV4, v4Candidates, targetsV4, m.env.probe)
		} else {
			newV4, reasonV4 = oldV4, reasonNoRoute
		}
	}()
	go func() {
		defer wg.Done()
		if v6Err == nil {
			newV6, reasonV6 = selectInterface(ctx, true, oldV6, v6Candidates, targetsV6, m.env.probe)
		} else {
			newV6, reasonV6 = oldV6, reasonNoRoute
		}
	}()
	wg.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	v4Event := m.logFamilyTransition("IPv4", oldV4, newV4, reasonV4)
	v6Event := m.logFamilyTransition("IPv6", oldV6, newV6, reasonV6)

	m.defaultV4.Store(newV4)
	m.defaultV6.Store(newV6)

	primary := newV4
	if primary == nil {
		primary = newV6
	}
	m.primary.Store(primary)

	if v4Event || v6Event {
		m.emit(primary, 0)
	}
	return nil
}

func (m *windowsDefaultInterfaceMonitor) logFamilyTransition(
	family string,
	oldIf *control.Interface,
	newIf *control.Interface,
	reason selectReason,
) bool {
	if oldIf == nil && newIf == nil {
		return false
	}
	if oldIf != nil && newIf != nil && oldIf.Index == newIf.Index {
		if !oldIf.Equals(*newIf) {
			log.Infoln("[TUN] %s default interface updated: %s (%s)", family, newIf.Name, reason)
			return true
		}
		log.Debugln("[TUN] %s default interface kept sticky: %s (%s)", family, newIf.Name, reason)
		return false
	}

	switch {
	case oldIf == nil && newIf != nil:
		log.Warnln("[TUN] %s default interface selected => %s (%s)", family, newIf.Name, reason)
	case oldIf != nil && newIf == nil:
		log.Warnln("[TUN] %s default interface lost (was %s, %s)", family, oldIf.Name, reason)
	default:
		log.Warnln("[TUN] %s default interface changed: %s => %s (%s)", family, oldIf.Name, newIf.Name, reason)
	}
	return true
}

type probeFn func(ctx context.Context, ifaceName string, isV6 bool, targets []resolver.ProbeTarget) (bool, bool)

// selectInterface implements the sticky-first + failover selection state machine
// for a single address family. candidates must be sorted by (Metric, Index).
func selectInterface(
	ctx context.Context,
	isV6 bool,
	current *control.Interface,
	candidates []routeCandidate,
	targets []resolver.ProbeTarget,
	probe probeFn,
) (*control.Interface, selectReason) {
	if len(candidates) == 0 {
		return nil, reasonNoRoute
	}

	hasTargets := len(targets) > 0 && probe != nil

	// Match current strictly by InterfaceIndex so DHCP renewals or address changes
	// on the active interface stay on the sticky path without probing new NICs.
	currentPos := -1
	if current != nil {
		for i := range candidates {
			if candidates[i].Interface.Index == current.Index {
				currentPos = i
				break
			}
		}
	}

	// Branch A: current interface is still present among default route candidates.
	if currentPos >= 0 {
		currentCand := candidates[currentPos]
		if len(candidates) == 1 {
			return currentCand.Interface, reasonStickySingle
		}

		if hasTargets {
			// Probe ONLY the current interface first. Never touch newly attached NICs
			// while the current egress still reaches the public DNS servers.
			if ok, probed := probe(ctx, currentCand.Interface.Name, isV6, targets); probed && ok {
				return currentCand.Interface, reasonStickyVerified
			}

			// Current interface failed DNS probe: concurrently probe all other candidates.
			others := make([]routeCandidate, 0, len(candidates)-1)
			for i, cand := range candidates {
				if i != currentPos {
					others = append(others, cand)
				}
			}
			if best := pickBestByDNSProbe(ctx, isV6, others, targets, probe); best != nil {
				return best, reasonFailoverDNS
			}
			// All candidates failed DNS probe: stay on current (do not switch based on stale NLM).
			return currentCand.Interface, reasonStickyAllUnreachable
		}

		// No public DNS probe targets configured: fall back to NLM Internet status.
		if currentCand.HasNLMInternet {
			return currentCand.Interface, reasonStickyNLM
		}
		for i, cand := range candidates {
			if i != currentPos && cand.HasNLMInternet {
				return cand.Interface, reasonFailoverNLM
			}
		}
		return currentCand.Interface, reasonStickyAllUnreachable
	}

	// Branch B: cold start (current == nil) or previous interface disappeared.
	if len(candidates) == 1 {
		return candidates[0].Interface, reasonSingleCandidate
	}

	if hasTargets {
		if best := pickBestByDNSProbe(ctx, isV6, candidates, targets, probe); best != nil {
			return best, reasonSelectedDNS
		}
	}
	for _, cand := range candidates {
		if cand.HasNLMInternet {
			return cand.Interface, reasonSelectedNLM
		}
	}
	return candidates[0].Interface, reasonSelectedMetricFallback
}

// pickBestByDNSProbe concurrently probes candidates (already sorted by Metric)
// and returns the lowest-Metric reachable interface, or nil if none succeed.
func pickBestByDNSProbe(
	ctx context.Context,
	isV6 bool,
	candidates []routeCandidate,
	targets []resolver.ProbeTarget,
	probe probeFn,
) *control.Interface {
	if len(candidates) == 0 || len(targets) == 0 || probe == nil {
		return nil
	}

	results := make([]bool, len(candidates))
	var wg sync.WaitGroup
	for i, cand := range candidates {
		wg.Add(1)
		go func(idx int, ifaceName string) {
			defer wg.Done()
			ok, probed := probe(ctx, ifaceName, isV6, targets)
			if probed && ok {
				results[idx] = true
			}
		}(i, cand.Interface.Name)
	}
	wg.Wait()

	for i, ok := range results {
		if ok {
			return candidates[i].Interface
		}
	}
	return nil
}

func (m *windowsDefaultInterfaceMonitor) DefaultInterface() *control.Interface {
	return m.primary.Load()
}

func (m *windowsDefaultInterfaceMonitor) DefaultInterfaceForAddr(destination netip.Addr) *control.Interface {
	dest := destination.Unmap()
	if !dest.IsValid() {
		return m.DefaultInterface()
	}
	if dest.Is4() {
		if v4 := m.defaultV4.Load(); v4 != nil {
			return v4
		}
		return m.defaultV6.Load()
	}
	if v6 := m.defaultV6.Load(); v6 != nil {
		return v6
	}
	return m.defaultV4.Load()
}

func (m *windowsDefaultInterfaceMonitor) DefaultInterfaces() []*control.Interface {
	v4 := m.defaultV4.Load()
	v6 := m.defaultV6.Load()
	if v4 == nil && v6 == nil {
		return nil
	}
	if v4 != nil && v6 != nil && v4.Index != v6.Index {
		return []*control.Interface{v4, v6}
	}
	if v4 != nil {
		return []*control.Interface{v4}
	}
	return []*control.Interface{v6}
}

func (m *windowsDefaultInterfaceMonitor) OverrideAndroidVPN() bool {
	return m.overrideAndroidVPN
}

func (m *windowsDefaultInterfaceMonitor) AndroidVPNEnabled() bool {
	return false
}

func (m *windowsDefaultInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *windowsDefaultInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()
	m.callbacks.Remove(element)
}

func (m *windowsDefaultInterfaceMonitor) emit(defaultInterface *control.Interface, flags int) {
	m.cbMu.Lock()
	callbacks := m.callbacks.Array()
	m.cbMu.Unlock()
	for _, callback := range callbacks {
		callback(defaultInterface, flags)
	}
}