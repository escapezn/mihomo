//go:build windows

package sing_tun

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/windows"
)

const (
	coinitMultithreaded = 0x0
	clsctxAll           = 0x17
	lmemZeroInit        = 0x0040

	comSOK          uintptr = 0x00000000
	comSFalse       uintptr = 0x00000001
	comENoInterface uintptr = 0x80004002
	comEPointer     uintptr = 0x80004003

	nlmConnectivityIPv4Internet uint32 = 0x0040
	nlmConnectivityIPv6Internet uint32 = 0x0400
)

var (
	modOle32             = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx   = modOle32.NewProc("CoInitializeEx")
	procCoCreateInstance = modOle32.NewProc("CoCreateInstance")
	procCoUninitialize   = modOle32.NewProc("CoUninitialize")

	modKernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procLocalAlloc = modKernel32.NewProc("LocalAlloc")
	procLocalFree  = modKernel32.NewProc("LocalFree")
)

var (
	iidIUnknown = windows.GUID{
		Data1: 0x00000000, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	clsidNetworkListManager = windows.GUID{
		Data1: 0xDCB00C01, Data2: 0x570F, Data3: 0x4A9B,
		Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B},
	}
	iidINetworkListManager = windows.GUID{
		Data1: 0xDCB00000, Data2: 0x570F, Data3: 0x4A9B,
		Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B},
	}
	iidINetworkConnectionEvents = windows.GUID{
		Data1: 0xDCB00007, Data2: 0x570F, Data3: 0x4A9B,
		Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B},
	}
	iidIConnectionPointContainer = windows.GUID{
		Data1: 0xB196B284, Data2: 0xBAB4, Data3: 0x101A,
		Data4: [8]byte{0xB6, 0x9C, 0x00, 0xAA, 0x00, 0x34, 0x1D, 0x07},
	}
)

var errNLMClosed = errors.New("nlm client closed")

// rawPtr converts an unmanaged Windows/COM pointer stored as uintptr to
// unsafe.Pointer. Must only be used for non-Go-heap memory.
func rawPtr(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

func comCall(obj uintptr, slot uintptr, args ...uintptr) uintptr {
	vtbl := *(*uintptr)(rawPtr(obj))
	method := *(*uintptr)(rawPtr(vtbl + slot*unsafe.Sizeof(uintptr(0))))
	callArgs := make([]uintptr, 0, len(args)+1)
	callArgs = append(callArgs, obj)
	callArgs = append(callArgs, args...)
	r0, _, _ := syscall.SyscallN(method, callArgs...)
	return r0
}

func comRelease(obj uintptr) {
	if obj != 0 {
		comCall(obj, 2)
	}
}

func comSucceeded(hr uintptr) bool {
	return int32(hr) >= 0
}

// nlmSinkVtbl matches the IUnknown + INetworkConnectionEvents COM vtable layout.
// Allocated as a package global so it stays alive for the lifetime of the process.
type nlmSinkVtbl struct {
	queryInterface       uintptr
	addRef               uintptr
	release              uintptr
	connectivityChanged  uintptr
	propertyChanged      uintptr
}

// nlmSinkObject is allocated in unmanaged Windows memory via LocalAlloc and
// freed by LocalFree only when refCount drops to zero in Release.
type nlmSinkObject struct {
	vtbl     uintptr
	refCount int32
	_        uint32
	sinkID   uintptr
}

var (
	nlmSinkInitOnce sync.Once
	nlmGlobalVtbl   nlmSinkVtbl
	nlmSinkNextID   atomic.Uintptr
	nlmSinkRegistry sync.Map // map[uintptr]func()
)

func initNLMSinkVtbl() bool {
	nlmSinkInitOnce.Do(func() {
		cbConn := newNLMConnectivityChangedCallback()
		cbProp := newNLMPropertyChangedCallback()
		if cbConn == 0 || cbProp == 0 {
			return
		}
		nlmGlobalVtbl = nlmSinkVtbl{
			queryInterface:      syscall.NewCallback(nlmSinkQueryInterface),
			addRef:              syscall.NewCallback(nlmSinkAddRef),
			release:             syscall.NewCallback(nlmSinkRelease),
			connectivityChanged: cbConn,
			propertyChanged:     cbProp,
		}
	})
	return nlmGlobalVtbl.connectivityChanged != 0
}

func nlmSinkQueryInterface(this, riid, ppvObject uintptr) uintptr {
	if ppvObject == 0 {
		return comEPointer
	}
	*(*uintptr)(rawPtr(ppvObject)) = 0
	if riid == 0 {
		return comENoInterface
	}
	guid := *(*windows.GUID)(rawPtr(riid))
	if guid == iidIUnknown || guid == iidINetworkConnectionEvents {
		*(*uintptr)(rawPtr(ppvObject)) = this
		nlmSinkAddRef(this)
		return comSOK
	}
	return comENoInterface
}

func nlmSinkAddRef(this uintptr) uintptr {
	obj := (*nlmSinkObject)(rawPtr(this))
	return uintptr(atomic.AddInt32(&obj.refCount, 1))
}

func nlmSinkRelease(this uintptr) uintptr {
	obj := (*nlmSinkObject)(rawPtr(this))
	rc := atomic.AddInt32(&obj.refCount, -1)
	if rc == 0 {
		_, _, _ = procLocalFree.Call(this)
	}
	return uintptr(rc)
}

func nlmNotifySink(this uintptr) {
	if this == 0 {
		return
	}
	obj := (*nlmSinkObject)(rawPtr(this))
	if fn, ok := nlmSinkRegistry.Load(obj.sinkID); ok {
		fn.(func())()
	}
}

func allocNLMSink(notify func()) (sinkPtr uintptr, sinkID uintptr, err error) {
	if !initNLMSinkVtbl() {
		return 0, 0, errors.New("NLM event callbacks unsupported on this architecture")
	}
	if err := procLocalAlloc.Find(); err != nil {
		return 0, 0, err
	}
	if err := procLocalFree.Find(); err != nil {
		return 0, 0, err
	}

	ptr, _, callErr := procLocalAlloc.Call(lmemZeroInit, unsafe.Sizeof(nlmSinkObject{}))
	if ptr == 0 {
		return 0, 0, fmt.Errorf("LocalAlloc nlmSinkObject: %w", callErr)
	}

	id := nlmSinkNextID.Add(1)
	nlmSinkRegistry.Store(id, notify)

	obj := (*nlmSinkObject)(rawPtr(ptr))
	obj.vtbl = uintptr(unsafe.Pointer(&nlmGlobalVtbl))
	obj.refCount = 1 // owned by Go caller until Close/Advise failure
	obj.sinkID = id
	return ptr, id, nil
}

type nlmQueryResp struct {
	connectivity map[windows.GUID]uint32
	err          error
}

type nlmQueryReq struct {
	ctx    context.Context
	respCh chan nlmQueryResp
}

type nlmClient struct {
	reqCh     chan nlmQueryReq
	stopCh    chan struct{}
	doneCh    chan struct{}
	sinkID    atomic.Uintptr
	closeOnce sync.Once
}

func startNLMClient(onChange func()) (*nlmClient, error) {
	if err := procCoInitializeEx.Find(); err != nil {
		return nil, err
	}
	if err := procCoCreateInstance.Find(); err != nil {
		return nil, err
	}
	if err := procCoUninitialize.Find(); err != nil {
		return nil, err
	}

	c := &nlmClient{
		reqCh:  make(chan nlmQueryReq),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	readyCh := make(chan error, 1)

	go c.run(onChange, readyCh)

	if err := <-readyCh; err != nil {
		<-c.doneCh
		return nil, err
	}
	return c, nil
}

func (c *nlmClient) run(onChange func(), readyCh chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(c.doneCh)

	hr, _, _ := procCoInitializeEx.Call(0, coinitMultithreaded)
	coInitOK := hr == comSOK || hr == comSFalse
	if !coInitOK {
		readyCh <- fmt.Errorf("CoInitializeEx failed: 0x%08x", uint32(hr))
		return
	}
	defer procCoUninitialize.Call()

	var nlm uintptr
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidNetworkListManager)),
		0,
		clsctxAll,
		uintptr(unsafe.Pointer(&iidINetworkListManager)),
		uintptr(unsafe.Pointer(&nlm)),
	)
	if !comSucceeded(hr) || nlm == 0 {
		readyCh <- fmt.Errorf("CoCreateInstance(NetworkListManager) failed: 0x%08x", uint32(hr))
		return
	}
	defer comRelease(nlm)

	var (
		cpc     uintptr
		cp      uintptr
		sinkPtr uintptr
		cookie  uint32
		advised bool
	)

	if onChange != nil {
		if err := c.adviseEvents(nlm, onChange, &cpc, &cp, &sinkPtr, &cookie, &advised); err != nil {
			log.Warnln("[TUN] NLM event subscription unavailable, continuing with query-only mode: %s", err)
		}
	}
	defer func() {
		if id := c.sinkID.Swap(0); id != 0 {
			nlmSinkRegistry.Delete(id)
		}
		if advised && cp != 0 {
			// IConnectionPoint::Unadvise is vtable slot 6.
			comCall(cp, 6, uintptr(cookie))
		}
		if sinkPtr != 0 {
			// Release Go owner reference; LocalFree runs when refCount hits 0.
			nlmSinkRelease(sinkPtr)
		}
		comRelease(cp)
		comRelease(cpc)
	}()

	readyCh <- nil

	for {
		select {
		case <-c.stopCh:
			return
		case req := <-c.reqCh:
			connMap, err := queryNLMConnections(nlm)
			select {
			case req.respCh <- nlmQueryResp{connectivity: connMap, err: err}:
			case <-req.ctx.Done():
			case <-c.stopCh:
				return
			}
		}
	}
}

func (c *nlmClient) adviseEvents(
	nlm uintptr,
	onChange func(),
	cpc *uintptr,
	cp *uintptr,
	sinkPtr *uintptr,
	cookie *uint32,
	advised *bool,
) error {
	// IUnknown::QueryInterface(IID_IConnectionPointContainer) is slot 0.
	hr := comCall(nlm, 0, uintptr(unsafe.Pointer(&iidIConnectionPointContainer)), uintptr(unsafe.Pointer(cpc)))
	if !comSucceeded(hr) || *cpc == 0 {
		return fmt.Errorf("QueryInterface(IConnectionPointContainer): 0x%08x", uint32(hr))
	}

	// IConnectionPointContainer::FindConnectionPoint(IID_INetworkConnectionEvents) is slot 4.
	hr = comCall(*cpc, 4, uintptr(unsafe.Pointer(&iidINetworkConnectionEvents)), uintptr(unsafe.Pointer(cp)))
	if !comSucceeded(hr) || *cp == 0 {
		return fmt.Errorf("FindConnectionPoint(INetworkConnectionEvents): 0x%08x", uint32(hr))
	}

	ptr, id, err := allocNLMSink(onChange)
	if err != nil {
		return err
	}
	*sinkPtr = ptr
	c.sinkID.Store(id)

	// IConnectionPoint::Advise(pUnkSink, &cookie) is slot 5.
	hr = comCall(*cp, 5, ptr, uintptr(unsafe.Pointer(cookie)))
	if !comSucceeded(hr) {
		c.sinkID.Store(0)
		nlmSinkRegistry.Delete(id)
		nlmSinkRelease(ptr) // 1 -> 0 triggers LocalFree
		*sinkPtr = 0
		return fmt.Errorf("IConnectionPoint::Advise: 0x%08x", uint32(hr))
	}
	*advised = true
	return nil
}

func queryNLMConnections(nlm uintptr) (map[windows.GUID]uint32, error) {
	// INetworkListManager::GetNetworkConnections is vtable slot 9 (after IUnknown[0..2] + IDispatch[3..6] + GetNetworks[7] + GetNetwork[8]).
	var enumPtr uintptr
	hr := comCall(nlm, 9, uintptr(unsafe.Pointer(&enumPtr)))
	if !comSucceeded(hr) || enumPtr == 0 {
		return nil, fmt.Errorf("GetNetworkConnections: 0x%08x", uint32(hr))
	}
	defer comRelease(enumPtr)

	result := make(map[windows.GUID]uint32)
	for {
		var connPtr uintptr
		var fetched uint32
		// IEnumNetworkConnections::Next(celt=1, &connPtr, &fetched) is slot 8.
		hr := comCall(enumPtr, 8, 1, uintptr(unsafe.Pointer(&connPtr)), uintptr(unsafe.Pointer(&fetched)))
		if !comSucceeded(hr) || fetched == 0 || connPtr == 0 {
			if connPtr != 0 {
				comRelease(connPtr)
			}
			break
		}

		var adapterGUID windows.GUID
		var connectivity uint32
		// INetworkConnection::GetConnectivity is slot 10; GetAdapterId is slot 12.
		hrConn := comCall(connPtr, 10, uintptr(unsafe.Pointer(&connectivity)))
		hrGUID := comCall(connPtr, 12, uintptr(unsafe.Pointer(&adapterGUID)))
		comRelease(connPtr)

		if comSucceeded(hrConn) && comSucceeded(hrGUID) {
			result[adapterGUID] |= connectivity
		}
		if hr == comSFalse {
			break
		}
	}
	return result, nil
}

// UnregisterSink immediately stops event callbacks from waking callers without
// blocking. Must be called before waiting for worker shutdown.
func (c *nlmClient) UnregisterSink() {
	if c == nil {
		return
	}
	if id := c.sinkID.Swap(0); id != 0 {
		nlmSinkRegistry.Delete(id)
	}
}

func (c *nlmClient) Query(ctx context.Context) (map[windows.GUID]uint32, error) {
	if c == nil {
		return nil, errNLMClosed
	}
	req := nlmQueryReq{
		ctx:    ctx,
		respCh: make(chan nlmQueryResp, 1),
	}
	select {
	case c.reqCh <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.doneCh:
		return nil, errNLMClosed
	}
	select {
	case resp := <-req.respCh:
		return resp.connectivity, resp.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.doneCh:
		return nil, errNLMClosed
	}
}

// Close shuts down the dedicated COM thread and waits for cleanup to complete.
// Callers must stop any worker issuing Query() before calling Close().
func (c *nlmClient) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.UnregisterSink()
		close(c.stopCh)
		<-c.doneCh
	})
}