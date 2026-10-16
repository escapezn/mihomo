package outbound

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
)

type Reject struct {
	*Base
	drop    bool
	noDrop  bool
	limiter *RejectRateLimiter
}

func (r *Reject) SetLimiter(limiter *RejectRateLimiter) {
	r.limiter = limiter
}

type RejectOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (r *Reject) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if r.drop || (!r.noDrop && r.limiter != nil && r.limiter.ShouldDrop(metadata)) {
		return NewConn(newDropConn(), r), nil
	}
	return NewConn(nopConn{}, r), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (r *Reject) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := r.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	if r.drop || (!r.noDrop && r.limiter != nil && r.limiter.ShouldDrop(metadata)) {
		return NewPacketConn(&dropPacketConn{}, r), nil
	}
	return NewPacketConn(&rejectPacketConn{}, r), nil
}

func (r *Reject) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if !metadata.Resolved() {
		metadata.DstIP = netip.IPv4Unspecified()
	}
	return nil
}

func NewRejectWithOption(option RejectOption) *Reject {
	return &Reject{
		Base: NewBase(BaseOption{
			Name: option.Name,
			Type: C.Reject,
			UDP:  true,
		}),
	}
}

func NewReject() *Reject {
	return &Reject{
		Base: NewBase(BaseOption{
			Name:   "REJECT",
			Type:   C.Reject,
			UDP:    true,
			Prefer: C.DualStack,
		}),
	}
}

func NewRejectDrop() *Reject {
	return &Reject{
		Base: NewBase(BaseOption{
			Name:   "REJECT-DROP",
			Type:   C.RejectDrop,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		drop: true,
	}
}

func NewRejectNoDrop() *Reject {
	return &Reject{
		Base: NewBase(BaseOption{
			Name:   "REJECT-NO-DROP",
			Type:   C.RejectNoDrop,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		noDrop: true,
	}
}

func NewPass() *Reject {
	return &Reject{
		Base: &Base{
			name:   "PASS",
			tp:     C.Pass,
			udp:    true,
			prefer: C.DualStack,
		},
	}
}

func NewPassRule() *Reject {
	return &Reject{
		Base: &Base{
			name:   "PASS-RULE",
			tp:     C.PassRule,
			udp:    true,
			prefer: C.DualStack,
		},
	}
}

type nopConn struct{}

func (rw nopConn) Read(b []byte) (int, error) { return 0, io.EOF }

func (rw nopConn) ReadBuffer(buffer *buf.Buffer) error { return io.EOF }

func (rw nopConn) Write(b []byte) (int, error)          { return 0, io.EOF }
func (rw nopConn) WriteBuffer(buffer *buf.Buffer) error { return io.EOF }
func (rw nopConn) Close() error                         { return nil }
func (rw nopConn) LocalAddr() net.Addr                  { return nil }
func (rw nopConn) RemoteAddr() net.Addr                 { return nil }
func (rw nopConn) SetDeadline(time.Time) error          { return nil }
func (rw nopConn) SetReadDeadline(time.Time) error      { return nil }
func (rw nopConn) SetWriteDeadline(time.Time) error     { return nil }

var udpAddrIPv4Unspecified = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

type nopPacketConn struct{}

func (npc nopPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return len(b), nil
}
func (npc nopPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}
func (npc nopPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, io.EOF
}
func (npc nopPacketConn) Close() error                     { return nil }
func (npc nopPacketConn) LocalAddr() net.Addr              { return udpAddrIPv4Unspecified }
func (npc nopPacketConn) SetDeadline(time.Time) error      { return nil }
func (npc nopPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (npc nopPacketConn) SetWriteDeadline(time.Time) error { return nil }

type rejectPacketConn struct {
	nopPacketConn
}

func (rpc *rejectPacketConn) IsReject() bool {
	return rpc != nil
}

type dropPacketConn struct {
	nopPacketConn
}

func (dpc *dropPacketConn) IsDrop() bool {
	return true
}

type dropConn struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newDropConn() *dropConn {
	return &dropConn{
		closed: make(chan struct{}),
	}
}

func (rw *dropConn) Read(b []byte) (int, error) {
	timer := time.NewTimer(C.DefaultDropTime)
	defer timer.Stop()

	select {
	case <-rw.closed:
		return 0, io.EOF
	case <-timer.C:
		return 0, io.EOF
	}
}

func (rw *dropConn) ReadBuffer(buffer *buf.Buffer) error {
	timer := time.NewTimer(C.DefaultDropTime)
	defer timer.Stop()

	select {
	case <-rw.closed:
		return io.EOF
	case <-timer.C:
		return io.EOF
	}
}

func (rw *dropConn) Write(b []byte) (int, error) {
	select {
	case <-rw.closed:
		return 0, io.EOF
	default:
		return len(b), nil
	}
}

func (rw *dropConn) WriteBuffer(buffer *buf.Buffer) error {
	if buffer != nil {
		buffer.Release()
	}
	select {
	case <-rw.closed:
		return io.EOF
	default:
		return nil
	}
}
func (rw *dropConn) Close() error {
	rw.closeOnce.Do(func() {
		close(rw.closed)
	})
	return nil
}
func (rw *dropConn) LocalAddr() net.Addr                  { return nil }
func (rw *dropConn) RemoteAddr() net.Addr                 { return nil }
func (rw *dropConn) SetDeadline(time.Time) error          { return nil }
func (rw *dropConn) SetReadDeadline(time.Time) error      { return nil }
func (rw *dropConn) SetWriteDeadline(time.Time) error     { return nil }
