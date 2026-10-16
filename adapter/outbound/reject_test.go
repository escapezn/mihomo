package outbound

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRejectListenPacketContext(t *testing.T) {
	reject := NewReject()
	require.NotNil(t, reject)

	metadata := &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
	}

	pc, err := reject.ListenPacketContext(context.Background(), metadata)
	require.NoError(t, err)
	require.NotNil(t, pc)
	defer pc.Close()

	assert.True(t, C.IsRejectPacketConn(pc), "REJECT packetConn should be identified as RejectPacketConn")

	rejectDrop := NewRejectDrop()
	require.NotNil(t, rejectDrop)

	pcDrop, err := rejectDrop.ListenPacketContext(context.Background(), metadata)
	require.NoError(t, err)
	require.NotNil(t, pcDrop)
	defer pcDrop.Close()

	assert.False(t, C.IsRejectPacketConn(pcDrop), "REJECT-DROP packetConn should NOT be identified as RejectPacketConn")
	assert.True(t, C.IsDropPacketConn(pcDrop), "REJECT-DROP packetConn should be identified as DropPacketConn")

	rejectNoDrop := NewRejectNoDrop()
	require.NotNil(t, rejectNoDrop)

	pcNoDrop, err := rejectNoDrop.ListenPacketContext(context.Background(), metadata)
	require.NoError(t, err)
	require.NotNil(t, pcNoDrop)
	defer pcNoDrop.Close()

	assert.True(t, C.IsRejectPacketConn(pcNoDrop), "REJECT-NO-DROP packetConn should be identified as RejectPacketConn")
	assert.False(t, C.IsDropPacketConn(pcNoDrop), "REJECT-NO-DROP packetConn should NOT be identified as DropPacketConn")
}

func TestRejectRateLimiter_SlidingWindow(t *testing.T) {
	limiter := NewRejectRateLimiter(5, 10*time.Second, 5*time.Second)
	metadata := &C.Metadata{
		NetWork: C.TCP,
		SrcIP:   netip.MustParseAddr("192.168.1.10"),
		Host:    "ads.example.com",
		DstPort: 443,
	}

	// First 4 requests within interval should NOT drop
	for i := 0; i < 4; i++ {
		assert.False(t, limiter.ShouldDrop(metadata), "request %d should not drop", i+1)
	}

	// 5th request reaches threshold, should trigger drop
	assert.True(t, limiter.ShouldDrop(metadata), "5th request should trigger drop")

	// 6th request within dropDuration should remain dropped
	assert.True(t, limiter.ShouldDrop(metadata), "subsequent request in penalty should drop")

	// Different client source IP should NOT be affected (Client isolation)
	diffClient := &C.Metadata{
		NetWork: C.TCP,
		SrcIP:   netip.MustParseAddr("192.168.1.20"),
		Host:    "ads.example.com",
		DstPort: 443,
	}
	assert.False(t, limiter.ShouldDrop(diffClient), "different client should not be dropped")

	// Different port should NOT be affected (Port isolation)
	diffPort := &C.Metadata{
		NetWork: C.TCP,
		SrcIP:   netip.MustParseAddr("192.168.1.10"),
		Host:    "ads.example.com",
		DstPort: 80,
	}
	assert.False(t, limiter.ShouldDrop(diffPort), "different port should not be dropped")
}

func TestRejectTracker_PenaltyRecoveryAndIdleReset(t *testing.T) {
	tracker := &rejectTracker{}
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	interval := 10 * time.Second
	duration := 5 * time.Second
	maxTriggers := 3

	triggered := false
	onTrigger := func() { triggered = true }

	// 1st request at t=0
	assert.False(t, tracker.shouldDrop(baseTime, maxTriggers, interval, duration, onTrigger))
	// 2nd request at t=1s
	assert.False(t, tracker.shouldDrop(baseTime.Add(1*time.Second), maxTriggers, interval, duration, onTrigger))
	// 3rd request at t=2s -> triggers drop!
	assert.True(t, tracker.shouldDrop(baseTime.Add(2*time.Second), maxTriggers, interval, duration, onTrigger))
	assert.True(t, triggered)

	// Probe during penalty at t=3s -> still dropped, but dropUntil must NOT be extended!
	assert.True(t, tracker.shouldDrop(baseTime.Add(3*time.Second), maxTriggers, interval, duration, onTrigger))
	assert.Equal(t, baseTime.Add(2*time.Second).Add(duration), tracker.dropUntil)

	// After duration expires at t=8s -> penalty over, can recover (not dropped)
	assert.False(t, tracker.shouldDrop(baseTime.Add(8*time.Second), maxTriggers, interval, duration, onTrigger))

	// Idle for > 2 intervals (e.g. t=100s) -> should reset completely
	assert.False(t, tracker.shouldDrop(baseTime.Add(100*time.Second), maxTriggers, interval, duration, onTrigger))
	assert.Equal(t, 1, tracker.currCount)
	assert.Equal(t, 0, tracker.prevCount)
}

func TestDropConnInterruptible(t *testing.T) {
	conn := newDropConn()
	require.NotNil(t, conn)

	done := make(chan error, 1)
	go func() {
		buf := buf.New()
		defer buf.Release()
		done <- conn.ReadBuffer(buf)
	}()

	// Close conn almost immediately
	time.Sleep(20 * time.Millisecond)
	err := conn.Close()
	require.NoError(t, err)

	select {
	case readErr := <-done:
		assert.Equal(t, io.EOF, readErr)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dropConn did not exit promptly on Close")
	}
}

func TestDropConnBlackholeWrite(t *testing.T) {
	conn := newDropConn()
	require.NotNil(t, conn)

	// Writing data should succeed (blackholed) and not return EOF
	n, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.NoError(t, err)
	assert.Equal(t, 18, n)

	buffer := buf.New()
	_, _ = buffer.Write([]byte("ClientHello"))
	err = conn.WriteBuffer(buffer)
	require.NoError(t, err)

	// Close conn
	err = conn.Close()
	require.NoError(t, err)

	// After close, writes should return EOF
	_, err = conn.Write([]byte("after close"))
	assert.Equal(t, io.EOF, err)

	buffer2 := buf.New()
	_, _ = buffer2.Write([]byte("after close"))
	err = conn.WriteBuffer(buffer2)
	assert.Equal(t, io.EOF, err)
}

