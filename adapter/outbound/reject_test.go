package outbound

import (
	"context"
	"net/netip"
	"testing"

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
}
