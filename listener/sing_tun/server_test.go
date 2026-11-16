package sing_tun

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/dialer"
	LC "github.com/metacubex/mihomo/listener/config"

	tun "github.com/metacubex/sing-tun"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auto-redirect without auto-route must be reported as a config error before
// anything is started, not panic in the deferred cleanup with a nil Listener.
func TestNewAutoRedirectRequiresAutoRoute(t *testing.T) {
	if !supportRedirect {
		t.Skip("auto-redirect is not supported on this platform")
	}
	l, err := New(LC.Tun{Enable: true, AutoRedirect: true, AutoRoute: false}, nil)
	if err == nil {
		t.Fatal("expected an error for auto-redirect without auto-route")
	}
	if l != nil {
		t.Fatal("expected a nil listener on error")
	}
}

func TestClaimRoutingMarkKeepsUserMark(t *testing.T) {
	const mark = int32(0x2024)
	old := dialer.DefaultRoutingMark.Swap(mark) // user configured the same value as the auto-redirect output mark
	t.Cleanup(func() { dialer.DefaultRoutingMark.Store(old) })

	l := &Listener{}
	require.Error(t, l.claimRoutingMark(mark))
	require.NoError(t, l.Close()) // what the deferred cleanup in New does
	assert.Equal(t, mark, dialer.DefaultRoutingMark.Load())
}

func TestClaimRoutingMarkReleasedOnClose(t *testing.T) {
	old := dialer.DefaultRoutingMark.Swap(0)
	t.Cleanup(func() { dialer.DefaultRoutingMark.Store(old) })

	l := &Listener{}
	require.NoError(t, l.claimRoutingMark(0x2024))
	assert.Equal(t, int32(0x2024), dialer.DefaultRoutingMark.Load())
	require.NoError(t, l.Close())
	assert.Equal(t, int32(0), dialer.DefaultRoutingMark.Load())
}

type fakeStack struct {
	tun.Stack
	startErr error
	closed   bool
}

func (s *fakeStack) Start() error { return s.startErr }
func (s *fakeStack) Close() error { s.closed = true; return nil }

func TestStartStackFailureClosedByListener(t *testing.T) {
	stack := &fakeStack{startErr: errors.New("inet6 listen failed")}
	l := &Listener{}
	require.Error(t, l.startStack(stack))
	require.NoError(t, l.Close())
	assert.True(t, stack.closed, "a stack whose Start failed must still be closed")
}
