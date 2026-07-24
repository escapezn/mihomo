# Mihomo Networking Architecture

## System Overview

Mihomo is a proxy gateway kernel. It accepts inbound connections from local clients on multiple protocol listeners, matches them against routing rules, and forwards them through outbound proxy adapters to remote servers. DNS runs as a parallel subsystem providing resolution, caching, and FakeIP mapping.

```
Client → [Listener] → [Tunnel] → [Adapter] → Remote Server
                         │            │
                       Rules          │
                         │            │
                    [DNS Resolver]    │
                         │            │
                    [Transport] ←─────┘
```

## Layer Responsibilities

### Listener (`listener/`)
Accepts inbound connections. Each protocol (HTTP, SOCKS5, Shadowsocks, VMess, VLESS, Trojan, Snell, TUIC, Hysteria2, AnyTLS, Sudoku, TrustTunnel, etc.) is implemented as an `InboundListener`. The orchestrator (`listener/listener.go`) manages lifecycle.

Unix domain sockets are a first-class transport alongside TCP. Every TCP-based protocol supports UDS listening. The network type (`"tcp"` or `"unix"`) is determined by the `Base` struct via auto-detection of the listen address and propagated through `Network()` to the protocol server.

**Configuration model:** Built-in listeners (HTTP, SOCKS, Mixed) use dedicated `*-socket` config fields. Custom listeners (under `listeners:`) use the `listen` field with a UDS path directly.

**Socket lifecycle** (unlink stale file, create parent directory, bind, set permissions) is centralized in `adapter/inbound/listen.go:ListenConfig.Listen()` and applies to all listeners automatically.

### Tunnel (`tunnel/`)
The routing engine. For each connection, builds `Metadata`, matches rules to find a target proxy, dials the proxy adapter, and relays data bidirectionally. Maintains a NAT table for UDP session tracking and connection statistics.

### Adapter (`adapter/`)
Outbound proxy implementations. Each adapter wraps a protocol and provides `DialContext(metadata) → Conn` and `ListenPacketContext(metadata) → PacketConn`. The `Base` struct auto-detects TCP vs Unix socket transport from the address format (`utils.IsUnixPath`). Adapters use `Base.Network()` when dialing the proxy server, avoiding hardcoded `"tcp"`.

Inner tunnel dials (through TUN devices, gost relays, SSH channels) intentionally remain `"tcp"` — they represent virtual circuits within an established tunnel, not transport-layer choices.

### DNS (`dns/`)
Full DNS subsystem: UDP/TCP/DoT/DoH/DoQ/DHCP transports, FakeIP mapping, ARC/LRU caching, policy-based nameserver routing, and a built-in DNS listener.

### Rules (`rules/`)
30+ rule types across domain, IP, port, process, network, and logic categories. Rule providers support file, HTTP, and inline sources.

### Transport (`transport/`)
Wire-format implementations for outbound protocols. Pure byte-level encoding on `net.Conn` — network-agnostic by design. Never imports `"tcp"` or `"unix"`.

### Dialer (`component/dialer/`)
Low-level socket creation. Dual-stack IPv4/IPv6 racing, interface binding, routing marks, TCP Fast Open, MPTCP, and Unix socket dialing. All outbound connections flow through `DialContext(ctx, network, address, options...)`.

## Key Abstractions

### `Metadata` (`constant/metadata.go`)
Central connection descriptor: source/dest IP/port, host, network type, inbound info, process info, GEOIP data, DNS mode.

### `ProxyAdapter` Interface (`constant/adapters.go`)
```go
type ProxyAdapter interface {
    Name() string; Type() AdapterType; Addr() string
    SupportUDP() bool; SupportUOT() bool
    DialContext(ctx, metadata) (Conn, error)
    ListenPacketContext(ctx, metadata) (PacketConn, error)
    IsL3Protocol(metadata) bool
    Unwrap(metadata, touch) Proxy
    Close() error
}
```

### `Tunnel` Interface (`constant/tunnel.go`)
```go
type Tunnel interface {
    HandleTCPConn(conn, metadata)
    HandleUDPPacket(packet, metadata)
    NatTable() NatTable
}
```

### `InboundListener` Interface (`constant/listener.go`)
```go
type InboundListener interface {
    Name() string; Listen(tunnel Tunnel) error; Close() error
    Address() string; Config() InboundConfig
}
```

## Data Flow: TCP Connection

1. Listener accepts connection → `Tunnel.HandleTCPConn(conn, metadata)`
2. Tunnel maps metadata (FakeIP reverse, DNS hosts)
3. Optional sniffer extracts domain (TLS SNI / HTTP Host / QUIC)
4. `resolveMetadata()` matches rules → target proxy
5. Proxy adapter `DialContext(metadata)` dials the remote
6. Bidirectional relay via `handleSocket()`
7. Tracked by `statistic.TCPTracker`

## Data Flow: Outbound Dial

1. Adapter calls `Base.dialer.DialContext(ctx, Base.Network(), addr)`
2. `Base.Network()` returns `"tcp"` for host:port, `"unix"` for filesystem paths
3. Dialer dispatches: TCP → DNS resolve → dual-stack race → dial; UDS → dial path directly
4. TCP-only socket options (interface binding, routing mark, TFO, MPTCP) are skipped for `"unix"`

## Data Flow: Inbound Listener Creation

1. Config parsed → protocol server `New(network string, config, lc, tunnel, additions)`
2. `network` comes from `Base.Network()` (custom) or `"tcp"`/`"unix"` (built-in)
3. Protocol server calls `lc.Listen(ctx, network, addr)`
4. `ListenConfig.Listen()` handles socket lifecycle if `network == "unix"`, then delegates to `tfo.ListenConfig.Listen()`
5. `preResolve()` passes `"unix"` through without IP resolution

## Transport Network Model

The transport boundary is `net.Conn`. All layers above the dialer/listener are network-agnostic:

- **Outbound detection**: `adapter/outbound.Base` auto-detects via `utils.IsUnixPath(opt.Addr)` — paths starting with `/`, `./`, `../`, `~/` are Unix sockets
- **Inbound detection**: `listener/inbound.Base` auto-detects via `utils.IsUnixPath(options.Listen)`
- **Shared predicate**: `common/utils.IsUnixPath(s string) bool`
- **Address helper**: `adapter/outbound/util.go:resolveAddr(server, port)` — returns path as-is for UDS, `host:port` for TCP

## Configuration Architecture

```
YAML → RawConfig (flat struct) → parseGeneral/parseProxies/parseDNS/etc.
     → Config (typed structs)    → hub/executor.ApplyConfig()
                                  → ReCreate*/Update* functions
```

Two UDS configuration models coexist:
- **Built-in listeners**: dedicated `*-socket` fields (`port-socket`, `socks-socket`, `mixed-socket`) alongside `int` port fields. Mutual exclusion enforced.
- **Custom listeners**: `listen` field accepts either an IP or a UDS path. Auto-detected by `Base.NewBase()`.

## Invariants

- **Transport is network-agnostic**: `transport/` packages never hardcode `"tcp"` or `"unix"`.
- **Dialer handles all socket creation**: No direct `net.Dial` calls. Everything through `component/dialer.DialContext`.
- **New adapters use `resolveAddr(server, port)`** to build `Base.Addr`, ensuring compatibility with `IsUnixPath` auto-detection.
- **Adapter `DialContext` uses `Network()`** not `"tcp"` when dialing the proxy server. Inner tunnel dials (TUN, SSH channels, gost relays) intentionally stay `"tcp"`.
- **Protocol servers never hardcode `"tcp"`**: All use the `network` parameter from their `New()` function signature. Built-in callers pass `"tcp"` explicitly; custom listeners pass `Base.Network()`.
- **Socket lifecycle in `ListenConfig.Listen()`**: All UDS listeners get socket cleanup, parent directory creation, and permission setting from one location.
- **Port fields remain `int`**: No type migration. UDS paths use separate fields or the `listen` field.
- **Listener lifecycle is mutex-protected**: Per-protocol mutexes in `listener/listener.go`. Stop-before-start ordering.
- **CMFA compatibility**: `NewWithAuthenticate` signature unchanged. `NewWithConfig` gained a `network` parameter but all callers were updated in the same change.
