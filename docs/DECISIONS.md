# Design Decisions

## Decision 1: Dedicated `*-socket` fields for built-in listeners

### Context
Built-in listener port fields (`port`, `socks-port`, `mixed-port`) were `int`. Adding UDS support required a way to specify socket paths.

### Decision
Add dedicated `string` fields (`port-socket`, `socks-socket`, `mixed-socket`). Keep `int` port fields unchanged. Enforce mutual exclusion at parse time.

### Why not change `int` to `string`?
Would cascade through `General`, `Ports` (public REST API JSON), the executor, and the config PATCH handler — a type migration touching dozens of call sites for no benefit.

### Consequences
- Zero backward-compatibility impact
- Built-in and custom listeners use different configuration models (see Decision 7)

---

## Decision 2: Auto-detect network from address format (outbound)

### Context
Outbound proxy adapters need to know whether to dial TCP or a Unix socket. The address comes from `server: example.com` or `server: /var/run/ss.sock`.

### Decision
Auto-detect the network type in `adapter/outbound/base.go:NewBase()` using `utils.IsUnixPath(opt.Addr)`. No new config field needed. Expose via `Base.Network()`.

### Why not add explicit `network` to every proxy option struct?
22 adapter option structs would need the field threaded through YAML decode paths — boilerplate for something definitionally derivable from the address.

### Consequences
- `server: /var/run/ss.sock` works automatically
- If a future protocol needs `unixpacket` or abstract namespace sockets, `BaseOption.Network` can be added as an optional override

---

## Decision 3: Separate `ReCreate*Socket` functions for built-in UDS listeners

### Context
Built-in listeners (HTTP, SOCKS, Mixed) use dedicated `*-socket` config fields. They need independent lifecycle from their TCP counterparts.

### Decision
Add `ReCreateHTTPSocket`, `ReCreateSocksSocket`, `ReCreateMixedSocket` as standalone functions with their own listener variables and mutexes. Do not modify `ReCreateHTTP`/`ReCreateSocks`/`ReCreateMixed`.

### Why not accept both port and socket in a single function?
Would mix TCP-specific logic (`genAddr`, `allowLan`) with UDS lifecycle in the same function. Separate functions keep concerns isolated.

---

## Decision 4: Centralized socket lifecycle in `ListenConfig.Listen()`

### Context
Unix domain sockets require filesystem lifecycle: remove stale socket file (`syscall.Unlink`), create parent directories (`os.MkdirAll`), set permissions after bind (`os.Chmod`).

Initially this was duplicated in each protocol server's `NewWithConfig` function.

### Decision
Move lifecycle to `adapter/inbound/listen.go:ListenConfig.Listen()`. All listeners automatically get UDS lifecycle when `network == "unix"`. Remove lifecycle from individual protocol servers.

### Why centralize?
When unified listener UDS support was added (Decision 6), 10+ protocol servers would otherwise each duplicate the same 6-line lifecycle block. Centralizing it means one implementation, one place to fix bugs, and new protocol listeners get it for free.

### Consequences
- Protocol servers no longer import `os`, `syscall`, `path/filepath` just for socket lifecycle
- The original REST API UDS listener (`hub/route/server.go`) still has its own lifecycle — that code predates this decision and isn't part of the listener abstraction

---

## Decision 5: `NewWithConfig` gains a `network` parameter

### Context
Listener constructors needed to support both TCP and Unix socket creation. External callers (CMFA) depend on existing `New` and `NewWithAuthenticate` signatures.

### Decision
Add `network string` as the first parameter to `NewWithConfig`. `New` delegates to `NewWithNetwork("tcp", ...)`. `NewWithAuthenticate` passes `"tcp"` directly. No existing public signature changed.

### Consequences
- CMFA compatibility preserved
- `NewWithNetwork` is the entry point for code that knows the network type

---

## Decision 6: Unified listener network abstraction

### Context
After initial UDS support for HTTP/SOCKS/Mixed, all other TCP-based protocols (Snell, Trojan, Shadowsocks, VMess, VLESS, AnyTLS, Sudoku, TrustTunnel, Tunnel) still hardcoded `"tcp"` in their protocol server implementations. They could not listen on Unix sockets.

### Decision
Extend the same pattern to all TCP-based listeners:

1. `listener/inbound/base.go`: Add `socketPath`, `network` fields and `Network()` method. `NewBase()` auto-detects UDS from `listen` field.
2. Every protocol server `New()` function gains `network string` as first parameter, passes it to `lc.Listen(ctx, network, addr)`.
3. Every inbound adapter's `Listen()` passes `b.Network()` to its protocol server.
4. Built-in callers (`ReCreateShadowSocks`, `ReCreateVmess`, tunnel patch) pass `"tcp"` explicitly.

### Why this approach?
- Reuses the same auto-detection pattern from outbound adapters (Decision 2)
- Protocol servers don't need to know *why* the network is `"unix"` — they just pass it through
- `ListenConfig.Listen()` handles all UDS lifecycle centrally (Decision 4)
- Custom listeners get UDS for free: `listen: /var/run/snell.sock` just works

### What stays TCP-only?
- Redir/TProxy: require IP-level socket options (`SO_ORIGINAL_DST`, `IP_TRANSPARENT`)
- QUIC/UDP-based protocols (TUIC, Hysteria2, ShadowQUIC): use `ListenPacket("udp", ...)` not `Listen("tcp", ...)`
- REALITY `dest` field: consumed by the external utls library, which hardcodes `net.Dial("tcp", ...)`

---

## Decision 7: Two UDS configuration models coexist

### Context
Built-in listeners (HTTP/SOCKS/Mixed) use dedicated `*-socket` config fields (Decision 1). Custom listeners (Snell, Trojan, etc.) auto-detect from the `listen` field (Decision 6). The two models coexist in the same codebase.

### Decision
Accept the duality. Built-in listeners stay with `*-socket` fields because changing their port types would break the REST API's `Ports` struct. Custom listeners use the auto-detection pattern because `listen` is already a `string` field and adding parallel fields for 15+ protocol types would be excessive.

### Consequences
- Two configuration patterns: `mixed-socket: /path` (built-in) vs `listen: /path` (custom)
- Both are documented in the config example
- The internal plumbing (`ListenConfig.Listen()`, `Base.Network()`) is shared regardless of config path

---

## Decision 8: TrustTunnel mixed-mode TCP/UDS + UDP/port

### Context
TrustTunnel supports both TCP and UDP via `network: [tcp, udp]`. When `listen: /path/to/sock`, the UDP listener cannot use the Unix socket path. The port from `BaseOption.Port` was lost when `Base.RawAddress()` returned only the UDS path.

### Decision
Thread the port through `LC.TrustTunnelServer.Port`. When `network == "unix"` and `config.Port != ""`, the UDP listener uses `:port` (all interfaces) instead of the UDS path. TCP continues on the Unix socket.

### Why not a general solution?
Other protocols with dual TCP+UDP (Shadowsocks, VMess, VLESS, Trojan, Snell, AnyTLS, Sudoku) may have the same issue but were not tested in this configuration. The TrustTunnel fix establishes the pattern: add a `Port` field to the config struct, propagate it from `BaseOption`, and use it for UDP when the TCP transport is UDS. These other protocols can follow the same pattern if needed.
