package trusttunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
)

type Handler interface {
	network.TCPConnectionHandler
	network.UDPConnectionHandler
}

type ICMPHandler interface {
	NewICMPConnection(ctx context.Context, conn *IcmpConn)
}

type ServiceOptions struct {
	Ctx                   context.Context
	Logger                logger.ContextLogger
	Handler               Handler
	ICMPHandler           ICMPHandler
	QUICCongestionControl string
	QUICCwnd              int
	QUICBBRProfile        string
	// Fallback is an optional backend (host:port) that unauthenticated requests are
	// served from, so active probing sees an ordinary web server instead of a proxy.
	Fallback string
}

type Service struct {
	ctx                   context.Context
	logger                logger.ContextLogger
	users                 map[string][sha256.Size]byte
	handler               Handler
	icmpHandler           ICMPHandler
	quicCongestionControl string
	quicCwnd              int
	quicBBRProfile        string
	httpServer            *http.Server
	h3Server              *http3.Server
	tcpListener           net.Listener
	tlsListener           net.Listener
	udpConn               net.PacketConn
	fallbackProxy         *httputil.ReverseProxy
	fallbackTransport     *http.Transport
	fallbackSlots         chan struct{}
	fallbackIdleTimeout   time.Duration
	fallbackSourceAccess  sync.Mutex
	fallbackSources       map[netip.Prefix]int
	authFailureLog        logLimiter
	// fallbackCtx is cancelled on Close so in-flight fallback requests stop too,
	// including upgraded connections that the HTTP servers no longer track.
	fallbackCtx    context.Context
	fallbackCancel context.CancelFunc
}

const (
	// fallbackIdleTimeout bounds how long a fallback request may go without any
	// body bytes moving in either direction, like nginx's proxy_read_timeout.
	// It is an idle limit, not a total one, so long downloads and SSE streams
	// that keep sending keep working.
	fallbackIdleTimeout = 60 * time.Second
	// fallbackMaxConcurrent caps in-flight fallback requests so a slow or hung
	// backend cannot pin an unbounded number of handlers and backend connections.
	fallbackMaxConcurrent = 256
	// fallbackMaxHeaderBytes is Caddy's request header limit. The HTTP/2 server
	// announces it in SETTINGS (MAX_HEADER_LIST_SIZE, plus 320), where Go's 1 MB
	// default would differ from the cover site's own front.
	fallbackMaxHeaderBytes = 16 << 10
	// fallbackMaxPerSource caps one client network's share of those, so a single
	// prober trickling uploads cannot take every slot and turn the cover site into
	// a blank 503 for everyone else. A browser loading a page over HTTP/2 stays well
	// below it.
	fallbackMaxPerSource = 64
	// authFailureLogInterval spaces out the log of wrong credentials, which a prober
	// can send on every request.
	authFailureLogInterval = 10 * time.Second
)

var errFallbackAddress = errors.New("fallback address is link-local, multicast, unspecified or a cloud metadata service")

// cloudMetadata are metadata services outside the link-local range, which the check
// below covers already (169.254.169.254 and fe80::/10).
var cloudMetadata = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),   // AWS, IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
}

// fallbackDialControl refuses backend addresses that unauthenticated clients must
// never reach through the fallback, such as the cloud metadata service. The panel
// checks the configured address, but a host name is only resolved here.
func fallbackDialControl(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	ip := addrPort.Addr().Unmap()
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return errFallbackAddress
	}
	for _, metadata := range cloudMetadata {
		if ip == metadata {
			return errFallbackAddress
		}
	}
	return nil
}

// fallbackSource is the client network a request counts against: the address for
// IPv4, the /64 for IPv6, where one client usually holds a whole prefix.
func fallbackSource(remoteAddr string) (netip.Prefix, bool) {
	addrPort, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Prefix{}, false
	}
	ip := addrPort.Addr().Unmap()
	bits := 32
	if ip.Is6() {
		bits = 64
	}
	prefix, err := ip.Prefix(bits)
	return prefix, err == nil
}

// logLimiter lets one message through per interval and counts the rest.
type logLimiter struct {
	access     sync.Mutex
	last       time.Time
	suppressed int
}

// allow reports whether to log now and how many messages were dropped since the
// last one that was logged.
func (l *logLimiter) allow(now time.Time, interval time.Duration) (bool, int) {
	l.access.Lock()
	defer l.access.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < interval {
		l.suppressed++
		return false, 0
	}
	suppressed := l.suppressed
	l.last, l.suppressed = now, 0
	return true, suppressed
}

type fallbackWatchdogKey struct{}

func NewService(options ServiceOptions) *Service {
	s := &Service{
		ctx:                   options.Ctx,
		logger:                options.Logger,
		handler:               options.Handler,
		icmpHandler:           options.ICMPHandler,
		quicCongestionControl: options.QUICCongestionControl,
		quicCwnd:              options.QUICCwnd,
		quicBBRProfile:        options.QUICBBRProfile,
	}
	if options.Fallback != "" {
		// A dedicated transport with timeouts for connecting and for the response
		// headers; stalled bodies are handled by the idle watchdog in serveFallback.
		s.fallbackTransport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, Control: fallbackDialControl}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
		}
		s.fallbackCtx, s.fallbackCancel = context.WithCancel(context.Background())
		s.fallbackSlots = make(chan struct{}, fallbackMaxConcurrent)
		s.fallbackSources = make(map[netip.Prefix]int)
		s.fallbackIdleTimeout = fallbackIdleTimeout
		target := options.Fallback
		s.fallbackProxy = &httputil.ReverseProxy{
			Transport:     s.fallbackTransport,
			FlushInterval: -1, // flush each write so SSE and streaming are not buffered
			// Rewrite drops Forwarded and the standard X-Forwarded-For, -Host and
			// -Proto headers before SetXForwarded supplies the values for this request.
			Rewrite: func(r *httputil.ProxyRequest) {
				r.Out.URL.Scheme = "http"
				r.Out.URL.Host = target
				// Keep the client's Host header: named virtual hosts keep working and
				// the internal backend address is not leaked in redirects. The backend
				// therefore routes on a Host the client chose: point the fallback at a
				// server that serves only the cover site, not at one whose other virtual
				// hosts are meant to stay internal.
				r.Out.Host = r.In.Host
				r.SetXForwarded()
			},
			ModifyResponse: func(response *http.Response) error {
				// Let this server stamp Date itself, as a Go front server such as Caddy
				// does: it then comes last in an HTTP/2 response, instead of sorted among
				// the backend's headers, where it would set the fallback apart.
				response.Header.Del("Date")
				watchdog, loaded := response.Request.Context().Value(fallbackWatchdogKey{}).(*idleWatchdog)
				if !loaded {
					return nil
				}
				// An upgraded (WebSocket) connection may legitimately stay quiet for
				// long, so it is left to the concurrency cap instead of the idle limit.
				if response.StatusCode == http.StatusSwitchingProtocols {
					watchdog.stop()
					return nil
				}
				watchdog.startResponse()
				response.Body = &idleReadCloser{ReadCloser: response.Body, watchdog: watchdog, response: true}
				return nil
			},
			ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
				if s.logger != nil {
					s.logger.DebugContext(request.Context(), E.Cause(err, "fallback request from ", request.RemoteAddr))
				}
				writer.WriteHeader(http.StatusBadGateway)
			},
		}
	}
	return s
}

func (s *Service) Start(tcpListener net.Listener, udpConn net.PacketConn, tlsConfig *tls.Config) error {
	if tcpListener != nil {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
		// Enable HTTP/2 support unconditionally on the server.
		//
		// Note that this usage is limited to our own net/http fork
		// The standard library also needs to mask the tls.Conn type for the conn returned by the Listener.
		// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
		//
		// With a fallback the listener negotiates ALPN instead (see below), and HTTP/2 is
		// served only to clients that negotiated h2, as a real HTTPS site does. Prior-knowledge
		// HTTP/2 over TLS that negotiated http/1.1 or nothing would give the proxy away to a
		// prober; such a preface is read as an HTTP/1 request and goes to the fallback.
		protocols.SetUnencryptedHTTP2(s.fallbackProxy == nil)
		maxHeaderBytes := 0 // the default
		if s.fallbackProxy != nil {
			maxHeaderBytes = fallbackMaxHeaderBytes
		}
		s.httpServer = &http.Server{
			Handler:     s,
			IdleTimeout: DefaultSessionTimeout,
			BaseContext: func(net.Listener) context.Context {
				return s.ctx
			},
			MaxHeaderBytes: maxHeaderBytes,
			Protocols:      protocols,
		}
		listener := tcpListener
		s.tcpListener = tcpListener
		if tlsConfig != nil {
			tcpTLSConfig := tlsConfig
			if s.fallbackProxy != nil && len(tlsConfig.NextProtos) == 0 {
				// A real HTTPS site negotiates ALPN, so a browser or scanner offering
				// h2 gets h2 instead of no protocol at all. TrustTunnel clients offer
				// h2 and keep working.
				tcpTLSConfig = tlsConfig.Clone()
				tcpTLSConfig.NextProtos = []string{"h2", "http/1.1"}
			}
			listener = tls.NewListener(listener, tcpTLSConfig)
			s.tlsListener = listener
		}
		go func() {
			sErr := s.httpServer.Serve(listener)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				s.logger.ErrorContext(s.ctx, "HTTP server close: ", sErr)
			}
		}()
	}
	if udpConn != nil {
		err := s.configHTTP3Server(tlsConfig, udpConn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) UpdateUsers(users map[string]string) {
	hashedUsers := make(map[string][sha256.Size]byte, len(users))
	for username, password := range users {
		hashedUsers[username] = sha256.Sum256([]byte(password))
	}
	s.users = hashedUsers
}

func (s *Service) Close() error {
	if s.fallbackCancel != nil {
		s.fallbackCancel()
	}
	var shutdownErr error
	if s.httpServer != nil {
		const shutdownTimeout = 5 * time.Second
		ctx, cancel := context.WithTimeout(s.ctx, shutdownTimeout)
		shutdownErr = s.httpServer.Shutdown(ctx)
		cancel()
		if errors.Is(shutdownErr, http.ErrServerClosed) {
			shutdownErr = nil
		}
	}
	if s.fallbackTransport != nil {
		s.fallbackTransport.CloseIdleConnections()
	}
	closeErr := common.Close(
		common.PtrOrNil(s.httpServer),
		s.tlsListener,
		s.tcpListener,
		common.PtrOrNil(s.h3Server),
		s.udpConn,
	)
	return E.Errors(shutdownErr, closeErr)
}

func (s *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	authorization := request.Header.Get("Proxy-Authorization")
	username, loaded := s.verify(authorization)
	if !loaded {
		if s.serveFallback(writer, request) {
			// A request with credentials that do not match is most likely a misconfigured
			// client, so it is logged as before; one without credentials is a browser or a
			// prober, which would only flood the log.
			switch {
			case s.logger == nil:
			case authorization != "":
				if allowed, suppressed := s.authFailureLog.allow(time.Now(), authFailureLogInterval); allowed {
					if suppressed > 0 {
						s.badRequest(request.Context(), request, E.New("authorization failed, served the fallback (", suppressed, " more since the last such message)"))
					} else {
						s.badRequest(request.Context(), request, E.New("authorization failed, served the fallback"))
					}
				}
			default:
				s.logger.DebugContext(request.Context(), "unauthenticated request from ", request.RemoteAddr, " served the fallback")
			}
			return
		}
		writer.WriteHeader(http.StatusProxyAuthRequired)
		s.badRequest(request.Context(), request, E.New("authorization failed"))
		return
	}
	if request.Method != http.MethodConnect {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		s.badRequest(request.Context(), request, E.New("unexpected HTTP method ", request.Method))
		return
	}
	ctx := request.Context()
	ctx = auth.ContextWithUser(ctx, username)
	s.logger.DebugContext(ctx, "[", username, "] ", "request from ", request.RemoteAddr)
	s.logger.DebugContext(ctx, "[", username, "] ", "request to ", request.Host)
	switch request.Host {
	case UDPMagicAddress:
		writer.WriteHeader(http.StatusOK)
		flusher, isFlusher := writer.(http.Flusher)
		if isFlusher {
			flusher.Flush()
		}
		conn := &serverPacketConn{
			packetConn: packetConn{
				httpConn: httpConn{
					writer:  writer,
					flusher: flusher,
					created: make(chan struct{}),
				},
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, request)
		conn.setup(request.Body, nil)
		firstPacket := buf.NewPacket()
		destination, err := conn.ReadPacket(firstPacket)
		if err != nil {
			firstPacket.Release()
			_ = conn.Close()
			s.logger.ErrorContext(ctx, E.Cause(err, "read first packet of ", request.RemoteAddr))
			return
		}
		destination = destination.Unwrap()
		cachedConn := bufio.NewCachedPacketConn(conn, firstPacket, destination)
		_ = s.handler.NewPacketConnection(ctx, cachedConn, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: destination,
		})
	case ICMPMagicAddress:
		flusher, isFlusher := writer.(http.Flusher)
		if s.icmpHandler == nil {
			writer.WriteHeader(http.StatusNotImplemented)
			if isFlusher {
				flusher.Flush()
			}
			_ = request.Body.Close()
		} else {
			writer.WriteHeader(http.StatusOK)
			if isFlusher {
				flusher.Flush()
			}
			conn := &IcmpConn{
				httpConn{
					writer:  writer,
					flusher: flusher,
					created: make(chan struct{}),
				},
			}
			httputils.SetAddrFromRequest(&conn.NetAddr, request)
			conn.setup(request.Body, nil)
			s.icmpHandler.NewICMPConnection(ctx, conn)
		}
	case HealthCheckMagicAddress:
		writer.WriteHeader(http.StatusOK)
		if flusher, isFlusher := writer.(http.Flusher); isFlusher {
			flusher.Flush()
		}
		_ = request.Body.Close()
	default:
		writer.WriteHeader(http.StatusOK)
		flusher, isFlusher := writer.(http.Flusher)
		if isFlusher {
			flusher.Flush()
		}
		conn := &tcpConn{
			httpConn{
				writer:  writer,
				flusher: flusher,
				created: make(chan struct{}),
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, request)
		conn.setup(request.Body, nil)
		wrapper := &h2ConnWrapper{
			ExtendedConn: N.NewDeadlineConn(conn),
		}
		_ = s.handler.NewConnection(ctx, wrapper, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: M.ParseSocksaddr(request.Host).Unwrap(),
		})
		wrapper.CloseWrapper()
	}
}

func (s *Service) verify(authorization string) (username string, loaded bool) {
	username, password, loaded := parseBasicAuth(authorization)
	if !loaded {
		return "", false
	}
	recordedHash, known := s.users[username]
	passwordHash := sha256.Sum256([]byte(password))
	// Compare fixed-size digests even for unknown users: comparing raw passwords
	// would return immediately when their lengths differ. This does not make the
	// entire authentication path (including the map lookup) constant-time.
	if subtle.ConstantTimeCompare(passwordHash[:], recordedHash[:]) != 1 || !known {
		return "", false
	}
	return username, true
}

func (s *Service) badRequest(ctx context.Context, request *http.Request, err error) {
	s.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

// serveFallback serves an unauthenticated request from the configured backend
// instead of answering with proxy-specific status codes, which makes the port
// harder to identify with a single probe. It runs only when a fallback backend
// is configured; otherwise the caller keeps the previous 407 response. It
// returns true when it has handled the request.
//
// Every method goes to the backend, CONNECT included, so the backend's own
// answer (status, headers, body) is what a prober sees for it too, instead of a
// response the backend would never produce.
//
// The reverse proxy strips hop-by-hop headers, carries WebSocket upgrades, and
// flushes streaming responses. A backend that fails to connect or to send
// headers in time yields 502. Once headers have been sent the status can no
// longer change, so a body that stalls for fallbackIdleTimeout in either
// direction aborts the response instead, the way a reverse proxy drops a dead
// upstream or a client that stopped reading.
func (s *Service) serveFallback(writer http.ResponseWriter, request *http.Request) bool {
	if s.fallbackProxy == nil {
		return false
	}
	if source, loaded := fallbackSource(request.RemoteAddr); loaded {
		if !s.acquireFallbackSource(source) {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		defer s.releaseFallbackSource(source)
	}
	select {
	case s.fallbackSlots <- struct{}{}:
		defer func() { <-s.fallbackSlots }()
	default:
		writer.WriteHeader(http.StatusServiceUnavailable)
		return true
	}
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	go func() {
		select {
		case <-s.fallbackCtx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	controller := http.NewResponseController(writer)
	watchdog := newIdleWatchdog(s.fallbackIdleTimeout, func() {
		// Stop the backend side and release a read stuck on a client that stopped
		// uploading. Writes are left alone here: an HTTP/1 server may still be
		// draining the request body before it sends an early answer such as 413.
		cancel()
		_ = controller.SetReadDeadline(time.Now())
	}, func() {
		// Still running a full idle period later, so the handler is stuck writing
		// to a client that stopped reading. Deadlines are per stream on HTTP/2
		// and HTTP/3, and HTTP/1 carries one request at a time, so other requests
		// are not affected.
		err := controller.SetWriteDeadline(time.Now())
		if err != nil && s.logger != nil {
			s.logger.WarnContext(ctx, E.Cause(err, "abort stalled fallback response to ", request.RemoteAddr))
		}
	})
	defer watchdog.stop()
	request = request.WithContext(context.WithValue(ctx, fallbackWatchdogKey{}, watchdog))
	if request.Body != nil && request.Body != http.NoBody {
		var bodyFinished *atomic.Bool
		request.Body, bodyFinished = newFallbackRequestBody(ctx, request.Body, watchdog)
		defer func() {
			if !bodyFinished.Load() {
				// The backend answered before the whole body arrived (an early 413,
				// say). The server drains the rest before it sends the answer, so
				// release that read instead of waiting on a client that may never
				// send more; the server then answers and closes the connection.
				_ = controller.SetReadDeadline(time.Now())
			}
		}()
	}
	s.fallbackProxy.ServeHTTP(writer, request)
	if watchdog.stop() {
		// The response was cut short. Abort it so the client sees a reset rather
		// than a body that looks complete; the proxy does this itself only when
		// it recognises the server it runs under.
		panic(http.ErrAbortHandler)
	}
	return true
}

func (s *Service) acquireFallbackSource(source netip.Prefix) bool {
	s.fallbackSourceAccess.Lock()
	defer s.fallbackSourceAccess.Unlock()
	if s.fallbackSources[source] >= fallbackMaxPerSource {
		return false
	}
	s.fallbackSources[source]++
	return true
}

func (s *Service) releaseFallbackSource(source netip.Prefix) {
	s.fallbackSourceAccess.Lock()
	defer s.fallbackSourceAccess.Unlock()
	if s.fallbackSources[source]--; s.fallbackSources[source] <= 0 {
		delete(s.fallbackSources, source)
	}
}

// newFallbackRequestBody feeds the inbound body through a pipe that is closed as
// soon as the request is cancelled. The transport waits for the body writer
// before RoundTrip returns, so without this a client that stops uploading would
// keep the handler and the backend connection even after cancellation.
// The returned flag reports whether the whole inbound body has been read.
func newFallbackRequestBody(ctx context.Context, body io.ReadCloser, watchdog *idleWatchdog) (io.ReadCloser, *atomic.Bool) {
	reader, writer := io.Pipe()
	finished := new(atomic.Bool)
	go func() {
		_, err := io.Copy(writer, &idleReadCloser{ReadCloser: body, watchdog: watchdog})
		finished.Store(err == nil)
		_ = writer.CloseWithError(err)
	}()
	go func() {
		<-ctx.Done()
		_ = writer.CloseWithError(ctx.Err())
	}()
	return reader, finished
}

// idleWatchdog calls onIdle once no body data has moved for timeout, and
// onStuck if the request is still running a further timeout after that.
type idleWatchdog struct {
	access       sync.Mutex
	timer        *time.Timer
	timeout      time.Duration
	onIdle       func()
	onStuck      func()
	responding   bool
	responseDone bool
	stopped      bool
	fired        bool
	stuck        bool
}

func newIdleWatchdog(timeout time.Duration, onIdle func(), onStuck func()) *idleWatchdog {
	w := &idleWatchdog{timeout: timeout, onIdle: onIdle, onStuck: onStuck}
	w.timer = time.AfterFunc(timeout, w.fire)
	return w
}

func (w *idleWatchdog) fire() {
	w.access.Lock()
	defer w.access.Unlock()
	if w.stopped {
		return
	}
	if !w.fired {
		w.fired = true
		w.onIdle()
		w.timer.Reset(w.timeout)
		return
	}
	w.stuck = true
	w.onStuck()
}

func (w *idleWatchdog) touch() {
	w.access.Lock()
	defer w.access.Unlock()
	if !w.stopped && !w.fired {
		w.timer.Reset(w.timeout)
	}
}

// startResponse records that the response is being written to the client.
func (w *idleWatchdog) startResponse() {
	w.access.Lock()
	defer w.access.Unlock()
	w.responding = true
}

// finishResponse records that the whole backend response body has been read.
func (w *idleWatchdog) finishResponse() {
	w.access.Lock()
	defer w.access.Unlock()
	w.responseDone = true
}

// stop disarms the watchdog; once it returns, no callback will run. It reports
// whether the response was cut short: either writes were aborted, or the body
// was still incomplete when the backend side was cancelled.
func (w *idleWatchdog) stop() (truncated bool) {
	w.access.Lock()
	defer w.access.Unlock()
	w.stopped = true
	w.timer.Stop()
	return w.stuck || (w.fired && w.responding && !w.responseDone)
}

type idleReadCloser struct {
	io.ReadCloser
	watchdog *idleWatchdog
	response bool
}

func (r *idleReadCloser) Read(p []byte) (n int, err error) {
	n, err = r.ReadCloser.Read(p)
	if n > 0 {
		r.watchdog.touch()
	}
	if err == io.EOF && r.response {
		r.watchdog.finishResponse()
	}
	return
}

// h2ConnWrapper used to avoid "panic: Write called after Handler finished" for gun.Conn
type h2ConnWrapper struct {
	N.ExtendedConn
	access sync.Mutex
	closed bool
}

func (w *h2ConnWrapper) Write(p []byte) (n int, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	return w.ExtendedConn.Write(p)
}

func (w *h2ConnWrapper) WriteBuffer(buffer *buf.Buffer) error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	return w.ExtendedConn.WriteBuffer(buffer)
}

func (w *h2ConnWrapper) CloseWrapper() {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
}

func (w *h2ConnWrapper) Upstream() any {
	return w.ExtendedConn
}
