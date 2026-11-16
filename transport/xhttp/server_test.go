package xhttp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerHandlerModeRestrictions(t *testing.T) {
	testCases := []struct {
		name       string
		mode       string
		method     string
		target     string
		wantStatus int
	}{
		{
			name:       "StreamOneAcceptsStreamOne",
			mode:       "stream-one",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamOneRejectsSessionDownload",
			mode:       "stream-one",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "StreamUpAcceptsStreamOne",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpAllowsDownloadEndpoint",
			mode:       "stream-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpRejectsPacketUpload",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpAllowsDownloadEndpoint",
			mode:       "packet-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpAcceptsPostUpload",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpAcceptsGetUpload",
			mode:       "packet-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpAcceptsPutUpload",
			mode:       "packet-up",
			method:     http.MethodPut,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "AutoAcceptsGetUpload",
			mode:       "auto",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpRejectsGetPacketUpload",
			mode:       "stream-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpRejectsStreamOne",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpRejectsStreamUpUpload",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{
				Path: "/xhttp",
				Mode: testCase.mode,
			}
			handler, err := NewServerHandler(ServerOption{
				Config: config,
				ConnHandler: func(conn net.Conn) {
					_ = conn.Close()
				},
			})
			assert.NoError(t, err)

			req := httptest.NewRequest(testCase.method, testCase.target, io.NopCloser(http.NoBody))
			recorder := httptest.NewRecorder()

			err = config.FillStreamRequest(req, "")
			assert.NoError(t, err)

			handler.ServeHTTP(recorder, req)

			assert.Equal(t, testCase.wantStatus, recorder.Result().StatusCode)
		})
	}
}

// Packet-up uploads with any method and data placement reach the session, with
// the server's uplink-data-placement unset ("auto") or naming the placement, and
// the default uplink-data-key / x-padding-obfs-mode settings on both sides (Xray-core's).
func TestServerHandlerPacketUpUploadPlacements(t *testing.T) {
	payload := bytes.Repeat([]byte("citrus-xhttp-"), 700) // ~9 KiB, several header chunks
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost} {
		for _, placement := range []string{PlacementBody, PlacementHeader, PlacementCookie} {
			for _, serverPlacement := range []string{"", placement} {
				for _, obfs := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/server=%q/obfs=%v", method, placement, serverPlacement, obfs)
					t.Run(name, func(t *testing.T) {
						serverConfig := Config{
							Path:                "/xhttp",
							Mode:                "packet-up",
							UplinkDataPlacement: serverPlacement,
							XPaddingObfsMode:    obfs,
						}
						clientConfig := Config{
							Path:                "/xhttp",
							Mode:                "packet-up",
							UplinkHTTPMethod:    method,
							UplinkDataPlacement: placement,
							XPaddingObfsMode:    obfs,
						}
						handler, err := NewServerHandler(ServerOption{
							Config:      serverConfig,
							ConnHandler: func(conn net.Conn) { _ = conn.Close() },
						})
						require.NoError(t, err)

						req := httptest.NewRequest(clientConfig.GetNormalizedUplinkHTTPMethod(), "https://example.com/xhttp", nil)
						require.NoError(t, clientConfig.FillPacketRequest(req, "session", "0", payload))
						if req.Body == nil {
							req.Body = http.NoBody
						}
						if placement == PlacementHeader {
							assert.NotEmpty(t, req.Header.Get("X-Data-0"))
						}
						recorder := httptest.NewRecorder()
						handler.ServeHTTP(recorder, req)

						result := recorder.Result()
						require.Equal(t, http.StatusOK, result.StatusCode)
						if method == http.MethodGet || placement != PlacementBody {
							assert.Equal(t, "no-store", result.Header.Get("Cache-Control"))
						}

						session := handler.(*requestHandler).getSession("session")
						require.NotNil(t, session)
						got := make([]byte, len(payload))
						_, err = io.ReadFull(session.uploadQueue, got)
						require.NoError(t, err)
						assert.Equal(t, payload, got)
						_ = session.uploadQueue.Close()
					})
				}
			}
		}
	}
}

// A server that names a placement reads only that placement, as in Xray-core.
func TestServerHandlerPacketUpUploadWrongPlacement(t *testing.T) {
	handler, err := NewServerHandler(ServerOption{
		Config:      Config{Path: "/xhttp", Mode: "packet-up", UplinkDataPlacement: PlacementBody},
		ConnHandler: func(conn net.Conn) { _ = conn.Close() },
	})
	require.NoError(t, err)
	clientConfig := Config{Path: "/xhttp", Mode: "packet-up", UplinkDataPlacement: PlacementHeader}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp", nil)
	require.NoError(t, clientConfig.FillPacketRequest(req, "session", "0", []byte("data")))
	req.Body = http.NoBody
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Result().StatusCode)

	session := handler.(*requestHandler).getSession("session")
	require.NotNil(t, session)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = session.uploadQueue.Close()
	}()
	n, _ := session.uploadQueue.Read(make([]byte, 16))
	assert.Equal(t, 0, n)
}
