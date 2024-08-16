package server

import (
	"errors"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func Test_Server(t *testing.T) {
	var testConfigHTTP = &config.Config{
		Server: config.Server{
			Addr: ":0",
		},
	}

	var testConfigHTTPS = &config.Config{
		Server: config.Server{
			TLS: config.TLS{
				Addr: ":0",
			},
		},
	}

	var testConfigBoth = &config.Config{
		Server: config.Server{
			Addr: ":0",
			TLS: config.TLS{
				Addr: ":0",
			},
		},
	}

	type testConfigParameter struct {
		name          string
		config        *config.Config
		expectedCount uint32
		hasError      bool
	}

	var testConfigParameters = []testConfigParameter{
		{name: "http", config: testConfigHTTP, expectedCount: 1, hasError: false},
		{name: "https", config: testConfigHTTPS, expectedCount: 1, hasError: false},
		{name: "both", config: testConfigBoth, expectedCount: 2, hasError: false},
		{name: "http", config: testConfigHTTP, expectedCount: 0, hasError: true},
		{name: "https", config: testConfigHTTPS, expectedCount: 0, hasError: true},
		{name: "both", config: testConfigBoth, expectedCount: 0, hasError: true},
	}

	t.Run("Register handlers", func(t *testing.T) {
		patterns := &[]string{}
		reg := func(pattern string, handler http.Handler) {
			*patterns = append(*patterns, pattern)
		}
		registerHandlers(&config.Config{}, reg)

		if len(*patterns) != 8 {
			t.Errorf("Incorrect number of patterns registered, expected 7 got %v", len(*patterns))
		}

		// Server
		slices.Contains(*patterns, endpoint.Health)
		slices.Contains(*patterns, endpoint.Account)
		slices.Contains(*patterns, endpoint.Logout)

		// OAuth2
		slices.Contains(*patterns, endpoint.Authorization)
		slices.Contains(*patterns, endpoint.Token)

		// OAuth2 extensions
		slices.Contains(*patterns, endpoint.Introspect)
		slices.Contains(*patterns, endpoint.Revoke)
		slices.Contains(*patterns, endpoint.Metadata)
	})

	for _, test := range testConfigParameters {
		testMessage := fmt.Sprintf("Start server with %s should start %d listeners", test.name, test.expectedCount)
		t.Run(testMessage, func(t *testing.T) {
			rwMutex := &sync.RWMutex{}
			//count := new(int)
			var c atomic.Uint32
			r := func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error {
				if test.hasError {
					return errors.New("")
				}
				c.Add(1)
				//*count = *count + 1

				if c.Load() == 1 {
					stopnikServer.httpServer = server
				} else if c.Load() == 2 {
					stopnikServer.httpsServer = server
				}
				return nil
			}
			server := newStopnikServerWithServe(rwMutex, test.config, http.NewServeMux(), r, r)

			server.Start()

			if c.Load() != test.expectedCount {
				t.Error("Incorrect number of servers registered")
			}

			server.Shutdown()
		})
	}

	t.Run("Start server", func(t *testing.T) {
		server := NewStopnikServer(testConfigBoth)

		if server == nil {
			t.Error("Failed to start server")
		}

		go server.Start()

		server.Shutdown()
	})

}
