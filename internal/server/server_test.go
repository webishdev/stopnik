package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"stopnik/internal/config"
	"testing"
)

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
	expectedCount int
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

func Test_Server(t *testing.T) {
	t.Run("Register handlers", func(t *testing.T) {
		patterns := &[]string{}
		reg := func(pattern string, handler http.Handler) {
			*patterns = append(*patterns, pattern)
		}
		registerHandlers(&config.Config{}, reg)

		if len(*patterns) != 7 {
			t.Error("Incorrect number of patterns registered")
		}

		// Server
		slices.Contains(*patterns, "/health")
		slices.Contains(*patterns, "/account")
		slices.Contains(*patterns, "/logout")

		// OAuth2
		slices.Contains(*patterns, "/authorize")
		slices.Contains(*patterns, "/token")

		// OAuth2 extensions
		slices.Contains(*patterns, "/introspect")
		slices.Contains(*patterns, "/revoke")
	})

	for _, test := range testConfigParameters {
		testMessage := fmt.Sprintf("Start server with %s should start %d listeners", test.name, test.expectedCount)
		t.Run(testMessage, func(t *testing.T) {

			count := new(int)
			r := func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error {
				if test.hasError {
					return errors.New("")
				}
				*count = *count + 1
				if *count == 1 {
					stopnikServer.httpServer = server
				} else if *count == 2 {
					stopnikServer.httpsServer = server
				}
				return nil
			}
			server := newStopnikServerWithServe(test.config, http.NewServeMux(), r, r)

			server.Start()

			if *count != test.expectedCount {
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
