package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
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
		emptyConfig := &config.Config{}
		initializationError := config.Initialize(emptyConfig)
		if initializationError != nil {
			t.Fatal(initializationError)
		}
		patterns := &[]string{}
		reg := func(pattern string, handler http.Handler) {
			*patterns = append(*patterns, pattern)
		}
		registerHandlers(emptyConfig, reg)

		expectedHandlers := 9
		if len(*patterns) != expectedHandlers {
			t.Errorf("Incorrect number of patterns registered, expected %v got %v", expectedHandlers, len(*patterns))
		}

		// Server
		healthPattern := slices.Contains(*patterns, endpoint.Health)
		if !healthPattern {
			t.Errorf("Health endpoint not registered")
		}
		accountPattern := slices.Contains(*patterns, endpoint.Account)
		if !accountPattern {
			t.Errorf("Account endpoint not registered")
		}
		logoutPattern := slices.Contains(*patterns, endpoint.Logout)
		if !logoutPattern {
			t.Errorf("Logout endpoint not registered")
		}

		// OAuth2
		authorizationPattern := slices.Contains(*patterns, endpoint.Authorization)
		if !authorizationPattern {
			t.Errorf("Authorization endpoint not registered")
		}
		tokenPattern := slices.Contains(*patterns, endpoint.Token)
		if !tokenPattern {
			t.Errorf("Token endpoint not registered")
		}

		// OAuth2 extensions
		introspectPattern := slices.Contains(*patterns, endpoint.Introspect)
		if !introspectPattern {
			t.Errorf("Introspect endpoint not registered")
		}
		revokePattern := slices.Contains(*patterns, endpoint.Revoke)
		if !revokePattern {
			t.Errorf("Revoke endpoint not registered")
		}
		metadataPattern := slices.Contains(*patterns, endpoint.Metadata)
		if !metadataPattern {
			t.Errorf("Metadata endpoint not registered")
		}
		keysPattern := slices.Contains(*patterns, endpoint.Keys)
		if !keysPattern {
			t.Errorf("Keys endpoint not registered")
		}
	})

	for _, test := range testConfigParameters {
		initializationError := config.Initialize(test.config)
		if initializationError != nil {
			t.Fatal(initializationError)
		}
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
			server := newStopnikServerWithServe(rwMutex, http.NewServeMux(), r, r)

			server.Start()

			if c.Load() != test.expectedCount {
				t.Error("Incorrect number of servers registered")
			}

			server.Shutdown()
		})
	}

	t.Run("Start server", func(t *testing.T) {
		initializationError := config.Initialize(testConfigBoth)
		if initializationError != nil {
			t.Fatal(initializationError)
		}
		server := NewStopnikServer()

		if server == nil {
			t.Error("Failed to start server")
		}

		go server.Start()

		server.Shutdown()
	})

}
