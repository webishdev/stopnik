package log

import (
	"bytes"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_Log(t *testing.T) {
	type logLevelStringParameter struct {
		value         string
		expectedLevel slog.Level
	}

	var logLevels = []logLevelStringParameter{
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"debug", slog.LevelDebug},
		{"foo", slog.LevelInfo},
		{"bar", slog.LevelInfo},
	}

	type loggerTestParameter struct {
		name   string
		method func(format string, v ...any)
		logger *log.Logger
	}

	var loggerTests = []loggerTestParameter{
		{name: "Info", method: Info, logger: infoLogger},
		{name: "Debug", method: Debug, logger: debugLogger},
		{name: "Warn", method: Warn, logger: warnLogger},
		{name: "Error", method: Error, logger: errorLogger},
	}

	t.Run("Get log level from string", func(t *testing.T) {
		for _, test := range logLevels {
			levelFromString := getLogLevelFromString(test.value)

			if levelFromString != test.expectedLevel {
				t.Errorf("Expected level '%s', got '%s'", test.expectedLevel, levelFromString)
			}

			SetLogLevel(test.value)

			if levelFromString == slog.LevelDebug && !IsDebug() {
				t.Error("Expected level debug")
			}
		}

	})

	for _, test := range loggerTests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			test.logger.SetOutput(&buf)

			test.method("Hello %s", "world")

			value := buf.String()

			if value != "Hello world\n" {
				t.Errorf("Expected 'Hello world', got '%s'", value)
			}
		})
	}

}

func Test_AccessLog(t *testing.T) {
	type accessLogParameter struct {
		name     string
		method   func(r *http.Request)
		expected string
	}

	var accessLogTests = []accessLogParameter{
		{
			name:     "Request",
			method:   AccessLogRequest,
			expected: "192.0.2.1:1234 - example.com - GET http://example.com/foo",
		},
		{
			name: "Result",
			method: func(r *http.Request) {
				AccessLogResult(r, http.StatusOK, "OK")
			},
			expected: "192.0.2.1:1234 - example.com - GET http://example.com/foo - 200 OK",
		},
		{
			name: "Invalid login",
			method: func(r *http.Request) {
				AccessLogInvalidLogin(r, "Invalid login for %s", "foo")
			},
			expected: "Invalid login for foo - 192.0.2.1:1234",
		},
	}

	for _, test := range accessLogTests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			accessLogger.SetOutput(&buf)

			request := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
			test.method(request)

			value := buf.String()

			if !strings.Contains(value, test.expected) {
				t.Errorf("Expected '%s' in '%s'", test.expected, value)
			}
		})
	}
}

func Test_GetAddrFromRequest(t *testing.T) {
	type addrParameter struct {
		forwardedFor string
		realIp       string
		expected     string
	}

	var addrTests = []addrParameter{
		{"", "", "192.0.2.1:1234"},
		{"203.0.113.1", "", "192.0.2.1:1234, X-Forwarded-For: 203.0.113.1"},
		{"", "203.0.113.2", "192.0.2.1:1234, X-Real-Ip: 203.0.113.2"},
		{"203.0.113.1", "203.0.113.2", "192.0.2.1:1234, X-Forwarded-For: 203.0.113.1, X-Real-Ip: 203.0.113.2"},
	}

	for _, test := range addrTests {
		t.Run(test.expected, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.forwardedFor != "" {
				request.Header.Set("X-Forwarded-For", test.forwardedFor)
			}
			if test.realIp != "" {
				request.Header.Set("X-Real-Ip", test.realIp)
			}

			addr := getAddrFromRequest(request)

			if addr != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, addr)
			}
		})
	}
}
