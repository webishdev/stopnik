package log

import (
	"bytes"
	"log"
	"log/slog"
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
