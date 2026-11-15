package pkce

import (
	"fmt"
	"strings"
	"testing"
)

func Test_ValidatePKCE(t *testing.T) {
	type challengeMethodParameters struct {
		method        CodeChallengeMethod
		codeChallenge string
		codeVerifier  string
		expected      bool
	}

	var parameters = []challengeMethodParameters{
		{S256, "zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-8", "R79LG4zTGgB6WS7QGkf3x1BmPqe0RLHl1771POQjuTE", true},
		{S256, "zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-7", "R79LG4zTGgB6WS7QGkf3x1BmPqe0RLHl1771POQjuTE", false},
		{PLAIN, "foo", "foo", true},
		{PLAIN, "foo", "bar", false},
	}

	for _, test := range parameters {
		testMessage := fmt.Sprintf("Validate PKCE %s %s %s", test.method, test.codeChallenge, test.codeVerifier)
		t.Run(testMessage, func(t *testing.T) {
			if output := ValidatePKCE(test.method, test.codeChallenge, test.codeVerifier); output != test.expected {
				t.Errorf("Output %t not equal to expected %t", output, test.expected)
			}
		})
	}
}

func Test_IsValidCodeVerifier(t *testing.T) {
	var parameters = []struct {
		codeVerifier string
		expected     bool
	}{
		{"R79LG4zTGgB6WS7QGkf3x1BmPqe0RLHl1771POQjuTE", true},
		{strings.Repeat("a", 43), true},
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 42), false},
		{strings.Repeat("a", 129), false},
		{strings.Repeat("a", 40) + "-._~", true},
		{strings.Repeat("a", 42) + "+", false},
		{strings.Repeat("a", 42) + "/", false},
		{strings.Repeat("a", 42) + " ", false},
		{"", false},
	}

	for _, test := range parameters {
		t.Run(test.codeVerifier, func(t *testing.T) {
			if output := IsValidCodeVerifier(test.codeVerifier); output != test.expected {
				t.Errorf("Output %t not equal to expected %t", output, test.expected)
			}
		})
	}
}

func Test_IsValidS256CodeChallenge(t *testing.T) {
	var parameters = []struct {
		codeChallenge string
		expected      bool
	}{
		{"zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-8", true},
		{"zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-", false},
		{"zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-88", false},
		{"zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q+8", false},
		{"zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q.8", false},
		{"", false},
	}

	for _, test := range parameters {
		t.Run(test.codeChallenge, func(t *testing.T) {
			if output := IsValidS256CodeChallenge(test.codeChallenge); output != test.expected {
				t.Errorf("Output %t not equal to expected %t", output, test.expected)
			}
		})
	}
}

func Test_GenerateCodeVerifier(t *testing.T) {
	first := GenerateCodeVerifier()
	second := GenerateCodeVerifier()
	if !IsValidCodeVerifier(first) || first == second {
		t.Errorf("expected different valid code verifiers, got %s and %s", first, second)
	}
	if !IsValidS256CodeChallenge(CalculatePKCE(S256, first)) {
		t.Error("expected valid code challenge for generated code verifier")
	}
}
