package pkce

import (
	"fmt"
	"testing"
)

func Test_ValidatePKCE(t *testing.T) {
	type challengeMethodParameters struct {
		method   CodeChallengeMethod
		value    string
		verifier string
		expected bool
	}

	var parameters = []challengeMethodParameters{
		{S256, "zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-8", "R79LG4zTGgB6WS7QGkf3x1BmPqe0RLHl1771POQjuTE", true},
		{S256, "zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-7", "R79LG4zTGgB6WS7QGkf3x1BmPqe0RLHl1771POQjuTE", false},
		{PLAIN, "foo", "foo", true},
		{PLAIN, "foo", "bar", false},
	}

	for _, test := range parameters {
		testMessage := fmt.Sprintf("Validate PKCE %s %s %s", test.method, test.value, test.verifier)
		t.Run(testMessage, func(t *testing.T) {
			if output := ValidatePKCE(test.method, test.value, test.verifier); output != test.expected {
				t.Errorf("Output %t not equal to expected %t", output, test.expected)
			}
		})
	}
}
