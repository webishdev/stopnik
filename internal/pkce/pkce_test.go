package pkce

import (
	"testing"
)

type parameter struct {
	method   CodeChallengeMethod
	value    string
	verifier string
	expected bool
}

var parameters = []parameter{
	{S256, "zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-8", "R79LG4zTGgB6WS7QGkf3x1BmPqe0RLHl1771POQjuTE", true},
	{S256, "zzq3NtZoI3xStS6o35KHynY9X8XK5Cuqi9NaZfk1Q-7", "R79LG4zTGgB6WS7QGkf3x1BmPqe0RLHl1771POQjuTE", false},
	{PLAIN, "foo", "foo", true},
	{PLAIN, "foo", "bar", false},
}

func TestValidatePKCE(t *testing.T) {

	for _, test := range parameters {
		t.Logf("Testing %s %s %s", test.method, test.value, test.verifier)
		if output := ValidatePKCE(test.method, test.value, test.verifier); output != test.expected {
			t.Errorf("Output %t not equal to expected %t", output, test.expected)
		}
	}
}
