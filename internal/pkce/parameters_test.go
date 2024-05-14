package pkce

import (
	"fmt"
	"testing"
)

type pkceParameter struct {
	value    string
	expected string
}

var pkceParameters = []pkceParameter{
	{ParameterCodeChallenge, "code_challenge"},
	{ParameterCodeChallengeMethod, "code_challenge_method"},
	{ParameterCodeVerifier, "code_verifier"},
}

func Test_PKCEParameters(t *testing.T) {
	for _, test := range pkceParameters {
		testMessage := fmt.Sprintf("PKCE parameter %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("assertion error, %v != %v", test.value, test.expected)
			}
		})
	}
}
