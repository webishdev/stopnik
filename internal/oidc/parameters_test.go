package oidc

import (
	"fmt"
	"testing"
)

func Test_Parameters(t *testing.T) {
	type paramParameter struct {
		value    string
		expected string
	}

	var paramParameters = []paramParameter{
		{ParameterNonce, "nonce"},
		{ParameterIdToken, "id_token"},
	}

	for _, test := range paramParameters {
		testMessage := fmt.Sprintf("OIDC parameter %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("assertion error, %v != %v", test.value, test.expected)
			}
		})
	}
}
