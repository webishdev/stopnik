package oidc

import (
	"fmt"
	"testing"
)

func Test_Claims(t *testing.T) {
	type claimParameter struct {
		value    string
		expected string
	}

	var claimParameters = []claimParameter{
		{ClaimNonce, "nonce"},
		{ClaimAuthorizedParty, "azp"},
		{ClaimAtHash, "at_hash"},
	}

	for _, test := range claimParameters {
		testMessage := fmt.Sprintf("OIDC claim %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("assertion error, %v != %v", test.value, test.expected)
			}
		})
	}
}
