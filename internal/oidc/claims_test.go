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

func Test_HasUserInfoClaim(t *testing.T) {
	claimsParameter := &ClaimsParameter{}
	claimsParameter.UserInfo = make(map[string]*ClaimsParameterMember)
	claimsParameter.UserInfo["foo"] = &ClaimsParameterMember{}

	type claimParameter struct {
		name     string
		expected bool
	}

	var claimParameters = []claimParameter{
		{"foo", true},
		{"bar", false},
	}

	for _, test := range claimParameters {
		testMessage := fmt.Sprintf("OIDC has claim %s", test.name)
		t.Run(testMessage, func(t *testing.T) {
			exists := HasUserInfoClaim(claimsParameter, test.name)
			if exists != test.expected {
				t.Errorf("assertion error, %v != %v", exists, test.expected)
			}
		})
	}
}

func Test_HasUserInfoClaimNoValue(t *testing.T) {
	exists := HasUserInfoClaim(nil, "foo")
	if exists {
		t.Errorf("claim should not exist")
	}
}
