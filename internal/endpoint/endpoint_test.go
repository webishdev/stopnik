package endpoint

import (
	"fmt"
	"testing"
)

func Test_Endpoint(t *testing.T) {
	type parameter struct {
		value    string
		expected string
	}

	var endpointParameters = []parameter{
		{Authorization, "/authorize"},
		{Token, "/token"},
		{Health, "/health"},
		{Account, "/account"},
		{Logout, "/logout"},
		{Introspect, "/introspect"},
		{Revoke, "/revoke"},
		{Metadata, "/.well-known/oauth-authorization-server"},
	}

	for _, test := range endpointParameters {
		testMessage := fmt.Sprintf("Endppoint %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("Endpoint value %s did not match %s", test.value, test.expected)
			}
		})

	}
}
