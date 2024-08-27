package oauth2

import (
	"fmt"
	"testing"
)

func Test_GrantTypeFromString(t *testing.T) {
	type parameter struct {
		value    string
		exists   bool
		expected string
	}

	var grandTypeParameters = []parameter{
		{string(GtAuthorizationCode), true, "authorization_code"},
		{string(GtClientCredentials), true, "client_credentials"},
		{string(GtPassword), true, "password"},
		{string(GtRefreshToken), true, "refresh_token"},
		{string(GtImplicit), true, "implicit"},
		{"foo", false, ""},
	}

	for _, test := range grandTypeParameters {
		testMessage := fmt.Sprintf("Grand type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if grandType, exits := GrantTypeFromString(test.value); exits != test.exists && string(grandType) != test.expected {
				t.Errorf("Grand type %s not found,", test.value)
			}
		})
	}
}

func Test_ResponseTypeFromString(t *testing.T) {
	type parameter struct {
		value    string
		exists   bool
		expected string
	}

	var responseTypeParameters = []parameter{
		{string(RtCode), true, "code"},
		{string(RtToken), true, "token"},
		{string(RtPassword), true, "password"},
		{string(RtClientCredentials), true, "client_credentials"},
		{"foo", false, ""},
	}

	for _, test := range responseTypeParameters {
		testMessage := fmt.Sprintf("Response type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if responseType, exits := ResponseTypeFromString(test.value); exits != test.exists && string(responseType) != test.expected {
				t.Errorf("Response type %s not found,", test.value)
			}
		})

	}
}

func Test_ClientTypeFromString(t *testing.T) {
	type parameter struct {
		value    string
		exists   bool
		expected string
	}

	var clientTypeParameters = []parameter{
		{string(CtConfidential), true, "confidential"},
		{string(CtPublic), true, "public"},
		{"foo", false, ""},
	}

	for _, test := range clientTypeParameters {
		testMessage := fmt.Sprintf("Client type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if clientType, exits := ClientTypeFromString(test.value); exits != test.exists && string(clientType) != test.expected {
				t.Errorf("Client type %s not found,", test.value)
			}
		})
	}
}

func Test_TokenTypeFromString(t *testing.T) {
	type parameter struct {
		value    string
		exists   bool
		expected string
	}

	var tokenTypeParameters = []parameter{
		{string(TtBearer), true, "Bearer"},
		{string(TtMAC), true, "mac"},
		{"foo", false, ""},
	}

	for _, test := range tokenTypeParameters {
		testMessage := fmt.Sprintf("Token type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if tokenType, exits := TokenTypeFromString(test.value); exits != test.exists && string(tokenType) != test.expected {
				t.Errorf("Token type %s not found,", test.value)
			}
		})
	}
}

func Test_IntrospectTokenTypeFromString(t *testing.T) {
	type parameter struct {
		value    string
		exists   bool
		expected string
	}

	var clientTypeParameters = []parameter{
		{string(ItAccessToken), true, "access_token"},
		{string(ItRefreshToken), true, "refresh_token"},
		{"foo", false, ""},
	}

	for _, test := range clientTypeParameters {
		testMessage := fmt.Sprintf("Introspect token type %s %v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if introspectTokenType, exits := IntrospectTokenTypeFromString(test.value); exits != test.exists && string(introspectTokenType) != test.expected {
				t.Errorf("Introspect token type %s not found,", test.value)
			}
		})
	}
}
