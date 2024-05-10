package oauth2

import "testing"

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
	{"foo", false, ""},
}

var responseTypeParameters = []parameter{
	{string(RtCode), true, "code"},
	{string(RtToken), true, "token"},
	{string(RtPassword), true, "password"},
	{string(RtClientCredentials), true, "client_credentials"},
	{"foo", false, ""},
}

func TestGrantTypeFromString(t *testing.T) {

	for _, test := range grandTypeParameters {
		t.Logf("Testing %s %v", test.value, test.exists)
		if grandType, exits := GrantTypeFromString(test.value); exits != test.exists && string(grandType) != test.expected {
			t.Errorf("Grand type %s not found,", test.value)
		}
	}
}

func TestResponseTypeFromString(t *testing.T) {

	for _, test := range responseTypeParameters {
		t.Logf("Testing %s %v", test.value, test.exists)
		if grandType, exits := ResponseTypeFromString(test.value); exits != test.exists && string(grandType) != test.expected {
			t.Errorf("Response type %s not found,", test.value)
		}
	}
}
