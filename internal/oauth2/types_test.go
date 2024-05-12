package oauth2

import (
	"fmt"
	"testing"
)

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

func Test_GrantTypeFromString(t *testing.T) {

	for _, test := range grandTypeParameters {
		testMessage := fmt.Sprintf("%s_%v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if grandType, exits := GrantTypeFromString(test.value); exits != test.exists && string(grandType) != test.expected {
				t.Errorf("Grand type %s not found,", test.value)
			}
		})
	}
}

func Test_ResponseTypeFromString(t *testing.T) {

	for _, test := range responseTypeParameters {
		testMessage := fmt.Sprintf("%s_%v", test.value, test.exists)
		t.Run(testMessage, func(t *testing.T) {
			if grandType, exits := ResponseTypeFromString(test.value); exits != test.exists && string(grandType) != test.expected {
				t.Errorf("Response type %s not found,", test.value)
			}
		})

	}
}
