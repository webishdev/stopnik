package oauth2

import (
	"fmt"
	"testing"
)

func Test_OAuth2Parameters(t *testing.T) {
	type oauth2Parameter struct {
		value    string
		expected string
	}

	var oauth2Parameters = []oauth2Parameter{
		{ParameterResponseType, "response_type"},
		{ParameterRedirectUri, "redirect_uri"},
		{ParameterState, "state"},
		{ParameterScope, "scope"},
		{ParameterClientId, "client_id"},
		{ParameterClientSecret, "client_secret"},
		{ParameterGrantType, "grant_type"},
		{ParameterTokenType, "token_type"},
		{ParameterAccessToken, "access_token"},
		{ParameterRefreshToken, "refresh_token"},
		{ParameterExpiresIn, "expires_in"},
		{ParameterCode, "code"},
		{ParameterUsername, "username"},
		{ParameterPassword, "password"},
		{ParameterToken, "token"},
		{ParameterTokenTypeHint, "token_type_hint"},
	}

	for _, test := range oauth2Parameters {
		testMessage := fmt.Sprintf("OAuth2 parameter %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if test.value != test.expected {
				t.Errorf("assertion error, %v != %v", test.value, test.expected)
			}
		})
	}
}
