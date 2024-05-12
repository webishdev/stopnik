package oauth2

import (
	"reflect"
	"testing"
)

func Test_OAuth2Parameters(t *testing.T) {
	assertEqual(t, ParameterResponseType, "response_type")
	assertEqual(t, ParameterRedirectUri, "redirect_uri")
	assertEqual(t, ParameterState, "state")
	assertEqual(t, ParameterScope, "scope")
	assertEqual(t, ParameterClientId, "client_id")
	assertEqual(t, ParameterClientSecret, "client_secret")
	assertEqual(t, ParameterGrantType, "grant_type")
	assertEqual(t, ParameterTokenType, "token_type")
	assertEqual(t, ParameterAccessToken, "access_token")
	assertEqual(t, ParameterRefreshToken, "refresh_token")
	assertEqual(t, ParameterExpiresIn, "expires_in")
	assertEqual(t, ParameterCode, "code")
	assertEqual(t, ParameterUsername, "username")
	assertEqual(t, ParameterPassword, "password")
	assertEqual(t, ParameterToken, "token")
	assertEqual(t, ParameterTokenTypeHint, "token_type_hint")
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		t.Errorf("%v != %v", a, b)
	}
}
