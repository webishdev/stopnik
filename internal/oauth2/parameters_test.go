package oauth2

import (
	"stopnik/assert"
	"testing"
)

func Test_OAuth2Parameters(t *testing.T) {
	assert.Equal(t, ParameterResponseType, "response_type")
	assert.Equal(t, ParameterRedirectUri, "redirect_uri")
	assert.Equal(t, ParameterState, "state")
	assert.Equal(t, ParameterScope, "scope")
	assert.Equal(t, ParameterClientId, "client_id")
	assert.Equal(t, ParameterClientSecret, "client_secret")
	assert.Equal(t, ParameterGrantType, "grant_type")
	assert.Equal(t, ParameterTokenType, "token_type")
	assert.Equal(t, ParameterAccessToken, "access_token")
	assert.Equal(t, ParameterRefreshToken, "refresh_token")
	assert.Equal(t, ParameterExpiresIn, "expires_in")
	assert.Equal(t, ParameterCode, "code")
	assert.Equal(t, ParameterUsername, "username")
	assert.Equal(t, ParameterPassword, "password")
	assert.Equal(t, ParameterToken, "token")
	assert.Equal(t, ParameterTokenTypeHint, "token_type_hint")
}
