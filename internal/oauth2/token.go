package oauth2

import "time"

type AccessToken struct {
	Key       string
	TokenType TokenType
	Username  string
	ClientId  string
	Scopes    []string
}
type RefreshToken struct {
	Key      string
	Username string
	ClientId string
	Scopes   []string
	AuthTime time.Time
}

// AccessTokenResponse as described in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
type AccessTokenResponse struct {
	AccessTokenValue  string    `json:"access_token,omitempty"`
	TokenType         TokenType `json:"token_type,omitempty"`
	ExpiresIn         int       `json:"expires_in,omitempty"` // seconds
	RefreshTokenValue string    `json:"refresh_token,omitempty"`
	IdTokenValue      string    `json:"id_token,omitempty"` // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
}
