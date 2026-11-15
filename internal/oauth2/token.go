package oauth2

import (
	"github.com/webishdev/stopnik/internal/oidc"
	"time"
)

// AccessToken holds the stored information about an issued access token.
// The GrantId is shared by all tokens issued for the same authorization, including refreshed tokens.
type AccessToken struct {
	Key             string
	TokenType       TokenType
	Username        string
	ClientId        string
	GrantId         string
	Scopes          []string
	RequestedClaims *oidc.ClaimsParameter
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

// RefreshToken holds the stored information about an issued refresh token.
// The GrantId is shared by all tokens issued for the same authorization, including refreshed tokens.
type RefreshToken struct {
	Key             string
	Username        string
	ClientId        string
	GrantId         string
	Scopes          []string
	RequestedClaims *oidc.ClaimsParameter
	AuthTime        time.Time
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

// AccessTokenResponse as described in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
type AccessTokenResponse struct {
	AccessTokenValue  string    `json:"access_token,omitempty"`
	TokenType         TokenType `json:"token_type,omitempty"`
	ExpiresIn         int       `json:"expires_in,omitempty"` // seconds
	RefreshTokenValue string    `json:"refresh_token,omitempty"`
	IdTokenValue      string    `json:"id_token,omitempty"` // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
}
