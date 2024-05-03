package oauth2

type AccessToken string
type RefreshToken string

// AccessTokenResponse as described in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
type AccessTokenResponse struct {
	AccessToken  AccessToken  `json:"access_token,omitempty"`
	TokenType    TokenType    `json:"token_type,omitempty"`
	ExpiresIn    int          `json:"expires_in,omitempty"` // seconds
	RefreshToken RefreshToken `json:"refresh_token,omitempty"`
}
