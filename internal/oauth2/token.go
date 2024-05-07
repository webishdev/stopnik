package oauth2

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
}

// AccessTokenResponse as described in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
type AccessTokenResponse struct {
	AccessTokenKey  string    `json:"access_token,omitempty"`
	TokenType       TokenType `json:"token_type,omitempty"`
	ExpiresIn       int       `json:"expires_in,omitempty"` // seconds
	RefreshTokenKey string    `json:"refresh_token,omitempty"`
}
