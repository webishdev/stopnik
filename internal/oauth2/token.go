package oauth2

import (
	"encoding/base64"
	"github.com/google/uuid"
	"stopnik/internal/store"
	"time"
)

type AccessToken string
type RefreshToken string

// AccessTokenResponse as described in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
type AccessTokenResponse struct {
	AccessToken  AccessToken  `json:"access_token,omitempty"`
	TokenType    TokenType    `json:"token_type,omitempty"`
	ExpiresIn    int          `json:"expires_in,omitempty"` // seconds
	RefreshToken RefreshToken `json:"refresh_token,omitempty"`
}

func CreateAccessTokenResponse(accessTokenStore *store.Store[AccessToken]) AccessTokenResponse {
	id := uuid.New()
	accessTokenValue := base64.RawURLEncoding.EncodeToString([]byte(id.String()))
	accessToken := AccessToken(accessTokenValue)
	tokenDuration := time.Minute * time.Duration(45)
	accessTokenStore.SetWithDuration(string(accessToken), accessToken, tokenDuration)

	return AccessTokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   int(tokenDuration / time.Millisecond),
	}
}
