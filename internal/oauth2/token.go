package oauth2

import (
	"encoding/base64"
	"github.com/google/uuid"
	"stopnik/internal/store"
	"time"
)

type AccessToken struct {
	Key      string
	ClientId string
	Scopes   []string
}
type RefreshToken string

// AccessTokenResponse as described in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
type AccessTokenResponse struct {
	AccessTokenKey  string    `json:"access_token,omitempty"`
	TokenType       TokenType `json:"token_type,omitempty"`
	ExpiresIn       int       `json:"expires_in,omitempty"` // seconds
	RefreshTokenKey string    `json:"refresh_token,omitempty"`
}

func CreateAccessTokenResponse(accessTokenStore *store.Store[AccessToken], clientId string, scopes []string) AccessTokenResponse {
	id := uuid.New()
	accessTokenKey := base64.RawURLEncoding.EncodeToString([]byte(id.String()))
	accessToken := AccessToken{
		Key:      accessTokenKey,
		ClientId: clientId,
		Scopes:   scopes,
	}
	tokenDuration := time.Minute * time.Duration(15)
	accessTokenStore.SetWithDuration(accessTokenKey, accessToken, tokenDuration)

	return AccessTokenResponse{
		AccessTokenKey: accessTokenKey,
		TokenType:      TtBearer,
		ExpiresIn:      int(tokenDuration / time.Second),
	}
}
