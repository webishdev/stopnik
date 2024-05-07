package oauth2

import (
	"encoding/base64"
	"github.com/google/uuid"
	"stopnik/internal/config"
	"stopnik/internal/store"
	"stopnik/log"
	"time"
)

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

type TokenGenerator struct {
	config            *config.Config
	accessTokenStore  *store.Store[AccessToken]
	refreshTokenStore *store.Store[RefreshToken]
}

func CreateAccessTokenResponse(accessTokenStore *store.Store[AccessToken], refreshTokenStore *store.Store[RefreshToken], username string, client *config.Client, scopes []string) AccessTokenResponse {
	log.Debug("Creating new access token for %s, access TTL %d, refresh TTL %d", client.Id, client.GetAccessTTL(), client.GetRefreshTTL())

	accessTokenId := uuid.New()
	accessTokenKey := base64.RawURLEncoding.EncodeToString([]byte(accessTokenId.String()))
	accessToken := &AccessToken{
		Key:       accessTokenKey,
		TokenType: TtBearer,
		Username:  username,
		ClientId:  client.Id,
		Scopes:    scopes,
	}
	accessTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
	accessTokenStore.SetWithDuration(accessTokenKey, accessToken, accessTokenDuration)

	accessTokenResponse := AccessTokenResponse{
		AccessTokenKey: accessTokenKey,
		TokenType:      TtBearer,
		ExpiresIn:      int(accessTokenDuration / time.Second),
	}

	if client.GetRefreshTTL() > 0 {
		refreshTokenId := uuid.New()
		refreshTokenKey := base64.RawURLEncoding.EncodeToString([]byte(refreshTokenId.String()))
		refreshToken := &RefreshToken{
			Key:      refreshTokenKey,
			Username: username,
			ClientId: client.Id,
			Scopes:   scopes,
		}

		refreshTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
		refreshTokenStore.SetWithDuration(refreshTokenKey, refreshToken, refreshTokenDuration)

		accessTokenResponse.RefreshTokenKey = refreshTokenKey
	}

	return accessTokenResponse
}

type TokenGeneratorX interface {
	GenerateAccessToken() string
	GenerateRefreshToken() string
}

type OpaqueTokenGenerator struct {
}

func (otk OpaqueTokenGenerator) GenerateAccessToken(username string, client *config.Client, scopes []string) *AccessToken {
	accessTokenId := uuid.New()
	accessTokenKey := base64.RawURLEncoding.EncodeToString([]byte(accessTokenId.String()))
	return &AccessToken{
		Key:       accessTokenKey,
		TokenType: TtBearer,
		Username:  username,
		ClientId:  client.Id,
		Scopes:    scopes,
	}
}

func (otk OpaqueTokenGenerator) GenerateOpaqueToken() string {
	id := uuid.New()
	return base64.RawURLEncoding.EncodeToString([]byte(id.String()))
}
