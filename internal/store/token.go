package store

import (
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"stopnik/log"
	"strings"
	"time"
)

type TokenManager struct {
	config            *config.Config
	accessTokenStore  *Store[oauth2.AccessToken]
	refreshTokenStore *Store[oauth2.RefreshToken]
}

func NewTokenManager(config *config.Config) *TokenManager {
	return &TokenManager{
		config:            config,
		accessTokenStore:  NewCache[oauth2.AccessToken](),
		refreshTokenStore: NewCache[oauth2.RefreshToken](),
	}
}

func (tokenManager *TokenManager) GetAccessToken(token string) (*oauth2.AccessToken, bool) {
	return tokenManager.accessTokenStore.Get(token)
}

func (tokenManager *TokenManager) RevokeAccessToken(token string) {
	tokenManager.accessTokenStore.Delete(token)
}

func (tokenManager *TokenManager) GetRefreshToken(token string) (*oauth2.RefreshToken, bool) {
	return tokenManager.refreshTokenStore.Get(token)
}

func (tokenManager *TokenManager) RevokeRefreshToken(token string) {
	tokenManager.refreshTokenStore.Delete(token)
}

func (tokenManager *TokenManager) CreateAccessTokenResponse(username string, client *config.Client, scopes []string) oauth2.AccessTokenResponse {
	log.Debug("Creating new access token for %s, access TTL %d, refresh TTL %d", client.Id, client.GetAccessTTL(), client.GetRefreshTTL())

	accessTokenId := uuid.New()
	accessTokenKey := base64.RawURLEncoding.EncodeToString([]byte(accessTokenId.String()))
	accessToken := &oauth2.AccessToken{
		Key:       accessTokenKey,
		TokenType: oauth2.TtBearer,
		Username:  username,
		ClientId:  client.Id,
		Scopes:    scopes,
	}
	accessTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
	tokenManager.accessTokenStore.SetWithDuration(accessTokenKey, accessToken, accessTokenDuration)

	accessTokenResponse := oauth2.AccessTokenResponse{
		AccessTokenKey: accessTokenKey,
		TokenType:      oauth2.TtBearer,
		ExpiresIn:      int(accessTokenDuration / time.Second),
	}

	if client.GetRefreshTTL() > 0 {
		refreshTokenId := uuid.New()
		refreshTokenKey := base64.RawURLEncoding.EncodeToString([]byte(refreshTokenId.String()))
		refreshToken := &oauth2.RefreshToken{
			Key:      refreshTokenKey,
			Username: username,
			ClientId: client.Id,
			Scopes:   scopes,
		}

		refreshTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
		tokenManager.refreshTokenStore.SetWithDuration(refreshTokenKey, refreshToken, refreshTokenDuration)

		accessTokenResponse.RefreshTokenKey = refreshTokenKey
	}

	return accessTokenResponse
}

func (tokenManager *TokenManager) ValidateAccessToken(r *http.Request) (*config.User, []string, bool) {
	log.Debug("Validating access token")
	authorization := r.Header.Get(internalHttp.Authorization)
	if authorization == "" || !strings.Contains(authorization, internalHttp.AuthBearer) {
		return nil, []string{}, false
	}

	replaceBearer := fmt.Sprintf("%s ", internalHttp.AuthBearer)
	authorizationHeader := strings.Replace(authorization, replaceBearer, "", 1)
	accessToken, authorizationHeaderExists := tokenManager.accessTokenStore.Get(authorizationHeader)
	if !authorizationHeaderExists {
		return nil, []string{}, false
	}

	username := accessToken.Username
	user, userExists := tokenManager.config.GetUser(username)

	if !userExists {
		return nil, []string{}, false
	}

	return user, accessToken.Scopes, true
}
