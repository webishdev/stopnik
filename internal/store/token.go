package store

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
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

	accessTokenKey := tokenManager.generateToken(client)
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
		refreshTokenKey := tokenManager.generateToken(client)
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

func (tokenManager *TokenManager) generateToken(client *config.Client) string {
	if client.OpaqueToken {
		return tokenManager.generateOpaqueToken()
	}
	return tokenManager.generateJWTToken()
}

func (tokenManager *TokenManager) generateOpaqueToken() string {
	tokenId := uuid.New()
	return base64.RawURLEncoding.EncodeToString([]byte(tokenId.String()))
}

// switch to github.com/golang-jwt/jwt/v5
// https://datatracker.ietf.org/doc/html/rfc9068
// https://www.iana.org/assignments/jwt/jwt.xhtml
/*
{
  "iss": "https://authorization-server.com/",
  "exp": 1637344572,
  "aud": "api://default",
  "sub": "1000",
  "client_id": "https://example-app.com",
  "iat": 1637337372,
  "jti": "1637337372.2051.620f5a3dc0ebaa097312",
  "scope": "read write"
}
*/
func (tokenManager *TokenManager) generateJWTToken() string {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}
	if tokenManager.config.Server.TokenCert == "" && tokenManager.config.Server.TokenKey == "" {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString([]byte(tokenManager.config.GetServerSecret()))
		if err != nil {
			panic(err)
		}

		return tokenString
	} else {
		keyPair, pairError := tls.LoadX509KeyPair(tokenManager.config.Server.TokenCert, tokenManager.config.Server.TokenKey)
		if pairError != nil {
			panic(pairError)
		}
		key := keyPair.PrivateKey.(*rsa.PrivateKey)
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

		tokenString, tokenError := token.SignedString(key)
		if tokenError != nil {
			panic(tokenError)
		}

		return tokenString
	}

}
