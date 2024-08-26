package store

import (
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/log"
	"strings"
	"time"
)

type TokenManager struct {
	config            *config.Config
	keyLoader         crypto.KeyLoader
	accessTokenStore  *ExpiringStore[oauth2.AccessToken]
	refreshTokenStore *ExpiringStore[oauth2.RefreshToken]
}

func NewTokenManager(config *config.Config, keyLoader crypto.KeyLoader) *TokenManager {
	accessTokenStore := NewDefaultTimedStore[oauth2.AccessToken]()
	refreshTokenStore := NewDefaultTimedStore[oauth2.RefreshToken]()
	return &TokenManager{
		config:            config,
		keyLoader:         keyLoader,
		accessTokenStore:  &accessTokenStore,
		refreshTokenStore: &refreshTokenStore,
	}
}

func (tokenManager *TokenManager) GetAccessToken(token string) (*oauth2.AccessToken, bool) {
	accessTokenStore := *tokenManager.accessTokenStore
	return accessTokenStore.Get(token)
}

func (tokenManager *TokenManager) RevokeAccessToken(accessToken *oauth2.AccessToken) {
	accessTokenStore := *tokenManager.accessTokenStore
	accessTokenStore.Delete(accessToken.Key)
}

func (tokenManager *TokenManager) GetRefreshToken(token string) (*oauth2.RefreshToken, bool) {
	refreshTokenStore := *tokenManager.refreshTokenStore
	return refreshTokenStore.Get(token)
}

func (tokenManager *TokenManager) RevokeRefreshToken(refreshToken *oauth2.RefreshToken) {
	refreshTokenStore := *tokenManager.refreshTokenStore
	refreshTokenStore.Delete(refreshToken.Key)
}

func (tokenManager *TokenManager) CreateAccessTokenResponse(username string, client *config.Client, scopes []string) oauth2.AccessTokenResponse {
	log.Debug("Creating new access token for %s, access TTL %d, refresh TTL %d", client.Id, client.GetAccessTTL(), client.GetRefreshTTL())

	accessTokenStore := *tokenManager.accessTokenStore
	refreshTokenStore := *tokenManager.refreshTokenStore

	accessTokenDuration := time.Minute * time.Duration(client.GetAccessTTL())
	accessTokenKey := tokenManager.generateToken(username, client, accessTokenDuration)
	accessToken := &oauth2.AccessToken{
		Key:       accessTokenKey,
		TokenType: oauth2.TtBearer,
		Username:  username,
		ClientId:  client.Id,
		Scopes:    scopes,
	}

	accessTokenStore.SetWithDuration(accessTokenKey, accessToken, accessTokenDuration)

	accessTokenResponse := oauth2.AccessTokenResponse{
		AccessTokenKey: accessTokenKey,
		TokenType:      oauth2.TtBearer,
		ExpiresIn:      int(accessTokenDuration / time.Second),
	}

	if client.GetRefreshTTL() > 0 {
		refreshTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
		refreshTokenKey := tokenManager.generateToken(username, client, refreshTokenDuration)
		refreshToken := &oauth2.RefreshToken{
			Key:      refreshTokenKey,
			Username: username,
			ClientId: client.Id,
			Scopes:   scopes,
		}

		refreshTokenStore.SetWithDuration(refreshTokenKey, refreshToken, refreshTokenDuration)

		accessTokenResponse.RefreshTokenKey = refreshTokenKey
	}

	return accessTokenResponse
}

func (tokenManager *TokenManager) ValidateAccessToken(authorizationHeader string) (*config.User, []string, bool) {
	log.Debug("Validating access token")
	accessTokenStore := *tokenManager.accessTokenStore
	headerValue := getAuthorizationHeaderValue(authorizationHeader)
	if headerValue == nil {
		return nil, []string{}, false
	}
	accessToken, authorizationHeaderExists := accessTokenStore.Get(*headerValue)
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

func (tokenManager *TokenManager) generateToken(username string, client *config.Client, duration time.Duration) string {
	tokenId := uuid.New()
	if client.OpaqueToken {
		return tokenManager.generateOpaqueToken(tokenId.String())
	}
	return tokenManager.generateJWTToken(tokenId.String(), duration, username, client)
}

func (tokenManager *TokenManager) generateOpaqueToken(tokenId string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(tokenId))
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
func (tokenManager *TokenManager) generateJWTToken(tokenId string, duration time.Duration, username string, client *config.Client) string {
	builder := jwt.NewBuilder().
		Expiration(time.Now().Add(duration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                  // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	for claimIndex := range client.Claims {
		claim := client.Claims[claimIndex]
		builder.Claim(claim.Name, claim.Value)
	}

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(client.GetIssuer())

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	builder.Audience(client.GetAudience())

	token, builderError := builder.Build()

	if builderError != nil {
		panic(builderError)
	}

	loader := tokenManager.keyLoader
	managedKey, keyExists := loader.LoadKeys(client)

	if !keyExists {
		options := loader.GetServerSecret()
		tokenString, tokenError := jwt.Sign(token, options)
		if tokenError != nil {
			panic(tokenError)
		}

		return string(tokenString)
	} else {
		key := *managedKey.Key

		options := jwt.WithKey(key.Algorithm(), key)

		tokenString, tokenError := jwt.Sign(token, options)
		if tokenError != nil {
			panic(tokenError)
		}

		return string(tokenString)
	}

}

func getAuthorizationHeaderValue(authorizationHeader string) *string {
	if authorizationHeader == "" || !strings.Contains(authorizationHeader, internalHttp.AuthBearer) {
		return nil
	}

	replaceBearer := fmt.Sprintf("%s ", internalHttp.AuthBearer)
	result := strings.Replace(authorizationHeader, replaceBearer, "", 1)
	return &result
}
