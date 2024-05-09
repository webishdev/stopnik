package store

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
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

	accessTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
	accessTokenKey := tokenManager.generateToken(username, client, accessTokenDuration)
	accessToken := &oauth2.AccessToken{
		Key:       accessTokenKey,
		TokenType: oauth2.TtBearer,
		Username:  username,
		ClientId:  client.Id,
		Scopes:    scopes,
	}

	tokenManager.accessTokenStore.SetWithDuration(accessTokenKey, accessToken, accessTokenDuration)

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
	if tokenManager.config.Server.TokenCert == "" && tokenManager.config.Server.TokenKey == "" {
		tokenString, tokenError := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte(tokenManager.config.GetServerSecret())))
		if tokenError != nil {
			panic(tokenError)
		}

		return string(tokenString)
	} else {
		keyPair, pairError := tls.LoadX509KeyPair(tokenManager.config.Server.TokenCert, tokenManager.config.Server.TokenKey)
		if pairError != nil {
			panic(pairError)
		}
		key := keyPair.PrivateKey.(*rsa.PrivateKey)

		tokenString, tokenError := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
		if tokenError != nil {
			panic(tokenError)
		}

		return string(tokenString)
	}

}
