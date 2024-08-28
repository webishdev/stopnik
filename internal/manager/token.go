package manager

import (
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"strings"
	"time"
)

type TokenManager struct {
	config            *config.Config
	keyLoader         crypto.KeyLoader
	accessTokenStore  *store.ExpiringStore[oauth2.AccessToken]
	refreshTokenStore *store.ExpiringStore[oauth2.RefreshToken]
}

func NewTokenManager(config *config.Config, keyLoader crypto.KeyLoader) *TokenManager {
	accessTokenStore := store.NewDefaultTimedStore[oauth2.AccessToken]()
	refreshTokenStore := store.NewDefaultTimedStore[oauth2.RefreshToken]()
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

func (tokenManager *TokenManager) CreateAccessTokenResponse(r *http.Request, username string, client *config.Client, scopes []string, nonce string) oauth2.AccessTokenResponse {
	log.Debug("Creating new access token for %s, access TTL %d, refresh TTL %d", client.Id, client.GetAccessTTL(), client.GetRefreshTTL())

	requestData := internalHttp.NewRequestData(r)
	accessTokenStore := *tokenManager.accessTokenStore
	refreshTokenStore := *tokenManager.refreshTokenStore

	accessTokenDuration := time.Minute * time.Duration(client.GetAccessTTL())
	accessTokenKey := tokenManager.generateAccessToken(requestData, username, client, accessTokenDuration)
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
		refreshTokenKey := tokenManager.generateAccessToken(requestData, username, client, refreshTokenDuration)
		refreshToken := &oauth2.RefreshToken{
			Key:      refreshTokenKey,
			Username: username,
			ClientId: client.Id,
			Scopes:   scopes,
		}

		refreshTokenStore.SetWithDuration(refreshTokenKey, refreshToken, refreshTokenDuration)

		accessTokenResponse.RefreshTokenKey = refreshTokenKey
	}

	if client.Oidc && oidc.HasOidcScope(scopes) {
		user, userExists := tokenManager.config.GetUser(username)
		if userExists {
			idTokenDuration := time.Minute * time.Duration(client.GetIdTTL())
			idTokenKey := tokenManager.generateIdToken(requestData, user, client, nonce, idTokenDuration)
			accessTokenResponse.IdToken = idTokenKey
		}
	}

	return accessTokenResponse
}

func (tokenManager *TokenManager) ValidateAccessToken(authorizationHeader string) (*config.User, *config.Client, []string, bool) {
	log.Debug("Validating access token")
	accessTokenStore := *tokenManager.accessTokenStore
	headerValue := getAuthorizationHeaderValue(authorizationHeader)
	if headerValue == nil {
		return nil, nil, []string{}, false
	}
	accessToken, authorizationHeaderExists := accessTokenStore.Get(*headerValue)
	if !authorizationHeaderExists {
		return nil, nil, []string{}, false
	}

	username := accessToken.Username
	user, userExists := tokenManager.config.GetUser(username)

	if !userExists {
		return nil, nil, []string{}, false
	}

	clientId := accessToken.ClientId
	client, clientExists := tokenManager.config.GetClient(clientId)

	if !clientExists {
		return nil, nil, []string{}, false
	}

	return user, client, accessToken.Scopes, true
}

func (tokenManager *TokenManager) generateIdToken(requestData *internalHttp.RequestData, user *config.User, client *config.Client, nonce string, duration time.Duration) string {
	idToken := generateIdToken(requestData, user, client, nonce, duration)
	return tokenManager.generateJWTToken(client, idToken)
}

func (tokenManager *TokenManager) generateAccessToken(requestData *internalHttp.RequestData, username string, client *config.Client, duration time.Duration) string {
	tokenId := uuid.New()
	if client.OpaqueToken {
		return tokenManager.generateOpaqueAccessToken(tokenId.String())
	}
	accessToken := generateAccessToken(requestData, tokenId.String(), duration, username, client)
	return tokenManager.generateJWTToken(client, accessToken)
}

func (tokenManager *TokenManager) generateOpaqueAccessToken(tokenId string) string {
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
func (tokenManager *TokenManager) generateJWTToken(client *config.Client, token jwt.Token) string {

	loader := tokenManager.keyLoader
	managedKey, keyExists := loader.LoadKeys(client)

	if !keyExists {
		options := loader.GetServerKey()
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

func generateIdToken(requestData *internalHttp.RequestData, user *config.User, client *config.Client, nonce string, duration time.Duration) jwt.Token {
	tokenId := uuid.New().String()
	builder := jwt.NewBuilder().
		Expiration(time.Now().Add(duration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                  // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(client.GetIssuer(requestData))

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(user.Username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	audience := append(client.GetAudience(), client.Id)
	builder.Audience(audience)

	builder.Claim(oidc.ClaimAuthorizedParty, client.Id)
	builder.Claim(oidc.ClaimNonce, nonce)
	roles := user.GetRoles(client.Id)
	if len(roles) != 0 {
		builder.Claim(client.GetRolesClaim(), roles)
	}

	token, builderError := builder.Build()

	if builderError != nil {
		panic(builderError)
	}

	return token
}

func generateAccessToken(requestData *internalHttp.RequestData, tokenId string, duration time.Duration, username string, client *config.Client) jwt.Token {
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
	builder.Issuer(client.GetIssuer(requestData))

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	builder.Audience(client.GetAudience())

	token, builderError := builder.Build()

	if builderError != nil {
		panic(builderError)
	}

	return token
}

func getAuthorizationHeaderValue(authorizationHeader string) *string {
	if authorizationHeader == "" || !strings.Contains(authorizationHeader, internalHttp.AuthBearer) {
		return nil
	}

	replaceBearer := fmt.Sprintf("%s ", internalHttp.AuthBearer)
	result := strings.Replace(authorizationHeader, replaceBearer, "", 1)
	return &result
}
