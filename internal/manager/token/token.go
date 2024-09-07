package token

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/key"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	config            *config.Config
	keyLoader         crypto.KeyLoader
	accessTokenStore  *store.ExpiringStore[oauth2.AccessToken]
	refreshTokenStore *store.ExpiringStore[oauth2.RefreshToken]
}

var tokenManagerLock = &sync.Mutex{}
var tokenManagerSingleton *Manager

func GetTokenManagerInstance() *Manager {
	tokenManagerLock.Lock()
	defer tokenManagerLock.Unlock()
	if tokenManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		keyLoader := key.GetDefaultKeyLoaderInstance()
		accessTokenStore := store.NewDefaultTimedStore[oauth2.AccessToken]()
		refreshTokenStore := store.NewDefaultTimedStore[oauth2.RefreshToken]()
		tokenManagerSingleton = &Manager{
			config:            currentConfig,
			keyLoader:         keyLoader,
			accessTokenStore:  &accessTokenStore,
			refreshTokenStore: &refreshTokenStore,
		}
	}
	return tokenManagerSingleton
}

func (tokenManager *Manager) GetAccessToken(token string) (*oauth2.AccessToken, bool) {
	accessTokenStore := *tokenManager.accessTokenStore
	return accessTokenStore.Get(token)
}

func (tokenManager *Manager) RevokeAccessToken(accessToken *oauth2.AccessToken) {
	accessTokenStore := *tokenManager.accessTokenStore
	accessTokenStore.Delete(accessToken.Key)
}

func (tokenManager *Manager) GetRefreshToken(token string) (*oauth2.RefreshToken, bool) {
	refreshTokenStore := *tokenManager.refreshTokenStore
	return refreshTokenStore.Get(token)
}

func (tokenManager *Manager) RevokeRefreshToken(refreshToken *oauth2.RefreshToken) {
	refreshTokenStore := *tokenManager.refreshTokenStore
	refreshTokenStore.Delete(refreshToken.Key)
}

func (tokenManager *Manager) CreateAccessTokenResponse(r *http.Request, username string, client *config.Client, scopes []string, nonce string) oauth2.AccessTokenResponse {
	log.Debug("Creating new access token for %s, access TTL %d, refresh TTL %d", client.Id, client.GetAccessTTL(), client.GetRefreshTTL())

	requestData := internalHttp.NewRequestData(r)
	accessTokenStore := *tokenManager.accessTokenStore
	refreshTokenStore := *tokenManager.refreshTokenStore

	accessTokenDuration := time.Minute * time.Duration(client.GetAccessTTL())
	accessTokenKey := tokenManager.CreateAccessToken(r, username, client, accessTokenDuration)
	accessToken := &oauth2.AccessToken{
		Key:       accessTokenKey,
		TokenType: oauth2.TtBearer,
		Username:  username,
		ClientId:  client.Id,
		Scopes:    scopes,
	}

	accessTokenStore.SetWithDuration(accessToken.Key, accessToken, accessTokenDuration)

	accessTokenResponse := oauth2.AccessTokenResponse{
		AccessTokenValue: accessToken.Key,
		TokenType:        oauth2.TtBearer,
		ExpiresIn:        int(accessTokenDuration / time.Second),
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

		refreshTokenStore.SetWithDuration(refreshToken.Key, refreshToken, refreshTokenDuration)

		accessTokenResponse.RefreshTokenValue = refreshToken.Key
	}

	if client.Oidc && oidc.HasOidcScope(scopes) {
		user, userExists := tokenManager.config.GetUser(username)
		if userExists {
			accessTokenHash := tokenManager.CreateAccessTokenHash(client, accessToken.Key)
			accessTokenResponse.IdTokenValue = tokenManager.CreateIdToken(r, user.Username, client, scopes, nonce, accessTokenHash)
		}
	}

	return accessTokenResponse
}

func (tokenManager *Manager) CreateIdToken(r *http.Request, username string, client *config.Client, scopes []string, nonce string, atHash string) string {
	if client.Oidc && oidc.HasOidcScope(scopes) {
		requestData := internalHttp.NewRequestData(r)
		user, userExists := tokenManager.config.GetUser(username)
		if userExists {
			idTokenDuration := time.Minute * time.Duration(client.GetIdTTL())
			return tokenManager.generateIdToken(requestData, user, client, nonce, atHash, idTokenDuration)
		}
	}
	return ""
}

func (tokenManager *Manager) CreateAccessToken(r *http.Request, username string, client *config.Client, accessTokenDuration time.Duration) string {
	requestData := internalHttp.NewRequestData(r)
	return tokenManager.generateAccessToken(requestData, username, client, accessTokenDuration)
}

func (tokenManager *Manager) CreateAccessTokenHash(client *config.Client, accessTokenKey string) string {
	loader := tokenManager.keyLoader
	managedKey, keyExists := loader.LoadKeys(client)
	if !keyExists {
		return ""
	}

	return hashToken(managedKey.HashAlgorithm, accessTokenKey)
}

func (tokenManager *Manager) ValidateAccessToken(authorizationHeader string) (*config.User, *config.Client, []string, bool) {
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

func (tokenManager *Manager) generateIdToken(requestData *internalHttp.RequestData, user *config.User, client *config.Client, nonce string, atHash string, duration time.Duration) string {
	idToken := generateIdToken(requestData, tokenManager.config, user, client, nonce, atHash, duration)
	return tokenManager.generateJWTToken(client, idToken)
}

func (tokenManager *Manager) generateAccessToken(requestData *internalHttp.RequestData, username string, client *config.Client, duration time.Duration) string {
	tokenId := uuid.New()
	if client.OpaqueToken {
		return tokenManager.generateOpaqueAccessToken(tokenId.String())
	}
	accessToken := generateAccessToken(requestData, tokenManager.config, client, tokenId.String(), duration, username)
	return tokenManager.generateJWTToken(client, accessToken)
}

func (tokenManager *Manager) generateOpaqueAccessToken(tokenId string) string {
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
func (tokenManager *Manager) generateJWTToken(client *config.Client, token jwt.Token) string {

	loader := tokenManager.keyLoader
	managedKey, keyExists := loader.LoadKeys(client)

	if !keyExists {
		options := loader.GetServerKey()
		tokenString, tokenError := jwt.Sign(token, options)
		if tokenError != nil {
			system.Error(tokenError)
		}

		return string(tokenString)
	} else {
		currentKey := *managedKey.Key

		options := jwt.WithKey(currentKey.Algorithm(), currentKey)

		tokenString, tokenError := jwt.Sign(token, options)
		if tokenError != nil {
			system.Error(tokenError)
		}

		return string(tokenString)
	}

}

func generateIdToken(requestData *internalHttp.RequestData, config *config.Config, user *config.User, client *config.Client, nonce string, atHash string, duration time.Duration) jwt.Token {
	tokenId := uuid.NewString()
	builder := jwt.NewBuilder().
		Expiration(time.Now().Add(duration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                  // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(config.GetIssuer(requestData))

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(user.Username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	audience := append(client.GetAudience(), client.Id)
	builder.Audience(audience)

	addStringClaim(builder, oidc.ClaimAuthorizedParty, client.Id)
	addStringClaim(builder, oidc.ClaimAtHash, atHash)
	addStringClaim(builder, oidc.ClaimNonce, nonce)
	roles := user.GetRoles(client.Id)
	if len(roles) != 0 {
		builder.Claim(client.GetRolesClaim(), roles)
	}

	token, builderError := builder.Build()

	if builderError != nil {
		system.Error(builderError)
	}

	return token
}

func generateAccessToken(requestData *internalHttp.RequestData, config *config.Config, client *config.Client, tokenId string, duration time.Duration, username string) jwt.Token {
	builder := jwt.NewBuilder().
		Expiration(time.Now().Add(duration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                  // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	for claimIndex := range client.Claims {
		claim := client.Claims[claimIndex]
		addStringClaim(builder, claim.Name, claim.Value)
	}

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(config.GetIssuer(requestData))

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	builder.Audience(client.GetAudience())

	token, builderError := builder.Build()

	if builderError != nil {
		system.Error(builderError)
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

func addStringClaim(builder *jwt.Builder, claimName string, claimValue string) {
	if claimValue != "" {
		builder.Claim(claimName, claimValue)
	}
}

func hashToken(algorithm crypto.HashAlgorithm, token string) string {
	tokenBytes := []byte(token)

	var hashedAccessKey []byte
	hashAlgorithm := algorithm
	switch hashAlgorithm {
	case crypto.SHA256:
		hashed := sha256.Sum256(tokenBytes)
		hashedAccessKey = hashed[:]
	case crypto.SHA512:
		hashed := sha512.Sum384(tokenBytes)
		hashedAccessKey = hashed[:]
	case crypto.SHA384:
		hashed := sha512.Sum512(tokenBytes)
		hashedAccessKey = hashed[:]
	default:
		hashedAccessKey = make([]byte, 0)
	}

	if len(hashedAccessKey) >= 2 {
		midpoint := len(hashedAccessKey) / 2
		firstHalf := hashedAccessKey[:midpoint]
		return base64.RawURLEncoding.EncodeToString(firstHalf)
	}

	return ""
}
