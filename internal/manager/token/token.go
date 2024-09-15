package token

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
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

type clientStores struct {
	accessTokenStore       *store.ExpiringStore[oauth2.AccessToken]
	refreshTokenStore      *store.ExpiringStore[oauth2.RefreshToken]
	authorizationCodeStore *store.ExpiringStore[string]
}

type Manager struct {
	config       *config.Config
	keyLoader    crypto.KeyLoader
	clientStores map[string]*clientStores
}

type IdTokenInput struct {
	Username string
	User     *config.User
	Client   *config.Client
	Scopes   []string
	Nonce    string
	AtHash   string
	AuthTime time.Time
}

var tokenManagerLock = &sync.Mutex{}
var tokenManagerSingleton *Manager

func GetTokenManagerInstance() *Manager {
	tokenManagerLock.Lock()
	defer tokenManagerLock.Unlock()
	if tokenManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		keyLoader := key.GetDefaultKeyLoaderInstance()
		tokenManagerSingleton = &Manager{
			config:       currentConfig,
			keyLoader:    keyLoader,
			clientStores: make(map[string]*clientStores),
		}

		for _, client := range currentConfig.Clients {
			accessStoreTime := time.Minute*time.Duration(client.GetAccessTTL()) + time.Minute*time.Duration(1)
			refreshStoreTime := time.Minute*time.Duration(client.GetRefreshTTL()) + time.Minute*time.Duration(1)
			accessTokenStore := store.NewTimedStore[oauth2.AccessToken](accessStoreTime)
			refreshTokenStore := store.NewTimedStore[oauth2.RefreshToken](refreshStoreTime)
			authorizationCodeStore := store.NewDefaultTimedStore[string]()
			stores := &clientStores{
				accessTokenStore:       &accessTokenStore,
				refreshTokenStore:      &refreshTokenStore,
				authorizationCodeStore: &authorizationCodeStore,
			}
			tokenManagerSingleton.clientStores[client.Id] = stores
		}
	}
	return tokenManagerSingleton
}

func (tokenManager *Manager) GetAccessToken(token string) (*oauth2.AccessToken, bool) {
	for _, currentClientStores := range tokenManager.clientStores {
		accessTokenStore := *currentClientStores.accessTokenStore
		accessToken, accessTokenExists := accessTokenStore.Get(token)
		if accessTokenExists {
			return accessToken, true
		}
	}
	return nil, false
}

func (tokenManager *Manager) RevokeAccessToken(accessToken *oauth2.AccessToken) {
	if accessToken != nil {
		for _, currentClientStores := range tokenManager.clientStores {
			accessTokenStore := *currentClientStores.accessTokenStore
			accessTokenStore.Delete(accessToken.Key)
		}
	}
}

func (tokenManager *Manager) GetRefreshToken(token string) (*oauth2.RefreshToken, bool) {
	for _, currentClientStores := range tokenManager.clientStores {
		refreshTokenStore := *currentClientStores.refreshTokenStore
		refreshToken, refreshTokenExists := refreshTokenStore.Get(token)
		if refreshTokenExists {
			return refreshToken, true
		}
	}
	return nil, false
}

func (tokenManager *Manager) RevokeRefreshToken(refreshToken *oauth2.RefreshToken) {
	if refreshToken != nil {
		for _, currentClientStores := range tokenManager.clientStores {
			refreshTokenStore := *currentClientStores.refreshTokenStore
			refreshTokenStore.Delete(refreshToken.Key)
		}
	}
}

func (tokenManager *Manager) RevokeAccessTokenByAuthorizationCode(authorizationCode string) {
	for _, currentClientStores := range tokenManager.clientStores {
		authorizationCodeStore := *currentClientStores.authorizationCodeStore
		accessTokenKey, accessTokenKeyExists := authorizationCodeStore.Get(authorizationCode)
		if accessTokenKeyExists {
			accessToken, accessTokenExists := tokenManager.GetAccessToken(*accessTokenKey)
			if accessTokenExists {
				tokenManager.RevokeAccessToken(accessToken)
			}
		}
	}
}

func (tokenManager *Manager) CreateAccessTokenResponse(r *http.Request, username string, client *config.Client, authTime *time.Time, scopes []string, nonce string, authorizationCode string) oauth2.AccessTokenResponse {
	log.Debug("Creating new access token for %s, access TTL %d, refresh TTL %d", client.Id, client.GetAccessTTL(), client.GetRefreshTTL())

	requestData := internalHttp.NewRequestData(r)
	accessTokenStore := *tokenManager.clientStores[client.Id].accessTokenStore
	refreshTokenStore := *tokenManager.clientStores[client.Id].refreshTokenStore
	authorizationCodeStore := *tokenManager.clientStores[client.Id].authorizationCodeStore

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

	if (!client.Oidc && client.GetRefreshTTL() > 0) || (client.Oidc && oidc.HasOfflineAccessScope(scopes) && client.GetRefreshTTL() > 0) {
		refreshTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
		refreshTokenKey := tokenManager.generateAccessToken(requestData, username, client, refreshTokenDuration)
		refreshToken := &oauth2.RefreshToken{
			Key:      refreshTokenKey,
			Username: username,
			ClientId: client.Id,
			Scopes:   scopes,
		}

		if authTime != nil {
			refreshToken.AuthTime = *authTime
		}

		refreshTokenStore.SetWithDuration(refreshToken.Key, refreshToken, refreshTokenDuration)

		accessTokenResponse.RefreshTokenValue = refreshToken.Key
	}

	if client.Oidc && oidc.HasOidcScope(scopes) {
		user, userExists := tokenManager.config.GetUser(username)
		if userExists {
			accessTokenHash := tokenManager.CreateAccessTokenHash(client, accessToken.Key)
			idTokenInput := IdTokenInput{
				Username: user.Username,
				User:     user,
				Client:   client,
				Scopes:   scopes,
				Nonce:    nonce,
				AtHash:   accessTokenHash,
			}
			if authTime != nil {
				idTokenInput.AuthTime = *authTime
			}
			accessTokenResponse.IdTokenValue = tokenManager.createIdToken(r, idTokenInput)
		}
	}

	if authorizationCode != "" {
		authorizationCodeStore.Set(authorizationCode, &accessToken.Key)
	}

	return accessTokenResponse
}

func (tokenManager *Manager) createIdToken(r *http.Request, idTokenInput IdTokenInput) string {
	if idTokenInput.Client.Oidc && oidc.HasOidcScope(idTokenInput.Scopes) {
		requestData := internalHttp.NewRequestData(r)
		return tokenManager.generateIdToken(requestData, idTokenInput)
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

// ValidateAccessTokenRequest  implements https://datatracker.ietf.org/doc/html/rfc6750#section-2
func (tokenManager *Manager) ValidateAccessTokenRequest(r *http.Request) (*config.User, *config.Client, []string, bool) {
	// https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
	log.Debug("Checking authorization request header field")
	authorizationHeader := r.Header.Get(internalHttp.Authorization)
	if authorizationHeader == "" {
		// https://datatracker.ietf.org/doc/html/rfc6750#section-2.2
		log.Debug("Checking form-encoded body parameter")
		accessTokenValue := r.PostFormValue("access_token")
		return tokenManager.validateAccessToken(accessTokenValue)
	} else {
		return tokenManager.validateAccessTokenHeader(authorizationHeader)
	}
}

func (tokenManager *Manager) validateAccessTokenHeader(authorizationHeader string) (*config.User, *config.Client, []string, bool) {
	headerValue := getAuthorizationHeaderValue(authorizationHeader)
	if headerValue == nil {
		return nil, nil, []string{}, false
	}
	return tokenManager.validateAccessToken(*headerValue)
}

func (tokenManager *Manager) validateAccessToken(accessTokenValue string) (*config.User, *config.Client, []string, bool) {
	log.Debug("Validating access token")
	accessToken, accessTokenExists := tokenManager.GetAccessToken(accessTokenValue)
	if !accessTokenExists {
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

func (tokenManager *Manager) generateIdToken(requestData *internalHttp.RequestData, idTokenInput IdTokenInput) string {
	client := idTokenInput.Client
	idToken := generateIdToken(requestData, tokenManager.config, idTokenInput)
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

func generateIdToken(requestData *internalHttp.RequestData, config *config.Config, idTokenInput IdTokenInput) jwt.Token {
	user := idTokenInput.User
	client := idTokenInput.Client
	atHash := idTokenInput.AtHash
	nonce := idTokenInput.Nonce
	authTime := idTokenInput.AuthTime
	idTokenDuration := time.Minute * time.Duration(idTokenInput.Client.GetIdTTL())
	tokenId := uuid.NewString()
	builder := openid.NewBuilder().
		Expiration(time.Now().Add(idTokenDuration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                         // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(config.GetIssuer(requestData))

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(user.Username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	audience := append(client.GetAudience(), client.Id)
	builder.Audience(audience)

	addStringClaimOpenId(builder, oidc.ClaimAuthorizedParty, client.Id)
	addStringClaimOpenId(builder, oidc.ClaimAtHash, atHash)
	addStringClaimOpenId(builder, oidc.ClaimNonce, nonce)
	builder.Claim(oidc.ClaimAuthTime, authTime.Unix())
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

func addStringClaimOpenId(builder *openid.Builder, claimName string, claimValue string) {
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
