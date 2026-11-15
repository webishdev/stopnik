package token

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
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
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"
)

type clientStores struct {
	accessTokenStore       *store.ExpiringStore[oauth2.AccessToken]
	refreshTokenStore      *store.ExpiringStore[oauth2.RefreshToken]
	usedRefreshTokenStore  *store.ExpiringStore[usedRefreshToken]
	authorizationCodeStore *store.ExpiringStore[string]
}

// usedRefreshToken remembers a refresh token after it was used, to detect a reuse.
type usedRefreshToken struct {
	GrantId  string
	ClientId string
	Username string
}

type ValidAccessToken struct {
	User            *config.User
	Client          *config.Client
	Scopes          []string
	RequestedClaims *oidc.ClaimsParameter
}

type Manager struct {
	config          *config.Config
	keyLoader       crypto.KeyLoader
	clientStores    map[string]*clientStores
	clientStoresMux *sync.RWMutex
}

type IdTokenInput struct {
	Username        string
	User            *config.User
	Client          *config.Client
	RequestedClaims *oidc.ClaimsParameter
	Scopes          []string
	Nonce           string
	AtHash          string
	AuthTime        time.Time
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
			config:          currentConfig,
			keyLoader:       keyLoader,
			clientStores:    make(map[string]*clientStores),
			clientStoresMux: &sync.RWMutex{},
		}
	}
	return tokenManagerSingleton
}

// getClientStores returns the stores for the given client, they are created on first access
// because clients can be added by the dynamic configuration at any time.
func (tokenManager *Manager) getClientStores(client *config.Client) *clientStores {
	tokenManager.clientStoresMux.RLock()
	stores, exists := tokenManager.clientStores[client.Id]
	tokenManager.clientStoresMux.RUnlock()
	if exists {
		return stores
	}

	tokenManager.clientStoresMux.Lock()
	defer tokenManager.clientStoresMux.Unlock()
	if stores, exists = tokenManager.clientStores[client.Id]; exists {
		return stores
	}

	accessStoreTime := time.Minute*time.Duration(client.GetAccessTTL()) + time.Minute*time.Duration(1)
	refreshStoreTime := time.Minute*time.Duration(client.GetRefreshTTL()) + time.Minute*time.Duration(1)
	accessTokenStore := store.NewTimedStore[oauth2.AccessToken](accessStoreTime)
	refreshTokenStore := store.NewTimedStore[oauth2.RefreshToken](refreshStoreTime)
	usedRefreshTokenStore := store.NewTimedStore[usedRefreshToken](refreshStoreTime)
	authorizationCodeStore := store.NewDefaultTimedStore[string]()
	stores = &clientStores{
		accessTokenStore:       &accessTokenStore,
		refreshTokenStore:      &refreshTokenStore,
		usedRefreshTokenStore:  &usedRefreshTokenStore,
		authorizationCodeStore: &authorizationCodeStore,
	}
	tokenManager.clientStores[client.Id] = stores
	return stores
}

// allClientStores returns the stores of all clients which were used so far.
func (tokenManager *Manager) allClientStores() []*clientStores {
	tokenManager.clientStoresMux.RLock()
	defer tokenManager.clientStoresMux.RUnlock()
	result := make([]*clientStores, 0, len(tokenManager.clientStores))
	for _, stores := range tokenManager.clientStores {
		result = append(result, stores)
	}
	return result
}

// TokenCount returns the number of stored access and refresh tokens of the client with the given id.
func (tokenManager *Manager) TokenCount(clientId string) (int, int) {
	tokenManager.clientStoresMux.RLock()
	stores, exists := tokenManager.clientStores[clientId]
	tokenManager.clientStoresMux.RUnlock()
	if !exists {
		return 0, 0
	}
	accessTokenStore := *stores.accessTokenStore
	refreshTokenStore := *stores.refreshTokenStore
	return accessTokenStore.Len(), refreshTokenStore.Len()
}

func (tokenManager *Manager) GetAccessToken(token string) (*oauth2.AccessToken, bool) {
	for _, currentClientStores := range tokenManager.allClientStores() {
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
		for _, currentClientStores := range tokenManager.allClientStores() {
			accessTokenStore := *currentClientStores.accessTokenStore
			accessTokenStore.Delete(accessToken.Key)
		}
	}
}

func (tokenManager *Manager) GetRefreshToken(token string) (*oauth2.RefreshToken, bool) {
	for _, currentClientStores := range tokenManager.allClientStores() {
		refreshTokenStore := *currentClientStores.refreshTokenStore
		refreshToken, refreshTokenExists := refreshTokenStore.Get(token)
		if refreshTokenExists {
			return refreshToken, true
		}
	}
	return nil, false
}

// TakeRefreshToken returns and removes the refresh token, so it can only be used once.
// https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
// A used refresh token is remembered, when it is presented again, either the client or an attacker holds a stolen token,
// so all tokens of its grant are revoked.
func (tokenManager *Manager) TakeRefreshToken(token string) (*oauth2.RefreshToken, bool) {
	for _, currentClientStores := range tokenManager.allClientStores() {
		refreshTokenStore := *currentClientStores.refreshTokenStore
		refreshToken, refreshTokenExists := refreshTokenStore.Take(token)
		if refreshTokenExists {
			usedRefreshTokenStore := *currentClientStores.usedRefreshTokenStore
			usedRefreshTokenStore.Set(token, &usedRefreshToken{
				GrantId:  refreshToken.GrantId,
				ClientId: refreshToken.ClientId,
				Username: refreshToken.Username,
			})
			return refreshToken, true
		}
	}

	for _, currentClientStores := range tokenManager.allClientStores() {
		usedRefreshTokenStore := *currentClientStores.usedRefreshTokenStore
		usedToken, usedTokenExists := usedRefreshTokenStore.Get(token)
		if usedTokenExists {
			log.Warn("Reuse of refresh token detected for client %s and user %s, revoking all tokens of the grant", usedToken.ClientId, usedToken.Username)
			tokenManager.RevokeGrant(usedToken.GrantId)
			return nil, false
		}
	}
	return nil, false
}

func (tokenManager *Manager) RevokeRefreshToken(refreshToken *oauth2.RefreshToken) {
	if refreshToken != nil {
		for _, currentClientStores := range tokenManager.allClientStores() {
			refreshTokenStore := *currentClientStores.refreshTokenStore
			refreshTokenStore.Delete(refreshToken.Key)
		}
	}
}

// RevokeGrant revokes all access and refresh tokens, which were issued for the grant with the given grantId.
func (tokenManager *Manager) RevokeGrant(grantId string) {
	if grantId == "" {
		return
	}
	for _, currentClientStores := range tokenManager.allClientStores() {
		accessTokenStore := *currentClientStores.accessTokenStore
		for _, accessToken := range accessTokenStore.GetValues() {
			if accessToken.GrantId == grantId {
				accessTokenStore.Delete(accessToken.Key)
			}
		}
		refreshTokenStore := *currentClientStores.refreshTokenStore
		for _, refreshToken := range refreshTokenStore.GetValues() {
			if refreshToken.GrantId == grantId {
				refreshTokenStore.Delete(refreshToken.Key)
			}
		}
	}
}

// RevokeAccessTokenByAuthorizationCode revokes all access and refresh tokens, which were issued for the given authorization code.
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
// If an authorization code is used more than once, all tokens previously issued based on that code should be revoked.
func (tokenManager *Manager) RevokeAccessTokenByAuthorizationCode(authorizationCode string) {
	for _, currentClientStores := range tokenManager.allClientStores() {
		authorizationCodeStore := *currentClientStores.authorizationCodeStore
		grantId, grantIdExists := authorizationCodeStore.Get(authorizationCode)
		if grantIdExists {
			tokenManager.RevokeGrant(*grantId)
		}
	}
}

// CreateAccessTokenResponse creates and stores new tokens for the given client, including a refresh token when enabled.
// The tokens become part of the grant with the given grantId, an empty grantId starts a new grant.
func (tokenManager *Manager) CreateAccessTokenResponse(r *http.Request, username string, client *config.Client, authTime *time.Time, scopes []string, requestedClaims *oidc.ClaimsParameter, nonce string, authorizationCode string, grantId string) oauth2.AccessTokenResponse {
	return tokenManager.createAccessTokenResponse(r, username, client, authTime, scopes, requestedClaims, nonce, authorizationCode, grantId, true)
}

// CreateAccessTokenResponseWithoutRefreshToken creates and stores new tokens for the given client, but never a refresh token.
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
// Used for the implicit and the client credentials grant, which must not issue refresh tokens.
func (tokenManager *Manager) CreateAccessTokenResponseWithoutRefreshToken(r *http.Request, username string, client *config.Client, authTime *time.Time, scopes []string, requestedClaims *oidc.ClaimsParameter, nonce string) oauth2.AccessTokenResponse {
	return tokenManager.createAccessTokenResponse(r, username, client, authTime, scopes, requestedClaims, nonce, "", "", false)
}

// CreateIdToken creates an ID token without creating an access token, so the ID token contains no at_hash.
// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
// Used for response_type=id_token, returns an empty string when no ID token can be created.
func (tokenManager *Manager) CreateIdToken(r *http.Request, username string, client *config.Client, authTime *time.Time, scopes []string, requestedClaims *oidc.ClaimsParameter, nonce string) string {
	user, userExists := tokenManager.config.GetUser(username)
	if !userExists {
		return ""
	}
	idTokenInput := IdTokenInput{
		Username:        user.Username,
		User:            user,
		Client:          client,
		Scopes:          scopes,
		Nonce:           nonce,
		RequestedClaims: requestedClaims,
	}
	if authTime != nil {
		idTokenInput.AuthTime = *authTime
	}
	return tokenManager.createIdToken(r, idTokenInput)
}

func (tokenManager *Manager) createAccessTokenResponse(r *http.Request, username string, client *config.Client, authTime *time.Time, scopes []string, requestedClaims *oidc.ClaimsParameter, nonce string, authorizationCode string, grantId string, issueRefreshToken bool) oauth2.AccessTokenResponse {
	log.Debug("Creating new access token for %s, access TTL %d, refresh TTL %d", client.Id, client.GetAccessTTL(), client.GetRefreshTTL())

	if grantId == "" {
		grantId = uuid.New().String()
	}
	issuedAt := time.Now()

	currentClientStores := tokenManager.getClientStores(client)
	accessTokenStore := *currentClientStores.accessTokenStore
	refreshTokenStore := *currentClientStores.refreshTokenStore
	authorizationCodeStore := *currentClientStores.authorizationCodeStore

	accessTokenDuration := time.Minute * time.Duration(client.GetAccessTTL())
	accessTokenKey := tokenManager.CreateAccessToken(r, username, client, scopes, accessTokenDuration)
	accessToken := &oauth2.AccessToken{
		Key:       accessTokenKey,
		TokenType: oauth2.TtBearer,
		Username:  username,
		ClientId:  client.Id,
		GrantId:   grantId,
		Scopes:    scopes,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(accessTokenDuration),
	}
	if client.Oidc && requestedClaims != nil {
		accessToken.RequestedClaims = requestedClaims
	}

	accessTokenStore.SetWithDuration(accessToken.Key, accessToken, accessTokenDuration)

	accessTokenResponse := oauth2.AccessTokenResponse{
		AccessTokenValue: accessToken.Key,
		TokenType:        oauth2.TtBearer,
		ExpiresIn:        int(accessTokenDuration / time.Second),
	}

	refreshTokenEnabled := (!client.Oidc && client.GetRefreshTTL() > 0) || (client.Oidc && oidc.HasOfflineAccessScope(scopes) && client.GetRefreshTTL() > 0)
	if issueRefreshToken && refreshTokenEnabled {
		refreshTokenDuration := time.Minute * time.Duration(client.GetRefreshTTL())
		refreshTokenKey := tokenManager.generateRefreshToken(username, client, scopes, refreshTokenDuration)
		refreshToken := &oauth2.RefreshToken{
			Key:       refreshTokenKey,
			Username:  username,
			ClientId:  client.Id,
			GrantId:   grantId,
			Scopes:    scopes,
			IssuedAt:  issuedAt,
			ExpiresAt: issuedAt.Add(refreshTokenDuration),
		}

		if authTime != nil {
			refreshToken.AuthTime = *authTime
		}
		if client.Oidc && requestedClaims != nil {
			refreshToken.RequestedClaims = requestedClaims
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
			if requestedClaims != nil {
				idTokenInput.RequestedClaims = requestedClaims
			}
			if authTime != nil {
				idTokenInput.AuthTime = *authTime
			}
			accessTokenResponse.IdTokenValue = tokenManager.createIdToken(r, idTokenInput)
		}
	}

	if authorizationCode != "" {
		authorizationCodeStore.Set(authorizationCode, &grantId)
	}

	return accessTokenResponse
}

func (tokenManager *Manager) createIdToken(r *http.Request, idTokenInput IdTokenInput) string {
	if idTokenInput.Client.Oidc && oidc.HasOidcScope(idTokenInput.Scopes) {
		return tokenManager.generateIdToken(idTokenInput)
	}
	return ""
}

func (tokenManager *Manager) CreateAccessToken(r *http.Request, username string, client *config.Client, scopes []string, accessTokenDuration time.Duration) string {
	return tokenManager.generateAccessToken(username, client, scopes, accessTokenDuration)
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
func (tokenManager *Manager) ValidateAccessTokenRequest(r *http.Request) (*ValidAccessToken, bool) {
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

func (tokenManager *Manager) validateAccessTokenHeader(authorizationHeader string) (*ValidAccessToken, bool) {
	headerValue := getAuthorizationHeaderValue(authorizationHeader)
	if headerValue == nil {
		return &ValidAccessToken{}, false
	}
	return tokenManager.validateAccessToken(*headerValue)
}

func (tokenManager *Manager) validateAccessToken(accessTokenValue string) (*ValidAccessToken, bool) {
	log.Debug("Validating access token")
	accessToken, accessTokenExists := tokenManager.GetAccessToken(accessTokenValue)
	if !accessTokenExists {
		return &ValidAccessToken{}, false
	}

	username := accessToken.Username
	user, userExists := tokenManager.config.GetUser(username)

	if !userExists {
		return &ValidAccessToken{}, false
	}

	clientId := accessToken.ClientId
	client, clientExists := tokenManager.config.GetClient(clientId)

	if !clientExists {
		return &ValidAccessToken{}, false
	}

	validAccessToken := &ValidAccessToken{
		User:            user,
		Client:          client,
		Scopes:          accessToken.Scopes,
		RequestedClaims: accessToken.RequestedClaims,
	}

	return validAccessToken, true
}

func (tokenManager *Manager) generateIdToken(idTokenInput IdTokenInput) string {
	client := idTokenInput.Client
	idToken := generateIdToken(tokenManager.config, idTokenInput)
	return tokenManager.generateJWTToken(client, idToken)
}

func (tokenManager *Manager) generateAccessToken(username string, client *config.Client, scopes []string, duration time.Duration) string {
	tokenId := uuid.New()
	if client.OpaqueToken {
		return tokenManager.generateOpaqueToken(tokenId.String())
	}
	accessToken := generateAccessToken(tokenManager.config, client, tokenId.String(), duration, username, scopes)
	return tokenManager.generateJWTToken(client, accessToken)
}

func (tokenManager *Manager) generateRefreshToken(username string, client *config.Client, scopes []string, duration time.Duration) string {
	tokenId := uuid.New()
	if client.OpaqueToken {
		return tokenManager.generateOpaqueToken(tokenId.String())
	}
	accessToken := generateRefreshToken(tokenManager.config, client, tokenId.String(), duration, username, scopes)
	return tokenManager.generateJWTToken(client, accessToken)
}

func (tokenManager *Manager) generateOpaqueToken(tokenId string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(tokenId))
}

// generateJWTToken signs the token with the key of the client or the server key.
// A server key always exists, tokens are never signed with the server secret.
func (tokenManager *Manager) generateJWTToken(client *config.Client, token jwt.Token) string {
	loader := tokenManager.keyLoader
	managedKey, keyExists := loader.LoadKeys(client)
	if !keyExists {
		system.CriticalError(fmt.Errorf("no key found to sign token for client %s", client.Id))
		return ""
	}

	currentKey := *managedKey.Key

	algorithm, _ := currentKey.Algorithm()
	options := jwt.WithKey(algorithm, currentKey)

	tokenString, tokenError := jwt.Sign(token, options)
	if tokenError != nil {
		system.Error(tokenError)
	}

	return string(tokenString)
}

func generateIdToken(config *config.Config, idTokenInput IdTokenInput) jwt.Token {
	user := idTokenInput.User
	client := idTokenInput.Client
	atHash := idTokenInput.AtHash
	nonce := idTokenInput.Nonce
	authTime := idTokenInput.AuthTime
	scopes := idTokenInput.Scopes
	idTokenDuration := time.Minute * time.Duration(idTokenInput.Client.GetIdTTL())
	tokenId := uuid.New().String()
	builder := openid.NewBuilder().
		Expiration(time.Now().Add(idTokenDuration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                         // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(config.GetIssuer())

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(user.Username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	audience := append(client.GetAudience(), client.Id)
	builder.Audience(audience)

	addStringClaimOpenId(builder, oidc.ClaimAuthorizedParty, client.Id)
	addStringClaimOpenId(builder, oidc.ClaimAtHash, atHash)
	addStringClaimOpenId(builder, oidc.ClaimNonce, nonce)
	builder.Claim(oidc.ClaimAuthTime, authTime.Unix())

	if slices.Contains(scopes, oidc.ScopeProfile) {
		builder.Name(user.GetName())
		builder.GivenName(user.UserProfile.GivenName)
		builder.MiddleName(user.UserProfile.MiddleName)
		builder.FamilyName(user.UserProfile.FamilyName)
		builder.Nickname(user.UserProfile.Nickname)
		builder.PreferredUsername(user.GetPreferredUsername())
		builder.Gender(user.UserProfile.Gender)
		builder.Zoneinfo(user.UserProfile.ZoneInfo)
		builder.Locale(user.UserProfile.Locale)
		builder.Website(user.UserProfile.Website)
		builder.Profile(user.UserProfile.Profile)
		builder.Picture(user.UserProfile.Picture)
		if user.UserProfile.BirthDate != "" {
			builder.Claim(openid.BirthdateKey, user.UserProfile.BirthDate)
		}

	}

	if slices.Contains(scopes, oidc.ScopeAddress) {
		address := openid.NewAddress()
		if user.UserInformation.Address != nil {
			addStringAddressClaim(address, openid.AddressFormattedKey, user.GetFormattedAddress())
			addStringAddressClaim(address, openid.AddressStreetAddressKey, user.UserInformation.Address.Street)
			addStringAddressClaim(address, openid.AddressLocalityKey, user.UserInformation.Address.City)
			addStringAddressClaim(address, openid.AddressPostalCodeKey, user.UserInformation.Address.PostalCode)
			addStringAddressClaim(address, openid.AddressRegionKey, user.UserInformation.Address.Region)
			addStringAddressClaim(address, openid.AddressCountryKey, user.UserInformation.Address.Country)
		}
		builder.Address(address)
	}

	//if slices.Contains(scopes, oidc.ScopeEmail) {
	//	builder.Email(user.UserInformation.Email)
	//	builder.EmailVerified(user.UserInformation.EmailVerified)
	//}

	if slices.Contains(scopes, oidc.ScopePhone) {
		builder.PhoneNumber(user.UserInformation.PhoneNumber)
		builder.PhoneNumberVerified(user.UserInformation.PhoneVerified)
	}

	claims := config.GetClaims(user.Username, client.Id, scopes)
	for _, claim := range claims {
		currentClaim := *claim
		name := currentClaim.GetName()
		values := currentClaim.GetValues()
		builder.Claim(name, values)
	}

	token, builderError := builder.Build()

	if builderError != nil {
		system.Error(builderError)
	}

	return token
}

func generateAccessToken(config *config.Config, client *config.Client, tokenId string, duration time.Duration, username string, scopes []string) jwt.Token {
	builder := jwt.NewBuilder().
		Expiration(time.Now().Add(duration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                  // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(config.GetIssuer())

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2
	builder.Subject(username)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	builder.Audience(client.GetAudience())

	claims := config.GetClaims(username, client.Id, scopes)
	for _, claim := range claims {
		currentClaim := *claim
		name := currentClaim.GetName()
		values := currentClaim.GetValues()
		builder.Claim(name, values)
	}

	token, builderError := builder.Build()

	if builderError != nil {
		system.Error(builderError)
	}

	return token
}

func generateRefreshToken(config *config.Config, client *config.Client, tokenId string, duration time.Duration, username string, scopes []string) jwt.Token {
	builder := jwt.NewBuilder().
		Expiration(time.Now().Add(duration)). // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
		IssuedAt(time.Now())                  // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
	builder.JwtID(tokenId)

	// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1
	builder.Issuer(config.GetIssuer())

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

func addStringClaimOpenId(builder *openid.Builder, claimName string, claimValue string) {
	if claimValue != "" {
		builder.Claim(claimName, claimValue)
	}
}

func addStringAddressClaim(builder *openid.AddressClaim, claimName string, claimValue string) {
	if claimValue != "" {
		err := builder.Set(claimName, claimValue)
		if err != nil {
			system.Error(err)
		}
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
	case crypto.SHA384:
		hashed := sha512.Sum384(tokenBytes)
		hashedAccessKey = hashed[:]
	case crypto.SHA512:
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
