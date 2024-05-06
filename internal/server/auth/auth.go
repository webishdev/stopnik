package auth

import (
	"fmt"
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/crypto"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"stopnik/internal/store"
	"stopnik/log"
	"strings"
)

func UserBasicAuth(config *config.Config, r *http.Request) (*config.User, bool) {
	if r.Method == http.MethodPost {

		username := r.PostFormValue("stopnik_username")
		password := r.PostFormValue("stopnik_password")

		// When login invalid
		// https://en.wikipedia.org/wiki/Post/Redirect/Get
		// redirect with Status 303
		// When login valid
		user, exists := config.GetUser(username)
		if !exists {
			return nil, false
		}

		passwordHash := crypto.Sha512Hash(password)
		if passwordHash != user.Password {
			return nil, false
		}

		return user, true
	}
	return nil, false
}

func ClientCredentials(config *config.Config, r *http.Request) (*config.Client, bool) {
	log.Debug("Validating client credentials")
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
	clientId, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Check fallback
		clientId = r.PostFormValue(oauth2.ParameterClientId)
		clientSecret = r.PostFormValue(oauth2.ParameterClientSecret)
	}

	if clientId == "" || clientSecret == "" {
		return nil, false
	}

	client, clientExists := config.GetClient(clientId)
	if !clientExists {
		return nil, false
	}

	secretHash := crypto.Sha512Hash(clientSecret)

	if secretHash != client.Secret {
		return nil, false
	}

	return client, true
}

func AccessToken(config *config.Config, accessTokenStore *store.Store[oauth2.AccessToken], r *http.Request) (*config.User, []string, bool) {
	log.Debug("Validating access token")
	authorization := r.Header.Get(internalHttp.Authorization)
	if authorization == "" || !strings.Contains(authorization, internalHttp.AuthBearer) {
		return nil, []string{}, false
	}

	replaceBearer := fmt.Sprintf("%s ", internalHttp.AuthBearer)
	authorizationHeader := strings.Replace(authorization, replaceBearer, "", 1)
	accessToken, authorizationHeaderExists := accessTokenStore.Get(authorizationHeader)
	if !authorizationHeaderExists {
		return nil, []string{}, false
	}

	username := accessToken.Username
	user, userExists := config.GetUser(username)

	if !userExists {
		return nil, []string{}, false
	}

	return user, accessToken.Scopes, true
}
