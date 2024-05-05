package auth

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/internal/oauth2"
	oauth2parameters "stopnik/internal/oauth2/parameters"
	"stopnik/internal/store"
	"stopnik/log"
	"strings"
)

func ClientCredentials(config *config.Config, r *http.Request) (*config.Client, bool) {
	log.Debug("Validating client credentials")
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
	clientId, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Check fallback
		clientId = r.PostFormValue(oauth2parameters.ClientId)
		clientSecret = r.PostFormValue(oauth2parameters.ClientSecret)
	}

	if clientId == "" || clientSecret == "" {
		return nil, false
	}

	client, clientExists := config.GetClient(clientId)
	if !clientExists {
		return nil, false
	}

	secretHash := fmt.Sprintf("%x", sha512.Sum512([]byte(clientSecret)))

	if secretHash != client.Secret {
		return nil, false
	}

	return client, true
}

func AccessToken(config *config.Config, accessTokenStore *store.Store[oauth2.AccessToken], r *http.Request) (*config.User, []string, bool) {
	log.Debug("Validating access token")
	authorization := r.Header.Get(httpHeader.Authorization)
	if authorization == "" || !strings.Contains(authorization, httpHeader.AuthBearer) {
		return nil, []string{}, false
	}

	replaceBearer := fmt.Sprintf("%s ", httpHeader.AuthBearer)
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
