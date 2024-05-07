package auth

import (
	"fmt"
	"net/http"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"stopnik/internal/store"
	"stopnik/log"
	"strings"
)

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
