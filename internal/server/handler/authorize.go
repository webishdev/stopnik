package handler

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/internal/oauth2"
	pkceParameters "stopnik/internal/pkce"
	"stopnik/internal/store"
	"stopnik/internal/template"
	"stopnik/log"
	"strings"
)

type AuthorizeHandler struct {
	config            *config.Config
	authSessionStore  *store.Store[store.AuthSession]
	accessTokenStore  *store.Store[oauth2.AccessToken]
	refreshTokenStore *store.Store[oauth2.RefreshToken]
}

func CreateAuthorizeHandler(config *config.Config, authSessionStore *store.Store[store.AuthSession], tokenStores *store.TokenStores[oauth2.AccessToken, oauth2.RefreshToken]) *AuthorizeHandler {
	return &AuthorizeHandler{
		config:            config,
		authSessionStore:  authSessionStore,
		accessTokenStore:  tokenStores.AccessTokenStore,
		refreshTokenStore: tokenStores.RefreshTokenStore,
	}
}

func (handler *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		clientId := r.URL.Query().Get(oauth2.ParameterClientId)
		client, exists := handler.config.GetClient(clientId)
		if !exists {
			ForbiddenHandler(w, r)
			return
		}

		responseTypeQueryParameter := r.URL.Query().Get(oauth2.ParameterResponseType)
		responseType, valid := oauth2.ResponseTypeFromString(responseTypeQueryParameter)
		if !valid {
			ForbiddenHandler(w, r)
			return
		}

		redirect := r.URL.Query().Get(oauth2.ParameterRedirectUri)
		state := r.URL.Query().Get(oauth2.ParameterState)
		scope := r.URL.Query().Get(oauth2.ParameterScope)
		codeChallenge := r.URL.Query().Get(pkceParameters.ParameterCodeChallenge)
		codeChallengeMethod := r.URL.Query().Get(pkceParameters.ParameterCodeChallengeMethod)

		log.Debug("Response type: %s", responseType)
		log.Debug("Redirect URI: %s", redirect)
		log.Debug("State: %s", state)
		log.Debug("Scope: %s", scope)

		scopes := strings.Split(scope, " ")

		id := uuid.New()
		authSession := &store.AuthSession{
			Redirect:            redirect,
			AuthURI:             r.URL.RequestURI(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ClientId:            clientId,
			ResponseType:        string(responseType),
			Scopes:              scopes,
			State:               state,
		}

		handler.authSessionStore.Set(id.String(), authSession)

		user, validCookie := ValidateCookie(handler.config, r)

		if validCookie {
			authSession.Username = user.Username
			redirectURL, urlParseError := url.Parse(redirect)
			if urlParseError != nil {
				InternalServerErrorHandler(w, r)
				return
			}

			query := redirectURL.Query()

			if responseType == oauth2.RtToken {
				accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore, handler.refreshTokenStore, user.Username, client, scopes)
				query.Add(oauth2.ParameterAccessToken, accessTokenResponse.AccessTokenKey)
				query.Add(oauth2.ParameterTokenType, string(accessTokenResponse.TokenType))
				query.Add(oauth2.ParameterExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
			} else {
				query.Add(oauth2.ParameterCode, id.String())
			}

			if state != "" {
				query.Add(oauth2.ParameterState, state)
			}

			redirectURL.RawQuery = query.Encode()

			w.Header().Set(httpHeader.Location, redirectURL.String())
			w.WriteHeader(http.StatusFound)
		} else {
			// http.ServeFile(w, r, "foo.html")
			// bytes := []byte(loginHtml)
			loginTemplate := template.LoginTemplate(id.String())

			_, err := w.Write(loginTemplate.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
