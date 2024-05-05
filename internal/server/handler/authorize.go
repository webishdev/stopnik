package handler

import (
	"fmt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/internal/oauth2"
	oauth2Parameters "stopnik/internal/oauth2/parameters"
	pkceParameters "stopnik/internal/pkce/parameters"
	"stopnik/internal/store"
	"stopnik/internal/template"
	"strings"
)

type AuthorizeHandler struct {
	config           *config.Config
	authSessionStore *store.Store[store.AuthSession]
	accessTokenStore *store.Store[oauth2.AccessToken]
}

func CreateAuthorizeHandler(config *config.Config, authSessionStore *store.Store[store.AuthSession], accessTokenStore *store.Store[oauth2.AccessToken]) *AuthorizeHandler {
	return &AuthorizeHandler{
		config:           config,
		authSessionStore: authSessionStore,
		accessTokenStore: accessTokenStore,
	}
}

func (handler *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodGet {
		clientId := r.URL.Query().Get(oauth2Parameters.ClientId)
		client, exists := handler.config.GetClient(clientId)
		if !exists {
			ForbiddenHandler(w, r)
			return
		}

		responseTypeQueryParameter := r.URL.Query().Get(oauth2Parameters.ResponseType)
		responseType, valid := oauth2.ResponseTypeFromString(responseTypeQueryParameter)
		if !valid {
			ForbiddenHandler(w, r)
			return
		}
		log.Printf("Response type: %s", responseType)

		redirect := r.URL.Query().Get(oauth2Parameters.RedirectUri)
		log.Printf("Redirect URI: %s", redirect)

		scope := r.URL.Query().Get(oauth2Parameters.Scope)
		log.Printf("Scope: %s", scope)
		scopes := strings.Split(scope, " ")

		codeChallenge := r.URL.Query().Get(pkceParameters.CodeChallenge)
		codeChallengeMethod := r.URL.Query().Get(pkceParameters.CodeChallengeMethod)

		id := uuid.New()
		authSession := &store.AuthSession{
			Redirect:            redirect,
			AuthURI:             r.URL.RequestURI(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ClientId:            clientId,
			ResponseType:        string(responseType),
			Scopes:              scopes,
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
				accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore, user.Username, client.Id, scopes, client.GetAccessTTL())
				query.Add(oauth2Parameters.AccessToken, accessTokenResponse.AccessTokenKey)
				query.Add(oauth2Parameters.TokenType, string(accessTokenResponse.TokenType))
				query.Add(oauth2Parameters.ExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
			} else {
				query.Add(oauth2Parameters.Code, id.String())
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
