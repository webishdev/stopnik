package handler

import (
	"fmt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
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
		clientId := r.URL.Query().Get("client_id")
		client, exists := handler.config.GetClient(clientId)
		if !exists {
			ForbiddenHandler(w, r)
			return
		}

		responseTypeQueryParameter := r.URL.Query().Get("response_type")
		responseType, valid := oauth2.ResponseTypeFromString(responseTypeQueryParameter)
		if !valid {
			ForbiddenHandler(w, r)
			return
		}
		log.Printf("Response type: %s", responseType)

		redirect := r.URL.Query().Get("redirect_uri")
		log.Printf("Redirect URI: %s", redirect)

		scope := r.URL.Query().Get("scope")
		log.Printf("Scope: %s", scope)
		scopes := strings.Split(scope, " ")

		codeChallenge := r.URL.Query().Get("code_challenge")
		codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

		id := uuid.New()
		handler.authSessionStore.Set(id.String(), store.AuthSession{
			Redirect:            redirect,
			AuthURI:             r.URL.RequestURI(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ClientId:            clientId,
			ResponseType:        string(responseType),
			Scopes:              scopes,
		})

		validCookie := ValidateCookie(handler.config, r)
		if validCookie {

			redirectURL, urlParseError := url.Parse(redirect)
			if urlParseError != nil {
				InternalServerErrorHandler(w, r)
				return
			}

			query := redirectURL.Query()

			if responseType == oauth2.RtToken {
				accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore, clientId, scopes, client.GetAccessTTL())
				query.Add("access_token", accessTokenResponse.AccessTokenKey)
				query.Add("token_type", string(accessTokenResponse.TokenType))
				query.Add("expires_in", fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
			} else {
				query.Add("code", id.String())
			}

			redirectURL.RawQuery = query.Encode()

			w.Header().Set("Location", redirectURL.String())
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
