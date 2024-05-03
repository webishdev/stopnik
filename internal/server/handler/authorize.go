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
		clientIdParameter := r.URL.Query().Get("client_id")
		_, exists := handler.config.GetClient(clientIdParameter)
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

		id := uuid.New()

		log.Printf("Response type: %s", responseType)
		redirect := r.URL.Query().Get("redirect_uri")
		log.Printf("redirect URI: %s", redirect)

		codeChallenge := r.URL.Query().Get("code_challenge")
		codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

		handler.authSessionStore.Set(id.String(), store.AuthSession{
			Redirect:            redirect,
			AuthURI:             r.URL.RequestURI(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ResponseType:        string(responseType),
		})

		cookie, noCookieError := r.Cookie("STOPIK_AUTH")
		if noCookieError == nil {
			log.Printf("I like cookies! %s", cookie.Value)

			redirectURL, urlParseError := url.Parse(redirect)
			if urlParseError != nil {
				InternalServerErrorHandler(w, r)
				return
			}

			query := redirectURL.Query()

			if responseType == oauth2.RtToken {
				accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore)
				query.Add("access_token", string(accessTokenResponse.AccessToken))
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
			loginTemplate, templateError := template.LoginTemplate(id.String())
			if templateError != nil {
				InternalServerErrorHandler(w, r)
				return
			}

			_, err := w.Write(loginTemplate.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		}
	} else {
		NotFoundHandler(w, r)
	}
}
