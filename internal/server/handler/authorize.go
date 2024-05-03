package handler

import (
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"tiny-gate/internal/config"
	"tiny-gate/internal/oauth2"
	"tiny-gate/internal/store"
	"tiny-gate/internal/template"
)

type AuthorizeHandler struct {
	config           *config.Config
	authSessionStore *store.Store[store.AuthSession]
}

func CreateAuthorizeHandler(config *config.Config, authSessionStore *store.Store[store.AuthSession]) *AuthorizeHandler {
	return &AuthorizeHandler{
		config:           config,
		authSessionStore: authSessionStore,
	}
}

func (handler *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodGet {
		responseTypeQueryParameter := r.URL.Query().Get("response_type")
		responseType, valid := oauth2.ResponseTypeFromString(responseTypeQueryParameter)
		if !valid {
			ForbiddenHandler(w, r)
			return
		}

		clientIdParameter := r.URL.Query().Get("client_id")
		_, exists := handler.config.GetClient(clientIdParameter)
		if !exists {
			ForbiddenHandler(w, r)
			return
		}

		id := uuid.New()
		loginTemplate, templateError := template.LoginTemplate(id.String())
		if templateError != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		log.Printf("Response type: %s", responseType)
		redirect := r.URL.Query().Get("redirect_uri")
		log.Printf("redirect URI: %s", redirect)

		codeChallenge := r.URL.Query().Get("code_challenge")

		handler.authSessionStore.Set(id.String(), store.AuthSession{
			Redirect:      redirect,
			AuthURI:       r.URL.RequestURI(),
			CodeChallenge: codeChallenge,
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
			query.Add("code", id.String())
			redirectURL.RawQuery = query.Encode()

			w.Header().Set("Location", redirectURL.String())
			w.WriteHeader(http.StatusFound)
		} else {
			// http.ServeFile(w, r, "foo.html")
			// bytes := []byte(loginHtml)
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
