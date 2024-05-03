package handler

import (
	"github.com/google/uuid"
	"log"
	"net/http"
	"tiny-gate/internal/config"
	"tiny-gate/internal/oauth2"
	"tiny-gate/internal/store"
	"tiny-gate/internal/template"
)

type AuthorizeHandler struct {
	config *config.Config
	store  *store.Store[store.AuthSession]
}

func CreateAuthorizeHandler(config *config.Config, store *store.Store[store.AuthSession]) *AuthorizeHandler {
	return &AuthorizeHandler{
		config: config,
		store:  store,
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

		cookie, noCookieError := r.Cookie("STOPIK_AUTH")

		if noCookieError == nil {
			log.Printf("I like cookies! %s", cookie.Value)
			w.Header().Set("Location", redirect)
			w.WriteHeader(http.StatusFound)
		} else {
			handler.store.Set(id.String(), store.AuthSession{
				Redirect: redirect,
				AuthURI:  r.URL.RequestURI(),
			})

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
