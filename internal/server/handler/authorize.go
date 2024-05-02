package handler

import (
	"bytes"
	_ "embed"
	"github.com/google/uuid"
	"html/template"
	"log"
	"net/http"
	"tiny-gate/internal/cache"
	"tiny-gate/internal/oauth2"
)

//go:embed resources/login.html
var loginHtml []byte

type AuthorizeHandler struct {
	cache *cache.Cache[cache.AuthSession]
}

func CreateAuthorizeHandler(cache *cache.Cache[cache.AuthSession]) *AuthorizeHandler {
	return &AuthorizeHandler{
		cache: cache,
	}
}

func (handler *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodGet {
		responseTypeQueryParameter := r.URL.Query().Get("response_type")
		responseType, valid := oauth2.ResponseTypeFromString(responseTypeQueryParameter)
		if !valid {
			InternalServerErrorHandler(w, r)
			return
		}

		tmpl, templateError := template.New("name").Parse(string(loginHtml))
		if templateError != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		id := uuid.New()
		data := struct {
			Token string
		}{
			Token: id.String(),
		}

		var tpl bytes.Buffer
		eerr := tmpl.Execute(&tpl, data)
		if eerr != nil {
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
			handler.cache.Set(id.String(), cache.AuthSession{
				Redirect: redirect,
				AuthURI:  r.URL.RequestURI(),
			})

			// http.ServeFile(w, r, "foo.html")
			// bytes := []byte(loginHtml)
			_, err := w.Write(tpl.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		}
	} else {
		NotFoundHandler(w, r)
	}
}
