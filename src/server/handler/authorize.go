package handler

import (
	"bytes"
	_ "embed"
	"github.com/google/uuid"
	"html/template"
	"log"
	"net/http"
	"tiny-gate/src/oauth2"
)

//go:embed resources/login.html
var loginHtml []byte

type AuthorizeHandler struct {
	redirect *string
	authURI  *string
}

func CreateAuthorizeHandler(redirect *string, authURI *string) *AuthorizeHandler {
	return &AuthorizeHandler{
		redirect: redirect,
		authURI:  authURI,
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
		*handler.redirect = redirect
		*handler.authURI = r.URL.RequestURI()
		// http.ServeFile(w, r, "foo.html")
		// bytes := []byte(loginHtml)
		_, err := w.Write(tpl.Bytes())
		if err != nil {
			InternalServerErrorHandler(w, r)
			return
		}
	} else {
		NotFoundHandler(w, r)
	}
}
