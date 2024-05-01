package handler

import (
	_ "embed"
	"log"
	"net/http"
)

//go:embed resources/login.html
var loginHtml []byte

type LoginHandler struct {
	redirect *string
	authURI  *string
}

func CreateLoginHandler(redirect *string, authURI *string) *LoginHandler {
	return &LoginHandler{
		redirect: redirect,
		authURI:  authURI,
	}
}

func (handler *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		log.Printf("redirect URI: %s", *handler.redirect)
		parseError := r.ParseForm()
		if parseError != nil {
			InternalServerErrorHandler(w, r)
			return
		}
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		// When login invalid
		// https://en.wikipedia.org/wiki/Post/Redirect/Get
		// redirect with Status 303
		// When login valid
		if username == "foo" && password == "bar" {
			w.Header().Set("Location", *handler.redirect)
			w.WriteHeader(http.StatusFound)
		}
		w.Header().Set("Location", *handler.authURI)
		w.WriteHeader(http.StatusSeeOther)
	} else {
		NotFoundHandler(w, r)
	}
}
