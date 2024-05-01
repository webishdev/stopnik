package handler

import (
	_ "embed"
	"log"
	"net/http"
)

//go:embed resources/login.html
var loginHtml []byte

type LoginHandler struct {
	Redirect *string
}

func CreateLoginHandler(redirect *string) *LoginHandler {
	return &LoginHandler{
		Redirect: redirect,
	}
}

func (handler *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		log.Printf("Redirect URI: %s", *handler.Redirect)
		w.Header().Set("Location", *handler.Redirect)
		w.WriteHeader(http.StatusFound)
	} else {
		NotFoundHandler(w, r)
	}
}
