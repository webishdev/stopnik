package server

import (
	"net/http"
	"tiny-gate/internal/server/handler"
)

var (
	redirect string
	authURI  string
)

func StartServer() {
	mux := http.NewServeMux()

	authorizeHandler := handler.CreateAuthorizeHandler(&redirect, &authURI)
	loginHandler := handler.CreateLoginHandler(&redirect, &authURI)

	mux.Handle("/", &handler.HomeHandler{})
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", &handler.TokenHandler{})
	mux.Handle("/login", loginHandler)

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		return
	}
}
