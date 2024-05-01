package server

import (
	"net/http"
	"tiny-gate/src/server/handler"
)

var (
	redirect string
)

func StartServer() {
	mux := http.NewServeMux()

	authorizeHandler := handler.CreateAuthorizeHandler(&redirect)
	loginHandler := handler.CreateLoginHandler(&redirect)

	mux.Handle("/", &handler.HomeHandler{})
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", &handler.TokenHandler{})
	mux.Handle("/login", loginHandler)

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		return
	}
}
