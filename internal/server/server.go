package server

import (
	"net/http"
	"tiny-gate/internal/cache"
	"tiny-gate/internal/server/handler"
)

func StartServer() {
	authSessionCache := cache.NewCache[cache.AuthSession]()

	mux := http.NewServeMux()

	authorizeHandler := handler.CreateAuthorizeHandler(authSessionCache)
	loginHandler := handler.CreateLoginHandler(authSessionCache)

	mux.Handle("/", &handler.HomeHandler{})
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", &handler.TokenHandler{})
	mux.Handle("/login", loginHandler)

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		return
	}
}
