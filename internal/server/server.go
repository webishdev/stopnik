package server

import (
	"net/http"
	"tiny-gate/internal/cache"
	"tiny-gate/internal/config"
	"tiny-gate/internal/server/handler"
)

func StartServer(config *config.Config) {
	authSessionCache := cache.NewCache[cache.AuthSession]()

	mux := http.NewServeMux()

	authorizeHandler := handler.CreateAuthorizeHandler(config, authSessionCache)
	loginHandler := handler.CreateLoginHandler(config, authSessionCache)
	logoutHandler := handler.CreateLogoutHandler()

	mux.Handle("/", &handler.HomeHandler{})
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", &handler.TokenHandler{})
	mux.Handle("/login", loginHandler)
	mux.Handle("/logout", logoutHandler)

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		return
	}
}
