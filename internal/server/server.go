package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"tiny-gate/internal/config"
	"tiny-gate/internal/server/handler"
	"tiny-gate/internal/store"
)

func StartServer(config *config.Config) {
	authSessionStore := store.NewCache[store.AuthSession]()
	//accessTokenStore := store.NewCache[oauth2.AccessToken]()

	mux := http.NewServeMux()

	authorizeHandler := handler.CreateAuthorizeHandler(config, authSessionStore)
	loginHandler := handler.CreateLoginHandler(config, authSessionStore)
	logoutHandler := handler.CreateLogoutHandler()

	// Server
	mux.Handle("/", &handler.HomeHandler{})
	mux.Handle("/login", loginHandler)
	mux.Handle("/logout", logoutHandler)

	// OAuth2
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", &handler.TokenHandler{})

	listener, listenError := net.Listen("tcp", fmt.Sprintf(":%d", config.Server.Port))
	if listenError != nil {
		panic(listenError)
	}

	log.Printf("Will accept connections at %s", listener.Addr().String())

	errorServer := http.Serve(listener, mux)
	if errorServer != nil {
		panic(errorServer)
	}
}
