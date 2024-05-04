package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/server/handler"
	"stopnik/internal/store"
)

func StartServer(config *config.Config) {
	authSessionStore := store.NewCache[store.AuthSession]()
	accessTokenStore := store.NewCache[oauth2.AccessToken]()

	mux := http.NewServeMux()

	// Own
	loginHandler := handler.CreateLoginHandler(config, authSessionStore, accessTokenStore)
	logoutHandler := handler.CreateLogoutHandler(config)

	// OAuth2
	authorizeHandler := handler.CreateAuthorizeHandler(config, authSessionStore, accessTokenStore)
	tokenHandler := handler.CreateTokenHandler(config, authSessionStore, accessTokenStore)

	// OAuth2 extensions
	introspectHandler := handler.CreateIntrospectHandler(config, accessTokenStore)

	// Server
	mux.Handle("/", &handler.HomeHandler{})
	mux.Handle("/login", loginHandler)
	mux.Handle("/logout", logoutHandler)

	// OAuth2
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", tokenHandler)

	// OAuth2 extensions
	mux.Handle("/introspect", introspectHandler)

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
