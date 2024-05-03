package server

import (
	"fmt"
	"log"
	"net"
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
