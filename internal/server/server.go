package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/server/handler"
	"stopnik/internal/store"
	"stopnik/log"
)

type mainHandler struct {
	next   http.Handler
	assets *handler.AssetHandler
}

func (mh mainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if mh.assets.Matches(r) {
		mh.assets.ServeHTTP(w, r)
	} else {
		mh.next.ServeHTTP(w, r)
	}
}

func StartServer(config *config.Config) {
	authSessionStore := store.NewCache[store.AuthSession]()
	accessTokenStore := store.NewCache[oauth2.AccessToken]()
	refreshTokenStore := store.NewCache[oauth2.RefreshToken]()

	tokens := &store.TokenStores[oauth2.AccessToken, oauth2.RefreshToken]{
		AccessTokenStore:  accessTokenStore,
		RefreshTokenStore: refreshTokenStore,
	}

	// Own
	accountHandler := handler.CreateAccountHandler(config)
	logoutHandler := handler.CreateLogoutHandler(config)

	// OAuth2
	authorizeHandler := handler.CreateAuthorizeHandler(config, authSessionStore, tokens)
	tokenHandler := handler.CreateTokenHandler(config, authSessionStore, tokens)

	// OAuth2 extensions
	introspectHandler := handler.CreateIntrospectHandler(config, tokens)
	revokeHandler := handler.CreateRevokeHandler(config, tokens)

	mux := http.NewServeMux()

	main := &mainHandler{
		next:   mux,
		assets: &handler.AssetHandler{},
	}

	// Server
	mux.Handle("/", &handler.HomeHandler{})
	mux.Handle("/account", accountHandler)
	mux.Handle("/logout", logoutHandler)

	// OAuth2
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", tokenHandler)

	// OAuth2 extensions
	mux.Handle("/introspect", introspectHandler)
	mux.Handle("/revoke", revokeHandler)

	listener, listenError := net.Listen("tcp", fmt.Sprintf(":%d", config.Server.Port))
	if listenError != nil {
		log.Error("Failed to setup listener: %v", listenError)
		os.Exit(1)
	}

	log.Info("Will accept connections at %s", listener.Addr().String())

	errorServer := http.Serve(listener, main)
	if errorServer != nil {
		log.Error("Failed to start server: %v", errorServer)
		os.Exit(1)
	}
}
