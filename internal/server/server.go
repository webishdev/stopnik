package server

import (
	"net"
	"net/http"
	"os"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/server/handler"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"stopnik/log"
	"time"
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
	sessionManager := store.NewSessionManager(config)
	tokenManager := store.NewTokenManager(config)
	cookieManager := internalHttp.NewCookieManager(config)
	requestValidator := validation.NewRequestValidator(config)

	// Own
	accountHandler := handler.CreateAccountHandler(requestValidator, cookieManager)
	logoutHandler := handler.CreateLogoutHandler(cookieManager)

	// OAuth2
	authorizeHandler := handler.CreateAuthorizeHandler(requestValidator, cookieManager, sessionManager, tokenManager)
	tokenHandler := handler.CreateTokenHandler(requestValidator, sessionManager, tokenManager)

	// OAuth2 extensions
	introspectHandler := handler.CreateIntrospectHandler(config, requestValidator, tokenManager)
	revokeHandler := handler.CreateRevokeHandler(config, requestValidator, tokenManager)

	mux := http.NewServeMux()

	main := &mainHandler{
		next:   mux,
		assets: &handler.AssetHandler{},
	}

	// Server
	mux.Handle("/health", &handler.HealthHandler{})
	mux.Handle("/account", accountHandler)
	mux.Handle("/logout", logoutHandler)

	// OAuth2
	mux.Handle("/authorize", authorizeHandler)
	mux.Handle("/token", tokenHandler)

	// OAuth2 extensions
	mux.Handle("/introspect", introspectHandler)
	mux.Handle("/revoke", revokeHandler)

	var readHeaderTimeout = 15 * time.Second
	var readTimeout = 15 * time.Second
	var writeTimeout = 10 * time.Second
	var idleTimeout = 30 * time.Second

	go func() {
		listener, listenError := net.Listen("tcp", config.Server.Addr)
		if listenError != nil {
			log.Error("Failed to setup listener: %v", listenError)
			os.Exit(1)
		}

		httpServer := &http.Server{
			Addr:              listener.Addr().String(),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			Handler:           main,
		}

		log.Info("Will accept connections at %s", httpServer.Addr)

		errorServer := httpServer.Serve(listener)
		if errorServer != nil {
			log.Error("Failed to start server: %v", errorServer)
			os.Exit(1)
		}
	}()

	if config.Server.TLS.Addr != "" {
		go func() {
			tlsListener, tlsListenError := net.Listen("tcp", config.Server.TLS.Addr)
			if tlsListenError != nil {
				log.Error("Failed to setup TLS listener: %v", tlsListenError)
				os.Exit(1)
			}

			httpsServer := &http.Server{
				Addr:              tlsListener.Addr().String(),
				ReadHeaderTimeout: readHeaderTimeout,
				ReadTimeout:       readTimeout,
				WriteTimeout:      writeTimeout,
				IdleTimeout:       idleTimeout,
				Handler:           main,
			}

			log.Info("Will accept TLS connections at %s", httpsServer.Addr)

			tlsServerError := httpsServer.ServeTLS(tlsListener, config.Server.TLS.Cert, config.Server.TLS.Key)
			if tlsServerError != nil {
				log.Error("Failed to start TLS server: %v", tlsServerError)
				os.Exit(1)
			}
		}()
	}

	select {}

}
