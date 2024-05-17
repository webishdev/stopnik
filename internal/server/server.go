package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/server/handler"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"stopnik/log"
	"sync"
	"time"
)

type ListenAndServe func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error

type middlewareHandler struct {
	next   http.Handler
	assets *handler.AssetHandler
}

func (mh middlewareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if mh.assets.Matches(r) {
		mh.assets.ServeHTTP(w, r)
	} else {
		mh.next.ServeHTTP(w, r)
	}
}

type StopnikServer struct {
	config            *config.Config
	middleware        *middlewareHandler
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
	httpServer        *http.Server
	httpsServer       *http.Server
	serve             *ListenAndServe
	serveTLS          *ListenAndServe
}

func NewStopnikServer(config *config.Config) *StopnikServer {
	listenAndServe := func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error {
		stopnikServer.httpServer = server
		return server.Serve(*listener)
	}
	listenAndServeTLS := func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error {
		stopnikServer.httpsServer = server
		return server.Serve(*listener)
	}
	return NewStopnikServerWithServe(config, listenAndServe, listenAndServeTLS)
}

func NewStopnikServerWithServe(config *config.Config, serve ListenAndServe, serveTLS ListenAndServe) *StopnikServer {
	mux := newMux(config)

	middleware := &middlewareHandler{
		next:   mux,
		assets: &handler.AssetHandler{},
	}
	return &StopnikServer{
		config:            config,
		middleware:        middleware,
		readHeaderTimeout: 15 * time.Second,
		readTimeout:       15 * time.Second,
		writeTimeout:      10 * time.Second,
		idleTimeout:       30 * time.Second,
		serve:             &serve,
		serveTLS:          &serveTLS,
	}
}

func (stopnikServer *StopnikServer) Start() {

	wg := sync.WaitGroup{}

	if stopnikServer.config.Server.Addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errorServer := stopnikServer.listenAndServe(stopnikServer.config.Server.Addr, *stopnikServer.serve)

			if errorServer != nil && !errors.Is(errorServer, http.ErrServerClosed) {
				log.Error("Error starting server: %v", errorServer)
			}
		}()
	}

	if stopnikServer.config.Server.TLS.Addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errorServer := stopnikServer.listenAndServe(stopnikServer.config.Server.TLS.Addr, *stopnikServer.serveTLS)

			if errorServer != nil && !errors.Is(errorServer, http.ErrServerClosed) {
				log.Error("Error starting server: %v", errorServer)
			}
		}()
	}

	wg.Wait()
}

func (stopnikServer *StopnikServer) Shutdown() {
	log.Info("Shutting down STOPnik...")
	if stopnikServer.httpServer != nil {
		shutdownServer(stopnikServer.httpServer)
	}

	if stopnikServer.httpsServer != nil {
		shutdownServer(stopnikServer.httpsServer)
	}
}

func (stopnikServer *StopnikServer) listenAndServe(addr string, serve func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error) error {
	listener, listenError := net.Listen("tcp", addr)
	if listenError != nil {
		return listenError
	}

	httpServer := &http.Server{
		Addr:              listener.Addr().String(),
		ReadHeaderTimeout: stopnikServer.readHeaderTimeout,
		ReadTimeout:       stopnikServer.readTimeout,
		WriteTimeout:      stopnikServer.writeTimeout,
		IdleTimeout:       stopnikServer.idleTimeout,
		Handler:           stopnikServer.middleware,
	}

	log.Info("Will accept connections at %s", httpServer.Addr)

	errorServer := serve(stopnikServer, &listener, httpServer)
	if errorServer != nil {
		return errorServer
	}

	return nil
}

func shutdownServer(server *http.Server) {
	errorServer := server.Shutdown(context.Background())
	if errorServer != nil {
		log.Error("Failed to shutdown server: %v", errorServer)
	}
}

func newMux(config *config.Config) *http.ServeMux {
	sessionManager := store.NewSessionManager(config)
	tokenManager := store.NewTokenManager(config, store.NewDefaultKeyLoader(config))
	cookieManager := internalHttp.NewCookieManager(config)
	requestValidator := validation.NewRequestValidator(config)

	// Own
	accountHandler := handler.CreateAccountHandler(requestValidator, cookieManager)
	logoutHandler := handler.CreateLogoutHandler(cookieManager, config.Server.LogoutRedirect)

	// OAuth2
	authorizeHandler := handler.CreateAuthorizeHandler(requestValidator, cookieManager, sessionManager, tokenManager)
	tokenHandler := handler.CreateTokenHandler(requestValidator, sessionManager, tokenManager)

	// OAuth2 extensions
	introspectHandler := handler.CreateIntrospectHandler(config, requestValidator, tokenManager)
	revokeHandler := handler.CreateRevokeHandler(config, requestValidator, tokenManager)

	mux := http.NewServeMux()

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

	return mux
}
