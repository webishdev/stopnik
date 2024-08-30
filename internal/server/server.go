package server

import (
	"context"
	"errors"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"github.com/webishdev/stopnik/internal/manager"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	token2 "github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/server/handler/account"
	"github.com/webishdev/stopnik/internal/server/handler/assets"
	"github.com/webishdev/stopnik/internal/server/handler/authorize"
	"github.com/webishdev/stopnik/internal/server/handler/health"
	"github.com/webishdev/stopnik/internal/server/handler/introspect"
	"github.com/webishdev/stopnik/internal/server/handler/keys"
	"github.com/webishdev/stopnik/internal/server/handler/logout"
	"github.com/webishdev/stopnik/internal/server/handler/metadata"
	"github.com/webishdev/stopnik/internal/server/handler/oidc"
	"github.com/webishdev/stopnik/internal/server/handler/revoke"
	"github.com/webishdev/stopnik/internal/server/handler/token"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"github.com/webishdev/stopnik/log"
	"net"
	"net/http"
	"sync"
	"time"
)

type ListenAndServe func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error

type middlewareHandler struct {
	next   http.Handler
	assets *assets.Handler
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
	rwMutex           *sync.RWMutex
}

func NewStopnikServer() *StopnikServer {
	rwMutex := &sync.RWMutex{}
	listenAndServe := func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error {
		rwMutex.Lock()
		stopnikServer.httpServer = server
		rwMutex.Unlock()
		log.Info("Will accept connections at %s", server.Addr)
		return server.Serve(*listener)
	}
	listenAndServeTLS := func(stopnikServer *StopnikServer, listener *net.Listener, server *http.Server) error {
		rwMutex.Lock()
		stopnikServer.httpsServer = server
		rwMutex.Unlock()
		if stopnikServer.config.Server.TLS.Keys.Cert == "" || stopnikServer.config.Server.TLS.Keys.Key == "" {
			return errors.New("TLS Keys not configured")
		}
		log.Info("Will accept TLS connections at %s", server.Addr)
		return server.ServeTLS(*listener, stopnikServer.config.Server.TLS.Keys.Cert, stopnikServer.config.Server.TLS.Keys.Key)
	}
	return newStopnikServerWithServe(rwMutex, http.NewServeMux(), listenAndServe, listenAndServeTLS)
}

func newStopnikServerWithServe(rwMutex *sync.RWMutex, mux *http.ServeMux, serve ListenAndServe, serveTLS ListenAndServe) *StopnikServer {
	currentConfig := config.GetConfigInstance()
	registerHandlers(currentConfig, mux.Handle)

	middleware := &middlewareHandler{
		next:   mux,
		assets: assets.NewAssetHandler(),
	}
	return &StopnikServer{
		config:            currentConfig,
		middleware:        middleware,
		readHeaderTimeout: 15 * time.Second,
		readTimeout:       15 * time.Second,
		writeTimeout:      10 * time.Second,
		idleTimeout:       30 * time.Second,
		serve:             &serve,
		serveTLS:          &serveTLS,
		rwMutex:           rwMutex,
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
	stopnikServer.rwMutex.RLock()
	defer stopnikServer.rwMutex.RUnlock()
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

func registerHandlers(config *config.Config, handle func(pattern string, handler http.Handler)) {
	keyManger := manager.GetKeyMangerInstance()
	sessionManager := session.GetSessionManagerInstance()
	tokenManager := token2.GetTokenManagerInstance()
	cookieManager := cookie.GetCookieManagerInstance()
	requestValidator := validation.NewRequestValidator()
	templateManager := template.NewTemplateManager()

	// Own
	healthHandler := health.NewHealthHandler(tokenManager)
	accountHandler := account.NewAccountHandler(requestValidator, cookieManager, templateManager)
	logoutHandler := logout.NewLogoutHandler(cookieManager, config.Server.LogoutRedirect)

	// OAuth2
	authorizeHandler := authorize.NewAuthorizeHandler(requestValidator, cookieManager, sessionManager, tokenManager, templateManager)
	tokenHandler := token.NewTokenHandler(requestValidator, sessionManager, tokenManager)

	// OAuth2 extensions
	introspectHandler := introspect.NewIntrospectHandler(requestValidator, tokenManager)
	revokeHandler := revoke.NewRevokeHandler(requestValidator, tokenManager)
	metadataHandler := metadata.NewMetadataHandler()
	keysHandler := keys.NewKeysHandler(keyManger)

	// Server
	handle(endpoint.Health, healthHandler)
	handle(endpoint.Account, accountHandler)
	handle(endpoint.Logout, logoutHandler)

	// OAuth2
	handle(endpoint.Authorization, authorizeHandler)
	handle(endpoint.Token, tokenHandler)

	// OAuth2 extensions
	handle(endpoint.Introspect, introspectHandler)
	handle(endpoint.Revoke, revokeHandler)
	handle(endpoint.Metadata, metadataHandler)
	handle(endpoint.Keys, keysHandler)

	// Oidc 1.0 Core
	if config.GetOidc() {
		discoveryHandler := oidc.NewOidcDiscoveryHandler()
		userInfoHandler := oidc.NewOidcUserInfoHandler(tokenManager)

		handle(endpoint.OidcDiscovery, discoveryHandler)
		handle(endpoint.OidcUserInfo, userInfoHandler)
	}
}
