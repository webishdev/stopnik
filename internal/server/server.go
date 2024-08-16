package server

import (
	"context"
	"errors"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/server/handler/account"
	"github.com/webishdev/stopnik/internal/server/handler/assets"
	"github.com/webishdev/stopnik/internal/server/handler/authorize"
	"github.com/webishdev/stopnik/internal/server/handler/health"
	"github.com/webishdev/stopnik/internal/server/handler/introspect"
	"github.com/webishdev/stopnik/internal/server/handler/logout"
	"github.com/webishdev/stopnik/internal/server/handler/revoke"
	"github.com/webishdev/stopnik/internal/server/handler/token"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/store"
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

func NewStopnikServer(config *config.Config) *StopnikServer {
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
	return newStopnikServerWithServe(rwMutex, config, http.NewServeMux(), listenAndServe, listenAndServeTLS)
}

func newStopnikServerWithServe(rwMutex *sync.RWMutex, config *config.Config, mux *http.ServeMux, serve ListenAndServe, serveTLS ListenAndServe) *StopnikServer {
	registerHandlers(config, mux.Handle)

	middleware := &middlewareHandler{
		next:   mux,
		assets: assets.NewAssetHandler(),
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
	sessionManager := store.NewSessionManager(config)
	tokenManager := store.NewTokenManager(config, store.NewDefaultKeyLoader(config))
	cookieManager := internalHttp.NewCookieManager(config)
	requestValidator := validation.NewRequestValidator(config)
	templateManager := template.NewTemplateManager(config)

	// Own
	healthHandler := health.NewHealthHandler(tokenManager)
	accountHandler := account.CreateAccountHandler(requestValidator, cookieManager, templateManager)
	logoutHandler := logout.CreateLogoutHandler(cookieManager, config.Server.LogoutRedirect)

	// OAuth2
	authorizeHandler := authorize.CreateAuthorizeHandler(requestValidator, cookieManager, sessionManager, tokenManager, templateManager)
	tokenHandler := token.CreateTokenHandler(requestValidator, sessionManager, tokenManager)

	// OAuth2 extensions
	introspectHandler := introspect.CreateIntrospectHandler(config, requestValidator, tokenManager)
	revokeHandler := revoke.CreateRevokeHandler(config, requestValidator, tokenManager)

	// Server
	handle("/health", healthHandler)
	handle("/account", accountHandler)
	handle("/logout", logoutHandler)

	// OAuth2
	handle("/authorize", authorizeHandler)
	handle("/token", tokenHandler)

	// OAuth2 extensions
	handle("/introspect", introspectHandler)
	handle("/revoke", revokeHandler)
}
